"""The AI threat-hunting brain: turns one ExecEvent into one Verdict.

Structured output strategy
---------------------------
We use forced tool-use (`tool_choice={"type": "tool", "name": ...}`) rather
than asking the model for free-text JSON and hoping it parses. This is the
long-established, broadly-supported mechanism for schema-conformant Claude
output (see https://docs.claude.com/en/docs/agents-and-tools/tool-use/overview);
Anthropic's newer `output_format` "Structured Outputs" beta is a stronger
guarantee where available for your pinned model -- see
https://docs.claude.com/en/docs/build-with-claude/structured-outputs for
whether it covers your target model, and swap `evaluate()`'s call site if
so. Either way, we still validate the tool's returned JSON against our own
Pydantic schema before trusting it (defense in depth: never assume a
provider's schema enforcement is infallible).

Authority boundary
-------------------
The model proposes; this module disposes. A `kill` verdict is only ever
honored if it *also* clears a server-side confidence floor set independent
of the model -- see `_parse_tool_input`. No single LLM call gets unilateral
authority to terminate a process.
"""

from __future__ import annotations

import json
import logging

import anthropic

from config import Settings
from mitre import NONE_TECHNIQUE, is_known_technique, prompt_reference_block
from models import Action, ExecEvent, Severity, Verdict

logger = logging.getLogger("cyber_patrol.hunter")

_VERDICT_TOOL = {
    "name": "emit_threat_verdict",
    "description": (
        "Report the final security assessment of a single Linux "
        "process-execution event. Call this exactly once, as your final action."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "severity": {"type": "string", "enum": [s.value for s in Severity]},
            "action": {
                "type": "string",
                "enum": [a.value for a in Action],
                "description": (
                    "'kill' only for severity='critical' with high confidence this is "
                    "active, ongoing exploitation -- not a plausible-but-unconfirmed "
                    "administrative action."
                ),
            },
            "mitre_technique": {
                "type": "string",
                "description": "A technique ID from the reference list in the system prompt, or 'NONE'.",
            },
            "mitre_tactic": {"type": "string"},
            "confidence": {"type": "number", "minimum": 0, "maximum": 1},
            "rationale": {"type": "string", "description": "One or two sentences, analyst-readable."},
        },
        "required": ["severity", "action", "mitre_technique", "mitre_tactic", "confidence", "rationale"],
    },
}


def _build_system_prompt() -> str:
    return f"""You are the automated threat-hunting brain of a Linux eBPF \
endpoint-detection pipeline. You receive one process-execution event, \
captured at the sys_enter_execve syscall boundary, and must classify it.

Ground your classification in this MITRE ATT&CK (Enterprise) technique \
set. Prefer one of these IDs, or '{NONE_TECHNIQUE}' if the activity is benign:
{prompt_reference_block()}

Guidance:
- Most process execution on a normal Linux host is benign: package \
managers, editors, shell built-ins, CI runners, ordinary admin work. \
Default to severity=benign/low and action=monitor or ignore unless the \
evidence is specific.
- Weigh the full argument list, not just the binary name. An interpreter \
running a short inline script that opens a raw socket, or a chmod that \
flips +x on a file immediately after it was written into a world-writable \
temp directory, are much stronger signals than a binary name in isolation.
- Reserve action='kill' for severity='critical' cases where you have high \
confidence (>0.85) this is active, ongoing exploitation -- e.g. a shell \
spawned with its stdin/stdout wired to a network socket (a classic reverse \
shell pattern), or execution from a hidden path immediately following a \
permission change that made it executable. A human reviews every 'alert' \
action; only bypass that review for genuinely unambiguous cases.
- Be calibrated: do not report confidence above 0.85 unless the argument \
list gives you specific, unambiguous evidence, not just a suspicious \
binary name.
- Call emit_threat_verdict exactly once, with your final answer.
"""


class ThreatHuntingEngine:
    """Wraps the Claude API. Swap `_call_model` to point at a different
    provider/model without touching the rest of the service -- `evaluate`
    and the confidence-floor enforcement below are provider-agnostic."""

    def __init__(self, settings: Settings):
        self._settings = settings
        self._client = anthropic.Anthropic(
            api_key=settings.anthropic_api_key,
            base_url=settings.anthropic_base_url,
        )
        self._system_prompt = _build_system_prompt()

    def evaluate(self, event: ExecEvent) -> Verdict:
        try:
            response = self._call_model(event)
        except anthropic.APIError as exc:
            logger.error("LLM call failed for pid=%s: %s", event.pid, exc)
            return self._fallback_verdict(f"LLM unavailable: {exc}")

        for block in response.content:
            if block.type == "tool_use" and block.name == "emit_threat_verdict":
                return self._parse_tool_input(block.input, event)

        logger.warning("model returned no tool_use block for pid=%s", event.pid)
        return self._fallback_verdict("model returned no structured verdict")

    def _call_model(self, event: ExecEvent) -> anthropic.types.Message:
        return self._client.messages.create(
            model=self._settings.model,
            max_tokens=self._settings.max_tokens,
            system=self._system_prompt,
            tools=[_VERDICT_TOOL],
            tool_choice={"type": "tool", "name": "emit_threat_verdict"},
            messages=[{"role": "user", "content": self._build_user_prompt(event)}],
        )

    def _parse_tool_input(self, raw: dict, event: ExecEvent) -> Verdict:
        try:
            verdict = Verdict.model_validate(raw)
        except Exception as exc:  # noqa: BLE001 -- any schema drift must fail safe, not crash the request
            logger.error("verdict validation failed for pid=%s: %s (raw=%s)", event.pid, exc, raw)
            return self._fallback_verdict("verdict failed local schema validation")

        if not is_known_technique(verdict.mitre_technique):
            logger.warning(
                "model returned unrecognized technique %r for pid=%s; downgrading to %s",
                verdict.mitre_technique, event.pid, NONE_TECHNIQUE,
            )
            verdict.mitre_technique = NONE_TECHNIQUE

        # Server-side authority boundary: never let a single LLM call
        # unilaterally authorize a kill, regardless of what it claims.
        floor = self._settings.kill_confidence_floor
        if verdict.action == Action.KILL and (
            verdict.severity != Severity.CRITICAL or verdict.confidence < floor
        ):
            logger.warning(
                "downgrading kill->alert for pid=%s: severity=%s confidence=%.2f (floor=%.2f)",
                event.pid, verdict.severity, verdict.confidence, floor,
            )
            verdict.action = Action.ALERT

        return verdict

    @staticmethod
    def _build_user_prompt(event: ExecEvent) -> str:
        return json.dumps(
            {
                "pid": event.pid,
                "uid": event.uid,
                "comm": event.comm,
                "filename": event.filename,
                "args": event.args,
                "command_line": event.command_line,
                "truncated": event.truncated,
            },
            indent=2,
        )

    @staticmethod
    def _fallback_verdict(reason: str) -> Verdict:
        # Fail safe, not fail open: if the model is unreachable or returns
        # something we can't validate, alert a human rather than silently
        # treating the event as benign.
        return Verdict(
            severity=Severity.MEDIUM,
            action=Action.ALERT,
            mitre_technique=NONE_TECHNIQUE,
            mitre_tactic="N/A",
            confidence=0.0,
            rationale=f"Automated fallback verdict: {reason}",
        )
