"""A small, curated slice of MITRE ATT&CK (Enterprise) relevant to Linux
host process-execution telemetry.

This is passed into the LLM's system prompt as grounding context, so the
model classifies against a known, closed set of technique IDs rather than
inventing plausible-looking ones -- and is used again afterwards to
validate the model's output. Not exhaustive: extend it as the sensor's
telemetry surface grows (e.g. add T1547 persistence techniques once the
kernel-space program also hooks cron/systemd-unit writes).
"""

from __future__ import annotations

TECHNIQUES: dict[str, str] = {
    "T1059": "Command and Scripting Interpreter",
    "T1059.004": "Command and Scripting Interpreter: Unix Shell",
    "T1059.006": "Command and Scripting Interpreter: Python",
    "T1071.001": "Application Layer Protocol: Web Protocols (C2 egress)",
    "T1105": "Ingress Tool Transfer",
    "T1222.002": "File and Directory Permissions Modification: Linux and Mac File Permissions",
    "T1564.001": "Hide Artifacts: Hidden Files and Directories",
    "T1036": "Masquerading",
    "T1036.005": "Masquerading: Match Legitimate Name or Location",
    "T1053.003": "Scheduled Task/Job: Cron",
    "T1548.001": "Abuse Elevation Control Mechanism: Setuid and Setgid",
    "T1090": "Proxy",
    "T1046": "Network Service Discovery",
}

TACTICS_BY_TECHNIQUE: dict[str, str] = {
    "T1059": "Execution",
    "T1059.004": "Execution",
    "T1059.006": "Execution",
    "T1071.001": "Command and Control",
    "T1105": "Command and Control",
    "T1222.002": "Defense Evasion",
    "T1564.001": "Defense Evasion",
    "T1036": "Defense Evasion",
    "T1036.005": "Defense Evasion",
    "T1053.003": "Persistence",
    "T1548.001": "Privilege Escalation",
    "T1090": "Command and Control",
    "T1046": "Discovery",
}

NONE_TECHNIQUE = "NONE"  # sentinel for "no corresponding technique -- benign"


def is_known_technique(technique_id: str) -> bool:
    return technique_id == NONE_TECHNIQUE or technique_id in TECHNIQUES


def prompt_reference_block() -> str:
    lines = [f"- {tid}: {desc}" for tid, desc in TECHNIQUES.items()]
    lines.append(f"- {NONE_TECHNIQUE}: no corresponding technique -- benign activity")
    return "\n".join(lines)
