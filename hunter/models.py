"""Pydantic models for the AI Threat Hunter's HTTP contract.

`ExecEvent` mirrors `broker/internal/events/events.go`'s `Event` struct
field-for-field (same JSON keys) -- FastAPI validates every inbound
POST /v1/evaluate body against it. `Verdict` mirrors
`broker/internal/hunter/verdict.go`'s `Verdict` struct; keep both in sync
if you add a field on either side.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field, field_validator


class Severity(str, Enum):
    BENIGN = "benign"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Action(str, Enum):
    IGNORE = "ignore"
    MONITOR = "monitor"
    ALERT = "alert"
    KILL = "kill"


class ExecEvent(BaseModel):
    """A single normalized process-execution observation, as forwarded by
    the Go broker. `timestamp` arrives as an RFC3339 string (Go's
    `encoding/json` renders `time.Time` that way by default)."""

    timestamp: str
    pid: int
    tid: int
    uid: int
    gid: int
    comm: str
    filename: str
    args: list[str] = Field(default_factory=list)
    argc: int = 0
    truncated: bool = False
    command_line: str = ""


class Verdict(BaseModel):
    """The AI hunter's assessment of a single ExecEvent."""

    severity: Severity
    action: Action
    mitre_technique: str = Field(
        description="A MITRE ATT&CK technique ID (e.g. 'T1059.006') or 'NONE'."
    )
    mitre_tactic: str = Field(description="The corresponding ATT&CK tactic, or 'N/A'.")
    confidence: float = Field(ge=0.0, le=1.0)
    rationale: str = Field(description="One or two sentence, analyst-readable justification.")

    @field_validator("confidence")
    @classmethod
    def _clamp_confidence(cls, v: float) -> float:
        # Belt-and-suspenders against a provider returning something just
        # outside [0, 1] due to floating point noise; Field(ge=0, le=1)
        # already rejects grossly out-of-range values at validation time.
        return max(0.0, min(1.0, v))
