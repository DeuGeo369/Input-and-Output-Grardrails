"""Result types shared by all guardrails."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class Action(str, Enum):
    ALLOW = "ALLOW"
    REDACT = "REDACT"
    ALLOW_WITH_DISCLAIMER = "ALLOW_WITH_DISCLAIMER"
    ALLOW_WITH_SAFETY_NOTICE = "ALLOW_WITH_SAFETY_NOTICE"
    ESCALATE = "ESCALATE"            # answer general info, flag for professional review
    QUARANTINE = "QUARANTINE"        # drop an untrusted document, keep the request
    REGENERATE = "REGENERATE"
    FALLBACK = "FALLBACK"
    REFUSE = "REFUSE"
    REFUSE_WITH_SUPPORT = "REFUSE_WITH_SUPPORT"
    BLOCK = "BLOCK"


@dataclass
class GuardrailResult:
    """Uniform result returned by every guardrail."""

    guardrail: str
    flagged: bool
    action: Action
    score: float = 0.0
    findings: list[dict[str, Any]] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)
    sanitized_text: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["action"] = self.action.value
        return d
