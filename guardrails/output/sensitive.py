"""Sensitive-information detection on model output.

Two classes of leak, handled differently:
* Personal data (emails, phones, IDs...)        -> REDACT and still answer.
* Secrets / system internals (API keys, private
  keys, the canary token, verbatim system-prompt
  text)                                          -> BLOCK, return a safe fallback.

The canary is a random token placed in the system prompt; it has no business
appearing in an answer, so seeing it proves the prompt leaked. The prompt-leak
check looks for any 8-word run copied from the system prompt.
"""
from __future__ import annotations

import re

from guardrails.input.pii import PIIDetector
from guardrails.text_utils import tokens
from guardrails.types import Action, GuardrailResult

SECRET_PATTERNS = {
    "GOOGLE_API_KEY": re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    "OPENAI_STYLE_KEY": re.compile(r"\bsk-[A-Za-z0-9_\-]{20,}\b"),
    "AWS_ACCESS_KEY": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "PRIVATE_KEY": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "BEARER_TOKEN": re.compile(r"(?i)\bbearer\s+[A-Za-z0-9\-._~+/]{20,}=*"),
    "CONNECTION_STRING": re.compile(r"\b(?:postgres(?:ql)?|mysql|mongodb)://\S+:\S+@\S+"),
}


def _shingles(text: str, n: int) -> set[tuple[str, ...]]:
    t = tokens(text)
    return {tuple(t[i : i + n]) for i in range(len(t) - n + 1)}


class SensitiveOutputDetector:
    name = "sensitive_output_detector"

    def __init__(self, canary: str, system_prompt: str, pii_allowlist: set[str] | None = None, shingle: int = 8) -> None:
        self.canary = canary
        self.pii = PIIDetector(allowlist=pii_allowlist)
        self.prompt_shingles = _shingles(system_prompt, shingle)
        self.shingle = shingle

    def check(self, text: str) -> GuardrailResult:
        findings: list[dict] = []
        if self.canary and self.canary in text:
            findings.append({"type": "CANARY_TOKEN", "class": "secret"})
        for name, pat in SECRET_PATTERNS.items():
            if pat.search(text):
                findings.append({"type": name, "class": "secret"})
        leaked = _shingles(text, self.shingle) & self.prompt_shingles
        if leaked:
            findings.append({"type": "SYSTEM_PROMPT_TEXT", "class": "secret", "overlap_ngrams": len(leaked)})

        pii = self.pii.find(text)
        findings.extend({**f, "class": "pii"} for f in pii)

        if any(f["class"] == "secret" for f in findings):
            action = Action.BLOCK
        elif pii:
            action = Action.REDACT
        else:
            action = Action.ALLOW
        return GuardrailResult(
            guardrail=self.name,
            flagged=bool(findings),
            action=action,
            score=1.0 if findings else 0.0,
            findings=findings,
            details={"types": sorted({f["type"] for f in findings})},
            sanitized_text=self.pii.redact(text, pii) if pii else text,
        )
