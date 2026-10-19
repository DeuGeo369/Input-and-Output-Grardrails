"""PII detection and redaction (used on user input AND on model output).

Approach: regular expressions for structured identifiers, with checksum
validation where the identifier has one (TFN, Medicare, payment card). Checksums
cut false positives on long numbers that are common in surveying (mark numbers,
coordinates, plan numbers).

Action: every finding is replaced by a typed placeholder (e.g. "[EMAIL]") before
the text reaches the model. HIGH-severity identifiers additionally trigger a
notice telling the user not to share them.

Known limitations (see report): no named-entity model, so personal names are
only caught in the explicit "my name is ..." form; street addresses only when
they use a common street-type suffix; overseas phone/ID formats are not covered.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from guardrails.types import Action, GuardrailResult


def _digits(s: str) -> str:
    return re.sub(r"\D", "", s)


def _tfn_valid(s: str) -> bool:
    d = _digits(s)
    if len(d) != 9:
        return False
    w = [1, 4, 3, 7, 5, 8, 6, 9, 10]
    return sum(int(c) * x for c, x in zip(d, w)) % 11 == 0


def _medicare_valid(s: str) -> bool:
    d = _digits(s)
    if len(d) not in (10, 11) or d[0] not in "23456":
        return False
    w = [1, 3, 7, 9, 1, 3, 7, 9]
    return sum(int(c) * x for c, x in zip(d[:8], w)) % 10 == int(d[8])


def _luhn_valid(s: str) -> bool:
    d = _digits(s)
    if not 13 <= len(d) <= 19:
        return False
    total = 0
    for i, c in enumerate(reversed(d)):
        n = int(c)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


@dataclass(frozen=True)
class PIIRule:
    name: str
    pattern: re.Pattern
    severity: str  # "high" | "medium"
    validator: object = None
    group: int = 0


_STREET_TYPES = (
    r"Street|St|Road|Rd|Avenue|Ave|Drive|Dr|Lane|Ln|Place|Pl|Court|Ct|Crescent|Cres|"
    r"Parade|Pde|Highway|Hwy|Close|Cl|Way|Terrace|Tce|Boulevard|Blvd|Circuit|Cct"
)

# Order matters: earlier rules win when matches overlap.
RULES: list[PIIRule] = [
    PIIRule("EMAIL", re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b"), "medium"),
    PIIRule("CREDIT_CARD", re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)"), "high", _luhn_valid),
    PIIRule("MEDICARE", re.compile(r"(?<!\d)[2-6]\d{3}[ -]?\d{5}[ -]?\d(?:[ -]?\d)?(?!\d)"), "high", _medicare_valid),
    PIIRule("TFN", re.compile(r"(?<!\d)\d{3}[ -]?\d{3}[ -]?\d{3}(?!\d)"), "high", _tfn_valid),
    PIIRule("PHONE", re.compile(r"(?<!\d)(?<!\d\.)(?:\+?61[ -]?|0)4\d{2}[ -]?\d{3}[ -]?\d{3}(?!\d|\.\d)"), "medium"),
    PIIRule("PHONE", re.compile(r"(?<!\d)(?<!\d\.)(?:\+?61[ -]?|\(0|0)[2378]\)?[ -]?\d{4}[ -]?\d{4}(?!\d|\.\d)"), "medium"),
    PIIRule(
        "DRIVER_LICENCE",
        re.compile(r"(?i)\b(?:driver'?s?\s+)?licen[cs]e\s+(?:no\.?|number|#)?\s*(?:is\s+)?:?\s*((?=[A-Z]*\d)[A-Z0-9]{6,10})\b"),
        "high",
        group=1,
    ),
    PIIRule("IP_ADDRESS", re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"), "medium"),
    PIIRule(
        "STREET_ADDRESS",
        re.compile(rf"\b\d{{1,5}}[A-Za-z]?\s+(?:[A-Z][a-z]+\s){{1,3}}(?:{_STREET_TYPES})\b\.?"),
        "medium",
    ),
    PIIRule("PERSON_NAME", re.compile(r"(?i:\bmy name is)\s+([A-Z][a-z]+(?:\s[A-Z][a-z]+){0,2})"), "medium", group=1),
]


class PIIDetector:
    name = "pii_detector"

    def __init__(self, allowlist: set[str] | None = None) -> None:
        # Values that are public and may pass (e.g. an official helpline).
        self.allowlist = {a.lower() for a in (allowlist or set())}

    def find(self, text: str) -> list[dict]:
        found: list[dict] = []
        taken: list[tuple[int, int]] = []
        for rule in RULES:
            for m in rule.pattern.finditer(text):
                start, end = m.span(rule.group)
                value = m.group(rule.group)
                if value.lower() in self.allowlist:
                    continue
                if rule.validator and not rule.validator(value):
                    continue
                if any(start < e and end > s for s, e in taken):
                    continue
                taken.append((start, end))
                found.append({"type": rule.name, "start": start, "end": end,
                              "severity": rule.severity, "masked": _mask(value)})
        return sorted(found, key=lambda f: f["start"])

    def redact(self, text: str, findings: list[dict]) -> str:
        out = text
        for f in sorted(findings, key=lambda f: f["start"], reverse=True):
            out = out[: f["start"]] + f"[{f['type']}]" + out[f["end"]:]
        return out

    def check(self, text: str) -> GuardrailResult:
        findings = self.find(text)
        flagged = bool(findings)
        return GuardrailResult(
            guardrail=self.name,
            flagged=flagged,
            action=Action.REDACT if flagged else Action.ALLOW,
            score=1.0 if flagged else 0.0,
            findings=findings,
            details={"types": sorted({f["type"] for f in findings}),
                     "high_severity": any(f["severity"] == "high" for f in findings)},
            sanitized_text=self.redact(text, findings) if flagged else text,
        )


def _mask(value: str) -> str:
    """Keep the shape for the audit log without storing the value."""
    if len(value) <= 4:
        return "*" * len(value)
    return value[:2] + "*" * (len(value) - 4) + value[-2:]
