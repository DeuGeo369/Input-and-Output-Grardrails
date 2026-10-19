"""Prompt-injection detection.

Layers, cheapest first:
1. Normalisation  - NFKC, invisible-character removal, leetspeak reversal and
                    re-joining of spaced-out letters ("i g n o r e").
2. Pattern bank   - regexes grouped by attack category, each with a weight.
3. Decoding       - base64 / hex blobs are decoded and re-scanned, because an
                    encoded payload is a common way around keyword filters.
4. Scoring        - category weights combine as 1 - prod(1 - w); the request
                    is BLOCKED at >= block_threshold.

The same detector scans untrusted reference documents supplied with a request
(indirect injection). There the action is QUARANTINE: the document is dropped
but the user's question is still answered.

Limitations: English-only patterns, no semantic model, so paraphrased or
non-English attacks can pass (see failure analysis).
"""
from __future__ import annotations

import base64
import binascii
import re

from guardrails.text_utils import deobfuscate, normalize
from guardrails.types import Action, GuardrailResult

_TARGET = r"(?:instructions?|prompts?|rules?|directions?|guidelines?|constraints?|polic(?:y|ies)|guardrails?|programming|system\s+message)"
_PRIOR = r"(?:previous|prior|above|earlier|preceding|original|initial|existing|all|your|the|any|these|those)"

CATEGORIES: dict[str, tuple[float, list[str]]] = {
    "instruction_override": (0.6, [
        rf"\b(?:ignore|disregard|forget|override|bypass|skip|drop|abandon)\b(?:\s+\w+){{0,3}}?\s+{_PRIOR}\s+(?:\w+\s+){{0,2}}?{_TARGET}",
        rf"\b(?:ignore|disregard|forget)\s+(?:everything|all)\b(?:\s+\w+){{0,3}}\s+(?:above|before|said|told)",
        rf"\b(?:new|updated|revised|real)\s+(?:system\s+)?(?:instructions?|rules?|prompt)\s*:",
        r"\bfrom\s+now\s+on\b.{0,40}\b(?:you\s+(?:are|will|must)|respond|answer|act)\b",
        r"\b(?:do\s+not|don'?t|never)\s+(?:follow|obey|apply)\s+(?:your|the|any)\s+(?:rules|instructions|guidelines|policy)",
        r"\bwithout\s+(?:any\s+)?(?:the\s+)?(?:disclaimers?|safety\s+(?:checks?|filters?)|restrictions?|guardrails?)\b",
    ]),
    "role_hijack": (0.5, [
        r"\byou\s+are\s+(?:now\s+)?(?:a|an)?\s*(?:free|unrestricted|unfiltered|uncensored|jailbroken|evil|unconstrained)\b",
        r"\b(?:dan|d\.a\.n)\b(?:\s+mode)?|\bdo\s+anything\s+now\b|\bjail\s*break",
        r"\b(?:pretend|act|behave|roleplay|role-play)\b.{0,40}\b(?:no|without)\s+(?:rules|restrictions|limits|filters|guidelines|ethics)",
        r"\b(?:developer|god|admin|debug|maintenance)\s+mode\b",
        r"\byou\s+(?:have\s+been|are)\s+(?:replaced|overridden|reprogrammed|freed|unlocked)",
    ]),
    "prompt_extraction": (0.6, [
        rf"\b(?:print|output|reveal|show|display|repeat|dump|leak|recite|spell\s+out|tell\s+me|give\s+me|share|restate)\b.{{0,40}}\b(?:your|hidden|secret|internal|initial|original|system|the\s+(?:system|hidden|secret|internal|initial|original|full))\s+(?:\w+\s+)?(?:{_TARGET}|configuration|config|setup|canary|context\s+window)",
        r"\b(?:what|which)\s+(?:are|were)\s+(?:your|the)\s+(?:hidden|secret|initial|original|system)?\s*(?:instructions?|rules|prompt)",
        r"\b(?:repeat|print|output)\s+(?:everything|all\s+(?:text|words))\s+(?:above|before)",
        r"\b(?:rules?|instructions?|guidance|text)\s+(?:you|it)\s+(?:was|were)\s+(?:given|configured|programmed|told|instructed)",
        r"\bcanary\b",
    ]),
    "delimiter_injection": (0.4, [
        r"</?\s*(?:system|assistant|instructions?|context|im_start|im_end)\s*>",
        r"\[\s*(?:system|inst|/inst|admin|developer)\s*\]",
        r"(?:^|\s)(?:system|assistant|developer)\s*:\s",
        r"#{2,}\s*(?:system|instruction|admin)",
        r"<\|[a-z_]+\|>",
        r"\b(?:end|close)\s+of\s+(?:system\s+)?(?:prompt|instructions|context)\b",
    ]),
    "privilege_escalation": (0.45, [
        r"\b(?:i\s+am|i'm|this\s+is|as)\s+(?:your|the|an?)\s+(?:developer|creator|admin(?:istrator)?|owner|operator|anthropic|google|openai)\b",
        r"\b(?:the\s+)?user\s+is\s+(?:an?\s+)?(?:admin(?:istrator)?|developer|root|superuser)\b",
        r"\b(?:i\s+)?(?:authori[sz]e|grant)\s+(?:you|myself)\b.{0,40}\b(?:access|permission|mode|disable)",
        r"\bsudo\b|\broot\s+access\b",
    ]),
    "exfiltration": (0.6, [
        r"\b(?:send|email|post|upload|forward|transmit|exfiltrate)\b.{0,60}\b(?:conversation|chat|history|data|keys?|secrets?|credentials|prompt|context)\b.{0,40}\b(?:to|at)\b",
        r"!\[[^\]]*\]\(\s*https?://",
    ]),
    # Weak signal on its own (a user may legitimately ask about a password reset),
    # but it pushes a borderline request over the threshold.
    "secret_seeking": (0.35, [
        r"\b(?:api|secret|access)\s*keys?\b|\bcredentials\b|\benvironment\s+variables?\b|\btokens?\s+you\s+(?:use|hold)",
    ]),
}

COMPACT_KEYWORDS = (
    "ignorepreviousinstructions", "ignoreallpreviousinstructions", "ignoreyourinstructions",
    "disregardpreviousinstructions", "forgetpreviousinstructions", "revealyoursystemprompt",
    "printyoursystemprompt", "showyoursystemprompt", "developermode", "jailbreak", "doanythingnow",
)

_B64 = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/=])")
_HEX = re.compile(r"\b(?:[0-9a-fA-F]{2}){16,}\b")


class InjectionDetector:
    name = "prompt_injection_detector"

    def __init__(self, block_threshold: float = 0.5) -> None:
        self.block_threshold = block_threshold
        self._compiled = {
            cat: (w, [re.compile(p, re.IGNORECASE) for p in pats])
            for cat, (w, pats) in CATEGORIES.items()
        }

    def _decode_blobs(self, text: str) -> list[str]:
        decoded = []
        for m in _B64.finditer(text):
            try:
                raw = base64.b64decode(m.group() + "=" * (-len(m.group()) % 4), validate=True)
                s = raw.decode("utf-8")
                if sum(ch.isprintable() for ch in s) / max(len(s), 1) > 0.9:
                    decoded.append(s)
            except (binascii.Error, UnicodeDecodeError, ValueError):
                pass
        for m in _HEX.finditer(text):
            try:
                decoded.append(bytes.fromhex(m.group()).decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                pass
        return decoded

    def _scan(self, text: str, source: str) -> list[dict]:
        hits = []
        for cat, (w, pats) in self._compiled.items():
            for p in pats:
                m = p.search(text)
                if m:
                    hits.append({"category": cat, "weight": w, "source": source,
                                 "match": m.group()[:80]})
                    break  # one hit per category per view is enough
        return hits

    def check(self, text: str, untrusted_document: bool = False) -> GuardrailResult:
        views = {"raw": normalize(text), "deobfuscated": deobfuscate(text)}
        decoded = self._decode_blobs(normalize(text))
        for i, d in enumerate(decoded):
            views[f"decoded_{i}"] = deobfuscate(d)

        hits: list[dict] = []
        for source, view in views.items():
            hits.extend(self._scan(view, source))
            # Compact view catches keywords split by spaces, dots or symbols.
            compact = re.sub(r"[^a-z]", "", view.lower())
            for kw in COMPACT_KEYWORDS:
                if kw in compact:
                    hits.append({"category": "obfuscated_keyword", "weight": 0.6, "source": source + "_compact", "match": kw})
                    break

        cats = {}
        for h in hits:
            cats.setdefault(h["category"], h["weight"])
        if decoded and cats:
            cats["obfuscation"] = 0.3  # hiding instructions in an encoding is itself a signal

        p_clean = 1.0
        for w in cats.values():
            p_clean *= 1 - w
        score = round(1 - p_clean, 3)

        flagged = score >= self.block_threshold
        if flagged:
            action = Action.QUARANTINE if untrusted_document else Action.BLOCK
        else:
            action = Action.ALLOW
        return GuardrailResult(
            guardrail=self.name,
            flagged=flagged,
            action=action,
            score=score,
            findings=hits,
            details={"categories": sorted(cats), "decoded_payloads": len(decoded),
                     "threshold": self.block_threshold},
        )
