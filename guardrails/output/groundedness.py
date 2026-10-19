"""Groundedness validation: are the answer's claims supported by the cited passages?

Approach (deterministic, no second model):
1. Split the answer into sentences; skip non-factual sentences (advice,
   referrals, hedges such as "consult a registered surveyor").
2. For each claim, find the best-supporting *sentence* among the cited passages
   using stemmed content-word recall: |claim ∩ source| / |claim|.
3. A claim is SUPPORTED when
     - recall >= min_overlap, and
     - every number in the claim appears somewhere in the same cited passage, and
     - the claim and its best source sentence agree on negation.
4. The answer passes when supported/total >= min_score and no claim with a
   number is unsupported (numeric errors are the costly ones in surveying).

Limitations: lexical overlap cannot check that numbers are attached to the
right subject (zone 56 vs zone 55 in the same passage), cannot judge
paraphrases with low word overlap, and trusts the "non-factual" filter.
"""
from __future__ import annotations

import re

from guardrails.text_utils import content_tokens, has_negation, numbers, sentences
from guardrails.types import Action, GuardrailResult

NON_CLAIM = re.compile(
    r"(?i)^\s*(?:please\s+)?(?:consult|contact|call|phone|ring|email|speak\s+(?:to|with)|seek|check\s+with|refer\s+to|"
    r"for\s+(?:more|further|specific)|you\s+(?:should|may\s+want\s+to)\s+(?:consult|contact|seek|check|confirm|verify)|"
    r"i\s+(?:can(?:not|'t)|could\s+not|couldn't|don't|do\s+not)\b|this\s+is\s+(?:general|not\s+legal))"
)


class GroundednessChecker:
    name = "groundedness_validator"

    def __init__(self, min_overlap: float = 0.6, min_score: float = 0.8) -> None:
        self.min_overlap = min_overlap
        self.min_score = min_score

    def _claim_support(self, claim: str, passages: dict[str, str]) -> dict:
        ctoks = content_tokens(claim)
        cnums = numbers(claim)
        best = {"recall": 0.0, "source": None, "sentence": ""}
        for pid, text in passages.items():
            for s in sentences(text):
                stoks = content_tokens(s)
                recall = len(ctoks & stoks) / max(len(ctoks), 1)
                if recall > best["recall"]:
                    best = {"recall": recall, "source": pid, "sentence": s}
        reasons = []
        if best["recall"] < self.min_overlap:
            reasons.append(f"low overlap ({best['recall']:.2f})")
        if best["source"]:
            missing = cnums - numbers(passages[best["source"]])
            if missing:
                reasons.append(f"numbers not in source: {sorted(missing)}")
            if has_negation(claim) != has_negation(best["sentence"]):
                reasons.append("negation mismatch with source")
        elif cnums:
            reasons.append(f"numbers not in source: {sorted(cnums)}")
        return {
            "claim": claim,
            "supported": not reasons,
            "recall": round(best["recall"], 3),
            "best_source": best["source"],
            "has_number": bool(cnums),
            "reasons": reasons,
        }

    def check(self, answer: str, passages: dict[str, str]) -> GuardrailResult:
        claims = [s for s in sentences(answer) if not NON_CLAIM.match(s)]
        if not claims:
            return GuardrailResult(self.name, False, Action.ALLOW, 1.0, [], {"claims": 0})
        if not passages:
            results = [{"claim": c, "supported": False, "reasons": ["no cited passages"], "has_number": bool(numbers(c))} for c in claims]
        else:
            results = [self._claim_support(c, passages) for c in claims]
        supported = sum(r["supported"] for r in results)
        score = supported / len(results)
        numeric_failure = any(r["has_number"] and not r["supported"] for r in results)
        ok = score >= self.min_score and not numeric_failure
        return GuardrailResult(
            guardrail=self.name,
            flagged=not ok,
            action=Action.ALLOW if ok else Action.REGENERATE,
            score=round(score, 3),
            findings=[r for r in results if not r["supported"]],
            details={"claims": len(results), "supported": supported,
                     "numeric_failure": numeric_failure, "min_score": self.min_score},
        )
