"""Sensitive-topic classification with a per-category handling policy.

Approach: a weighted pattern lexicon per category. Every matching category is
reported; the one with the most restrictive action becomes the primary label.
The lexicon is domain-specific (NSW surveying), which keeps it small and
auditable, but means it only knows the phrasings it was written for.

Policy (most -> least restrictive):
  self_harm                  REFUSE_WITH_SUPPORT  no answer; crisis resources
  survey_fraud               REFUSE               tampering with marks, falsifying plans
  privacy_surveillance       REFUSE               locating/watching identifiable people
  professional_certification ESCALATE             general info + "needs a registered surveyor"
  safety_critical            ALLOW_WITH_SAFETY_NOTICE
  legal_dispute              ALLOW_WITH_DISCLAIMER  general info + "not legal advice"
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from guardrails.text_utils import normalize
from guardrails.types import Action, GuardrailResult

_MARK = r"(?:survey\s+|boundary\s+|reference\s+|permanent\s+|state\s+survey\s+)?(?:marks?|pegs?|markers?|monuments?|pms?|ssms?|pins?|star\s+pickets?)"


@dataclass(frozen=True)
class Topic:
    name: str
    action: Action
    patterns: tuple[str, ...]


TOPICS: tuple[Topic, ...] = (
    Topic("self_harm", Action.REFUSE_WITH_SUPPORT, (
        r"\b(?:kill|hurt|harm|cut)\s+myself\b",
        r"\bsuicid\w*",
        r"\bend\s+(?:it\s+all|my\s+life)\b",
        r"\b(?:want|wish)\s+(?:to\s+be\s+|i\s+was\s+|i\s+were\s+)?(?:to\s+)?die\b",
        r"\bno\s+reason\s+to\s+live\b",
    )),
    Topic("survey_fraud", Action.REFUSE, (
        rf"\b(?:move|moving|shift|relocate|pull\s+(?:out|up)|remove|dig\s+up|destroy|tamper\w*\s+with|knock\s+out|bury)\b.{{0,40}}\b{_MARK}\b",
        r"\b(?:falsif\w*|fake|forg(?:e|ing|ed)|fabricat\w*|backdat\w*|doctor(?:ing)?|alter(?:ing)?)\b.{0,40}\b(?:survey|plan|certificate|signature|measurements?|reports?|data|field\s*notes|readings)\b",
        r"\bsign\w*\b.{0,40}\b(?:as\s+(?:a\s+)?registered|under\s+(?:someone|another|his|her)|someone\s+else'?s)",
        r"\b(?:without|before)\s+(?:being\s+)?(?:registered|licen[cs]ed)\b.{0,40}\b(?:sign|certify|lodge)",
        r"\bwithout\s+(?:anyone|the\s+neighbou?rs?|council)\s+(?:noticing|knowing|finding\s+out)",
    )),
    Topic("privacy_surveillance", Action.REFUSE, (
        r"\b(?:find|get|look\s*up|tell\s+me|give\s+me)\b.{0,40}\b(?:home\s+address|phone\s+number|mobile|email|who\s+lives|personal\s+details)\b",
        r"\b(?:owner'?s?|resident'?s?|occupant'?s?)\s+(?:name|details|phone|email|address)\b",
        r"\b(?:track|follow|spy\s+on|stalk|watch|monitor|film|photograph)\w*\b.{0,40}\b(?:neighbou?rs?|my\s+ex|wife|husband|partner|girlfriend|boyfriend|someone|that\s+person|what\s+they)",
        r"\bdrone\b.{0,60}\b(?:backyard|window|bedroom|pool)\b",
    )),
    Topic("professional_certification", Action.ESCALATE, (
        r"\b(?:certify|certification\s+of|sign\s*-?\s*off|sign\s+off|approve|lodge|register)\b.{0,40}\b(?:my|this|our|a)\b.{0,20}\b(?:plan|survey|subdivision|identification\s+survey|surveyor'?s\s+report|strata)\b",
        r"\bis\s+(?:this|my|our)\s+(?:survey|plan|boundary|subdivision)\s+(?:correct|valid|accurate|compliant|legal)\b",
    )),
    Topic("safety_critical", Action.ALLOW_WITH_SAFETY_NOTICE, (
        r"\b(?:live|energi[sz]ed|overhead|high[\s-]voltage|transmission|power)\s*(?:lines?|conductors?|wires?|powerlines?|towers?)\b",
        r"\b(?:exclusion\s+zone|confined\s+space|trench\w*|excavation|traffic\s+control|working\s+at\s+heights?|cliff\s+edge|unstable\s+(?:ground|embankment)|snake\s+bite|heat\s+stress)\b",
    )),
    Topic("legal_dispute", Action.ALLOW_WITH_DISCLAIMER, (
        r"\b(?:boundary|fence|encroach\w*|easement|neighbou?r)\b.{0,60}\b(?:dispute|disagree\w*|argument|fight|court|tribunal|sue|suing|lawyer|legal\w*|compensation)\b",
        r"\b(?:sue|suing|lawsuit|litigation|ncat|adverse\s+possession|land\s+and\s+environment\s+court)\b",
        r"\b(?:am\s+i|are\s+we|is\s+(?:he|she|it|my\s+neighbou?r))\s+(?:legally\s+)?(?:liable|allowed|entitled|responsible)\b",
    )),
)

_ACTION_RANK = {
    Action.REFUSE_WITH_SUPPORT: 6, Action.REFUSE: 5, Action.ESCALATE: 4,
    Action.ALLOW_WITH_SAFETY_NOTICE: 3, Action.ALLOW_WITH_DISCLAIMER: 2, Action.ALLOW: 0,
}


class SensitiveTopicClassifier:
    name = "sensitive_topic_classifier"

    def __init__(self) -> None:
        self._compiled = [(t, [re.compile(p, re.IGNORECASE) for p in t.patterns]) for t in TOPICS]

    def check(self, text: str) -> GuardrailResult:
        t = normalize(text)
        matched = []
        for topic, pats in self._compiled:
            for p in pats:
                m = p.search(t)
                if m:
                    matched.append({"topic": topic.name, "action": topic.action.value, "match": m.group()[:80]})
                    break
        if not matched:
            return GuardrailResult(self.name, False, Action.ALLOW, 0.0, [], {"primary": "none", "topics": []})
        primary = max(matched, key=lambda m: _ACTION_RANK[Action(m["action"])])
        return GuardrailResult(
            guardrail=self.name,
            flagged=True,
            action=Action(primary["action"]),
            score=1.0,
            findings=matched,
            details={"primary": primary["topic"], "topics": [m["topic"] for m in matched]},
        )
