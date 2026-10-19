"""LLM back-ends.

* ExtractiveMockLLM - deterministic, offline. Answers by quoting the passage
  sentences that best match the question. Used for the evaluation so results
  are reproducible without an API key.
* ScriptedLLM       - returns pre-written raw outputs in order. Used by tests
  to inject faulty outputs (bad JSON, wrong types, unsupported claims, leaks)
  and check the output guardrails catch them.
* GeminiLLM         - optional real model (google-genai SDK, GEMINI_API_KEY).
"""
from __future__ import annotations

import json
import os
from typing import Protocol

from guardrails.text_utils import content_tokens, sentences


class LLM(Protocol):
    def generate(self, system_prompt: str, question: str, passages: dict[str, str], feedback: str | None = None) -> str: ...


def build_user_prompt(question: str, passages: dict[str, str], feedback: str | None) -> str:
    ctx = "\n".join(f"[{pid}] {text}" for pid, text in passages.items())
    prompt = f"REFERENCE PASSAGES:\n{ctx}\n\nQUESTION:\n{question}\n"
    if feedback:
        prompt += f"\nYOUR PREVIOUS ANSWER WAS REJECTED BY A VALIDATOR:\n{feedback}\nReturn a corrected JSON object.\n"
    return prompt


class ExtractiveMockLLM:
    name = "extractive-mock"

    def generate(self, system_prompt, question, passages, feedback=None) -> str:
        q = content_tokens(question)
        scored = []
        for rank, (pid, text) in enumerate(passages.items()):
            for i, s in enumerate(sentences(text)):
                overlap = len(q & content_tokens(s))
                if overlap:
                    # Prefer sentences from higher-ranked passages (retrieval order).
                    scored.append((round(overlap * (1 - 0.2 * rank), 3), -i, pid, s))
        if not scored:
            return json.dumps({
                "answer": "I could not find this in the reference material.",
                "citations": [], "confidence": "low",
                "response_type": "clarification", "requires_professional_review": False,
            })
        scored.sort(reverse=True)
        best = scored[:2]
        best.sort(key=lambda x: (list(passages).index(x[2]), -x[1]))
        answer = " ".join(s for _, _, _, s in best)
        cites = list(dict.fromkeys(pid for _, _, pid, _ in best))
        return json.dumps({
            "answer": answer,
            "citations": cites,
            "confidence": "high" if best[0][0] >= 3 else "medium",
            "response_type": "answer",
            "requires_professional_review": False,
        })


class ScriptedLLM:
    name = "scripted"

    def __init__(self, outputs: list[str]) -> None:
        self.outputs = list(outputs)
        self.calls = 0

    def generate(self, system_prompt, question, passages, feedback=None) -> str:
        out = self.outputs[min(self.calls, len(self.outputs) - 1)]
        self.calls += 1
        return out


class GeminiLLM:
    """Optional real model. Requires `pip install google-genai` and GEMINI_API_KEY."""

    name = "gemini"

    def __init__(self, model: str | None = None) -> None:
        from google import genai  # imported lazily so the project runs without it

        self.client = genai.Client(api_key=os.environ["GEMINI_API_KEY"])
        self.model = model or os.environ.get("GEMINI_MODEL", "gemini-2.5-flash")

    def generate(self, system_prompt, question, passages, feedback=None) -> str:
        resp = self.client.models.generate_content(
            model=self.model,
            contents=build_user_prompt(question, passages, feedback),
            config={"system_instruction": system_prompt, "response_mime_type": "application/json", "temperature": 0.2},
        )
        return resp.text or ""
