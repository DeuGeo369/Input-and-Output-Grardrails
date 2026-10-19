"""Output schema validation.

The model must return a single JSON object matching ``AssistantResponse``.
Pydantic (strict types, extra fields forbidden) checks structure and types;
``validate_against_context`` adds the cross-field rules a JSON schema cannot
express on its own: an answer must cite at least one passage, and every cited
passage must be one that was actually retrieved for this request.
"""
from __future__ import annotations

import json
import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictStr, ValidationError, field_validator, model_validator

from guardrails.types import Action, GuardrailResult

CITATION_ID = re.compile(r"^(?:KB|USR)-\d{3}$")


class AssistantResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    answer: StrictStr = Field(min_length=1, max_length=1500)
    citations: list[StrictStr] = Field(default_factory=list, max_length=5)
    confidence: Literal["low", "medium", "high"]
    response_type: Literal["answer", "refusal", "clarification"]
    requires_professional_review: StrictBool

    @field_validator("citations")
    @classmethod
    def _citation_format(cls, v: list[str]) -> list[str]:
        bad = [c for c in v if not CITATION_ID.match(c)]
        if bad:
            raise ValueError(f"citation ids must look like KB-001 / USR-001, got {bad}")
        if len(set(v)) != len(v):
            raise ValueError("duplicate citation ids")
        return v

    @model_validator(mode="after")
    def _answer_needs_citation(self) -> "AssistantResponse":
        if self.response_type == "answer" and not self.citations:
            raise ValueError("response_type 'answer' requires at least one citation")
        return self


def _strip_fences(raw: str) -> str:
    m = re.search(r"```(?:json)?\s*(\{.*\})\s*```", raw, re.DOTALL)
    return m.group(1) if m else raw.strip()


class SchemaValidator:
    name = "schema_validator"

    def check(self, raw: str, allowed_citations: set[str]) -> tuple[GuardrailResult, AssistantResponse | None]:
        errors: list[str] = []
        parsed: AssistantResponse | None = None
        try:
            data = json.loads(_strip_fences(raw))
            if not isinstance(data, dict):
                raise ValueError("top-level JSON value must be an object")
            parsed = AssistantResponse.model_validate(data)
        except json.JSONDecodeError as e:
            errors.append(f"not valid JSON: {e.msg} at pos {e.pos}")
        except ValidationError as e:
            for err in e.errors():
                loc = ".".join(str(x) for x in err["loc"]) or "<root>"
                errors.append(f"{loc}: {err['msg']}")
        except ValueError as e:
            errors.append(str(e))

        if parsed is not None:
            unknown = [c for c in parsed.citations if c not in allowed_citations]
            if unknown:
                errors.append(f"citations not in retrieved context: {unknown}")
                parsed = None

        ok = not errors
        return (
            GuardrailResult(
                guardrail=self.name,
                flagged=not ok,
                action=Action.ALLOW if ok else Action.REGENERATE,
                score=1.0 if ok else 0.0,
                findings=[{"error": e} for e in errors],
            ),
            parsed,
        )
