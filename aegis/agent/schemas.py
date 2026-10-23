"""AEGIS agent LLM-output schemas (PHASES P0.4).

FROZEN after P0 (STRUCTURE invariant I-8). These are the ONLY shapes the LLM
is allowed to produce; every LLM call uses one of them via
``with_structured_output`` and is validated before use.
"""

from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field

__all__ = [
    "NextStep",
    "Target",
    "NextStepDecision",
    "Claim",
    "Explanation",
    "FixDraft",
]


class NextStep(str, Enum):
    request_source_evidence = "request_source_evidence"
    request_runtime_retest = "request_runtime_retest"
    request_crypto_scan = "request_crypto_scan"
    link_and_score = "link_and_score"
    mark_sufficient = "mark_sufficient"
    escalate_to_human = "escalate_to_human"


class Target(BaseModel):
    route: str | None = None
    function: str | None = None


class NextStepDecision(BaseModel):
    finding_id: str
    next_step: NextStep
    target: Target = Field(default_factory=Target)
    reason_evidence_ids: list[str] = Field(min_length=1)


class Claim(BaseModel):
    """One explanation sentence produced by the LLM. Distinct from the DB
    table ``evidence.models.Claim`` (conflict C27)."""

    field: Literal["what", "impact", "exploit", "fix"]
    text: str = Field(max_length=400)
    evidence_ids: list[str] = Field(min_length=1)


class Explanation(BaseModel):
    finding_id: str
    claims: list[Claim] = Field(max_length=12)


class FixDraft(BaseModel):
    finding_id: str
    unified_diff: str
    evidence_ids: list[str] = Field(default_factory=list)
