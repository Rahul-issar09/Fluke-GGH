"""AEGIS LangGraph state (PHASES P0.4, SYSTEM_DESIGN §5.1) + fix-graph state
(AG00.3).

FROZEN after P0 (STRUCTURE invariant I-8).

Key rule (SD §5.1): state holds **IDs and small normalized summaries only**.
Raw evidence stays in SQLite; nodes fetch what they need. This keeps the LLM
context small and blocks prompt injection from target content.
"""

from __future__ import annotations

import operator
from typing import Annotated, Any, TypedDict

from pydantic import BaseModel

from aegis.agent.schemas import NextStepDecision
from aegis.evidence.models import Mode

__all__ = ["ScanInputs", "AegisState", "FixState"]


class ScanInputs(BaseModel):
    url: str | None = None
    folder: str | None = None
    repo: str | None = None
    identities: str | None = None


class AegisState(TypedDict):
    scan_id: str
    mode: Mode
    inputs: ScanInputs
    plan: list[str]  # ordered stage names
    completed_stages: Annotated[list[str], operator.add]
    open_findings: list[str]  # finding IDs still under investigation
    pending_actions: list[NextStepDecision]  # queued requests for workers
    iterations: int  # investigation loop counter
    max_iterations: int  # default 3
    errors: Annotated[list[str], operator.add]


class FixState(TypedDict):
    """State for the human-in-the-loop fix subgraph (AG00.3, SD §5.7)."""

    fix_id: str
    finding_id: str
    workspace_path: str | None
    diff: str | None
    verify_report: dict[str, Any] | None
    approved: bool
    commit_mode: str | None  # patch | apply | pr
    errors: Annotated[list[str], operator.add]
