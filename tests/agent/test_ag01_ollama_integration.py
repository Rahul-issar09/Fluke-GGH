"""AG01.2 — opt-in integration test against a real local Ollama.

Skipped unless run explicitly with ``-m ollama`` and reachable at
``AEGIS_OLLAMA_URL`` (default http://localhost:11434). Proves the structured
call produces a valid, schema-constrained decision from qwen2.5:7b.
"""

from __future__ import annotations

import os

import httpx
import pytest

from aegis.agent.llm import structured_call
from aegis.agent.schemas import NextStep, NextStepDecision
from aegis.config import ModelSettings

pytestmark = [pytest.mark.phase("AG01"), pytest.mark.ollama, pytest.mark.slow]

_URL = os.getenv("AEGIS_OLLAMA_URL", "http://localhost:11434")
_MODEL = os.getenv("AEGIS_MODEL", "qwen2.5:7b")


def _reachable() -> bool:
    try:
        httpx.get(f"{_URL}/api/tags", timeout=2.0)
        return True
    except Exception:
        return False


async def test_real_qwen_produces_valid_decision():
    if not _reachable():
        pytest.skip(f"Ollama not reachable at {_URL}")

    system = (
        "You are AEGIS's investigation planner. Given a finding summary, choose "
        "exactly one next_step from valid_next_steps. Cite at least one "
        "reason_evidence_id taken from the finding's evidence_ids. Respond as JSON "
        "matching the schema."
    )
    payload = {
        "finding_id": "F-0012",
        "type": "broken_access_control",
        "state": "confirmed",
        "route": "GET /api/accounts/{id}",
        "function": None,
        "evidence_ids": ["E-0041"],
        "valid_next_steps": ["request_source_evidence", "escalate_to_human"],
    }

    def validate(d: NextStepDecision) -> list[str]:
        errs: list[str] = []
        if d.finding_id != "F-0012":
            errs.append("finding_id mismatch")
        if d.next_step not in (NextStep.request_source_evidence, NextStep.escalate_to_human):
            errs.append("next_step not in valid set")
        if not set(d.reason_evidence_ids) <= {"E-0041"}:
            errs.append("cited unknown evidence id")
        return errs

    settings = ModelSettings(name=_MODEL, ollama_url=_URL, temperature=0.1, num_ctx=8192)
    out, source = await structured_call(
        NextStepDecision, system, payload, validate, settings=settings
    )
    assert source in ("llm", "llm_retry"), f"model fell back: {source}"
    assert out is not None
    assert out.finding_id == "F-0012"
    assert out.next_step in (NextStep.request_source_evidence, NextStep.escalate_to_human)
