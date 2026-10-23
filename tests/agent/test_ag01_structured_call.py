"""AG01.2 — structured_call: validate → retry once → fallback."""

from __future__ import annotations

import pytest
from langchain_core.exceptions import OutputParserException

from aegis.agent.llm import structured_call
from aegis.agent.schemas import NextStep, NextStepDecision
from fakes.fake_llm import FakeLLM

pytestmark = pytest.mark.phase("AG01")

_SYSTEM = "Choose the next step."
_PAYLOAD = {"finding_id": "F-0012", "valid_next_steps": ["mark_sufficient"]}


def _decision(finding_id: str) -> NextStepDecision:
    return NextStepDecision(
        finding_id=finding_id,
        next_step=NextStep.mark_sufficient,
        reason_evidence_ids=["E-0041"],
    )


def _validate(d: NextStepDecision) -> list[str]:
    return [] if d.finding_id == "F-0012" else ["finding_id mismatch"]


async def test_valid_first_try_is_llm():
    fake = FakeLLM([_decision("F-0012")])
    out, source = await structured_call(
        NextStepDecision, _SYSTEM, _PAYLOAD, _validate, llm=fake
    )
    assert source == "llm"
    assert out is not None and out.finding_id == "F-0012"
    assert len(fake.calls) == 1


async def test_invalid_then_valid_is_llm_retry():
    fake = FakeLLM([_decision("WRONG"), _decision("F-0012")])
    out, source = await structured_call(
        NextStepDecision, _SYSTEM, _PAYLOAD, _validate, llm=fake
    )
    assert source == "llm_retry"
    assert out is not None and out.finding_id == "F-0012"
    # a corrective message was appended before the retry
    assert len(fake.calls) == 2
    assert len(fake.calls[1]) == len(fake.calls[0]) + 1


async def test_invalid_twice_is_fallback():
    fake = FakeLLM([_decision("WRONG"), _decision("ALSO-WRONG")])
    out, source = await structured_call(
        NextStepDecision, _SYSTEM, _PAYLOAD, _validate, llm=fake
    )
    assert source == "fallback"
    assert out is None
    assert len(fake.calls) == 2


async def test_unparseable_then_valid_is_llm_retry():
    fake = FakeLLM([OutputParserException("not json"), _decision("F-0012")])
    out, source = await structured_call(
        NextStepDecision, _SYSTEM, _PAYLOAD, _validate, llm=fake
    )
    assert source == "llm_retry"
    assert out is not None


async def test_unparseable_twice_is_fallback():
    fake = FakeLLM([OutputParserException("x"), OutputParserException("y")])
    out, source = await structured_call(
        NextStepDecision, _SYSTEM, _PAYLOAD, _validate, llm=fake
    )
    assert source == "fallback"
    assert out is None
