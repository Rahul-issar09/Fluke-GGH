"""P0.4 — agent schemas & state (contract)."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from aegis.agent import schemas as s
from aegis.agent import state as st
from aegis.evidence.models import Mode

pytestmark = pytest.mark.phase("AG00")


def test_valid_decision():
    d = s.NextStepDecision(
        finding_id="F-0012",
        next_step=s.NextStep.request_source_evidence,
        target=s.Target(route="GET /api/accounts/{id}"),
        reason_evidence_ids=["E-0041"],
    )
    assert d.next_step is s.NextStep.request_source_evidence


def test_unknown_enum_rejected():
    with pytest.raises(ValidationError):
        s.NextStepDecision(
            finding_id="F-0012", next_step="bogus", reason_evidence_ids=["E-1"]
        )


def test_empty_evidence_ids_rejected():
    with pytest.raises(ValidationError):
        s.NextStepDecision(
            finding_id="F-0012",
            next_step=s.NextStep.mark_sufficient,
            reason_evidence_ids=[],
        )


def test_claim_field_and_length():
    with pytest.raises(ValidationError):
        s.Claim(field="nope", text="x", evidence_ids=["E-1"])
    with pytest.raises(ValidationError):
        s.Claim(field="what", text="x" * 401, evidence_ids=["E-1"])


def test_explanation_max_claims():
    good = s.Explanation(
        finding_id="F-1",
        claims=[s.Claim(field="what", text="t", evidence_ids=["E-1"])],
    )
    assert len(good.claims) == 1
    with pytest.raises(ValidationError):
        s.Explanation(
            finding_id="F-1",
            claims=[s.Claim(field="what", text="t", evidence_ids=["E-1"])] * 13,
        )


def test_state_shapes():
    assert "completed_stages" in st.AegisState.__annotations__
    assert "max_iterations" in st.AegisState.__annotations__
    assert set(st.FixState.__annotations__) >= {
        "fix_id",
        "finding_id",
        "workspace_path",
        "verify_report",
        "approved",
        "commit_mode",
    }
    si = st.ScanInputs(url="http://demo-app:5000")
    assert si.folder is None
    assert Mode.correlated.value == "correlated"
