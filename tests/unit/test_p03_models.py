"""P0.3 — data models (contract) create and behave."""

from __future__ import annotations

import pytest
from sqlmodel import SQLModel, Session, create_engine

from aegis.evidence import models as m

pytestmark = pytest.mark.phase("AG00")

_EXPECTED_TABLES = {
    "scan",
    "finding",
    "evidence",
    "statetransition",
    "agentdecision",
    "claim",
    "fixattempt",
    "toolcalllog",
    "counter",
}


def test_create_all_makes_every_table():
    engine = create_engine("sqlite://")
    SQLModel.metadata.create_all(engine)
    assert _EXPECTED_TABLES <= set(SQLModel.metadata.tables)


def test_enum_members():
    assert [e.value for e in m.Mode] == ["runtime", "code", "correlated"]
    assert [e.value for e in m.FindingState] == [
        "candidate",
        "corroborated",
        "confirmed",
        "resolved",
    ]
    assert "awaiting_approval" in {e.value for e in m.ScanStatus}
    assert "tool_error" in {e.value for e in m.EvidenceKind}


def test_insert_and_read_finding():
    engine = create_engine("sqlite://")
    SQLModel.metadata.create_all(engine)
    with Session(engine) as s:
        s.add(m.Scan(id="S-0001", mode=m.Mode.correlated))
        s.add(
            m.Finding(
                id="F-0012",
                scan_id="S-0001",
                type="broken_access_control",
                owasp="A01",
                state=m.FindingState.confirmed,
                severity=0.9,
                risk=0.792,
            )
        )
        s.commit()
        got = s.get(m.Finding, "F-0012")
        assert got is not None and got.owasp == "A01"
        assert got.state == m.FindingState.confirmed
