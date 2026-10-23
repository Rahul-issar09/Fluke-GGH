"""P0.6 — API schemas (contract) import and render examples in OpenAPI."""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from aegis.api import schemas as api

pytestmark = pytest.mark.phase("AG00")


def test_models_import_and_construct():
    api.GateOut(passed=False, exit_code=1, blocking_findings=["F-0012"])
    api.CommitRequest(mode="apply")
    api.AskOut(answer="x", finding_ids=["F-0012"], evidence_ids=["E-0041"])
    api.ErrorOut(error="not_found")


def test_commit_mode_rejects_bad_value():
    with pytest.raises(Exception):
        api.CommitRequest(mode="force-push")


def test_scanrequest_examples_render_in_openapi():
    app = FastAPI()

    @app.post("/api/scans")
    def _start(req: api.ScanRequest) -> api.ScanOut:  # pragma: no cover - schema only
        return api.ScanOut(id="S-0001", mode="correlated", status="queued")

    spec = TestClient(app).get("/openapi.json").json()
    schema = spec["components"]["schemas"]["ScanRequest"]
    assert len(schema.get("examples", [])) == 3
    assert any("url" in ex and "folder" in ex for ex in schema["examples"])


def test_finding_detail_has_five_part_and_scores():
    fields = api.FindingDetail.model_fields
    for part in ("what", "where", "impact", "exploit", "fix"):
        assert part in fields
    assert "scores" in fields and "evidence_ids" in fields
