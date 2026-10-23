"""AG13.2 — every route, then the whole demo flow over HTTP with a real Mode 3 scan.

The flow: start scan → watch SSE to ``completed`` → ranked findings → explained finding and its
evidence → audit → graph → gate (blocking) → verify the drafted fix → approve ``apply`` →
RESOLVED → gate no longer blocked by it → HTML report.

Everything is the real pipeline, including the code worker (AG14); only the semgrep and gitleaks
binaries are replaced by stand-ins that answer exactly as the real tools do on the demo code
(checked against them in the ``-m tools`` tests).
"""

from __future__ import annotations

import json
import shutil
import time

import httpx
import pytest
from fastapi.testclient import TestClient

from aegis.api.main import create_app
from aegis.config import ApiSettings, AppSettings, ModelSettings
from aegis.fix.verifier import PatchedTarget
from fakes.demo_apps import ROOT, create_app_from_dir, demo_stack
from fakes.fake_llm import PickFirstLLM
from fakes.tool_executors import fix_executor
from test_ag10_remediate_support import FixesTheAccessBug

pytestmark = pytest.mark.phase("AG13")

DOWN = "http://127.0.0.1:9"
ACCOUNTS = "app/routes/accounts.py"


# --------------------------------------------------------------------------------------------- #
# an app wired to the in-process demo network
# --------------------------------------------------------------------------------------------- #
@pytest.fixture
def demo(tmp_path):
    src = tmp_path / "src" / "demo-app"
    shutil.copytree(ROOT / "demo-app" / "app", src / "app")
    shutil.copy(ROOT / "demo-app" / "identities.yml", src / "identities.yml")
    router, _listener = demo_stack("vulnerable")
    builds = []

    async def patched_build(workspace):
        app = create_app_from_dir(workspace, f"api_patched_build_{len(builds)}_{id(router)}")
        builds.append(workspace)
        router._routes["patched-build"] = httpx.ASGITransport(app=app)
        return PatchedTarget(base_url="http://patched-build:5000", built_from_workspace=True)

    settings = AppSettings(
        data_dir=str(tmp_path / "data"),
        offline_db_dir=str(tmp_path / "offline-db"),
        allowlist=("demo-app:5000", "callback:8080", "patched-build:5000"),  # as .aegis.yml lists them
        model=ModelSettings(ollama_url=DOWN),
        api=ApiSettings(allowed_source_roots=(str(tmp_path / "src"),)),
    )
    overrides = dict(
        http_transport=router, tool_executor=fix_executor, llm=FixesTheAccessBug(), patched_target=patched_build,
        rate_limit_rps=1000.0, rate_limit_burst=1000, oob_wait_s=0.3,
    )
    return {"settings": settings, "overrides": overrides, "src": src, "builds": builds}


def make_client(demo) -> TestClient:
    return TestClient(create_app(demo["settings"], agent_overrides=demo["overrides"]), base_url="http://127.0.0.1:8000", raise_server_exceptions=False)


def mode3_body(demo) -> dict:
    return {"url": "http://demo-app:5000", "folder": str(demo["src"]), "identities": str(demo["src"] / "identities.yml")}


def events(c: TestClient, scan_id: str) -> list[dict]:
    out = []
    with c.stream("GET", f"/api/scans/{scan_id}/events") as resp:
        assert resp.status_code == 200 and resp.headers["content-type"].startswith("text/event-stream")
        for line in resp.iter_lines():
            if line.startswith("data:"):
                out.append(json.loads(line[5:].strip()))
    return out


def wait_for(c: TestClient, url: str, done, timeout: float = 60.0) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        body = c.get(url).json()
        if done(body):
            return body
        time.sleep(0.05)
    raise AssertionError(f"timed out waiting on {url}: {body}")


# --------------------------------------------------------------------------------------------- #
# the whole demo, over HTTP
# --------------------------------------------------------------------------------------------- #
def test_ag13_full_flow_over_http(demo):
    with make_client(demo) as c:
        # 1. start the Mode 3 scan and follow it live
        started = c.post("/api/scans", json=mode3_body(demo))
        assert started.status_code == 202
        scan_id = started.json()["scan_id"]

        stream = events(c, scan_id)
        assert stream[-1] == {**stream[-1], "stage": "scan", "node": "scan", "status": "completed"}
        nodes = [e["node"] for e in stream]
        assert {"check_bola", "extract_routes", "semgrep", "correlate", "score", "explain", "remediate", "finalize"} <= set(nodes)
        assert nodes.index("check_bola") < nodes.index("correlate") < nodes.index("finalize")

        scan = c.get(f"/api/scans/{scan_id}").json()
        assert scan["status"] == "completed" and scan["mode"] == "correlated"
        assert scan["completed_stages"][-1] == "finalize" and scan["counts"]["findings"] >= 3

        # 2. the access-control bug is ranked first, explained, and every claim's evidence is real
        ranked = c.get("/api/findings", params={"scan_id": scan_id}).json()
        top = ranked[0]
        assert (top["type"], top["route"], top["file"], top["risk"]) == ("broken_access_control", "GET /api/accounts/{id}", ACCOUNTS, 0.792)
        assert [f["risk"] for f in ranked] == sorted((f["risk"] for f in ranked), reverse=True)
        fid = top["id"]

        detail = c.get(f"/api/findings/{fid}").json()
        assert detail["what"] and detail["impact"] and detail["exploit"] and detail["where"].startswith(f"{ACCOUNTS}:")
        assert detail["fix"]["status"] == "drafted" and 'row["owner_id"] != user["id"]' in detail["fix"]["diff"]
        cited = {e for claim in detail["claims"] for e in claim["evidence_ids"]}
        assert cited and all(c.get(f"/api/evidence/{e}").status_code == 200 for e in cited)
        proof = c.get(f"/api/evidence/{detail['evidence_ids'][0]}").json()
        assert proof["kind"] == "http_exchange" and proof["payload"]["identity"] == "B"

        # 3. audit, graph and the CI gate
        audit = c.get(f"/api/scans/{scan_id}/audit").json()
        assert {d["node"] for d in audit["decisions"]} >= {"investigate", "explain", "remediate"}
        assert all(d["valid"] or d["source"] in ("llm", "llm_retry") for d in audit["decisions"])  # invalid only as rejected model answers
        graph = c.get("/api/graph", params={"scan_id": scan_id}).json()
        handled = [e["data"] for e in graph["edges"] if e["data"]["kind"] == "HANDLED_BY" and "get_account" in e["data"]["target"]]
        # route (0.5) + method (0.2) + data flow (0.3): the path id reaches the DB lookup (traced by AEGIS)
        signals = handled[0]["signals"] if handled else {}
        assert handled and handled[0]["score"] == 1.0 and signals["route"] and signals["method"] and signals["dataflow"], handled
        assert all(c.get(f"/api/evidence/{e}").json()["kind"] == "dataflow_path" for e in signals["dataflow_evidence"])
        gate = c.get(f"/api/scans/{scan_id}/gate").json()
        assert gate["exit_code"] == 1 and gate["passed"] is False and gate["blocking_findings"][0] == fid

        # 4. verify the drafted fix, approve it, and the finding is resolved
        fix = c.post(f"/api/findings/{fid}/fix")
        assert fix.status_code == 202
        fix_id = fix.json()["fix_id"]
        waiting = wait_for(c, f"/api/fixes/{fix_id}", lambda b: b["status"] != "verifying" and b["status"] != "drafted")
        assert waiting["status"] == "awaiting_approval", waiting
        report = waiting["verify_report"]
        assert report["passed"] is True and report["static"]["status"] == "passed" and report["runtime"]["status"] == "passed"
        assert report["approval"]["modes"] == ["patch", "apply"]

        refused = c.post(f"/api/fixes/{fix_id}/commit", json={"mode": "pr"})
        assert refused.status_code == 409 and "C6" in refused.json()["detail"]
        done = c.post(f"/api/fixes/{fix_id}/commit", json={"mode": "apply"})
        assert done.status_code == 200 and done.json()["status"] == "committed"
        assert c.get(f"/api/findings/{fid}").json()["state"] == "resolved"
        assert 'row["owner_id"] != user["id"]' in (demo["src"] / ACCOUNTS).read_text(encoding="utf-8")
        assert fid not in c.get(f"/api/scans/{scan_id}/gate").json()["blocking_findings"]

        # 5. the report tells the story
        html = c.get("/api/reports", params={"scan_id": scan_id})
        assert html.status_code == 200 and html.headers["content-type"].startswith("text/html")
        assert f'id="{fid}"' in html.text and "Verification: <b>passed</b>" in html.text
        data = c.get("/api/reports", params={"scan_id": scan_id, "format": "json"})
        assert data.headers["content-disposition"] == f'attachment; filename="aegis-{scan_id}.json"'
        assert json.loads(data.content)["risk"]["formula"].startswith("Risk = ")


# --------------------------------------------------------------------------------------------- #
# scans
# --------------------------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "body",
    [{}, {"url": "ftp://demo-app"}, {"folder": "/etc"}, {"url": "http://demo-app:5000", "repo": "x", "folder": "/x"}],
)
def test_an_invalid_scan_request_is_422(demo, body):
    with make_client(demo) as c:
        resp = c.post("/api/scans", json=body)
    assert resp.status_code == 422 and resp.json()["error"] == "invalid request"


def test_a_second_scan_while_one_runs_is_409(demo):
    with make_client(demo) as c:
        runner = c.app.state.runner

        async def busy():
            import asyncio

            return [asyncio.ensure_future(asyncio.sleep(3600))]

        (task,) = c.portal.call(busy)
        runner.tasks["S-0099"] = task
        resp = c.post("/api/scans", json={"url": "http://demo-app:5000"})
        assert resp.status_code == 409 and "S-0099" in resp.json()["detail"]


def test_status_cancel_and_unknown_scans(demo):
    with make_client(demo) as c:
        scan_id = c.post("/api/scans", json={"url": "http://demo-app:5000", "identities": str(demo["src"] / "identities.yml")}).json()["scan_id"]
        assert events(c, scan_id)[-1]["status"] == "completed"
        assert c.post(f"/api/scans/{scan_id}/cancel").status_code == 204       # already finished: no-op
        assert c.get(f"/api/scans/{scan_id}").json()["status"] == "completed"
        for path in ("/api/scans/S-9999", "/api/scans/S-9999/gate", "/api/scans/S-9999/audit", "/api/scans/S-9999/events"):
            assert c.get(path).status_code == 404, path
        assert c.post("/api/scans/S-9999/cancel").status_code == 404
        assert c.get("/api/scans/not-an-id").status_code == 422


def test_a_late_subscriber_replays_history_and_a_restarted_server_still_ends_the_stream(demo):
    with make_client(demo) as c:
        scan_id = c.post("/api/scans", json={"url": "http://demo-app:5000", "identities": str(demo["src"] / "identities.yml")}).json()["scan_id"]
        first = events(c, scan_id)
        assert events(c, scan_id) == first and c.app.state.bus.subscriber_count(scan_id) == 0  # replayed; cleaned up
    with make_client(demo) as restarted:                                       # no in-memory history any more
        (only,) = events(restarted, scan_id)
        assert (only["stage"], only["node"], only["status"]) == ("scan", "scan", "completed")


def test_the_gate_is_2_for_a_scan_that_did_not_complete(demo):
    with make_client(demo) as c:
        store = c.app.state.store
        scan = store.add_scan(mode="runtime", status="failed")
        assert c.get(f"/api/scans/{scan.id}/gate").json() == {"passed": False, "exit_code": 2, "blocking_findings": []}


# --------------------------------------------------------------------------------------------- #
# findings, evidence, graph, reports, ask
# --------------------------------------------------------------------------------------------- #
def test_findings_filters_and_unknown_ids(demo):
    with make_client(demo) as c:
        scan_id = c.post("/api/scans", json={"url": "http://demo-app:5000", "identities": str(demo["src"] / "identities.yml")}).json()["scan_id"]
        events(c, scan_id)
        everything = c.get("/api/findings", params={"scan_id": scan_id}).json()
        assert everything and {f["mode"] for f in everything} == {"runtime"}
        a01 = c.get("/api/findings", params={"scan_id": scan_id, "owasp": "A01"}).json()
        assert a01 and all(f["owasp"] == "A01" for f in a01)
        assert c.get("/api/findings", params={"scan_id": scan_id, "state": "resolved"}).json() == []
        assert c.get("/api/findings", params={"scan_id": scan_id, "severity_min": 1.01}).status_code == 422
        assert c.get("/api/findings", params={"scan_id": "S-9999"}).status_code == 404
        assert c.get("/api/findings/F-9999").status_code == 404
        assert c.get("/api/evidence/E-9999").status_code == 404
        assert c.get("/api/fixes/X-9999").status_code == 404
        assert c.post("/api/findings/F-9999/fix").status_code == 404
        assert c.post(f"/api/findings/{everything[0]['id']}/fix").status_code == 409   # no draft: runtime-only scan


def test_reports_cbom_sarif_and_ask(demo):
    with make_client(demo) as c:
        scan_id = c.post("/api/scans", json={"url": "http://demo-app:5000", "identities": str(demo["src"] / "identities.yml")}).json()["scan_id"]
        events(c, scan_id)
        assert c.get("/api/reports", params={"scan_id": scan_id, "format": "sarif"}).status_code == 501
        assert c.get("/api/reports", params={"scan_id": scan_id, "format": "pdf"}).status_code == 422
        assert c.get("/api/cbom", params={"scan_id": scan_id}).status_code == 404   # a runtime-only scan has no crypto stage
        assert c.get("/api/graph", params={"scan_id": scan_id}).status_code == 200
        answer = c.post("/api/ask", json={"scan_id": scan_id, "question": "what are the critical issues?"})
        body = answer.json()
        assert answer.status_code == 200 and body["answer"]
        # the structured path answers from the store with real finding ids (no model needed)
        assert all(c.app.state.store.get_finding(fid) is not None for fid in body["finding_ids"])
        assert c.post("/api/ask", json={"scan_id": "S-9999", "question": "?"}).status_code == 404

        queued = c.app.state.store.add_scan(mode="runtime", status="running")
        assert c.get("/api/reports", params={"scan_id": queued.id}).status_code == 409
        assert c.get("/api/graph", params={"scan_id": queued.id}).status_code == 404


def test_swagger_documents_every_route_with_examples(demo):
    with make_client(demo) as c:
        spec = c.get("/openapi.json").json()
    for path, ops in spec["paths"].items():
        for method, op in ops.items():
            assert op.get("summary") and op.get("tags"), (method, path)
    examples = spec["paths"]["/api/scans"]["post"]["requestBody"]["content"]["application/json"]["examples"]
    assert set(examples) == {"mode1_code", "mode2_runtime", "mode3_correlated"}
    assert {t["name"] for t in spec["tags"]} >= {"scans", "findings", "graph", "fix", "reports", "health"}


def test_recent_scans_are_listed_newest_first(demo):
    with make_client(demo) as c:
        first = c.post("/api/scans", json={"url": "http://demo-app:5000", "identities": str(demo["src"] / "identities.yml")}).json()["scan_id"]
        events(c, first)
        second = c.post("/api/scans", json={"url": "http://demo-app:5000", "identities": str(demo["src"] / "identities.yml")}).json()["scan_id"]
        events(c, second)
        listed = c.get("/api/scans").json()
        assert [s["id"] for s in listed[:2]] == [second, first]
        assert listed[0]["status"] == "completed" and listed[0]["findings"] >= 1 and listed[0]["top_risk"] == 0.792
        assert len(c.get("/api/scans", params={"limit": 1}).json()) == 1
