"""AG06.1 — Worker 1 (runtime): validate, discover, authenticate, model, and the
differential access-control check, plus the adapter → confirmed finding."""

from __future__ import annotations

import ast
import contextlib
import json
import pathlib

import httpx
import pytest
import yaml
from sqlmodel import select

from _graph_helpers import make_run
from aegis.agent.graph import build_aegis_graph
from aegis.evidence.digest import digest
from aegis.evidence.models import Evidence, FindingState, Mode, ScanStatus, StateTransition
from aegis.safety.allowlist import Allowlist
from aegis.safety.egress import make_client
from aegis.workers.runtime.auth import authenticate, load_identities
from aegis.workers.runtime.bola import check_bola, owner_fields_present, record_bola_findings
from aegis.workers.runtime.context import RuntimeStageError, request_as
from aegis.workers.runtime.discover import discover_routes
from aegis.workers.runtime.model import build_model
from aegis.workers.runtime.validate import validate_target
from fakes.demo_apps import ROOT, demo_transport, identities_path

pytestmark = pytest.mark.phase("AG06")

BASE = "http://demo-app:5000"


def _client(kind: str = "vulnerable", allow=("demo-app:5000",), inner=None) -> httpx.AsyncClient:
    return make_client(Allowlist(allow), inner=inner or demo_transport(kind))


@contextlib.asynccontextmanager
async def _prepared(kind: str = "vulnerable"):
    """Yield (client, sessions, routes, model) against a demo build; closes the client."""
    client = _client(kind)
    try:
        sessions = await authenticate(client, BASE, load_identities(identities_path(kind)))
        routes, _ = await discover_routes(client, BASE)
        model = await build_model(client, BASE, routes, sessions)
        yield client, sessions, routes, model
    finally:
        await client.aclose()


def _tool_errors(store, scan_id: str) -> list[Evidence]:
    with store.session() as s:
        return list(
            s.exec(select(Evidence).where(Evidence.scan_id == scan_id, Evidence.kind == "tool_error"))
        )


# --- validate_target -------------------------------------------------------- #
async def test_validate_reachable_target():
    async with _client() as client:
        info = await validate_target(client, BASE)
    assert info["reachable"] is True and info["status"] in (200, 404)


async def test_validate_offscope_fails():
    async with _client(allow=("some-other-host:1",)) as client:
        with pytest.raises(RuntimeStageError, match="allowlist"):
            await validate_target(client, BASE)


async def test_validate_unreachable_fails():
    def boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    async with _client(inner=httpx.MockTransport(boom)) as client:
        with pytest.raises(RuntimeStageError, match="unreachable"):
            await validate_target(client, BASE)


# --- discover_routes -------------------------------------------------------- #
async def test_discover_from_openapi():
    async with _client() as client:
        routes, payload = await discover_routes(client, BASE)
    templates = [r.template for r in routes]
    assert "GET /api/accounts/{id}" in templates and "GET /api/accounts" in templates
    assert payload["routes_found"] == len(routes) and payload["status"] == 200


async def test_discover_without_openapi_returns_no_routes():
    stub = httpx.MockTransport(lambda request: httpx.Response(404))
    async with _client(inner=stub) as client:
        routes, payload = await discover_routes(client, BASE)
    assert routes == [] and payload["routes_found"] == 0


# --- authenticate ----------------------------------------------------------- #
async def test_auth_two_identities_get_working_distinct_sessions():
    async with _client() as client:
        sessions = await authenticate(client, BASE, load_identities(identities_path()))
        assert set(sessions) == {"A", "B"}
        owners = {}
        for label in ("A", "B"):
            reply = await request_as(client, BASE, sessions[label], "GET", "/api/accounts")
            assert reply.status == 200
            owners[label] = reply.json[0]["owner"]
        assert owners == {"A": "alice", "B": "bob"}  # no session leaked between identities


def _identities_with(tmp_path: pathlib.Path, mutate) -> str:
    data = yaml.safe_load(pathlib.Path(identities_path()).read_text(encoding="utf-8"))
    mutate(data)
    path = tmp_path / "identities.yml"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    return str(path)


async def test_auth_bad_password_aborts_without_leaking_it(tmp_path):
    secret = "totally-wrong-password-123"
    path = _identities_with(tmp_path, lambda d: d["identities"]["B"].update(password=secret))
    async with _client() as client:
        with pytest.raises(RuntimeStageError) as ei:
            await authenticate(client, BASE, load_identities(path))
    assert "login failed for identity 'B'" in str(ei.value)
    assert secret not in str(ei.value)


def test_auth_requires_identities_a_and_b(tmp_path):
    path = _identities_with(tmp_path, lambda d: d["identities"].pop("B"))
    with pytest.raises(RuntimeStageError, match="A and B"):
        load_identities(path)


def test_auth_missing_identities_file():
    with pytest.raises(RuntimeStageError, match="not found"):
        load_identities("/no/such/identities.yml")


# --- request model ---------------------------------------------------------- #
async def test_model_has_target_route_with_owner_ids():
    async with _prepared() as (_client_, _sessions, _routes, model):
        pass
    by_route = {m.route.template: m for m in model}
    assert "GET /api/accounts/{id}" in by_route
    assert by_route["GET /api/accounts/{id}"].owner_ids == [1]  # A's own account only
    assert by_route["GET /api/accounts/{id}"].list_path == "/api/accounts"


# --- owner-field comparison ------------------------------------------------- #
@pytest.mark.parametrize(
    "baseline,replay,expected",
    [
        ({"id": 1, "owner": "alice"}, {"id": 1, "owner": "alice"}, True),
        ({"id": 1, "owner": "alice"}, {"id": 2, "owner": "bob"}, False),
        ({"id": 1, "account_number": "ACC-1"}, {"x": {"account_number": "ACC-1"}}, True),
        # generic fields two different objects could share must NOT count
        ({"id": 1, "name": "Checking", "type": "basic"}, {"id": 2, "name": "Checking", "type": "basic"}, False),
        ({"detail": "forbidden"}, {"detail": "forbidden"}, False),
        (None, None, False),
    ],
)
def test_owner_fields_present(baseline, replay, expected):
    assert owner_fields_present(baseline, replay) is expected


# --- differential check ----------------------------------------------------- #
async def test_bola_vulnerable_on_demo():
    async with _prepared("vulnerable") as (client, sessions, _, model):
        results = await check_bola(client, BASE, model, sessions)
    assert len(results) == 1
    r = results[0]
    assert r["route"] == "GET /api/accounts/{id}" and r["object_id"] == 1
    assert r["baseline"] == {"identity": "A", "status": 200, "timing_ms": r["baseline"]["timing_ms"]}
    assert r["replay"]["identity"] == "B" and r["replay"]["status"] == 200
    assert r["replay"]["contains_owner_fields"] is True
    assert r["vulnerable"] is True


async def test_bola_safe_on_patched():
    async with _prepared("patched") as (client, sessions, _, model):
        results = await check_bola(client, BASE, model, sessions)
    assert len(results) == 1
    assert results[0]["vulnerable"] is False and results[0]["replay"]["status"] == 403


# --- adapter → confirmed finding -------------------------------------------- #
async def test_adapter_creates_confirmed_finding_with_evidence(store):
    scan = store.add_scan(mode="runtime")
    async with _prepared("vulnerable") as (client, sessions, _, model):
        results = await check_bola(client, BASE, model, sessions)

    ids = record_bola_findings(store, scan.id, "runtime", results)
    assert len(ids) == 1
    finding = store.get_finding(ids[0])
    assert finding.type == "broken_access_control" and finding.owasp == "A01"
    assert finding.route == "GET /api/accounts/{id}" and finding.function is None
    assert finding.state == FindingState.confirmed

    (evidence,) = store.evidence_for(finding.id)
    payload = json.loads(evidence.payload_json)
    assert evidence.kind == "http_exchange" and payload["identity"] == "B" and payload["status"] == 200
    assert payload["route"] == "/api/accounts/1" and payload["route_template"] == "GET /api/accounts/{id}"
    assert "alice" in payload["response"]  # the leaked record is the proof
    assert "Cookie" not in evidence.payload_json and "session=" not in evidence.payload_json

    assert digest(evidence) == f"{evidence.id}: identity B, GET /api/accounts/1, → 200, contains owner fields"

    with store.session() as s:
        rows = list(s.exec(select(StateTransition).where(StateTransition.finding_id == finding.id)))
    assert [(t.from_state, t.to_state, t.actor) for t in rows] == [("candidate", "confirmed", "worker")]


async def test_recording_twice_does_not_duplicate_or_retransition(store):
    scan = store.add_scan(mode="runtime")
    async with _prepared("vulnerable") as (client, sessions, _, model):
        results = await check_bola(client, BASE, model, sessions)
    first = record_bola_findings(store, scan.id, "runtime", results)
    second = record_bola_findings(store, scan.id, "runtime", results)
    assert first == second and len(store.list_findings(scan.id)) == 1
    assert store.get_finding(first[0]).state == FindingState.confirmed


async def test_safe_results_create_no_finding(store):
    scan = store.add_scan(mode="runtime")
    async with _prepared("patched") as (client, sessions, _, model):
        results = await check_bola(client, BASE, model, sessions)
    assert record_bola_findings(store, scan.id, "runtime", results) == []
    assert store.list_findings(scan.id) == []


# --- through the real graph (Mode 1) ---------------------------------------- #
async def test_mode1_scan_confirms_the_access_control_finding(store, tmp_path):
    scan_id, state, config = make_run(store, tmp_path, Mode.runtime)
    final = await build_aegis_graph().ainvoke(state, config)

    assert final["errors"] == [] and final["completed_stages"][-1] == "finalize"
    findings = {(f.type, f.state, f.route) for f in store.list_findings(scan_id)}
    # the demo target has two runtime-provable weaknesses; both are CONFIRMED
    assert findings == {
        ("broken_access_control", FindingState.confirmed, "GET /api/accounts/{id}"),
        ("ssrf", FindingState.confirmed, "GET /api/fetch"),
    }
    bac = next(f for f in store.list_findings(scan_id) if f.type == "broken_access_control")
    # route-discovery evidence is scan-level; the replay proof belongs to the finding
    assert any(e.kind == "http_exchange" for e in store.evidence_for(bac.id))
    # sessions and the HTTP client do not outlive the stage
    assert config["configurable"]["deps"].scratch == {}


async def test_mode1_scan_on_patched_build_finds_nothing(store, tmp_path):
    scan_id, state, config = make_run(store, tmp_path, Mode.runtime, demo="patched")
    final = await build_aegis_graph().ainvoke(state, config)
    assert final["errors"] == [] and store.list_findings(scan_id) == []


async def test_unreachable_target_aborts_the_stage_cleanly(store, tmp_path):
    def boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    scan_id, state, config = make_run(
        store, tmp_path, Mode.runtime, http_transport=httpx.MockTransport(boom)
    )
    final = await build_aegis_graph().ainvoke(state, config)

    assert final["completed_stages"][-1] == "finalize"  # the scan carries on and reports it
    assert any("runtime.validate_target" in e and "unreachable" in e for e in final["errors"])
    assert store.list_findings(scan_id) == []
    assert len(_tool_errors(store, scan_id)) == 1


async def test_login_failure_aborts_the_stage_with_a_reason(store, tmp_path):
    path = _identities_with(tmp_path, lambda d: d["identities"]["A"].update(password="nope"))
    scan_id, state, config = make_run(store, tmp_path, Mode.runtime, identities=path)
    final = await build_aegis_graph().ainvoke(state, config)

    assert any("runtime.authenticate" in e and "login failed" in e for e in final["errors"])
    assert store.list_findings(scan_id) == []
    assert store.get_scan(scan_id).status == ScanStatus.queued  # status is the JobRunner's job


async def test_no_credentials_or_session_tokens_are_persisted(store, tmp_path):
    scan_id, state, config = make_run(store, tmp_path, Mode.runtime)
    await build_aegis_graph().ainvoke(state, config)

    blobs = [store.get_scan(scan_id).config_json]
    with store.session() as s:
        blobs += [e.payload_json for e in s.exec(select(Evidence).where(Evidence.scan_id == scan_id))]
    joined = "\n".join(blobs)
    for needle in ("alice-demo-pass", "bob-demo-pass", "session=", "Cookie"):
        assert needle not in joined


# --- structural guarantees --------------------------------------------------- #
def test_auth_never_passes_credentials_to_the_logger():
    tree = ast.parse((ROOT / "aegis" / "workers" / "runtime" / "auth.py").read_text(encoding="utf-8"))
    forbidden = {"password", "creds", "payload"}
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "log"
        ):
            names = {n.id for arg in [*node.args, *[k.value for k in node.keywords]] for n in ast.walk(arg) if isinstance(n, ast.Name)}
            assert not names & forbidden, f"log call at line {node.lineno} references {names & forbidden}"


def test_worker_modules_do_not_import_the_agent_layer():
    for py in (ROOT / "aegis" / "workers").rglob("*.py"):
        tree = ast.parse(py.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            module = node.module if isinstance(node, ast.ImportFrom) else None
            if isinstance(node, ast.Import):
                assert not any(a.name.startswith("aegis.agent") for a in node.names), py
            if module:
                assert not module.startswith("aegis.agent"), f"{py.name} imports {module}"
