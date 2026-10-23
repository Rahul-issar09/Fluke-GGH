"""MCP server — the seven read-only tools, resources, redaction, audit (MCP_PHASES MCP01–MCP08).

Every test talks to the server through the real MCP protocol (``mcp.Client`` in-process), over a
store opened read-only, with a fake embedder and a scripted fake model: offline and deterministic.
"""

from __future__ import annotations

import asyncio
import json

import pytest
from mcp import Client

from aegis.api.schemas import AskOut
from aegis.chat.chroma_store import ChromaStore
from aegis.chat.indexer import index_scan
from aegis.chat.schemas import Answer
from aegis.config import ChatSettings, McpSettings
from aegis.evidence.models import ScanStatus
from aegis.evidence.store import EvidenceStore
from aegis.mcp.server import NO_SCANS, TOOL_NAMES, build_mcp
from aegis.services.chat_service import ChatService
from aegis.services.query_service import QueryService
from aegis.services.read_services import ReadServices, read_only_engine
from fakes.fake_embedder import FakeEmbedder
from fakes.fake_llm import FakeLLM

pytestmark = pytest.mark.phase("MCP")

DIM = 64
TOKEN = "s3cr3t-session-value-123456"


def _seed(store):
    scan = store.add_scan(mode="correlated").id
    f = store.add_finding(scan, type="broken_access_control", owasp="A01", route="GET /api/accounts/{id}",
                          file="app/routes/accounts.py", line=37, function="get_account", source="w")
    e = store.add_evidence(scan, "http_exchange", "bola", finding_id=f.id, payload={
        "method": "GET", "route": "/api/accounts/1", "status": 200, "identity": "B", "contains_owner_fields": True,
        "request": f"GET /api/accounts/1\nAuthorization: Bearer {TOKEN}\n", "session_token": TOKEN,
    })
    store.update_finding_fields(f.id, risk=0.79, severity=0.9,
                                what="The accounts endpoint returns any account by id without an ownership check.",
                                impact="A signed-in user can read another user's account balance.")
    low = store.add_finding(scan, type="misconfig", owasp="A05", route="GET /docs", source="w")
    store.add_evidence(scan, "http_exchange", "nuclei", finding_id=low.id, payload={"method": "GET", "route": "/docs", "status": 200})
    store.update_finding_fields(low.id, risk=0.1, severity=0.4, what="The API documentation page is public.")
    store.update_scan(scan, status=ScanStatus.completed)
    return scan, f.id, e.id, low.id


def _services(store_path, tmp_path, *, llm=None) -> ReadServices:
    store = EvidenceStore(read_only_engine(store_path))
    chroma = ChromaStore(str(tmp_path / "chroma"))
    chat = ChatService(store, ChatSettings(embed_dim=DIM, min_dense_similarity=0.0),
                       embedder=FakeEmbedder(DIM), chroma=chroma, llm=llm)
    return ReadServices(data_dir=tmp_path, store=store, query=QueryService(store, tmp_path), chat=chat)


@pytest.fixture
async def world(store, tmp_path):
    scan, fid, eid, low = _seed(store)
    await index_scan(store, ChromaStore(str(tmp_path / "chroma")), FakeEmbedder(DIM), scan)
    return {"scan": scan, "fid": fid, "eid": eid, "low": low, "db": tmp_path / "aegis.db", "tmp": tmp_path}


def _server(world, *, llm=None, **settings):
    cfg = McpSettings(audit_path=str(world["tmp"] / "audit" / "mcp.jsonl"), **settings)
    return build_mcp(_services(world["db"], world["tmp"], llm=llm), cfg)


def _body(result):
    return result.structured_content if result.structured_content is not None else [c.text for c in result.content]


def _audit(world) -> list[dict]:
    path = world["tmp"] / "audit" / "mcp.jsonl"
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()] if path.exists() else []


# ------------------------------------------------------------------------------------------ surface
async def test_exactly_the_eight_read_only_tools_are_registered(world):
    async with Client(_server(world)) as c:
        tools = (await c.list_tools()).tools
    assert {t.name for t in tools} == set(TOOL_NAMES) and len(tools) == 8   # + llm_status (LP10)
    assert all(t.annotations and t.annotations.read_only_hint and not t.annotations.destructive_hint for t in tools)
    assert not {t.name for t in tools} & {"start_scan", "cancel_scan", "commit_fix", "apply_fix", "verify_fix"}


async def test_report_resource_is_hidden_unless_raw_evidence_is_exposed(world):
    async with Client(_server(world)) as c:
        uris = {t.uri_template for t in (await c.list_resource_templates()).resource_templates}
    assert uris == {"aegis://findings/{finding_id}", "aegis://scans/{scan_id}/graph", "aegis://scans/{scan_id}/cbom"}
    async with Client(_server(world, expose_raw_evidence=True)) as c:
        uris = {t.uri_template for t in (await c.list_resource_templates()).resource_templates}
    assert "aegis://scans/{scan_id}/report.json" in uris


# ------------------------------------------------------------------------------------------ tools
async def test_list_findings_defaults_to_the_latest_scan_ranked_by_risk(world):
    async with Client(_server(world)) as c:
        body = _body(await c.call_tool("list_findings", {}))
    assert body["scan_id"] == world["scan"] and body["total"] == 2
    assert [f["id"] for f in body["findings"]] == [world["fid"], world["low"]]


async def test_list_findings_filters_and_caps_the_limit(world):
    async with Client(_server(world, max_list_limit=1)) as c:
        capped = _body(await c.call_tool("list_findings", {"limit": 50}))
        high = _body(await c.call_tool("list_findings", {"severity_min": 0.7}))
    assert capped["total"] == 2 and len(capped["findings"]) == 1
    assert [f["id"] for f in high["findings"]] == [world["fid"]]


async def test_get_finding_and_scan_status(world):
    async with Client(_server(world)) as c:
        detail = _body(await c.call_tool("get_finding", {"finding_id": world["fid"]}))
        status = _body(await c.call_tool("scan_status", {}))
    assert detail["id"] == world["fid"] and detail["what"].startswith("The accounts endpoint")
    assert world["eid"] in detail["evidence_ids"]
    assert status["id"] == world["scan"] and status["counts"]["findings"] == 2


async def test_unknown_or_malformed_ids_are_error_results_not_crashes(world):
    async with Client(_server(world)) as c:
        unknown = await c.call_tool("get_finding", {"finding_id": "F-9999"})
        malformed = await c.call_tool("get_finding", {"finding_id": "../../etc/passwd"})
        bad_scan = await c.call_tool("list_findings", {"scan_id": "S-9999"})
    assert unknown.is_error and "unknown finding F-9999" in _body(unknown)[0]
    assert malformed.is_error and bad_scan.is_error


async def test_no_scans_yet_gives_a_helpful_message(store, tmp_path):
    server = build_mcp(_services(tmp_path / "aegis.db", tmp_path), McpSettings(audit_path=str(tmp_path / "a.jsonl")))
    async with Client(server) as c:
        result = await c.call_tool("list_findings", {})
    assert result.is_error and NO_SCANS in _body(result)[0]


# ------------------------------------------------------------------------------------------ evidence (M-3)
async def test_evidence_is_a_digest_by_default(world):
    async with Client(_server(world)) as c:
        body = _body(await c.call_tool("get_evidence", {"evidence_id": world["eid"]}))
    text = json.dumps(body)
    record = body.get("result", body)
    assert record["digest"].startswith(world["eid"]) and "payload" not in record
    assert record["raw_payload_available"] is False and TOKEN not in text


async def test_raw_evidence_is_redacted_even_when_exposed(world):
    async with Client(_server(world, expose_raw_evidence=True)) as c:
        body = _body(await c.call_tool("get_evidence", {"evidence_id": world["eid"]}))
    text = json.dumps(body)
    assert "payload" in text and "/api/accounts/1" in text
    assert TOKEN not in text                       # both the named field and the header inside the request


# ------------------------------------------------------------------------------------------ ask
async def test_ask_answers_from_the_findings_with_citations(world):
    good = Answer(text="Ownership is not checked.", finding_ids=[world["fid"]], evidence_ids=[world["eid"]])
    async with Client(_server(world, llm=FakeLLM([good]))) as c:
        body = _body(await c.call_tool("ask", {"question": "why is the accounts ownership check a risk?"}))
    assert AskOut.model_validate(body) == AskOut(answer="Ownership is not checked.",
                                                 finding_ids=[world["fid"]], evidence_ids=[world["eid"]])


async def test_ask_out_of_scope_and_counts_need_no_model(world):
    async with Client(_server(world, llm=FakeLLM([]))) as c:   # an empty script: any model call would fail
        k8s = _body(await c.call_tool("ask", {"question": "what is k8s"}))
        count = _body(await c.call_tool("ask", {"question": "how many findings are there?"}))
    # answered_by / note: which model answered (LLM_PROVIDER_PHASES LP10); this test server has no model configuration
    assert k8s == {"answer": "No finding matches.", "finding_ids": [], "evidence_ids": [], "answered_by": None, "note": None}
    assert count["answer"].startswith("2 finding")


async def test_ask_times_out_with_a_clear_message(world):
    class Slow:
        def with_structured_output(self, *a, **k):
            return self

        async def ainvoke(self, messages):
            await asyncio.sleep(5)

    async with Client(_server(world, llm=Slow(), ask_timeout_s=0.2)) as c:
        result = await c.call_tool("ask", {"question": "why is the accounts ownership check a risk?"})
    assert result.is_error and "did not answer within" in _body(result)[0]


# ------------------------------------------------------------------------------------------ resources
async def test_resources_resolve(world):
    async with Client(_server(world)) as c:
        finding = await c.read_resource(f"aegis://findings/{world['fid']}")
        graph = await c.read_resource(f"aegis://scans/{world['scan']}/graph")
    assert json.loads(finding.contents[0].text)["id"] == world["fid"]
    assert "attack_paths" in json.loads(graph.contents[0].text)


# ------------------------------------------------------------------------------------------ audit (M-4)
async def test_every_call_is_audited_once_without_free_text(world):
    async with Client(_server(world, llm=FakeLLM([]))) as c:
        await c.call_tool("list_findings", {})
        await c.call_tool("get_finding", {"finding_id": "F-9999"})
        await c.call_tool("ask", {"question": "what is k8s"})
        await c.read_resource(f"aegis://findings/{world['fid']}")
    lines = _audit(world)
    assert [(l["name"], l["status"]) for l in lines] == [
        ("list_findings", "ok"), ("get_finding", "not_found"), ("ask", "ok"), ("finding", "ok")]
    assert lines[2]["args"] == {"question_chars": len("what is k8s")}
    assert "k8s" not in json.dumps(lines)


async def test_the_store_is_read_only(world):
    services = _services(world["db"], world["tmp"])
    with pytest.raises(Exception, match="readonly"):
        services.store.add_scan(mode="code")
