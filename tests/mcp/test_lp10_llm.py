"""LP10 — MCP clients can see which model AEGIS uses (llm_status, aegis://config/llm) but never change it,
and never see anything about a key. `ask` says which model answered."""

from __future__ import annotations

import json

import pytest
from mcp import Client

from aegis.chat.chroma_store import ChromaStore
from aegis.chat.indexer import index_scan
from aegis.config import ChatSettings, McpSettings
from aegis.llm.base import ProviderId
from aegis.llm.consent import DISCLOSURE_VERSION, ConsentInput
from aegis.llm.manager import ProviderManager
from aegis.mcp.server import TOOL_NAMES, build_mcp
from aegis.services.chat_service import ChatService
from aegis.services.query_service import QueryService
from aegis.services.read_services import ReadServices, read_only_engine
from aegis.evidence.store import EvidenceStore
from fakes.fake_embedder import FakeEmbedder
from fakes.fake_llm import FakeLLM
from fakes.fake_provider import TEST_KEY, FakeGemini, FakeProvider, manager_with, memory_secrets
from test_mcp_server import DIM, _seed

pytestmark = pytest.mark.phase("LP10")


@pytest.fixture
async def world(store, tmp_path):
    scan, fid, eid, low = _seed(store)
    await index_scan(store, ChromaStore(str(tmp_path / "chroma")), FakeEmbedder(DIM), scan)
    app_side = manager_with(tmp_path, FakeProvider(), FakeGemini(TEST_KEY), secrets=memory_secrets(None))
    return {"scan": scan, "db": tmp_path / "aegis.db", "tmp": tmp_path, "app": app_side}


def mcp_manager(world, key=None) -> ProviderManager:
    """The MCP process: read-only, its own (empty) memory — a key typed into the app is not here."""
    app = world["app"]
    return ProviderManager(app.settings, app.data_dir, read_only=True, registry=app.registry, environ={},
                           secrets=memory_secrets(key))


def server(world, llm, answer=None):
    store = EvidenceStore(read_only_engine(world["db"]))
    chat = ChatService(store, ChatSettings(embed_dim=DIM, min_dense_similarity=0.0), embedder=FakeEmbedder(DIM),
                       chroma=ChromaStore(str(world["tmp"] / "chroma")), llm=FakeLLM([ConnectionError("down")] * 4),
                       llm_manager=llm)
    services = ReadServices(data_dir=world["tmp"], store=store, query=QueryService(store, world["tmp"]), chat=chat, llm=llm)
    return build_mcp(services, McpSettings(audit_path=str(world["tmp"] / "audit" / "mcp.jsonl")))


async def go_online(app):
    result, vid = await app.validate(ProviderId.gemini, "gemini-2.5-flash", TEST_KEY)
    await app.activate(ProviderId.gemini, "gemini-2.5-flash", validation_id=vid, actor="ui",
                       consent=ConsentInput(disclosure_version=DISCLOSURE_VERSION, accepted=True))


def no_key_anything(payload) -> None:
    """No key value and no key metadata (no field about it, no fingerprint, no last characters)."""
    fields = set(payload)
    assert not fields & {"key", "fingerprint", "last4", "key_source", "api_key"}, fields
    text = json.dumps(payload)
    assert TEST_KEY not in text and "sha256:" not in text and TEST_KEY[-4:] not in text


# ---------------------------------------------------------------- what the client sees
async def test_offline_status_and_resource(world):
    async with Client(server(world, mcp_manager(world))) as c:
        status = (await c.call_tool("llm_status", {})).structured_content
        resource = json.loads((await c.read_resource("aegis://config/llm")).contents[0].text)
    assert (status["provider"], status["location"], status["online_chosen_but_inactive"]) == ("ollama", "local", False)
    assert status["embeddings"]["location"] == "local"
    assert resource == status
    no_key_anything(status)


async def test_online_chosen_in_the_app_but_no_key_here(world):
    await go_online(world["app"])                         # the app has this run's key; the MCP process does not
    async with Client(server(world, mcp_manager(world))) as c:
        status = (await c.call_tool("llm_status", {})).structured_content
        answer = (await c.call_tool("ask", {"question": "why is the accounts ownership check a risk?"})).structured_content
    assert status["online_chosen_but_inactive"] is True and status["online_model"] == "gemini-2.5-flash"
    assert status["location"] == "local" and "offline model" in status["note"]
    assert answer["answered_by"] == {"provider": "ollama", "model": "qwen2.5:7b", "location": "local"}
    assert "never saved" in answer["note"]
    no_key_anything(status)


async def test_an_operator_key_in_the_mcp_environment_makes_it_online(world):
    await go_online(world["app"])
    async with Client(server(world, mcp_manager(world, key=TEST_KEY))) as c:
        status = (await c.call_tool("llm_status", {})).structured_content
        answer = (await c.call_tool("ask", {"question": "how many findings are there?"})).structured_content
    assert (status["provider"], status["location"], status["note"]) == ("gemini", "cloud", None)
    assert answer["answered_by"]["location"] == "cloud"
    no_key_anything(status)


async def test_a_switch_in_the_app_is_seen_without_restarting_the_server(world):
    mcp = mcp_manager(world)
    async with Client(server(world, mcp)) as c:
        before = (await c.call_tool("llm_status", {})).structured_content
        await world["app"].activate(ProviderId.ollama, "llama3", actor="ui")
        after = (await c.call_tool("llm_status", {})).structured_content
    assert (before["model"], after["model"]) == ("qwen2.5:7b", "llama3")


# ---------------------------------------------------------------- read-only
async def test_nothing_here_can_change_the_model(world):
    async with Client(server(world, mcp_manager(world))) as c:
        tools = {t.name: t for t in (await c.list_tools()).tools}
    assert set(tools) == set(TOOL_NAMES) and "llm_status" in tools
    assert tools["llm_status"].annotations.read_only_hint is True
    assert not set(tools) & {"configure", "set_model", "activate", "go_offline", "set_key"}
    assert not (world["tmp"] / "config").exists()           # the MCP side never writes the configuration


async def test_the_audit_records_which_model_answered_and_no_key(world):
    await go_online(world["app"])
    async with Client(server(world, mcp_manager(world, key=TEST_KEY))) as c:
        await c.call_tool("ask", {"question": "how many findings are there?"})
        await c.call_tool("llm_status", {})
    lines = [json.loads(l) for l in (world["tmp"] / "audit" / "mcp.jsonl").read_text(encoding="utf-8").splitlines()]
    ask = next(l for l in lines if l["name"] == "ask")
    assert ask["args"]["model"] == "gemini:gemini-2.5-flash"
    assert any(l["name"] == "llm_status" for l in lines)
    assert TEST_KEY not in json.dumps(lines)
