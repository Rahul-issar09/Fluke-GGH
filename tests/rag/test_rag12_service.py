"""RAG12 — ChatService facade and the /api/ask surface."""

from __future__ import annotations

import pytest

from aegis.api.schemas import AskOut
from aegis.chat.chroma_store import ChromaStore
from aegis.chat.indexer import index_scan
from aegis.chat.schemas import Answer
from aegis.chat.structured import NO_MATCH
from aegis.config import ChatSettings
from aegis.services.chat_service import ChatService
from fakes.fake_embedder import FakeEmbedder
from fakes.fake_llm import FakeLLM

pytestmark = pytest.mark.phase("RAG12")

DIM = 64


async def _world(store, tmp_path):
    scan = store.add_scan(mode="correlated").id
    f = store.add_finding(scan, type="broken_access_control", owasp="A01", route="GET /api/accounts/{id}",
                          file="app/routes/accounts.py", line=37, source="w")
    e = store.add_evidence(scan, "http_exchange", "httpx", finding_id=f.id,
                           payload={"method": "GET", "route": "/api/accounts/1", "status": 200})
    store.update_finding_fields(f.id, risk=0.79, severity=0.9,
                                what="The endpoint returns any account by id without checking ownership.",
                                impact="A signed-in user can read other users' accounts.")
    chroma = ChromaStore(str(tmp_path / "chroma"))
    await index_scan(store, chroma, FakeEmbedder(DIM), scan)
    return scan, f.id, e.id, chroma


def _service(store, chroma, *, llm=None, enabled=True):
    return ChatService(store, ChatSettings(enabled=enabled, embed_dim=DIM, min_dense_similarity=0.0),
                       embedder=FakeEmbedder(DIM), chroma=chroma, llm=llm)


async def test_a_counting_question_routes_to_structured_no_model(store, tmp_path):
    scan, fid, _e, chroma = await _world(store, tmp_path)
    svc = _service(store, chroma, llm=FakeLLM([]))     # llm must not be called
    out = await svc.ask(scan, "how many A01 findings?")
    assert isinstance(out, AskOut) and fid in out.finding_ids and out.answer.startswith("1 finding")


async def test_an_explain_question_routes_to_explain(store, tmp_path):
    scan, fid, eid, chroma = await _world(store, tmp_path)
    good = Answer(text="The account endpoint leaks data.", finding_ids=[fid], evidence_ids=[eid])
    out = await _service(store, chroma, llm=FakeLLM([good])).ask(scan, "why is the account leak a risk?")
    assert out.answer == "The account endpoint leaks data." and out.finding_ids == [fid] and out.evidence_ids == [eid]


async def test_disabled_returns_no_match_without_touching_retrieval(store, tmp_path):
    scan, _fid, _e, chroma = await _world(store, tmp_path)
    out = await _service(store, chroma, llm=FakeLLM([]), enabled=False).ask(scan, "why?")
    assert out.answer == NO_MATCH and out.finding_ids == [] and out.evidence_ids == []


async def test_retrieval_unavailable_degrades_to_structured(store, tmp_path):
    scan, fid, _e, _chroma = await _world(store, tmp_path)
    # a ChatService whose chroma cannot open (bad path + no injected store) still answers structured
    svc = ChatService(store, ChatSettings(embed_dim=DIM, chroma_path="\0invalid"), embedder=FakeEmbedder(DIM))
    out = await svc.ask(scan, "list the A01 findings")
    assert fid in out.finding_ids                       # structured path works without the vector store


async def test_askout_shape(store, tmp_path):
    scan, _fid, _e, chroma = await _world(store, tmp_path)
    out = await _service(store, chroma, llm=FakeLLM([Answer(text="x", finding_ids=[], evidence_ids=[])])).ask(scan, "why?")
    assert set(out.model_dump()) == {"answer", "finding_ids", "evidence_ids"}
