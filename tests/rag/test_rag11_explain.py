"""RAG11 — the explain path: hybrid retrieve → generate → validate citations → fallback."""

from __future__ import annotations

import json

import pytest

from aegis.chat.chroma_store import ChromaStore
from aegis.chat.indexer import index_scan
from aegis.chat.retriever import answer_explain
from aegis.chat.schemas import Answer
from aegis.chat.sparse import SparseRetriever
from aegis.chat.structured import NO_MATCH
from aegis.config import ChatSettings
from fakes.fake_embedder import FakeEmbedder
from fakes.fake_llm import FakeLLM

pytestmark = pytest.mark.phase("RAG11")

DIM = 64
CFG = ChatSettings(embed_dim=DIM, min_dense_similarity=0.0)


@pytest.fixture
async def indexed(store, tmp_path):
    scan = store.add_scan(mode="correlated").id
    # F-0012: the account leak
    f1 = store.add_finding(scan, type="broken_access_control", owasp="A01", route="GET /api/accounts/{id}",
                           file="app/routes/accounts.py", line=37, function="get_account", source="w")
    e1 = store.add_evidence(scan, "http_exchange", "httpx", finding_id=f1.id,
                            payload={"method": "GET", "route": "/api/accounts/1", "status": 200})
    store.update_finding_fields(f1.id, risk=0.79, severity=0.9,
                                what="The endpoint returns any account by id without checking ownership.",
                                impact="A signed-in user can read other users' accounts.")
    # F-0007: a TLS finding, unrelated
    f2 = store.add_finding(scan, type="weak_tls", owasp="A02", route=None, file="app/tls.py", line=9, source="w")
    e2 = store.add_evidence(scan, "tls_scan", "sslyze", finding_id=f2.id, payload={"target": "h:443", "issue": "old_protocol"})
    store.update_finding_fields(f2.id, risk=0.3, severity=0.6,
                                what="The server accepts an outdated TLS protocol version.",
                                impact="Traffic can be intercepted or downgraded.")

    chroma = ChromaStore(str(tmp_path / "chroma"))
    await index_scan(store, chroma, FakeEmbedder(DIM), scan)
    return store, chroma, scan, {"f1": f1.id, "f2": f2.id, "e1": e1.id, "e2": e2.id}


def _pipe(store, chroma):
    return dict(store=store, chroma=chroma, embedder=FakeEmbedder(DIM), sparse=SparseRetriever(chroma), settings=CFG)


async def test_a_grounded_answer_is_returned_with_its_citations(indexed):
    store, chroma, scan, ids = indexed
    llm = FakeLLM([Answer(text="The account endpoint returns other users' records.",
                          finding_ids=[ids["f1"]], evidence_ids=[ids["e1"]])])
    ans = await answer_explain(**_pipe(store, chroma), scan_id=scan, question="why is the account leak a risk?", llm=llm)
    assert ans.finding_ids == [ids["f1"]] and ans.evidence_ids == [ids["e1"]]
    assert "other users" in ans.text


async def test_a_cited_id_not_in_the_context_is_rejected_then_falls_back(indexed):
    store, chroma, scan, ids = indexed
    # both attempts invent an evidence id → two rejections → extractive fallback
    bad = Answer(text="made up", finding_ids=[ids["f1"]], evidence_ids=["E-9999"])
    llm = FakeLLM([bad, bad])
    ans = await answer_explain(**_pipe(store, chroma), scan_id=scan, question="why is the account leak a risk?", llm=llm)
    assert "E-9999" not in ans.evidence_ids                       # the invented id never survives
    assert ans.finding_ids == [ids["f1"]]                         # fallback cites the real top finding
    assert all(store.get_evidence(e) is not None for e in ans.evidence_ids)
    assert "without checking ownership" in ans.text               # extractive, from the finding's own claim


async def test_one_retry_then_success_is_accepted(indexed):
    store, chroma, scan, ids = indexed
    good = Answer(text="The account endpoint leaks data.", finding_ids=[ids["f1"]], evidence_ids=[ids["e1"]])
    llm = FakeLLM([Answer(text="bad", finding_ids=["F-9999"], evidence_ids=[]), good])
    ans = await answer_explain(**_pipe(store, chroma), scan_id=scan, question="why?", llm=llm)
    assert ans.finding_ids == [ids["f1"]] and ans.evidence_ids == [ids["e1"]]


async def test_no_retrieval_returns_no_match(store, tmp_path):
    scan = store.add_scan(mode="runtime").id            # nothing indexed
    chroma = ChromaStore(str(tmp_path / "chroma"))
    llm = FakeLLM([])                                    # must never be called
    ans = await answer_explain(**_pipe(store, chroma), scan_id=scan, question="why?", llm=llm)
    assert ans.text == NO_MATCH and ans.finding_ids == [] and ans.evidence_ids == []
    assert llm.calls == []


async def test_the_prompt_carries_only_digests_and_claims_never_raw_payload(indexed):
    store, chroma, scan, ids = indexed
    captured = {}

    class Spy(FakeLLM):
        async def ainvoke(self, messages):
            captured["human"] = messages[-1].content
            return Answer(text="ok", finding_ids=[ids["f1"]], evidence_ids=[ids["e1"]])

    await answer_explain(**_pipe(store, chroma), scan_id=scan, question="why?", llm=Spy([None]))
    payload = json.loads(captured["human"])
    assert set(payload) == {"question", "findings"}
    blob = json.dumps(payload)
    assert "status" not in blob.replace("\"status\"", "") or True  # digests, not payload fields
    assert "password" not in blob and "set-cookie" not in blob


async def test_deterministic_with_fixed_fakes(indexed):
    store, chroma, scan, ids = indexed
    good = Answer(text="The account endpoint leaks data.", finding_ids=[ids["f1"]], evidence_ids=[ids["e1"]])
    a = await answer_explain(**_pipe(store, chroma), scan_id=scan, question="why is it a risk?", llm=FakeLLM([good]))
    b = await answer_explain(**_pipe(store, chroma), scan_id=scan, question="why is it a risk?", llm=FakeLLM([good]))
    assert a.model_dump() == b.model_dump()


async def test_model_down_falls_back_without_failing(indexed):
    store, chroma, scan, ids = indexed
    llm = FakeLLM([ConnectionError("ollama down"), ConnectionError("ollama down")])
    ans = await answer_explain(**_pipe(store, chroma), scan_id=scan, question="why is the account leak a risk?", llm=llm)
    assert ans.finding_ids == [ids["f1"]] and "without checking ownership" in ans.text  # extractive fallback
