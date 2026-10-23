"""RAG14 — embedding model down: honest message, keyword-only answers, and re-indexing."""

from __future__ import annotations

import pytest

from aegis.chat.chroma_store import ChromaStore
from aegis.chat.embedder import EmbeddingUnavailable
from aegis.chat.indexer import index_scan
from aegis.chat.retriever import RETRIEVAL_UNAVAILABLE, answer_explain
from aegis.chat.schemas import Answer
from aegis.chat.sparse import SparseRetriever
from aegis.chat.structured import NO_MATCH
from aegis.chat.__main__ import reindex
from aegis.config import ChatSettings
from fakes.fake_embedder import FakeEmbedder
from fakes.fake_llm import FakeLLM

pytestmark = pytest.mark.phase("RAG14")

DIM = 64
CFG = ChatSettings(embed_dim=DIM, min_dense_similarity=0.0)


class DownEmbedder:
    """The Ollama 404 case: the embedding model is not pulled / not reachable."""

    model = "nomic-embed-text"

    async def embed_documents(self, texts):
        raise EmbeddingUnavailable("could not reach the embedding model 'nomic-embed-text': HTTPStatusError")

    async def embed_query(self, text):
        raise EmbeddingUnavailable("could not reach the embedding model 'nomic-embed-text': HTTPStatusError")


def _scan(store):
    scan = store.add_scan(mode="correlated").id
    f = store.add_finding(scan, type="broken_access_control", owasp="A01", route="GET /api/accounts/{id}",
                          file="app/routes/accounts.py", line=37, function="get_account", source="w")
    store.add_evidence(scan, "http_exchange", "httpx", finding_id=f.id,
                       payload={"method": "GET", "route": "/api/accounts/1", "status": 200})
    store.update_finding_fields(f.id, risk=0.79, severity=0.9,
                                what="The accounts endpoint returns any account by id without an ownership check.",
                                impact="A signed-in user can read another user's account balance.")
    return scan, f.id


def _other_scan(store):
    scan = store.add_scan(mode="runtime").id
    f = store.add_finding(scan, type="misconfig", owasp="A05", route="GET /dashboard", source="w")
    store.add_evidence(scan, "http_exchange", "httpx", finding_id=f.id, payload={"method": "GET", "route": "/dashboard", "status": 200})
    store.update_finding_fields(f.id, what="A kubernetes ingress dashboard is exposed without authentication.")
    return scan, f.id


async def _ask(store, chroma, embedder, scan, question, llm):
    return await answer_explain(store, chroma, embedder, SparseRetriever(chroma), scan, question, settings=CFG, llm=llm)


async def test_embeddings_down_and_nothing_indexed_still_answers_by_keyword(store, tmp_path):
    scan, fid = _scan(store)
    chroma = ChromaStore(str(tmp_path / "chroma"))
    assert chroma.all_for_scan(scan) == []                 # never indexed (the 404 happened at finalize)
    good = Answer(text="The accounts endpoint leaks other users' data.", finding_ids=[fid], evidence_ids=[])
    ans = await _ask(store, chroma, DownEmbedder(), scan, "why can a user read another account without an ownership check?", FakeLLM([good]))
    assert ans.finding_ids == [fid] and ans.text != RETRIEVAL_UNAVAILABLE


async def test_embeddings_down_and_no_keyword_match_says_retrieval_unavailable(store, tmp_path):
    scan, _fid = _scan(store)
    # an in-scope-by-form question (no subject words to check) that keyword search cannot match
    ans = await _ask(store, ChromaStore(str(tmp_path / "chroma")), DownEmbedder(), scan,
                     "summarize the overview", FakeLLM([]))
    assert ans.text == RETRIEVAL_UNAVAILABLE and ans.finding_ids == [] and ans.evidence_ids == []
    assert ans.text != NO_MATCH                            # an outage is not "this scan has no match"


async def test_embeddings_up_and_no_match_stays_no_finding_matches(store, tmp_path):
    scan, _fid = _scan(store)
    chroma = ChromaStore(str(tmp_path / "chroma"))
    await index_scan(store, chroma, FakeEmbedder(DIM), scan)
    ans = await _ask(store, chroma, FakeEmbedder(DIM), scan, "zzqq flibbertigibbet", FakeLLM([]))
    assert ans.text != RETRIEVAL_UNAVAILABLE


async def test_keyword_fallback_is_scoped_to_the_asked_scan(store, tmp_path):
    scan_a, _fa = _scan(store)
    _scan_b, fb = _other_scan(store)
    chroma = ChromaStore(str(tmp_path / "chroma"))
    ans = await _ask(store, chroma, DownEmbedder(), scan_a, "why is the kubernetes ingress dashboard exposed?", FakeLLM([]))
    assert fb not in ans.finding_ids
    assert ans.text == NO_MATCH                            # scan A has no dashboard: out of scope


async def test_an_existing_index_is_used_when_only_the_query_embedding_fails(store, tmp_path):
    scan, fid = _scan(store)
    chroma = ChromaStore(str(tmp_path / "chroma"))
    await index_scan(store, chroma, FakeEmbedder(DIM), scan)
    good = Answer(text="Ownership is not checked.", finding_ids=[fid], evidence_ids=[])
    ans = await _ask(store, chroma, DownEmbedder(), scan, "why is the ownership check missing on the accounts endpoint?", FakeLLM([good]))
    assert ans.finding_ids == [fid]                        # keyword search over the stored index


async def test_reindex_builds_the_index_and_is_idempotent(store, tmp_path):
    scan, _fid = _scan(store)
    chroma = ChromaStore(str(tmp_path / "chroma"))
    first = await reindex(store, CFG, "", [scan], chroma=chroma, embedder=FakeEmbedder(DIM))
    count = len(chroma.all_for_scan(scan))
    second = await reindex(store, CFG, "", [scan], chroma=chroma, embedder=FakeEmbedder(DIM))
    assert first[0]["ok"] and second[0]["ok"] and count > 0
    assert len(chroma.all_for_scan(scan)) == count         # replaced, not duplicated


async def test_reindex_reports_failures_without_stopping_the_rest(store, tmp_path):
    scan, _fid = _scan(store)
    chroma = ChromaStore(str(tmp_path / "chroma"))
    down = await reindex(store, CFG, "", ["S-9999", scan], chroma=chroma, embedder=DownEmbedder())
    assert down[0] == {"scan_id": "S-9999", "ok": False, "error": "unknown scan"}
    assert down[1]["ok"] is False and "EmbeddingUnavailable" in down[1]["error"]
    ok = await reindex(store, CFG, "", [scan], chroma=chroma, embedder=FakeEmbedder(DIM))
    assert ok[0]["ok"] is True                              # a later run with a working model recovers
