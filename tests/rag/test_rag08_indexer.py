"""RAG08 — build/refresh the chat index at finalize, in the background, never blocking the scan."""

from __future__ import annotations

import asyncio

import pytest

from aegis.chat.chroma_store import ChromaStore
from aegis.chat.embedder import EmbeddingUnavailable
from aegis.chat.indexer import index_scan, make_chat_indexer
from aegis.config import ChatSettings
from fakes.fake_embedder import FakeEmbedder

pytestmark = pytest.mark.phase("RAG08")


def seed_scan(store, n=2):
    scan = store.add_scan(mode="correlated").id
    ids = []
    for i in range(n):
        f = store.add_finding(scan, type="broken_access_control", route=f"GET /api/x{i}/{{id}}",
                              file=f"app/r{i}.py", line=10, source="w")
        store.add_evidence(scan, "http_exchange", "httpx", finding_id=f.id,
                           payload={"method": "GET", "route": f"/api/x{i}/1", "status": 200})
        store.update_finding_fields(f.id, what=f"finding {i} returns another user's object",
                                    impact="any user reads others data")
        ids.append(f.id)
    return scan, ids


@pytest.fixture
def chroma(tmp_path):
    return ChromaStore(str(tmp_path / "chroma"))


async def test_index_populates_chroma_and_is_queryable(store, chroma):
    scan, _ = seed_scan(store, n=2)
    result = await index_scan(store, chroma, FakeEmbedder(dim=64), scan)
    assert result["ok"] and result["findings"] == 2 and result["chunks"] > 0
    assert chroma.count() == result["chunks"]
    rows = chroma.all_for_scan(scan)
    assert rows and all(meta.scan_id == scan for _c, meta, _d in rows)
    # the recorded flag says an index exists
    import json
    assert json.loads(store.get_scan(scan).config_json)["chat_index"]["ok"] is True


async def test_reindex_replaces_without_duplicates(store, chroma):
    scan, ids = seed_scan(store, n=1)
    first = await index_scan(store, chroma, FakeEmbedder(64), scan)
    count1 = chroma.count()
    # change a finding's text, re-index: same chunk count, new content, no duplicates
    store.update_finding_fields(ids[0], what="the finding now says something different")
    second = await index_scan(store, chroma, FakeEmbedder(64), scan)
    assert chroma.count() == count1 == second["chunks"] == first["chunks"]
    texts = " ".join(doc for _c, _m, doc in chroma.all_for_scan(scan))
    assert "something different" in texts


async def test_a_scan_with_no_claims_indexes_zero_chunks(store, chroma):
    scan = store.add_scan(mode="runtime").id
    store.add_finding(scan, type="misconfig", route="GET /x", source="w")  # no what/impact/exploit/fix
    result = await index_scan(store, chroma, FakeEmbedder(64), scan)
    assert result["ok"] and result["chunks"] == 0 and chroma.count() == 0


async def test_embedding_failure_leaves_the_prior_index_intact(store, chroma):
    scan, ids = seed_scan(store, n=1)
    await index_scan(store, chroma, FakeEmbedder(64), scan)   # a good index exists
    before = chroma.count()

    class BrokenEmbedder:
        dim = 64
        async def embed_documents(self, texts):
            raise EmbeddingUnavailable("ollama down")

    with pytest.raises(EmbeddingUnavailable):
        await index_scan(store, chroma, BrokenEmbedder(), scan)
    assert chroma.count() == before                           # not wiped (delete happens only after embed)
    import json
    assert json.loads(store.get_scan(scan).config_json)["chat_index"]["ok"] is False


# --- the factory + the finalize trigger ------------------------------------------------------- #
def test_make_chat_indexer_is_none_when_chat_is_disabled(store):
    assert make_chat_indexer(store, ChatSettings(enabled=False), "http://ollama:11434") is None


async def test_make_chat_indexer_runs_the_index(store, chroma):
    scan, _ = seed_scan(store, n=1)
    indexer = make_chat_indexer(store, ChatSettings(embed_dim=64), "http://ollama:11434",
                                embedder=FakeEmbedder(64), chroma=chroma)
    result = await indexer(scan)
    assert result["ok"] and chroma.count() > 0


async def test_finalize_starts_the_indexer_in_the_background(store, tmp_path):
    from aegis.agent.deps import AgentDeps
    from aegis.agent.nodes.finalize import finalize

    scan, _ = seed_scan(store, n=1)
    called: list[str] = []

    async def fake_indexer(scan_id):
        called.append(scan_id)

    deps = AgentDeps(store=store, data_dir=str(tmp_path), chat_indexer=fake_indexer)
    out = await finalize({"scan_id": scan}, {"configurable": {"deps": deps}})
    await asyncio.gather(*deps.background_tasks)               # let the fire-and-forget task run
    assert isinstance(out, dict) and called == [scan]


async def test_a_failing_indexer_never_fails_the_scan(store, tmp_path):
    from aegis.agent.deps import AgentDeps
    from aegis.agent.nodes.finalize import finalize

    scan, _ = seed_scan(store, n=1)

    async def boom(scan_id):
        raise EmbeddingUnavailable("ollama down")

    deps = AgentDeps(store=store, data_dir=str(tmp_path), chat_indexer=boom)
    out = await finalize({"scan_id": scan}, {"configurable": {"deps": deps}})  # must not raise
    await asyncio.gather(*deps.background_tasks)               # the task's exception is swallowed
    assert isinstance(out, dict)                              # the scan is unaffected
