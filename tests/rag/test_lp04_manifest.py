"""LP4 — the chat index records which embedding model built it, and vectors from two models never mix."""

from __future__ import annotations

import json

import pytest

from aegis.chat.chroma_store import ChromaStore
from aegis.chat.index_manifest import MANIFEST_FILE, check, read_manifest
from aegis.chat.indexer import index_scan
from aegis.chat.__main__ import reindex
from aegis.config import ChatSettings
from aegis.services.chat_service import ChatService
from fakes.fake_embedder import FakeEmbedder
from fakes.fake_llm import FakeLLM

pytestmark = pytest.mark.phase("LP4")

DIM = 64


class Named(FakeEmbedder):
    """The fake embedder under another model name (same vectors), counting calls."""

    def __init__(self, dim=DIM, model="fake-embed"):
        super().__init__(dim)
        self.model = model
        self.calls = 0

    async def embed_query(self, text):
        self.calls += 1
        return await super().embed_query(text)


@pytest.fixture
def chroma(tmp_path):
    return ChromaStore(str(tmp_path / "chroma"))


@pytest.fixture
def scan(store):
    s = store.add_scan("code")
    f = store.add_finding(s.id, type="sqli", owasp="A03", title="SQL injection in search", file="app/routes/search.py",
                          line=12, function="search")
    store.add_evidence(s.id, "code_location", "semgrep", payload={"file": "app/routes/search.py", "line": 12}, finding_id=f.id)
    # the index is built from a finding's validated explanation text
    store.update_finding_fields(f.id, what="SQL injection in the search handler", impact="the database can be read")
    return s.id


def manifest_path(chroma):
    return chroma.path + "/" + MANIFEST_FILE


# ---------------------------------------------------------------- the record
def test_a_stand_in_without_model_or_dim_is_never_checked(chroma):
    class Bare:
        pass

    assert check(chroma, Bare()).compatible is True


async def test_the_first_index_writes_the_record(store, chroma, scan):
    assert check(chroma, Named()).compatible is True
    await index_scan(store, chroma, Named(), scan)
    rec = read_manifest(chroma.path)
    assert (rec["embed_model"], rec["embed_dim"], rec["adopted"]) == ("fake-embed", DIM, False)
    assert rec["prefix_scheme"] == "search_document/search_query"


async def test_another_model_is_refused_when_indexing_and_the_index_is_kept(store, chroma, scan):
    await index_scan(store, chroma, Named(), scan)
    before = chroma.count()
    with pytest.raises(Exception, match="reindex --all"):
        await index_scan(store, chroma, Named(model="other-embed"), scan)
    assert chroma.count() == before
    recorded = json.loads(store.get_scan(scan).config_json)["chat_index"]
    assert recorded["ok"] is False and "other-embed" in recorded["error"]


async def test_latest_tag_is_the_same_model(store, chroma, scan):
    await index_scan(store, chroma, Named(model="bge-m3"), scan)
    assert check(chroma, Named(model="bge-m3:latest")).compatible is True


# ---------------------------------------------------------------- an index from before LP4
async def _legacy(store, chroma, scan, dim=DIM):
    """An index with vectors but no record, as every index built before LP4 is."""
    import os

    await index_scan(store, chroma, Named(dim=dim), scan)
    os.remove(manifest_path(chroma))


async def test_a_legacy_index_with_matching_vectors_is_adopted_by_the_indexer_only(store, chroma, scan):
    await _legacy(store, chroma, scan)
    compat = check(chroma, Named(model="bge-m3"))
    assert compat.compatible is True and compat.adopt is True
    assert read_manifest(chroma.path) is None             # checking never writes (read-only MCP stays read-only)
    await index_scan(store, chroma, Named(model="bge-m3"), scan)
    rec = read_manifest(chroma.path)
    assert (rec["embed_model"], rec["adopted"]) == ("bge-m3", True)


async def test_a_legacy_index_with_other_dimensions_is_refused(store, chroma, scan):
    await _legacy(store, chroma, scan, dim=DIM)
    compat = check(chroma, Named(dim=DIM * 2, model="bge-m3"))
    assert compat.compatible is False
    assert f"{DIM}-dim" in compat.reason and "reindex --all" in compat.reason


async def test_an_unreadable_record_is_refused(chroma):
    import pathlib

    pathlib.Path(manifest_path(chroma)).write_text("{broken", encoding="utf-8")
    assert check(chroma, Named()).compatible is False


# ---------------------------------------------------------------- questions never compare different models
async def test_a_mismatched_index_answers_by_keyword_without_embedding(store, chroma, scan):
    await index_scan(store, chroma, Named(), scan)
    other = Named(model="other-embed")
    svc = ChatService(store, ChatSettings(embed_dim=DIM, min_dense_similarity=0.0, min_term_coverage=0.0),
                      embedder=other, chroma=chroma, llm=FakeLLM([ConnectionError("model down")]))
    out = await svc.ask(scan, "why is the SQL injection in search a risk?")
    assert other.calls == 0                                # semantic search was off: no vector compared
    assert out.finding_ids                                 # keyword search still found the finding


# ---------------------------------------------------------------- reindex
async def test_reindex_of_one_scan_refuses_a_model_change(store, chroma, scan):
    await index_scan(store, chroma, Named(), scan)
    (result,) = await reindex(store, ChatSettings(embed_dim=DIM), "", [scan], chroma=chroma, embedder=Named(model="other"))
    assert result["ok"] is False and "reindex --all" in result["error"]
    assert read_manifest(chroma.path)["embed_model"] == "fake-embed"


async def test_reindex_all_rebuilds_for_the_new_model(store, chroma, scan):
    await index_scan(store, chroma, Named(), scan)
    (result,) = await reindex(store, ChatSettings(embed_dim=DIM * 2), "", [scan], chroma=chroma,
                              embedder=Named(dim=DIM * 2, model="other"), rebuild=True)
    assert result["ok"] is True
    rec = read_manifest(chroma.path)
    assert (rec["embed_model"], rec["embed_dim"], rec["adopted"]) == ("other", DIM * 2, False)
    assert chroma.sample_dim() == DIM * 2
