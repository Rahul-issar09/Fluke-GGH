"""RAG04 — security-aware BM25 sparse retrieval over a scan's chunks."""

from __future__ import annotations

import pytest

from aegis.chat.chroma_store import ChromaStore
from aegis.chat.schemas import Chunk, ChunkMetadata
from aegis.chat.sparse import BM25Index, SparseRetriever, tokenize

pytestmark = pytest.mark.phase("RAG04")


# --- the tokenizer ----------------------------------------------------------------------------- #
def test_identifier_is_kept_whole_and_also_split():
    toks = tokenize("the get_account handler")
    assert {"get_account", "get", "account"} <= set(toks)


def test_owasp_and_cwe_codes_survive():
    assert "a01" in tokenize("OWASP A01 broken access control")
    cwe = tokenize("CWE-89 injection")
    assert "cwe-89" in cwe and "cwe" in cwe and "89" in cwe


def test_camel_and_snake_both_produce_subtokens():
    assert {"getaccount", "get", "account"} <= set(tokenize("getAccount"))
    assert {"get_account", "get", "account"} <= set(tokenize("get_account"))


def test_filename_keeps_whole_and_stem():
    toks = tokenize("in auth.py")
    assert "auth.py" in toks and "auth" in toks and "py" in toks


def test_single_letter_subtokens_are_dropped_as_noise():
    assert "a" not in tokenize("A01")          # the stray "a" from splitting is noise; "a01" is kept


# --- BM25 directly ----------------------------------------------------------------------------- #
def test_exact_identifier_ranks_its_document_first():
    idx = BM25Index([
        ("F-1:what:0", tokenize("the get_account endpoint returns any account by id")),
        ("F-2:what:0", tokenize("the login handler checks the password hash")),
        ("F-3:what:0", tokenize("tls uses an outdated protocol version")),
    ])
    assert idx.search(tokenize("get_account"), 3)[0][0] == "F-1:what:0"


def test_no_match_scores_nothing():
    idx = BM25Index([("F-1:what:0", tokenize("account endpoint"))])
    assert idx.search(tokenize("kubernetes helm chart"), 5) == []


def test_empty_index_is_empty_not_an_error():
    assert BM25Index([]).search(tokenize("anything"), 5) == []


def test_order_is_deterministic_with_tie_break_by_id():
    docs = [("F-2:what:0", tokenize("sql injection in the query")),
            ("F-1:what:0", tokenize("sql injection in the query"))]
    out = BM25Index(docs).search(tokenize("sql injection"), 2)
    assert [cid for cid, _ in out] == ["F-1:what:0", "F-2:what:0"]  # equal score → chunk_id ascending


# --- the retriever over the real store (scan-scoped) ------------------------------------------- #
def _chunk(cid, scan_id, text, **meta) -> Chunk:
    base = dict(chunk_id=cid, finding_id=cid.split(":")[0], scan_id=scan_id, field="what",
                chunk_index=0, type="broken_access_control", indexed_at="2026-10-09T00:00:00Z")
    base.update(meta)
    return Chunk(chunk_id=cid, text=text, metadata=ChunkMetadata(**base))


@pytest.fixture
def store(tmp_path):
    return ChromaStore(str(tmp_path / "chroma"))


def test_retriever_matches_metadata_tokens_and_is_scan_scoped(store):
    store.upsert([
        _chunk("F-1:what:0", "S-1", "returns another user's record", function="get_account", owasp="A01"),
        _chunk("F-9:what:0", "S-2", "a different scan about get_account", function="get_account", owasp="A01"),
    ], [[1.0, 0.0], [0.0, 1.0]])
    r = SparseRetriever(store)
    hits = r.query_sparse("S-1", "get_account", k=10)
    assert [cid for cid, _ in hits] == ["F-1:what:0"]          # S-2 never appears (R-7)
    assert r.query_sparse("S-1", "A01", k=10)[0][0] == "F-1:what:0"   # matched via owasp metadata


def test_empty_scan_returns_nothing(store):
    assert SparseRetriever(store).query_sparse("S-empty", "anything", k=5) == []


def test_index_is_cached_until_the_scan_is_reindexed(store):
    store.upsert([_chunk("F-1:what:0", "S-1", "old account text")], [[1.0, 0.0]])
    r = SparseRetriever(store)
    assert r.query_sparse("S-1", "account", 5)[0][0] == "F-1:what:0"
    # re-index with new content + newer indexed_at → the cache signature changes → rebuilt
    store.delete_scan("S-1")
    store.upsert([_chunk("F-1:what:0", "S-1", "tls protocol only", indexed_at="2026-10-09T01:00:00Z")], [[0.0, 1.0]])
    assert r.query_sparse("S-1", "account", 5) == []           # old text gone
    assert r.query_sparse("S-1", "tls", 5)[0][0] == "F-1:what:0"
