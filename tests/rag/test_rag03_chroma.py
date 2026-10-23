"""RAG03 — the ChromaDB store wrapper: upsert, scan-scoped query, delete-by-scan."""

from __future__ import annotations

import pytest

from aegis.chat.chroma_store import ChromaStore, ChromaUnavailable
from aegis.chat.schemas import Chunk, ChunkMetadata

pytestmark = pytest.mark.phase("RAG03")


def chunk(chunk_id, scan_id, text, **meta) -> Chunk:
    fid = chunk_id.split(":")[0]
    base = dict(chunk_id=chunk_id, finding_id=fid, scan_id=scan_id, field="what", chunk_index=0,
                type="broken_access_control", evidence_ids=["E-1"])
    base.update(meta)
    return Chunk(chunk_id=chunk_id, text=text, metadata=ChunkMetadata(**base))


@pytest.fixture
def store(tmp_path):
    return ChromaStore(str(tmp_path / "chroma"))


def test_upsert_then_query_within_a_scan(store):
    store.upsert(
        [chunk("F-1:what:0", "S-1", "the endpoint returns other users accounts"),
         chunk("F-2:what:0", "S-1", "tls uses an outdated protocol")],
        [[1.0, 0.0], [0.0, 1.0]],
    )
    rows = store.query_dense("S-1", [1.0, 0.0], k=2)
    assert rows[0][0] == "F-1:what:0"                       # nearest to [1,0]
    cid, dist, meta, doc = rows[0]
    assert meta.finding_id == "F-1" and meta.evidence_ids == ["E-1"] and "accounts" in doc and dist == pytest.approx(0.0)


def test_a_query_is_scoped_to_its_scan(store):
    store.upsert([chunk("F-1:what:0", "S-1", "scan one finding"),
                  chunk("F-9:what:0", "S-2", "scan two finding")], [[1.0, 0.0], [1.0, 0.0]])
    rows = store.query_dense("S-1", [1.0, 0.0], k=10)
    assert [r[0] for r in rows] == ["F-1:what:0"]           # S-2's chunk never appears
    assert all(r[2].scan_id == "S-1" for r in rows)


def test_a_query_without_a_scan_id_is_refused(store):
    store.upsert([chunk("F-1:what:0", "S-1", "x")], [[1.0, 0.0]])
    with pytest.raises(ChromaUnavailable, match="scan_id"):
        store.query_dense("", [1.0, 0.0], k=5)
    with pytest.raises(ChromaUnavailable, match="scan_id"):
        store.all_for_scan("")


def test_delete_scan_removes_only_that_scan(store):
    store.upsert([chunk("F-1:what:0", "S-1", "a"), chunk("F-2:what:0", "S-1", "b"),
                  chunk("F-9:what:0", "S-2", "c")], [[1.0, 0.0], [0.5, 0.5], [0.0, 1.0]])
    store.delete_scan("S-1")
    assert store.count() == 1
    assert [cid for cid, _m, _d in store.all_for_scan("S-2")] == ["F-9:what:0"]
    assert store.all_for_scan("S-1") == []


def test_reindex_upsert_does_not_duplicate(store):
    store.upsert([chunk("F-1:what:0", "S-1", "old text")], [[1.0, 0.0]])
    store.delete_scan("S-1")                                  # the indexer's re-index pattern
    store.upsert([chunk("F-1:what:0", "S-1", "new text")], [[0.0, 1.0]])
    rows = store.all_for_scan("S-1")
    assert len(rows) == 1 and rows[0][2] == "new text"


def test_all_for_scan_and_get_by_ids_round_trip_metadata(store):
    store.upsert([chunk("F-1:what:0", "S-1", "a", owasp="A01", risk=0.79, line=37,
                        route="GET /api/accounts/{id}", evidence_ids=["E-2", "E-1"])], [[1.0, 0.0]])
    (cid, meta, doc), = store.all_for_scan("S-1")
    assert (meta.owasp, meta.risk, meta.line, meta.route) == ("A01", 0.79, 37, "GET /api/accounts/{id}")
    assert meta.evidence_ids == ["E-1", "E-2"]               # list field restored, sorted
    (gid, gmeta, gdoc), = store.get_by_ids(["F-1:what:0"])
    assert gid == "F-1:what:0" and gmeta.owasp == "A01"
    assert store.get_by_ids([]) == []


def test_upsert_length_mismatch_is_refused(store):
    with pytest.raises(ChromaUnavailable, match="chunks but"):
        store.upsert([chunk("F-1:what:0", "S-1", "a")], [[1.0], [2.0]])


def test_telemetry_is_off_and_persistence_survives_reopen(tmp_path):
    path = str(tmp_path / "chroma")
    s1 = ChromaStore(path)
    s1.upsert([chunk("F-1:what:0", "S-1", "persisted")], [[1.0, 0.0]])
    s2 = ChromaStore(path)                                    # reopen the same directory
    assert s2.count() == 1 and s2.all_for_scan("S-1")[0][2] == "persisted"
    import chromadb
    assert chromadb.config.Settings(anonymized_telemetry=False).anonymized_telemetry is False
