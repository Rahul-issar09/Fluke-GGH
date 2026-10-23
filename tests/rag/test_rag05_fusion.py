"""RAG05 — reciprocal-rank fusion of the dense and sparse lists."""

from __future__ import annotations

import pytest

from aegis.chat.fusion import fuse
from aegis.chat.schemas import ChunkMetadata

pytestmark = pytest.mark.phase("RAG05")


def meta(cid, *, risk=0.0, finding=None):
    fid = finding or cid.split(":")[0]
    return ChunkMetadata(chunk_id=cid, finding_id=fid, scan_id="S-1", field="what",
                         chunk_index=0, type="broken_access_control", risk=risk)


def dense_row(cid, distance=0.1, **kw):
    return (cid, distance, meta(cid, **kw), f"doc {cid}")


def by_id(fused):
    return [r.chunk.chunk_id for r in fused]


def test_rrf_math_matches_hand_calculation():
    dense = [dense_row("A"), dense_row("B")]            # ranks 1, 2
    sparse = [("B", 9.0), ("C", 3.0)]                   # ranks 1, 2
    fused = fuse(dense, sparse, rrf_k=60, resolve=lambda ids: [(c, meta(c), f"doc {c}") for c in ids])
    scores = {r.chunk.chunk_id: round(r.fused_score, 6) for r in fused}
    assert scores["A"] == round(1 / 61, 6)                           # dense rank 1 only
    assert scores["B"] == round(1 / 62 + 1 / 61, 6)                  # dense rank 2 + sparse rank 1
    assert scores["C"] == round(1 / 62, 6)                           # sparse rank 2 only
    assert by_id(fused)[0] == "B"                                     # in both → ranks first


def test_scores_are_carried_through():
    dense = [dense_row("A", distance=0.25)]
    sparse = [("A", 7.5)]
    (rc,) = fuse(dense, sparse)
    assert rc.dense_score == pytest.approx(0.75) and rc.sparse_score == 7.5 and rc.fused_score > 0


def test_item_in_both_lists_outranks_item_in_one():
    dense = [dense_row("A"), dense_row("X")]
    sparse = [("A", 1.0)]
    assert by_id(fuse(dense, sparse))[0] == "A"


def test_true_tie_breaks_by_risk_then_finding_then_chunk():
    # construct a real tie: two chunks each appear only in dense but at the same rank is impossible;
    # instead both appear in dense rank 1 and sparse rank 1 by running two independent lists is not
    # allowed. So simulate equal fused via equal single-list rank using rrf symmetry:
    dense = [dense_row("F-2:w:0", risk=0.3)]
    sparse = [("F-1:w:0", 1.0)]                          # both at rank 1 of their one list → equal fused
    fused = fuse(dense, sparse, resolve=lambda ids: [(c, meta(c, risk=0.3), f"doc {c}") for c in ids])
    assert fused[0].fused_score == pytest.approx(fused[1].fused_score)
    assert by_id(fused) == ["F-1:w:0", "F-2:w:0"]        # equal risk → finding_id ascending


def test_higher_risk_wins_a_tie():
    dense = [dense_row("F-2:w:0", risk=0.9)]
    sparse = [("F-1:w:0", 1.0)]
    fused = fuse(dense, sparse, resolve=lambda ids: [(c, meta(c, risk=0.1), f"doc {c}") for c in ids])
    assert fused[0].chunk.chunk_id == "F-2:w:0"          # equal fused score, higher risk first


def test_degrades_to_the_only_nonempty_list():
    assert by_id(fuse([dense_row("A"), dense_row("B")], [])) == ["A", "B"]
    only_sparse = fuse([], [("A", 2.0), ("B", 1.0)], resolve=lambda ids: [(c, meta(c), f"doc {c}") for c in ids])
    assert by_id(only_sparse) == ["A", "B"]
    assert fuse([], []) == []


def test_sparse_only_chunk_without_a_resolver_is_skipped():
    fused = fuse([dense_row("A")], [("A", 1.0), ("Z", 5.0)])   # Z only in sparse, no resolver
    assert by_id(fused) == ["A"]                                # Z skipped, not crashed
