"""Reciprocal-rank fusion of the dense and sparse result lists (RAG05).

Dense (meaning) and sparse (exact terms) each return a ranked list. RRF combines them by **rank**,
not by raw score, so the two incomparable score scales never need normalizing: a chunk's fused
score is ``Σ 1/(rrf_k + rank)`` over the lists it appears in. A chunk both methods rank highly
rises to the top. Fully deterministic (RAG invariant R-5), with a fixed tie-break. If one list is
empty (e.g. embeddings were unavailable), fusion degrades to the other.

The dense rows carry each chunk's metadata and text; the sparse rows carry only ids and scores, so
a ``resolve`` callable fetches the content of any chunk that appears **only** in the sparse list
(the retriever passes ``store.get_by_ids``). A sparse-only chunk that cannot be resolved is skipped.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence

from aegis.chat.schemas import Chunk, ChunkMetadata, RetrievedChunk
from aegis.observability import get_logger

__all__ = ["fuse", "DEFAULT_RRF_K"]

log = get_logger("chat.fusion")

DEFAULT_RRF_K = 60

DenseRow = tuple[str, float, ChunkMetadata, str]            # (chunk_id, distance, metadata, document)
SparseRow = tuple[str, float]                               # (chunk_id, bm25_score)
Resolver = Callable[[list[str]], Sequence[tuple[str, ChunkMetadata, str]]]


def fuse(
    dense: list[DenseRow],
    sparse: list[SparseRow],
    *,
    rrf_k: int = DEFAULT_RRF_K,
    resolve: Resolver | None = None,
) -> list[RetrievedChunk]:
    """Merge the two ranked lists into one, best-first. Lists must already be sorted best-first."""
    if bool(dense) ^ bool(sparse):
        log.warning("fusion.one_list_empty", dense=len(dense), sparse=len(sparse))

    content: dict[str, tuple[ChunkMetadata, str]] = {}
    dense_sim: dict[str, float] = {}
    for cid, distance, meta, doc in dense:
        content[cid] = (meta, doc)
        dense_sim[cid] = 1.0 - float(distance)             # cosine distance → similarity (higher better)
    sparse_score: dict[str, float] = {cid: float(score) for cid, score in sparse}

    # resolve any chunk that appeared only in the sparse list (no metadata/text yet)
    missing = [cid for cid, _ in sparse if cid not in content]
    if missing and resolve is not None:
        for cid, meta, doc in resolve(missing):
            content[cid] = (meta, doc)

    dense_rank = {cid: i + 1 for i, (cid, *_rest) in enumerate(dense)}
    sparse_rank = {cid: i + 1 for i, (cid, _s) in enumerate(sparse)}

    fused: list[RetrievedChunk] = []
    for cid in {*dense_rank, *sparse_rank}:
        if cid not in content:
            log.warning("fusion.unresolved_chunk", chunk_id=cid)   # sparse-only and not resolvable
            continue
        score = 0.0
        if cid in dense_rank:
            score += 1.0 / (rrf_k + dense_rank[cid])
        if cid in sparse_rank:
            score += 1.0 / (rrf_k + sparse_rank[cid])
        meta, doc = content[cid]
        fused.append(RetrievedChunk(
            chunk=Chunk(chunk_id=cid, text=doc, metadata=meta),
            dense_score=dense_sim.get(cid),
            sparse_score=sparse_score.get(cid),
            fused_score=score,
        ))

    # best fused score first; then higher risk, then finding_id, then chunk_id — all deterministic
    fused.sort(key=lambda r: (-r.fused_score, -r.chunk.metadata.risk, r.chunk.metadata.finding_id, r.chunk.chunk_id))
    return fused
