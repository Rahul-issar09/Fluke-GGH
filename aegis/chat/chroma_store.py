"""The ChromaDB vector store wrapper (RAG03).

One wrapper owns the single collection ``aegis_findings`` in a local ``PersistentClient`` (no
server, no telemetry). AEGIS passes embeddings in explicitly — the collection has **no** embedding
function of its own — so the embedder (RAG02) stays the only source of vectors and everything stays
offline and deterministic.

Isolation is by metadata, not by separate collections: **every** query must carry a ``scan_id``
filter (invariant R-7), enforced here — a query without one raises rather than risk leaking another
scan's findings. Re-indexing a scan is ``delete_scan`` then ``upsert``, so there are never stale
duplicates.
"""

from __future__ import annotations

from pathlib import Path

from aegis.chat.schemas import Chunk, ChunkMetadata
from aegis.observability import get_logger

__all__ = ["ChromaUnavailable", "ChromaStore"]

log = get_logger("chat.chroma")


class ChromaUnavailable(RuntimeError):
    """The vector store could not be opened or a store operation failed."""


class ChromaStore:
    def __init__(self, path: str, collection: str = "aegis_findings"):
        try:
            import chromadb
            from chromadb.config import Settings
        except ImportError as exc:  # pragma: no cover - chromadb is a declared dependency
            raise ChromaUnavailable("chromadb is not installed") from exc

        self.path = str(path)
        self.collection_name = collection
        Path(self.path).mkdir(parents=True, exist_ok=True)
        try:
            self._client = chromadb.PersistentClient(path=self.path, settings=Settings(anonymized_telemetry=False))
            self._col = self._client.get_or_create_collection(collection, metadata={"hnsw:space": "cosine"})
        except Exception as exc:  # noqa: BLE001 - a corrupt persist dir, a bad name, etc.
            raise ChromaUnavailable(f"could not open the Chroma collection: {type(exc).__name__}: {exc}") from exc
        log.info("chroma.open", path=self.path, collection=collection, count=self._col.count())

    # --------------------------------------------------------------------- writes
    def upsert(self, chunks: list[Chunk], embeddings: list[list[float]]) -> int:
        """Add or replace *chunks* with their matching *embeddings* (same order)."""
        if len(chunks) != len(embeddings):
            raise ChromaUnavailable(f"{len(chunks)} chunks but {len(embeddings)} embeddings")
        if not chunks:
            return 0
        try:
            self._col.upsert(
                ids=[c.chunk_id for c in chunks],
                embeddings=[list(v) for v in embeddings],
                documents=[c.text for c in chunks],
                metadatas=[c.metadata.to_chroma() for c in chunks],
            )
        except Exception as exc:  # noqa: BLE001
            raise ChromaUnavailable(f"upsert failed: {type(exc).__name__}: {exc}") from exc
        log.info("chroma.upsert", count=len(chunks), scan_ids=sorted({c.metadata.scan_id for c in chunks}))
        return len(chunks)

    def delete_scan(self, scan_id: str) -> None:
        """Remove every chunk of one scan (used before a re-index, and on cleanup)."""
        if not scan_id:
            raise ChromaUnavailable("delete_scan needs a scan_id")
        try:
            self._col.delete(where={"scan_id": scan_id})
        except Exception as exc:  # noqa: BLE001
            raise ChromaUnavailable(f"delete failed: {type(exc).__name__}: {exc}") from exc
        log.info("chroma.delete_scan", scan_id=scan_id)

    # --------------------------------------------------------------------- reads
    def query_dense(self, scan_id: str, query_vec: list[float], k: int) -> list[tuple[str, float, ChunkMetadata, str]]:
        """Nearest chunks **within one scan**: ``(chunk_id, distance, metadata, document)``.

        A missing ``scan_id`` raises (R-7): a query may never run unscoped.
        """
        if not scan_id:
            raise ChromaUnavailable("query_dense requires a scan_id (scan isolation, R-7)")
        if k <= 0:
            return []
        try:
            res = self._col.query(
                query_embeddings=[list(query_vec)], n_results=k, where={"scan_id": scan_id},
                include=["distances", "metadatas", "documents"],
            )
        except Exception as exc:  # noqa: BLE001
            raise ChromaUnavailable(f"query failed: {type(exc).__name__}: {exc}") from exc
        return self._rows(res["ids"][0], res["distances"][0], res["metadatas"][0], res["documents"][0])

    def all_for_scan(self, scan_id: str) -> list[tuple[str, ChunkMetadata, str]]:
        """Every chunk of one scan: ``(chunk_id, metadata, document)`` — feeds the sparse index (RAG04)."""
        if not scan_id:
            raise ChromaUnavailable("all_for_scan requires a scan_id (R-7)")
        try:
            res = self._col.get(where={"scan_id": scan_id}, include=["metadatas", "documents"])
        except Exception as exc:  # noqa: BLE001
            raise ChromaUnavailable(f"get failed: {type(exc).__name__}: {exc}") from exc
        return [(cid, ChunkMetadata.from_chroma(meta), doc)
                for cid, meta, doc in zip(res["ids"], res["metadatas"], res["documents"])]

    def get_by_ids(self, ids: list[str]) -> list[tuple[str, ChunkMetadata, str]]:
        """Fetch specific chunks by id (used by fusion/rerank to resolve candidates)."""
        if not ids:
            return []
        try:
            res = self._col.get(ids=list(ids), include=["metadatas", "documents"])
        except Exception as exc:  # noqa: BLE001
            raise ChromaUnavailable(f"get failed: {type(exc).__name__}: {exc}") from exc
        return [(cid, ChunkMetadata.from_chroma(meta), doc)
                for cid, meta, doc in zip(res["ids"], res["metadatas"], res["documents"])]

    def count(self) -> int:
        return self._col.count()

    def sample_dim(self) -> int | None:
        """The dimension of one stored vector, or ``None`` for an empty index (LP4: legacy adoption)."""
        try:
            res = self._col.get(limit=1, include=["embeddings"])
        except Exception as exc:  # noqa: BLE001
            raise ChromaUnavailable(f"get failed: {type(exc).__name__}: {exc}") from exc
        embeddings = res.get("embeddings")
        return len(embeddings[0]) if embeddings is not None and len(embeddings) else None

    def reset(self) -> None:
        """Drop every vector (all scans) — only for a rebuild with another embedding model (LP4)."""
        try:
            self._client.delete_collection(self.collection_name)
            self._col = self._client.get_or_create_collection(self.collection_name, metadata={"hnsw:space": "cosine"})
        except Exception as exc:  # noqa: BLE001
            raise ChromaUnavailable(f"reset failed: {type(exc).__name__}: {exc}") from exc
        log.warning("chroma.reset", path=self.path, collection=self.collection_name)

    @staticmethod
    def _rows(ids, distances, metadatas, documents):
        out = []
        for cid, dist, meta, doc in zip(ids, distances, metadatas, documents):
            out.append((cid, float(dist), ChunkMetadata.from_chroma(meta), doc))
        return out
