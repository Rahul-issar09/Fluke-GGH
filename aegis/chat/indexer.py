"""Build (and refresh) a scan's chat index at finalize (RAG08).

Loads the scan's visible findings, chunks them (RAG01), embeds the chunk texts (RAG02), then
**deletes the scan's old chunks and upserts the new ones** (RAG03) so a re-index never leaves
duplicates. Embedding happens *before* the delete, so an embedding failure leaves any existing
index intact (invariant R-6: a failed or slow index never blocks the scan, and the structured path
still answers). The outcome is recorded on the scan's config as ``chat_index`` so the chat service
knows whether an index exists.

``make_chat_indexer`` returns the callable ``finalize`` fires in the background — or ``None`` when
chat is disabled, so no index is built.
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone

from aegis.chat import index_manifest
from aegis.chat.chroma_store import ChromaStore, ChromaUnavailable
from aegis.chat.chunker import chunk_from_store
from aegis.chat.embedder import EmbeddingUnavailable, make_embedder
from aegis.evidence.links import visible_findings
from aegis.observability import get_logger

__all__ = ["index_scan", "make_chat_indexer"]

log = get_logger("chat.indexer")


def _record(store, scan_id: str, **flag) -> None:
    """Note the index outcome on the scan's config (``chat_index``) — never changes scan status."""
    scan = store.get_scan(scan_id)
    if scan is None:
        return
    try:
        config = json.loads(scan.config_json or "{}")
    except (ValueError, TypeError):
        config = {}
    config["chat_index"] = flag
    store.update_scan(scan_id, config_json=json.dumps(config))


async def index_scan(store, chroma: ChromaStore, embedder, scan_id: str, *, indexed_at: str | None = None) -> dict:
    """Index one scan's findings. Returns a summary; raises on an embedding/store failure (the
    caller treats that as a soft failure)."""
    indexed_at = indexed_at or datetime.now(timezone.utc).isoformat()
    findings = visible_findings(store, scan_id)
    chunks = []
    for finding in sorted(findings, key=lambda f: f.id):
        chunks.extend(chunk_from_store(store, finding, indexed_at=indexed_at))

    try:
        # never mix two embedding models' vectors in one index (LP4)
        compat = index_manifest.check(chroma, embedder)
        if not compat.compatible:
            raise index_manifest.IndexMismatch(compat.reason)
        embeddings = await embedder.embed_documents([c.text for c in chunks]) if chunks else []
        chroma.delete_scan(scan_id)                 # replace the scan's index atomically-ish
        if chunks:
            chroma.upsert(chunks, embeddings)
            expected = index_manifest.expected_for(embedder)
            if compat.manifest is None and expected is not None and getattr(chroma, "path", None):
                index_manifest.write_manifest(chroma.path, expected, adopted=compat.adopt)
    except (EmbeddingUnavailable, ChromaUnavailable, index_manifest.IndexMismatch) as exc:
        _record(store, scan_id, ok=False, chunks=0, indexed_at=indexed_at, error=f"{type(exc).__name__}: {str(exc)[:160]}")
        log.error("chat.index_error", scan_id=scan_id, error=f"{type(exc).__name__}: {str(exc)[:200]}")
        raise

    _record(store, scan_id, ok=True, findings=len(findings), chunks=len(chunks), indexed_at=indexed_at)
    log.info("chat.index_scan", scan_id=scan_id, findings=len(findings), chunks=len(chunks))
    return {"scan_id": scan_id, "findings": len(findings), "chunks": len(chunks), "indexed_at": indexed_at, "ok": True}


def make_chat_indexer(store, chat_settings, ollama_url: str = "", *, embedder=None, chroma=None, guard: bool = False):
    """The background indexer ``finalize`` calls, or ``None`` when chat is disabled.

    The Chroma store and embedder are built lazily on first use (and reused), so nothing is opened
    for a scan that is never indexed. ``embedder`` / ``chroma`` may be injected for tests. The
    embedder uses ``chat_settings.embed_url`` (``ollama_url`` only as a fallback); ``guard`` keeps
    it local (see :func:`~aegis.chat.embedder.make_embedder`).
    """
    if not chat_settings.enabled:
        return None

    cache = {"chroma": chroma, "embedder": embedder}

    async def indexer(scan_id: str) -> dict:
        if cache["chroma"] is None:
            cache["chroma"] = ChromaStore(chat_settings.chroma_path, chat_settings.collection)
        if cache["embedder"] is None:
            cache["embedder"] = make_embedder(chat_settings, ollama_url, guard=guard)
        return await asyncio.wait_for(
            index_scan(store, cache["chroma"], cache["embedder"], scan_id),
            timeout=chat_settings.index_timeout_s,
        )

    return indexer
