"""Re-index scans for the findings chatbot: ``python -m aegis.chat reindex S-0015`` (or ``--all``).

A scan is indexed once, when it finishes. If that failed (the embedding model was missing or down)
or you changed ``AEGIS_CHAT__EMBED_MODEL``, run this instead of re-scanning. It reads the same
settings and database as the API, replaces each scan's chunks (no duplicates), and records the
outcome on the scan. Stop the API first when you are also changing the embedding model, so two
processes do not hold the vector store open at once.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from dataclasses import replace
from pathlib import Path

from aegis.chat.chroma_store import ChromaStore
from aegis.chat.embedder import EmbeddingUnavailable, make_embedder
from aegis.chat.indexer import index_scan
from aegis.config import get_app_settings
from aegis.evidence.db import init_db, make_engine
from aegis.evidence.store import EvidenceStore

__all__ = ["main", "reindex"]


def _out(line: str) -> None:
    sys.stdout.write(line + "\n")


async def reindex(store, chat_settings, ollama_url: str, scan_ids: list[str], *, chroma=None, embedder=None) -> list[dict]:
    """Re-index each scan; a failure on one is reported and does not stop the rest."""
    chroma = chroma or ChromaStore(chat_settings.chroma_path, chat_settings.collection)
    embedder = embedder or make_embedder(chat_settings, ollama_url)
    results: list[dict] = []
    for scan_id in scan_ids:
        if store.get_scan(scan_id) is None:
            results.append({"scan_id": scan_id, "ok": False, "error": "unknown scan"})
            continue
        try:
            results.append(await index_scan(store, chroma, embedder, scan_id))
        except Exception as exc:  # noqa: BLE001 - report and continue with the next scan
            results.append({"scan_id": scan_id, "ok": False, "error": f"{type(exc).__name__}: {str(exc)[:160]}"})
    return results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m aegis.chat", description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    cmd = sub.add_parser("reindex", help="rebuild the chat index for one or more scans")
    cmd.add_argument("scan_ids", nargs="*", help="scan ids, e.g. S-0015")
    cmd.add_argument("--all", action="store_true", help="re-index every scan")
    args = parser.parse_args(argv)

    settings = get_app_settings()
    data = Path(settings.data_dir)
    chat = settings.chat
    if not Path(chat.chroma_path).is_absolute():
        chat = replace(chat, chroma_path=str(data / "chroma"))   # same place the API puts it
    engine = make_engine(f"sqlite:///{(data / 'aegis.db').resolve().as_posix()}")
    init_db(engine)
    store = EvidenceStore(engine)

    scan_ids = [s.id for s in store.list_scans(limit=100000)] if args.all else list(args.scan_ids)
    if not scan_ids:
        parser.error("give one or more scan ids, or --all")

    _out(f"embedding model: {chat.embed_model} (dim {chat.embed_dim})")
    try:
        results = asyncio.run(reindex(store, chat, settings.model.ollama_url, scan_ids))
    except EmbeddingUnavailable as exc:
        _out(f"embedding model unavailable: {exc}")
        return 2
    failed = 0
    for r in results:
        if r.get("ok"):
            _out(f"{r['scan_id']}: indexed {r['chunks']} chunks from {r['findings']} findings")
        else:
            failed += 1
            _out(f"{r['scan_id']}: FAILED - {r.get('error')}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
