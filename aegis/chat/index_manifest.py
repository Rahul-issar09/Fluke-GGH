"""Which embedding model built the chat index (LLM_PROVIDER_PHASES LP4, findings F-7 / F-8).

Vectors from two embedding models must never be mixed in one index: their dimensions may differ
(a Chroma error), and even with equal dimensions their distances mean nothing to each other. Before
LP4 nothing recorded which model built ``data/chroma``; that is how a 768-dim configuration came to
query a 1024-dim index.

The record is ``aegis_index.json`` next to the Chroma files::

    {"schema_version": 1, "embed_model": "bge-m3", "embed_dim": 1024,
     "prefix_scheme": "search_document/search_query", "created_at": "…", "adopted": false}

* **Indexing** checks it first and refuses to add vectors from another model (re-index with
  ``python -m aegis.chat reindex --all``, which rebuilds the whole index), and writes it with the
  first vectors.
* **Questions** check it: on a mismatch, semantic search is turned off with the reason and the chat
  falls back to keyword search — it never compares vectors from different models. Reading never
  writes anything, so the read-only MCP server stays read-only.
* **An index from before LP4** has no record. If one stored vector has the configured dimension,
  the index is *adopted*: the record is written (by the indexer only) with ``adopted: true``.
  Adoption infers the model from the dimension — an assumption, so it is marked.

Changing the **LLM** never touches any of this: the record is about embeddings only.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from aegis.observability import get_logger

__all__ = ["MANIFEST_FILE", "Compatibility", "IndexMismatch", "check", "expected_for", "read_manifest", "write_manifest"]

log = get_logger("chat.index_manifest")

MANIFEST_FILE = "aegis_index.json"
SCHEMA_VERSION = 1
REINDEX_HINT = "run: python -m aegis.chat reindex --all"


class IndexMismatch(RuntimeError):
    """The index was built by a different embedding model than the one configured."""


@dataclass(frozen=True)
class Compatibility:
    compatible: bool
    reason: str | None = None
    manifest: dict[str, Any] | None = None   # the record as found (None: none yet — the indexer writes one)
    adopt: bool = False                       # no record, but existing vectors match: written as adopted


def _norm(model: str | None) -> str | None:
    return model[: -len(":latest")] if model and model.endswith(":latest") else model


def expected_for(embedder: Any) -> dict[str, Any] | None:
    """What *embedder* would write, or ``None`` if it does not say (a test stand-in): no check then."""
    from aegis.chat.embedder import PREFIX_SCHEME

    model, dim = getattr(embedder, "model", None), getattr(embedder, "dim", None)
    if not isinstance(model, str) or not isinstance(dim, int):
        return None
    return {"embed_model": _norm(model), "embed_dim": dim, "prefix_scheme": PREFIX_SCHEME}


def _dir(chroma: Any) -> Path | None:
    path = getattr(chroma, "path", None)
    return Path(path) if path else None


def read_manifest(directory: str | Path | None) -> dict[str, Any] | None:
    if directory is None:
        return None
    try:
        data = json.loads((Path(directory) / MANIFEST_FILE).read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except (OSError, ValueError) as exc:
        log.warning("index_manifest.unreadable", directory=str(directory), error=type(exc).__name__)
        return {"unreadable": True}
    return data if isinstance(data, dict) else {"unreadable": True}


def write_manifest(directory: str | Path, expected: dict[str, Any], *, adopted: bool = False) -> None:
    path = Path(directory) / MANIFEST_FILE
    path.parent.mkdir(parents=True, exist_ok=True)
    body = {"schema_version": SCHEMA_VERSION, **expected, "created_at": datetime.now(timezone.utc).isoformat(),
            "adopted": adopted}
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(body, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, path)
    log.info("index_manifest.written", directory=str(directory), adopted=adopted, **expected)


def check(chroma: Any, embedder: Any) -> Compatibility:
    """May *embedder*'s vectors be compared with (or added to) *chroma*'s? Never writes."""
    expected = expected_for(embedder)
    directory = _dir(chroma)
    if expected is None or directory is None:
        return Compatibility(True)  # nothing to compare against (test stand-ins)
    found = read_manifest(directory)
    if found is None:
        sample = chroma.sample_dim() if hasattr(chroma, "sample_dim") else None
        if sample is None:
            return Compatibility(True)               # empty index: the first vectors decide
        if sample == expected["embed_dim"]:
            return Compatibility(True, adopt=True)   # vectors from before LP4 that fit: adopt them
        return Compatibility(False, (f"the chat index holds {sample}-dim vectors but the embedding model "
                                     f"'{expected['embed_model']}' makes {expected['embed_dim']}-dim ones; "
                                     f"{REINDEX_HINT}"))
    if found.get("unreadable"):
        return Compatibility(False, f"the chat index record ({MANIFEST_FILE}) cannot be read; {REINDEX_HINT}", found)
    mismatched = [k for k in ("embed_model", "embed_dim", "prefix_scheme")
                  if (_norm(found.get(k)) if k == "embed_model" else found.get(k)) != expected[k]]
    if mismatched:
        return Compatibility(False, (f"the chat index was built with '{found.get('embed_model')}' "
                                     f"({found.get('embed_dim')} dims) but the configured embedding model is "
                                     f"'{expected['embed_model']}' ({expected['embed_dim']} dims); {REINDEX_HINT}"), found)
    return Compatibility(True, manifest=found)
