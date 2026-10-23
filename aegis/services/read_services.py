"""The read-only side of AEGIS, built from settings alone (MCP_PHASES MCP00.2).

The MCP server (stdio) needs findings, evidence, graphs and the chat assistant — and nothing that
can change them. ``build_read_services`` gives exactly that: the evidence store opened **read-only**
(SQLite ``mode=ro``), the :class:`QueryService` facade and the :class:`ChatService`. It starts no
scan machinery (no graph, no job runner, no fix service).

It never creates a database: an editor may start the server in any working directory, so a missing
``aegis.db`` is reported with its absolute path instead of silently serving an empty store.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass, replace
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.pool import NullPool

from aegis.config import AppSettings
from aegis.evidence.store import EvidenceStore
from aegis.observability import get_logger
from aegis.services.chat_service import ChatService
from aegis.services.query_service import QueryService

__all__ = ["NoAegisData", "ReadServices", "build_read_services", "read_only_engine"]

log = get_logger("services.read")


class NoAegisData(RuntimeError):
    """The data directory has no AEGIS database."""


@dataclass
class ReadServices:
    data_dir: Path
    store: EvidenceStore
    query: QueryService
    chat: ChatService


def read_only_engine(db_path: Path):
    """A SQLAlchemy engine over an existing SQLite file, opened read-only."""
    uri = db_path.resolve().as_uri() + "?mode=ro"
    return create_engine(
        "sqlite://",
        creator=lambda: sqlite3.connect(uri, uri=True, check_same_thread=False),
        poolclass=NullPool,
    )


def build_read_services(settings: AppSettings) -> ReadServices:
    data = Path(settings.data_dir).resolve()
    db_path = data / "aegis.db"
    if not db_path.is_file():
        raise NoAegisData(
            f"no AEGIS data at {db_path}: run a scan first, or set AEGIS_DATA_DIR to the folder that holds aegis.db"
        )
    store = EvidenceStore(read_only_engine(db_path))
    chat_cfg = settings.chat
    if not Path(chat_cfg.chroma_path).is_absolute():  # same place the API keeps the chat index
        chat_cfg = replace(chat_cfg, chroma_path=str(data / "chroma"))
    chat = ChatService(store, chat_cfg, ollama_url=settings.model.ollama_url, model_settings=settings.model)
    log.info("read_services.ready", data_dir=str(data), model=settings.model.name, embed_model=chat_cfg.embed_model)
    return ReadServices(data_dir=data, store=store, query=QueryService(store, data), chat=chat)
