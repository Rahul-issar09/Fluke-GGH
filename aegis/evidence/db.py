"""Database engine + init (PHASES P5.1).

SQLite (conflict C1). One engine per process; the store opens short-lived
sessions. ``expire_on_commit=False`` so returned rows keep their values after
commit (callers often use them detached).
"""

from __future__ import annotations

from pathlib import Path

from sqlmodel import SQLModel, create_engine

# Import models so their tables register on SQLModel.metadata before create_all.
from aegis.evidence import models as _models  # noqa: F401
from aegis.evidence import links as _links  # noqa: F401  (registers FindingLink)
from aegis.observability import get_logger

__all__ = ["make_engine", "init_db", "default_db_url"]

log = get_logger("evidence.db")


def default_db_url() -> str:
    data_dir = Path("data")
    data_dir.mkdir(parents=True, exist_ok=True)
    return f"sqlite:///{(data_dir / 'aegis.db').as_posix()}"


def make_engine(url: str | None = None):
    url = url or default_db_url()
    engine = create_engine(url, connect_args={"check_same_thread": False})
    return engine


def init_db(engine) -> None:
    SQLModel.metadata.create_all(engine)
    log.info("db.init", url=str(engine.url))
