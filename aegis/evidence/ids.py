"""Human-readable monotonic IDs (PHASES P5.1).

``next_id(session, "F") -> "F-0001"``. Prefixes: S (scan), F (finding),
E (evidence), X (fix attempt), D (agent decision). Driven by the ``Counter``
table so IDs survive restarts. Single-writer (JobRunner semaphore=1) makes the
increment safe.
"""

from __future__ import annotations

from sqlmodel import Session

from aegis.evidence.models import Counter

__all__ = ["next_id", "PREFIXES"]

PREFIXES = ("S", "F", "E", "X", "D")


def next_id(session: Session, prefix: str) -> str:
    if prefix not in PREFIXES:
        raise ValueError(f"unknown id prefix '{prefix}'")
    counter = session.get(Counter, prefix)
    if counter is None:
        counter = Counter(prefix=prefix, value=0)
        session.add(counter)
    counter.value += 1
    session.add(counter)
    session.flush()
    return f"{prefix}-{counter.value:04d}"
