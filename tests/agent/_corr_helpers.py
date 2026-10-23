"""Seeding helpers for correlation tests (AG07).

They recreate what a Mode 3 scan leaves in the store before ``correlate`` runs:
a confirmed runtime finding (Worker 1), static findings with dataflow evidence
(Worker 2 / Semgrep), and the route -> handler map (Worker 2 extractor).
"""

from __future__ import annotations

import json
import pathlib

from aegis.evidence.adapters.semgrep import SemgrepAdapter
from aegis.evidence.normalizer import ingest
from aegis.workers.runtime.bola import record_bola_findings

FIXTURES = pathlib.Path(__file__).resolve().parents[1] / "fixtures"


def handler_rows() -> list[dict]:
    return json.loads((FIXTURES / "golden" / "handlers_demo.json").read_text(encoding="utf-8"))


def seed_handlers(store, scan_id: str, rows: list[dict] | None = None) -> list[str]:
    """Write route-handler evidence the way the code worker will."""
    ids = []
    for row in handler_rows() if rows is None else rows:
        ev = store.add_evidence(
            scan_id, kind="code_location", tool="treesitter", payload={"role": "route_handler", **row}
        )
        ids.append(ev.id)
    return ids


def seed_static(store, scan_id: str) -> list[str]:
    """Semgrep findings: owner-check (accounts.py:27), SQLi (users.py:42), weak hash (auth.py:14)."""
    raw = json.loads((FIXTURES / "tools" / "semgrep.json").read_text(encoding="utf-8"))
    return ingest(store, scan_id, SemgrepAdapter().parse(raw, scan_id))


def bola_result(path: str = "/api/accounts/1", route: str = "GET /api/accounts/{id}") -> dict:
    return {
        "route": route,
        "path": path,
        "object_id": 1,
        "baseline": {"identity": "A", "status": 200, "timing_ms": 1},
        "replay": {
            "identity": "B",
            "status": 200,
            "timing_ms": 2,
            "contains_owner_fields": True,
            "response_excerpt": '{"id": 1, "owner": "alice"}',
        },
        "vulnerable": True,
    }


def seed_runtime_bac(store, scan_id: str, mode: str = "correlated") -> str:
    (finding_id,) = record_bola_findings(store, scan_id, mode, [bola_result()])
    return finding_id


def by_type(store, scan_id: str, type_: str):
    return [f for f in store.list_findings(scan_id) if f.type == type_]
