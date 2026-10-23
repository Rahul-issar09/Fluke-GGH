"""Semgrep wrapper (Worker 2, AG14.1, PHASES P7.4).

Runs the local rules in ``rules/semgrep`` — through the SafetyController, offline (no
registry rules, no metrics, no version check) — over the whole source or, for an
investigation follow-up, one file. Results become findings through ``SemgrepAdapter``:
``code_location`` evidence, plus ``dataflow_path`` evidence when a request input reaches the
reported line.

Semgrep's free engine exports no taint traces (``--dataflow-traces`` only changes its text
output and its SARIF has no code flows). So for every result inside a **route handler** the
trace is computed by ``workers.code.dataflow`` from the source: which handler parameter (a
request input) reaches the reported statement, through which assignments. Outside a route
handler a parameter is not known to come from a request, so no flow is claimed.
"""

from __future__ import annotations

import ast
from pathlib import Path

from aegis.evidence.adapters.semgrep import rule_id
from aegis.observability import get_logger
from aegis.safety.models import ToolCall
from aegis.workers.code.dataflow import trace_through_call, trace_to_line
from aegis.workers.code.routes_fastapi import is_route_handler, route_handlers

__all__ = ["RULES_DIR", "SemgrepUnavailable", "add_dataflow_traces", "run_semgrep"]

log = get_logger("workers.code.semgrep")

RULES_DIR = Path(__file__).resolve().parents[3] / "rules" / "semgrep"


class SemgrepUnavailable(RuntimeError):
    """Semgrep could not run (not installed, refused by the safety layer, or failed)."""


def _rel(path: str) -> str:
    rel = Path(path).as_posix()
    return rel[2:] if rel.startswith("./") else rel


def add_dataflow_traces(results: list[dict], source_root: Path) -> list[dict]:
    """Give each result inside a route handler the traced flow from a request input, if one exists."""
    files: dict[str, tuple[str, ast.Module] | None] = {}
    for r in results:
        rel = _rel(r.get("path", ""))
        line = (r.get("start") or {}).get("line")
        if not line or (r.get("extra") or {}).get("dataflow_trace"):
            continue
        if rel not in files:
            try:
                text = (source_root / rel).read_bytes().decode("utf-8", "replace")
                files[rel] = (text, ast.parse(text))
            except (OSError, SyntaxError, ValueError):
                files[rel] = None
        if files[rel] is None:
            continue
        text, tree = files[rel]
        if is_route_handler(tree, line):
            trace = trace_to_line(text, line, tree=tree)
        else:  # a helper: followed back one call, into a route handler of the same file (TNW-5)
            trace = trace_through_call(text, line, route_handlers(tree), tree=tree)
        if trace is None:
            continue
        payload = trace.as_payload()
        r.setdefault("extra", {})["dataflow_trace"] = {
            "taint_source": payload["source"],
            "steps": payload["steps"],
            "taint_sink": payload["sink"],
            "traced_by": payload["traced_by"],
            "handler": f"{rel}::{trace.function}",  # the route handler the input enters through
        }
    return results


async def run_semgrep(controller, scan_id: str, source_root: str | Path, *, only_file: str | None = None, rules_dir: Path = RULES_DIR) -> list[dict]:
    """Semgrep JSON results for the source (paths relative to it), taint traces added."""
    root = Path(source_root)
    args = {"path": str(root), "config": str(rules_dir)}
    if only_file:
        args["files"] = [only_file]
    result = await controller.run(ToolCall(tool="semgrep", scan_id=scan_id, args=args))
    if result.blocked_reason:
        raise SemgrepUnavailable(result.blocked_reason)
    output = result.output if isinstance(result.output, dict) else {}
    if not result.ok:
        raise SemgrepUnavailable(f"semgrep failed: {(result.stderr_tail or '').strip()[:200]}")
    for error in output.get("errors") or []:
        log.warning("semgrep.file_error", scan_id=scan_id, message=str(error.get("message", ""))[:200], path=error.get("path"))
    results = output.get("results") or []
    for r in results:
        r["path"] = _rel(r.get("path", ""))
    add_dataflow_traces(results, root)
    log.info("semgrep.done", scan_id=scan_id, results=len(results), file=only_file, rules=sorted({rule_id(r.get("check_id", "")) for r in results}))
    return results
