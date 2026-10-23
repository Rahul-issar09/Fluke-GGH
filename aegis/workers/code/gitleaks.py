"""Gitleaks wrapper (Worker 2, AG14.1, PHASES P7.5) — hard-coded secrets in the working tree.

Runs ``gitleaks dir`` through the SafetyController with ``--redact``, so gitleaks itself
replaces every secret value before AEGIS sees its report. As a second guard this wrapper
drops the ``Secret`` / ``Match`` fields entirely: no secret value can reach the evidence
store or the logs, whatever the gitleaks version does. File paths are made relative to the
scanned source.
"""

from __future__ import annotations

from pathlib import Path, PurePath

from aegis.observability import get_logger
from aegis.safety.models import ToolCall

__all__ = ["GitleaksUnavailable", "clean_report", "run_gitleaks"]

log = get_logger("workers.code.gitleaks")

_DROP = ("Secret", "Match", "Line")  # anything that could carry the value


class GitleaksUnavailable(RuntimeError):
    pass


def _relative(path: str, root: Path) -> str:
    p = PurePath(path)
    if p.is_absolute():
        try:
            return Path(p).resolve().relative_to(root.resolve()).as_posix()
        except ValueError:
            return p.as_posix()
    rel = p.as_posix()
    return rel[2:] if rel.startswith("./") else rel


def clean_report(items: list, root: Path) -> list[dict]:
    """The report without secret-bearing fields, with paths relative to *root*."""
    out = []
    for item in items if isinstance(items, list) else []:
        if not isinstance(item, dict):
            continue
        row = {k: v for k, v in item.items() if k not in _DROP}
        row["File"] = _relative(str(item.get("File", "")), root)
        out.append(row)
    return out


async def run_gitleaks(controller, scan_id: str, source_root: str | Path, *, only_file: str | None = None) -> list[dict]:
    root = Path(source_root)
    target = root / only_file if only_file else root
    result = await controller.run(ToolCall(tool="gitleaks", scan_id=scan_id, args={"path": str(target)}))
    if result.blocked_reason:
        raise GitleaksUnavailable(result.blocked_reason)
    if not result.ok:
        raise GitleaksUnavailable(f"gitleaks failed: {(result.stderr_tail or '').strip()[:200]}")
    report = clean_report(result.output if isinstance(result.output, list) else [], root)
    log.info("gitleaks.done", scan_id=scan_id, leaks=len(report), files=sorted({r["File"] for r in report}))
    return report
