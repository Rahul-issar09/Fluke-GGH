"""TruffleHog wrapper (Worker 2, AG14 / PHASES P7.6) — a second, independent secret scanner.

``trufflehog filesystem --no-verification --no-update``: found secrets are never sent anywhere to
be tested. TruffleHog has no redaction option and reports the raw value (``Raw``/``RawV2`` and in
other fields), so this wrapper keeps an explicit list of safe fields — detector, file, line,
verified — and drops everything else before anything is stored or logged.
"""

from __future__ import annotations

from pathlib import Path, PurePath

from aegis.observability import get_logger
from aegis.safety.models import ToolCall

__all__ = ["TrufflehogUnavailable", "clean_results", "run_trufflehog"]

log = get_logger("workers.code.trufflehog")


class TrufflehogUnavailable(RuntimeError):
    pass


def _relative(path: str, root: Path) -> str:
    p = PurePath(path)
    if p.is_absolute():
        try:
            return Path(p).resolve().relative_to(root.resolve()).as_posix()
        except ValueError:
            return p.as_posix()
    try:  # trufflehog reports the path as given on the command line
        return Path(p).resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return p.as_posix()


def clean_results(rows: list, root: Path) -> list[dict]:
    """Only detector / file / line / verified survive; the secret value never leaves this function."""
    out = []
    for row in rows if isinstance(rows, list) else []:
        if not isinstance(row, dict):
            continue
        fs = ((row.get("SourceMetadata") or {}).get("Data") or {}).get("Filesystem") or {}
        if not fs.get("file"):
            continue
        out.append({
            "detector": str(row.get("DetectorName") or "unknown"),
            "description": str(row.get("DetectorDescription") or "")[:200],
            "file": _relative(str(fs["file"]), root),
            "line": fs.get("line"),
            "verified": bool(row.get("Verified")),
        })
    return out


async def run_trufflehog(controller, scan_id: str, source_root: str | Path) -> list[dict]:
    root = Path(source_root)
    result = await controller.run(ToolCall(tool="trufflehog", scan_id=scan_id, args={"path": str(root)}))
    if result.blocked_reason:
        raise TrufflehogUnavailable(result.blocked_reason)
    if not result.ok:
        raise TrufflehogUnavailable(f"trufflehog failed: {(result.stderr_tail or '').strip()[:200]}")
    found = clean_results(result.output if isinstance(result.output, list) else [], root)
    log.info("trufflehog.done", scan_id=scan_id, secrets=len(found), files=sorted({f["file"] for f in found}))
    return found
