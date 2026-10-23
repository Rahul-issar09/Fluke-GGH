"""Commit a verified, approved fix (AG11.2, PHASES P12.8, SYSTEM_DESIGN §5.7).

* ``patch`` — write the diff to ``<patches_dir>/<fix_id>.diff`` for the user to apply. Nothing
  of the user's is touched. Always available.
* ``apply`` — write the verified files from the workspace into the scanned folder. Refused
  (nothing written) when the scan was of a cloned repository (the "original" is a temp clone),
  when the folder is read-only (conflict C14: a read-only mount), or when any target file has
  changed since the fix was verified — a commit never overwrites the user's newer work. All
  files are checked first, then written; a failed write rolls back the ones already written.
* ``pr`` — not available yet: it needs the ``gh`` tool in the tool contract (conflict C6) and a
  connected (online) mode. It is refused, never attempted.

A secret fix carries the warning that the key was already committed and must be rotated:
removing it from the code does not un-leak it.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field
from pathlib import Path

from aegis.observability import get_logger

__all__ = ["CommitResult", "MODES", "ROTATE_WARNING", "commit_fix", "unavailable_reason"]

log = get_logger("fix.committer")

MODES = ("patch", "apply", "pr")
ROTATE_WARNING = "The key was already committed — rotate it. Removing it from the code does not revoke it."
PR_UNAVAILABLE = (
    "pr mode is not available: it needs the 'gh' tool in the tool contract (conflict C6) "
    "and a connected mode; use patch or apply"
)


@dataclass
class CommitResult:
    ok: bool
    mode: str
    reason: str | None = None
    path: str | None = None
    files: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {"ok": self.ok, "mode": self.mode, "reason": self.reason, "path": self.path, "files": self.files, "warnings": self.warnings}


def unavailable_reason(mode: str) -> str | None:
    """Why *mode* can never be used right now (``None`` if it can be tried)."""
    if mode not in MODES:
        return f"unknown commit mode {mode!r}; choose one of {', '.join(MODES)}"
    if mode == "pr":
        return PR_UNAVAILABLE
    return None


def _sha(path: Path) -> str | None:
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None


def _write_patch(fix_id: str, finding_id: str, diff: str, patches_dir: Path, warnings: list[str]) -> Path:
    patches_dir.mkdir(parents=True, exist_ok=True)
    path = patches_dir / f"{fix_id}.diff"
    # git apply / patch ignore text before the first "---" header, so the notes travel with the diff
    header = [f"# AEGIS fix {fix_id} for {finding_id} — verified, approved", *(f"# WARNING: {w}" for w in warnings), ""]
    path.write_bytes(("\n".join(header) + "\n" + diff).encode("utf-8"))
    return path


def _apply_files(source: Path, workspace: Path, files: list[str], expected: dict[str, str | None]) -> str | None:
    """Write the workspace's verified files into *source*; return why not, or ``None`` on success."""
    for rel in files:
        target, patched = source / rel, workspace / rel
        if not target.resolve().is_relative_to(source.resolve()):
            return f"{rel} is outside the scanned folder"
        if not patched.is_file():
            return f"the verified copy of {rel} is missing"
        if _sha(target) != expected.get(rel):
            return f"{rel} has changed since the fix was verified; re-scan before applying"
        if not os.access(target if target.exists() else target.parent, os.W_OK):
            return f"{rel} is read-only (the source is mounted read-only); use patch mode"

    written: list[tuple[Path, bytes | None]] = []
    try:
        for rel in files:
            target = source / rel
            before = target.read_bytes() if target.exists() else None
            tmp = target.with_name(target.name + ".aegis-tmp")
            tmp.write_bytes((workspace / rel).read_bytes())
            os.replace(tmp, target)
            written.append((target, before))
    except OSError as exc:
        for target, before in reversed(written):  # all or nothing
            if before is not None:
                target.write_bytes(before)
        return f"could not write the fix ({type(exc).__name__}); nothing was changed"
    return None


def commit_fix(
    mode: str,
    *,
    fix_id: str,
    finding_id: str,
    finding_type: str,
    diff: str,
    files: list[str],
    source_files: dict[str, str | None],
    workspace: Path | None,
    source: Path | None,
    from_clone: bool,
    patches_dir: Path,
) -> CommitResult:
    warnings = [ROTATE_WARNING] if finding_type == "secret" else []
    blocked = unavailable_reason(mode)
    if blocked:
        return CommitResult(ok=False, mode=mode, reason=blocked, warnings=warnings)

    if mode == "patch":
        path = _write_patch(fix_id, finding_id, diff, patches_dir, warnings)
        log.info("fix.committed", fix_id=fix_id, mode=mode, path=str(path))
        return CommitResult(ok=True, mode=mode, path=str(path), files=files, warnings=warnings)

    # apply
    if from_clone:
        reason = "this scan was of a cloned repository, so there is no folder of yours to apply to; use patch"
    elif source is None or workspace is None or not source.is_dir() or not workspace.is_dir():
        reason = "the scanned folder or the verified copy is no longer available"
    else:
        reason = _apply_files(source, workspace, files, source_files)
    if reason:
        log.info("fix.commit_refused", fix_id=fix_id, mode=mode, reason=reason)
        return CommitResult(ok=False, mode=mode, reason=reason, files=files, warnings=warnings)
    log.info("fix.committed", fix_id=fix_id, mode=mode, files=files)
    return CommitResult(ok=True, mode=mode, path=str(source), files=files, warnings=warnings)
