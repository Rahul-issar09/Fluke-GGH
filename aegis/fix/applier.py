"""Apply a drafted diff to a fix workspace (AG11.1, PHASES P12.5).

The patch is applied with ``git apply`` through the SafetyController (an audited tool
call whose policy only lets ``apply`` patch a ``workspaces/<fix_id>`` folder). ``git apply``
is atomic — either every hunk applies or no file changes — and refuses paths that leave
the folder.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from aegis.observability import get_logger
from aegis.safety.models import ToolCall

__all__ = ["ApplyResult", "apply_diff", "changed_files"]

log = get_logger("fix.applier")

_PATCH_NAME = ".aegis-fix.patch"


@dataclass
class ApplyResult:
    ok: bool
    reason: str | None = None
    files: list[str] = field(default_factory=list)


def changed_files(diff: str) -> list[str]:
    files = []
    for line in diff.splitlines():
        if line.startswith("+++ "):
            name = line[4:].strip()
            files.append(name[2:] if name.startswith("b/") else name)
    return files


async def apply_diff(controller, scan_id: str, workspace: Path, diff: str) -> ApplyResult:
    """Apply *diff* inside *workspace*; return what changed or why it could not be applied."""
    files = changed_files(diff)
    if not diff.strip() or not files:
        return ApplyResult(ok=False, reason="the fix has no diff")

    patch = workspace / _PATCH_NAME
    patch.write_bytes(diff.encode("utf-8"))
    try:
        result = await controller.run(
            ToolCall(tool="git", scan_id=scan_id, args={"op": "apply", "patch": str(patch), "workdir": str(workspace)})
        )
    finally:
        patch.unlink(missing_ok=True)

    if result.blocked_reason:
        reason = f"could not apply the diff: {result.blocked_reason}"
    elif not result.ok:
        reason = f"the diff does not apply: {(result.stderr_tail or '').strip()[:300] or f'git exit {result.exit_code}'}"
    else:
        log.info("fix.applied", scan_id=scan_id, workspace=workspace.name, files=files)
        return ApplyResult(ok=True, files=files)
    log.info("fix.apply_failed", scan_id=scan_id, workspace=workspace.name, reason=reason)
    return ApplyResult(ok=False, reason=reason, files=files)
