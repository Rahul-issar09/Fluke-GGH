"""Repository scans (TNW-1): a shallow clone of a public https repo, through the SafetyController.

The clone is the only networked step of a repo scan. It is a ``git`` tool call like any other
(allowlist → policy → rate limit → execute → audit); the allowlist here is the configured git
hosts (``safety.git_hosts``), not the scan targets. After the clone:

* the commit that was scanned is read from ``.git`` (for the report),
* ``.git`` is removed — scanners read the working tree, and nothing later runs git config or
  hooks from a downloaded repository,
* the working tree must stay under the size and file-count limits, or the clone is deleted.

Clones live in ``<data_dir>/clones/aegis-<scan_id>``. They are kept after the scan so its fixes
can be verified on a copy (fix ``apply`` mode is refused for clones — patch only), and removed by
:func:`prune_clones`: a failed or cancelled scan's clone right away, others after
``keep_hours``. A failed clone never leaves a folder behind (``router.prepare_source``).
"""

from __future__ import annotations

import os
import re
import shutil
import stat
from collections.abc import Awaitable, Callable, Iterable
from datetime import datetime, timedelta, timezone
from pathlib import Path

from aegis.observability import get_logger
from aegis.safety.allowlist import Allowlist
from aegis.safety.controller import SafetyController
from aegis.safety.models import ToolCall
from aegis.safety.rate_limiter import RateLimiter
from aegis.safety.repo_url import parse_repo_url
from aegis.safety.test_inputs import TestInputLibrary

__all__ = [
    "CloneError",
    "CLONE_PREFIX",
    "clone_repo",
    "make_clone_fn",
    "prune_clones",
    "read_commit",
    "remove_tree",
]

log = get_logger("worker.code.clone")

CLONE_PREFIX = "aegis-"
_CLONE_NAME = re.compile(r"^aegis-(S-\d{4,})$")  # only folders AEGIS named are ever pruned
DEFAULT_MAX_MB = 500
DEFAULT_MAX_FILES = 50_000
DEFAULT_KEEP_HOURS = 24
_FINISHED_BADLY = {"failed", "cancelled"}


class CloneError(RuntimeError):
    """The repository could not be cloned (the message says why, for the scan's failure reason)."""


def _make_writable(func, path, _exc_info) -> None:
    # git writes its pack files read-only; Windows refuses to delete those until they are writable
    try:
        os.chmod(path, stat.S_IWRITE)
        func(path)
    except OSError as exc:
        log.warning("clone.remove_failed", path=str(path), error=str(exc))


def remove_tree(path: str | Path) -> None:
    """Delete a folder, read-only files included; a missing folder is fine. Never raises (a file
    that still cannot be removed is logged)."""
    path = Path(path)
    if path.exists():
        shutil.rmtree(path, onerror=_make_writable)


def read_commit(git_dir: Path) -> str | None:
    """The checked-out commit of a clone, read from its ``.git`` folder without running git."""
    try:
        head = (git_dir / "HEAD").read_text(encoding="utf-8").strip()
    except OSError:
        return None
    if not head.startswith("ref:"):
        return head if len(head) in (40, 64) else None
    ref = head[4:].strip()
    loose = git_dir / ref
    if loose.is_file():
        return loose.read_text(encoding="utf-8").strip() or None
    packed = git_dir / "packed-refs"
    if packed.is_file():
        for line in packed.read_text(encoding="utf-8").splitlines():
            parts = line.split()
            if len(parts) == 2 and parts[1] == ref:
                return parts[0]
    return None


def _branch(git_dir: Path) -> str | None:
    try:
        head = (git_dir / "HEAD").read_text(encoding="utf-8").strip()
    except OSError:
        return None
    return head.rsplit("/", 1)[-1] if head.startswith("ref: refs/heads/") else None


def _measure(root: Path) -> tuple[int, int]:
    total = files = 0
    for dirpath, _dirs, names in os.walk(root):
        for name in names:
            try:
                total += os.lstat(os.path.join(dirpath, name)).st_size
            except OSError:
                continue
            files += 1
    return total, files


async def clone_repo(
    controller: SafetyController,
    scan_id: str,
    repo: str,
    dest: str | Path,
    *,
    max_bytes: int = DEFAULT_MAX_MB * 1024 * 1024,
    max_files: int = DEFAULT_MAX_FILES,
) -> dict:
    """Clone *repo* into *dest* (which must not exist yet) and return what was cloned.

    Raises :class:`CloneError` with a readable reason; the caller removes a partial *dest*."""
    try:
        url = parse_repo_url(repo)
    except ValueError as exc:
        raise CloneError(str(exc)) from exc
    dest = Path(dest)
    result = await controller.run(
        ToolCall(
            tool="git",
            scan_id=scan_id,
            target_host=url.target,
            args={"op": "clone", "repo": repo, "dest": str(dest), "depth": 1},
        )
    )
    if not result.ok:
        if result.blocked_reason and result.blocked_reason.startswith("host not allowlisted"):
            raise CloneError(
                f"{url.host} is not an allowed git host; add {url.target} to AEGIS_SAFETY__GIT_HOSTS"
            )
        reason = result.blocked_reason or (result.stderr_tail or "").strip() or f"git exited with {result.exit_code}"
        raise CloneError(f"git clone failed: {reason[-300:]}")
    if not dest.is_dir():
        raise CloneError("git clone reported success but wrote no folder")

    git_dir = dest / ".git"
    commit, branch = read_commit(git_dir), _branch(git_dir)
    remove_tree(git_dir)
    size, files = _measure(dest)
    if size > max_bytes or files > max_files:
        raise CloneError(
            f"the repository is too large to scan ({size // (1024 * 1024)} MB, {files} files; "
            f"the limit is {max_bytes // (1024 * 1024)} MB and {max_files} files)"
        )
    info = {"url": repo, "name": url.name, "host": url.host, "commit": commit, "branch": branch, "bytes": size, "files": files}
    log.info("clone.done", scan_id=scan_id, **{k: v for k, v in info.items() if k != "url"})
    return info


def make_clone_fn(
    git_hosts: Iterable[str],
    *,
    executor: Callable[..., Awaitable] | None = None,
    audit_sink: Callable[[dict], None] | None = None,
    max_bytes: int = DEFAULT_MAX_MB * 1024 * 1024,
    max_files: int = DEFAULT_MAX_FILES,
) -> Callable[[str, str, str], Awaitable[dict]]:
    """The ``AgentDeps.clone_fn`` for the configured git hosts: ``await clone_fn(repo, dest, scan_id)``."""
    from aegis.workers.executor import execute_tool  # the real executor, unless a test injects one

    hosts = tuple(git_hosts)

    async def clone_fn(repo: str, dest: str, scan_id: str) -> dict:
        controller = SafetyController(
            Allowlist(hosts),
            TestInputLibrary.load(),
            RateLimiter(),
            executor=executor or execute_tool,
            audit_sink=audit_sink,
        )
        return await clone_repo(controller, scan_id, repo, dest, max_bytes=max_bytes, max_files=max_files)

    return clone_fn


def prune_clones(clones_root: str | Path, store, *, keep_hours: float = DEFAULT_KEEP_HOURS, now: datetime | None = None) -> list[str]:
    """Remove clones that are no longer needed; return the removed scan ids.

    A clone is removed when its scan is unknown, failed or cancelled, or finished more than
    *keep_hours* ago. A queued or running scan's clone is always kept."""
    root = Path(clones_root)
    if not root.is_dir():
        return []
    now = now or datetime.now(timezone.utc)
    removed: list[str] = []
    for folder in root.iterdir():
        match = _CLONE_NAME.match(folder.name)
        if not (match and folder.is_dir()):
            continue
        scan_id = match.group(1)
        scan = store.get_scan(scan_id)
        status = getattr(getattr(scan, "status", None), "value", getattr(scan, "status", None))
        finished = getattr(scan, "finished_at", None)
        if finished is not None and finished.tzinfo is None:
            finished = finished.replace(tzinfo=timezone.utc)
        expired = finished is not None and now - finished > timedelta(hours=keep_hours)
        if scan is None or status in _FINISHED_BADLY or expired:
            remove_tree(folder)
            removed.append(scan_id)
    if removed:
        log.info("clone.pruned", scans=removed)
    return removed
