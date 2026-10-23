"""Fix workspaces (AG11.1, PHASES P12.5).

A drafted fix is applied and proven on a **copy** of the scanned source, never on the
source itself: ``<workspaces_root>/<fix_id>/``. The copy leaves out what only adds weight
or risk (VCS metadata, virtualenvs, caches); symlinks are copied as links, so nothing
outside the source tree is pulled in.

``tree_hash`` lets callers prove the original was not touched.
"""

from __future__ import annotations

import hashlib
import re
import shutil
from pathlib import Path

from aegis.observability import get_logger

__all__ = ["WorkspaceError", "make_workspace", "remove_workspace", "tree_hash", "workspace_path"]

log = get_logger("fix.workspace")

_FIX_ID = re.compile(r"^X-\d{4,}$")
_SKIP = shutil.ignore_patterns(".git", ".hg", ".svn", ".venv", "venv", "node_modules", "__pycache__", "*.pyc", ".pytest_cache")


class WorkspaceError(Exception):
    """A workspace cannot be created safely."""


def workspace_path(workspaces_root: str | Path, fix_id: str) -> Path:
    if not _FIX_ID.match(fix_id):
        raise WorkspaceError(f"not a fix id: {fix_id!r}")
    root = Path(workspaces_root).resolve()
    if root.name != "workspaces":  # the git policy only lets `apply` patch <...>/workspaces/<id>
        raise WorkspaceError("the workspaces root must be a folder named 'workspaces'")
    return root / fix_id


def make_workspace(source_root: str | Path, workspaces_root: str | Path, fix_id: str) -> Path:
    """Copy *source_root* to ``<workspaces_root>/<fix_id>`` (replacing a stale copy) and return it."""
    source = Path(source_root).resolve()
    if not source.is_dir():
        raise WorkspaceError("the scanned source is not available")
    dest = workspace_path(workspaces_root, fix_id)
    root = dest.parent
    if root.is_relative_to(source) or source.is_relative_to(root):
        raise WorkspaceError("the workspaces root and the source must not contain each other")

    if dest.exists():
        shutil.rmtree(dest)
    root.mkdir(parents=True, exist_ok=True)
    shutil.copytree(source, dest, symlinks=True, ignore=_SKIP)
    files = sum(1 for p in dest.rglob("*") if p.is_file())
    log.info("fix.workspace_created", fix_id=fix_id, files=files)
    return dest


def remove_workspace(workspaces_root: str | Path, fix_id: str) -> None:
    shutil.rmtree(workspace_path(workspaces_root, fix_id), ignore_errors=True)


def tree_hash(root: str | Path) -> str:
    """One hash over every file's relative path and bytes (symlinks by their target)."""
    root = Path(root)
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root).as_posix()
        if path.is_symlink():
            digest.update(f"L {rel} -> {path.readlink()}\n".encode())
        elif path.is_file():
            digest.update(f"F {rel}\n".encode())
            digest.update(hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()
