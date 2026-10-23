"""AEGIS input router (PHASES P1).

Deterministic — never the LLM. AG02.1 implements request validation; mode
selection, source preparation, file listing and the stage plan follow in
AG02.2 / AG02.3.

Validation rules (P1.1):
* at least one of ``url`` / ``folder`` / ``repo`` is required,
* ``folder`` and ``repo`` are mutually exclusive,
* ``url`` must be http(s),
* ``identities`` are required when ``url`` is given (needed for the
  differential access-control check),
* ``folder`` must exist and its real path must resolve inside an allowed
  source root (path-traversal / symlink-escape defence, GAP C35),
* ``repo`` must be a public ``https://`` repository URL (``safety.repo_url``) on one of the
  configured git hosts (TNW-1).
"""

from __future__ import annotations

import inspect
import tempfile
from collections.abc import Callable, Iterable
from pathlib import Path

import pathspec

from aegis.api.schemas import ScanRequest
from aegis.config import get_api_settings
from aegis.evidence.models import Mode
from aegis.observability import get_logger
from aegis.safety.allowlist import Allowlist
from aegis.safety.repo_url import parse_repo_url
from aegis.workers.code.clone import remove_tree

__all__ = [
    "RepoScanUnavailable",
    "RequestInvalid",
    "validate_request",
    "select_mode",
    "prepare_source",
    "cleanup_source",
    "list_files",
    "build_plan",
    "SKIP_DIRS",
]

log = get_logger("router")

# Directories never scanned (P1.4 default skip-list).
SKIP_DIRS: frozenset[str] = frozenset(
    {
        "node_modules",
        "venv",
        ".venv",
        "dist",
        "build",
        "__pycache__",
        ".git",
        ".pytest_cache",
        ".mypy_cache",
        ".tox",
        ".idea",
    }
)

# Stage plan per mode (P1.5).
_PLANS: dict[Mode, list[str]] = {
    Mode.runtime: ["runtime"],
    Mode.code: ["code", "crypto"],
    Mode.correlated: ["runtime", "code", "crypto"],
}


class RequestInvalid(ValueError):
    """A scan request failed validation. ``reason`` is the client-facing cause
    (the API maps this to HTTP 422)."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def _reject(reason: str) -> "RequestInvalid":
    log.warning("router.request_invalid", reason=reason)
    return RequestInvalid(reason)


def _within_roots(folder: str, roots: Iterable[str]) -> bool:
    real = Path(folder).resolve()
    for root in roots:
        try:
            root_real = Path(root).resolve()
        except (OSError, ValueError):
            continue
        if real == root_real or real.is_relative_to(root_real):
            return True
    return False


def validate_request(
    req: ScanRequest,
    *,
    allowed_source_roots: Iterable[str] | None = None,
    git_hosts: Iterable[str] | None = None,
) -> ScanRequest:
    """Return *req* unchanged if valid, else raise :class:`RequestInvalid`.

    *git_hosts* (``safety.git_hosts``) are the hosts a repo may be cloned from; ``None`` skips
    that check here (the clone's own allowlist still enforces it)."""
    roots = tuple(allowed_source_roots or get_api_settings().allowed_source_roots)

    url = (req.url or "").strip() or None
    folder = (req.folder or "").strip() or None
    repo = (req.repo or "").strip() or None
    identities = (req.identities or "").strip() or None

    if not (url or folder or repo):
        raise _reject("at least one of url, folder or repo is required")

    if folder and repo:
        raise _reject("folder and repo are mutually exclusive")

    if url and not (url.startswith("http://") or url.startswith("https://")):
        raise _reject("url must be http(s)")

    if url and not identities:
        raise _reject("identities are required when url is given")

    if folder:
        path = Path(folder)
        if not path.exists() or not path.is_dir():
            raise _reject("folder does not exist")
        if not _within_roots(folder, roots):
            raise _reject("folder is outside the allowed source roots")

    verify = (req.options or {}).get("verify_tls", True)
    if not isinstance(verify, bool):
        raise _reject("options.verify_tls must be true or false")

    if repo:
        try:
            target = parse_repo_url(repo).target
        except ValueError as exc:
            raise _reject(str(exc)) from exc
        if git_hosts is not None and not Allowlist(git_hosts).check(target):
            raise _reject(
                f"repo scans from {target} are not enabled; add it to AEGIS_SAFETY__GIT_HOSTS "
                "(e.g. github.com:443)"
            )

    log.info(
        "router.request_valid",
        has_url=bool(url),
        has_folder=bool(folder),
        has_repo=bool(repo),
    )
    return req


# --------------------------------------------------------------------------- #
# AG02.2 — mode selection (deterministic, never the LLM)
# --------------------------------------------------------------------------- #
def select_mode(req: ScanRequest) -> Mode:
    """Pick Mode from the (already validated) request.

    url only → runtime · folder/repo only → code · both → correlated.
    """
    has_url = bool((req.url or "").strip())
    has_source = bool((req.folder or "").strip() or (req.repo or "").strip())
    if has_url and has_source:
        mode = Mode.correlated
    elif has_url:
        mode = Mode.runtime
    else:
        mode = Mode.code
    log.info("router.mode_selected", mode=mode.value)
    return mode


# --------------------------------------------------------------------------- #
# AG02.3 — source preparation, file listing, stage plan
# --------------------------------------------------------------------------- #
class RepoScanUnavailable(RuntimeError):
    """A repo scan was requested but no clone function is configured."""


def _clone_unavailable(repo: str, dest: str, scan_id: str) -> None:
    raise RepoScanUnavailable(
        "repo scans are not enabled: set AEGIS_SAFETY__GIT_HOSTS (e.g. github.com:443) and restart the backend"
    )


async def prepare_source(
    *,
    folder: str | None = None,
    repo: str | None = None,
    scan_id: str = "S-0000",
    clone_fn: Callable[[str, str, str], object] | None = None,
    tmp_root: str | None = None,
) -> dict:
    """Turn a folder or repo into a local, read-only source directory.

    * folder → used in place, never written, ``cleanup=False``.
    * repo → shallow-cloned by ``clone_fn(repo, dest, scan_id)`` (sync or async; the real one is
      ``workers.code.clone.make_clone_fn`` — a SafetyController ``git`` call) into
      ``<tmp_root>/aegis-<scan_id>``, ``cleanup=True``. What ``clone_fn`` returns (the commit,
      size …) is passed on as ``repo``.

    Returns ``{"source_path": str, "cleanup": bool}`` plus ``repo`` for a clone.
    """
    folder = (folder or "").strip() or None
    repo = (repo or "").strip() or None
    if folder:
        return {"source_path": folder, "cleanup": False}
    if repo:
        # resolve to absolute: the clone policy requires it, and the backend's data dir may be
        # relative (e.g. the launcher runs with AEGIS_DATA_DIR=data) — TNW-7
        root = Path(tmp_root or tempfile.gettempdir()).resolve()
        root.mkdir(parents=True, exist_ok=True)
        dest = root / f"aegis-{scan_id}"
        if dest.exists():  # a leftover from an earlier, interrupted run of this scan
            remove_tree(dest)
        try:
            info = (clone_fn or _clone_unavailable)(repo, str(dest), scan_id)
            if inspect.isawaitable(info):
                info = await info
        except BaseException:
            # a failed/partial clone must never be left behind
            remove_tree(dest)
            log.error("router.clone_failed", scan_id=scan_id, dest=str(dest))
            raise
        log.info("router.source_cloned", scan_id=scan_id, dest=str(dest))
        return {"source_path": str(dest), "cleanup": True, "repo": info if isinstance(info, dict) else {}}
    raise ValueError("prepare_source needs a folder or repo")


def cleanup_source(prep: dict) -> None:
    """Delete a temp clone (no-op for a user-supplied folder)."""
    if prep.get("cleanup") and prep.get("source_path"):
        remove_tree(prep["source_path"])
        log.info("router.source_cleaned", path=prep["source_path"])


def list_files(source_path: str) -> list[str]:
    """List scannable files (relative, POSIX) under *source_path*.

    Excludes the default skip-list and any path matched by a root
    ``.gitignore``.
    """
    root = Path(source_path)
    spec: pathspec.PathSpec | None = None
    gitignore = root / ".gitignore"
    if gitignore.exists():
        spec = pathspec.PathSpec.from_lines(
            "gitignore", gitignore.read_text(encoding="utf-8").splitlines()
        )

    out: list[str] = []
    for path in root.rglob("*"):
        if path.is_dir():
            continue
        rel = path.relative_to(root)
        if set(rel.parts) & SKIP_DIRS:
            continue
        rel_posix = rel.as_posix()
        if spec is not None and spec.match_file(rel_posix):
            continue
        out.append(rel_posix)
    return sorted(out)


def build_plan(mode: Mode) -> list[str]:
    """Ordered stage list for a mode (P1.5)."""
    return list(_PLANS[mode])
