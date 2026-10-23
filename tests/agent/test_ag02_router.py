"""AG02.2 / AG02.3 — mode selection, source prep, file list, stage plan."""

from __future__ import annotations

import asyncio
import pathlib

import pytest

from aegis.api.schemas import ScanRequest
from aegis.evidence.models import Mode
from aegis.router import (
    build_plan,
    cleanup_source,
    list_files,
    RepoScanUnavailable,
    prepare_source as _prepare_source,
    select_mode,
)

pytestmark = pytest.mark.phase("AG02")


# --- AG02.2 mode selection ------------------------------------------------- #

def prepare_source(**kwargs):  # the router's prepare_source is async since TNW-1
    return asyncio.run(_prepare_source(**kwargs))


def test_mode_runtime():
    assert select_mode(ScanRequest(url="http://demo-app:5000", identities="/id")) is Mode.runtime


def test_mode_code_folder():
    assert select_mode(ScanRequest(folder="/scan")) is Mode.code


def test_mode_code_repo():
    assert select_mode(ScanRequest(repo="https://x/y")) is Mode.code


def test_mode_correlated():
    req = ScanRequest(url="http://demo-app:5000", folder="/scan", identities="/id")
    assert select_mode(req) is Mode.correlated


# --- AG02.3 stage plan ----------------------------------------------------- #
def test_build_plan_per_mode():
    assert build_plan(Mode.runtime) == ["runtime"]
    assert build_plan(Mode.code) == ["code", "crypto"]
    assert build_plan(Mode.correlated) == ["runtime", "code", "crypto"]


# --- AG02.3 file listing --------------------------------------------------- #
def test_list_files_excludes_skip_dirs_and_gitignore(tmp_path):
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "main.py").write_text("x", encoding="utf-8")
    (tmp_path / "app" / "routes").mkdir()
    (tmp_path / "app" / "routes" / "accounts.py").write_text("x", encoding="utf-8")
    # skip-list dirs
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "junk.js").write_text("x", encoding="utf-8")
    (tmp_path / "__pycache__").mkdir()
    (tmp_path / "__pycache__" / "c.pyc").write_text("x", encoding="utf-8")
    # gitignored
    (tmp_path / ".gitignore").write_text("secret.txt\n*.log\n", encoding="utf-8")
    (tmp_path / "secret.txt").write_text("x", encoding="utf-8")
    (tmp_path / "app" / "debug.log").write_text("x", encoding="utf-8")

    files = list_files(str(tmp_path))
    assert "app/main.py" in files
    assert "app/routes/accounts.py" in files
    assert not any(f.startswith("node_modules/") for f in files)
    assert not any("__pycache__" in f for f in files)
    assert "secret.txt" not in files
    assert "app/debug.log" not in files


# --- AG02.3 source preparation --------------------------------------------- #
def test_prepare_folder_in_place(tmp_path):
    folder = tmp_path / "scan"
    folder.mkdir()
    prep = prepare_source(folder=str(folder))
    assert prep == {"source_path": str(folder), "cleanup": False}


def test_prepare_repo_with_injected_clone(tmp_path):
    def fake_clone(repo: str, dest: str, scan_id: str) -> None:
        d = pathlib.Path(dest)
        d.mkdir(parents=True)
        (d / "README.md").write_text("cloned", encoding="utf-8")

    prep = prepare_source(
        repo="https://x/y", scan_id="S-0001", clone_fn=fake_clone, tmp_root=str(tmp_path)
    )
    assert prep["cleanup"] is True
    assert pathlib.Path(prep["source_path"]).is_dir()


def test_prepare_repo_without_clone_raises(tmp_path):
    with pytest.raises(RepoScanUnavailable, match="AEGIS_SAFETY__GIT_HOSTS"):
        prepare_source(repo="https://x/y", tmp_root=str(tmp_path))


def test_failed_clone_leaves_nothing_behind(tmp_path):
    def failing_clone(repo: str, dest: str, scan_id: str) -> None:
        pathlib.Path(dest).mkdir(parents=True)
        raise RuntimeError("boom")

    with pytest.raises(RuntimeError):
        prepare_source(
            repo="https://x/y", scan_id="S-0003", clone_fn=failing_clone, tmp_root=str(tmp_path)
        )
    assert not (tmp_path / "aegis-S-0003").exists()


def test_cleanup_removes_clone(tmp_path):
    def fake_clone(repo: str, dest: str, scan_id: str) -> None:
        pathlib.Path(dest).mkdir(parents=True)

    prep = prepare_source(
        repo="https://x/y", scan_id="S-0002", clone_fn=fake_clone, tmp_root=str(tmp_path)
    )
    path = prep["source_path"]
    assert pathlib.Path(path).exists()
    cleanup_source(prep)
    assert not pathlib.Path(path).exists()


def test_cleanup_folder_is_noop(tmp_path):
    folder = tmp_path / "scan"
    folder.mkdir()
    prep = prepare_source(folder=str(folder))
    cleanup_source(prep)
    assert folder.exists()  # user folder never deleted
