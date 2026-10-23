"""CLI01 — packaging and the `aegis` command (CLI_PHASES.md).

Guards what makes a fresh checkout installable and the command usable on Windows and Linux:
every third-party import is a declared dependency, every data file inside the package ships with
it, both console scripts resolve, the help works from any folder, and the byte-exact demo and
fixture files keep LF line endings (a CRLF checkout made 53 tests fail).
"""

from __future__ import annotations

import ast
import fnmatch
import importlib
import importlib.metadata as md
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name
from typer.testing import CliRunner

from aegis.cli.main import app

pytestmark = pytest.mark.phase("CLI01")

ROOT = Path(__file__).resolve().parents[2]
PYPROJECT = (ROOT / "pyproject.toml").read_text(encoding="utf-8")


def _table(name: str) -> str:
    """The body of one ``[table]`` of pyproject.toml (no TOML parser on Python 3.10)."""
    m = re.search(rf"^\[{re.escape(name)}\]\s*$(.*?)(?=^\[|\Z)", PYPROJECT, re.M | re.S)
    assert m, f"[{name}] missing from pyproject.toml"
    return m.group(1)


_REQ = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*\s*(\[|[<>=!~;]|$)")


def _requirements() -> set[str]:
    """Every distribution named in dependencies and optional-dependencies (canonical names)."""
    deps = re.search(r"^dependencies\s*=\s*\[(.*?)^\]", _table("project"), re.M | re.S)
    assert deps, "dependencies = [...] missing from [project]"
    text = deps.group(1) + _table("project.optional-dependencies")
    return {canonicalize_name(Requirement(r).name) for r in re.findall(r'"([^"]+)"', text) if _REQ.match(r)}


def _import_providers() -> dict[str, set[str]]:
    """Import name -> distributions that install it, from each distribution's file list.

    ``importlib.metadata.packages_distributions`` on Python 3.10 reads only ``top_level.txt``, which
    many current wheels (structlog, fastapi, jinja2) no longer ship, so derive it from RECORD instead.
    """
    out: dict[str, set[str]] = {}
    for dist in md.distributions():
        name = canonicalize_name(dist.metadata["Name"] or "")
        for f in dist.files or []:
            top = f.parts[0] if f.parts else ""
            if top.endswith((".dist-info", ".egg-info", ".data")) or top in ("..", "__pycache__", ""):
                continue
            mod = top[:-3] if top.endswith(".py") else top.split(".")[0]
            if mod.isidentifier():
                out.setdefault(mod, set()).add(name)
    return out


def _third_party_imports() -> dict[str, set[str]]:
    std = set(sys.stdlib_module_names)
    found: dict[str, set[str]] = {}
    for path in (ROOT / "aegis").rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            names = []
            if isinstance(node, ast.Import):
                names = [a.name.split(".")[0] for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                names = [node.module.split(".")[0]]
            for name in names:
                if name not in std and name != "aegis":
                    found.setdefault(name, set()).add(str(path.relative_to(ROOT)))
    return found


def test_every_third_party_import_is_a_declared_dependency():
    declared = _requirements()
    providers = _import_providers()
    missing = {}
    for module, files in _third_party_imports().items():
        if not providers.get(module, set()) & declared:
            missing[module] = sorted(files)[:3]
    assert not missing, f"imported but not declared in pyproject.toml: {missing}"


def test_every_data_file_in_the_package_ships_with_it():
    globs = re.findall(r'"([^"]+)"', _table("tool.setuptools.package-data"))
    data = [p for p in (ROOT / "aegis").rglob("*")
            if p.is_file() and p.suffix not in (".py", ".pyc") and "__pycache__" not in p.parts]
    unshipped = [str(p.relative_to(ROOT)) for p in data
                 if not any(fnmatch.fnmatch(p.relative_to(ROOT / "aegis").as_posix(), g) for g in globs)]
    assert data and not unshipped, f"data files not listed in package-data: {unshipped}"


def test_console_scripts_resolve_to_callables():
    scripts = dict(re.findall(r'^([\w-]+)\s*=\s*"([^"]+)"', _table("project.scripts"), re.M))
    assert set(scripts) == {"aegis", "aegis-mcp"}
    for name, target in scripts.items():
        module, _, attr = target.partition(":")
        assert callable(getattr(importlib.import_module(module), attr)), name


# ------------------------------------------------------------------------------------------ command
runner = CliRunner()


def test_help_describes_the_three_scan_modes():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "Usage" in result.output and "(M1)" in result.output and "(M3)" in result.output


def test_no_arguments_shows_help_and_succeeds():
    result = runner.invoke(app, [])
    assert result.exit_code == 0 and "Usage" in result.output


def test_an_unknown_option_is_a_usage_error():
    assert runner.invoke(app, ["--no-such-option"]).exit_code == 2


def test_python_dash_m_works_from_any_folder(tmp_path):
    env = {**os.environ, "PYTHONPATH": str(ROOT)}
    proc = subprocess.run([sys.executable, "-m", "aegis.cli", "--help"], cwd=tmp_path, env=env,
                          capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60)
    assert proc.returncode == 0, proc.stderr[-400:]
    assert "Usage" in proc.stdout


# ------------------------------------------------------------------------------------------ line endings
@pytest.mark.skipif(shutil.which("git") is None or not (ROOT / ".git").exists(), reason="needs git and a checkout")
@pytest.mark.parametrize("path", [
    "demo-app/app/routes/accounts.py", "demo-app-patched/app/routes/accounts.py",
    "tests/fixtures/golden/routes_demo_app.json", "rules/fix_templates/sqli.md",
])
def test_byte_exact_files_keep_lf_endings_on_every_os(path):
    out = subprocess.run(["git", "check-attr", "eol", "--", path], cwd=ROOT, capture_output=True, text=True, timeout=30)
    assert out.stdout.strip().endswith("eol: lf"), out.stdout
