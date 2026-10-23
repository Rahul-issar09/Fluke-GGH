"""N2 — `aegis scan run / watch / cancel` through the API (cli_new_phases.md).

The real API runs in-process with the same fakes as the API tests (fake scanners, fake model, the
demo app in memory), so complete M2 and M3 scans run in seconds without real tools or a network.
"""

from __future__ import annotations

import json
import re
import shutil

import pytest
from typer.testing import CliRunner

from aegis.cli import errors
from aegis.cli.commands.scan_run import build_request, mode_of
from aegis.cli.main import app
from aegis.config import ApiSettings, AppSettings, ModelSettings
from fakes import api_server
from fakes.demo_apps import ROOT, demo_stack
from fakes.fake_llm import PickFirstLLM
from fakes.tool_executors import fix_executor

pytestmark = pytest.mark.phase("N2")

runner = CliRunner()
DOWN = "http://127.0.0.1:9"


@pytest.fixture
def world(tmp_path, monkeypatch):
    src = tmp_path / "src" / "demo-app"
    shutil.copytree(ROOT / "demo-app" / "app", src / "app")
    shutil.copy(ROOT / "demo-app" / "identities.yml", src / "identities.yml")
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    router, _listener = demo_stack("vulnerable")
    settings = AppSettings(
        data_dir=str(tmp_path / "data"), offline_db_dir=str(tmp_path / "offline-db"),
        allowlist=("demo-app:5000", "callback:8080"), model=ModelSettings(ollama_url=DOWN),
        api=ApiSettings(allowed_source_roots=(str(tmp_path / "src"),)),
    )
    overrides = dict(http_transport=router, tool_executor=fix_executor, llm=PickFirstLLM(),
                     rate_limit_rps=1000.0, rate_limit_burst=1000, oob_wait_s=0.3)
    stop = api_server.serve(monkeypatch, settings, agent_overrides=overrides)
    yield {"src": src, "identities": src / "identities.yml", "outside": outside}
    stop()


def cli(*args):
    return runner.invoke(app, list(args))


def test_m2_folder_scan_runs_shows_progress_and_a_summary(world):
    result = cli("scan", "run", "--folder", str(world["src"]))
    assert result.exit_code == 0, result.stderr
    out = result.stdout
    assert "Scan mode: M2" in out and "Following S-" in out
    assert "semgrep" in out                                   # one progress line per finished step
    assert re.search(r"Status +completed", out) and "CI gate:" in out and "Next:" in out


def test_m3_full_scan_through_the_api(world):
    result = cli("--json", "scan", "run", "--url", "http://demo-app:5000", "--identities", str(world["identities"]),
                 "--folder", str(world["src"]))
    assert result.exit_code == 0, result.stderr
    summary = json.loads(result.stdout)                       # --json: only the final summary on stdout
    assert summary["scan"]["mode"] == "correlated" and summary["scan"]["status"] == "completed"
    assert any(f["type"] == "broken_access_control" for f in summary["findings"])
    assert summary["gate"]["exit_code"] in (0, 1) and summary["total_findings"] >= len(summary["findings"])
    assert "own or have written permission" in result.stderr   # the authorisation note for live targets


def test_detach_then_watch_and_cancel(world):
    started = cli("--json", "scan", "run", "--folder", str(world["src"]), "--detach")
    assert started.exit_code == 0, started.stderr
    info = json.loads(started.stdout)
    assert info["mode"] == "M2" and info["scan_id"].startswith("S-")
    watched = cli("scan", "watch", info["scan_id"])
    assert watched.exit_code == 0 and "completed" in watched.stdout
    cancelled = cli("--json", "scan", "cancel", info["scan_id"])  # finished already: a no-op, still exit 0
    assert cancelled.exit_code == 0 and json.loads(cancelled.stdout) == {"scan_id": info["scan_id"], "cancelled": True}


def test_the_api_refusal_is_shown_with_its_reason(world):
    result = cli("scan", "run", "--folder", str(world["outside"]))
    assert result.exit_code == errors.USAGE and "outside the allowed source roots" in result.stderr


@pytest.mark.parametrize("args, reason", [
    (["--url", "127.0.0.1:5000", "--identities", "x"], "must start with http"),
    (["--folder", ".", "--repo", "https://github.com/a/b"], "cannot be used together"),
    (["--url", "http://127.0.0.1:5000"], "needs --identities"),
    (["--folder", "no/such/folder"], "folder not found"),
    (["--repo", "git@github.com:a/b.git"], "https://"),
    ([], "give what to scan"),
])
def test_obvious_typos_are_caught_before_sending(args, reason):
    result = runner.invoke(app, ["--api", DOWN, "scan", "run", *args])   # never reaches the (absent) API
    assert result.exit_code == errors.USAGE and reason in result.stderr


def test_scans_need_the_api(tmp_path):
    assert runner.invoke(app, ["--local", "scan", "run", "--folder", str(tmp_path)]).exit_code == errors.USAGE
    down = runner.invoke(app, ["--api", DOWN, "scan", "run", "--folder", str(tmp_path)])
    assert down.exit_code == errors.UNAVAILABLE and "not running" in down.stderr


def test_mode_rule_matches_the_api(tmp_path):
    ident = tmp_path / "ids.yml"
    ident.write_text("x", encoding="utf-8")
    assert mode_of(build_request("http://a:1", None, None, str(ident))) == "M1"
    assert mode_of(build_request(None, str(tmp_path), None, None)) == "M2"
    assert mode_of(build_request(None, None, "https://github.com/a/b", None)) == "M2"
    assert mode_of(build_request("http://a:1", None, "https://github.com/a/b", str(ident))) == "M3"
    body = build_request(None, f'"{tmp_path}"', None, None, ["127.0.0.1:5443"])   # quotes from copy-paste are removed
    assert body == {"folder": str(tmp_path.resolve()), "options": {"tls_targets": ["127.0.0.1:5443"]}}
