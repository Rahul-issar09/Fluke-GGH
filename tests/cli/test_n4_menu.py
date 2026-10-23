"""N4 — the interactive menu (cli_new_phases.md).

The menu is driven with scripted answers against the real API run in-process (fake scanners and a
fake model, as in N2): scan in each mode, see progress and the summary, land in the question prompt,
handle bad input, an API refusal, no scans yet, and an API that is not running.
"""

from __future__ import annotations

import shutil

import pytest
from typer.testing import CliRunner

from aegis.cli import main as cli_main
from aegis.cli.context import build_context
from aegis.cli.main import app
from aegis.cli.ui.menu import run_menu
from aegis.config import ApiSettings, AppSettings, ModelSettings
from fakes import api_server
from fakes.demo_apps import ROOT, demo_stack
from fakes.fake_llm import PickFirstLLM
from fakes.tool_executors import fix_executor

pytestmark = pytest.mark.phase("N4")

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
    monkeypatch.chdir(tmp_path)                                  # an on-demand report is saved here
    yield {"src": src, "identities": src / "identities.yml", "outside": outside}
    stop()


def script(*answers):
    """A reader that gives *answers* in order, then ends the input (like Ctrl+Z / Ctrl+D)."""
    queue = list(answers)

    def read(prompt: str) -> str:
        if not queue:
            raise EOFError
        return queue.pop(0)

    return read


def menu(*answers, api=None):
    return run_menu(build_context(api=api), read=script(*answers))


def test_m2_scan_from_the_menu_then_questions(world, capsys):
    code = menu("1", "2", "2", str(world["src"]), "", "",      # Scan → M2 → local folder → path → keep model → start
                "how many findings are there?", "/quit",       # the question prompt for that scan
                "0")                                            # back in the main menu → exit
    out = capsys.readouterr().out
    assert code == 0
    assert "Which kind of scan?" in out and "Ready to scan" in out and "M2 - code only" in out
    assert "Following S-0001" in out and "CI gate:" in out
    assert "Ask about S-0001" in out and "finding" in out.split("Ask about S-0001")[1]


def test_m3_scan_asks_for_authorisation_and_respects_no(world, capsys):
    code = menu("1", "3", "not-a-url", "http://demo-app:5000", str(world["identities"]), "2", str(world["src"]),
                "n",                                            # not authorised → nothing starts
                "0", "0")
    out, err = capsys.readouterr()
    assert code == 0 and "must start with http" in err
    assert "M3 - full" in out and "Not started." in out and "Following" not in out


def test_an_api_refusal_is_explained(world, capsys):
    code = menu("1", "2", "2", str(world["outside"]), "", "", "0", "0")
    err = capsys.readouterr().err
    assert code == 0 and "refused the scan" in err and "outside the allowed source roots" in err
    assert "AEGIS_API__ALLOWED_SOURCE_ROOTS" in err


def test_the_scan_asks_which_model_and_enter_keeps_the_active_one(world, capsys):
    code = menu("1", "2", "2", str(world["src"]), "x", "", "", "/quit", "0")   # a bad answer is asked again
    out, err = capsys.readouterr()
    assert code == 0 and "AI for this scan" in out and "type 1, 2 or 0" in err
    assert "AI for this scan: " in out and "(offline, this machine)" in out and "Following S-0001" in out


def test_back_from_the_model_question_starts_nothing(world, capsys):
    code = menu("1", "2", "2", str(world["src"]), "0", "0", "0")              # AI question → back → modes → main
    out = capsys.readouterr().out
    assert code == 0 and "AI for this scan" in out and "Following" not in out


def test_options_need_a_finished_scan(world, capsys):
    code = menu("2", "0")
    out, err = capsys.readouterr()
    assert code == 0 and "(needs a scan - choose 1 first)" in out and "no finished scan yet" in err


def test_results_report_and_history_after_a_scan(world, capsys):
    menu("1", "2", "2", str(world["src"]), "", "", "/quit", "0")
    capsys.readouterr()
    code = menu("3", "", "F-0001", "",                         # Results → default scan → open F-0001 → back
                "4", "", "n",                                  # Report & gate → default scan → don't open
                "5", "0")                                      # history → exit
    out = capsys.readouterr().out
    assert code == 0
    assert "Findings of S-0001" in out and "F-0001  " in out and "Risk" in out
    assert "Gate for S-0001" in out and "Report: " in out
    assert "Scan " in out and "S-0001" in out


def test_api_not_running():
    assert menu("0", api=DOWN) == 5


def test_aegis_alone_opens_the_menu_in_a_terminal(monkeypatch):
    monkeypatch.setattr(cli_main, "_interactive", lambda: True)
    result = CliRunner().invoke(app, ["--api", DOWN], input="0\n")
    assert result.exit_code == 5 and "NOT RUNNING" in result.stdout
    monkeypatch.setattr(cli_main, "_interactive", lambda: False)
    assert "Usage" in CliRunner().invoke(app, []).stdout     # scripts and pipes get the help
