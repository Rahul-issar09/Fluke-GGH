"""LP9 — `aegis llm …`: the model through the CLI. The Gemini key is asked every run (hidden prompt,
stdin or a named environment variable — never an argument) and never printed."""

from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from aegis.cli.commands import llm as llm_cmd
from aegis.cli.main import app
from aegis.config import AppSettings, ModelSettings
from aegis.evidence.models import ScanStatus
from aegis.llm.consent import DISCLOSURE_VERSION
from fakes import api_server
from fakes.fake_llm import PickFirstLLM
from fakes.fake_provider import FakeGemini, FakeProvider, manager_with, memory_secrets

pytestmark = pytest.mark.phase("LP9")

KEY = "AIzaSyCLI-test-key-never-printed-00000007"
runner = CliRunner()


def start(monkeypatch, tmp_path, **llm):
    mgr = manager_with(tmp_path / "cfg", FakeProvider(), FakeGemini(KEY), secrets=memory_secrets(None), **llm)
    settings = AppSettings(data_dir=str(tmp_path), model=ModelSettings(ollama_url="http://127.0.0.1:9"))
    stop = api_server.serve(monkeypatch, settings, agent_overrides={"llm_manager": mgr, "llm": PickFirstLLM()})
    return mgr, stop


@pytest.fixture
def world(store, tmp_path, monkeypatch):
    scan = store.add_scan(mode="code").id
    f = store.add_finding(scan, type="sqli", owasp="A03", file="app/search.py", line=3, source="w", title="SQL injection")
    store.update_finding_fields(f.id, severity=0.8, risk=0.6, what="The search builds SQL from user input.")
    store.update_scan(scan, status=ScanStatus.completed)
    mgr, stop = start(monkeypatch, tmp_path)
    yield {"mgr": mgr, "scan": scan, "monkeypatch": monkeypatch}
    stop()


def cli(*args, input=None, env=None):
    result = runner.invoke(app, list(args), input=input, env=env)
    assert KEY not in result.stdout and KEY not in result.stderr, "the key must never be printed"
    return result


def online(**kw):
    return cli("llm", "configure", "--provider", "gemini", "--model", "gemini-2.5-flash", "--api-key-env", "AEGIS_TEST_KEY",
               "--accept-cloud-disclosure", DISCLOSURE_VERSION, env={"AEGIS_TEST_KEY": KEY}, **kw)


# ---------------------------------------------------------------- reading
def test_status_and_json_match_the_api(world):
    text = cli("llm", "status")
    assert text.exit_code == 0 and "Offline - this machine" in text.stdout and "asked every run" in text.stdout
    data = json.loads(cli("--json", "llm", "status").stdout)
    assert (data["provider"], data["location"], data["awaiting_key"]) == ("ollama", "local", False)
    assert data["disclosure"]["version"] == DISCLOSURE_VERSION


def test_providers(world):
    rows = json.loads(cli("--json", "llm", "providers").stdout)
    assert {r["id"] for r in rows} == {"ollama", "gemini"}


def test_gemini_models_for_a_key_from_an_environment_variable(world):
    data = json.loads(cli("--json", "llm", "models", "-p", "gemini", "--api-key-env", "AEGIS_TEST_KEY",
                          env={"AEGIS_TEST_KEY": KEY}).stdout)
    assert [m["id"] for m in data["models"]] == ["gemini-2.5-flash"]


# ---------------------------------------------------------------- the key is never an argument
def test_there_is_no_api_key_argument(world):
    result = cli("llm", "configure", "--provider", "gemini", "--api-key", KEY)
    assert result.exit_code == 2 and "No such option" in result.output + result.stderr


def test_without_a_key_scripts_are_told_how_to_give_one(world):
    result = cli("llm", "configure", "--provider", "gemini", "--model", "gemini-2.5-flash")
    assert result.exit_code == 2 and "--api-key-stdin" in result.stderr


# ---------------------------------------------------------------- scripted switching
def test_scripted_online_with_the_notice_version(world):
    result = online()
    assert result.exit_code == 0, result.stderr
    assert "Online - Google Gemini" in result.stdout and "entered this run, memory only" in result.stdout
    mgr = world["mgr"]
    assert mgr.secrets.get().value.get_secret_value() == KEY and mgr.secrets.get().source == "session"
    assert mgr.audit.read()[-1]["actor"] == "cli"


def test_the_key_can_come_from_stdin(world):
    result = cli("llm", "configure", "-p", "gemini", "-m", "gemini-2.5-flash", "--api-key-stdin",
                 "--accept-cloud-disclosure", DISCLOSURE_VERSION, input=KEY + "\n")
    assert result.exit_code == 0, result.stderr


def test_no_consent_no_switch(world):
    result = cli("llm", "configure", "-p", "gemini", "-m", "gemini-2.5-flash", "--api-key-env", "K", env={"K": KEY})
    assert result.exit_code == 4 and "privacy notice" in result.stderr and DISCLOSURE_VERSION in result.stderr
    assert world["mgr"].snapshot.location == "local"


def test_an_old_notice_version_is_refused(world):
    result = cli("llm", "configure", "-p", "gemini", "-m", "gemini-2.5-flash", "--api-key-env", "K",
                 "--accept-cloud-disclosure", "2020-01-01.0", env={"K": KEY})
    assert result.exit_code == 4


def test_a_wrong_key_is_a_usage_error_with_the_providers_reason(world):
    result = cli("llm", "configure", "-p", "gemini", "-m", "gemini-2.5-flash", "--api-key-env", "K",
                 "--accept-cloud-disclosure", DISCLOSURE_VERSION, env={"K": "AIzaSyWRONG-cli-key-000000000000000000"})
    assert result.exit_code == 2 and "refused the API key" in result.stderr


def test_offline_and_forget_key(world):
    online()
    off = cli("llm", "offline")
    assert off.exit_code == 0 and "Offline - this machine" in off.stdout
    gone = cli("llm", "forget-key", "--yes")
    assert gone.exit_code == 0 and world["mgr"].secrets.get() is None


# ---------------------------------------------------------------- the wizard
def test_the_wizard_switches_online_with_a_hidden_key_and_consent(world):
    result = cli("llm", "configure", input=f"2\n{KEY}\n1\nn\nYES\n")
    assert result.exit_code == 0, result.stderr
    assert "Before switching to Online mode" in result.stdout and "Online - Google Gemini" in result.stdout
    assert world["mgr"].allows_source_code(world["mgr"].snapshot) is False     # answered "n"


def test_the_wizard_stays_as_it_was_without_yes(world):
    result = cli("llm", "configure", input=f"2\n{KEY}\n1\nn\nno\n")
    assert result.exit_code == 4 and world["mgr"].snapshot.location == "local"


# ---------------------------------------------------------------- every run asks for the key
def restart(world) -> None:
    """What an API restart leaves: Online chosen, consent on record, no key in memory."""
    world["mgr"].secrets.delete()
    world["mgr"].reload()
    assert world["mgr"].status()["awaiting_key"] is True


def test_after_a_restart_status_says_the_key_is_needed(world):
    online()
    restart(world)
    assert "waiting for this run's key" in cli("llm", "status").stdout


def test_after_a_restart_the_wizard_asks_for_the_key_and_reuses_consent(world):
    online()
    restart(world)
    result = cli("llm", "configure", input=f"y\n{KEY}\n")
    assert result.exit_code == 0, result.stderr
    assert "Before switching" not in result.stdout                  # same key: no new agreement
    assert world["mgr"].snapshot.location == "cloud"


def test_a_question_asks_for_this_runs_key_in_a_terminal(world):
    online()
    restart(world)
    world["monkeypatch"].setattr(llm_cmd, "_interactive", lambda: True)
    result = cli("ask", "how many findings are there?", input=f"{KEY}\n")
    assert result.exit_code == 0, result.stderr
    assert "waiting for this run's API key" in result.stderr and "Online mode resumed" in result.stderr
    assert "sent to Google" in result.stderr                         # what this question sends, said once
    assert world["mgr"].snapshot.location == "cloud"


def test_enter_continues_offline(world):
    online()
    restart(world)
    world["monkeypatch"].setattr(llm_cmd, "_interactive", lambda: True)
    result = cli("ask", "how many findings are there?", input="\n")
    assert result.exit_code == 0 and "Continuing offline" in result.stderr
    assert world["mgr"].snapshot.location == "local"


# ---------------------------------------------------------------- "AI for this scan"
def test_a_scan_in_a_terminal_asks_which_model_and_switches_online(world, tmp_path):
    world["monkeypatch"].setattr(llm_cmd, "_interactive", lambda: True)
    result = cli("scan", "run", "--folder", str(tmp_path), input=f"2\n{KEY}\n1\nn\nYES\n")
    assert "AI for this scan" in result.stdout and "Before switching to Online mode" in result.stdout
    assert world["mgr"].snapshot.location == "cloud"                 # switched before the scan was sent
    assert "AI for this scan: Gemini gemini-2.5-flash (online)" in result.stderr and "sent to Google" in result.stderr
    assert "outside the allowed source roots" in result.stderr       # this API then refuses the folder


def test_model_option_takes_the_scan_to_a_local_model_without_asking(world, tmp_path):
    online()
    result = cli("scan", "run", "--folder", str(tmp_path), "--model", "qwen2.5:7b")
    assert "AI for this scan" not in result.stdout
    assert world["mgr"].snapshot.location == "local" and world["mgr"].snapshot.model == "qwen2.5:7b"
    assert "AI for this scan: qwen2.5:7b (offline, this machine)" in result.stderr


def test_scripts_are_not_asked_which_model(world, tmp_path):
    result = cli("scan", "run", "--folder", str(tmp_path))            # not a terminal: the active model
    assert "AI for this scan" not in result.stdout and world["mgr"].snapshot.location == "local"


def test_scripts_are_told_and_run_offline(world):
    online()
    restart(world)
    result = cli("--json", "ask", "how many findings are there?")
    assert result.exit_code == 0 and "aegis llm configure" in result.stderr
    json.loads(result.stdout)                                        # stdout stays clean JSON


# ---------------------------------------------------------------- refusals the API decides
def test_a_disabled_cloud_is_not_reported_as_a_token_problem(store, tmp_path, monkeypatch):
    _, stop = start(monkeypatch, tmp_path, allow_cloud=False)
    try:
        result = cli("llm", "configure", "-p", "gemini", "-m", "gemini-2.5-flash", "--api-key-env", "K",
                     "--accept-cloud-disclosure", DISCLOSURE_VERSION, env={"K": KEY})
    finally:
        stop()
    assert result.exit_code == 5 and "disabled" in result.stderr and "token" not in result.stderr


def test_doctor_shows_the_ai_model_and_embeddings(world):
    out = cli("doctor").stdout
    assert "AI model" in out and "Embeddings" in out and "bge-m3" in out


def test_local_status_reads_this_machine_without_the_api(world, tmp_path):
    result = cli("--local", "--data-dir", str(tmp_path / "elsewhere"), "--json", "llm", "status")
    assert result.exit_code == 0 and json.loads(result.stdout)["provider"] == "ollama"
    assert not (tmp_path / "elsewhere" / "config").exists()          # read-only
