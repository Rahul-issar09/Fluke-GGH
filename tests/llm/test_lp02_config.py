"""LP2 — LLM settings, the persisted config file, precedence and fail-closed resolution."""

from __future__ import annotations

import json
import os

import pytest

from aegis.config import AppSettings, LlmSettings, ModelSettings, get_llm_settings
from aegis.llm.base import ProviderId
from aegis.llm.config_store import (
    ConsentRecord,
    LlmConfigFile,
    OllamaSection,
    GeminiSection,
    ReadResult,
    config_path,
    read_config,
    resolve,
    write_config,
)

pytestmark = pytest.mark.phase("LP2")

SENTINEL = "AIzaSyLP2-SENTINEL-NEVER-ECHO-THIS-0001"
NO_ENV: dict[str, str] = {}


def _settings(**llm) -> AppSettings:
    return AppSettings(model=ModelSettings(name="qwen2.5:7b"), llm=LlmSettings(**llm))


def _write(path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data), encoding="utf-8")


# ---------------------------------------------------------------- environment parsing
def test_llm_settings_defaults(monkeypatch):
    for name in ("AEGIS_LLM__PROVIDER", "AEGIS_LLM__ALLOW_CLOUD", "AEGIS_LLM__TIMEOUT_S", "AEGIS_LLM__GEMINI__MODEL"):
        monkeypatch.delenv(name, raising=False)
    s = get_llm_settings()
    assert s == LlmSettings()
    assert s.provider is None and s.allow_cloud is True and s.gemini_model is None


def test_llm_settings_from_env(monkeypatch):
    monkeypatch.setenv("AEGIS_LLM__PROVIDER", " Gemini ")
    monkeypatch.setenv("AEGIS_LLM__ALLOW_CLOUD", "false")
    monkeypatch.setenv("AEGIS_LLM__TIMEOUT_S", "30")
    monkeypatch.setenv("AEGIS_LLM__GEMINI__MODEL", "some-model")
    s = get_llm_settings()
    assert (s.provider, s.allow_cloud, s.timeout_s, s.gemini_model) == ("gemini", False, 30.0, "some-model")


def test_unknown_provider_in_env_is_refused(monkeypatch):
    monkeypatch.setenv("AEGIS_LLM__PROVIDER", "openai")
    with pytest.raises(ValueError, match="AEGIS_LLM__PROVIDER"):
        get_llm_settings()


# ---------------------------------------------------------------- precedence
def test_no_env_no_file_is_todays_behaviour(tmp_path):
    res = resolve(_settings(), read_config(config_path(tmp_path)), environ=NO_ENV)
    assert res.provider is ProviderId.ollama
    assert res.model == "qwen2.5:7b"
    assert res.generation == 0
    assert res.config_error is None
    assert res.managed_by == {"provider": "default", "ollama_model": "default"}


def test_file_picks_the_ollama_model(tmp_path):
    path = config_path(tmp_path)
    write_config(path, LlmConfigFile(generation=3, ollama=OllamaSection(model="llama3")))
    res = resolve(_settings(), read_config(path), environ=NO_ENV)
    assert (res.provider, res.model, res.generation) == (ProviderId.ollama, "llama3", 3)
    assert res.managed_by["ollama_model"] == "file"


def test_env_model_beats_the_file(tmp_path):
    path = config_path(tmp_path)
    write_config(path, LlmConfigFile(ollama=OllamaSection(model="llama3")))
    res = resolve(_settings(), read_config(path), environ={"AEGIS_MODEL": "qwen2.5:7b"})
    assert res.model == "qwen2.5:7b"
    assert res.managed_by["ollama_model"] == "env"


def test_env_provider_beats_the_file(tmp_path):
    path = config_path(tmp_path)
    write_config(path, LlmConfigFile(provider=ProviderId.gemini, gemini=GeminiSection(model="m")))
    res = resolve(_settings(provider="ollama"), read_config(path), environ=NO_ENV, available=lambda p: True)
    assert res.provider is ProviderId.ollama
    assert res.managed_by["provider"] == "env"


# ---------------------------------------------------------------- fail closed
def test_gemini_not_installed_falls_back_offline(tmp_path):
    path = config_path(tmp_path)
    write_config(path, LlmConfigFile(provider=ProviderId.gemini, gemini=GeminiSection(model="m")))
    res = resolve(_settings(), read_config(path), environ=NO_ENV, available=lambda p: p is ProviderId.ollama)
    assert res.provider is ProviderId.ollama and res.model == "qwen2.5:7b"
    assert "not available" in res.config_error


def test_cloud_kill_switch_falls_back_offline(tmp_path):
    path = config_path(tmp_path)
    write_config(path, LlmConfigFile(provider=ProviderId.gemini, gemini=GeminiSection(model="m")))
    res = resolve(_settings(allow_cloud=False), read_config(path), environ=NO_ENV, available=lambda p: True)
    assert res.provider is ProviderId.ollama
    assert "ALLOW_CLOUD" in res.config_error


def test_gemini_without_a_model_falls_back_offline(tmp_path):
    res = resolve(_settings(provider="gemini"), ReadResult(), environ=NO_ENV, available=lambda p: True)
    assert res.provider is ProviderId.ollama
    assert "no Gemini model" in res.config_error


def test_gemini_with_a_model_and_consent_is_selected(tmp_path):
    consented = LlmConfigFile(consent=ConsentRecord(disclosure_version="v1", accepted_at="2026-10-22T10:00:00Z",
                                                    accepted_via="ui"))
    res = resolve(_settings(provider="gemini", gemini_model="m"), ReadResult(config=consented), environ=NO_ENV,
                  available=lambda p: True)
    assert (res.provider, res.model, res.config_error) == (ProviderId.gemini, "m", None)
    assert res.managed_by["gemini_model"] == "env"


def test_gemini_without_consent_falls_back_offline():
    res = resolve(_settings(provider="gemini", gemini_model="m"), ReadResult(), environ=NO_ENV, available=lambda p: True)
    assert res.provider is ProviderId.ollama
    assert "consent" in res.config_error


@pytest.mark.parametrize("body, reason", [
    ("{not json", "not valid JSON"),
    ("[1, 2]", "JSON object"),
    (json.dumps({"schema_version": 99, "provider": "gemini"}), "unsupported schema_version 99"),
    (json.dumps({"schema_version": 1, "provider": "nope"}), "invalid"),
])
def test_broken_file_falls_back_offline(tmp_path, body, reason):
    path = config_path(tmp_path)
    path.parent.mkdir(parents=True)
    path.write_text(body, encoding="utf-8")
    read = read_config(path)
    assert read.config is None and reason in read.error
    res = resolve(_settings(), read, environ=NO_ENV, available=lambda p: True)
    assert res.provider is ProviderId.ollama and res.config_error


def test_file_cannot_hold_a_key_and_errors_never_echo_values(tmp_path):
    path = config_path(tmp_path)
    _write(path, {"schema_version": 1, "provider": "gemini", "gemini": {"model": "m", "api_key": SENTINEL}})
    read = read_config(path)
    assert read.config is None
    assert "api_key" in read.error
    assert SENTINEL not in read.error


def test_key_ref_holds_only_a_fingerprint():
    assert "api_key" not in json.dumps(LlmConfigFile.model_json_schema())
    with pytest.raises(ValueError):
        GeminiSection.model_validate({"key_ref": {"source": "session", "fingerprint": SENTINEL}})


# ---------------------------------------------------------------- writes
def test_reading_never_creates_the_folder(tmp_path):
    read_config(config_path(tmp_path))
    assert not (tmp_path / "config").exists()


def test_write_round_trips_and_leaves_no_temp_file(tmp_path):
    path = config_path(tmp_path)
    cfg = LlmConfigFile(generation=2, ollama=OllamaSection(model="llama3"))
    write_config(path, cfg)
    assert read_config(path).config == cfg
    assert [p.name for p in path.parent.iterdir()] == ["llm.json"]


def test_failed_replace_keeps_the_old_file(tmp_path, monkeypatch):
    path = config_path(tmp_path)
    write_config(path, LlmConfigFile(ollama=OllamaSection(model="llama3")))

    def boom(src, dst):
        raise OSError("disk full")

    monkeypatch.setattr(os, "replace", boom)
    with pytest.raises(OSError):
        write_config(path, LlmConfigFile(ollama=OllamaSection(model="mistral")))
    monkeypatch.undo()
    assert read_config(path).config.ollama.model == "llama3"


@pytest.mark.skipif(os.name != "posix", reason="file modes are POSIX-only")
def test_file_is_owner_only(tmp_path):
    path = config_path(tmp_path)
    write_config(path, LlmConfigFile())
    assert (path.stat().st_mode & 0o777) == 0o600
