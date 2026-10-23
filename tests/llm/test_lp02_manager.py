"""LP2 — the provider manager and registry: the active snapshot, the gate, reloads, no cloud imports."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from aegis.config import AppSettings, LlmSettings, ModelSettings
from aegis.llm.base import LlmError, LlmSnapshot, ProviderId
from aegis.llm.config_store import LlmConfigFile, OllamaSection, config_path, write_config
from aegis.llm.manager import ProviderManager
from aegis.llm.registry import DEFAULT_FACTORIES, ProviderRegistry

pytestmark = pytest.mark.phase("LP2")

ROOT = Path(__file__).resolve().parents[2]


def _settings(tmp_path, **llm) -> AppSettings:
    return AppSettings(data_dir=str(tmp_path), model=ModelSettings(name="qwen2.5:7b"), llm=LlmSettings(**llm))


def test_default_manager_is_offline_and_creates_nothing(tmp_path):
    mgr = ProviderManager(_settings(tmp_path), environ={})
    snap = mgr.snapshot
    assert (snap.provider, snap.model, snap.location, snap.generation) == (ProviderId.ollama, "qwen2.5:7b", "local", 0)
    status = mgr.status()
    assert status["provider"] == "ollama" and status["location"] == "local"
    assert status["config_error"] is None and status["allow_cloud"] is True
    assert list(tmp_path.iterdir()) == []  # reading the configuration never creates files


def test_status_reports_the_fail_closed_reason(tmp_path):
    settings = _settings(tmp_path, provider="gemini", gemini_model="m")
    offline_only = ProviderRegistry(settings, DEFAULT_FACTORIES)   # an install without the gemini extra
    mgr = ProviderManager(settings, registry=offline_only, environ={})
    assert mgr.snapshot.provider is ProviderId.ollama
    assert "not available" in mgr.status()["config_error"]


def test_structured_uses_the_active_model(tmp_path):
    from aegis.agent.schemas import Explanation

    runnable = ProviderManager(_settings(tmp_path), environ={}).structured(Explanation)
    assert hasattr(runnable, "ainvoke")


def test_local_snapshots_are_always_authorized(tmp_path):
    mgr = ProviderManager(_settings(tmp_path), environ={})
    mgr.authorize(LlmSnapshot(ProviderId.ollama, "anything", "local", generation=99))


def test_cloud_snapshot_is_revoked_while_offline(tmp_path):
    mgr = ProviderManager(_settings(tmp_path), environ={})
    with pytest.raises(LlmError) as err:
        mgr.structured(object, snapshot=LlmSnapshot(ProviderId.gemini, "m", "cloud"))
    assert err.value.kind == "revoked"


def test_reload_if_changed_picks_up_a_switch(tmp_path):
    mgr = ProviderManager(_settings(tmp_path), environ={})
    assert mgr.reload_if_changed() is False
    pinned = mgr.snapshot
    write_config(config_path(tmp_path), LlmConfigFile(generation=1, ollama=OllamaSection(model="llama3")))
    assert mgr.reload_if_changed() is True
    assert (mgr.snapshot.model, mgr.snapshot.generation) == ("llama3", 1)
    assert pinned.model == "qwen2.5:7b"  # a pinned snapshot never changes
    mgr.authorize(pinned)                 # and a local one stays usable


def test_registry_refuses_unknown_providers(tmp_path):
    reg = ProviderRegistry(_settings(tmp_path), DEFAULT_FACTORIES)   # without the gemini extra
    assert reg.registered() == [ProviderId.ollama]
    assert reg.available(ProviderId.gemini) is False
    with pytest.raises(LlmError) as err:
        reg.get(ProviderId.gemini)
    assert err.value.kind == "provider_unavailable"
    assert reg.get(ProviderId.ollama) is reg.get(ProviderId.ollama)  # built once


def test_offline_install_never_imports_a_cloud_sdk(tmp_path):
    """Building the manager and a runnable must not import any Google package."""
    code = (
        "import sys\n"
        "from aegis.config import get_app_settings\n"
        "from aegis.llm.manager import ProviderManager\n"
        "from aegis.agent.schemas import Explanation\n"
        "m = ProviderManager(get_app_settings())\n"
        "m.structured(Explanation)\n"
        "sdks = ('google.genai', 'google.generativeai', 'google.ai', 'langchain_google')\n"
        "bad = sorted(n for n in sys.modules if n.startswith(sdks))\n"
        "print('IMPORTED:' + ','.join(bad))\n"
    )
    env = {k: v for k, v in os.environ.items() if not k.startswith("AEGIS_")}
    env.update({"AEGIS_DATA_DIR": str(tmp_path), "PYTHONPATH": str(ROOT), "AEGIS_LOGGING__JSON": "false"})
    out = subprocess.run([sys.executable, "-c", code], cwd=ROOT, env=env, capture_output=True, text=True, timeout=120)
    assert out.returncode == 0, out.stderr[-2000:]
    assert "IMPORTED:\n" in out.stdout or out.stdout.strip().endswith("IMPORTED:"), out.stdout
