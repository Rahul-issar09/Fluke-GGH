"""LP5 — /api/health reports a cloud provider from its own health check, and says when it is not ready."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from aegis.api.main import create_app
from aegis.config import AppSettings, ModelSettings
from aegis.llm.base import ProviderHealth, ProviderId
from fakes.fake_llm import PickFirstLLM
from fakes.fake_provider import FakeProvider, manager_with

pytestmark = pytest.mark.phase("LP5")


class Unready(FakeProvider):
    async def health(self, snapshot):
        return ProviderHealth(self.id, snapshot.model, True, False, "cloud", error="model_not_found",
                              detail={"reason": "Gemini has no such model for this key (HTTP 404)"})


@pytest.mark.parametrize("cloud, ready", [(FakeProvider(provider=ProviderId.gemini, location="cloud"), True),
                                          (Unready(provider=ProviderId.gemini, location="cloud"), False)])
def test_health_uses_the_cloud_providers_own_check(tmp_path, cloud, ready):
    mgr = manager_with(tmp_path / "cfg", FakeProvider(), cloud, provider="gemini", gemini_model="cloud-model",
                       record_consent=True)
    settings = AppSettings(data_dir=str(tmp_path / "data"), offline_db_dir=str(tmp_path / "offline-db"),
                           model=ModelSettings(ollama_url="http://127.0.0.1:9"))
    with TestClient(create_app(settings, agent_overrides={"llm_manager": mgr, "llm": PickFirstLLM()}),
                    base_url="http://127.0.0.1:8000") as c:
        llm = c.get("/api/health").json()["llm"]
    assert (llm["provider"], llm["model"], llm["location"], llm["ready"]) == ("gemini", "cloud-model", "cloud", ready)
    if not ready:
        assert "no such model" in llm["reason"] and "will not switch" in llm["reason"]
