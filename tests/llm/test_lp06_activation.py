"""LP6 — switching Online mode on (validated key + consent), off (at once), and forgetting the key.

The key is asked for every run and kept in memory only (decision Q-4, revised): after a restart
Online mode waits for it; the same key resumes without asking for consent again, another key does not.
"""

from __future__ import annotations

import json

import pytest

from aegis.llm.base import LlmError, LlmSnapshot, ProviderId
from aegis.llm.config_store import config_path, read_config
from aegis.llm.consent import DISCLOSURE_VERSION, ConsentInput
from aegis.llm.manager import ProviderManager
from aegis.llm.policy import ConfigRefused
from aegis.llm.secrets import fingerprint
from fakes.fake_provider import TEST_KEY, FakeProvider, manager_with, memory_secrets

pytestmark = pytest.mark.phase("LP6")

NEW_KEY = "AIzaSyNEW-candidate-key-000000000000002"
OK = ConsentInput(disclosure_version=DISCLOSURE_VERSION, accepted=True)


def world(tmp_path, *, key=None, **llm):
    local, cloud = FakeProvider(), FakeProvider(provider=ProviderId.gemini, location="cloud")
    return manager_with(tmp_path, local, cloud, secrets=memory_secrets(key), **llm)


def restart(mgr) -> ProviderManager:
    """The same install after a restart: same data folder, a fresh process (no session key)."""
    return ProviderManager(mgr.settings, mgr.data_dir, registry=mgr.registry, environ={}, secrets=memory_secrets(None))


def audit(mgr):
    return [e["event"] for e in mgr.audit.read()]


def session_key(mgr):
    stored = mgr.secrets.get()
    return stored.value.get_secret_value() if stored else None


async def validated(mgr, model="cloud-model", key=NEW_KEY):
    result, vid = await mgr.validate(ProviderId.gemini, model, key)
    assert result.ok and vid
    return vid


async def online(mgr, key=NEW_KEY, **consent):
    vid = await validated(mgr, key=key)
    return await mgr.activate(ProviderId.gemini, "cloud-model", validation_id=vid, actor="ui",
                              consent=ConsentInput(disclosure_version=DISCLOSURE_VERSION, accepted=True, **consent))


# ---------------------------------------------------------------- switching Online on
async def test_activation_keeps_the_key_in_memory_records_consent_and_switches(tmp_path):
    mgr = world(tmp_path)
    status = await online(mgr)

    assert (status["provider"], status["model"], status["location"]) == ("gemini", "cloud-model", "cloud")
    assert mgr.snapshot.generation == 1
    assert session_key(mgr) == NEW_KEY and mgr.secrets.get().source == "session"
    raw = config_path(tmp_path).read_text(encoding="utf-8")
    assert NEW_KEY not in raw
    cfg = read_config(config_path(tmp_path)).config
    assert cfg.consent.disclosure_version == DISCLOSURE_VERSION and cfg.consent.accepted_via == "ui"
    assert cfg.consent.key_fingerprint == fingerprint(NEW_KEY) and cfg.consent.allow_source_code is False
    assert cfg.gemini.key_ref.source == "session" and cfg.gemini.key_ref.last4 == "0002"
    assert audit(mgr) == ["key_stored", "consent_granted", "provider_activated"]
    assert status["consent"]["granted"] is True and status["key"]["fingerprint"] == fingerprint(NEW_KEY)
    assert status["awaiting_key"] is False and NEW_KEY not in json.dumps(status)


async def test_activation_with_this_sessions_key_and_source_code_consent(tmp_path):
    mgr = world(tmp_path, key=TEST_KEY)
    result, vid = await mgr.validate(ProviderId.gemini, "cloud-model")        # no candidate: this session's key
    await mgr.activate(ProviderId.gemini, "cloud-model", validation_id=vid, actor="cli",
                       consent=ConsentInput(disclosure_version=DISCLOSURE_VERSION, accepted=True, allow_source_code=True))
    assert mgr.allows_source_code(mgr.snapshot) is True
    assert "key_stored" not in audit(mgr) and session_key(mgr) == TEST_KEY


async def test_a_new_key_replaces_the_old_one_and_is_recorded_as_rotated(tmp_path):
    mgr = world(tmp_path, key=TEST_KEY)
    await online(mgr)
    rotated = next(e for e in mgr.audit.read() if e["event"] == "key_rotated")
    assert rotated["previous_key_fingerprint"] == fingerprint(TEST_KEY) and rotated["key_fingerprint"] == fingerprint(NEW_KEY)


# ---------------------------------------------------------------- every run asks for the key again
async def test_after_a_restart_online_mode_waits_for_the_key(tmp_path):
    mgr = world(tmp_path)
    await online(mgr)
    again = restart(mgr)
    status = again.status()
    assert status["location"] == "local" and status["awaiting_key"] is True
    assert "enter the Gemini API key" in status["config_error"]
    assert status["consent"]["granted"] is True                     # the choice and consent are kept
    assert status["online_model"] == "cloud-model"                  # …so the UI can preselect it
    assert read_config(config_path(tmp_path)).config.provider is ProviderId.gemini


async def test_the_same_key_resumes_without_asking_for_consent_again(tmp_path):
    mgr = world(tmp_path)
    await online(mgr)
    again = restart(mgr)
    vid = await validated(again, key=NEW_KEY)
    status = await again.activate(ProviderId.gemini, "cloud-model", validation_id=vid, actor="ui")   # no consent
    assert status["location"] == "cloud" and status["awaiting_key"] is False
    assert audit(again)[-2:] == ["key_stored", "provider_activated"]          # consent was reused, not re-given


async def test_a_different_key_after_a_restart_needs_consent(tmp_path):
    mgr = world(tmp_path)
    await online(mgr)
    again = restart(mgr)
    vid = await validated(again, key="AIzaSyANOTHER-key-entered-later-000003")
    with pytest.raises(ConfigRefused) as err:
        await again.activate(ProviderId.gemini, "cloud-model", validation_id=vid, actor="ui")
    assert err.value.code == "consent_required" and session_key(again) is None   # the refused key is not kept


async def test_nothing_about_the_key_survives_on_disk(tmp_path):
    from pathlib import Path

    mgr = world(tmp_path)
    await online(mgr)
    await mgr.go_offline(actor="ui")
    assert [p for p in Path(tmp_path).rglob("*") if p.is_file() and NEW_KEY.encode() in p.read_bytes()] == []


# ---------------------------------------------------------------- refusals
@pytest.mark.parametrize("consent", [
    None,
    ConsentInput(disclosure_version=DISCLOSURE_VERSION, accepted=False),
    ConsentInput(disclosure_version="2020-01-01.0", accepted=True),
])
async def test_no_activation_without_consent_to_the_current_notice(tmp_path, consent):
    mgr = world(tmp_path)
    vid = await validated(mgr)
    with pytest.raises(ConfigRefused) as err:
        await mgr.activate(ProviderId.gemini, "cloud-model", validation_id=vid, consent=consent, actor="ui")
    assert err.value.code == "consent_required"
    assert mgr.snapshot.location == "local" and session_key(mgr) is None and not config_path(tmp_path).exists()


async def test_a_validation_is_used_once_and_must_match_the_model(tmp_path):
    mgr = world(tmp_path)
    with pytest.raises(ConfigRefused) as err:
        await mgr.activate(ProviderId.gemini, "cloud-model", validation_id="made-up", consent=OK, actor="ui")
    assert err.value.code == "validation_expired"
    vid = await validated(mgr, model="cloud-model")
    with pytest.raises(ConfigRefused) as err:
        await mgr.activate(ProviderId.gemini, "other-model", validation_id=vid, consent=OK, actor="ui")
    assert err.value.code == "invalid_request"
    with pytest.raises(ConfigRefused) as err:                 # it was consumed by the refused attempt
        await mgr.activate(ProviderId.gemini, "cloud-model", validation_id=vid, consent=OK, actor="ui")
    assert err.value.code == "validation_expired"


async def test_the_kill_switch_refuses_activation(tmp_path):
    mgr = world(tmp_path, allow_cloud=False)
    vid = await validated(mgr)
    with pytest.raises(ConfigRefused) as err:
        await mgr.activate(ProviderId.gemini, "cloud-model", validation_id=vid, consent=OK, actor="ui")
    assert err.value.code == "cloud_disabled"


async def test_a_provider_pinned_by_the_environment_cannot_be_changed(tmp_path):
    mgr = world(tmp_path, provider="ollama")
    vid = await validated(mgr)
    with pytest.raises(ConfigRefused) as err:
        await mgr.activate(ProviderId.gemini, "cloud-model", validation_id=vid, consent=OK, actor="ui")
    assert err.value.code == "managed_by_environment"


async def test_a_read_only_manager_never_writes(tmp_path):
    mgr = world(tmp_path)
    ro = ProviderManager(mgr.settings, tmp_path, read_only=True, registry=mgr.registry, environ={}, secrets=mgr.secrets)
    with pytest.raises(ConfigRefused) as err:
        await ro.go_offline(actor="api")
    assert err.value.code == "read_only"


async def test_a_failed_config_write_puts_the_previous_key_back(tmp_path, monkeypatch):
    import aegis.llm.manager as manager_mod

    mgr = world(tmp_path, key=TEST_KEY)
    vid = await validated(mgr)

    def fail(*_a, **_k):
        raise OSError("disk full")

    monkeypatch.setattr(manager_mod, "write_config", fail)
    with pytest.raises(OSError):
        await mgr.activate(ProviderId.gemini, "cloud-model", validation_id=vid, consent=OK, actor="ui")
    assert session_key(mgr) == TEST_KEY and mgr.snapshot.location == "local"


# ---------------------------------------------------------------- switching Online off
async def test_going_offline_takes_effect_at_once_and_revokes_consent(tmp_path):
    mgr = world(tmp_path)
    await online(mgr)
    pinned = mgr.snapshot                                            # a scan that started online

    status = await mgr.go_offline(actor="ui")

    assert status["location"] == "local" and status["consent"] is None
    with pytest.raises(LlmError) as err:
        mgr.authorize(pinned)
    assert err.value.kind == "revoked"
    assert read_config(config_path(tmp_path)).config.consent is None
    assert audit(mgr)[-2:] == ["consent_revoked", "provider_deactivated"]


async def test_switching_back_online_needs_a_new_validation_and_consent(tmp_path):
    mgr = world(tmp_path)
    vid = await validated(mgr)
    await mgr.activate(ProviderId.gemini, "cloud-model", validation_id=vid, consent=OK, actor="ui")
    await mgr.go_offline(actor="ui")
    with pytest.raises(ConfigRefused):
        await mgr.activate(ProviderId.gemini, "cloud-model", validation_id=vid, consent=OK, actor="ui")
    vid = await validated(mgr)
    with pytest.raises(ConfigRefused) as err:                        # consent was revoked by going offline
        await mgr.activate(ProviderId.gemini, "cloud-model", validation_id=vid, actor="ui")
    assert err.value.code == "consent_required"


async def test_choosing_another_local_model(tmp_path):
    mgr = world(tmp_path)
    status = await mgr.activate(ProviderId.ollama, "llama3", actor="cli")
    assert (status["provider"], status["model"]) == ("ollama", "llama3")
    with pytest.raises(ConfigRefused) as err:
        await mgr.activate(ProviderId.ollama, "missing-model", actor="cli")
    assert err.value.code == "invalid_request"


# ---------------------------------------------------------------- forgetting the key
async def test_forgetting_the_key_goes_offline_first(tmp_path):
    mgr = world(tmp_path)
    await online(mgr)
    status = await mgr.forget_key(actor="ui")
    assert status["location"] == "local" and status["key"] == {"configured": False}
    assert session_key(mgr) is None and read_config(config_path(tmp_path)).config.gemini.key_ref is None
    assert audit(mgr)[-1] == "key_deleted"


# ---------------------------------------------------------------- the policy keeps checking
async def test_a_key_swapped_outside_the_consent_switches_online_off(tmp_path):
    mgr = world(tmp_path)
    await online(mgr)
    mgr.secrets.put("AIzaSySWAPPED-without-consent-0000000003")
    mgr.reload()
    assert mgr.snapshot.location == "local" and "key changed" in mgr.status()["config_error"]


async def test_the_kill_switch_revokes_recorded_consent_on_the_next_start(tmp_path):
    from dataclasses import replace

    mgr = world(tmp_path)
    await online(mgr)
    killed = replace(mgr.settings, llm=replace(mgr.settings.llm, allow_cloud=False))
    restarted = ProviderManager(killed, tmp_path, registry=mgr.registry, environ={}, secrets=mgr.secrets)
    assert restarted.snapshot.location == "local"
    assert read_config(config_path(tmp_path)).config.consent is None   # turning cloud on again needs new consent
    assert restarted.audit.read()[-1]["reason"] == "kill_switch"


async def test_operator_consent_through_the_environment(tmp_path):
    mgr = world(tmp_path, key=TEST_KEY, provider="gemini", gemini_model="cloud-model",
                cloud_consent=DISCLOSURE_VERSION, cloud_source_consent=True)
    assert mgr.snapshot.location == "cloud" and mgr.allows_source_code(mgr.snapshot)
    old = world(tmp_path / "old", key=TEST_KEY, provider="gemini", gemini_model="cloud-model",
                cloud_consent="2020-01-01.0")
    assert old.snapshot.location == "local" and "current notice" in old.status()["config_error"]


def test_a_cloud_snapshot_without_source_consent_is_never_shown_code(tmp_path):
    mgr = manager_with(tmp_path, FakeProvider(), FakeProvider(provider=ProviderId.gemini, location="cloud"),
                       provider="gemini", gemini_model="m", record_consent=True)
    assert mgr.snapshot.location == "cloud" and mgr.allows_source_code(mgr.snapshot) is False
    assert mgr.allows_source_code(LlmSnapshot(ProviderId.ollama, "x", "local")) is True
