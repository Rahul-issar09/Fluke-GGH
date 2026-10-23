"""LP3 — ``structured_call`` through the provider manager: pinning, retries, the breaker, the gate."""

from __future__ import annotations

import asyncio

import pytest
from pydantic import BaseModel

from aegis.agent import llm as llm_mod
from aegis.agent.llm import llm_unavailable, structured_call
from aegis.llm.base import LlmError, LlmSnapshot, ProviderId
from fakes.fake_llm import FakeLLM
from fakes.fake_provider import FakeProvider, StatusError, manager_with

pytestmark = pytest.mark.phase("LP3")


class Out(BaseModel):
    ok: bool


def ok(_out) -> list[str]:
    return []


async def call(**kw):
    return await structured_call(Out, "system", {"q": 1}, ok, **kw)


@pytest.fixture(autouse=True)
def _no_retry_pause(monkeypatch):
    monkeypatch.setattr(llm_mod, "TRANSIENT_RETRY_DELAY_S", 0)


# ---------------------------------------------------------------- which model answers
async def test_the_manager_serves_the_active_model(tmp_path):
    fake = FakeProvider([Out(ok=True)])
    mgr = manager_with(tmp_path, fake)
    out, source = await call(manager=mgr)
    assert (out, source) == (Out(ok=True), "llm")
    assert fake.used == [mgr.snapshot]


async def test_an_injected_test_model_wins_over_the_manager(tmp_path):
    fake = FakeProvider([])
    out, _ = await call(llm=FakeLLM([Out(ok=True)]), manager=manager_with(tmp_path, fake))
    assert out == Out(ok=True) and fake.used == []


async def test_a_pinned_snapshot_is_used_instead_of_the_active_one(tmp_path):
    fake = FakeProvider([Out(ok=True)])
    pinned = LlmSnapshot(ProviderId.ollama, "pinned-model", "local", generation=7)
    await call(manager=manager_with(tmp_path, fake), snapshot=pinned)
    assert fake.used == [pinned]


async def test_without_a_manager_the_legacy_path_is_unchanged(monkeypatch):
    built = []

    def fake_make_llm(settings=None):
        built.append(settings)
        return FakeLLM([Out(ok=True)])

    monkeypatch.setattr(llm_mod, "make_llm", fake_make_llm)
    out, _ = await call()
    assert out == Out(ok=True) and built == [None]


# ---------------------------------------------------------------- retries follow the provider's rule
async def test_a_server_error_is_retried_once(tmp_path):
    fake = FakeProvider([StatusError(500), Out(ok=True)])
    out, source = await call(manager=manager_with(tmp_path, fake))
    assert (out, source) == (Out(ok=True), "llm") and len(fake.runnable.calls) == 2


async def test_a_missing_model_is_not_retried(tmp_path):
    fake = FakeProvider([StatusError(404)])
    with pytest.raises(StatusError):
        await call(manager=manager_with(tmp_path, fake))
    assert len(fake.runnable.calls) == 1


# ---------------------------------------------------------------- the breaker
async def test_a_fatal_error_stops_further_calls_in_the_same_scan(tmp_path):
    fake = FakeProvider([StatusError(404), Out(ok=True)])
    mgr = manager_with(tmp_path, fake)
    with pytest.raises(StatusError):
        await call(manager=mgr, scope="S-0001")
    with pytest.raises(LlmError) as err:
        await call(manager=mgr, scope="S-0001")
    assert err.value.kind == "model_not_found" and "skipped" in str(err.value)
    assert len(fake.runnable.calls) == 1               # the model was not asked again
    out, _ = await call(manager=mgr, scope="S-0002")   # another scan is not affected
    assert out == Out(ok=True)


async def test_a_new_configuration_closes_the_breaker(tmp_path):
    fake = FakeProvider([StatusError(404), Out(ok=True)])
    mgr = manager_with(tmp_path, fake)
    with pytest.raises(StatusError):
        await call(manager=mgr, scope="S-0001")
    newer = LlmSnapshot(ProviderId.ollama, mgr.snapshot.model, "local", generation=mgr.snapshot.generation + 1)
    out, _ = await call(manager=mgr, scope="S-0001", snapshot=newer)
    assert out == Out(ok=True)


async def test_transient_failures_do_not_open_the_breaker(tmp_path):
    fake = FakeProvider([ConnectionError("down"), ConnectionError("down")])
    mgr = manager_with(tmp_path, fake)
    for _ in range(2):
        with pytest.raises(ConnectionError):
            await call(manager=mgr, scope="S-0001")
    assert len(fake.runnable.calls) == 2


# ---------------------------------------------------------------- the gate
async def test_a_cloud_snapshot_is_refused_while_offline_without_calling_anything(tmp_path):
    local = FakeProvider([])
    cloud = FakeProvider([Out(ok=True)], provider=ProviderId.gemini, location="cloud")
    mgr = manager_with(tmp_path, local, cloud)      # active: offline
    pinned = LlmSnapshot(ProviderId.gemini, "m", "cloud")
    with pytest.raises(LlmError) as err:
        await call(manager=mgr, snapshot=pinned, scope="S-0001")
    assert err.value.kind == "revoked"
    assert cloud.used == [] and cloud.runnable.calls == []
    assert llm_unavailable(err.value) == "llm unavailable: revoked"


async def test_going_offline_during_a_call_stops_its_retry_too(tmp_path):
    """LP12: the gate is checked before every attempt, so a corrective retry never reaches a cloud
    model that was switched off while the first attempt was running."""
    from aegis.llm.consent import DISCLOSURE_VERSION, ConsentInput

    class SwitchesOffThenAnswersBadly:
        calls = 0

        async def ainvoke(self, messages):
            SwitchesOffThenAnswersBadly.calls += 1
            await mgr.go_offline(actor="ui")          # the user clicks "Go offline now" meanwhile
            raise ValueError("not JSON")               # → structured_call would ask again

    cloud = FakeProvider(provider=ProviderId.gemini, location="cloud", runnable=SwitchesOffThenAnswersBadly())
    mgr = manager_with(tmp_path, FakeProvider([]), cloud)
    _, vid = await mgr.validate(ProviderId.gemini, "m")
    await mgr.activate(ProviderId.gemini, "m", validation_id=vid, actor="ui",
                       consent=ConsentInput(disclosure_version=DISCLOSURE_VERSION, accepted=True))
    assert mgr.snapshot.location == "cloud"
    with pytest.raises(LlmError) as err:
        await call(manager=mgr, scope="S-0001")
    assert err.value.kind == "revoked"
    assert SwitchesOffThenAnswersBadly.calls == 1     # the retry never reached the cloud model


def test_unavailable_reason_keeps_the_old_wording_for_client_errors():
    assert llm_unavailable(ConnectionError("x")) == "llm unavailable: ConnectionError"
    assert llm_unavailable(LlmError("quota_exhausted", "spent")) == "llm unavailable: quota_exhausted"


# ---------------------------------------------------------------- cancellation
class _Slow:
    def __init__(self):
        self.started = asyncio.Event()

    async def ainvoke(self, messages):
        self.started.set()
        await asyncio.sleep(30)


async def test_cancelling_during_a_model_call_propagates_and_opens_nothing(tmp_path):
    slow = _Slow()
    fake = FakeProvider(runnable=slow)
    mgr = manager_with(tmp_path, fake)
    task = asyncio.create_task(call(manager=mgr, scope="S-0001"))
    await asyncio.wait_for(slow.started.wait(), 5)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert not mgr.breaker.is_open("S-0001", mgr.snapshot)
