"""LP11 — findings of the security review, fixed and pinned.

1. ``GOOGLE_GEMINI_BASE_URL`` would make the Gemini SDK send requests (the key header included) to
   another host: AEGIS passes Google's address explicitly, which the SDK puts first.
2. ``GOOGLE_GENAI_CLIENT_MODE`` (record/replay) would make the SDK write request bodies — findings,
   source excerpts — to disk, or answer from files: AEGIS refuses to build a client while it is set.
3. A key must not cross the network unencrypted: the CLI refuses plain HTTP to another machine.
"""

from __future__ import annotations

import pytest

from aegis.cli.commands.llm import _send, check_key_transport
from aegis.cli.errors import CliError
from aegis.config import AppSettings, LlmSettings
from aegis.llm.base import LlmError
from aegis.llm.providers.gemini import GeminiProvider, check_sdk_environment, installed
from aegis.llm.secrets import ENV_KEY, SecretRegistry, SecretStore

pytestmark = pytest.mark.phase("LP11")

KEY = "AIzaSyLP11-review-test-key-00000000000011"
needs_sdk = pytest.mark.skipif(not installed(), reason="the gemini extra is not installed")


def provider() -> GeminiProvider:
    return GeminiProvider(AppSettings(llm=LlmSettings(gemini_model="gemini-2.5-flash")),
                          secrets=SecretStore({ENV_KEY: KEY}, registry=SecretRegistry()))


@needs_sdk
def test_the_sdk_would_follow_the_environment_without_the_fix(monkeypatch):
    """Why the fix is needed: the SDK on its own uses GOOGLE_GEMINI_BASE_URL."""
    from langchain_google_genai import ChatGoogleGenerativeAI

    monkeypatch.setenv("GOOGLE_GEMINI_BASE_URL", "https://evil.example.com/")
    bare = ChatGoogleGenerativeAI(model="gemini-2.5-flash", google_api_key=KEY, vertexai=False)
    assert bare.client._api_client._http_options.base_url == "https://evil.example.com/"


@needs_sdk
def test_aegis_always_talks_to_google(monkeypatch):
    monkeypatch.setenv("GOOGLE_GEMINI_BASE_URL", "https://evil.example.com/")
    p = provider()
    client = p.chat_model(p.snapshot())
    assert client.client._api_client._http_options.base_url == "https://generativelanguage.googleapis.com/"


@pytest.mark.parametrize("name", ["GOOGLE_GENAI_CLIENT_MODE", "GOOGLE_GENAI_REPLAYS_DIRECTORY", "GOOGLE_GENAI_REPLAY_ID"])
def test_record_and_replay_modes_are_refused(monkeypatch, name):
    monkeypatch.setenv(name, "record")
    with pytest.raises(LlmError) as err:
        check_sdk_environment()
    assert err.value.kind == "config_error" and name in str(err.value)


@needs_sdk
async def test_validation_reports_the_refusal_instead_of_recording(monkeypatch, tmp_path):
    from fakes.fake_gemini import FakeGeminiApi, KEY as API_KEY

    monkeypatch.setenv("GOOGLE_GENAI_CLIENT_MODE", "record")
    monkeypatch.setenv("GOOGLE_GENAI_REPLAYS_DIRECTORY", str(tmp_path / "replays"))
    p = GeminiProvider(AppSettings(llm=LlmSettings(gemini_model="gemini-2.5-flash")),
                       secrets=SecretStore({ENV_KEY: API_KEY}, registry=SecretRegistry()), transport=FakeGeminiApi().transport)
    result = await p.validate("gemini-2.5-flash")
    assert (result.ok, result.error_kind) == (False, "config_error")
    assert not (tmp_path / "replays").exists()


def test_a_clean_environment_passes():
    check_sdk_environment({})


# ---------------------------------------------------------------- the key in transit (CLI)
@pytest.mark.parametrize("url", ["https://aegis.example.com", "http://127.0.0.1:8000", "http://localhost:8000",
                                 "http://[::1]:8000"])
def test_keys_go_over_https_or_stay_on_this_machine(url):
    check_key_transport(url)


@pytest.mark.parametrize("url", ["http://aegis.lan:8000", "http://192.168.1.20:8000", "http://10.0.0.5"])
def test_plain_http_to_another_machine_is_refused(url):
    with pytest.raises(CliError, match="unencrypted"):
        check_key_transport(url)


def test_the_refusal_happens_before_anything_is_sent():
    class Api:
        base_url = "http://aegis.lan:8000"

        def request(self, *a, **k):
            raise AssertionError("nothing may be sent")

    with pytest.raises(CliError):
        _send(Api(), "POST", "/api/llm/validate", {"provider": "gemini", "model": "m", "api_key": KEY})
