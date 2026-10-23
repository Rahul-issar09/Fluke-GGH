"""Run the real AEGIS API in-process for CLI tests (cli_new_phases.md, "Testing without a real server").

``serve(monkeypatch, settings)`` starts ``create_app(settings)`` inside a FastAPI ``TestClient`` (no
network, no port) and points the CLI's HTTP client at it. Call ``stop()`` (or use the pytest fixture
in the test module) to run the API's shutdown.
"""

from __future__ import annotations

from typing import Any

from fastapi.testclient import TestClient

__all__ = ["SharedClient", "serve"]


class SharedClient:
    """The in-process client, shared by every CLI command in a test: closing it must not stop the API."""

    def __init__(self, client: TestClient):
        self._client = client

    def request(self, *args: Any, **kwargs: Any):
        kwargs.pop("timeout", None)                  # TestClient does not take per-request timeouts
        return self._client.request(*args, **kwargs)

    def stream(self, *args: Any, **kwargs: Any):
        kwargs.pop("timeout", None)
        return self._client.stream(*args, **kwargs)

    def close(self) -> None:
        pass


def serve(monkeypatch, settings, *, agent_overrides: dict | None = None):
    """Start the API; route ``aegis.cli.remote.make_http_client`` to it. Returns ``stop``."""
    from aegis.api.main import create_app
    from aegis.cli import remote

    # as the real CLI meets the API: a client on this machine (the model-configuration routes accept
    # changes only from loopback on an API without a token, LLM_PROVIDER_PHASES §9.6)
    client = TestClient(create_app(settings, agent_overrides=agent_overrides),
                        base_url="http://127.0.0.1:8000", client=("127.0.0.1", 50000))
    client.__enter__()                                # the API's startup (lifespan)
    monkeypatch.setattr(remote, "make_http_client", lambda base_url, timeout: SharedClient(client))

    def stop() -> None:
        client.__exit__(None, None, None)

    return stop
