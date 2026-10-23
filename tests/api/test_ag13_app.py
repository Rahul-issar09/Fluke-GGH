"""AG13.1 — app factory, lifespan wiring, request logging, errors, auth, body limit, health."""

from __future__ import annotations

import asyncio
import io
import json

import pytest
from fastapi import APIRouter
from fastapi.testclient import TestClient

from aegis import observability as obs
from aegis.api.errors import Conflict, NotFound
from aegis.api.main import StartupError, create_app, ensure_dirs
from aegis.api.routers import health as health_router
from aegis.config import ApiSettings, AppSettings, ModelSettings
from aegis.evidence.state_machine import IllegalTransition
from aegis.router import RequestInvalid
from aegis.safety.egress import EgressBlocked
from aegis.services.fix_service import FixServiceError
from fakes.fake_llm import PickFirstLLM

pytestmark = pytest.mark.phase("AG13")

DOWN = "http://127.0.0.1:9"  # nothing listens here: "Ollama is down"


def settings(tmp_path, **api) -> AppSettings:
    return AppSettings(
        data_dir=str(tmp_path / "data"),
        offline_db_dir=str(tmp_path / "offline-db"),
        model=ModelSettings(ollama_url=DOWN),
        api=ApiSettings(allowed_source_roots=(str(tmp_path),), **api),
    )


@pytest.fixture
def logs():
    obs.reset_logging()
    stream = io.StringIO()
    obs.configure_logging(level="INFO", json=True, stream=stream)
    yield lambda: [json.loads(line) for line in stream.getvalue().splitlines() if line.startswith("{")]
    obs.reset_logging()


def client(tmp_path, **api) -> TestClient:
    return TestClient(create_app(settings(tmp_path, **api), agent_overrides={"llm": PickFirstLLM()}), base_url="http://127.0.0.1:8000", raise_server_exceptions=False)


# --------------------------------------------------------------------------------------------- #
# the plan's test: the app starts, the lifespan wires everything, health answers, requests are logged
# --------------------------------------------------------------------------------------------- #
def test_ag13_app(tmp_path, logs):
    with client(tmp_path) as c:
        state = c.app.state
        assert state.graph.checkpointer is state.checkpointer is state.fix_graph.checkpointer  # one checkpointer
        assert state.runner.store is state.store and state.runner.deps is state.agent_deps
        assert state.fix_service.graph is state.fix_graph and state.runner._sem._value == 1  # one scan at a time
        assert state.agent_deps.data_dir == str(tmp_path / "data")
        assert state.agent_deps.default_allowlist == ("demo-app:5000", "callback:8080")

        resp = c.get("/api/health")
        assert resp.status_code == 200 and resp.json()["status"] == "ok"

    for sub in ("reports", "workspaces", "patches", "graphs"):
        assert (tmp_path / "data" / sub).is_dir()
    assert (tmp_path / "data" / "aegis.db").is_file() and (tmp_path / "data" / "checkpoints.db").is_file()

    records = logs()
    access = [r for r in records if r["event"] == "http.request"]
    assert access and access[-1]["method"] == "GET" and access[-1]["path"] == "/api/health"
    assert access[-1]["status"] == 200 and isinstance(access[-1]["duration_ms"], int) and access[-1]["request_id"]
    assert any(r["event"] == "startup.ready" for r in records) and any(r["event"] == "shutdown.done" for r in records)


def test_swagger_is_served(tmp_path):
    with client(tmp_path) as c:
        assert c.get("/docs").status_code == 200
        spec = c.get("/openapi.json").json()
    assert spec["info"]["title"] == "AEGIS" and "/api/health" in spec["paths"]


def test_the_entry_point_exposes_the_app():
    import aegis.main

    assert aegis.main.app.title == "AEGIS"


# --------------------------------------------------------------------------------------------- #
# failure cases the plan names
# --------------------------------------------------------------------------------------------- #
def test_ollama_down_is_reported_and_the_app_still_starts(tmp_path):
    with client(tmp_path) as c:
        body = c.get("/api/health").json()
    assert body["status"] == "ok"
    assert body["ollama"]["reachable"] is False and body["ollama"]["model_present"] is False and body["ollama"]["error"]


def test_a_data_folder_that_cannot_be_written_is_a_clear_startup_error(tmp_path):
    blocker = tmp_path / "data"
    blocker.write_text("a file where the data folder should be", encoding="utf-8")
    with pytest.raises(StartupError, match="is not writable"):
        ensure_dirs(blocker)
    with pytest.raises(StartupError, match="is not writable"):
        with client(tmp_path):
            pass


# --------------------------------------------------------------------------------------------- #
# health
# --------------------------------------------------------------------------------------------- #
def test_health_shape_and_a_missing_tool_shows_false(tmp_path, monkeypatch):
    monkeypatch.setattr(health_router, "find_binary", lambda name: "/usr/bin/git" if name == "git" else None)
    with client(tmp_path) as c:
        body = c.get("/api/health").json()
    # "llm": the active model and whether it is ready (LLM_PROVIDER_PHASES LP3) — added beside "ollama";
    # "embeddings": the local embedding model and the chat index it built (LP4)
    assert set(body) == {"status", "database", "ollama", "llm", "embeddings", "tools", "db_snapshot_dates", "repo_scans"}
    assert body["database"] is True
    assert body["tools"]["git"] == {"found": True, "path": "/usr/bin/git"} and body["tools"]["semgrep"] == {"found": False}
    assert body["db_snapshot_dates"] == {"osv": None, "trivy": None, "nuclei": None}
    assert body["repo_scans"] == {"enabled": False, "git_hosts": []}  # off unless git hosts are configured (TNW-1)


async def test_the_ollama_probe_sees_whether_the_model_is_pulled(monkeypatch):
    import httpx

    def tags(request):
        return httpx.Response(200, json={"models": [{"name": "qwen2.5:7b"}, {"name": "llama3:latest"}]})

    real = httpx.AsyncClient
    monkeypatch.setattr(health_router.httpx, "AsyncClient", lambda **kw: real(transport=httpx.MockTransport(tags), **kw))
    assert (await health_router.probe_ollama("http://ollama:11434", "qwen2.5:7b"))["model_present"] is True
    assert (await health_router.probe_ollama("http://ollama:11434", "llama3"))["model_present"] is True
    assert (await health_router.probe_ollama("http://ollama:11434", "mistral"))["model_present"] is False


# --------------------------------------------------------------------------------------------- #
# request IDs and errors
# --------------------------------------------------------------------------------------------- #
def test_every_response_carries_a_request_id(tmp_path):
    with client(tmp_path) as c:
        mine = c.get("/api/health", headers={"X-Request-ID": "trace-42"})
        fresh = c.get("/api/health")
        hostile = c.get("/api/health", headers={"X-Request-ID": "x" * 200})
    assert mine.headers["x-request-id"] == "trace-42"
    assert fresh.headers["x-request-id"] and fresh.headers["x-request-id"] != "trace-42"
    assert len(hostile.headers["x-request-id"]) == 16                       # an unusable ID is replaced


def _app_with_failures(tmp_path):
    app = create_app(settings(tmp_path))
    boom = APIRouter()
    failures = {
        "not-found": NotFound("unknown finding F-9", ["F-9"]),
        "conflict": Conflict("another scan is running"),
        "illegal": IllegalTransition("candidate -> resolved is not a legal transition"),
        "egress": EgressBlocked("evil.example:443"),
        "invalid": RequestInvalid("folder is outside the allowed roots"),
        "fix": FixServiceError("pr mode is not available", code=422),
        "crash": RuntimeError("secret internal detail /etc/aegis/key"),
    }
    for name, exc in failures.items():
        boom.add_api_route(f"/api/boom/{name}", (lambda e: (lambda: (_ for _ in ()).throw(e)))(exc))
    app.include_router(boom)
    return app


@pytest.mark.parametrize(
    "name, status, error",
    [
        ("not-found", 404, "not found"), ("conflict", 409, "conflict"), ("illegal", 409, "conflict"),
        ("egress", 403, "forbidden"), ("invalid", 422, "invalid request"), ("fix", 422, "invalid request"),
        ("crash", 500, "internal error"),
    ],
)
def test_domain_errors_map_to_clean_responses(tmp_path, name, status, error):
    with TestClient(_app_with_failures(tmp_path), base_url="http://127.0.0.1:8000", raise_server_exceptions=False) as c:
        resp = c.get(f"/api/boom/{name}")
    assert resp.status_code == status and resp.json()["error"] == error
    assert "Traceback" not in resp.text and "/etc/aegis/key" not in resp.text   # nothing internal leaks


def test_unknown_routes_and_bad_bodies_use_the_same_error_shape(tmp_path):
    with client(tmp_path) as c:
        missing = c.get("/api/nope")
        bad = c.post("/api/health")
    assert missing.status_code == 404 and missing.json() == {"error": "not found", "detail": "Not Found"}
    assert bad.status_code == 405 and bad.json()["error"] == "method not allowed"


# --------------------------------------------------------------------------------------------- #
# auth and body limit
# --------------------------------------------------------------------------------------------- #
def test_open_when_no_token_is_set(tmp_path):
    with client(tmp_path) as c:
        assert c.get("/api/health").status_code == 200


def test_a_token_is_required_when_set(tmp_path, logs):
    with client(tmp_path, auth_token="s3cret-token") as c:
        assert c.get("/api/health").status_code == 401
        wrong = c.get("/api/health", headers={"Authorization": "Bearer nope"})
        assert wrong.status_code == 401 and wrong.headers["www-authenticate"] == "Bearer"
        assert c.get("/api/health", headers={"Authorization": "Bearer s3cret-token"}).status_code == 200
        assert c.get("/docs").status_code == 200                              # the API description stays readable
    failures = [r for r in logs() if r["event"] == "api.auth_failed"]
    assert len(failures) == 2 and all("s3cret" not in json.dumps(r) for r in logs())


def test_oversized_bodies_are_refused_with_413(tmp_path):
    with client(tmp_path, max_body_bytes=100) as c:
        declared = c.post("/api/health", content=b"x" * 101, headers={"content-type": "application/json"})
        streamed = c.post("/api/health", content=iter([b"x" * 60, b"x" * 60]))     # no content-length
        small = c.post("/api/health", content=b"{}")
    assert declared.status_code == 413 and declared.json()["error"] == "payload too large"
    assert streamed.status_code == 413
    assert small.status_code == 405                                            # reached the app (GET-only route)


# --------------------------------------------------------------------------------------------- #
# shutdown
# --------------------------------------------------------------------------------------------- #
def test_shutdown_cancels_running_scans(tmp_path):
    with client(tmp_path) as c:
        runner = c.app.state.runner

        async def forever():
            await asyncio.sleep(3600)

        async def start():  # returns the task; the portal would wait for a bare future
            return [asyncio.ensure_future(forever())]

        (task,) = c.portal.call(start)
        runner.tasks["S-0001"] = task
    assert task.cancelled()
