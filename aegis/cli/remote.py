"""Talking to the running AEGIS API (cli_new_phases.md N0–N3).

The CLI is a thin client: scans and questions go to the REST API, which does all the work. This
module is the one place that knows the API's address, sends the bearer token, and turns HTTP errors
into the CLI's exit codes, using the API's own reason (``{"error", "detail"}``) as the message.
:class:`RemoteBackend` serves every command through the API (the default); ``--local`` uses
:class:`~aegis.cli.backend.LocalBackend` instead.

Address: ``--api URL``, else ``AEGIS_API_URL``, else ``http://127.0.0.1:8000`` (127.0.0.1, not
localhost: on Windows "localhost" can resolve to IPv6 first). Server code is never changed or run from
here; only the evidence redaction helpers are reused, so both modes redact identically.
"""

from __future__ import annotations

import json
import os
from typing import Any, Iterator

import httpx

from aegis.cli.backend import Backend
from aegis.cli.errors import CONFLICT, FAILED, NOT_FOUND, UNAVAILABLE, USAGE, CliError

__all__ = ["DEFAULT_API", "ApiClient", "RemoteBackend", "api_url", "make_http_client"]

DEFAULT_API = "http://127.0.0.1:8000"
START_HINT = r"start it with scripts\run_local.cmd (or: uvicorn aegis.main:app --host 127.0.0.1 --port 8000), or pass --api URL"

_STATUS = {404: NOT_FOUND, 409: CONFLICT, 413: USAGE, 422: USAGE, 400: USAGE, 501: UNAVAILABLE}


def api_url(option: str | None = None) -> str:
    """The API address in effect: ``--api``, then ``AEGIS_API_URL``, then the default."""
    return (option or os.getenv("AEGIS_API_URL") or DEFAULT_API).rstrip("/")


def make_http_client(base_url: str, timeout: float) -> httpx.Client:
    """The HTTP client (tests replace this with FastAPI's in-process ``TestClient``)."""
    return httpx.Client(base_url=base_url, timeout=timeout)


def _detail(response: httpx.Response) -> str:
    try:
        body = response.json()
    except ValueError:
        return response.text[:200] or response.reason_phrase
    if isinstance(body, dict):
        return str(body.get("detail") or body.get("error") or body)[:500]
    return str(body)[:500]


class ApiClient:
    def __init__(self, base_url: str, token: str | None = None, *, timeout: float = 30.0, client: httpx.Client | None = None):
        self.base_url = base_url.rstrip("/")
        self._client = client or make_http_client(self.base_url, timeout)
        self._headers = {"Authorization": f"Bearer {token}"} if token else {}

    # ------------------------------------------------------------------ requests
    def request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        """Send one request; any failure becomes a :class:`CliError` with the right exit code."""
        headers = {**self._headers, **kwargs.pop("headers", {})}
        try:
            response = self._client.request(method, path, headers=headers, **kwargs)
        except httpx.ConnectError as exc:
            raise CliError(f"AEGIS API is not running at {self.base_url}", UNAVAILABLE, hint=START_HINT) from exc
        except httpx.TimeoutException as exc:
            raise CliError(f"AEGIS API at {self.base_url} did not answer in time", UNAVAILABLE,
                           hint="it may be busy (a scan or a local-model answer); try again") from exc
        except httpx.HTTPError as exc:
            raise CliError(f"cannot talk to the AEGIS API at {self.base_url}: {type(exc).__name__}", UNAVAILABLE) from exc
        self.raise_for_status(response)
        return response

    def raise_for_status(self, response: httpx.Response) -> None:
        status = response.status_code
        if status < 400:
            return
        if status in (401, 403):
            raise CliError("the AEGIS API needs a valid token", UNAVAILABLE,
                           hint="pass --token or set AEGIS_API__AUTH_TOKEN (the token the API was started with)")
        code = _STATUS.get(status, FAILED if status >= 500 else USAGE)
        message = _detail(response)
        raise CliError(message if status < 500 else f"the AEGIS API failed ({status}): {message}", code)

    def get(self, path: str, **kwargs: Any) -> Any:
        return self.request("GET", path, **kwargs).json()

    def post(self, path: str, **kwargs: Any) -> Any:
        response = self.request("POST", path, **kwargs)
        return response.json() if response.content else None

    def stream_events(self, path: str) -> Iterator[dict]:
        """Follow a server-sent-events stream; yield each ``data:`` JSON object. No read timeout: a
        scan step can run for minutes (keep-alive pings arrive every 15 s)."""
        try:
            with self._client.stream("GET", path, headers=self._headers, timeout=httpx.Timeout(15.0, read=None)) as response:
                if response.status_code >= 400:
                    response.read()
                    self.raise_for_status(response)
                data: list[str] = []
                for line in response.iter_lines():
                    if line.startswith(":"):                     # keep-alive ping
                        continue
                    if line.startswith("data:"):
                        data.append(line[5:].strip())
                    elif line == "" and data:                    # a blank line ends one event
                        yield json.loads("\n".join(data))
                        data = []
                if data:
                    yield json.loads("\n".join(data))
        except httpx.ConnectError as exc:
            raise CliError(f"AEGIS API is not running at {self.base_url}", UNAVAILABLE, hint=START_HINT) from exc
        except httpx.RemoteProtocolError as exc:
            raise CliError("the AEGIS API closed the progress stream (did it stop?)", UNAVAILABLE) from exc

    # ------------------------------------------------------------------ endpoints
    def health(self) -> dict:
        return self.get("/api/health", timeout=15.0)

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "ApiClient":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()


def _clean(params: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in params.items() if v is not None}


class RemoteBackend(Backend):
    """Every CLI command, served by the running AEGIS API (cli_new_phases.md N1).

    Returns the API's JSON shapes, which the ``ui`` views render exactly like local results.
    """

    mode = "api"

    def __init__(self, api: ApiClient):
        self.api = api

    def describe(self) -> dict[str, Any]:
        return {"mode": self.mode, "api": self.api.base_url}

    # ---- read
    def latest_scan_id(self) -> str | None:
        rows = self.list_scans(1)
        return rows[0]["id"] if rows else None

    def list_scans(self, limit: int = 20) -> list[dict]:
        return self.api.get("/api/scans", params={"limit": limit})

    def scan_status(self, scan_id: str) -> dict:
        return self.api.get(f"/api/scans/{scan_id}")

    def scan_audit(self, scan_id: str) -> dict:
        return self.api.get(f"/api/scans/{scan_id}/audit")

    def list_findings(self, scan_id: str, **filters: Any) -> list[dict]:
        return self.api.get("/api/findings", params=_clean({"scan_id": scan_id, **filters}))

    def get_finding(self, finding_id: str) -> dict:
        return self.api.get(f"/api/findings/{finding_id}")

    def get_evidence(self, evidence_id: str, *, raw: bool = False) -> Any:
        """The API returns the raw record (its operator surface); the CLI applies the same projection
        as local mode — a digest by default, or the payload with credentials redacted — so a secret
        is never printed and both modes show exactly the same thing."""
        record = self.api.get(f"/api/evidence/{evidence_id}")
        return project_evidence(_evidence_model(record), expose_raw=raw)

    def get_graph(self, scan_id: str) -> dict:
        return self.api.get("/api/graph", params={"scan_id": scan_id})

    def get_cbom(self, scan_id: str) -> dict:
        return self.api.get("/api/cbom", params={"scan_id": scan_id})

    # ---- reports and the gate
    def get_report(self, scan_id: str, fmt: str) -> dict[str, Any]:
        response = self.api.request("GET", "/api/reports", params={"scan_id": scan_id, "format": fmt})
        suffix = "cbom.json" if fmt == "cbom" else fmt
        return {"content": response.content, "media_type": response.headers.get("content-type", ""),
                "filename": f"aegis-{scan_id}.{suffix}", "path": None}

    def gate(self, scan_id: str, threshold: float | None = None) -> dict:
        return self.api.get(f"/api/scans/{scan_id}/gate", params=_clean({"severity_threshold": threshold}))

    # ---- scans (N2): the API runs them; the CLI starts, follows and cancels
    def start_scan(self, body: dict) -> str:
        """``POST /api/scans``; the API validates the request and picks the mode. Returns the scan id."""
        return self.api.post("/api/scans", json=body)["scan_id"]

    def scan_events(self, scan_id: str) -> Iterator[dict]:
        """Progress events of a scan until its final one (``GET /api/scans/{id}/events``)."""
        return self.api.stream_events(f"/api/scans/{scan_id}/events")

    def cancel_scan(self, scan_id: str) -> None:
        self.api.post(f"/api/scans/{scan_id}/cancel")

    # ---- questions (N3): answered by the API's chat (local model), cited
    ASK_TIMEOUT_S = 180.0      # a local-model explanation took ~30-46 s on the reference laptop

    def ask(self, scan_id: str, question: str) -> dict:
        """``POST /api/ask`` → ``{"answer", "finding_ids", "evidence_ids"}``."""
        return self.api.post("/api/ask", json={"scan_id": scan_id, "question": question}, timeout=self.ASK_TIMEOUT_S)

    def close(self) -> None:
        self.api.close()


def project_evidence(evidence: Any, *, expose_raw: bool) -> Any:
    """The CLI's evidence policy (same functions as local mode and the MCP server)."""
    from aegis.mcp.redaction import project_evidence as _project

    return _project(evidence, expose_raw=expose_raw)


def _evidence_model(record: dict) -> Any:
    """An API evidence record as the model the redaction functions take (nothing is stored)."""
    import json
    from datetime import datetime

    from aegis.evidence.models import Evidence

    created = record.get("created_at")
    return Evidence(
        id=record["id"], finding_id=record.get("finding_id"), scan_id=record["scan_id"], kind=record["kind"],
        tool=record["tool"], tool_version=record.get("tool_version") or "", db_date=record.get("db_date"),
        payload_json=json.dumps(record.get("payload")), created_at=datetime.fromisoformat(created) if created else None,
    )
