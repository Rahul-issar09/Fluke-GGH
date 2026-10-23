"""AG06.2 (part 1) — callback listener + out-of-band SSRF check."""

from __future__ import annotations

import contextlib

import httpx
import pytest

from aegis.evidence.adapters.base import FindingDraft, fingerprint
from aegis.evidence.digest import digest
from aegis.evidence.models import FindingState
from aegis.safety.allowlist import Allowlist
from aegis.safety.egress import make_client
from aegis.safety.test_inputs import TestInputLibrary
from aegis.workers.runtime.auth import authenticate, load_identities
from aegis.workers.runtime.context import Route, RuntimeStageError
from aegis.workers.runtime.discover import discover_routes
from aegis.workers.runtime.ssrf import (
    check_ssrf,
    find_ssrf_candidates,
    listener_base,
    looks_like_url_param,
    record_ssrf_findings,
)
from fakes.demo_apps import HostRouter, create_listener, demo_stack, identities_path

pytestmark = pytest.mark.phase("AG06")

BASE = "http://demo-app:5000"
ALLOW = ("demo-app:5000", "callback:8080")


class Recorder(httpx.AsyncBaseTransport):
    """Pass-through transport that remembers every request it saw."""

    def __init__(self, inner: httpx.AsyncBaseTransport):
        self.inner = inner
        self.requests: list[httpx.Request] = []

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return await self.inner.handle_async_request(request)


@contextlib.asynccontextmanager
async def _setup(kind: str = "vulnerable", transport=None, allow=ALLOW):
    """Yield (client, sessions, routes, listener) on an in-process scan network."""
    stack, listener = demo_stack(kind)
    client = make_client(Allowlist(allow), inner=transport or stack)
    try:
        sessions = await authenticate(client, BASE, load_identities(identities_path(kind)))
        routes, _ = await discover_routes(client, BASE)
        yield client, sessions, routes, listener
    finally:
        await client.aclose()


# --- candidate selection ---------------------------------------------------- #
@pytest.mark.parametrize(
    "name,expected",
    [("url", True), ("redirect_uri", True), ("imageUrl", True), ("callback", True),
     ("name", False), ("id", False), ("page", False), ("q", False)],
)
def test_url_like_parameter_names(name, expected):
    assert looks_like_url_param(name) is expected


def test_candidates_are_safe_get_routes_only():
    routes = [
        Route("GET", "/api/fetch", ("url",), ("url",)),                       # yes
        Route("GET", "/api/preview", ("target", "lang"), ()),                  # yes (optional url-like)
        Route("GET", "/api/users/search", ("name",), ("name",)),               # not url-like
        Route("GET", "/api/files/{id}/import", ("source_url",), ("source_url",)),  # path parameter
        Route("GET", "/api/proxy", ("url", "token"), ("url", "token")),        # another required param
        Route("POST", "/api/webhook", ("url",), ("url",)),                     # not a safe method
    ]
    assert [(r.path, p) for r, p in find_ssrf_candidates(routes)] == [
        ("/api/fetch", "url"),
        ("/api/preview", "target"),
    ]


def test_listener_base_is_the_origin_of_the_approved_input():
    value = TestInputLibrary.load().resolve("SSRF-CB-001", "S-0001")
    assert value == "http://callback:8080/hit/S-0001"
    assert listener_base(value) == "http://callback:8080"


# --- the check --------------------------------------------------------------- #
async def test_ssrf_confirmed_on_the_vulnerable_demo():
    async with _setup("vulnerable") as (client, sessions, routes, _):
        results = await check_ssrf(
            client, BASE, find_ssrf_candidates(routes), sessions["A"],
            TestInputLibrary.load(), "S-0001", wait_s=1.0,
        )
    assert len(results) == 1
    r = results[0]
    assert (r["route"], r["param"], r["test_input_id"]) == ("GET /api/fetch", "url", "SSRF-CB-001")
    assert r["probe_status"] == 200 and r["hits"] == 1 and r["vulnerable"] is True


async def test_ssrf_not_found_on_the_patched_demo():
    async with _setup("patched") as (client, sessions, routes, _):
        results = await check_ssrf(
            client, BASE, find_ssrf_candidates(routes), sessions["A"],
            TestInputLibrary.load(), "S-0001", wait_s=0.3,
        )
    assert len(results) == 1
    assert results[0]["vulnerable"] is False and results[0]["probe_status"] == 400
    assert results[0]["hits"] == 0


async def test_only_the_approved_callback_url_is_ever_sent():
    stack, _ = demo_stack("vulnerable")
    recorder = Recorder(stack)
    async with _setup(transport=recorder) as (client, sessions, routes, _):
        await check_ssrf(
            client, BASE, find_ssrf_candidates(routes), sessions["A"],
            TestInputLibrary.load(), "S-0042", wait_s=1.0,
        )
    probes = [r for r in recorder.requests if r.url.path == "/api/fetch"]
    assert len(probes) == 1
    assert probes[0].url.params["url"] == "http://callback:8080/hit/S-0042"  # the library value, verbatim
    assert {r.url.host for r in recorder.requests} <= {"demo-app", "callback"}


async def test_probes_are_attributed_one_at_a_time():
    """A hit is only credited to the probe that caused it."""
    # a second, harmless candidate that never contacts the listener
    quiet = Route("GET", "/health", ("url",), ())
    async with _setup("vulnerable") as (client, sessions, routes, _):
        candidates = find_ssrf_candidates(routes)
        results = await check_ssrf(
            client, BASE, [*candidates, (quiet, "url")], sessions["A"],
            TestInputLibrary.load(), "S-0001", wait_s=0.3,
        )
    by_route = {r["route"]: r["vulnerable"] for r in results}
    assert by_route == {"GET /api/fetch": True, "GET /health": False}


async def test_unreachable_listener_is_reported_not_swallowed():
    stack, _ = demo_stack("vulnerable")
    only_target = HostRouter({"demo-app": stack._routes["demo-app"]})  # no route to callback:8080
    async with _setup(transport=only_target) as (client, sessions, routes, _):
        with pytest.raises(RuntimeStageError, match="callback listener unreachable"):
            await check_ssrf(
                client, BASE, find_ssrf_candidates(routes), sessions["A"],
                TestInputLibrary.load(), "S-0001", wait_s=0.2,
            )


async def test_listener_must_be_on_the_allowlist():
    async with _setup(allow=("demo-app:5000",)) as (client, sessions, routes, _):
        with pytest.raises(RuntimeStageError, match="allowlist"):
            await check_ssrf(
                client, BASE, find_ssrf_candidates(routes), sessions["A"],
                TestInputLibrary.load(), "S-0001", wait_s=0.2,
            )


# --- adapter / finding -------------------------------------------------------- #
def _result(param: str = "url", route: str = "GET /api/fetch") -> dict:
    return {"route": route, "path": "/api/fetch", "param": param, "test_input_id": "SSRF-CB-001",
            "probe_status": 200, "hits": 1, "vulnerable": True}


def test_oob_hit_creates_a_confirmed_ssrf_finding(store):
    scan = store.add_scan(mode="runtime")
    ids = record_ssrf_findings(store, scan.id, "runtime", [_result(), {**_result(), "vulnerable": False}])
    assert len(ids) == 1

    finding = store.get_finding(ids[0])
    assert (finding.type, finding.owasp, finding.route) == ("ssrf", "A10", "GET /api/fetch")
    assert finding.state == FindingState.confirmed

    (evidence,) = store.evidence_for(finding.id)
    assert evidence.kind == "oob_hit"
    assert digest(evidence) == f"{evidence.id}: out-of-band callback hit for url"
    assert "SSRF-CB-001" in evidence.payload_json
    assert "callback:8080" not in evidence.payload_json  # the probe value is referenced by ID only


def test_two_vulnerable_parameters_on_one_route_stay_two_findings(store):
    scan = store.add_scan(mode="runtime")
    ids = record_ssrf_findings(store, scan.id, "runtime", [_result("url"), _result("redirect")])
    assert len(set(ids)) == 2
    assert record_ssrf_findings(store, scan.id, "runtime", [_result("url")]) == [ids[0]]  # idempotent


def test_variant_changes_the_fingerprint_only_when_set():
    plain = FindingDraft(type="sqli", file="f.py", line=3)
    assert fingerprint(FindingDraft(type="ssrf", route="GET /x", variant="a")) != fingerprint(
        FindingDraft(type="ssrf", route="GET /x", variant="b")
    )
    # an unset variant leaves existing fingerprints exactly as they were
    import hashlib

    assert fingerprint(plain) == hashlib.sha1(b"sqli|f.py|3").hexdigest()


# --- callback listener -------------------------------------------------------- #
async def _listener_client():
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=create_listener()), base_url="http://callback:8080")


async def test_listener_counts_hits_per_token():
    async with await _listener_client() as c:
        assert (await c.get("/hits/S-0001")).json()["count"] == 0
        assert (await c.get("/hit/S-0001")).status_code == 200
        await c.post("/hit/S-0001")
        await c.get("/hit/S-0002")
        assert (await c.get("/hits/S-0001")).json()["count"] == 2
        assert (await c.get("/hits/S-0002")).json()["count"] == 1


async def test_listener_records_only_the_fact_of_a_hit():
    async with await _listener_client() as c:
        await c.post("/hit/S-0001", content=b"super secret body", headers={"Authorization": "Bearer abc"})
        (entry,) = (await c.get("/hits/S-0001")).json()["hits"]
    assert set(entry) == {"at", "method", "from"} and entry["method"] == "POST"


async def test_listener_rejects_bad_tokens_and_bounds_memory(monkeypatch):
    async with await _listener_client() as c:
        assert (await c.get("/hit/bad token!")).status_code in (400, 404)
        assert (await c.get("/hit/" + "x" * 65)).status_code == 400
        assert (await c.get("/hits/" + "x" * 65)).status_code == 400
        for _ in range(105):
            await c.get("/hit/S-0001")
        assert (await c.get("/hits/S-0001")).json()["count"] == 100  # per-token cap
