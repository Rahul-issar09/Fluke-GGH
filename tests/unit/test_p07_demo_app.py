"""P0.7 / P0.8 — the demo target and its patched build behave as specified."""

from __future__ import annotations

import pathlib

import httpx
import pytest
import yaml

from fakes.demo_apps import ROOT, create_demo_app, demo_transport, identities_path

pytestmark = pytest.mark.phase("AG06")


async def _login(client: httpx.AsyncClient, user: str, password: str) -> dict[str, str]:
    resp = await client.post("/login", json={"username": user, "password": password})
    assert resp.status_code == 200
    return dict(resp.cookies)


def _client(kind: str) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=demo_transport(kind), base_url="http://demo-app:5000")


async def test_vulnerable_app_lets_bob_read_alices_account():
    async with _client("vulnerable") as c:
        bob = await _login(c, "bob", "bob-demo-pass")
        c.cookies.clear()
        resp = await c.get("/api/accounts/1", headers={"Cookie": f"session={bob['session']}"})
        assert resp.status_code == 200
        assert resp.json()["owner"] == "alice"  # B reads A's record


async def test_patched_app_denies_bob():
    async with _client("patched") as c:
        bob = await _login(c, "bob", "bob-demo-pass")
        c.cookies.clear()
        resp = await c.get("/api/accounts/1", headers={"Cookie": f"session={bob['session']}"})
        assert resp.status_code == 403


@pytest.mark.parametrize("kind", ["vulnerable", "patched"])
async def test_owner_can_still_read_own_account(kind):
    async with _client(kind) as c:
        alice = await _login(c, "alice", "alice-demo-pass")
        c.cookies.clear()
        headers = {"Cookie": f"session={alice['session']}"}
        listing = await c.get("/api/accounts", headers=headers)
        assert [a["id"] for a in listing.json()] == [1]
        assert (await c.get("/api/accounts/1", headers=headers)).status_code == 200


@pytest.mark.parametrize("kind", ["vulnerable", "patched"])
async def test_unauthenticated_and_bad_login_rejected(kind):
    async with _client(kind) as c:
        assert (await c.get("/api/accounts/1")).status_code == 401
        bad = await c.post("/login", json={"username": "alice", "password": "wrong"})
        assert bad.status_code == 401


@pytest.mark.parametrize("kind", ["vulnerable", "patched"])
async def test_search_works_for_a_normal_query(kind):
    async with _client(kind) as c:
        cookies = await _login(c, "alice", "alice-demo-pass")
        c.cookies.clear()
        resp = await c.get(
            "/api/users/search", params={"name": "bo"}, headers={"Cookie": f"session={cookies['session']}"}
        )
        assert [u["username"] for u in resp.json()] == ["bob"]


def test_openapi_lists_the_routes_aegis_needs():
    paths = create_demo_app("vulnerable").openapi()["paths"]
    assert "get" in paths["/api/accounts/{id}"] and "get" in paths["/api/accounts"]


def test_planted_weaknesses_present_and_fixed_in_patched():
    vuln = ROOT / "demo-app" / "app"
    fixed = ROOT / "demo-app-patched" / "app"
    read = lambda base, rel: (base / rel).read_text(encoding="utf-8")  # noqa: E731

    assert read(vuln, "config.py").count("sk_live_") == 1  # planted hardcoded secret
    assert "md5" in read(vuln, "auth.py")  # planted weak hash
    assert "'%\" + name" in read(vuln, "routes/users.py")  # string-built SQL
    assert "owner_id\"] != user" not in read(vuln, "routes/accounts.py")  # no owner check

    assert "sk_live_" not in read(fixed, "config.py")
    assert "md5" not in read(fixed, "auth.py") and "scrypt" in read(fixed, "auth.py")
    assert "LIKE ?" in read(fixed, "routes/users.py")
    assert "owner_id\"] != user" in read(fixed, "routes/accounts.py")


@pytest.mark.parametrize("kind", ["vulnerable", "patched"])
def test_identities_file_defines_a_and_b(kind):
    cfg = yaml.safe_load(pathlib.Path(identities_path(kind)).read_text(encoding="utf-8"))
    assert set(cfg["identities"]) == {"A", "B"}
    assert cfg["login"]["url"] == "/login"
