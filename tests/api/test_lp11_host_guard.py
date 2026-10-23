"""LP11, finding S-4 — DNS rebinding: without an API token, the API answers only requests addressed to
this machine, so a web page that rebinds its own domain to 127.0.0.1 cannot read scans or findings."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from aegis.api.main import create_app
from aegis.config import ApiSettings, AppSettings, ModelSettings

pytestmark = pytest.mark.phase("LP11")

READS = ("/api/scans", "/api/health", "/api/llm/config", "/api/findings?scan_id=S-0001")


def app(tmp_path, **api):
    settings = AppSettings(data_dir=str(tmp_path / "data"), offline_db_dir=str(tmp_path / "offline-db"),
                           model=ModelSettings(ollama_url="http://127.0.0.1:9"), api=ApiSettings(**api))
    return create_app(settings)


@pytest.mark.parametrize("base", ["http://attacker.example:8000", "http://aegis-rebind.example.com", "http://192.168.1.5:8000"])
def test_a_rebound_name_reads_nothing(tmp_path, base):
    with TestClient(app(tmp_path), base_url=base, client=("127.0.0.1", 1), raise_server_exceptions=False) as c:
        for path in READS:
            r = c.get(path)
            assert (r.status_code, r.json()["error"]) == (403, "host_not_allowed"), path


@pytest.mark.parametrize("base", ["http://127.0.0.1:8000", "http://localhost:8000", "http://[::1]:8000"])
def test_this_machine_reads_as_before(tmp_path, base):
    with TestClient(app(tmp_path), base_url=base, raise_server_exceptions=False) as c:
        assert c.get("/api/scans").status_code == 200 and c.get("/api/health").status_code == 200


def test_a_listed_name_is_allowed(tmp_path):
    with TestClient(app(tmp_path, allowed_hosts=("aegis.lan",)), base_url="http://aegis.lan:8000",
                    raise_server_exceptions=False) as c:
        assert c.get("/api/scans").status_code == 200


def test_with_a_token_the_token_decides(tmp_path):
    with TestClient(app(tmp_path, auth_token="s3cret-token-value"), base_url="http://aegis.lan:8000",
                    raise_server_exceptions=False) as c:
        assert c.get("/api/scans").status_code == 401
        assert c.get("/api/scans", headers={"Authorization": "Bearer s3cret-token-value"}).status_code == 200


def test_swagger_stays_readable(tmp_path):
    with TestClient(app(tmp_path), base_url="http://attacker.example", raise_server_exceptions=False) as c:
        assert c.get("/openapi.json").status_code == 200    # the API's description, no data


def test_allowed_hosts_from_the_environment(monkeypatch):
    from aegis.config import get_api_settings

    monkeypatch.setenv("AEGIS_API__ALLOWED_HOSTS", "aegis.lan, scanner.internal")
    assert get_api_settings().allowed_hosts == ("aegis.lan", "scanner.internal")
