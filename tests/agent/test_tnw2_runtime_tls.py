"""TNW-2 — the TLS check on a runtime-only https link, and https links in general.

* a link without a port (``https://example.com``) is allowed by its ``host:443`` allowlist entry
  (the egress guard used to see the host without a port and block every such link),
* a runtime-only https scan runs sslyze in the runtime stage (first, so a target whose certificate
  is not trusted still gets its TLS findings) and writes a CBOM of the checked endpoints,
* with source code the check stays in the crypto stage (linked to the code) and never runs twice,
* ``options.verify_tls=false`` lets a test target with a self-signed certificate be scanned; without
  it such a target stops the runtime stage with a reason that says what to do.

Default tests use the in-process demo network and sslyze's real recorded report;
``test_real_runtime_only_https_scan`` (``-m tools``) runs real sslyze against the demo's live HTTPS
server, over the real network.
"""

from __future__ import annotations

import json
import ssl

import httpx
import pytest

import aegis.agent.nodes.runtime_subgraph  # noqa: F401 - registers the runtime steps
from _graph_helpers import make_run
from aegis.agent.graph import build_aegis_graph
from aegis.agent.nodes.worker_stage import STAGE_STEPS, run_steps
from aegis.agent.state import ScanInputs
from aegis.api.schemas import ScanRequest
from aegis.evidence.models import Mode
from aegis.router import RequestInvalid, validate_request
from aegis.safety.allowlist import Allowlist
from aegis.safety.egress import EgressBlocked, make_client
from aegis.safety.policies import validate_args
from aegis.workers.crypto.cbom import cbom_path
from aegis.workers.executor import BUILDERS
from aegis.workers.runtime.context import RuntimeStageError, verify_tls
from aegis.workers.runtime.validate import validate_target
from fakes.demo_apps import identities_path
from fakes.tool_executors import sslyze_executor

pytestmark = pytest.mark.phase("TNW-2")

HTTPS = "https://demo-app:5443"
TLS_TARGET = "demo-app:5443"


# --------------------------------------------------------------------------------------------- #
# links without a port
# --------------------------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "entry, url, allowed",
    [
        ("example.com:443", "https://example.com/", True),
        ("example.com:80", "http://example.com/login", True),
        ("example.com", "https://example.com/", True),             # a bare host allows any port
        ("example.com:443", "http://example.com/", False),         # port 80 is a different service
        ("example.com:8443", "https://example.com/", False),
        ("example.com:443", "https://example.com:443/", True),
    ],
)
async def test_the_egress_guard_fills_in_the_default_port(entry, url, allowed):
    reached = []
    inner = httpx.MockTransport(lambda request: reached.append(request.url) or httpx.Response(200))
    async with make_client(Allowlist([entry]), inner=inner) as client:
        if allowed:
            assert (await client.get(url)).status_code == 200
        else:
            with pytest.raises(EgressBlocked):
                await client.get(url)
    assert bool(reached) is allowed


# --------------------------------------------------------------------------------------------- #
# a runtime-only https scan
# --------------------------------------------------------------------------------------------- #
def https_run(store, tmp_path, *, verify: bool | None = None, executor=None):
    scan_id, state, config = make_run(
        store, tmp_path, Mode.runtime, tool_executor=executor or sslyze_executor("demo"),
        default_allowlist=(TLS_TARGET, "callback:8080"),
    )
    cfg = json.loads(store.get_scan(scan_id).config_json)
    cfg["url"] = HTTPS
    if verify is not None:
        cfg["options"] = {"verify_tls": verify}
    store.update_scan(scan_id, target_url=HTTPS, config_json=json.dumps(cfg))
    state["inputs"] = ScanInputs(url=HTTPS, identities=identities_path("vulnerable"))
    return scan_id, state, config


def weak_tls(store, scan_id):
    return [f for f in store.list_findings(scan_id) if f.type == "weak_tls"]


async def test_a_runtime_only_https_scan_reports_weak_tls(store, tmp_path):
    scan_id, state, config = https_run(store, tmp_path)
    final = await build_aegis_graph().ainvoke(state, config)
    assert final["errors"] == [] and final["plan"] == ["runtime"]

    tls = weak_tls(store, scan_id)
    titles = sorted(f.title for f in tls)
    assert "Server accepts TLSv1.0, TLSv1.1 (demo-app:5443)" in titles
    assert any("cipher suites" in t for t in titles)
    for f in tls:  # no source code: the live check is the evidence, not a line of config
        assert (f.file, f.line, getattr(f.mode, "value", f.mode)) == (None, None, "runtime")
        (ev,) = [e for e in store.evidence_for(f.id) if e.kind == "tls_scan"]
        assert json.loads(ev.payload_json)["linked_setting"] is None

    # the rest of the runtime checks still ran over https
    assert any(f.type == "broken_access_control" for f in store.list_findings(scan_id))
    (call,) = [c for c in store.list_tool_calls(scan_id) if c.tool == "sslyze"]
    assert call.target_host == TLS_TARGET and call.blocked_reason is None

    cbom = json.loads(cbom_path(tmp_path / "data", scan_id).read_text(encoding="utf-8"))
    assert cbom["components"], "the checked TLS endpoint is listed in the CBOM"


async def test_an_http_link_has_no_tls_check(store, tmp_path):
    scan_id, state, config = make_run(store, tmp_path, Mode.runtime, tool_executor=sslyze_executor("demo"))
    out = await run_steps("runtime", ["tls_scan"], state, config)
    assert out.get("errors", []) == [] and weak_tls(store, scan_id) == []
    assert [c for c in store.list_tool_calls(scan_id) if c.tool == "sslyze"] == []
    assert not cbom_path(tmp_path / "data", scan_id).exists()


async def test_with_source_code_the_tls_check_runs_once_in_the_crypto_stage(store, tmp_path):
    scan_id, state, config = https_run(store, tmp_path)
    store.update_scan(scan_id, source_path=str(tmp_path / "scan"))  # a correlated scan has source
    out = await run_steps("runtime", ["tls_scan"], state, config)
    assert out.get("errors", []) == [] and [c for c in store.list_tool_calls(scan_id) if c.tool == "sslyze"] == []


async def test_a_tls_target_off_the_allowlist_is_reported_and_the_scan_goes_on(store, tmp_path):
    scan_id, state, config = https_run(store, tmp_path)
    config["configurable"]["deps"].default_allowlist = ("demo-app:5000",)
    out = await run_steps("runtime", ["tls_scan"], state, config)
    assert any("not allowlisted" in e for e in out["errors"]) and weak_tls(store, scan_id) == []
    assert cbom_path(tmp_path / "data", scan_id).is_file()


# --------------------------------------------------------------------------------------------- #
# certificates: options.verify_tls
# --------------------------------------------------------------------------------------------- #
async def test_an_untrusted_certificate_says_what_to_do():
    def refuse(request):
        raise httpx.ConnectError("[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: self-signed certificate", request=request)

    async with make_client(Allowlist([TLS_TARGET]), inner=httpx.MockTransport(refuse)) as client:
        with pytest.raises(RuntimeStageError, match="options.verify_tls=false"):
            await validate_target(client, HTTPS)


def test_verify_tls_is_a_per_scan_option_and_defaults_to_on():
    assert verify_tls({}) is True and verify_tls({"options": {}}) is True
    assert verify_tls({"options": {"verify_tls": False}}) is False
    validate_request(ScanRequest(url=HTTPS, identities="x", options={"verify_tls": False}))
    with pytest.raises(RequestInvalid, match="verify_tls"):
        validate_request(ScanRequest(url=HTTPS, identities="x", options={"verify_tls": "no"}))


def _ssl_context(client: httpx.AsyncClient) -> ssl.SSLContext:
    return client._transport._inner._pool._ssl_context


async def test_the_runtime_client_follows_the_option():
    async with make_client(Allowlist([TLS_TARGET])) as on, make_client(Allowlist([TLS_TARGET]), verify=False) as off:
        assert _ssl_context(on).verify_mode == ssl.CERT_REQUIRED
        assert _ssl_context(off).verify_mode == ssl.CERT_NONE


def test_schemathesis_follows_the_option():
    base = {"openapi": f"{HTTPS}/openapi.json", "url": HTTPS}
    assert "--tls-verify" not in BUILDERS["schemathesis"](validate_args("schemathesis", base)).argv
    argv = BUILDERS["schemathesis"](validate_args("schemathesis", {**base, "tls_verify": False})).argv
    assert argv[argv.index("--tls-verify") + 1] == "false"


def test_tls_scan_runs_first_in_the_runtime_stage():
    assert STAGE_STEPS["runtime"][:2] == ["tls_scan", "validate_target"]


# --------------------------------------------------------------------------------------------- #
# real sslyze + real HTTPS (opt-in: -m tools)
# --------------------------------------------------------------------------------------------- #
@pytest.mark.tools
@pytest.mark.parametrize("verify", [True, False])
async def test_real_runtime_only_https_scan(store, tmp_path, verify):
    from aegis.workers import executor
    from aegis.workers.executor import execute_tool
    from test_ag15_tools_integration import _free_port  # noqa: F401 - same server helper
    import subprocess
    import sys
    import time
    import urllib.request

    from fakes.demo_apps import ROOT

    if executor.find_binary("sslyze") is None:
        pytest.skip("sslyze is not installed")
    port = _free_port()
    proc = subprocess.Popen([sys.executable, "serve_https.py", "--port", str(port)], cwd=ROOT / "demo-app",
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(80):
            try:
                urllib.request.urlopen(f"https://127.0.0.1:{port}/health", context=ssl._create_unverified_context(), timeout=1)
                break
            except Exception:  # noqa: BLE001 - still starting
                time.sleep(0.25)
        url, target = f"https://127.0.0.1:{port}", f"127.0.0.1:{port}"
        scan_id, state, config = make_run(store, tmp_path, Mode.runtime, tool_executor=execute_tool,
                                          http_transport=None, default_allowlist=(target,))
        cfg = json.loads(store.get_scan(scan_id).config_json)
        cfg.update(url=url, options={"verify_tls": verify})
        store.update_scan(scan_id, target_url=url, config_json=json.dumps(cfg))
        state["inputs"] = ScanInputs(url=url, identities=identities_path("vulnerable"))

        await build_aegis_graph().ainvoke(state, config)
        titles = {f.title.split(" (")[0] for f in weak_tls(store, scan_id)}
        assert "Server accepts TLSv1.0, TLSv1.1" in titles   # found either way: sslyze needs no trust
        bola = [f for f in store.list_findings(scan_id) if f.type == "broken_access_control"]
        failure = json.loads(store.get_scan(scan_id).config_json).get("failure_reason") or ""
        errors = [json.loads(e.payload_json) for e in store.list_evidence(scan_id, kind="tool_error")]
        if verify:  # the self-signed certificate is refused, with the way out named
            assert not bola and any("verify_tls=false" in json.dumps(e) for e in errors), (failure, errors)
        else:       # accepted for this test target: the access-control bug is found over https
            assert bola, errors
    finally:
        proc.terminate()
