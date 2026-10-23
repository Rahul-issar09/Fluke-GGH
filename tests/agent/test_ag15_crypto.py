"""AG15.1 — Worker 3 (crypto): discovery, classical + quantum rules, CBOM, live TLS linked to config.

Default tests use the crypto stand-in for semgrep and sslyze's real recorded reports
(``fakes.tool_executors``); ``test_ag15_tools_integration.py`` (``-m tools``) runs real semgrep and
real sslyze against the demo's live HTTPS port.
"""

from __future__ import annotations

import ast
import json
import shutil

import pytest

import aegis.agent.nodes.crypto_subgraph  # noqa: F401 - registers the crypto steps
from _graph_helpers import make_run
from aegis.agent.nodes.worker_stage import STAGE_STEPS, run_steps
from aegis.evidence.models import Mode
from aegis.workers.crypto.cbom import cbom_path
from aegis.workers.crypto.discover import asset_at
from aegis.workers.crypto.rules_classical import classical_risk
from aegis.workers.crypto.rules_quantum import quantum_risk
from aegis.workers.crypto.tls import link_issue, normalize_sslyze, tls_issues
from fakes.demo_apps import ROOT
from fakes.tool_executors import fix_executor, sslyze_executor

pytestmark = pytest.mark.phase("AG15")

TLS = "127.0.0.1:5443"
FIXTURES = ROOT / "tests" / "fixtures" / "tools"


def crypto_scan(store, tmp_path, app="demo-app", *, executor=None, tls=True):
    recording = "demo" if app == "demo-app" else "patched"
    scan_id, state, config = make_run(
        store, tmp_path, Mode.code, tool_executor=executor or sslyze_executor(recording),
        default_allowlist=(TLS,), data_dir=str(tmp_path / "data"),
    )
    src = tmp_path / "scan"
    shutil.rmtree(src, ignore_errors=True)
    shutil.copytree(ROOT / app, src, ignore=shutil.ignore_patterns("__pycache__"))
    cfg = json.loads(store.get_scan(scan_id).config_json)
    cfg["options"] = {"tls_targets": [TLS]} if tls else {}
    store.update_scan(scan_id, source_path=str(src), config_json=json.dumps(cfg))
    return scan_id, state, config


def found(store, scan_id, type_=None):
    return sorted((f.type, f.file, f.line) for f in store.list_findings(scan_id) if type_ in (None, f.type))


# --------------------------------------------------------------------------------------------- #
# the four tests the plan names
# --------------------------------------------------------------------------------------------- #
async def test_ag15_weak_hash_flagged(store, tmp_path):
    scan_id, state, config = crypto_scan(store, tmp_path)
    await run_steps("crypto", STAGE_STEPS["crypto"], state, config)
    (md5,) = [f for f in store.list_findings(scan_id) if f.type == "weak_crypto" and f.file == "app/auth.py"]
    assert (md5.line, md5.owasp, md5.function) == (12, "A02", "hash_password")
    assert "MD5" in md5.title and "passwords" in md5.title
    (ev,) = [json.loads(e.payload_json) for e in store.evidence_for(md5.id)]
    assert (ev["algo"], ev["usage"], ev["flag"]) == ("MD5", "password_hash", "weak_crypto")


async def test_ag15_rsa_quantum_flag(store, tmp_path):
    scan_id, state, config = crypto_scan(store, tmp_path)
    await run_steps("crypto", STAGE_STEPS["crypto"], state, config)
    rsa = [f for f in store.list_findings(scan_id) if f.file == "app/signing.py" and f.line == 15]
    assert sorted(f.type for f in rsa) == ["quantum_risk", "weak_crypto"]          # too short AND not quantum-safe
    quantum = next(f for f in rsa if f.type == "quantum_risk")
    assert "RSA-1024" in quantum.title and "ML-DSA" in quantum.title and quantum.severity == 0.4


async def test_ag15_cbom_has_both_flags(store, tmp_path):
    scan_id, state, config = crypto_scan(store, tmp_path)
    await run_steps("crypto", STAGE_STEPS["crypto"], state, config)
    cbom = json.loads(cbom_path(tmp_path / "data", scan_id).read_text(encoding="utf-8"))
    assert (cbom["bomFormat"], cbom["specVersion"]) == ("CycloneDX", "1.6")
    assert all(c["type"] == "cryptographic-asset" for c in cbom["components"])
    verdicts = [{p["name"]: p["value"] for p in c["properties"]} for c in cbom["components"]]
    assert sum(v["aegis:classical_risk"] != "none" for v in verdicts) >= 1
    assert sum(v["aegis:quantum_risk"] != "none" for v in verdicts) >= 1
    rsa = next(c for c in cbom["components"] if c["name"] == "RSA-1024")
    algo = rsa["cryptoProperties"]["algorithmProperties"]
    assert (algo["parameterSetIdentifier"], algo["classicalSecurityLevel"], algo["nistQuantumSecurityLevel"]) == ("1024", 80, 0)
    assert rsa["evidence"]["occurrences"] == [{"location": "app/signing.py", "line": 15}]
    endpoint = next(c for c in cbom["components"] if c["name"] == f"TLS endpoint {TLS}")
    assert "TLSv1.0" in endpoint["cryptoProperties"]["protocolProperties"]["version"]


async def test_ag15_tls_linked(store, tmp_path):
    scan_id, state, config = crypto_scan(store, tmp_path)
    await run_steps("crypto", STAGE_STEPS["crypto"], state, config)
    tls = {f.title.split(" (")[0]: f for f in store.list_findings(scan_id) if f.type == "weak_tls"}
    old = tls["Server accepts TLSv1.0, TLSv1.1"]
    assert (old.file, old.line, old.function) == ("app/tls.py", 9, "server_context")   # ctx.minimum_version = TLSv1
    kinds = {e.kind: json.loads(e.payload_json) for e in store.evidence_for(old.id)}
    assert kinds["tls_scan"]["target"] == TLS and kinds["tls_scan"]["linked_setting"] == "app/tls.py:9"
    assert kinds["crypto_asset"]["protocol"] == "TLSv1.0"                         # the setting that causes it
    ciphers = [f for t, f in tls.items() if "cipher suites" in t or "forward secrecy" in t]
    assert ciphers and all((f.file, f.line) == ("app/tls.py", 10) for f in ciphers)  # ctx.set_ciphers("ALL:@SECLEVEL=0")


# --------------------------------------------------------------------------------------------- #
# the patched app, and the whole picture
# --------------------------------------------------------------------------------------------- #
async def test_the_demo_app_finds_every_planted_crypto_weakness(store, tmp_path):
    scan_id, state, config = crypto_scan(store, tmp_path)
    out = await run_steps("crypto", STAGE_STEPS["crypto"], state, config)
    assert out.get("errors", []) == [] and out.get("steps_skipped", []) == []
    assert found(store, scan_id, "weak_crypto") == [
        ("weak_crypto", "app/auth.py", 12),        # MD5 for passwords
        ("weak_crypto", "app/signing.py", 15),     # RSA-1024
        ("weak_crypto", "app/signing.py", 21),     # SHA-1 signatures
        ("weak_crypto", "app/tls.py", 9),          # TLS 1.0 allowed
        ("weak_crypto", "app/tls.py", 10),         # legacy cipher string
    ]
    assert found(store, scan_id, "quantum_risk") == [("quantum_risk", "app/signing.py", 15), ("quantum_risk", "serve_https.py", 27)]


async def test_the_patched_app_has_no_weak_crypto_only_its_quantum_exposure(store, tmp_path):
    scan_id, state, config = crypto_scan(store, tmp_path, app="demo-app-patched")
    out = await run_steps("crypto", STAGE_STEPS["crypto"], state, config)
    assert out.get("errors", []) == [] and out["steps_run"] == STAGE_STEPS["crypto"]
    assert found(store, scan_id, "weak_crypto") == [] and found(store, scan_id, "weak_tls") == []
    # RSA-3072 is fine today, but no RSA is quantum-safe: that stays visible (informational)
    assert found(store, scan_id, "quantum_risk") == [("quantum_risk", "app/signing.py", 17), ("quantum_risk", "serve_https.py", 27)]


async def test_the_whole_graph_runs_the_crypto_stage_and_the_api_serves_the_cbom(store, tmp_path):
    from aegis.agent.graph import build_aegis_graph
    from aegis.services.query_service import QueryService

    scan_id, state, config = crypto_scan(store, tmp_path)
    final = await build_aegis_graph().ainvoke(state, config)
    assert final["errors"] == [] and "crypto" in final["completed_stages"]
    cbom = QueryService(store, tmp_path / "data").get_cbom(scan_id)
    assert cbom["metadata"]["properties"] == [{"name": "aegis:scan_id", "value": scan_id}]
    types = {f.type for f in store.list_findings(scan_id)}
    assert {"weak_crypto", "quantum_risk", "weak_tls"} <= types


# --------------------------------------------------------------------------------------------- #
# failure cases
# --------------------------------------------------------------------------------------------- #
async def test_a_tls_target_off_the_allowlist_is_refused_and_the_rest_still_runs(store, tmp_path):
    scan_id, state, config = crypto_scan(store, tmp_path)
    config["configurable"]["deps"].default_allowlist = ("demo-app:5000",)          # 127.0.0.1:5443 not allowed
    out = await run_steps("crypto", STAGE_STEPS["crypto"], state, config)
    assert any("not allowlisted" in e for e in out["errors"])
    assert found(store, scan_id, "weak_tls") == [] and found(store, scan_id, "weak_crypto")
    assert cbom_path(tmp_path / "data", scan_id).is_file()                          # the CBOM is still written
    (blocked,) = [c for c in store.list_tool_calls(scan_id) if c.tool == "sslyze"]
    assert blocked.blocked_reason.startswith("host not allowlisted")


async def test_without_tls_targets_or_tools_the_stage_degrades_quietly(store, tmp_path):
    from aegis.workers.executor import no_tools_executor

    scan_id, state, config = crypto_scan(store, tmp_path, executor=no_tools_executor)
    out = await run_steps("crypto", STAGE_STEPS["crypto"], state, config)
    assert out.get("errors", []) == [] and store.list_findings(scan_id) == []
    assert json.loads(cbom_path(tmp_path / "data", scan_id).read_text(encoding="utf-8"))["components"] == []


async def test_a_follow_up_on_one_file_adds_nothing_twice(store, tmp_path):
    scan_id, state, config = crypto_scan(store, tmp_path, tls=False)
    await run_steps("crypto", ["discover", "classical_rules", "quantum_rules"], state, config)
    before = (len(store.list_evidence(scan_id, kind="crypto_asset")), found(store, scan_id))
    await run_steps("crypto", ["discover", "classical_rules", "quantum_rules"], state, config, target={"file": "app/signing.py"})
    inventory = [e for e in store.list_evidence(scan_id, kind="crypto_asset") if json.loads(e.payload_json).get("role") == "inventory"]
    assert len({(json.loads(e.payload_json)["file"], json.loads(e.payload_json)["line"]) for e in inventory}) == len(inventory)
    assert found(store, scan_id) == before[1]


# --------------------------------------------------------------------------------------------- #
# the rules, one by one
# --------------------------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "asset, weak",
    [
        ({"primitive": "hash", "algo": "MD5", "usage": "hashing"}, True),
        ({"primitive": "hash", "algo": "SHA-1", "usage": "signature"}, True),
        ({"primitive": "hash", "algo": "SHA-256", "usage": "password_hash"}, True),     # fast hash for passwords
        ({"primitive": "hash", "algo": "SHA-256", "usage": "signature"}, False),
        ({"primitive": "pke", "family": "RSA", "algo": "RSA-1024", "key_size": 1024}, True),
        ({"primitive": "pke", "family": "RSA", "algo": "RSA-2048", "key_size": 2048}, False),
        ({"primitive": "pke", "family": "EC", "algo": "ECDSA-SECP192R1", "curve": "SECP192R1"}, True),
        ({"primitive": "pke", "family": "EC", "algo": "ECDSA-SECP256R1", "curve": "SECP256R1"}, False),
        ({"primitive": "block-cipher", "algo": "TripleDES"}, True),
        ({"primitive": "block-cipher", "algo": "AES", "mode": "ECB"}, True),
        ({"primitive": "block-cipher", "algo": "AES", "mode": "GCM"}, False),
        ({"asset_type": "protocol", "algo": "TLS", "setting": "minimum_version", "protocol": "TLSv1.0"}, True),
        ({"asset_type": "protocol", "algo": "TLS", "setting": "minimum_version", "protocol": "TLSv1.2"}, False),
        ({"asset_type": "protocol", "algo": "TLS", "setting": "ciphers", "ciphers": "ALL:@SECLEVEL=0"}, True),
        ({"asset_type": "protocol", "algo": "TLS", "setting": "ciphers", "ciphers": "ECDHE+AESGCM:ECDHE+CHACHA20"}, False),
        ({"primitive": "drbg", "algo": "random.choice", "usage": "token"}, True),
    ],
)
def test_classical_rules(asset, weak):
    assert bool(classical_risk(asset)) is weak


@pytest.mark.parametrize(
    "asset, exposed",
    [
        ({"primitive": "pke", "family": "RSA", "algo": "RSA-4096", "key_size": 4096}, True),   # any size
        ({"primitive": "pke", "family": "EC", "algo": "ECDSA-SECP256R1"}, True),
        ({"primitive": "pke", "family": "Ed25519", "algo": "Ed25519"}, True),
        ({"primitive": "block-cipher", "algo": "AES"}, False),
        ({"primitive": "hash", "algo": "SHA-256"}, False),
    ],
)
def test_quantum_rules(asset, exposed):
    assert bool(quantum_risk(asset)) is exposed


@pytest.mark.parametrize(
    "rule, code, expect",
    [
        ("crypto-hash", "hashlib.new('sha1', b'x')", {"algo": "SHA-1"}),
        ("crypto-hash", "hashes.SHA256()", {"algo": "SHA-256"}),
        ("crypto-public-key", "RSA.generate(1024)", {"algo": "RSA-1024", "key_size": 1024}),
        ("crypto-public-key", "ec.generate_private_key(ec.SECP192R1())", {"algo": "ECDSA-SECP192R1", "curve": "SECP192R1"}),
        ("crypto-public-key", "ed25519.Ed25519PrivateKey.generate()", {"algo": "Ed25519"}),
        ("crypto-cipher", "Cipher(algorithms.AES(k), modes.ECB())", {"algo": "AES", "mode": "ECB"}),
        ("crypto-cipher", "DES3.new(k, DES3.MODE_CBC)", {"algo": "DES3", "mode": "CBC"}),
        ("crypto-tls", "ssl.SSLContext(ssl.PROTOCOL_TLSv1_1)", {"protocol": "TLSv1.1"}),
    ],
)
def test_discovery_reads_the_details_from_the_code(rule, code, expect):
    tree = ast.parse(f"def token_or_key():\n    {code}\n")
    node = tree.body[0].body[0].value
    asset = asset_at(rule, tree, {"line": 2, "col": node.col_offset + 1}, {"line": 2, "col": node.end_col_offset + 1})
    assert {k: asset[k] for k in expect} == expect


def test_tls_issues_from_a_recorded_scan_and_their_links():
    report = json.loads((FIXTURES / "sslyze_demo.json").read_text(encoding="utf-8").replace('"{PORT}"', "5443").replace("{HOST}:{PORT}", TLS))
    (endpoint,) = normalize_sslyze(report)
    assert set(endpoint["accepted"]) == {"TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"}
    issues = {i["issue"]: i for i in tls_issues(endpoint)}
    assert issues["old_protocol"]["versions"] == ["TLSv1.0", "TLSv1.1"] and "weak_ciphers" in issues
    setting = {"asset_type": "protocol", "algo": "TLS", "setting": "minimum_version", "protocol": "TLSv1.0", "file": "app/tls.py", "line": 9}
    assert link_issue(issues["old_protocol"], [setting]) is setting
    assert link_issue(issues["old_protocol"], [{**setting, "protocol": "TLSv1.2"}]) is None   # a safe setting is not blamed

    patched = json.loads((FIXTURES / "sslyze_patched.json").read_text(encoding="utf-8").replace('"{PORT}"', "5443").replace("{HOST}:{PORT}", TLS))
    (safe,) = normalize_sslyze(patched)
    assert set(safe["accepted"]) == {"TLSv1.2", "TLSv1.3"} and tls_issues(safe) == []
