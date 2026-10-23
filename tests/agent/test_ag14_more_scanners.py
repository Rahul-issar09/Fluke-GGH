"""AG14 (P7.6) — TruffleHog, OSV-Scanner, Trivy and Syft in the code worker.

Default tests replay the tools' real outputs on the demo apps (recorded in tests/fixtures/tools);
``test_ag14_tools_integration.py`` (``-m tools``) runs the real binaries against the staged
offline databases.
"""

from __future__ import annotations

import json
import shutil

import pytest

import aegis.agent.nodes.code_subgraph  # noqa: F401 - registers the code worker's steps
from _graph_helpers import make_run
from aegis.agent.nodes.worker_stage import STAGE_STEPS, run_steps
from aegis.evidence.models import FindingState, Mode
from aegis.safety.policies import PolicyError, validate_args
from aegis.workers.code.dependencies import normalize_osv, normalize_trivy, package_line
from aegis.workers.code.inventory import components
from aegis.workers.code.trufflehog import clean_results
from aegis.workers.executor import _osv, _trivy, _trufflehog
from fakes.demo_apps import ROOT
from fakes.tool_executors import fix_executor
from test_ag10_remediate import SECRET_VALUE

pytestmark = pytest.mark.phase("AG14")

FIXTURES = ROOT / "tests" / "fixtures" / "tools"


def full_scan(store, tmp_path, app="demo-app", *, staged=True, executor=fix_executor):
    """A code scan of a whole demo app (code, requirements.txt, Dockerfile) with the databases staged."""
    offline = tmp_path / "offline-db"
    if staged:
        (offline / "osv").mkdir(parents=True)
        (offline / "trivy").mkdir(parents=True)
    scan_id, state, config = make_run(store, tmp_path, Mode.code, tool_executor=executor, offline_db_dir=str(offline))
    src = tmp_path / "scan"
    shutil.rmtree(src, ignore_errors=True)
    shutil.copytree(ROOT / app, src, ignore=shutil.ignore_patterns("__pycache__"))
    store.update_scan(scan_id, source_path=str(src), db_snapshot_dates=json.dumps({"osv": "2026-10-07", "trivy": "2026-10-07", "nuclei": None}))
    return scan_id, state, config, src


def findings(store, scan_id):
    return {(f.type, f.file, f.line): f for f in store.list_findings(scan_id)}


# --------------------------------------------------------------------------------------------- #
# the whole code stage on the demo apps
# --------------------------------------------------------------------------------------------- #
async def test_every_scanner_contributes_and_independent_tools_corroborate(store, tmp_path):
    scan_id, state, config, _ = full_scan(store, tmp_path)
    out = await run_steps("code", STAGE_STEPS["code"], state, config)
    assert out.get("errors", []) == [] and out.get("steps_skipped", []) == []
    found = findings(store, scan_id)

    dep = found[("vulnerable_dependency", "requirements.txt", 8)]           # requests==2.31.0
    assert dep.state is FindingState.corroborated and json.loads(dep.sources) == ["worker2.osv", "worker2.trivy"]
    assert dep.owasp == "A06" and "requests 2.31.0" in dep.title
    evidence = {e.tool: json.loads(e.payload_json) for e in store.evidence_for(dep.id)}
    assert "GHSA-9wx4-h78v-vm56" in evidence["osv-scanner"]["advisories"] and "CVE-2024-35195" in evidence["trivy"]["advisories"]
    assert "2.32.0" in evidence["osv-scanner"]["fixed_in"]
    assert {e.db_date for e in store.evidence_for(dep.id)} == {"2026-10-07"}   # the snapshot the result depends on

    secret = found[("secret", "app/config.py", 6)]
    assert secret.state is FindingState.corroborated and json.loads(secret.sources) == ["worker2.gitleaks", "worker2.trufflehog"]

    misconfigs = {f.title.split(":")[0] for f in store.list_findings(scan_id) if f.type == "misconfig"}
    assert misconfigs == {"DS-0002", "DS-0026"}                               # runs as root, no HEALTHCHECK

    (inventory,) = [json.loads(e.payload_json) for e in store.list_evidence(scan_id, kind="dependency") if e.tool == "syft"]
    assert {c["name"] for c in inventory["components"]} == {"fastapi", "requests"}  # pinned packages, no file entries


async def test_the_patched_app_is_clean_for_every_scanner(store, tmp_path):
    scan_id, state, config, _ = full_scan(store, tmp_path, app="demo-app-patched")
    out = await run_steps("code", STAGE_STEPS["code"], state, config)
    assert out.get("errors", []) == [] and out.get("steps_skipped", []) == []      # every scanner really ran...
    assert out["steps_run"] == STAGE_STEPS["code"] and store.list_findings(scan_id) == []  # ...and found nothing


async def test_no_secret_value_from_any_scanner_is_stored(store, tmp_path):
    raw = (FIXTURES / "trufflehog_demo.jsonl").read_text(encoding="utf-8")
    assert SECRET_VALUE in raw                                                # the recording does carry it...
    scan_id, state, config, _ = full_scan(store, tmp_path)
    await run_steps("code", STAGE_STEPS["code"], state, config)
    stored = [e.payload_json for e in store.list_evidence(scan_id)] + [f.title for f in store.list_findings(scan_id)]
    assert SECRET_VALUE not in "\n".join(stored)                              # ...none of it reaches the store


async def test_without_staged_databases_osv_and_trivy_are_skipped(store, tmp_path):
    scan_id, state, config, _ = full_scan(store, tmp_path, staged=False)
    out = await run_steps("code", STAGE_STEPS["code"], state, config)
    assert out.get("errors", []) == []
    assert not [f for f in store.list_findings(scan_id) if f.type in ("vulnerable_dependency", "misconfig")]
    assert [c.tool for c in store.list_tool_calls(scan_id) if c.tool in ("osv", "trivy")] == []   # not even attempted


# --------------------------------------------------------------------------------------------- #
# safety: offline only, no secret verification
# --------------------------------------------------------------------------------------------- #
def test_trufflehog_may_never_verify_a_secret(tmp_path):
    assert validate_args("trufflehog", {"path": str(tmp_path)}) == {"path": str(tmp_path), "verify": False}
    with pytest.raises(PolicyError):
        validate_args("trufflehog", {"path": str(tmp_path), "verify": True})


async def test_osv_with_no_dependency_manifest_finds_nothing_without_erroring(tmp_path):
    # TNW-7: a repo with no lockfile makes osv exit non-zero ("No package sources found"); that is
    # "nothing to scan", not a failure
    from aegis.safety.models import ToolCall, ToolResult
    from aegis.workers.code.dependencies import run_osv

    async def osv_no_sources(call: ToolCall):
        return ToolResult(ok=False, tool="osv", exit_code=128, stderr_tail="No package sources found, --help for usage information.")

    controller = type("C", (), {"run": staticmethod(osv_no_sources)})()
    assert await run_osv(controller, "S-1", tmp_path, tmp_path) == []


def test_osv_and_trivy_refuse_to_run_without_an_offline_database(tmp_path):
    for tool in ("osv", "trivy"):
        with pytest.raises(PolicyError, match="not staged"):
            validate_args(tool, {"path": str(tmp_path), "db_dir": str(tmp_path / "missing")})
        assert validate_args(tool, {"path": str(tmp_path), "db_dir": str(tmp_path)})


def test_the_command_lines_never_touch_the_network(tmp_path):
    osv = _osv({"path": str(tmp_path), "db_dir": str(tmp_path)})
    assert {"--offline", "--offline-vulnerabilities", "--no-resolve"} <= set(osv.argv)
    assert osv.env["OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY"] == str(tmp_path.resolve()) and osv.ok_exit_codes == (0, 1)
    trivy = _trivy({"path": str(tmp_path), "db_dir": str(tmp_path)})
    assert {"--skip-db-update", "--skip-java-db-update", "--skip-check-update", "--offline-scan"} <= set(trivy.argv)
    assert trivy.argv[trivy.argv.index("--scanners") + 1] == "vuln,misconfig"
    th = _trufflehog({"path": str(tmp_path)})
    assert {"--no-verification", "--no-update", "--json"} <= set(th.argv)


# --------------------------------------------------------------------------------------------- #
# building blocks
# --------------------------------------------------------------------------------------------- #
def test_osv_results_become_one_record_per_package_version(tmp_path):
    shutil.copy(ROOT / "demo-app" / "requirements.txt", tmp_path / "requirements.txt")
    report = json.loads((FIXTURES / "osv_demo.json").read_text(encoding="utf-8").replace("{ROOT}", str(tmp_path).replace("\\", "\\\\")))
    (row,) = normalize_osv(report, tmp_path)
    assert (row["package"], row["version"], row["manifest"], row["line"]) == ("requests", "2.31.0", "requirements.txt", 8)
    assert {"GHSA-9wx4-h78v-vm56", "CVE-2024-35195"} <= set(row["advisories"]) | set(row["aliases"])


def test_trivy_results_split_into_packages_and_misconfigurations(tmp_path):
    shutil.copy(ROOT / "demo-app" / "requirements.txt", tmp_path / "requirements.txt")
    report = json.loads((FIXTURES / "trivy_demo.json").read_text(encoding="utf-8").replace("{ROOT}", str(tmp_path).replace("\\", "\\\\")))
    vulns, misconfigs = normalize_trivy(report, tmp_path)
    (row,) = vulns
    assert (row["package"], row["line"]) == ("requests", 8) and "CVE-2024-35195" in row["advisories"]
    assert {m["check"] for m in misconfigs} == {"DS-0002", "DS-0026"} and {m["file"] for m in misconfigs} == {"Dockerfile"}


def test_package_lines_follow_python_name_rules(tmp_path):
    (tmp_path / "requirements.txt").write_text("# deps\nPyYAML==5.3\nzope.interface>=5\n", encoding="utf-8")
    assert package_line(tmp_path, "requirements.txt", "pyyaml") == 2
    assert package_line(tmp_path, "requirements.txt", "zope-interface") == 3
    assert package_line(tmp_path, "requirements.txt", "requests") is None


def test_only_safe_trufflehog_fields_survive(tmp_path):
    row = {
        "DetectorName": "AWS", "Raw": "AKIA…", "RawV2": "AKIA…:secret", "Redacted": "AKIA****", "ExtraData": {"k": "v"},
        "SourceMetadata": {"Data": {"Filesystem": {"file": str(tmp_path / "a.py"), "line": 3}}}, "Verified": False,
    }
    (clean,) = clean_results([row], tmp_path)
    assert clean == {"detector": "AWS", "description": "", "file": "a.py", "line": 3, "verified": False}


def test_the_inventory_drops_file_entries():
    sbom = json.loads((FIXTURES / "syft_demo.json").read_text(encoding="utf-8"))
    names = {c["name"] for c in components(sbom)}
    assert names == {"fastapi", "requests"} and not any(c.get("type") == "file" for c in components(sbom))
