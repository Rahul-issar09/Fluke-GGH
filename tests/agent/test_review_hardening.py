"""Review hardening (2026-10-08): dependency remediation, runtime coverage, evidence-based risk,
and the LLM-claim safety guard. Each section maps to one item of the review request.

Default tests only (scripted model / seeded store / in-process demo network); no GPU, no real binaries.
"""

from __future__ import annotations

import json

import httpx
import pytest

import aegis.agent.nodes.runtime_subgraph  # noqa: F401 - registers the runtime steps
from _graph_helpers import make_run
from aegis.agent.nodes.remediate import remediate
from aegis.agent.nodes.worker_stage import run_steps
from aegis.agent.validator import unsupported_strong_claim, validate_claims
from aegis.agent.schemas import Claim
from aegis.evidence.models import Mode
from aegis.fix.draft import choose_fixed_version, dependency_recommendation, requirements_upgrade_diff
from aegis.reports.json_report import build_json_report
from aegis.risk import factors
from aegis.risk.engine import load_severity, score_finding
from aegis.workers.runtime import coverage
from fakes.demo_apps import ROOT
from fakes.tool_executors import fix_executor

pytestmark = pytest.mark.phase("REVIEW")


# =============================================================================================== #
# 3. RISK — evidence-based severity for dependencies (no more identical 0.101 for every CVE)
# =============================================================================================== #
def _dep_finding(store, scan_id, version, severities, *, state="corroborated", package="lib"):
    f = store.add_finding(scan_id, type="vulnerable_dependency", file="requirements.txt", line=1, source="worker2.osv")
    store.add_evidence(scan_id, "dependency", "osv-scanner", finding_id=f.id, payload={
        "package": package, "version": version, "advisories": ["CVE-x"], "fixed_in": ["9.9.9"], "severities": severities,
    })
    return store.get_finding(f.id)  # left as candidate: equal confidence isolates the severity factor


def test_dependency_risk_follows_the_advisory_severity_and_is_reproducible(store):
    scan = store.add_scan(mode="code").id
    table = load_severity()

    def risk(version, labels):
        f = _dep_finding(store, scan, version, labels, package=f"p{version}")
        ev = store.evidence_for(f.id)
        return score_finding(f, ev, None, sensitive_routes=(), severity_table=table)

    critical = risk("1.0", ["CRITICAL"])
    low = risk("2.0", ["LOW"])
    none = risk("3.0", [])
    assert critical.severity == 0.9 and low.severity == 0.3 and none.severity == 0.7   # class default when no label
    assert critical.risk > low.risk                                                    # not all the same any more
    # deterministic: identical evidence → identical score, recomputable by hand from the factors
    again = risk("1.0", ["CRITICAL"])
    assert again.risk == critical.risk
    from aegis.risk.engine import compute_risk
    assert critical.risk == compute_risk(0.9, critical.confidence, critical.exploitability, critical.exposure, critical.criticality, critical.path_factor)


def test_dependency_severity_takes_the_highest_label_present(store):
    scan = store.add_scan(mode="code").id
    f = _dep_finding(store, scan, "1.0", ["LOW", "CRITICAL", "MEDIUM"])
    assert factors.dependency_severity(store.evidence_for(f.id), default=0.7) == 0.9


def test_an_unknown_severity_label_falls_back_to_the_class_default(store):
    scan = store.add_scan(mode="code").id
    f = _dep_finding(store, scan, "1.0", ["BOGUS"])
    assert factors.dependency_severity(store.evidence_for(f.id), default=0.7) == 0.7


# =============================================================================================== #
# 1. REMEDIATION — an evidence-backed upgrade recommendation for a vulnerable dependency
# =============================================================================================== #
def test_choose_fixed_version_is_the_lowest_published_fix_and_never_invented():
    assert choose_fixed_version("2.31.0", ["2.32.4", "2.34.2", "2.33.0"]) == "2.32.4"
    assert choose_fixed_version("1.23.2", ["1.23.3"]) == "1.23.3"
    assert choose_fixed_version("1.0", []) is None                       # nothing published → no version invented


def test_the_recommendation_uses_only_the_published_fixed_versions():
    text, chosen = dependency_recommendation("@remix-run/router", "1.23.2", ["1.23.3"], ["CVE-2026-1"])
    assert chosen == "1.23.3" and "1.23.3" in text and "CVE-2026-1" in text
    text2, chosen2 = dependency_recommendation("leftpad", "1.0", [], ["CVE-y"])
    assert chosen2 is None and "No fixed version" in text2               # honest when no fix exists


async def _dep_scan(store, tmp_path, *, manifest, line, version="2.31.0", fixed=("2.32.4",), severities=("HIGH",)):
    scan_id, state, config = make_run(store, tmp_path, Mode.code, tool_executor=fix_executor)
    src = tmp_path / "scan"
    (src / manifest).parent.mkdir(parents=True, exist_ok=True)
    if manifest == "requirements.txt":
        (src / manifest).write_text(f"flask\nrequests=={version}\n", encoding="utf-8", newline="\n")
    else:
        (src / manifest).write_text('{"name":"demo","dependencies":{"requests":"' + version + '"}}\n', encoding="utf-8", newline="\n")
    store.update_scan(scan_id, source_path=str(src))
    f = store.add_finding(scan_id, type="vulnerable_dependency", file=manifest, line=line, source="worker2.osv")
    store.add_evidence(scan_id, "dependency", "osv-scanner", finding_id=f.id, payload={
        "package": "requests", "version": version, "advisories": ["CVE-2026-1"], "fixed_in": list(fixed), "severities": list(severities),
    })
    return dict(store=store, scan=scan_id, state=state, config=config, finding=f.id)


async def test_a_pinned_requirement_gets_a_verifiable_upgrade_diff(store, tmp_path):
    w = await _dep_scan(store, tmp_path, manifest="requirements.txt", line=2)
    await remediate(w["state"], w["config"])
    (attempt,) = store.list_fix_attempts(w["finding"])
    draft = json.loads(attempt.verify_report_json)["draft"]
    assert draft["method"] == "dependency-upgrade" and draft["chosen_version"] == "2.32.4"
    assert "-requests==2.31.0" in attempt.diff and "+requests==2.32.4" in attempt.diff
    assert "Upgrade requests 2.31.0 to 2.32.4" in draft["description"]


async def test_a_lockfile_style_manifest_gets_a_recommendation_but_no_unsafe_diff(store, tmp_path):
    w = await _dep_scan(store, tmp_path, manifest="package.json", line=1)
    await remediate(w["state"], w["config"])
    (attempt,) = store.list_fix_attempts(w["finding"])
    draft = json.loads(attempt.verify_report_json)["draft"]
    assert draft["method"] == "recommendation" and attempt.diff == ""      # not repinned blindly
    assert draft["chosen_version"] == "2.32.4" and "Upgrade requests" in draft["description"]


async def test_no_published_fix_is_an_honest_recommendation_not_a_blank_no_fix(store, tmp_path):
    w = await _dep_scan(store, tmp_path, manifest="requirements.txt", line=2, fixed=())
    await remediate(w["state"], w["config"])
    (attempt,) = store.list_fix_attempts(w["finding"])
    draft = json.loads(attempt.verify_report_json)["draft"]
    assert draft["chosen_version"] is None and "No fixed version" in draft["description"]


# =============================================================================================== #
# 4. EVIDENCE / LLM SAFETY — no RCE / data-theft claims unless the evidence establishes them
# =============================================================================================== #
def _claim(text, field="impact", ev="E-1"):
    return Claim(field=field, text=text, evidence_ids=[ev])


class _FakeStore:
    def get_evidence(self, _id):  # every cited id is treated as existing & citable here
        return object()


@pytest.mark.parametrize("text", [
    "An attacker can achieve remote code execution on the server.",
    "This allows arbitrary code execution.",
    "An attacker gains unauthorized access to other accounts.",
    "The flaw lets an attacker exfiltrate the database.",
])
def test_strong_exploit_claims_are_dropped_when_exploitability_is_not_established(text):
    assert unsupported_strong_claim(text, exploit_established=False)
    verdicts = validate_claims([_claim(text)], finding_id="F-1", allowed_evidence_ids={"E-1"}, store=_FakeStore(), exploit_established=False)
    assert verdicts[0].kept is False and any("does not establish" in r for r in verdicts[0].reasons)


def test_the_same_strong_claim_is_allowed_once_evidence_establishes_exploitability():
    text = "An attacker can achieve remote code execution on the server."
    assert unsupported_strong_claim(text, exploit_established=True) is None
    verdicts = validate_claims([_claim(text)], finding_id="F-1", allowed_evidence_ids={"E-1"}, store=_FakeStore(), exploit_established=True)
    assert verdicts[0].kept is True


def test_conservative_dependency_wording_is_kept():
    text = "The known weakness may be reachable through the application, with the library's own impact."
    verdicts = validate_claims([_claim(text)], finding_id="F-1", allowed_evidence_ids={"E-1"}, store=_FakeStore(), exploit_established=False)
    assert verdicts[0].kept is True


def test_what_counts_as_exploit_established():
    from types import SimpleNamespace

    from aegis.agent.validator import exploit_established

    dep = SimpleNamespace(state="candidate", exploitability=0.3)          # only the version is known
    assert exploit_established(dep) is False
    dataflow = SimpleNamespace(state="candidate", exploitability=0.5)     # a traced flow to the sink
    assert exploit_established(dataflow) is True
    confirmed = SimpleNamespace(state="confirmed", exploitability=1.0)    # runtime-proven
    assert exploit_established(confirmed) is True


# =============================================================================================== #
# 2. RUNTIME COVERAGE — a clean result is not a clean bill of health
# =============================================================================================== #
def test_coverage_summary_and_limited_flag(store):
    scan = store.add_scan(mode="runtime").id
    coverage.record(store, scan, "discovery", coverage.BLOCKED, "the API description was refused (HTTP 403)")
    coverage.record(store, scan, "access_control", coverage.NOT_TESTED, "no routes")
    coverage.record(store, scan, "tls", coverage.PASS, "checked")
    rows = coverage.summarize(store, scan)
    statuses = {r["capability"]: r["status"] for r in rows}
    assert statuses == {"discovery": "BLOCKED", "access_control": "NOT_TESTED", "tls": "PASS"}
    assert coverage.is_limited(rows) is True
    assert [r["capability"] for r in rows] == ["discovery", "access_control", "tls"]   # report order


def test_the_latest_status_per_capability_wins(store):
    scan = store.add_scan(mode="runtime").id
    coverage.record(store, scan, "discovery", coverage.NOT_TESTED, "no spec")
    coverage.record(store, scan, "discovery", coverage.PASS, "found by crawling")
    assert {r["capability"]: r["status"] for r in coverage.summarize(store, scan)} == {"discovery": "PASS"}


def test_the_report_carries_coverage_and_the_limited_note(store, tmp_path):
    scan = store.add_scan(mode="runtime", status="completed", target_url="https://example.com").id
    coverage.record(store, scan, "discovery", coverage.BLOCKED, "HTTP 403")
    coverage.record(store, scan, "access_control", coverage.PASS, "compared 2 objects")
    report = build_json_report(store, scan, data_dir=tmp_path)
    caps = {r["capability"]: r["status"] for r in report["runtime_coverage"]}
    assert caps == {"discovery": "BLOCKED", "access_control": "PASS"}
    assert report["runtime_coverage_note"] and "coverage was limited" in report["runtime_coverage_note"]


def test_full_coverage_has_no_limited_note(store, tmp_path):
    scan = store.add_scan(mode="runtime", status="completed", target_url="https://example.com").id
    coverage.record(store, scan, "discovery", coverage.PASS, "ok")
    coverage.record(store, scan, "access_control", coverage.FAILED, "a bug was found")
    report = build_json_report(store, scan, data_dir=tmp_path)
    assert report["runtime_coverage_note"] is None                         # PASS + FAILED are both "covered"


async def test_a_403_on_the_api_description_is_blocked_coverage_not_a_silent_pass(store, tmp_path):
    scan_id, state, config = make_run(store, tmp_path, Mode.runtime, tool_executor=fix_executor)

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path in ("/openapi.json", "/swagger.json"):
            return httpx.Response(403, json={"detail": "forbidden"})
        return httpx.Response(200, json={"status": "ok"})

    config["configurable"]["deps"].http_transport = httpx.MockTransport(handler)
    out = await run_steps("runtime", ["validate_target", "discover_routes"], state, config)
    assert out.get("errors", []) == []
    (row,) = [r for r in coverage.summarize(store, scan_id) if r["capability"] == "discovery"]
    assert row["status"] == "BLOCKED" and "403" in row["detail"]
