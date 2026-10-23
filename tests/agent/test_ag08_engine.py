"""AG08 — severity table (P10.1), formula + scoring + ranking (P10.3)."""

from __future__ import annotations

import ast
import json
import random

import pytest
import yaml

from _corr_helpers import FIXTURES, seed_handlers, seed_runtime_bac, seed_static
from aegis.evidence import state_machine
from aegis.evidence.adapters.base import EvidenceDraft, FindingDraft
from aegis.evidence.adapters.bola import BolaAdapter
from aegis.evidence.adapters.gitleaks import GitleaksAdapter
from aegis.evidence.adapters.nuclei import NucleiAdapter
from aegis.evidence.adapters.schemathesis import SchemathesisAdapter
from aegis.evidence.adapters.semgrep import SemgrepAdapter, _RULE_MAP
from aegis.evidence.adapters.ssrf import SsrfAdapter
from aegis.evidence.links import merged_ids
from aegis.evidence.models import FindingState
from aegis.evidence.normalizer import ingest
from aegis.graph.correlator import build_graph, correlate_scan, load_handlers
from aegis.risk.engine import (
    KMAX,
    RISK_FORMULA,
    SeverityTable,
    compute_risk,
    load_severity,
    rank_findings,
    risk_breakdown,
    score_scan,
)
from fakes.demo_apps import ROOT

pytestmark = pytest.mark.phase("AG08")

SENSITIVE = ("/api/accounts", "/admin")


# --- P10.1 severity table ----------------------------------------------------- #
def _emitted_types() -> set[str]:
    """Every finding type the adapters can produce today."""
    types = {t for t, _, _ in _RULE_MAP.values()}
    raw_semgrep = json.loads((FIXTURES / "tools" / "semgrep.json").read_text(encoding="utf-8"))
    raw_semgrep["results"].append({"check_id": "some.unmapped.rule", "path": "x.py", "start": {"line": 1}, "extra": {}})
    types |= {d.type for d, _ in SemgrepAdapter().parse(raw_semgrep, "S-1")}
    raw_gitleaks = json.loads((FIXTURES / "tools" / "gitleaks.json").read_text(encoding="utf-8"))
    types |= {d.type for d, _ in GitleaksAdapter().parse(raw_gitleaks, "S-1")}
    bola = {"route": "GET /x", "baseline": {"identity": "A", "status": 200}, "replay": {"identity": "B", "status": 200}, "vulnerable": True}
    types |= {d.type for d, _ in BolaAdapter().parse([bola], "S-1")}
    ssrf = {"route": "GET /x", "param": "url", "test_input_id": "SSRF-CB-001", "vulnerable": True}
    types |= {d.type for d, _ in SsrfAdapter().parse([ssrf], "S-1")}
    nuclei = [json.loads(l) for l in (FIXTURES / "tools" / "nuclei_sample.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]
    types |= {d.type for d, _ in NucleiAdapter().parse(nuclei, "S-1")}
    junit = {"junit_xml": (FIXTURES / "tools" / "schemathesis_junit_authed.xml").read_text(encoding="utf-8")}
    types |= {d.type for d, _ in SchemathesisAdapter().parse(junit, "S-1")}
    return types


def test_every_type_the_adapters_emit_has_an_explicit_weight():
    emitted = _emitted_types()
    assert {"broken_access_control", "sqli", "weak_crypto", "secret", "ssrf", "misconfig", "api_conformance", "code_issue"} <= emitted
    assert emitted <= set(load_severity().types), emitted - set(load_severity().types)


def test_weights_follow_the_documented_table():
    t = load_severity().types
    assert (t["broken_access_control"], t["sqli"], t["ssrf"], t["secret"]) == (0.9, 0.9, 0.8, 0.8)
    assert (t["weak_crypto"], t["vulnerable_dependency"], t["misconfig"]) == (0.6, 0.7, 0.4)


def test_all_weights_are_within_the_allowed_range():
    table = load_severity()
    assert all(0.1 <= v <= 1.0 for v in [table.default, *table.types.values()])


def test_an_unlisted_type_falls_back_to_the_default():
    assert load_severity().for_type("something_new") == load_severity().default == 0.5


def test_an_out_of_range_weight_is_rejected(tmp_path):
    bad = tmp_path / "severity.yaml"
    bad.write_text(yaml.safe_dump({"default": 0.5, "types": {"x": 1.5}}), encoding="utf-8")
    with pytest.raises(ValueError, match="outside"):
        load_severity(bad)


def test_unmapped_semgrep_rules_share_one_bounded_type_but_stay_distinct_findings(store):
    scan = store.add_scan(mode="code")
    raw = {"results": [
        {"check_id": "rule.one", "path": "a.py", "start": {"line": 3}, "extra": {"message": "one"}},
        {"check_id": "rule.two", "path": "a.py", "start": {"line": 3}, "extra": {"message": "two"}},
    ]}
    ingest(store, scan.id, SemgrepAdapter().parse(raw, scan.id))
    findings = store.list_findings(scan.id)
    assert {f.type for f in findings} == {"code_issue"} and len(findings) == 2


# --- P10.3 formula -------------------------------------------------------------- #
@pytest.mark.parametrize(
    "args,expected",
    [
        ((0.9, 1.0, 1.0, 0.6, 1.0, 0.8), 0.792),   # the demo bug: PHASES P10.3
        ((0.9, 1.0, 1.0, 1.0, 1.0, 0.8), 0.864),   # the PRD's illustration (exposure 1.0) — conflict C7
        ((1.0, 1.0, 1.0, 1.0, 1.0, 1.0), 1.0),     # the ceiling
        ((0.1, 0.4, 0.3, 0.2, 0.3, 0.0), 0.014),   # a floor-ish case, rounded to 3 places
        ((0.9, 0.0, 1.0, 1.0, 1.0, 1.0), 0.0),     # no confidence, no risk
        ((0.8, 1.0, 1.0, 0.6, 0.3, 0.0), 0.464),
    ],
)
def test_formula_matches_hand_calculation(args, expected):
    assert compute_risk(*args) == expected
    sev, conf, e, x, c, p = args
    assert compute_risk(*args) == round(sev * conf * (1 + e + x + c + p) / 5, 3)


def test_kmax_is_the_maximum_of_the_bracket():
    assert KMAX == 5.0 and compute_risk(1, 1, 1, 1, 1, 1) == 1.0


def test_risk_always_lies_in_zero_one_and_inputs_are_clamped():
    rng = random.Random(2026)
    for _ in range(500):
        args = [rng.uniform(-1, 2) for _ in range(6)]
        assert 0.0 <= compute_risk(*args) <= 1.0
    assert compute_risk(9, 9, 9, 9, 9, 9) == 1.0


# --- scoring a real (seeded) scan ----------------------------------------------- #
@pytest.fixture
def scored(store):
    """The Mode 3 situation after correlation, then scored."""
    scan = store.add_scan(mode="correlated").id
    seed_handlers(store, scan)
    seed_static(store, scan)
    runtime = seed_runtime_bac(store, scan)
    handlers = load_handlers(store, scan)
    correlate_scan(store, scan, handlers)
    graph = build_graph(store, scan, handlers)
    results = score_scan(store, scan, graph, sensitive_routes=SENSITIVE)
    return store, scan, runtime, results


def test_the_demo_bug_scores_0_792_with_every_factor_stored(scored):
    store, _, runtime, results = scored
    f = store.get_finding(runtime)
    assert (f.severity, f.exploitability, f.exposure, f.criticality, f.path_factor) == (0.9, 1.0, 0.6, 1.0, 0.8)
    assert f.risk == 0.792 == results[runtime].risk
    assert f.risk == round(0.9 * 1.0 * (1 + 1.0 + 0.6 + 1.0 + 0.8) / 5, 3)  # the by-hand check


def test_static_findings_get_lower_confidence_and_pattern_factors(scored):
    store, scan, _, _ = scored
    (sqli,) = [f for f in store.list_findings(scan) if f.type == "sqli"]
    # candidate (0.4), dataflow (0.5), on an endpoint handler (0.6), "users" file (0.7), no sensitive path (0)
    assert (sqli.exploitability, sqli.exposure, sqli.criticality, sqli.path_factor) == (0.5, 0.6, 0.7, 0.0)
    assert sqli.risk == round(0.9 * 0.4 * (1 + 0.5 + 0.6 + 0.7 + 0.0) / 5, 3) == 0.202

    (crypto,) = [f for f in store.list_findings(scan) if f.type == "weak_crypto"]
    # pattern-only (0.3), not on any endpoint (0.2: internal), "auth" file (0.7)
    assert (crypto.exploitability, crypto.exposure, crypto.criticality, crypto.path_factor) == (0.3, 0.2, 0.7, 0.0)
    assert crypto.risk == round(0.6 * 0.4 * (1 + 0.3 + 0.2 + 0.7 + 0.0) / 5, 3) == 0.106


def test_merged_duplicates_are_not_scored(scored):
    store, scan, runtime, results = scored
    (duplicate,) = merged_ids(store, scan)
    assert duplicate not in results and store.get_finding(duplicate).risk == 0.0


def test_scoring_is_idempotent(scored):
    store, scan, _, results = scored
    handlers = load_handlers(store, scan)
    again = score_scan(store, scan, build_graph(store, scan, handlers), sensitive_routes=SENSITIVE)
    assert again == results


def test_stronger_evidence_raises_the_risk_of_the_same_weakness(scored):
    store, scan, _, _ = scored
    (sqli,) = [f for f in store.list_findings(scan) if f.type == "sqli"]
    before = sqli.risk
    extra = store.add_evidence(scan, "code_location", "trivy", payload={"file": "app/routes/users.py", "line": 42}, finding_id=sqli.id)
    state_machine.transition(store, sqli.id, "corroborated", evidence_ids=[extra.id], actor="rule")
    handlers = load_handlers(store, scan)
    score_scan(store, scan, build_graph(store, scan, handlers), sensitive_routes=SENSITIVE)
    after = store.get_finding(sqli.id)
    assert after.state == FindingState.corroborated and after.risk > before
    assert after.risk == round(0.9 * 0.7 * (1 + 0.5 + 0.6 + 0.7 + 0.0) / 5, 3)


# --- ranking ---------------------------------------------------------------------- #
def test_the_demo_bug_is_ranked_first(scored):
    store, scan, runtime, _ = scored
    ranked = rank_findings(store, scan)
    assert ranked[0].id == runtime
    assert [f.risk for f in ranked] == sorted((f.risk for f in ranked), reverse=True)


def test_merged_duplicates_are_not_ranked(scored):
    store, scan, runtime, _ = scored
    (duplicate,) = merged_ids(store, scan)
    assert duplicate not in {f.id for f in rank_findings(store, scan)}


def test_resolved_findings_leave_the_ranking_but_keep_their_score(scored):
    store, scan, runtime, _ = scored
    retest = store.add_evidence(scan, "retest", "bola", payload={"passed": True}, finding_id=runtime)
    state_machine.transition(store, runtime, "resolved", evidence_ids=[retest.id], actor="verifier")
    ranked = {f.id for f in rank_findings(store, scan)}
    assert runtime not in ranked
    assert store.get_finding(runtime).risk == 0.792  # the record stays complete


def test_ties_break_by_severity_then_id(store):
    scan = store.add_scan(mode="code").id
    a = store.add_finding(scan, type="x", risk=0.5, severity=0.4)
    b = store.add_finding(scan, type="x", risk=0.5, severity=0.9)
    c = store.add_finding(scan, type="x", risk=0.5, severity=0.9)
    assert [f.id for f in rank_findings(store, scan)] == [b.id, c.id, a.id]


# --- the printed formula ------------------------------------------------------------ #
def test_breakdown_prints_a_formula_a_reviewer_can_recompute(scored):
    store, _, runtime, _ = scored
    breakdown = risk_breakdown(store.get_finding(runtime))
    assert breakdown["formula"] == RISK_FORMULA and "/ 5" in breakdown["formula"]
    assert breakdown["expression"] == "0.9 × 1 × (1 + 1 + 0.6 + 1 + 0.8) / 5 = 0.792"
    assert breakdown["risk"] == 0.792
    assert breakdown["factors"] == {
        "severity": 0.9, "confidence": 1.0, "exploitability": 1.0,
        "exposure": 0.6, "criticality": 1.0, "path_factor": 0.8,
    }


# --- structural guarantee -------------------------------------------------------------- #
def test_risk_package_is_deterministic_and_llm_free():
    banned = ("langchain", "aegis.agent", "aegis.chat", "random", "ollama", "httpx", "requests", "time")
    for py in (ROOT / "aegis" / "risk").glob("*.py"):
        tree = ast.parse(py.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            names = [a.name for a in node.names] if isinstance(node, ast.Import) else (
                [node.module] if isinstance(node, ast.ImportFrom) and node.module else [])
            for name in names:
                assert not any(name == b or name.startswith(b + ".") for b in banned), f"{py.name} imports {name}"
