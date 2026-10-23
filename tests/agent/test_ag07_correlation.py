"""AG07 — correlate_scan (P9.4): link, merge, score, promote — deterministically."""

from __future__ import annotations

import json
import random

import pytest
from sqlmodel import select

from _corr_helpers import (
    bola_result,
    by_type,
    handler_rows,
    seed_handlers,
    seed_runtime_bac,
    seed_static,
)
from aegis.evidence.adapters.base import EvidenceDraft, FindingDraft
from aegis.evidence.adapters.nuclei import NucleiAdapter
from aegis.evidence.links import linked_to, links_for_scan, merged_ids, visible_findings
from aegis.evidence.models import FindingState, Mode, StateTransition
from aegis.evidence.normalizer import ingest
from aegis.graph.correlator import CORRELATION_THRESHOLD, correlate_scan, load_handlers

pytestmark = pytest.mark.phase("AG07")


@pytest.fixture
def scan(store):
    return store.add_scan(mode="correlated").id


def _demo(store, scan_id):
    """runtime BAC + static findings + handler map, as a Mode 3 scan leaves them."""
    seed_handlers(store, scan_id)
    static = seed_static(store, scan_id)
    runtime = seed_runtime_bac(store, scan_id)
    return runtime, static


# --- the demo flow ------------------------------------------------------------ #
def test_runtime_finding_is_linked_to_the_exact_handler_and_line(store, scan):
    runtime, _ = _demo(store, scan)
    report = correlate_scan(store, scan, load_handlers(store, scan))

    f = store.get_finding(runtime)
    assert (f.file, f.function) == ("app/routes/accounts.py", "get_account")
    assert f.line == 27  # the root-cause line from the static finding, not the def line (22)
    assert f.correlation_score == 1.0
    assert f.state == FindingState.confirmed  # runtime proof is kept, never downgraded
    assert f.mode == Mode.correlated

    (entry,) = report.correlated
    assert entry["finding_id"] == runtime and entry["score"] == 1.0
    assert entry["signals"]["route"] and entry["signals"]["method"] and entry["signals"]["dataflow"]


def test_the_matching_static_finding_is_merged_not_double_counted(store, scan):
    runtime, _ = _demo(store, scan)
    (static_dup,) = [f for f in by_type(store, scan, "broken_access_control") if f.id != runtime]
    correlate_scan(store, scan, load_handlers(store, scan))

    assert merged_ids(store, scan) == {static_dup.id}
    assert linked_to(store, runtime) == [static_dup.id]
    visible = {f.id for f in visible_findings(store, scan)}
    assert runtime in visible and static_dup.id not in visible

    # the static evidence moved to the primary issue; the duplicate keeps nothing
    kinds = sorted(e.kind for e in store.evidence_for(runtime))
    assert kinds == ["code_location", "dataflow_path", "http_exchange"]
    assert store.evidence_for(static_dup.id) == []
    assert sorted(json.loads(store.get_finding(runtime).sources)) == ["worker1.bola", "worker2.semgrep"]


def test_unrelated_static_findings_are_left_alone(store, scan):
    _demo(store, scan)
    correlate_scan(store, scan, load_handlers(store, scan))
    visible_types = {f.type for f in visible_findings(store, scan)}
    assert {"sqli", "weak_crypto", "broken_access_control"} <= visible_types
    sqli = by_type(store, scan, "sqli")[0]
    assert sqli.correlation_score is None and sqli.id not in merged_ids(store, scan)


def test_a_concrete_runtime_route_still_matches_the_declared_template(store, scan):
    seed_handlers(store, scan)
    f = store.add_finding(scan, type="broken_access_control", route="GET /api/accounts/12", state=FindingState.candidate)
    correlate_scan(store, scan, load_handlers(store, scan))
    assert store.get_finding(f.id).function == "get_account"


# --- the same-type rule -------------------------------------------------------- #
def test_a_dataflow_of_another_weakness_does_not_count_or_merge(store, scan):
    seed_handlers(store, scan)
    ingest(store, scan, [(
        FindingDraft(type="sqli", file="app/routes/accounts.py", line=25, source="worker2.semgrep"),
        [EvidenceDraft(kind="dataflow_path", tool="semgrep",
                       payload={"file": "app/routes/accounts.py", "line": 25, "sink": ["cursor.execute", 25]})],
    )])
    runtime = seed_runtime_bac(store, scan)
    report = correlate_scan(store, scan, load_handlers(store, scan))

    assert report.correlated[0]["score"] == 0.7  # route + method only
    assert "dataflow" not in report.correlated[0]["signals"]
    assert merged_ids(store, scan) == set()
    assert {e.kind for e in store.evidence_for(runtime)} == {"http_exchange"}  # nothing foreign pulled in
    assert store.get_finding(runtime).line == 22  # no static root cause -> the handler definition


# --- threshold ------------------------------------------------------------------ #
def test_route_only_links_are_dropped(store, scan):
    rows = [{**handler_rows()[0], "methods": ["POST"]}]  # same route, wrong method -> 0.5
    seed_handlers(store, scan, rows)
    runtime = seed_runtime_bac(store, scan)
    report = correlate_scan(store, scan, load_handlers(store, scan))

    assert report.correlated == [] and report.dropped[0]["best_score"] == 0.5
    f = store.get_finding(runtime)
    assert f.file is None and f.function is None and f.correlation_score is None


def test_the_threshold_is_inclusive_and_configurable(store, scan):
    seed_handlers(store, scan, handler_rows()[:1])
    runtime = seed_runtime_bac(store, scan)
    handlers = load_handlers(store, scan)

    assert correlate_scan(store, scan, handlers, threshold=0.75).correlated == []
    assert store.get_finding(runtime).correlation_score is None
    assert correlate_scan(store, scan, handlers, threshold=CORRELATION_THRESHOLD).correlated[0]["score"] == 0.7


def test_no_handler_map_changes_nothing(store, scan):
    runtime = seed_runtime_bac(store, scan)
    report = correlate_scan(store, scan, [])
    assert report.unmatched == [runtime] and report.correlated == []
    assert store.get_finding(runtime).correlation_score is None


# --- determinism / idempotency ------------------------------------------------- #
def test_running_twice_changes_nothing(store, scan):
    runtime, _ = _demo(store, scan)
    handlers = load_handlers(store, scan)
    correlate_scan(store, scan, handlers)
    snapshot = (
        store.get_finding(runtime).line,
        sorted(e.id for e in store.evidence_for(runtime)),
        len(links_for_scan(store, scan)),
        len(store.list_findings(scan)),
    )
    second = correlate_scan(store, scan, handlers)
    assert second.correlated[0]["score"] == 1.0
    assert snapshot == (
        store.get_finding(runtime).line,
        sorted(e.id for e in store.evidence_for(runtime)),
        len(links_for_scan(store, scan)),
        len(store.list_findings(scan)),
    )


def test_a_rescan_does_not_resurrect_the_merged_duplicate(store, scan):
    runtime, _ = _demo(store, scan)
    handlers = load_handlers(store, scan)
    correlate_scan(store, scan, handlers)
    before = len(store.list_findings(scan))

    seed_static(store, scan)  # Semgrep runs again (e.g. dispatch: request_source_evidence)
    assert len(store.list_findings(scan)) == before  # its fingerprint still finds the merged row
    correlate_scan(store, scan, handlers)
    assert len(store.list_findings(scan)) == before
    assert len(store.evidence_for(runtime)) == 5  # the re-found evidence joins the primary issue
    assert len(links_for_scan(store, scan)) == 1


def test_result_does_not_depend_on_handler_order(store, scan):
    runtime, _ = _demo(store, scan)
    handlers = load_handlers(store, scan)
    shuffled = handlers[:]
    random.Random(7).shuffle(shuffled)
    assert [h.qualname for h in handlers] != [h.qualname for h in shuffled]
    first = correlate_scan(store, scan, shuffled).correlated
    store.update_finding_fields(runtime, function=None, file=None, line=None, correlation_score=None)
    assert correlate_scan(store, scan, handlers).correlated[0]["handler"] == first[0]["handler"]


def test_equal_scores_break_ties_by_qualname(store, scan):
    rows = [
        {**handler_rows()[0], "qualname": "app/b.py::get_account", "file": "app/b.py", "function": "get_account"},
        {**handler_rows()[0], "qualname": "app/a.py::get_account", "file": "app/a.py", "function": "get_account"},
    ]
    seed_handlers(store, scan, rows)
    runtime = seed_runtime_bac(store, scan)
    correlate_scan(store, scan, load_handlers(store, scan))
    assert store.get_finding(runtime).file == "app/a.py"


# --- state ---------------------------------------------------------------------- #
def test_correlation_never_confirms_a_candidate(store, scan):
    rows = handler_rows()
    seed_handlers(store, scan, rows)
    # a Nuclei match is one tool signal: a candidate, even though its evidence is an http_exchange
    nuclei = [{"template-id": "http-missing-security-headers", "info": {"name": "Missing headers", "severity": "info"},
               "matched-at": "http://demo-app:5000/api/accounts"}]
    (fid,) = ingest(store, scan, NucleiAdapter(mode="runtime").parse(nuclei, scan))
    correlate_scan(store, scan, load_handlers(store, scan))
    assert store.get_finding(fid).state == FindingState.candidate  # linked, not confirmed
    assert store.get_finding(fid).function == "list_accounts"


def test_a_second_independent_layer_corroborates(store, scan):
    seed_handlers(store, scan)
    nuclei = [{"template-id": "x", "info": {"name": "Misconfigured", "severity": "low"},
               "matched-at": "http://demo-app:5000/api/accounts"}]
    (runtime,) = ingest(store, scan, NucleiAdapter(mode="runtime").parse(nuclei, scan))
    (static,) = ingest(store, scan, [(
        FindingDraft(type="misconfig", file="app/routes/accounts.py", line=16, source="worker2.trivy"),
        [EvidenceDraft(kind="code_location", tool="trivy", payload={"file": "app/routes/accounts.py", "line": 16})],
    )])
    correlate_scan(store, scan, load_handlers(store, scan))

    assert store.get_finding(runtime).state == FindingState.corroborated
    assert static in merged_ids(store, scan)
    with store.session() as s:
        moves = list(s.exec(select(StateTransition).where(StateTransition.finding_id == runtime)))
    assert [(t.from_state, t.to_state, t.actor) for t in moves] == [("candidate", "corroborated", "correlator")]


def test_confirmed_findings_are_never_demoted_or_retransitioned(store, scan):
    runtime, _ = _demo(store, scan)
    correlate_scan(store, scan, load_handlers(store, scan))
    with store.session() as s:
        rows = list(s.exec(select(StateTransition).where(StateTransition.finding_id == runtime)))
    assert [t.to_state for t in rows] == ["confirmed"]  # only the worker's own confirmation


# --- loaders -------------------------------------------------------------------- #
def test_malformed_handler_evidence_is_skipped_not_fatal(store, scan):
    store.add_evidence(scan, kind="code_location", tool="treesitter", payload={"role": "route_handler", "path": "/x"})
    store.add_evidence(scan, kind="code_location", tool="semgrep", payload={"file": "a.py", "line": 1})  # not a handler
    seed_handlers(store, scan, handler_rows()[:1])
    handlers = load_handlers(store, scan)
    assert [h.function for h in handlers] == ["get_account"]
    assert handlers[0].evidence_id is not None and handlers[0].end_line == 30
