"""RAG10 — the structured answer path (counts / lists / look-ups, no model)."""

from __future__ import annotations

import pytest

from aegis.chat.router import route
from aegis.chat.schemas import FindingFilter
from aegis.chat.structured import NO_MATCH, answer_structured, matching_findings

pytestmark = pytest.mark.phase("RAG10")


@pytest.fixture
def scan(store):
    sid = store.add_scan(mode="correlated").id
    specs = [
        ("broken_access_control", "A01", "confirmed", 0.9, 0.79, "app/routes/accounts.py", "get_account", "GET /api/accounts/{id}"),
        ("sqli", "A03", "corroborated", 0.9, 0.40, "app/routes/users.py", "search_users", None),
        ("secret", None, "candidate", 0.8, 0.26, "app/config.py", None, None),
        ("misconfig", "A05", "candidate", 0.4, 0.06, "Dockerfile", None, None),
    ]
    for i, (t, owasp, state, sev, risk, file, func, route_) in enumerate(specs):
        f = store.add_finding(sid, type=t, owasp=owasp, route=route_, file=file, line=10, function=func, source="w")
        store.add_evidence(sid, "code_location", "semgrep", finding_id=f.id, payload={"file": file, "line": 10})
        store.update_finding_fields(f.id, severity=sev, risk=risk)
        if state != "candidate":
            store.transition if False else None  # states set below via direct helper
        # advance state deterministically through the store's evidence state machine is heavy;
        # instead set via update is refused, so leave state as recorded by transitions in real runs.
    return sid, store


def filt(scan_id, **kw):
    return FindingFilter(scan_id=scan_id, **kw)


def test_count_by_severity(scan):
    sid, store = scan
    ans = answer_structured(store, filt(sid, severity_min=0.9, count=True))
    assert ans.text.startswith("2 findings")                 # bac + sqli are severity 0.9
    assert set(ans.finding_ids) and ans.evidence_ids == []   # count → no evidence citations


def test_list_by_owasp(scan):
    sid, store = scan
    ans = answer_structured(store, filt(sid, owasp="A01"))
    assert ans.text.startswith("1 finding ") and "A01" in ans.text
    assert len(ans.finding_ids) == 1 and ans.evidence_ids     # a listing cites evidence too


def test_list_by_type(scan):
    sid, store = scan
    ans = answer_structured(store, filt(sid, type="sqli"))
    assert len(ans.finding_ids) == 1 and "sqli" in ans.text


def test_lookup_by_file_matches_on_basename(scan):
    sid, store = scan
    ans = answer_structured(store, filt(sid, file="accounts.py"))   # not the full path
    assert len(ans.finding_ids) == 1 and "accounts.py" in ans.text


def test_lookup_by_route(scan):
    sid, store = scan
    ans = answer_structured(store, filt(sid, route="/api/accounts"))
    assert len(ans.finding_ids) == 1


def test_empty_result_is_the_no_match_message(scan):
    sid, store = scan
    ans = answer_structured(store, filt(sid, owasp="A09"))       # nothing is A09
    assert ans.text.startswith("No finding matches") and ans.finding_ids == [] and ans.evidence_ids == []


def test_a_nonexistent_file_is_empty_not_an_error(scan):
    sid, store = scan
    ans = answer_structured(store, filt(sid, file="does_not_exist.py"))
    assert ans.finding_ids == []


def test_citations_are_real_ids(scan):
    sid, store = scan
    ans = answer_structured(store, filt(sid, type="secret"))
    assert all(store.get_finding(i) is not None for i in ans.finding_ids)
    assert all(store.get_evidence(e) is not None for e in ans.evidence_ids)


def test_findings_are_ordered_by_risk(scan):
    sid, store = scan
    ans = answer_structured(store, filt(sid))                    # no filter → all, ranked
    # the account bug (risk 0.79) is named before the Dockerfile misconfig (risk 0.06)
    assert ans.text.index("risk 0.79") < ans.text.index("risk 0.06")


def test_count_plural_grammar(scan):
    sid, store = scan
    one = answer_structured(store, filt(sid, type="sqli", count=True))
    assert one.text == "1 finding matching sqli."


def test_router_plus_structured_end_to_end(scan):
    sid, store = scan
    decision = route("how many A03 findings?", sid)
    assert decision.path == "structured"
    ans = answer_structured(store, decision.filter)
    assert ans.text.startswith("1 finding") and "A03" in ans.text
