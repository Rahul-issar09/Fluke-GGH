"""RAG09 — the rules/keyword query router (no model)."""

from __future__ import annotations

import pytest

from aegis.chat.router import route

pytestmark = pytest.mark.phase("RAG09")

SCAN = "S-0001"


@pytest.mark.parametrize("question, path", [
    ("how many critical findings?", "structured"),
    ("count the vulnerable dependencies", "structured"),
    ("number of A03 issues", "structured"),
    ("list the A01 issues", "structured"),
    ("show me all ssrf findings", "structured"),
    ("which findings are confirmed?", "structured"),
    ("what's in auth.py?", "structured"),
    ("are there any secrets?", "structured"),
    ("A01", "structured"),
    ("sqli", "structured"),
    ("why is the account leak a risk?", "explain"),
    ("explain the sql injection simply", "explain"),
    ("is it serious?", "explain"),
    ("how do I fix the secret?", "explain"),
    ("what does broken access control mean?", "explain"),
    ("tell me about get_account", "explain"),
    ("how does the ssrf work?", "explain"),
])
def test_routing_table(question, path):
    assert route(question, SCAN).path == path


def test_every_decision_carries_the_scan_id():
    assert route("anything at all", SCAN).filter.scan_id == SCAN


def test_owasp_code_is_parsed():
    f = route("list A03 issues", SCAN).filter
    assert f.owasp == "A03"
    assert route("show A10 ssrf", SCAN).filter.owasp == "A10"


def test_severity_words_become_a_minimum():
    assert route("how many critical findings", SCAN).filter.severity_min == 0.9
    assert route("list high severity issues", SCAN).filter.severity_min == 0.7
    assert route("any low findings?", SCAN).filter.severity_min == 0.3


def test_type_keywords_map_to_finding_types():
    assert route("list sql injection findings", SCAN).filter.type == "sqli"
    assert route("show broken access control", SCAN).filter.type == "broken_access_control"
    assert route("any vulnerable dependencies?", SCAN).filter.type == "vulnerable_dependency"
    assert route("list the secrets", SCAN).filter.type == "secret"


def test_count_flag_is_set_only_for_counting_questions():
    assert route("how many criticals?", SCAN).filter.count is True
    assert route("list criticals", SCAN).filter.count is False


def test_file_and_function_and_route_parsed():
    assert route("what's in app/routes/accounts.py?", SCAN).filter.file == "app/routes/accounts.py"
    assert route("tell me about get_account", SCAN).filter.function == "get_account"
    assert route("show findings on /api/accounts", SCAN).filter.route == "/api/accounts"


def test_an_explain_question_keeps_its_parsed_filter_for_scoping():
    d = route("why is the sqli in users.py exploitable?", SCAN)
    assert d.path == "explain" and d.filter.type == "sqli" and d.filter.file == "users.py"


def test_a_plain_question_with_no_cues_defaults_to_explain():
    d = route("accounts", SCAN)
    assert d.path == "explain" and d.filter.owasp is None and d.filter.type is None


def test_structured_beats_nothing_but_explain_cue_wins_over_a_filter():
    # has a type keyword (would be structured) but also an explain cue → explain
    assert route("explain the ssrf", SCAN).path == "explain"
    # a listing cue with a type → structured
    assert route("list the ssrf findings", SCAN).path == "structured"


def test_deterministic():
    q = "how many high severity A01 findings in auth.py are confirmed?"
    a, b = route(q, SCAN), route(q, SCAN)
    assert a.model_dump() == b.model_dump()
