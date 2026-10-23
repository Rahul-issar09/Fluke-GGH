"""AG10.1 — the deterministic parts of an explanation: where, templates, 5-part assembly."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from aegis.agent.explanation import EXPLAIN_FIELDS, TEMPLATES, five_parts, render_where, template_claims
from aegis.agent.schemas import Claim
from aegis.evidence.models import Finding, FindingState
from aegis.risk.engine import load_severity

pytestmark = pytest.mark.phase("AG10")


def finding(**kw) -> Finding:
    base = dict(id="F-0001", scan_id="S-0001", type="broken_access_control", state=FindingState.confirmed)
    base.update(kw)
    return Finding(**base)


@pytest.fixture
def source(tmp_path):
    """A small source tree: app/routes/accounts.py with 30 numbered lines."""
    f = tmp_path / "src" / "app" / "routes" / "accounts.py"
    f.parent.mkdir(parents=True)
    f.write_text("\n".join(f"line {n}" for n in range(1, 31)) + "\n", encoding="utf-8")
    return tmp_path / "src"


# --- where ------------------------------------------------------------------------------------- #
def test_where_is_the_file_line_and_the_code_around_it(source):
    where = render_where(finding(file="app/routes/accounts.py", line=27, function="get_account"), str(source))
    assert where == (
        "app/routes/accounts.py:27 (get_account)\n"
        "    25 | line 25\n"
        "    26 | line 26\n"
        ">   27 | line 27\n"
        "    28 | line 28\n"
        "    29 | line 29"
    )


def test_where_without_a_source_tree_is_just_the_location():
    assert render_where(finding(file="app/routes/accounts.py", line=27), None) == "app/routes/accounts.py:27"
    assert render_where(finding(file="a.py"), None) == "a.py"  # no line known


@pytest.mark.parametrize("line,first,last", [(1, 1, 3), (2, 1, 4), (30, 28, 30), (29, 27, 30)])
def test_where_window_is_clamped_to_the_file(source, line, first, last):
    where = render_where(finding(file="app/routes/accounts.py", line=line), str(source))
    shown = [int(l.lstrip("> ").split("|")[0]) for l in where.splitlines()[1:]]
    assert (shown[0], shown[-1]) == (first, last)
    assert sum(l.startswith(">") for l in where.splitlines()) == 1


def test_where_for_a_runtime_only_finding_is_its_endpoint():
    assert render_where(finding(route="GET /api/accounts/{id}"), "/anything") == "GET /api/accounts/{id}"
    assert render_where(finding(), None) is None


def test_where_never_reads_outside_the_source_tree(tmp_path, source):
    secret = tmp_path / "secret.txt"
    secret.write_text("TOP-SECRET-CONTENT\n" * 5, encoding="utf-8")
    for attempt in ("../secret.txt", "app/../../secret.txt", str(secret)):  # traversal and an absolute path
        where = render_where(finding(file=attempt, line=2), str(source))
        assert "TOP-SECRET-CONTENT" not in where and "\n" not in where  # location only


@pytest.mark.parametrize("file,line", [("app/missing.py", 3), ("app/routes/accounts.py", 999)])
def test_where_degrades_to_the_location(source, file, line):
    assert render_where(finding(file=file, line=line), str(source)) == f"{file}:{line}"


def test_a_line_that_is_not_a_line_number_shows_only_the_file(source):
    assert render_where(finding(file="app/routes/accounts.py", line=0), str(source)) == "app/routes/accounts.py"


def test_where_truncates_long_lines_and_survives_bad_bytes(tmp_path):
    f = tmp_path / "x.py"
    f.write_bytes(b"ok\n" + b"A" * 500 + b"\n\xff\xfe broken \x80\n")
    where = render_where(finding(file="x.py", line=2), str(tmp_path))
    assert "A" * 200 in where and "A" * 201 not in where
    assert "broken" in where  # undecodable bytes are replaced, not fatal


def test_where_skips_files_too_large_to_display(tmp_path):
    f = tmp_path / "big.py"
    f.write_text("x\n" * 600_000, encoding="utf-8")
    assert render_where(finding(file="big.py", line=5), str(tmp_path)) == "big.py:5"


# --- templates -------------------------------------------------------------------------------- #
def test_every_finding_type_with_a_severity_has_explanation_text():
    for type_ in load_severity().types:
        assert type_ in TEMPLATES, f"no explanation template for '{type_}'"


def test_templates_are_complete_and_within_the_claim_limit():
    for type_, parts in TEMPLATES.items():
        assert set(parts) == set(EXPLAIN_FIELDS), type_
        for field, text in parts.items():
            assert 0 < len(text) <= 400, (type_, field)
            Claim(field=field, text=text, evidence_ids=["E-0001"])  # satisfies the schema


def test_template_claims_cite_the_findings_own_evidence():
    claims = template_claims(finding(), ["E-0009", "E-0003", "E-0005"], ["what", "exploit"])
    assert [c.field for c in claims] == ["what", "exploit"]
    assert all(c.evidence_ids == ["E-0003", "E-0005"] for c in claims)  # sorted, at most two
    assert claims[0].text == TEMPLATES["broken_access_control"]["what"]


def test_template_claims_need_evidence_to_cite():
    assert template_claims(finding(), [], list(EXPLAIN_FIELDS)) == []


def test_an_unknown_type_uses_the_generic_text():
    (claim,) = template_claims(finding(type="something_new"), ["E-0001"], ["what"])
    assert claim.text == TEMPLATES["code_issue"]["what"]


def test_a_claim_without_evidence_cannot_exist():
    with pytest.raises(ValidationError):
        Claim(field="what", text="x", evidence_ids=[])


# --- 5-part assembly --------------------------------------------------------------------------- #
def test_five_parts(source):
    f = finding(file="app/routes/accounts.py", line=27, what="W", impact="I", exploit="X")
    parts = five_parts(f, str(source))
    assert list(parts) == ["what", "where", "impact", "exploit", "fix"]
    assert (parts["what"], parts["impact"], parts["exploit"]) == ("W", "I", "X")
    assert parts["where"].startswith("app/routes/accounts.py:27") and ">   27 | line 27" in parts["where"]
    assert parts["fix"] is None  # the drafted diff arrives with remediation

    assert five_parts(finding(fix_diff="--- a\n+++ b"))["fix"] == {"description": None, "diff": "--- a\n+++ b"}
