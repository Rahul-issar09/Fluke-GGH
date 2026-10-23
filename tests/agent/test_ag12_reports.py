"""AG12.1 — finalize writes the JSON + HTML reports; the HTML tells the F-0012 story offline."""

from __future__ import annotations

import ast
import asyncio
import json
import os
import re
import shutil
from datetime import datetime, timezone
from html.parser import HTMLParser

import pytest

from _corr_helpers import seed_handlers, seed_runtime_bac
from _graph_helpers import make_run
from aegis.agent.graph import build_aegis_graph
from aegis.agent.nodes.finalize import finalize
from aegis.api.schemas import EvidenceOut, FindingDetail
from aegis.evidence.adapters.semgrep import SemgrepAdapter
from aegis.evidence.normalizer import ingest
from aegis.evidence.models import FindingState, Mode
from aegis.reports.html import attack_path_svg, render_html
from aegis.reports.json_report import REDACTED, build_json_report, redact
from aegis.risk.engine import RISK_FORMULA
from aegis.services.report_service import build_report, report_paths, write_reports
from fakes.demo_apps import ROOT
from fakes.tool_executors import fix_executor
from test_ag10_remediate import ACCOUNTS, SECRET_VALUE
from test_ag10_remediate_support import FixesTheAccessBug
from test_ag11_fix_graph import World
from test_ag11_verify import CONFIG_PY, FROM_ENV, unified

pytestmark = pytest.mark.phase("AG12")


class Page(HTMLParser):
    """Collect what matters for "does it open offline": tags, ids, links, external references."""

    def __init__(self, html: str):
        super().__init__()
        self.tags: list[str] = []
        self.ids: set[str] = set()
        self.hrefs: list[str] = []
        self.external: list[tuple[str, str, str]] = []
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)
        for name, value in attrs:
            if name == "id":
                self.ids.add(value)
            if name == "href":
                self.hrefs.append(value)
            if name in ("src", "href", "srcset", "action", "data", "poster") and value and not value.startswith("#"):
                self.external.append((tag, name, value))


def section_between(html: str, start: str, end: str) -> str:
    return html[html.index(start): html.index(end)]


def section(html: str, element_id: str) -> str:
    start = html.index(f'id="{element_id}"')
    return html[start: html.index("</section>", start)]


# --------------------------------------------------------------------------------------------- #
# the correlated Mode 3 scan of the demo, then its fix, approved and applied
# --------------------------------------------------------------------------------------------- #
def real_handler_rows() -> list[dict]:
    """Route handlers of the real demo source (what the code worker will extract), from its AST."""
    rows = []
    for path in sorted((ROOT / "demo-app" / "app" / "routes").glob("*.py")):
        rel = path.relative_to(ROOT / "demo-app").as_posix()
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if not isinstance(node, ast.FunctionDef):
                continue
            for dec in node.decorator_list:
                if isinstance(dec, ast.Call) and getattr(dec.func, "attr", "") in ("get", "post", "put", "delete"):
                    rows.append({
                        "path": dec.args[0].value, "methods": [dec.func.attr.upper()], "function": node.name,
                        "qualname": f"{rel}::{node.name}", "file": rel, "line": node.lineno, "end_line": node.end_lineno,
                    })
    return rows


def real_semgrep_results() -> dict:
    """What the three rules report on the demo source (lines as real semgrep 1.179 reports them)."""
    def result(rule, path, line, message, owasp):
        return {"check_id": f"rules.semgrep.{rule}", "path": path, "start": {"line": line}, "end": {"line": line},
                "extra": {"message": message, "severity": "ERROR", "metadata": {"owasp": owasp}}}
    return {"results": [
        result("fastapi-missing-owner-check", ACCOUNTS, 37, "Object is read by id without an owner check.", "A01"),
        result("fastapi-sqli", "app/routes/users.py", 16, "User input flows into a SQL query built by string concatenation.", "A03"),
        result("weak-hash", "app/auth.py", 12, "MD5 used for password hashing.", "A02"),
    ]}


async def scan_and_fix(store, tmp_path):
    scan_id, state, config = make_run(store, tmp_path, Mode.correlated, tool_executor=fix_executor)
    src = tmp_path / "scan"
    shutil.copytree(ROOT / "demo-app" / "app", src / "app")
    store.update_scan(scan_id, source_path=str(src))
    # the offline databases prepare will date: osv and the nuclei templates present, trivy absent
    offline = tmp_path / "offline-db"
    for name, day in (("osv", "2026-09-30"), ("nuclei-templates", "2026-09-28")):
        (offline / name).mkdir(parents=True)
        stamp = datetime(*map(int, day.split("-")), 12, tzinfo=timezone.utc).timestamp()
        os.utime(offline / name, (stamp, stamp))
    seed_handlers(store, scan_id, real_handler_rows())
    ingest(store, scan_id, SemgrepAdapter().parse(real_semgrep_results(), scan_id))
    config["configurable"]["deps"].llm = FixesTheAccessBug()

    final = await build_aegis_graph().ainvoke(state, config)
    assert final["errors"] == []
    bac = next(f for f in store.list_findings(scan_id) if f.type == "broken_access_control" and f.route and store.list_fix_attempts(f.id))
    before = build_json_report(store, scan_id, data_dir=tmp_path / "data")

    # the scan's allowlist (written by prepare) gains the patched build, as .aegis.yml would list it
    cfg = json.loads(store.get_scan(scan_id).config_json)
    cfg["allowlist"] = [*cfg["allowlist"], "patched-build:5000"]
    store.update_scan(scan_id, config_json=json.dumps(cfg))

    w = World(store=store, scan=scan_id, src=src, finding=bac.id, tmp=tmp_path)
    async with w.service() as service:
        await service.start(bac.id)
        await service.commit(store.latest_fix_attempt(bac.id).id, "apply")
    return scan_id, bac.id, before


# --------------------------------------------------------------------------------------------- #
# the three tests the plan names
# --------------------------------------------------------------------------------------------- #
async def test_ag12_json_report_shape(store, tmp_path):
    scan_id, f0012, _ = await scan_and_fix(store, tmp_path)
    paths = report_paths(tmp_path / "data", scan_id)
    report = json.loads(paths["json"].read_text(encoding="utf-8"))

    assert set(report) == {"aegis_report", "generated_at", "scan", "summary", "risk", "runtime_coverage", "runtime_coverage_note", "db_snapshot_dates", "findings", "attack_paths", "evidence", "audit"}
    assert isinstance(report["runtime_coverage"], list)  # coverage section (TNW); empty for a code-only world
    assert report["scan"]["id"] == scan_id and report["scan"]["mode"] == "correlated"
    for finding in report["findings"]:
        FindingDetail.model_validate(finding)                                # the API's frozen shape...
        assert {"rank", "risk_breakdown", "merged", "history"} <= set(finding)  # ...plus the report's additions
    for ev in report["evidence"]:
        EvidenceOut.model_validate(ev)

    # ranked: open findings by risk (highest first), then the resolved ones
    ranks = [f["rank"] for f in report["findings"]]
    assert ranks == list(range(1, len(ranks) + 1))
    open_risks = [f["risk"] for f in report["findings"] if f["state"] != "resolved"]
    assert open_risks == sorted(open_risks, reverse=True)
    assert report["findings"][-1]["id"] == f0012 and report["findings"][-1]["state"] == "resolved"
    assert report["summary"] == {
        "findings": len(report["findings"]), "open": len(open_risks), "resolved": 1,
        "by_state": report["summary"]["by_state"], "top_risk": report["findings"][0]["id"], "evidence": len(report["evidence"]),
    }

    # every ID the report mentions exists in it
    evidence_ids = {e["id"] for e in report["evidence"]}
    for finding in report["findings"]:
        assert set(finding["evidence_ids"]) <= evidence_ids
        for claim in finding["claims"]:
            assert claim["evidence_ids"] and set(claim["evidence_ids"]) <= evidence_ids
    assert report["audit"]["tool_calls"] >= 2 and report["audit"]["by_tool"].get("git")


async def test_ag12_html_opens_offline(store, tmp_path):
    scan_id, f0012, _ = await scan_and_fix(store, tmp_path)
    html = report_paths(tmp_path / "data", scan_id)["html"].read_text(encoding="utf-8")
    page = Page(html)

    assert page.external == []                                               # no src, no external href
    assert not {"script", "link", "img", "iframe", "object", "embed"} & set(page.tags)
    assert "@import" not in html and "url(" not in re.sub(r'url\(#arrow\)', "", html)
    assert page.tags.count("style") == 1 and "svg" in page.tags
    missing = {h[1:] for h in page.hrefs if h[1:] not in page.ids}
    assert missing == set(), f"links to nothing: {missing}"                  # every anchor resolves inside the file
    assert f0012 in page.ids and all(e["id"] in page.ids for e in build_json_report(store, scan_id)["evidence"])


async def test_ag12_formula_and_dbdates_present(store, tmp_path):
    scan_id, f0012, before = await scan_and_fix(store, tmp_path)
    html = report_paths(tmp_path / "data", scan_id)["html"].read_text(encoding="utf-8")

    assert RISK_FORMULA in html
    dates = section_between(html, 'id="db-dates"', 'id="attack-paths"')
    assert "<td>osv</td><td>2026-09-30</td>" in dates and "<td>nuclei</td><td>2026-09-28</td>" in dates
    assert "<td>trivy</td><td>not present</td>" in dates                     # an absent database is said so
    assert json.loads(report_paths(tmp_path / "data", scan_id)["json"].read_text(encoding="utf-8"))["db_snapshot_dates"] == {
        "nuclei": "2026-09-28", "osv": "2026-09-30", "trivy": None,
    }
    # the worked example, while the bug was open (PHASES: 0.9 × 1.0 × (1+1.0+0.6+1.0+0.8)/5 = 0.792)
    (open_bac,) = [f for f in before["findings"] if f["id"] == f0012]
    assert open_bac["risk_breakdown"]["expression"] == "0.9 × 1 × (1 + 1 + 0.6 + 1 + 0.8) / 5 = 0.792"
    assert "0.9 × 1 × (1 + 1 + 0.6 + 1 + 0.8) / 5 = 0.792" in render_html(before)
    # and once resolved, its confidence — so its risk — drops to 0, shown the same way
    detail = section(html, f0012)
    assert "/ 5 = 0" in detail


# --------------------------------------------------------------------------------------------- #
# Done When: the F-0012 story, readable end to end
# --------------------------------------------------------------------------------------------- #
async def test_the_access_control_story_reads_end_to_end(store, tmp_path):
    scan_id, f0012, _ = await scan_and_fix(store, tmp_path)
    html = report_paths(tmp_path / "data", scan_id)["html"].read_text(encoding="utf-8")
    story = section(html, f0012)
    finding = store.get_finding(f0012)

    assert "GET /api/accounts/{id}" in story                                  # where it is reached
    assert "app/routes/accounts.py:37 (get_account)" in story                  # where it is in the code
    for part in (finding.what, finding.impact, finding.exploit):              # the validated explanation
        assert part and part in story
    assert "row[&#34;owner_id&#34;] != user[&#34;id&#34;]" in story             # the fix, as a diff
    assert "Verification: <b>passed</b>" in story and "committed as apply" in story
    assert '<span class="badge resolved">resolved</span>' in story            # resolved...
    retest = [e for e in store.evidence_for(f0012) if e.kind == "retest"]
    assert retest and all(f'href="#{e.id}"' in story for e in retest)         # ...with links to the retest proof

    # the runtime proof itself, in the appendix: B read A's account
    proof = next(e for e in store.evidence_for(f0012) if e.kind == "http_exchange")
    appendix = section(html, proof.id)
    assert "&#34;identity&#34;: &#34;B&#34;" in appendix and "&#34;contains_owner_fields&#34;: true" in appendix
    assert f'href="#{f0012}"' in html.split('id="attack-paths"', 1)[1].split("</svg>", 1)[0]  # on the attack-path picture


# --------------------------------------------------------------------------------------------- #
# safety of a shareable file
# --------------------------------------------------------------------------------------------- #
async def test_target_content_cannot_inject_markup(store, tmp_path):
    scan_id, state, config = make_run(store, tmp_path, Mode.runtime)
    runtime = seed_runtime_bac(store, scan_id)
    hostile = '<script>alert("x")</script><img src=x onerror=alert(1)>'
    store.update_finding_fields(runtime, title=hostile, what=hostile)
    store.add_evidence(scan_id, "http_exchange", "bola", {"response": hostile}, finding_id=runtime)
    html = render_html(build_json_report(store, scan_id))
    page = Page(html)
    assert "script" not in page.tags and "img" not in page.tags and "<script>" not in html
    assert "&lt;script&gt;" in html


async def test_a_leaked_secret_never_appears_in_a_report(store, tmp_path):
    scan_id, _s, _c = make_run(store, tmp_path, Mode.code)
    src = tmp_path / "scan"
    (src / "config.py").write_text(CONFIG_PY, encoding="utf-8", newline="\n")
    store.update_scan(scan_id, source_path=str(src))
    finding = store.add_finding(scan_id, type="secret", file="config.py", line=3, source="worker2.gitleaks")
    store.add_evidence(scan_id, "secret", "gitleaks", {"file": "config.py", "line": 3, "value": "***REDACTED***", "value_fingerprint": "abc123"}, finding_id=finding.id)
    from aegis.fix.draft import mask_literals

    masked = mask_literals(unified("config.py", CONFIG_PY, CONFIG_PY.replace(f'API_KEY = "{SECRET_VALUE}"\n', FROM_ENV)), [f'"{SECRET_VALUE}"'])
    store.add_fix_attempt(finding.id, masked, status="drafted", verify_report={"draft": {"secret_masked": True}})

    for fmt in ("json", "html"):
        text = build_report(store, scan_id, fmt)
        assert SECRET_VALUE not in text
    report = build_json_report(store, scan_id)
    assert "config.py:3" in report["findings"][0]["where"] and "API_KEY = " in report["findings"][0]["where"]


def test_credentials_are_redacted_from_evidence_payloads():
    payload = {
        "request": {"headers": {"Authorization": "Bearer abc", "Cookie": "session=1", "Accept": "json"}},
        "password": "hunter2",
        "value_fingerprint": "f00d",
        "auth_context": "authenticated",
        "items": [{"api_key": "k"}],
        "session_id": "s-1",
    }
    out = redact(payload)
    assert out["request"]["headers"] == {"Authorization": REDACTED, "Cookie": REDACTED, "Accept": "json"}
    assert out["password"] == REDACTED and out["items"] == [{"api_key": REDACTED}]
    assert out["value_fingerprint"] == "f00d" and out["auth_context"] == "authenticated" and out["session_id"] == "s-1"


# --------------------------------------------------------------------------------------------- #
# finalize
# --------------------------------------------------------------------------------------------- #
async def test_finalize_writes_both_reports_for_every_scan(store, tmp_path):
    scan_id, state, config = make_run(store, tmp_path, Mode.runtime)
    final = await build_aegis_graph().ainvoke(state, config)
    assert final["completed_stages"][-1] == "finalize" and final["errors"] == []
    paths = report_paths(tmp_path / "data", scan_id)
    assert json.loads(paths["json"].read_text(encoding="utf-8"))["scan"]["id"] == scan_id
    assert paths["html"].read_text(encoding="utf-8").startswith("<!doctype html>")
    assert store.get_scan(scan_id).status.value == "queued"                  # status stays the job runner's


async def test_a_report_that_cannot_be_written_is_an_error_not_a_failed_scan(store, tmp_path, monkeypatch):
    import aegis.agent.nodes.finalize as node

    def broken(*args, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(node, "write_reports", broken)
    scan_id, state, config = make_run(store, tmp_path, Mode.runtime)
    out = await finalize({**state, "scan_id": scan_id}, config)
    assert out["completed_stages"] == ["finalize"] and out["errors"] == ["finalize: report not written: OSError: disk full"]


async def test_the_chat_index_is_started_without_waiting_and_cannot_fail_the_scan(store, tmp_path):
    scan_id, state, config = make_run(store, tmp_path, Mode.runtime)
    deps = config["configurable"]["deps"]
    started, release = asyncio.Event(), asyncio.Event()

    async def slow_indexer(sid):
        started.set()
        await release.wait()
        raise RuntimeError("index broke")

    deps.chat_indexer = slow_indexer
    out = await finalize({**state, "scan_id": scan_id}, config)       # returns while the index is still building
    assert out["errors"] == [] and len(deps.background_tasks) == 1
    await asyncio.wait_for(started.wait(), 2)
    release.set()
    await asyncio.gather(*list(deps.background_tasks))                  # the failure is logged, not raised
    assert not deps.background_tasks


# --------------------------------------------------------------------------------------------- #
# building blocks
# --------------------------------------------------------------------------------------------- #
def test_the_attack_path_picture_escapes_labels_and_links_findings():
    svg = str(attack_path_svg([["GET /a/<b>", "handler", "F-0001"]], {"F-0001"}))
    assert "&lt;b&gt;" in svg and '<a href="#F-0001">' in svg and svg.count("<line") == 2
    assert "No attack path" in str(attack_path_svg([], set()))


def test_report_inputs_are_checked(store, tmp_path):
    with pytest.raises(ValueError):
        report_paths(tmp_path, "../../etc")
    with pytest.raises(ValueError, match="unknown report format"):
        build_report(store, "S-0001", "pdf")
    with pytest.raises(KeyError):
        write_reports(store, "S-9999", tmp_path)
