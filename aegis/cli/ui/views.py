"""How scan results look in a terminal (CLI_PHASES.md CLI04).

Every view takes **plain JSON-like data** (the REST API's shapes after ``to_jsonable``), never AEGIS
objects, so a result renders the same whether it came from this machine or from ``--api``.
"""

from __future__ import annotations

import json
from typing import Any, Callable

from aegis.cli.ui.output import Output, to_jsonable

__all__ = [
    "RISK_FORMULA", "audit_view", "cbom_view", "evidence_view", "finding_view", "findings_view",
    "gate_view", "graph_view", "report_view", "risk_expression", "scan_status_view", "scans_view",
]

RISK_FORMULA = "Risk = Severity × Confidence × (1 + Exploitability + Exposure + Criticality + PathFactor) / 5"
_KMAX = 5.0


def _short(text: Any, width: int) -> str:
    text = "" if text is None else " ".join(str(text).split())
    return text if len(text) <= width else text[: width - 3] + "..."


def _num(value: Any) -> str:
    return "" if value is None else f"{float(value):g}"     # 0.792 → "0.792", 1.0 → "1"


def _where(f: dict) -> str:
    if f.get("file"):
        return f"{f['file']}:{f['line']}" if f.get("line") else f["file"]
    return f.get("route") or ""


def risk_expression(detail: dict) -> tuple[str, float]:
    """The risk arithmetic of one finding, from its own factor values: ``(expression, recomputed risk)``."""
    s = detail.get("scores") or {}
    sev, conf = float(detail.get("severity") or 0), float(s.get("confidence") or 0)
    parts = [float(s.get(k) or 0) for k in ("exploitability", "exposure", "criticality", "path_factor")]
    recomputed = round(sev * conf * (1 + sum(parts)) / _KMAX, 3)
    expr = f"{sev:g} × {conf:g} × (1 + {' + '.join(f'{p:g}' for p in parts)}) / {_KMAX:g} = {recomputed:g}"
    return expr, recomputed


# ------------------------------------------------------------------------------------------ scans
def scans_view(scans: list[dict]) -> Callable[[Output], None]:
    def render(out: Output) -> None:
        if not scans:
            out.line("No scans yet.")
            return
        out.table(
            ["Scan", "Mode", "Status", "Findings", "Top risk", "Target", "Started"],
            [[s["id"], s["mode"], s["status"], s["findings"], _num(s.get("top_risk")),
              _short(s.get("target_url") or s.get("source") or "", 40), (s.get("created_at") or "")[:16].replace("T", " ")]
             for s in scans],
        )
    return render


def scan_status_view(scan: dict) -> Callable[[Output], None]:
    def render(out: Output) -> None:
        counts = scan.get("counts") or {}
        by_state = ", ".join(f"{k} {v}" for k, v in counts.items() if k not in ("findings", "evidence"))
        out.heading(f"Scan {scan['id']}")
        rows = [("Mode", scan["mode"]), ("Status", scan["status"]),
                ("Stages", " → ".join(scan.get("stages") or []) or "-"),
                ("Findings", f"{counts.get('findings', 0)}" + (f" ({by_state})" if by_state else "")),
                ("Evidence", counts.get("evidence", 0)),
                ("Started", scan.get("started_at") or "-"), ("Finished", scan.get("finished_at") or "-")]
        if scan.get("completed_stages"):
            rows.insert(3, ("Completed", " → ".join(scan["completed_stages"])))
        out.kv(rows)
    return render


def audit_view(audit: dict, *, all_decisions: bool = False) -> Callable[[Output], None]:
    def render(out: Output) -> None:
        calls, decisions, transitions = audit["tool_calls"], audit["decisions"], audit["transitions"]
        out.heading(f"Audit of {audit['scan_id']}: {len(calls)} tool calls, {len(decisions)} agent decisions, "
                    f"{len(transitions)} state changes")
        out.line()
        out.table(["Tool", "Target", "Seconds", "Exit", "Blocked"],
                  [[c["tool"], c.get("target_host") or "", f"{(c.get('duration_ms') or 0) / 1000:.1f}",
                    "" if c.get("exit_code") is None else c["exit_code"], c.get("blocked_reason") or ""] for c in calls],
                  title="Tool calls (through the safety controller)")
        out.line()
        if all_decisions:
            out.table(["Decision", "Step", "Finding", "Source", "Valid", "Error"],
                      [[d["id"], d["node"], d.get("finding_id") or "", d["source"], "yes" if d["valid"] else "no",
                        _short(d.get("error"), 50)] for d in decisions],
                      title="Agent decisions")
        else:
            summary: dict[tuple[str, str, bool], int] = {}
            for d in decisions:
                key = (d["node"], d["source"], bool(d["valid"]))
                summary[key] = summary.get(key, 0) + 1
            out.table(["Step", "Decided by", "Valid", "Count"],
                      [[n, s, "yes" if v else "no (rejected)", c] for (n, s, v), c in sorted(summary.items())],
                      title="Agent decisions (summary; --decisions lists each)")
        out.line()
        out.table(["Finding", "From", "To", "By", "Evidence", "Reason"],
                  [[t["finding_id"], t.get("from") or "", t["to"], t.get("actor") or "",
                    ", ".join(t.get("evidence_ids") or []), _short(t.get("reason"), 60)] for t in transitions],
                  title="Finding state changes")
    return render


# ------------------------------------------------------------------------------------------ findings
def findings_view(scan: str, findings: list[dict], total: int) -> Callable[[Output], None]:
    def render(out: Output) -> None:
        shown = f"{len(findings)} of {total}" if len(findings) < total else f"{total}"
        out.heading(f"Findings of {scan}: {shown}, highest risk first")
        if not findings:
            out.line("No findings match.")
            return
        out.table(
            ["Finding", "Risk", "Severity", "State", "OWASP", "Type", "Where", "Title"],
            [[f["id"], _num(f.get("risk")), _num(f.get("severity")), f.get("state") or "", f.get("owasp") or "",
              f.get("type") or "", _short(_where(f), 34), _short(f.get("title"), 50)] for f in findings],
        )
    return render


def finding_view(detail: dict, *, show_diff: bool = False) -> Callable[[Output], None]:
    def render(out: Output) -> None:
        out.heading(f"{detail['id']}  {detail.get('title') or detail.get('type')}")
        out.kv([
            ("Type", f"{detail.get('type')}" + (f" (OWASP {detail['owasp']})" if detail.get("owasp") else "")),
            ("State", detail.get("state")), ("Mode", detail.get("mode") or "-"),
            ("Route", detail.get("route") or "-"), ("Function", detail.get("function") or "-"),
            ("Risk", _num(detail.get("risk"))),
        ])
        for title, key in (("What", "what"), ("Impact", "impact"), ("Exploit", "exploit")):
            out.line()
            out.heading(title)
            out.line("  " + (detail.get(key) or "-"))
        out.line()
        out.heading("Where")
        for row in (detail.get("where") or "-").splitlines():
            out.line("  " + row)
        fix = detail.get("fix") or {}
        out.line()
        out.heading("Fix")
        if fix:
            out.kv([("Fix", fix.get("fix_id") or "-"), ("Status", fix.get("status") or "-"),
                    ("What changes", fix.get("description") or "-")])
            if show_diff and fix.get("diff"):
                out.line()
                for row in fix["diff"].splitlines():
                    out.line("  " + row)
            elif fix.get("diff"):
                out.line("  (diff hidden; add --diff to show it)")
        else:
            out.line("  No fix drafted for this finding.")
        expr, _ = risk_expression(detail)
        out.line()
        out.heading("Risk")
        out.line(f"  {RISK_FORMULA}")
        out.line(f"  {expr}")
        claims = detail.get("claims") or []
        if claims:
            out.line()
            out.table(["Part", "Claim", "Evidence"],
                      [[c.get("field"), _short(c.get("text"), 70), ", ".join(c.get("evidence_ids") or [])] for c in claims],
                      title="Claims and the evidence behind each")
        out.line()
        out.kv([("Evidence", ", ".join(detail.get("evidence_ids") or []) or "-"),
                ("Found by", ", ".join(detail.get("sources") or []) or "-")])
    return render


def evidence_view(record: dict) -> Callable[[Output], None]:
    def render(out: Output) -> None:
        out.heading(f"Evidence {record['id']}")
        rows = [("Finding", record.get("finding_id") or "-"), ("Scan", record.get("scan_id")),
                ("Kind", record.get("kind")), ("Tool", record.get("tool"))]
        if "digest" in record:
            rows.append(("Digest", record["digest"]))
            out.kv(rows)
            out.line()
            out.line("  (summary only; --raw shows the recorded payload with credentials redacted)")
            return
        rows += [("Tool version", record.get("tool_version") or "-"), ("Recorded", record.get("created_at") or "-")]
        out.kv(rows)
        out.line()
        out.heading("Payload (credentials redacted)")
        for row in json.dumps(record.get("payload"), indent=2, ensure_ascii=False).splitlines():
            out.line("  " + row)
    return render


# ------------------------------------------------------------------------------------------ graph / cbom
def graph_view(graph: dict) -> Callable[[Output], None]:
    def render(out: Output) -> None:
        paths = graph.get("attack_paths") or []
        out.heading(f"Security graph of {graph['scan_id']}: {len(graph.get('nodes') or [])} nodes, "
                    f"{len(graph.get('edges') or [])} edges, {len(paths)} attack paths")
        if not paths:
            out.line("No attack paths: no finding links an endpoint to a handler and a sink.")
            return
        out.line()
        for i, path in enumerate(paths, 1):
            out.line(f"  {i}. " + "  →  ".join(_short(step, 60) for step in path))
    return render


def _prop(component: dict, name: str) -> str:
    return next((p.get("value", "") for p in component.get("properties") or [] if p.get("name") == name), "")


def cbom_view(scan: str, cbom: dict) -> Callable[[Output], None]:
    def render(out: Output) -> None:
        comps = cbom.get("components") or []
        out.heading(f"Cryptography bill of materials of {scan} (CycloneDX {cbom.get('specVersion')}): {len(comps)} assets")
        rows = []
        for c in comps:
            props = c.get("cryptoProperties") or {}
            algo = props.get("algorithmProperties") or {}
            occ = ((c.get("evidence") or {}).get("occurrences") or [{}])[0]
            where = f"{occ.get('location')}:{occ.get('line')}" if occ.get("location") else ""
            classical, quantum = _prop(c, "aegis:classical_risk"), _prop(c, "aegis:quantum_risk")
            rows.append([c.get("name"), props.get("assetType") or "", algo.get("primitive") or "",
                         _short(where, 28), _prop(c, "aegis:usage"),
                         "-" if classical in ("", "none") else _short(classical, 40),
                         "-" if quantum in ("", "none") else "at risk"])
        out.table(["Asset", "Type", "Primitive", "Where", "Usage", "Classical risk", "Quantum"], rows)
    return render


# ------------------------------------------------------------------------------------------ report / gate
def report_view(info: dict) -> Callable[[Output], None]:
    def render(out: Output) -> None:
        size = info["bytes"]
        human = f"{size / 1024:.1f} KB" if size >= 1024 else f"{size} bytes"
        out.line(f"Report ({info['format']}) of {info['scan_id']}: {info['path']}  ({human})")
    return render


def gate_view(scan: str, verdict: dict, findings: dict[str, dict], threshold: float | None) -> Callable[[Output], None]:
    def render(out: Output) -> None:
        code = verdict["exit_code"]
        at = f"risk >= {threshold:g}" if threshold is not None else "the configured risk threshold"
        if code == 0:
            out.heading(f"Gate for {scan}: PASSED (exit 0) - no open finding in a blocking category at {at}")
        elif code == 2:
            out.heading(f"Gate for {scan}: NOT COMPLETE (exit 2) - the scan did not finish, so there is no verdict")
        else:
            blocking = verdict.get("blocking_findings") or []
            out.heading(f"Gate for {scan}: BLOCKED (exit 1) - {len(blocking)} open finding(s) in a blocking category at {at}")
            out.table(["Finding", "Risk", "OWASP", "Type", "Title"],
                      [[fid, _num(findings.get(fid, {}).get("risk")), findings.get(fid, {}).get("owasp") or "",
                        findings.get(fid, {}).get("type") or "", _short(findings.get(fid, {}).get("title"), 60)]
                       for fid in blocking])
    return render


# ------------------------------------------------------------------------------------------ answers
def answer_view(answer: dict) -> Callable[[Output], None]:
    def render(out: Output) -> None:
        out.line(f"aegis> {answer.get('answer', '')}")
        cited = ", ".join(answer.get("finding_ids") or [])
        evidence = ", ".join(answer.get("evidence_ids") or [])
        if cited or evidence:
            out.line(f"       cited: {cited or '-'}   evidence: {evidence or '-'}")
    return render


# ------------------------------------------------------------------------------------------ doctor
def doctor_view(report: dict) -> Callable[[Output], None]:
    def render(out: Output) -> None:
        h = report["health"]
        ok, bad, warn = out.sym["ok"], out.sym["fail"], out.sym["warn"]
        ollama = h.get("ollama") or {}
        tools = h.get("tools") or {}
        found = sorted(n for n, t in tools.items() if t.get("found"))
        missing = sorted(n for n, t in tools.items() if not t.get("found"))
        repo = h.get("repo_scans") or {}
        dbs = h.get("db_snapshot_dates") or {}
        rows = [
            ("API", f"{ok} {report['api']} ({h.get('status', '?')})"),
            ("Database", f"{ok} ok" if h.get("database") else f"{bad} not answering"),
        ]
        if not ollama.get("reachable"):
            rows.append(("Ollama", f"{bad} not reachable at {ollama.get('url')} - start Ollama, then restart the API "
                                   "with AEGIS_OLLAMA_URL=http://127.0.0.1:11434"))
        else:
            rows.append(("Ollama", f"{ok} {ollama.get('url')}"))
            rows.append(("Model", f"{ok} {ollama.get('model')}" if ollama.get("model_present")
                         else f"{bad} {ollama.get('model')} is not pulled - run: ollama pull {ollama.get('model')}"))
        llm = h.get("llm")
        if llm:   # the model AEGIS reasons with (LLM_PROVIDER_PHASES LP9)
            where = "online" if llm.get("location") == "cloud" else "offline"
            state = ok if llm.get("ready") else (bad if llm.get("ready") is False else warn)
            rows.append(("AI model", f"{state} {llm.get('provider')} {llm.get('model')} ({where})"
                         + (f" - {llm['reason']}" if llm.get("reason") else "")))
        emb = h.get("embeddings")
        if emb:
            index = emb.get("index") or {}
            rows.append(("Embeddings", f"{ok if emb.get('model_present') else bad} {emb.get('model')} ({emb.get('dim')} dims, local)"
                         + (f" - {index['reason']}" if index.get("compatible") is False else "")))
        rows.append(("Scanners", f"{len(found)} of {len(tools)} found" + (f"; missing: {', '.join(missing)}" if missing else "")))
        rows.append(("Repo scans", f"{ok} from {', '.join(repo.get('git_hosts') or [])}" if repo.get("enabled")
                     else f"{warn} off (the API needs AEGIS_SAFETY__GIT_HOSTS, e.g. github.com:443)"))
        rows.append(("Offline DBs", ", ".join(f"{k} {v or 'missing'}" for k, v in dbs.items()) or "-"))
        out.heading("AEGIS doctor")
        out.kv(rows)
    return render


def to_data(value: Any) -> Any:
    """Shortcut for views: the API shape of any result as plain data."""
    return to_jsonable(value)
