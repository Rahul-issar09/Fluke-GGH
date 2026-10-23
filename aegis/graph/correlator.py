"""Deterministic correlation (PHASES P9.3, P9.4) — the core differentiator.

Links one runtime-proven finding (``GET /api/accounts/{id}``) to the exact
handler in code, scores the link, and merges the matching static finding into
one issue. Pure Python over the evidence store: no LLM, no randomness, same
inputs → same links and scores (NFR-3).

Link score (PRD §7.9)::

    +0.5  normalized route template matches
    +0.2  HTTP method matches
    +0.3  a data-flow path ties the handler to a flagged sink
    cap 1.0; only links >= CORRELATION_THRESHOLD (0.70) are kept

Evidence conventions this module reads (written by Worker 2, AG14):

* route → handler: ``code_location`` evidence, payload
  ``{"role": "route_handler", "path", "methods", "function", "qualname", "file",
  "line", "end_line"}``. ``end_line`` bounds the handler's body; without it the
  handler spans only its first line, so static findings inside the body are not
  attributed to it.
* data flow: ``dataflow_path`` evidence, payload ``{"file", "line", "sink":
  [name, line], optional "function": qualname}``. A flow belongs to a handler
  when its ``function`` equals the handler's qualname or its file:line falls
  inside the handler's span.

Only data flows from static findings of the **same weakness type** as the
runtime finding count toward the +0.3 signal and get merged — a SQL-injection
flow in a handler must not "confirm" an access-control finding or contribute
evidence to its explanation.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from aegis.evidence import dedup, state_machine
from aegis.evidence.links import add_link, linked_to, links_for_scan, merged_ids
from aegis.evidence.models import Finding, FindingState, Mode
from aegis.evidence.store import EvidenceStore
from aegis.graph.route_normalize import normalize_path, normalize_route, split_route
from aegis.graph.security_graph import SecurityGraph
from aegis.observability import get_logger

__all__ = [
    "CORRELATION_THRESHOLD",
    "Handler",
    "Dataflow",
    "RuntimeTarget",
    "CorrelationReport",
    "link_score",
    "load_handlers",
    "load_dataflows",
    "correlate_scan",
    "build_graph",
]

log = get_logger("graph.correlator")

CORRELATION_THRESHOLD = 0.70
_W_ROUTE, _W_METHOD, _W_FLOW = 0.5, 0.2, 0.3


@dataclass(frozen=True)
class Handler:
    path: str
    methods: tuple[str, ...]
    qualname: str
    function: str
    file: str
    line: int
    end_line: int | None = None
    evidence_id: str | None = None

    def contains(self, file: str | None, line: int | None) -> bool:
        if file != self.file or line is None:
            return False
        end = self.end_line if self.end_line is not None else self.line
        return self.line <= line <= end


@dataclass(frozen=True)
class Dataflow:
    evidence_id: str
    file: str | None = None
    line: int | None = None
    function: str | None = None  # qualname, when the extractor resolved it
    finding_id: str | None = None
    finding_type: str | None = None
    sink_name: str | None = None
    sink_line: int | None = None


@dataclass(frozen=True)
class RuntimeTarget:
    method: str
    path: str


@dataclass
class CorrelationReport:
    correlated: list[dict[str, Any]] = field(default_factory=list)
    dropped: list[dict[str, Any]] = field(default_factory=list)  # best link below threshold
    unmatched: list[str] = field(default_factory=list)  # runtime findings with no handler at all


# --------------------------------------------------------------------------- #
# P9.3 — link score
# --------------------------------------------------------------------------- #
def _flow_belongs(flow: Dataflow, handler: Handler) -> bool:
    if flow.function is not None and flow.function == handler.qualname:
        return True
    return handler.contains(flow.file, flow.line)


def link_score(
    target: RuntimeTarget, handler: Handler, dataflows: list[Dataflow]
) -> tuple[float, dict[str, Any]]:
    """Score how well *handler* explains the runtime *target*; ``(score, signals)``."""
    score = 0.0
    signals: dict[str, Any] = {}
    if normalize_path(target.path) == normalize_path(handler.path):
        score += _W_ROUTE
        signals["route"] = True
    if target.method.upper() in {m.upper() for m in handler.methods}:
        score += _W_METHOD
        signals["method"] = True
    flows = sorted(f.evidence_id for f in dataflows if _flow_belongs(f, handler))
    if flows:
        score += _W_FLOW
        signals["dataflow"] = True
        signals["dataflow_evidence"] = flows
    return round(min(score, 1.0), 2), signals


# --------------------------------------------------------------------------- #
# loaders (evidence store → typed inputs)
# --------------------------------------------------------------------------- #
def _payload(raw: str | None) -> dict[str, Any]:
    try:
        data = json.loads(raw or "{}")
    except (json.JSONDecodeError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def load_handlers(store: EvidenceStore, scan_id: str) -> list[Handler]:
    handlers: list[Handler] = []
    for ev in store.list_evidence(scan_id, kind="code_location"):
        p = _payload(ev.payload_json)
        if p.get("role") != "route_handler":
            continue
        if not all(p.get(k) is not None for k in ("path", "function", "file", "line")):
            log.warning("correlator.bad_handler_evidence", evidence_id=ev.id)
            continue
        handlers.append(
            Handler(
                path=str(p["path"]),
                methods=tuple(str(m).upper() for m in (p.get("methods") or ["GET"])),
                qualname=str(p.get("qualname") or f"{p['file']}::{p['function']}"),
                function=str(p["function"]),
                file=str(p["file"]),
                line=int(p["line"]),
                end_line=int(p["end_line"]) if p.get("end_line") is not None else None,
                evidence_id=ev.id,
            )
        )
    return sorted(handlers, key=lambda h: (h.qualname, h.path))


def _sink(raw: Any) -> tuple[str | None, int | None]:
    if isinstance(raw, (list, tuple)) and raw:
        return (str(raw[0]), int(raw[1]) if len(raw) > 1 and raw[1] is not None else None)
    if isinstance(raw, dict):
        return (raw.get("name"), raw.get("line"))
    if isinstance(raw, str):
        return (raw, None)
    return (None, None)


def load_dataflows(store: EvidenceStore, scan_id: str) -> list[Dataflow]:
    findings = {f.id: f for f in store.list_findings(scan_id)}
    flows: list[Dataflow] = []
    for ev in store.list_evidence(scan_id, kind="dataflow_path"):
        p = _payload(ev.payload_json)
        owner = findings.get(ev.finding_id) if ev.finding_id else None
        sink_name, sink_line = _sink(p.get("sink"))
        flows.append(
            Dataflow(
                evidence_id=ev.id,
                file=p.get("file"),
                line=p.get("line"),
                function=p.get("function"),
                finding_id=ev.finding_id,
                finding_type=owner.type if owner else None,
                sink_name=sink_name,
                sink_line=sink_line,
            )
        )
    return flows


# --------------------------------------------------------------------------- #
# P9.4 — apply correlation
# --------------------------------------------------------------------------- #
def _is_runtime_origin(f: Finding) -> bool:
    """Found at runtime: has a route; code-only findings have a file and no route."""
    return bool(f.route) and (f.file is None or f.correlation_score is not None)


def _is_static(f: Finding) -> bool:
    return bool(f.file) and not f.route


def correlate_scan(
    store: EvidenceStore,
    scan_id: str,
    handlers: list[Handler],
    *,
    threshold: float = CORRELATION_THRESHOLD,
) -> CorrelationReport:
    """Link runtime findings to their handlers and merge matching static findings.

    Idempotent: running again over the same store changes nothing.
    """
    report = CorrelationReport()
    dataflows = load_dataflows(store, scan_id)
    all_findings = sorted(store.list_findings(scan_id), key=lambda f: f.id)
    linked_elsewhere = {l.linked_id: l.primary_id for l in links_for_scan(store, scan_id)}

    for finding in all_findings:
        if finding.id in linked_elsewhere or not _is_runtime_origin(finding):
            continue
        parsed = split_route(finding.route or "")
        if parsed is None:
            continue
        target = RuntimeTarget(*parsed)
        same_type_flows = [d for d in dataflows if d.finding_type == finding.type]

        scored = [(link_score(target, h, same_type_flows), h) for h in handlers]
        if not scored:
            report.unmatched.append(finding.id)
            continue
        (score, signals), handler = sorted(scored, key=lambda s: (-s[0][0], s[1].qualname, s[1].path))[0]
        if score < threshold:
            report.dropped.append({"finding_id": finding.id, "best_score": score, "handler": handler.qualname})
            log.info("correlator.dropped", finding_id=finding.id, best_score=score, threshold=threshold)
            continue

        # a static finding of the same type inside the handler — or in a helper it calls, when a
        # traced flow runs from this handler to that finding (one call level, TNW-5)
        traced_here = {d.finding_id for d in same_type_flows if d.function == handler.qualname and d.finding_id}
        duplicates = [
            f
            for f in all_findings
            if f.id != finding.id
            and _is_static(f)
            and f.type == finding.type
            and (handler.contains(f.file, f.line) or f.id in traced_here)
            and linked_elsewhere.get(f.id, finding.id) == finding.id
        ]

        sources = finding.sources
        for dup in duplicates:
            moved = [e.id for e in store.evidence_for(dup.id)]
            for evidence_id in moved:
                store.attach_evidence(evidence_id, finding.id)
            sources = _merge_all_sources(sources, dup.sources)
            add_link(store, scan_id, finding.id, dup.id, score=score, evidence_ids=moved)

        # the root-cause line is the static finding's; otherwise the handler's definition
        root_lines = [d.line for d in duplicates if d.line is not None]
        store.update_finding_fields(
            finding.id,
            function=handler.function,
            file=handler.file,
            line=min(root_lines) if root_lines else handler.line,
            correlation_score=score,
            mode=Mode.correlated.value,
            sources=sources,
        )
        _promote(store, finding.id)

        report.correlated.append(
            {
                "finding_id": finding.id,
                "handler": handler.qualname,
                "score": score,
                "signals": signals,
                "merged": [d.id for d in duplicates],
            }
        )
        log.info(
            "correlator.linked",
            finding_id=finding.id,
            handler=handler.qualname,
            score=score,
            merged=[d.id for d in duplicates],
        )
    return report


def _merge_all_sources(existing_json: str, other_json: str) -> str:
    merged = existing_json
    try:
        for source in json.loads(other_json or "[]"):
            merged = dedup.merge_sources(merged, source)
    except (json.JSONDecodeError, ValueError):
        pass
    return merged


def _promote(store: EvidenceStore, finding_id: str) -> None:
    """Correlation never confirms; it can only corroborate (a second independent layer)."""
    finding = store.get_finding(finding_id)
    if finding is None or finding.state != FindingState.candidate:
        return
    evidence = store.evidence_for(finding_id)
    if len({e.tool for e in evidence}) < 2:
        return
    try:
        state_machine.transition(
            store,
            finding_id,
            "corroborated",
            evidence_ids=[e.id for e in evidence],
            actor="correlator",
            reason="runtime finding corroborated by a static finding in the same handler",
        )
    except state_machine.IllegalTransition as exc:  # evidence rules say no — leave it
        log.warning("correlator.promote_skipped", finding_id=finding_id, error=str(exc))


# --------------------------------------------------------------------------- #
# P9.2 — build the graph from the store
# --------------------------------------------------------------------------- #
def build_graph(store: EvidenceStore, scan_id: str, handlers: list[Handler]) -> SecurityGraph:
    graph = SecurityGraph()
    dataflows = load_dataflows(store, scan_id)

    # code side: handlers, the endpoints they declare, the sinks they reach
    for h in handlers:
        graph.add_function(h.qualname, name=h.function, file=h.file, line=h.line)
        for method in h.methods:
            endpoint = graph.add_endpoint(normalize_route(method, h.path))
            graph.handled_by(endpoint, h.qualname, score=1.0, signals={"static_route_map": True}, origin="static")

    def containing(file: str | None, line: int | None) -> Handler | None:
        return next((h for h in handlers if h.contains(file, line)), None)

    for flow in dataflows:
        handler = next((h for h in handlers if _flow_belongs(flow, h)), None)
        if handler is not None and flow.sink_name and flow.file:
            sink = graph.add_sink(flow.file, flow.sink_line or flow.line or 0, flow.sink_name)
            graph.flows_to(handler.qualname, sink, flow.evidence_id)

    for ev in store.list_evidence(scan_id, kind="crypto_asset"):
        p = _payload(ev.payload_json)
        if p.get("algo"):
            asset = graph.add_crypto_asset(str(p["algo"]), str(p.get("file")), p.get("line"))
            owner = containing(p.get("file"), p.get("line"))
            if owner is not None:
                graph.uses(owner.qualname, asset, ev.id)
    for ev in store.list_evidence(scan_id, kind="dependency"):
        p = _payload(ev.payload_json)
        purl = p.get("purl") or (f"pkg:pypi/{p['package']}@{p.get('version', '')}" if p.get("package") else None)
        if purl:
            graph.add_library(purl)

    # findings (merged duplicates are absorbed into their primary and not drawn)
    hidden = merged_ids(store, scan_id)
    for f in sorted(store.list_findings(scan_id), key=lambda x: x.id):
        if f.id in hidden:
            continue
        graph.add_finding(
            f.id,
            weakness=f.type,
            owasp=f.owasp,
            state=f.state.value,
            risk=f.risk,
            correlation=f.correlation_score,
            merged=linked_to(store, f.id),
        )
        parsed = split_route(f.route or "") if f.route else None
        endpoint = normalize_route(*parsed) if parsed else None
        if endpoint:
            graph.add_endpoint(endpoint)
            graph.on(f.id, endpoint)

        handler = None
        if f.file and f.function:
            handler = next((h for h in handlers if h.file == f.file and h.function == f.function), None)
        if handler is None and f.file and f.line is not None:
            handler = containing(f.file, f.line)
        if handler is not None:
            graph.on(f.id, handler.qualname)

        if handler is not None and endpoint and parsed and f.correlation_score is not None:
            flows = [d for d in dataflows if d.finding_type == f.type]
            score, signals = link_score(RuntimeTarget(*parsed), handler, flows)
            graph.handled_by(endpoint, handler.qualname, score=score, signals=signals, origin="correlated")
    return graph
