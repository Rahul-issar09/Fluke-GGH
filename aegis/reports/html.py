"""HTML report (AG12.1, PHASES P13.7) — the main human-readable output.

One self-contained file rendered from the JSON report: inline CSS, an inline SVG for the
attack paths, no scripts, no fonts, no external URL — it opens offline from disk. Every value
is HTML-escaped (Jinja autoescape): evidence excerpts come from the target and must never be
able to inject markup into the report.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, StrictUndefined
from markupsafe import Markup, escape

from aegis.observability import get_logger

__all__ = ["attack_path_svg", "render_html"]

log = get_logger("reports.html")

TEMPLATES = Path(__file__).with_name("templates")
_PAYLOAD_CHARS = 6000

# attack-path drawing
_BOX_W, _BOX_H, _GAP_X, _ROW_H, _PAD = 210, 38, 46, 62, 16
_LABEL_CHARS = 30


def _label(text: str) -> str:
    return text if len(text) <= _LABEL_CHARS else text[: _LABEL_CHARS - 1] + "…"


def attack_path_svg(paths: list[list[str]], finding_ids: set[str]) -> Markup:
    """Each path as a row of boxes joined by arrows; a finding box links to its section."""
    if not paths:
        return Markup('<p class="muted">No attack path: no finding is linked to an endpoint or code path.</p>')
    columns = max(len(p) for p in paths)
    width = _PAD * 2 + columns * _BOX_W + (columns - 1) * _GAP_X
    height = _PAD * 2 + len(paths) * _ROW_H - (_ROW_H - _BOX_H)
    parts = [
        f'<svg role="img" aria-label="Attack paths" '
        f'viewBox="0 0 {width} {height}" width="{width}" height="{height}" class="paths">',
        '<defs><marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto">'
        '<path d="M0,0 L10,5 L0,10 z" class="arrowhead"/></marker></defs>',
    ]
    for row, path in enumerate(paths):
        y = _PAD + row * _ROW_H
        for col, node in enumerate(path):
            x = _PAD + col * (_BOX_W + _GAP_X)
            is_finding = node in finding_ids
            box = (
                f'<rect x="{x}" y="{y}" width="{_BOX_W}" height="{_BOX_H}" rx="6" class="{"node finding" if is_finding else "node"}"/>'
                f'<text x="{x + _BOX_W / 2}" y="{y + _BOX_H / 2 + 5}" text-anchor="middle">{escape(_label(node))}</text>'
                f"<title>{escape(node)}</title>"
            )
            parts.append(f'<a href="#{escape(node)}">{box}</a>' if is_finding else box)
            if col < len(path) - 1:
                x1, x2, ym = x + _BOX_W, x + _BOX_W + _GAP_X - 4, y + _BOX_H / 2
                parts.append(f'<line x1="{x1}" y1="{ym}" x2="{x2}" y2="{ym}" class="edge" marker-end="url(#arrow)"/>')
    parts.append("</svg>")
    return Markup("".join(parts))


def _pretty(payload: Any) -> str:
    text = json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True, default=str)
    if len(text) > _PAYLOAD_CHARS:
        text = text[:_PAYLOAD_CHARS] + f"\n… ({len(text) - _PAYLOAD_CHARS} more characters in the JSON report)"
    return text


def _environment() -> Environment:
    env = Environment(
        loader=FileSystemLoader(str(TEMPLATES)),
        autoescape=True,  # everything is escaped unless explicitly marked safe (only our own SVG is)
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.filters["pretty"] = _pretty
    env.filters["pct"] = lambda v: f"{(v or 0) * 100:.0f}%"
    env.filters["num"] = lambda v: "—" if v is None else f"{v:g}"
    return env


def render_html(report: dict) -> str:
    finding_ids = {f["id"] for f in report["findings"]}
    evidence_ids = {e["id"] for e in report["evidence"]}
    html = _environment().get_template("report.html.j2").render(
        report=report,
        scan=report["scan"],
        findings=report["findings"],
        evidence=report["evidence"],
        evidence_ids=evidence_ids,
        paths_svg=attack_path_svg(report["attack_paths"], finding_ids),
        parts=("what", "where", "impact", "exploit"),
    )
    log.info("report.html_rendered", scan_id=report["scan"]["id"], bytes=len(html))
    return html
