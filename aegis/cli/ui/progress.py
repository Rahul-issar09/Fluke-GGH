"""Live scan progress and the end-of-scan summary (cli_new_phases.md N2).

One line per finished step as the API reports it (``GET /api/scans/{id}/events``), then a summary:
status and counts, the top findings by risk, the CI gate verdict, and where to look next.
Progress lines go to stdout for a person; with ``--json`` only the final summary is printed.
"""

from __future__ import annotations

import time
from typing import Callable

from aegis.cli.ui.output import Output
from aegis.cli.ui.views import findings_view, scan_status_view

__all__ = ["MODE_LABELS", "Progress", "summary_view"]

MODE_LABELS = {
    "M1": "M1 - live app only (runtime): tests the running app from outside as two test users",
    "M2": "M2 - code only (static): reads the code, never runs it",
    "M3": "M3 - full (code + running app, correlated): proves issues live and links each to its code line",
}

FINAL = ("completed", "failed", "cancelled")


class Progress:
    """Prints one line per progress event; remembers the final status."""

    def __init__(self, out: Output):
        self.out = out
        self.started = time.monotonic()
        self.final: str | None = None
        self.steps = 0

    def show(self, event: dict) -> None:
        if event.get("stage") == "scan" and event.get("status") in FINAL:
            self.final = event["status"]
            return
        self.steps += 1
        if self.out.json_mode:
            return
        elapsed = int(time.monotonic() - self.started)
        ms = event.get("ms")
        took = f"{ms / 1000:.1f}s" if isinstance(ms, (int, float)) else ""
        stage, node = event.get("stage") or "", event.get("node") or ""
        label = node if stage in ("", node) else f"{stage} / {node}"
        self.out.line(f"  [{elapsed // 60:02d}:{elapsed % 60:02d}]  {label:<34} {event.get('status', ''):<8} {took}")


def summary_view(scan: dict, findings: list[dict], gate: dict | None) -> Callable[[Output], None]:
    def render(out: Output) -> None:
        out.line()
        scan_status_view(scan)(out)
        if findings:
            out.line()
            findings_view(scan["id"], findings[:5], len(findings))(out)
        if gate is not None:
            verdict = {0: "PASSED", 1: "BLOCKED", 2: "NOT COMPLETE"}.get(gate["exit_code"], "?")
            blocking = ", ".join(gate.get("blocking_findings") or []) or "none"
            out.line()
            out.line(f"CI gate: {verdict} (exit {gate['exit_code']}); blocking findings: {blocking}")
        out.line()
        sid = scan["id"]
        out.line(f"Next:  aegis findings show <FINDING>   aegis report {sid} --open   aegis ask \"what should I fix first?\" --scan {sid}")
    return render
