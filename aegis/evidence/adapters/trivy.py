"""Trivy adapter (PHASES P7.6).

* Vulnerable packages → ``vulnerable_dependency`` (A06), merged with OSV's finding for the same
  package version (same fingerprint variant).
* Misconfigurations (e.g. a Dockerfile that runs as root) → ``misconfig`` (A05), one finding per
  check per file; the check ID is the fingerprint variant.
"""

from __future__ import annotations

from aegis.evidence.adapters.base import Adapter, EvidenceDraft, FindingDraft
from aegis.evidence.adapters.osv import dependency_draft

__all__ = ["TrivyAdapter"]


class TrivyAdapter(Adapter):
    tool = "trivy"

    def __init__(self, mode: str | None = None, db_date: str | None = None):
        self._mode = mode
        self._db_date = db_date

    def parse(self, raw, scan_id):
        vulns, misconfigs = raw if isinstance(raw, tuple) else ([], [])
        out = []
        for row in vulns:
            evidence = EvidenceDraft(
                kind="dependency",
                tool="trivy",
                db_date=self._db_date,
                payload={k: row.get(k) for k in ("package", "version", "ecosystem", "manifest", "line", "advisories", "fixed_in", "severities")},
            )
            out.append((dependency_draft(row, source="worker2.trivy", mode=self._mode), [evidence]))
        for m in misconfigs:
            draft = FindingDraft(
                type="misconfig",
                owasp="A05",
                title=f"{m.get('check')}: {m.get('title') or 'misconfiguration'}",
                file=m.get("file"),
                line=m.get("line"),
                severity=0.4,
                source="worker2.trivy",
                mode=self._mode,
                variant=str(m.get("check") or ""),
            )
            evidence = EvidenceDraft(
                kind="code_location",
                tool="trivy",
                payload={
                    "file": m.get("file"),
                    "line": m.get("line"),
                    "rule": m.get("check"),
                    "severity": m.get("severity"),
                    "note": m.get("message"),
                    "resolution": m.get("resolution"),
                },
            )
            out.append((draft, [evidence]))
        return out
