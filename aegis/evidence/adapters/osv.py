"""OSV-Scanner adapter (PHASES P7.6).

One ``vulnerable_dependency`` finding per package version (A06), located at the manifest line
that pins it, with ``dependency`` evidence listing the advisory IDs. The fingerprint variant is
``package@version``, so OSV and Trivy reports of the same package merge into one finding — two
independent databases agreeing corroborates it.
"""

from __future__ import annotations

from aegis.evidence.adapters.base import Adapter, EvidenceDraft, FindingDraft

__all__ = ["OsvAdapter", "dependency_draft"]


def dependency_draft(row: dict, *, source: str, mode: str | None) -> FindingDraft:
    advisories = row.get("advisories") or []
    head = ", ".join(advisories[:3]) + (f" and {len(advisories) - 3} more" if len(advisories) > 3 else "")
    return FindingDraft(
        type="vulnerable_dependency",
        owasp="A06",
        title=f"{row['package']} {row.get('version')} has known vulnerabilities ({head})",
        file=row.get("manifest"),
        line=row.get("line"),
        severity=0.7,
        source=source,
        mode=mode,
        variant=f"{str(row['package']).lower()}@{row.get('version')}",
    )


class OsvAdapter(Adapter):
    tool = "osv"

    def __init__(self, mode: str | None = None, db_date: str | None = None):
        self._mode = mode
        self._db_date = db_date

    def parse(self, raw, scan_id):
        out = []
        for row in raw if isinstance(raw, list) else []:
            evidence = EvidenceDraft(
                kind="dependency",
                tool="osv-scanner",
                db_date=self._db_date,
                payload={
                    "package": row["package"],
                    "version": row.get("version"),
                    "ecosystem": row.get("ecosystem"),
                    "manifest": row.get("manifest"),
                    "line": row.get("line"),
                    "advisories": row.get("advisories", []),
                    "aliases": row.get("aliases", []),
                    "fixed_in": row.get("fixed_in", []),
                    "severities": row.get("severities", []),
                    "summaries": row.get("summaries", []),
                },
            )
            out.append((dependency_draft(row, source="worker2.osv", mode=self._mode), [evidence]))
        return out
