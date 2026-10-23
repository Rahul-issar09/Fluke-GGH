"""TruffleHog adapter (PHASES P7.6) — ``secret`` findings (A05).

Input is already cleaned by ``workers.code.trufflehog`` (no secret value at all). The finding
has the same fingerprint as gitleaks' finding for the same file and line, so the two scanners
agreeing on a leak corroborate one finding instead of creating two.
"""

from __future__ import annotations

from aegis.evidence.adapters.base import Adapter, EvidenceDraft, FindingDraft

__all__ = ["TrufflehogAdapter"]


class TrufflehogAdapter(Adapter):
    tool = "trufflehog"

    def __init__(self, mode: str | None = None):
        self._mode = mode

    def parse(self, raw, scan_id):
        out = []
        for row in raw if isinstance(raw, list) else []:
            draft = FindingDraft(
                type="secret",
                owasp="A05",
                title=f"{row.get('detector')} secret",
                file=row.get("file"),
                line=row.get("line"),
                severity=0.8,
                source="worker2.trufflehog",
                mode=self._mode,
            )
            evidence = EvidenceDraft(
                kind="secret",
                tool="trufflehog",
                payload={
                    "file": row.get("file"),
                    "line": row.get("line"),
                    "rule": row.get("detector"),
                    "value": "***REDACTED***",
                    # never True here: verification is refused by policy (it would use the secret)
                    "verified": bool(row.get("verified")),
                },
            )
            out.append((draft, [evidence]))
        return out
