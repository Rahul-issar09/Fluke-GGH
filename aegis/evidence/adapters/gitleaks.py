"""Gitleaks adapter (PHASES P5.4).

Maps Gitleaks JSON to ``secret`` findings. The raw secret value is NEVER
stored in plaintext — only a redacted marker and a short fingerprint of the
value are kept, so the store and logs never carry the secret.
"""

from __future__ import annotations

import hashlib

from aegis.evidence.adapters.base import Adapter, EvidenceDraft, FindingDraft

__all__ = ["GitleaksAdapter"]


def _fp(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()[:12] if secret else ""


class GitleaksAdapter(Adapter):
    tool = "gitleaks"

    def __init__(self, mode: str | None = None):
        self._mode = mode

    def parse(self, raw, scan_id):
        items = raw if isinstance(raw, list) else []
        out: list[tuple[FindingDraft, list[EvidenceDraft]]] = []
        for it in items:
            file = it.get("File")
            line = it.get("StartLine")
            rule = it.get("RuleID", "secret")
            draft = FindingDraft(
                type="secret",
                owasp="A05",
                title=it.get("Description", rule),
                file=file,
                line=line,
                severity=0.8,
                source="worker2.gitleaks",
                mode=self._mode,
            )
            evidence = [
                EvidenceDraft(
                    kind="secret",
                    tool="gitleaks",
                    payload={
                        "file": file,
                        "line": line,
                        "rule": rule,
                        "value": "***REDACTED***",
                        "value_fingerprint": _fp(it.get("Secret", "")),
                        "verified": False,
                    },
                )
            ]
            out.append((draft, evidence))
        return out
