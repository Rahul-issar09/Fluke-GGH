"""Nuclei adapter (PHASES P6.8).

Maps Nuclei ``-jsonl`` results to ``misconfig`` **candidate** findings (one
tool signal; Nuclei matches are not reproduced by AEGIS itself). The template id
and matcher go into the fingerprint so two templates matching the same path stay
two findings.

Only the structured fields (template id, name, severity, matched URL path) are
kept — never ``curl-command``, ``request`` or ``response``, which can carry
headers or target content.
"""

from __future__ import annotations

from urllib.parse import urlparse

from aegis.evidence.adapters.base import Adapter, EvidenceDraft, FindingDraft

__all__ = ["NucleiAdapter"]

_TOOL_VERSION = "nuclei-v3"
_SEVERITY = {"info": 0.1, "low": 0.3, "medium": 0.5, "high": 0.7, "critical": 0.9}


def _path(matched_at: str | None) -> str:
    if not matched_at:
        return "/"
    return urlparse(matched_at).path or "/"


class NucleiAdapter(Adapter):
    tool = "nuclei"

    def __init__(self, mode: str | None = None):
        self._mode = mode

    def parse(self, raw, scan_id):
        items = raw if isinstance(raw, list) else []
        out: list[tuple[FindingDraft, list[EvidenceDraft]]] = []
        for item in items:
            if not isinstance(item, dict) or not item.get("template-id"):
                continue
            info = item.get("info") or {}
            template_id = str(item["template-id"])
            matcher = str(item.get("matcher-name") or "")
            path = _path(item.get("matched-at"))
            template = f"GET {path}"
            severity_label = str(info.get("severity", "info")).lower()

            draft = FindingDraft(
                type="misconfig",
                owasp="A05",
                title=str(info.get("name") or template_id),
                route=template,
                severity=_SEVERITY.get(severity_label, 0.1),
                source="worker1.nuclei",
                mode=self._mode,
                variant=f"{template_id}:{matcher}",
            )
            evidence = EvidenceDraft(
                kind="http_exchange",
                tool="nuclei",
                tool_version=_TOOL_VERSION,
                payload={
                    "method": "GET",
                    "route": path,
                    "route_template": template,
                    "template_id": template_id,
                    "matcher": matcher,
                    "severity": severity_label,
                    "auth_context": "unauthenticated",  # nuclei is run without any session
                    "status": None,
                    "request": template,
                },
            )
            out.append((draft, [evidence]))
        return out
