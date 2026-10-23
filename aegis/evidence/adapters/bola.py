"""Differential access-control adapter (PHASES P6.6).

Turns the raw result of the replay check (P6.5) into a finding draft plus one
``http_exchange`` evidence. Only vulnerable results produce a finding.

The evidence payload carries a request *description* (method + path + identity
label) — never cookies, tokens or credentials — and a bounded excerpt of the
response. It is operator evidence: the LLM only ever sees its digest.
"""

from __future__ import annotations

from aegis.evidence.adapters.base import Adapter, EvidenceDraft, FindingDraft

__all__ = ["BolaAdapter"]

_TOOL_VERSION = "0.1.0"


class BolaAdapter(Adapter):
    tool = "bola"

    def __init__(self, mode: str | None = None):
        self._mode = mode

    def parse(self, raw, scan_id):
        results = raw if isinstance(raw, list) else [raw]
        out: list[tuple[FindingDraft, list[EvidenceDraft]]] = []
        for result in results:
            if not result or not result.get("vulnerable"):
                continue
            replay = result["replay"]
            baseline = result["baseline"]
            template = result["route"]
            path = result.get("path", template)
            draft = FindingDraft(
                type="broken_access_control",
                owasp="A01",
                title=f"Broken object-level access control on {template}",
                route=template,
                severity=0.9,
                source="worker1.bola",
                mode=self._mode,
            )
            evidence = EvidenceDraft(
                kind="http_exchange",
                tool="bola",
                tool_version=_TOOL_VERSION,
                payload={
                    "method": template.split(" ", 1)[0],
                    "route": path,
                    "route_template": template,
                    "object_id": result.get("object_id"),
                    "identity": replay["identity"],
                    "auth_context": "authenticated",  # reproduced as a logged-in identity (risk: exposure)
                    "status": replay["status"],
                    "timing_ms": replay.get("timing_ms"),
                    "contains_owner_fields": bool(replay.get("contains_owner_fields")),
                    "baseline": {"identity": baseline["identity"], "status": baseline["status"]},
                    "request": f"{template.split(' ', 1)[0]} {path} (as identity {replay['identity']})",
                    "response": replay.get("response_excerpt", ""),
                },
            )
            out.append((draft, [evidence]))
        return out
