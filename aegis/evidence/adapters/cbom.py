"""Crypto adapters (Engine 3, AG15.1): flagged crypto assets and live TLS issues → findings.

* ``CryptoAdapter`` — a classically weak asset → ``weak_crypto`` (A02); a quantum-vulnerable one →
  ``quantum_risk`` (A02). Evidence: ``crypto_asset`` (the asset and the reason). One finding per
  asset and kind; the algorithm is the fingerprint variant.
* ``TlsAdapter`` — a live TLS issue → ``weak_tls`` (A02). Evidence: ``tls_scan`` (what sslyze saw)
  and, when the issue is linked to the setting that causes it, that ``crypto_asset`` — the finding
  then sits on the setting's file and line.
"""

from __future__ import annotations

from aegis.evidence.adapters.base import Adapter, EvidenceDraft, FindingDraft

__all__ = ["CryptoAdapter", "TlsAdapter"]


class CryptoAdapter(Adapter):
    tool = "crypto"

    def __init__(self, kind: str, mode: str | None = None):
        if kind not in ("weak_crypto", "quantum_risk"):
            raise ValueError(kind)
        self._kind = kind
        self._mode = mode

    def parse(self, raw, scan_id):
        out = []
        for asset, reason in raw if isinstance(raw, list) else []:
            draft = FindingDraft(
                type=self._kind,
                owasp="A02",
                title=(f"Weak cryptography: {reason}" if self._kind == "weak_crypto" else f"Quantum risk: {reason}"),
                file=asset.get("file"),
                line=asset.get("line"),
                function=asset.get("function"),
                severity=0.6 if self._kind == "weak_crypto" else 0.4,
                source="worker3.crypto",
                mode=self._mode,
                variant=str(asset.get("algo", "")),
            )
            evidence = EvidenceDraft(kind="crypto_asset", tool="crypto-discovery", payload={**asset, "flag": self._kind, "reason": reason})
            out.append((draft, [evidence]))
        return out


class TlsAdapter(Adapter):
    tool = "sslyze"

    def __init__(self, mode: str | None = None):
        self._mode = mode

    def parse(self, raw, scan_id):
        out = []
        for endpoint, issue, linked in raw if isinstance(raw, list) else []:
            draft = FindingDraft(
                type="weak_tls",
                owasp="A02",
                title=f"{issue['title']} ({endpoint['target']})",
                file=linked.get("file") if linked else None,
                line=linked.get("line") if linked else None,
                function=linked.get("function") if linked else None,
                severity=0.6,
                source="worker3.sslyze",
                mode=self._mode,
                variant=f"{issue['issue']}@{endpoint['target']}",
            )
            evidence = [
                EvidenceDraft(
                    kind="tls_scan",
                    tool="sslyze",
                    payload={
                        "target": endpoint["target"],
                        "issue": issue["issue"],
                        "protocol": ", ".join(issue.get("versions", [])) or None,
                        "accepted_versions": sorted(endpoint.get("accepted", {})),
                        "suites": issue.get("suites", [])[:40],
                        "certificate": endpoint.get("certificate"),
                        "linked_setting": f"{linked['file']}:{linked['line']}" if linked else None,
                    },
                )
            ]
            if linked:
                evidence.append(EvidenceDraft(kind="crypto_asset", tool="crypto-discovery", payload={**linked, "role": "tls_setting_causing_issue"}))
            out.append((draft, evidence))
        return out
