"""Cryptography bill of materials (Engine 3, AG15.1, PHASES P8.4) — CycloneDX 1.6.

Every discovered crypto asset becomes a ``cryptographic-asset`` component with CycloneDX
``cryptoProperties`` (algorithm or protocol), where it occurs (file and line) and AEGIS's verdicts
as properties: ``aegis:classical_risk`` and ``aegis:quantum_risk`` (the reason, or ``none``), plus
``aegis:usage``. Live TLS endpoints scanned by sslyze are added as protocol assets with the
versions and cipher suites they accept. Saved per scan at ``<data_dir>/cbom/<scan_id>.json``.
"""

from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path

from aegis.workers.crypto.rules_classical import classical_risk
from aegis.workers.crypto.rules_quantum import quantum_risk

__all__ = ["build_cbom", "cbom_path", "write_cbom"]

_SECURITY_BITS = {"RSA": {1024: 80, 2048: 112, 3072: 128, 4096: 152, 7680: 192, 15360: 256}}
_HASH_BITS = {"MD5": 0, "SHA-1": 0, "SHA-224": 112, "SHA-256": 128, "SHA-384": 192, "SHA-512": 256}
_FUNCTIONS = {"hash": ["digest"], "pke": ["keygen"], "block-cipher": ["encrypt", "decrypt"], "stream-cipher": ["encrypt", "decrypt"], "drbg": ["generate"]}


def cbom_path(data_dir: str | Path, scan_id: str) -> Path:
    return Path(data_dir) / "cbom" / f"{scan_id}.json"


def _primitive(asset: dict) -> str:
    if asset.get("primitive") == "pke":
        return {"signature": "signature", "certificate": "signature", "encryption": "pke"}.get(asset.get("usage"), "pke")
    return asset.get("primitive") or "other"


def _algorithm_component(asset: dict) -> dict:
    props: dict = {"primitive": _primitive(asset), "executionEnvironment": "software-plain-ram", "cryptoFunctions": list(_FUNCTIONS.get(asset.get("primitive"), []))}
    if asset.get("key_size"):
        props["parameterSetIdentifier"] = str(asset["key_size"])
        level = _SECURITY_BITS.get(asset.get("family"), {}).get(asset["key_size"])
        if level is not None:
            props["classicalSecurityLevel"] = level
    if asset.get("curve"):
        props["curve"] = asset["curve"]
    if asset.get("mode"):
        props["mode"] = asset["mode"].lower()
    if asset.get("primitive") == "hash" and asset.get("algo") in _HASH_BITS:
        props["classicalSecurityLevel"] = _HASH_BITS[asset["algo"]]
    if asset.get("family") in ("RSA", "DSA", "DH", "EC", "Ed25519", "Ed448", "X25519", "X448"):
        props["nistQuantumSecurityLevel"] = 0
    return {"assetType": "algorithm", "algorithmProperties": props}


def _protocol_component(asset: dict) -> dict:
    props: dict = {"type": "tls"}
    if asset.get("protocol"):
        props["version"] = asset["protocol"]
    if asset.get("ciphers"):
        props["cipherSuites"] = [{"name": asset["ciphers"]}]
    return {"assetType": "protocol", "protocolProperties": props}


def _component(asset: dict) -> dict:
    classical, quantum = classical_risk(asset), quantum_risk(asset)
    name = asset["algo"] if asset.get("asset_type") != "protocol" else f"TLS {asset.get('setting', 'setting')}"
    return {
        "type": "cryptographic-asset",
        "bom-ref": f"crypto:{asset['algo']}@{asset['file']}:{asset['line']}",
        "name": name,
        "cryptoProperties": _protocol_component(asset) if asset.get("asset_type") == "protocol" else _algorithm_component(asset),
        "evidence": {"occurrences": [{"location": asset["file"], "line": asset["line"]}]},
        "properties": [
            {"name": "aegis:classical_risk", "value": classical or "none"},
            {"name": "aegis:quantum_risk", "value": quantum or "none"},
            {"name": "aegis:usage", "value": asset.get("usage", "unknown")},
        ],
    }


def _endpoint_component(endpoint: dict, issues: list[dict]) -> dict:
    accepted = endpoint.get("accepted") or {}
    old = [i for i in issues if i["issue"] == "old_protocol"]
    cipher_issues = [i for i in issues if i["issue"] in ("weak_ciphers", "no_forward_secrecy", "weak_certificate_key")]
    classical = "; ".join(i["title"] for i in (*old, *cipher_issues)) or "none"
    return {
        "type": "cryptographic-asset",
        "bom-ref": f"crypto:tls@{endpoint['target']}",
        "name": f"TLS endpoint {endpoint['target']}",
        "cryptoProperties": {
            "assetType": "protocol",
            "protocolProperties": {
                "type": "tls",
                "version": ", ".join(sorted(accepted)),
                "cipherSuites": [{"name": s} for s in sorted({s for names in accepted.values() for s in names})],
            },
        },
        "properties": [
            {"name": "aegis:classical_risk", "value": classical},
            # TLS key exchange today is classical (RSA / ECDHE): recorded sessions are exposed later
            {"name": "aegis:quantum_risk", "value": "key exchange is not post-quantum: recorded sessions could be decrypted later" if accepted else "none"},
            {"name": "aegis:endpoint", "value": endpoint["target"]},
        ],
    }


def build_cbom(scan_id: str, subject: str, assets: list[dict], endpoints: list[tuple[dict, list[dict]]]) -> dict:
    components = [_component(a) for a in assets] + [_endpoint_component(e, i) for e, i in endpoints if not e.get("error")]
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, 'aegis:' + scan_id)}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": {"components": [{"type": "application", "name": "AEGIS", "version": "0.1.0"}]},
            "component": {"type": "application", "name": subject, "bom-ref": f"scan:{scan_id}"},
            "properties": [{"name": "aegis:scan_id", "value": scan_id}],
        },
        "components": components,
    }


def write_cbom(data_dir: str | Path, scan_id: str, cbom: dict) -> Path:
    path = cbom_path(data_dir, scan_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(cbom, indent=2), encoding="utf-8")
    os.replace(tmp, path)
    return path
