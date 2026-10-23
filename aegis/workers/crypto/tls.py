"""Live TLS posture (Engine 3, AG15.1, PHASES P8.5) — sslyze, and the link to the config line.

sslyze connects to each TLS endpoint of the scan (``host:port``, which must be on the scan's
allowlist — checked by the SafetyController like every other target) and reports which protocol
versions and cipher suites the server accepts and what certificate it presents. Issues:

* ``old_protocol`` — SSL 2/3, TLS 1.0 or 1.1 accepted;
* ``weak_ciphers`` — RC4, DES/3DES, NULL, EXPORT, anonymous or MD5 suites accepted;
* ``no_forward_secrecy`` — static-RSA key exchange suites accepted (TLS ≤ 1.2);
* ``weak_certificate_key`` — an RSA certificate key under 2048 bits.

Each issue is then **linked to the code that causes it** when the crypto discovery found it: an
old protocol to the TLS setting that allows it (``ctx.minimum_version = …``), cipher issues to a
cipher string the classical rules flagged (``ctx.set_ciphers(…)``). The finding then carries that
file and line, so it can be fixed where it is configured.
"""

from __future__ import annotations

import re

from aegis.observability import get_logger
from aegis.safety.models import ToolCall
from aegis.workers.crypto.rules_classical import classical_risk

__all__ = ["TlsUnavailable", "link_issue", "normalize_sslyze", "run_sslyze", "tls_issues"]

log = get_logger("workers.crypto.tls")

_VERSIONS = (("ssl_2_0", "SSLv2"), ("ssl_3_0", "SSLv3"), ("tls_1_0", "TLSv1.0"), ("tls_1_1", "TLSv1.1"), ("tls_1_2", "TLSv1.2"), ("tls_1_3", "TLSv1.3"))
_OLD = {"SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"}
_WEAK_SUITE = re.compile(r"(RC4|_DES_|3DES|_NULL_|EXPORT|_anon_|_MD5)")


class TlsUnavailable(RuntimeError):
    pass


def normalize_sslyze(report: dict) -> list[dict]:
    """One record per scanned endpoint: accepted versions and suites, certificate key."""
    out = []
    for server in (report or {}).get("server_scan_results") or []:
        loc = server.get("server_location") or {}
        target = f"{loc.get('hostname')}:{loc.get('port')}"
        if server.get("scan_status") != "COMPLETED":
            out.append({"target": target, "error": server.get("connectivity_error_trace") or server.get("scan_status")})
            continue
        result = server.get("scan_result") or {}
        accepted: dict[str, list[str]] = {}
        for key, name in _VERSIONS:
            suites = ((result.get(f"{key}_cipher_suites") or {}).get("result") or {}).get("accepted_cipher_suites") or []
            if suites:
                accepted[name] = sorted({s["cipher_suite"]["name"] for s in suites})
        cert = {}
        deployments = (((result.get("certificate_info") or {}).get("result") or {}).get("certificate_deployments")) or []
        if deployments:
            leaf = (deployments[0].get("received_certificate_chain") or [{}])[0]
            key = leaf.get("public_key") or {}
            cert = {"key_type": key.get("algorithm"), "key_size": key.get("key_size"), "signature": (leaf.get("signature_hash_algorithm") or {}).get("name")}
        out.append({"target": target, "accepted": accepted, "certificate": cert})
    return out


def tls_issues(endpoint: dict) -> list[dict]:
    """The weaknesses of one scanned endpoint."""
    if endpoint.get("error"):
        return []
    accepted = endpoint.get("accepted") or {}
    issues = []
    old = [v for v in accepted if v in _OLD]
    if old:
        issues.append({"issue": "old_protocol", "title": f"Server accepts {', '.join(old)}", "versions": old})
    suites = sorted({s for v, names in accepted.items() for s in names})
    weak = [s for s in suites if _WEAK_SUITE.search(s)]
    if weak:
        issues.append({"issue": "weak_ciphers", "title": f"Server accepts {len(weak)} broken cipher suites", "suites": weak})
    static_rsa = [s for s in suites if s.startswith("TLS_RSA_WITH_")]
    if static_rsa:
        issues.append({"issue": "no_forward_secrecy", "title": f"Server accepts {len(static_rsa)} suites without forward secrecy", "suites": static_rsa})
    cert = endpoint.get("certificate") or {}
    if cert.get("key_type") and "RSA" in str(cert["key_type"]) and cert.get("key_size") and cert["key_size"] < 2048:
        issues.append({"issue": "weak_certificate_key", "title": f"Certificate key is RSA-{cert['key_size']}", "certificate": cert})
    return issues


def link_issue(issue: dict, assets: list[dict]) -> dict | None:
    """The TLS setting in the code that causes *issue*, if the crypto discovery found it."""
    tls = [a for a in assets if a.get("asset_type") == "protocol"]
    if issue["issue"] == "old_protocol":
        return next((a for a in tls if a.get("setting") in ("minimum_version", "protocol") and a.get("protocol") in (*_OLD, "minimum supported")), None)
    if issue["issue"] in ("weak_ciphers", "no_forward_secrecy"):
        return next((a for a in tls if a.get("setting") == "ciphers" and classical_risk(a)), None)
    return None


async def run_sslyze(controller, scan_id: str, target: str) -> list[dict]:
    result = await controller.run(ToolCall(tool="sslyze", scan_id=scan_id, target_host=target, args={"host": target}))
    if result.blocked_reason:
        raise TlsUnavailable(result.blocked_reason)
    if not result.ok:
        raise TlsUnavailable(f"sslyze failed: {(result.stderr_tail or '').strip()[:200]}")
    endpoints = normalize_sslyze(result.output if isinstance(result.output, dict) else {})
    log.info("tls.scanned", scan_id=scan_id, target=target, accepted={e["target"]: sorted(e.get("accepted", {})) for e in endpoints})
    return endpoints
