"""Quantum risk (Engine 3, AG15.1, PHASES P8.3) — harvest-now, decrypt-later exposure.

Public-key cryptography based on factoring or discrete logarithms (RSA, DSA, DH, elliptic curves,
Ed25519/X25519…) is broken by a large quantum computer running Shor's algorithm, at any key size.
Data protected by it today can be recorded now and decrypted later, so every such asset is flagged
as a ``quantum_risk`` finding (A02, informational severity) whatever its size — the fix is a
migration plan to post-quantum algorithms (ML-KEM, ML-DSA), not a bigger key.

Symmetric ciphers and hashes are only weakened (Grover halves their strength); 128-bit keys are
noted in the CBOM but not flagged as findings.
"""

from __future__ import annotations

__all__ = ["QUANTUM_VULNERABLE", "quantum_risk"]

QUANTUM_VULNERABLE = {"RSA", "DSA", "DH", "EC", "Ed25519", "Ed448", "X25519", "X448"}

_WHY = {
    "signature": "signatures made with it can be forged once a large quantum computer exists",
    "certificate": "the certificate's signatures can be forged once a large quantum computer exists",
    "encryption": "data encrypted with it today can be recorded now and decrypted later",
    "key_management": "keys exchanged or wrapped with it today can be recorded now and recovered later",
}


def quantum_risk(asset: dict) -> str | None:
    family = asset.get("family")
    if asset.get("primitive") != "pke" or family not in QUANTUM_VULNERABLE:
        return None
    why = _WHY.get(asset.get("usage"), "it is broken by Shor's algorithm on a large quantum computer")
    return f"{asset.get('algo', family)} is not quantum-safe: {why}; plan a move to ML-KEM / ML-DSA"
