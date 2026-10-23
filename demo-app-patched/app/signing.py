"""Receipt signing — patched: a 3072-bit RSA key with SHA-256 and PSS padding.

(RSA is still exposed to future quantum computers; moving to a post-quantum signature scheme is
the long-term fix, which is why the crypto report keeps a quantum-risk flag on it.)
"""
from __future__ import annotations

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

_KEY = None


def signing_key():
    global _KEY
    if _KEY is None:
        _KEY = rsa.generate_private_key(public_exponent=65537, key_size=3072)  # FIX: 3072-bit key
    return _KEY


def sign_receipt(data: bytes) -> bytes:
    pss = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)
    return signing_key().sign(data, pss, hashes.SHA256())  # FIX: SHA-256 with PSS
