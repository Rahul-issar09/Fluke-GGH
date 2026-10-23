"""Receipt signing — INTENTIONALLY WEAK (planted cryptography weaknesses for the crypto worker)."""
from __future__ import annotations

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

_KEY = None


def signing_key():
    global _KEY
    if _KEY is None:
        # PLANTED WEAKNESS: a 1024-bit RSA key — too short today, and RSA of any size is exposed to
        # future quantum computers (signatures and key exchange recorded now can be broken later).
        _KEY = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    return _KEY


def sign_receipt(data: bytes) -> bytes:
    # PLANTED WEAKNESS: SHA-1 signatures (collisions are practical).
    return signing_key().sign(data, padding.PKCS1v15(), hashes.SHA1())
