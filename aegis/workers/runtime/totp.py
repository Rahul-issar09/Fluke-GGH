"""Time-based one-time passwords (RFC 6238, HMAC-SHA1) for test identities that use two-factor login.

The seed comes from the identities file (``totp_secret``) and never leaves the login step.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import struct
import time

__all__ = ["totp"]


def totp(secret: str, at: float | None = None, *, step: int = 30, digits: int = 6) -> str:
    """The code for base32 *secret* at time *at* (now by default)."""
    key = base64.b32decode(secret.strip().replace(" ", "").upper() + "=" * (-len(secret.strip().replace(" ", "")) % 8))
    counter = int((time.time() if at is None else at) // step)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % 10**digits
    return str(code).zfill(digits)
