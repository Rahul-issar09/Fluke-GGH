"""HTTPS settings for the demo — INTENTIONALLY WEAK (planted TLS weaknesses)."""
from __future__ import annotations

import ssl


def server_context(certfile: str, keyfile: str) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1  # PLANTED WEAKNESS: TLS 1.0 and 1.1 are still accepted
    ctx.set_ciphers("ALL:@SECLEVEL=0")  # PLANTED WEAKNESS: legacy cipher suites are allowed
    ctx.load_cert_chain(certfile, keyfile)
    return ctx
