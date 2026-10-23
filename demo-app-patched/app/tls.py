"""HTTPS settings for the demo — patched: TLS 1.2 or newer with modern cipher suites only."""
from __future__ import annotations

import ssl


def server_context(certfile: str, keyfile: str) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2  # FIX: no TLS 1.0 / 1.1
    ctx.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20")  # FIX: forward-secret AEAD suites only
    ctx.load_cert_chain(certfile, keyfile)
    return ctx
