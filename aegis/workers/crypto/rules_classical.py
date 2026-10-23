"""Classical crypto risk (Engine 3, AG15.1, PHASES P8.2) — deterministic rules over discovered assets.

Each rule says *why* an asset is weak against today's attackers. A flagged asset becomes a
``weak_crypto`` finding (A02). Nothing here uses the LLM.

| Asset                         | Flagged when                                                          |
|-------------------------------|-----------------------------------------------------------------------|
| hash                          | MD5 or SHA-1 (collisions); a fast hash used for passwords             |
| RSA / DSA / DH key            | shorter than 2048 bits                                                 |
| EC key                        | a curve under 224 bits (e.g. P-192)                                    |
| cipher                        | DES, 3DES, RC4, Blowfish, IDEA, RC2; ECB mode                          |
| TLS setting                   | allows anything older than TLS 1.2; cipher string with SECLEVEL=0, RC4, DES/3DES, NULL, EXPORT, anon or MD5 suites |
| random                        | the non-cryptographic ``random`` module making a secret                |
"""

from __future__ import annotations

import re

__all__ = ["classical_risk"]

_WEAK_HASHES = {"MD5": "MD5 is broken: collisions are trivial", "SHA-1": "SHA-1 is broken: practical collisions exist"}
_FAST_HASHES = {"SHA-224", "SHA-256", "SHA-384", "SHA-512", "SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512", "BLAKE2b", "BLAKE2s"}
_WEAK_CIPHERS = {"DES": "DES has a 56-bit key", "TripleDES": "3DES is deprecated (64-bit blocks, SWEET32)", "DES3": "3DES is deprecated (64-bit blocks, SWEET32)",
                 "ARC4": "RC4 has known keystream biases", "Blowfish": "Blowfish has 64-bit blocks", "IDEA": "IDEA has 64-bit blocks",
                 "ARC2": "RC2 is obsolete", "CAST5": "CAST5 has 64-bit blocks"}
_SMALL_CURVES = re.compile(r"(?i)(192|160|112|128)")
_OLD_TLS = {"SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1", "minimum supported"}
_WEAK_CIPHER_STRING = re.compile(r"(?i)(SECLEVEL=0|\bRC4\b|\b3?DES\b|\bNULL\b|\bEXPORT\b|\bEXP\b|\baNULL\b|\bADH\b|\bMD5\b|^ALL$|^ALL:)")


def classical_risk(asset: dict) -> str | None:
    """Why *asset* is weak today, or None."""
    algo, primitive = asset.get("algo", ""), asset.get("primitive")
    if primitive == "hash":
        if algo in _WEAK_HASHES:
            return _WEAK_HASHES[algo] + (" — and it is used for passwords" if asset.get("usage") == "password_hash" else "")
        if algo in _FAST_HASHES and asset.get("usage") == "password_hash":
            return f"{algo} is a fast, unsalted hash: passwords need a slow KDF (bcrypt, scrypt, Argon2, PBKDF2)"
        return None
    if primitive == "pke":
        family, size = asset.get("family"), asset.get("key_size")
        if family in ("RSA", "DSA", "DH") and size and size < 2048:
            return f"{family} key of {size} bits (at least 2048 required)"
        if family == "EC" and asset.get("curve") and _SMALL_CURVES.search(asset["curve"]):
            return f"elliptic curve {asset['curve']} is too small (at least 224 bits required)"
        return None
    if primitive in ("block-cipher", "stream-cipher"):
        if algo in _WEAK_CIPHERS:
            return _WEAK_CIPHERS[algo]
        if (asset.get("mode") or "").upper() == "ECB":
            return f"{algo} in ECB mode leaks patterns in the data"
        return None
    if asset.get("asset_type") == "protocol":
        if asset.get("protocol") in _OLD_TLS:
            return f"TLS settings allow {asset['protocol']}; TLS 1.2 is the minimum"
        ciphers = asset.get("ciphers") or ""
        if ciphers and _WEAK_CIPHER_STRING.search(ciphers):
            return f"cipher string '{ciphers}' enables legacy or broken cipher suites"
        return None
    if primitive == "drbg":
        return f"{algo} is predictable: secrets need the secrets module or os.urandom"
    return None
