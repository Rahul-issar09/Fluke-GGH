"""Crypto discovery (Worker 3 / Engine 3, AG15.1, PHASES P8.1) — what cryptography the code uses.

The local rules in ``rules/crypto`` find *where* cryptography is used (semgrep, through the
SafetyController). Semgrep's free CLI does not return the matched code or metavariable values, so
the details — algorithm, key size, curve, mode, TLS version, cipher string — are read from the
source at each reported position with ``ast`` (parsed, never executed). The enclosing function and
assignment names give the asset's *usage* (password hashing, signing, tokens, TLS…).

An asset: ``{"asset_type", "algo", "primitive", "key_size", "curve", "mode", "protocol",
"ciphers", "usage", "file", "line", "function"}`` (unused keys are omitted).
"""

from __future__ import annotations

import ast
from pathlib import Path

from aegis.evidence.adapters.semgrep import rule_id
from aegis.observability import get_logger
from aegis.workers.code.semgrep import run_semgrep

__all__ = ["CRYPTO_RULES_DIR", "asset_at", "discover_assets", "run_discovery"]

log = get_logger("workers.crypto.discover")

CRYPTO_RULES_DIR = Path(__file__).resolve().parents[3] / "rules" / "crypto"

_HASH_NAMES = {
    "md5": "MD5", "sha1": "SHA-1", "sha224": "SHA-224", "sha256": "SHA-256", "sha384": "SHA-384", "sha512": "SHA-512",
    "sha3_224": "SHA3-224", "sha3_256": "SHA3-256", "sha3_384": "SHA3-384", "sha3_512": "SHA3-512",
    "blake2b": "BLAKE2b", "blake2s": "BLAKE2s",
}
_PK = {
    "rsa": "RSA", "dsa": "DSA", "ec": "EC", "dh": "DH", "ed25519": "Ed25519", "ed448": "Ed448", "x25519": "X25519", "x448": "X448",
    "RSA": "RSA", "DSA": "DSA", "ECC": "EC",
}
_TLS_VERSIONS = {
    "SSLv2": "SSLv2", "SSLv3": "SSLv3", "TLSv1": "TLSv1.0", "TLSv1_1": "TLSv1.1", "TLSv1_2": "TLSv1.2", "TLSv1_3": "TLSv1.3",
    "MINIMUM_SUPPORTED": "minimum supported", "MAXIMUM_SUPPORTED": "maximum supported",
    "PROTOCOL_SSLv2": "SSLv2", "PROTOCOL_SSLv3": "SSLv3", "PROTOCOL_TLSv1": "TLSv1.0", "PROTOCOL_TLSv1_1": "TLSv1.1",
    "PROTOCOL_TLSv1_2": "TLSv1.2", "PROTOCOL_TLS": "negotiated", "PROTOCOL_TLS_SERVER": "negotiated", "PROTOCOL_TLS_CLIENT": "negotiated",
}
_USAGES = (
    ("password", "password_hash"), ("passwd", "password_hash"), ("sign", "signature"), ("verify", "signature"),
    ("token", "token"), ("session", "token"), ("nonce", "token"), ("otp", "token"), ("salt", "token"),
    ("cert", "certificate"), ("tls", "tls_config"), ("ssl", "tls_config"), ("encrypt", "encryption"), ("decrypt", "encryption"),
    ("key", "key_management"),
)


def _const(node) -> object:
    return node.value if isinstance(node, ast.Constant) else None


def _dotted(node) -> str:
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


def _kw(call: ast.Call, name: str):
    return next((k.value for k in call.keywords if k.arg == name), None)


def _node_at(tree: ast.Module, line: int, col: int, end_line: int, end_col: int):
    """The node exactly spanning the match (semgrep columns are 1-based), else the smallest covering one."""
    best = None
    for node in ast.walk(tree):
        if not hasattr(node, "lineno") or not hasattr(node, "end_lineno"):
            continue
        start, end = (node.lineno, node.col_offset + 1), (node.end_lineno, (node.end_col_offset or 0) + 1)
        if start == (line, col) and end == (end_line, end_col):
            return node
        if start <= (line, col) and end >= (end_line, end_col):
            if best is None or (node.end_lineno - node.lineno, node.end_col_offset - node.col_offset) < (best.end_lineno - best.lineno, best.end_col_offset - best.col_offset):
                best = node
    return best


def _context(tree: ast.Module, line: int) -> tuple[str | None, str]:
    """``(enclosing function, text used to guess the usage)``."""
    fn = None
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.lineno <= line <= (node.end_lineno or node.lineno):
            if fn is None or node.lineno > fn.lineno:
                fn = node
    names = [fn.name] if fn else []
    for node in ast.walk(fn or tree):
        if isinstance(node, ast.Assign) and node.lineno == line:
            names += [t.id for t in node.targets if isinstance(t, ast.Name)]
    return (fn.name if fn else None), " ".join(names).lower()


def _usage(hint: str, default: str) -> str:
    return next((usage for word, usage in _USAGES if word in hint), default)


def asset_at(rule: str, tree: ast.Module, start: dict, end: dict) -> dict | None:
    """The crypto asset matched by *rule* at the given semgrep positions, or None if unreadable."""
    node = _node_at(tree, start["line"], start["col"], end["line"], end["col"])
    if isinstance(node, ast.Expr):  # a call used as a statement spans exactly like its statement
        node = node.value
    if node is None:
        return None
    function, hint = _context(tree, start["line"])
    asset: dict = {"line": start["line"], "function": function}

    if rule == "crypto-hash" and isinstance(node, ast.Call):
        name = _dotted(node.func)
        if name.endswith(".new") and node.args:
            algo = str(_const(node.args[0]) or "").lower()
        else:
            algo = name.split(".")[-1].lower()
        asset.update(asset_type="algorithm", primitive="hash", algo=_HASH_NAMES.get(algo, algo.upper()), usage=_usage(hint, "hashing"))
        return asset

    if rule == "crypto-public-key" and isinstance(node, ast.Call):
        name = _dotted(node.func)
        family = _PK.get(name.split(".")[0], name.split(".")[0])
        size = _const(_kw(node, "key_size")) or (_const(node.args[0]) if node.args and family in ("RSA", "DSA") else None)
        curve = None
        if family == "EC":
            arg = node.args[0] if node.args else _kw(node, "curve")
            curve = (_dotted(arg.func) if isinstance(arg, ast.Call) else (_const(arg) or _dotted(arg))).split(".")[-1] if arg is not None else None
        algo = f"{family}-{size}" if size else (f"ECDSA-{curve}" if curve else family)
        asset.update(asset_type="algorithm", primitive="pke", algo=algo, family=family, usage=_usage(hint, "key_management"))
        if size:
            asset["key_size"] = int(size)
        if curve:
            asset["curve"] = str(curve)
        return asset

    if rule == "crypto-cipher" and isinstance(node, ast.Call):
        name = _dotted(node.func)
        if name == "Cipher" and node.args:
            algo = _dotted(node.args[0].func).split(".")[-1] if isinstance(node.args[0], ast.Call) else "unknown"
            mode = _dotted(node.args[1].func).split(".")[-1] if len(node.args) > 1 and isinstance(node.args[1], ast.Call) else None
        elif name.endswith(".new"):
            algo, mode = name.split(".")[0], (_dotted(node.args[1]).split(".")[-1].replace("MODE_", "") if len(node.args) > 1 else None)
        else:
            algo, mode = name.split(".")[-1], None
        asset.update(asset_type="algorithm", primitive="block-cipher" if algo not in ("ARC4", "ChaCha20", "Salsa20") else "stream-cipher",
                     algo=algo, usage=_usage(hint, "encryption"))
        if mode:
            asset["mode"] = mode
        return asset

    if rule == "crypto-tls":
        if isinstance(node, ast.Assign):  # ctx.minimum_version = ssl.TLSVersion.TLSv1
            version = _dotted(node.value).split(".")[-1]
            asset.update(asset_type="protocol", algo="TLS", setting="minimum_version", protocol=_TLS_VERSIONS.get(version, version))
        elif isinstance(node, ast.Call) and _dotted(node.func).endswith("set_ciphers"):
            asset.update(asset_type="protocol", algo="TLS", setting="ciphers", ciphers=str(_const(node.args[0]) if node.args else ""))
        elif isinstance(node, ast.Call):  # ssl.SSLContext(ssl.PROTOCOL_…) / wrap_socket(ssl_version=…)
            arg = node.args[0] if node.args else _kw(node, "ssl_version")
            proto = _dotted(arg).split(".")[-1] if arg is not None else ""
            asset.update(asset_type="protocol", algo="TLS", setting="protocol", protocol=_TLS_VERSIONS.get(proto, proto))
        else:
            return None
        asset["usage"] = "tls_config"
        return asset

    if rule == "crypto-random":
        call = node.value if isinstance(node, (ast.Assign, ast.Return)) else node
        asset.update(asset_type="algorithm", primitive="drbg", algo=f"random.{_dotted(getattr(call, 'func', call)).split('.')[-1]}",
                     usage=_usage(hint, "token"))
        return asset
    return None


def discover_assets(results: list[dict], source_root: Path) -> tuple[list[dict], list[dict]]:
    """``(assets, unreadable)`` from semgrep results of the crypto rules."""
    trees: dict[str, ast.Module | None] = {}
    assets, unreadable = [], []
    for r in results:
        rel = r["path"]
        if rel not in trees:
            try:
                trees[rel] = ast.parse((source_root / rel).read_bytes().decode("utf-8", "replace"))
            except (OSError, SyntaxError, ValueError):
                trees[rel] = None
        asset = asset_at(rule_id(r.get("check_id", "")).split(".")[-1], trees[rel], r["start"], r["end"]) if trees[rel] else None
        if asset is None:
            unreadable.append({"file": rel, "line": r["start"]["line"], "rule": r.get("check_id")})
            continue
        asset["file"] = rel
        assets.append(asset)
    assets.sort(key=lambda a: (a["file"], a["line"], a["algo"]))
    return assets, unreadable


async def run_discovery(controller, scan_id: str, source_root: str | Path, *, only_file: str | None = None) -> list[dict]:
    root = Path(source_root)
    results = await run_semgrep(controller, scan_id, root, only_file=only_file, rules_dir=CRYPTO_RULES_DIR)
    assets, unreadable = discover_assets(results, root)
    for miss in unreadable:
        log.warning("crypto.asset_unreadable", scan_id=scan_id, **miss)
    log.info("crypto.discovered", scan_id=scan_id, assets=len(assets), algorithms=sorted({a["algo"] for a in assets}))
    return assets
