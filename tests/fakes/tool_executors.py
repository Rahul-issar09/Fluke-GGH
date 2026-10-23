"""Tool executors for tests.

* ``git_only_executor`` — the real ``git`` (for ``apply --check``); every other tool "not installed".
* ``fix_executor`` — the real ``git`` and ``pytest``, plus ``semgrep_standin`` / ``gitleaks_standin``, so fix
  scans and verification run without the semgrep binary — over one file, or the whole folder. The
  stand-in mirrors what the three rules in
  ``rules/semgrep`` report on the demo code (checked against real semgrep in the ``-m tools``
  tests) and answers in semgrep's JSON shape, including its dotted ``check_id`` and Windows paths.
"""

from __future__ import annotations

import re
from pathlib import Path

from aegis.safety.models import ToolCall, ToolResult
from aegis.workers.executor import execute_tool, no_tools_executor


async def git_only_executor(call: ToolCall, args: dict, inputs: list[str]) -> ToolResult:
    """Run the real ``git`` (for ``apply --check``); report every other tool as not installed."""
    if call.tool == "git":
        return await execute_tool(call, args, inputs)
    return await no_tools_executor(call, args, inputs)


_OWNER_COMPARISON = re.compile(r"^\s*if\b.*[\"']owner_id[\"']")


def _owner_check(lines: list[str]) -> list[int]:
    if any(_OWNER_COMPARISON.search(l) for l in lines):
        return []
    return [n for n, l in enumerate(lines, 1) if ".execute(" in l and "(id,)" in l]


_CONCAT = re.compile(r"^\s*(\w+)\s*=\s*\".*\"\s*\+\s*name\s*\+")


def _sqli(lines: list[str]) -> list[int]:
    """Taint rule: reported at the sink, the ``execute`` of a query built by concatenation."""
    hits = []
    for n, line in enumerate(lines, 1):
        m = _CONCAT.search(line)
        if m:
            hits += [k for k, later in enumerate(lines[n:], n + 1) if f".execute({m.group(1)}" in later][:1]
    return hits


def _weak_hash(lines: list[str]) -> list[int]:
    return [n for n, l in enumerate(lines, 1) if "hashlib.md5(" in l or "hashlib.sha1(" in l]


def _ssrf(lines: list[str]) -> list[int]:
    """A client fetch of a request URL, unless an allowlist check that raises comes first."""
    guarded = any("ALLOWED" in l and l.strip().startswith("if ") for l in lines)
    return [] if guarded else [n for n, l in enumerate(lines, 1) if ".http.get(url" in l]


# the rules this stand-in models; the other rules match nothing in the demo code (checked against
# real semgrep in the -m tools tests), so they report nothing here
_RULES = {"fastapi-missing-owner-check": _owner_check, "fastapi-sqli": _sqli, "python-sqli": _sqli, "python-ssrf": _ssrf}


# --- the crypto rules (rules/crypto) -------------------------------------------------------------- #
# Found with ast at the positions semgrep reports (checked against real semgrep in -m tools tests).
_HASHLIB = {"md5", "sha1", "sha224", "sha256", "sha384", "sha512", "sha3_224", "sha3_256", "sha3_384", "sha3_512", "blake2b", "blake2s"}
_HASHES = {"MD5", "SHA1", "SHA224", "SHA256", "SHA384", "SHA512", "SHA3_256", "SHA3_512", "BLAKE2b", "BLAKE2s"}
_KEYGEN = {"rsa.generate_private_key", "dsa.generate_private_key", "ec.generate_private_key", "dh.generate_parameters",
           "ed25519.Ed25519PrivateKey.generate", "ed448.Ed448PrivateKey.generate", "x25519.X25519PrivateKey.generate",
           "x448.X448PrivateKey.generate", "RSA.generate", "DSA.generate", "ECC.generate"}
_SECRETISH = re.compile(r"(?i).*(token|secret|password|passwd|key|nonce|otp|salt|session).*")


def _dotted(node) -> str:
    import ast

    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


def _crypto_matches(text: str) -> list[tuple[str, object]]:
    import ast

    tree = ast.parse(text)
    found = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = _dotted(node.func)
            head, _, last = name.rpartition(".")
            if (head == "hashlib" and last in _HASHLIB) or name == "hashlib.new" or (head == "hashes" and last in _HASHES and not node.args):
                found.append(("crypto-hash", node))
            elif name in _KEYGEN:
                found.append(("crypto-public-key", node))
            elif name == "Cipher" or (head == "algorithms"):
                found.append(("crypto-cipher", node))
            elif name == "ssl.SSLContext" or name == "ssl.wrap_socket" or last == "set_ciphers":
                found.append(("crypto-tls", node))
        elif isinstance(node, ast.Assign) and len(node.targets) == 1:
            target, value = node.targets[0], node.value
            if isinstance(target, ast.Attribute) and target.attr == "minimum_version" and _dotted(value).startswith("ssl.TLSVersion."):
                found.append(("crypto-tls", node))
            elif isinstance(target, ast.Name) and _SECRETISH.match(target.id) and isinstance(value, ast.Call) and _dotted(value.func).startswith("random."):
                found.append(("crypto-random", node))
    # an algorithms.X(...) inside Cipher(...) belongs to the Cipher match
    inside = {id(a) for _, n in found if isinstance(n, ast.Call) and _dotted(n.func) == "Cipher" for a in n.args}
    return [(rule, node) for rule, node in found if id(node) not in inside]


def _crypto_results(root: Path, names: list[str]) -> list[dict]:
    results = []
    for name in names:
        text = (root / name).read_text(encoding="utf-8")
        for rule, node in _crypto_matches(text):
            results.append({
                "check_id": f"rules.crypto.{rule}", "path": name.replace("/", "\\"),
                "start": {"line": node.lineno, "col": node.col_offset + 1},
                "end": {"line": node.end_lineno, "col": node.end_col_offset + 1},
                "extra": {},
            })
    return results


def semgrep_standin(args: dict) -> ToolResult:
    root = Path(args["path"])
    results = []
    config = Path(args["config"])
    rules = [config.stem] if config.is_file() else sorted(r.stem for r in config.glob("*.yml"))
    names = args.get("files") or [p.relative_to(root).as_posix() for p in sorted(root.rglob("*.py")) if "__pycache__" not in p.parts]
    if config.name == "crypto" or config.parent.name == "crypto":
        return ToolResult(ok=True, tool="semgrep", exit_code=0, output={"results": _crypto_results(root, names), "errors": []})
    for rule in (r for r in rules if r in _RULES):
        for name in names:
            lines = (root / name).read_text(encoding="utf-8").splitlines()
            for line in _RULES[rule](lines):
                results.append({
                    "check_id": f"rules.semgrep.{rule}", "path": name.replace("/", "\\"),
                    "start": {"line": line}, "end": {"line": line}, "extra": {"lines": lines[line - 1]},
                })
    return ToolResult(ok=True, tool="semgrep", exit_code=0, output={"results": results, "errors": []})


# gitleaks' stripe-access-token rule (the one that fires on the demo's planted key, checked with
# real gitleaks 8.30.1 in the -m tools tests); answered the way `gitleaks dir --redact` does
_STRIPE = re.compile(r"\b(sk_(?:test|live|prod)_[0-9a-zA-Z]{10,99})\b")


def gitleaks_standin(args: dict) -> ToolResult:
    target = Path(args["path"])
    files = [target] if target.is_file() else [p for p in sorted(target.rglob("*")) if p.is_file() and "__pycache__" not in p.parts]
    report = []
    for path in files:
        for n, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            for m in _STRIPE.finditer(line):
                report.append({
                    "RuleID": "stripe-access-token", "Description": "Found a Stripe Access Token",
                    "File": str(path.resolve()), "StartLine": n, "EndLine": n,
                    "StartColumn": m.start() + 1, "EndColumn": m.end(),
                    "Secret": "REDACTED", "Match": "REDACTED", "Entropy": 3.77,
                })
    return ToolResult(ok=True, tool="gitleaks", exit_code=0, output=report)


# OSV / Trivy / TruffleHog / Syft: their real outputs on the two demo apps, recorded once
# (tests/fixtures/tools/*_{demo,patched}.*; paths replaced by "{ROOT}") and replayed for the copy
# being scanned. Which recording is chosen depends on the copy's requirements.txt; anything else
# gets an empty result, like a project with nothing to report.
_FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "tools"
_DEMO_ROOT = Path(__file__).resolve().parents[2]
_RECORDED = {"osv": ("osv", "json"), "trivy": ("trivy", "json"), "trufflehog": ("trufflehog", "jsonl"), "syft": ("syft", "json")}


def _which_demo(folder: Path) -> str | None:
    manifest = folder / "requirements.txt"
    if not manifest.is_file():
        return None
    text = manifest.read_text(encoding="utf-8")
    for tag, app in (("demo", "demo-app"), ("patched", "demo-app-patched")):
        if text == (_DEMO_ROOT / app / "requirements.txt").read_text(encoding="utf-8"):
            return tag
    return None


def recorded_standin(tool: str, args: dict) -> ToolResult:
    import json

    folder = Path(args["path"])
    tag = _which_demo(folder)
    name, kind = _RECORDED[tool]
    raw = (_FIXTURES / f"{name}_{tag}.{kind}").read_text(encoding="utf-8") if tag else ""
    root = str(folder.resolve()).replace("\\", "\\\\")  # the recordings are JSON: paths are escaped
    raw = raw.replace("{ROOT}", root)
    if kind == "jsonl":
        output = [json.loads(line) for line in raw.splitlines() if line.strip()]
    else:
        output = json.loads(raw) if raw else ({"components": []} if tool == "syft" else {})
    exit_code = 1 if tool == "osv" and output.get("results") else 0
    return ToolResult(ok=True, tool=tool, exit_code=exit_code, output=output)


async def fix_executor(call: ToolCall, args: dict, inputs: list[str]) -> ToolResult:
    if call.tool in ("git", "pytest"):
        return await execute_tool(call, args, inputs)
    if call.tool == "semgrep":
        return semgrep_standin(args)
    if call.tool == "gitleaks":
        return gitleaks_standin(args)
    if call.tool in _RECORDED:
        return recorded_standin(call.tool, args)
    return await no_tools_executor(call, args, inputs)


def sslyze_executor(recording: str):
    """``fix_executor`` plus sslyze answering with its real recorded report for one demo app
    (``"demo"`` or ``"patched"``), re-addressed to whatever ``host:port`` was asked for."""

    async def executor(call: ToolCall, args: dict, inputs: list[str]) -> ToolResult:
        if call.tool != "sslyze":
            return await fix_executor(call, args, inputs)
        import json

        host, port = args["host"].rsplit(":", 1)
        raw = (_FIXTURES / f"sslyze_{recording}.json").read_text(encoding="utf-8")
        raw = raw.replace('"{PORT}"', port).replace("{HOST}", host).replace("{PORT}", port).replace('"127.0.0.1"', json.dumps(host))
        return ToolResult(ok=True, tool="sslyze", exit_code=1, output=json.loads(raw))

    return executor
