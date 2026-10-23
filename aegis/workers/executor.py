"""Tool executor for SafetyController (AG06.2).

``SafetyController.run`` validates a ``ToolCall`` (allowlist, argument policy,
approved inputs, rate limit) and then hands the *validated* arguments to an
executor. This module is that executor for the external scanners. For each tool
a builder turns the validated args into a fixed command line — the caller never
supplies flags, a binary path or a shell string — and ``run_tool`` executes it
with ``create_subprocess_exec`` under the heavy-stage semaphore.

Tool-specific facts, verified against the real CLIs where they are installed:

* **schemathesis 4.x** — ``--include-method GET`` keeps it to read-only methods
  (it generates its own inputs, so it is never allowed to send mutating
  requests); ``--seed`` + ``--generation-deterministic`` make a run reproducible
  (NFR-3); exit code 1 means "found failures", not "crashed"; the JUnit report is
  the machine-readable output; it needs UTF-8 on Windows consoles, and a
  ``hypothesis`` release that matches it (``<6.150`` for 4.29.x).
* **nuclei v3** — ``-ni`` disables Interactsh (an external service) and ``-duc``
  disables update checks, so a scan stays offline; templates are the pinned,
  pre-staged snapshot.
* **git clone** — the only networked step of a repo scan: ``--depth 1 --single-branch
  --no-tags --no-recurse-submodules``, ``--template=`` (no hooks), and none of the user's or the
  system's git config (``GIT_CONFIG_GLOBAL``/``GIT_CONFIG_NOSYSTEM``), so no credential helper,
  URL rewrite or LFS filter can run; ``GIT_TERMINAL_PROMPT=0`` makes a private repo fail instead
  of asking for a password.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from aegis.observability import get_logger
from aegis.safety.models import ToolCall, ToolResult
from aegis.workers.base import heavy_stage, run_tool

__all__ = ["RunSpec", "BUILDERS", "execute_tool", "find_binary", "no_tools_executor"]

log = get_logger("workers.executor")

_UTF8_ENV = {"PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8"}
_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_SCHEMATHESIS_CHECKS = "not_a_server_error,status_code_conformance,response_schema_conformance"
_SCHEMATHESIS_SEED = "1234"


@dataclass
class RunSpec:
    argv: list[str]
    parse: str = "json"
    timeout: float = 120.0
    env: dict[str, str] | None = None
    ok_exit_codes: tuple[int, ...] = (0,)
    report_file: str | None = None  # read back after the run
    report_parse: str = "junit"  # junit → {"junit_xml": text}; json → the parsed document
    cleanup_dir: str | None = None
    cwd: str | None = None
    extra: dict = field(default_factory=dict)


def find_binary(name: str) -> str | None:
    """PATH, then ``AEGIS_TOOL_DIRS`` (extra folders, e.g. a separate semgrep venv), then the
    running interpreter's own scripts dir (venv installs)."""
    found = shutil.which(name)
    if found:
        return found
    extra = [Path(d) for d in os.environ.get("AEGIS_TOOL_DIRS", "").split(os.pathsep) if d]
    for folder in [*extra, Path(sys.executable).parent]:
        for candidate in (folder / name, folder / f"{name}.exe"):
            if candidate.is_file():
                return str(candidate)
    return None


# The AEGIS Nuclei profile (TNW-3): misconfiguration, exposure and exposed-panel HTTP templates —
# not the ~4 400 product CVE templates (hours at a polite rate, and mostly for software the target
# does not run). Never: anything intrusive, brute force, DoS, fuzzing, out-of-band (Interactsh),
# OSINT or token spraying (those contact *other* hosts), default logins or takeovers. Info-level
# templates are dropped except the few that report an exposed API description / console.
NUCLEI_TEMPLATE_DIRS = ("http/misconfiguration", "http/exposures", "http/exposed-panels")
NUCLEI_EXCLUDED_TAGS = (
    "intrusive", "dos", "fuzz", "fuzzing", "bruteforce", "brute-force", "oast", "osint",
    "token-spray", "default-login", "takeover", "honeypot",
)
NUCLEI_INFO_ALLOWED = ("fastapi-docs", "swagger-api", "openapi", "redoc-api-docs", "graphiql-exposure", "graphql-playground")
NUCLEI_CONDITION = "severity != 'info' || " + " || ".join(f"id == '{i}'" for i in NUCLEI_INFO_ALLOWED)
NUCLEI_REQUESTS = 4000  # about what the profile sends to one target (measured: 3 700)


def _nuclei(args: dict) -> RunSpec:
    """The AEGIS profile of the pinned, pre-staged templates. ``-duc`` no update checks, ``-ni`` no
    Interactsh, ``-dr`` no redirects (a redirect could leave the allowlisted host); the rate is the
    scan's rate limit, and the timeout follows from it."""
    root = Path(args["templates"])
    rate = int(args.get("rate_limit", 5))
    argv = ["nuclei", "-u", args["url"]]
    for folder in NUCLEI_TEMPLATE_DIRS:
        argv += ["-t", str(root / folder)]
    argv += [
        "-etags", ",".join(NUCLEI_EXCLUDED_TAGS),
        "-tc", NUCLEI_CONDITION,
        "-jsonl", "-silent", "-no-color",
        "-disable-update-check",
        "-no-interactsh",
        "-disable-redirects",
        "-rate-limit", str(rate),
        "-timeout", "10",
    ]
    return RunSpec(argv=argv, parse="jsonl", timeout=min(3600.0, 120.0 + NUCLEI_REQUESTS / rate))


# Katana (TNW-4): stay on the target's host name, follow links and the endpoints named in its
# JavaScript, never submit forms (no -aff) and never fetch URLs that look like they change state.
# ``-duf``: keep pages with identical bodies (API endpoints often answer alike); ``-or``: no raw
# requests in the output (they would carry the session cookie). Response bodies stay on: Katana
# needs them to read endpoints out of the JavaScript.
KATANA_SKIP = r"(?i)(log-?out|sign-?out|log-?off|/delete|/remove|/destroy)"
KATANA_EXTENSIONS_FILTERED = "png,jpg,jpeg,gif,svg,ico,webp,css,woff,woff2,ttf,eot,map,pdf,zip"


def _katana(args: dict) -> RunSpec:
    depth = int(args.get("depth", 3))
    seconds = int(args.get("crawl_seconds", 60))
    argv = [
        "katana", "-u", args["url"],
        "-d", str(depth), "-jc", "-duf", "-or",
        "-fs", "fqdn", "-cos", KATANA_SKIP, "-ef", KATANA_EXTENSIONS_FILTERED,
        "-rl", str(int(args.get("rate_limit", 5))), "-timeout", "10", "-ct", f"{seconds}s",
        "-j", "-nc", "-silent", "-duc",
    ]
    if depth >= 3:
        argv += ["-kf", "all"]  # robots.txt and sitemap.xml (Katana needs depth 3 for them)
    for name, value in (args.get("headers") or {}).items():
        argv += ["-H", f"{name}: {value}"]
    return RunSpec(argv=argv, parse="jsonl", timeout=seconds + 60.0)


def _playwright(args: dict) -> RunSpec:
    """The fixed browser-login flow (``aegis.workers.runtime.browser_login``) in this interpreter."""
    import importlib.util

    if importlib.util.find_spec("playwright") is None:  # reported as "tool not installed"
        return RunSpec(argv=["playwright (python package)"], parse="json")
    argv = [
        sys.executable, "-m", "aegis.workers.runtime.browser_login",
        "--login-url", args["login_url"], "--identities", str(Path(args["identities"]).resolve()),
        "--identity", args["identity"], "--allow", ",".join(args["allow"]),
    ]
    if args.get("verify_tls") is False:
        argv.append("--insecure")
    env = dict(_UTF8_ENV)
    staged = _PROJECT_ROOT / ".tools" / "ms-playwright"  # where the setup puts Chromium
    if not os.environ.get("PLAYWRIGHT_BROWSERS_PATH") and staged.is_dir():
        env["PLAYWRIGHT_BROWSERS_PATH"] = str(staged)
    return RunSpec(argv=argv, parse="json", timeout=90.0, env=env, cwd=str(_PROJECT_ROOT))


def _schemathesis(args: dict) -> RunSpec:
    workdir = tempfile.mkdtemp(prefix="aegis-schemathesis-")
    report = str(Path(workdir) / "junit.xml")
    argv = [
        "schemathesis", "run", args["openapi"],
        "--url", args["url"],
        "--include-method", "GET",
        "--phases", "examples,fuzzing",
        "--checks", _SCHEMATHESIS_CHECKS,
        "--max-examples", "5",
        "--workers", "1",
        "--seed", _SCHEMATHESIS_SEED,
        "--generation-deterministic",
        "--request-timeout", "10",
        "--rate-limit", "20/s",
        "--report", "junit",
        "--report-junit-path", report,
        "--no-color",
    ]
    if args.get("tls_verify") is False:
        argv += ["--tls-verify", "false"]
    for name, value in (args.get("headers") or {}).items():
        argv += ["-H", f"{name}: {value}"]
    return RunSpec(
        argv=argv,
        parse="text",
        timeout=300.0,
        env=_UTF8_ENV,
        ok_exit_codes=(0, 1),
        report_file=report,
        cleanup_dir=workdir,
    )


def _git_env(workdir: Path) -> dict[str, str]:
    # GIT_CEILING_DIRECTORIES: never let git find a repository *above* the folder it works in
    # (a workspace under a repo would otherwise be patched relative to that repo's root).
    # GIT_CONFIG_GLOBAL: none of the user's git config either — a global core.autocrlf=true (common on
    # Windows) made `git apply` rewrite the whole patched file with CRLF line endings (found in TNW-6)
    return {"GIT_TERMINAL_PROMPT": "0", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CEILING_DIRECTORIES": str(workdir.parent)}


# Every setting that could make a clone run code, prompt, or reach another host is switched off:
# no user/system git config (credential helpers, url rewrites, hooks), no hooks from a template,
# only the https protocol, no redirects to other hosts, no submodules, no LFS downloads.
_CLONE_CONFIG = (
    "protocol.allow=never",
    "protocol.https.allow=always",
    "http.followRedirects=false",
    "credential.helper=",
    "core.symlinks=false",
    "core.fsmonitor=false",
    "core.longpaths=true",
    "submodule.recurse=false",
)
_CLONE_ENV = {
    "GIT_TERMINAL_PROMPT": "0",
    "GIT_ASKPASS": "",
    "SSH_ASKPASS": "",
    "GCM_INTERACTIVE": "Never",
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_LFS_SKIP_SMUDGE": "1",
    "GIT_PROTOCOL_FROM_USER": "0",
}
CLONE_TIMEOUT_S = 300.0


def _git(args: dict) -> RunSpec:
    """``clone`` (a shallow, public https clone into a new folder — TNW-1), ``apply_check``
    (read-only) and ``apply`` (a fix workspace only — the policy enforces it).

    ``git apply`` is atomic: either every hunk applies or no file changes."""
    op = args.get("op")
    if op == "clone":
        dest = Path(args["dest"])
        argv = ["git"]
        for item in _CLONE_CONFIG:
            argv += ["-c", item]
        argv += [
            "clone", "--depth", "1", "--single-branch", "--no-tags", "--no-recurse-submodules",
            "--template=", "--quiet", "--", args["repo"], str(dest),
        ]
        return RunSpec(
            argv=argv,
            parse="text",
            timeout=CLONE_TIMEOUT_S,
            env={**_CLONE_ENV, "GIT_CEILING_DIRECTORIES": str(dest.parent)},
            cwd=str(dest.parent),
        )
    if op not in ("apply_check", "apply"):
        return RunSpec(argv=["git", "--no-such-operation"], parse="text")  # refused by git itself
    workdir = Path(args["workdir"]).resolve()
    flags = ["--check"] if op == "apply_check" else ["--whitespace=nowarn"]
    return RunSpec(
        argv=["git", "apply", *flags, str(Path(args["patch"]).resolve())],
        parse="text",
        timeout=30.0,
        env=_git_env(workdir),
        cwd=str(workdir),
    )


def _semgrep(args: dict) -> RunSpec:
    """Local rules only (the policy refuses registry configs); no metrics, no version check."""
    argv = [
        "semgrep", "scan",
        "--config", str(Path(args["config"]).resolve()),
        "--json", "--quiet",
        "--metrics=off", "--disable-version-check",
        "--no-git-ignore",
        *(args.get("files") or ["."]),
    ]
    return RunSpec(
        argv=argv,
        parse="json",
        timeout=300.0,
        env={**_UTF8_ENV, "SEMGREP_SEND_METRICS": "off", "SEMGREP_ENABLE_VERSION_CHECK": "0"},
        cwd=str(Path(args["path"]).resolve()),
    )


_PYTEST_CONFIGS = (("pytest.ini", ""), ("pyproject.toml", "[tool.pytest"), ("tox.ini", "[pytest]"), ("setup.cfg", "[tool:pytest]"))


def _project_pytest_config(workdir: Path) -> Path | None:
    for name, marker in _PYTEST_CONFIGS:
        candidate = workdir / name
        if candidate.is_file() and marker in candidate.read_text(encoding="utf-8", errors="replace"):
            return candidate
    return None


def _pytest(args: dict) -> RunSpec:
    """The project's own tests in a fix workspace.

    The run is pinned to the workspace: ``--rootdir``/``--confcutdir`` stop pytest from picking up
    a config or ``conftest.py`` from folders above it, and when the project has no pytest config of
    its own an empty one is used. Exit codes 0–5 all mean "pytest ran"; the verifier reads them
    (0 passed, 1 failures, 5 no tests collected, 2–4 could not run).
    """
    workdir = Path(args["workdir"]).resolve()
    config = _project_pytest_config(workdir)
    cleanup = None
    if config is None:
        cleanup = tempfile.mkdtemp(prefix="aegis-pytest-")
        config = Path(cleanup) / "pytest.ini"
        config.write_text("[pytest]\n", encoding="utf-8")
    return RunSpec(
        argv=[
            sys.executable, "-m", "pytest", "-q", "--no-header", "-p", "no:cacheprovider",
            "--rootdir", str(workdir), "--confcutdir", str(workdir), "-c", str(config),
        ],
        parse="text",
        timeout=600.0,
        env={**_UTF8_ENV, "PYTHONDONTWRITEBYTECODE": "1"},
        ok_exit_codes=(0, 1, 2, 3, 4, 5),
        cleanup_dir=cleanup,
        cwd=str(workdir),
    )


def _gitleaks(args: dict) -> RunSpec:
    """Working-tree scan (``gitleaks dir``, v8.19+). ``--redact``: gitleaks itself replaces every secret
    value, so the raw value never reaches AEGIS at all. ``--exit-code 0``: finding leaks is not a failure."""
    workdir = tempfile.mkdtemp(prefix="aegis-gitleaks-")
    report = str(Path(workdir) / "report.json")
    return RunSpec(
        argv=[
            "gitleaks", "dir", str(Path(args["path"]).resolve()),
            "--report-format", "json", "--report-path", report,
            "--redact", "--no-banner", "--exit-code", "0", "--log-level", "warn",
        ],
        parse="text",
        timeout=300.0,
        report_file=report,
        report_parse="json",
        cleanup_dir=workdir,
    )


def _syft(args: dict) -> RunSpec:
    """Software bill of materials of a folder (CycloneDX JSON on stdout), no update check."""
    return RunSpec(
        argv=["syft", f"dir:{Path(args['path']).resolve()}", "-o", "cyclonedx-json", "-q"],
        parse="json",
        timeout=300.0,
        env={"SYFT_CHECK_FOR_APP_UPDATE": "false"},
    )


def _osv(args: dict) -> RunSpec:
    """OSV-Scanner over the folder's manifests/lockfiles, fully offline: ``--offline`` turns off every
    network feature and ``--no-resolve`` the online transitive resolution; vulnerabilities come from
    the staged local database. Exit 1 means "vulnerabilities found"."""
    return RunSpec(
        argv=[
            "osv-scanner", "scan", "source", "-r", "--offline", "--offline-vulnerabilities", "--no-resolve",
            "--format", "json", "--verbosity", "error", str(Path(args["path"]).resolve()),
        ],
        parse="json",
        timeout=300.0,
        env={"OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY": str(Path(args["db_dir"]).resolve())},
        ok_exit_codes=(0, 1),
    )


def _trivy(args: dict) -> RunSpec:
    """Trivy filesystem scan for vulnerable packages and misconfiguration (e.g. Dockerfiles), offline:
    no database, Java-database or check-bundle updates; secrets are left to gitleaks/TruffleHog."""
    return RunSpec(
        argv=[
            "trivy", "fs", "--scanners", "vuln,misconfig",
            "--skip-db-update", "--skip-java-db-update", "--skip-check-update", "--offline-scan",
            "--cache-dir", str(Path(args["db_dir"]).resolve()), "--format", "json", "--quiet",
            str(Path(args["path"]).resolve()),
        ],
        parse="json",
        timeout=600.0,
    )


def _trufflehog(args: dict) -> RunSpec:
    """TruffleHog filesystem scan. ``--no-verification``: found secrets are never sent anywhere to test
    them; ``--no-update``: no self-update check. One JSON object per line."""
    return RunSpec(
        argv=["trufflehog", "filesystem", str(Path(args["path"]).resolve()), "--json", "--no-verification", "--no-update"],
        parse="jsonl",
        timeout=300.0,
    )


def _sslyze(args: dict) -> RunSpec:
    """sslyze on one ``host:port``; JSON report to a temp file. Exit 1 = \"not Mozilla-compliant\"."""
    workdir = tempfile.mkdtemp(prefix="aegis-sslyze-")
    report = str(Path(workdir) / "report.json")
    return RunSpec(
        argv=["sslyze", "--quiet", f"--json_out={report}", args["host"]],
        parse="text",
        timeout=300.0,
        env=_UTF8_ENV,
        ok_exit_codes=(0, 1),
        report_file=report,
        report_parse="json",
        cleanup_dir=workdir,
    )


BUILDERS: dict[str, Callable[[dict], RunSpec]] = {
    "nuclei": _nuclei,
    "katana": _katana,
    "playwright": _playwright,
    "schemathesis": _schemathesis,
    "git": _git,
    "semgrep": _semgrep,
    "gitleaks": _gitleaks,
    "syft": _syft,
    "osv": _osv,
    "trivy": _trivy,
    "trufflehog": _trufflehog,
    "sslyze": _sslyze,
    "pytest": _pytest,
}


async def execute_tool(call: ToolCall, args: dict, inputs: list[str]) -> ToolResult:
    """SafetyController executor: run the tool for *call* with its validated *args*."""
    builder = BUILDERS.get(call.tool)
    if builder is None:
        return ToolResult(ok=False, tool=call.tool, blocked_reason=f"no executor for tool: {call.tool}")

    spec = builder(args)
    try:
        binary = find_binary(spec.argv[0])
        if binary is None:
            return ToolResult(
                ok=False, tool=call.tool, blocked_reason=f"tool not installed: {spec.argv[0]}"
            )
        async with heavy_stage(call.tool):
            result = await run_tool(
                call.tool,
                [binary, *spec.argv[1:]],
                timeout=spec.timeout,
                parse=spec.parse,
                env=spec.env,
                ok_exit_codes=spec.ok_exit_codes,
                cwd=spec.cwd,
            )
        if result.ok and spec.report_file:
            report = Path(spec.report_file)
            if report.is_file() and spec.report_parse == "json":
                text = report.read_text(encoding="utf-8").strip()
                result.output = json.loads(text) if text else []
            elif report.is_file():
                result.output = {"junit_xml": report.read_text(encoding="utf-8")}
            else:
                result.ok = False
                result.stderr_tail = ((result.stderr_tail or "") + " [no report written]").strip()
        return result
    finally:
        if spec.cleanup_dir:
            shutil.rmtree(spec.cleanup_dir, ignore_errors=True)


async def no_tools_executor(call: ToolCall, args: dict, inputs: list[str]) -> ToolResult:
    """Executor that reports every tool as not installed (tests / minimal setups)."""
    return ToolResult(ok=False, tool=call.tool, blocked_reason=f"tool not installed: {call.tool}")
