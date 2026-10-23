"""Prove a drafted fix on a copy of the source (AG11.1, PHASES P12.6, SYSTEM_DESIGN §5.7).

``verify_fix`` copies the scanned source to ``workspaces/<fix_id>``, applies the draft
there, and runs three checks:

* **static** — the detector that reported the weakness is run again on the patched file:
  the same semgrep rule must no longer fire in the patched function. For a leaked secret the
  flagged value must be gone from the file.
* **tests** — the project's own ``pytest -q`` if it has tests, else ``skipped``. If they fail,
  they are run once on an unpatched copy too: tests that already failed before the fix cannot
  judge it (``inconclusive``), tests that only fail with the fix fail it.
* **runtime** (Mode 3, access-control findings) — the same differential replay as the scan
  (owner A, then B) against the patched build: A must still read their objects, B must be
  denied.

Every check that applies must pass; a check that cannot run (tool missing, no patched build)
fails the verification rather than being assumed fine, and at least one check must actually
prove the fix. Only then is the attempt ``verified`` and each passing proof stored as
``retest`` evidence — the evidence the state machine needs to resolve the finding later
(AG11.2). Otherwise the attempt is ``failed`` with the reason and the finding stays open.

All tools run through the SafetyController; HTTP goes through the egress guard with the
scan's own allowlist (the patched build's host is never added implicitly). The original
source is hashed before and after: verification never writes to it.
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import tempfile
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

from aegis.evidence.adapters.semgrep import rule_id
from aegis.evidence.links import linked_to
from aegis.evidence.models import Evidence, Finding
from aegis.evidence.store import EvidenceStore
from aegis.fix.applier import apply_diff, changed_files
from aegis.fix.draft import PLACEHOLDER_LITERAL, Unparseable, canonicalize_diff, handler_window, hide_untrusted, secret_literals, split_lines
from aegis.fix.workspace import WorkspaceError, make_workspace, tree_hash
from aegis.graph.route_normalize import normalize_path
from aegis.observability import get_logger
from aegis.safety.allowlist import Allowlist
from aegis.safety.egress import EgressBlocked, make_client
from aegis.safety.models import ToolCall
from aegis.safety.rate_limiter import RateLimiter
from aegis.workers.runtime.auth import authenticate, load_identities
from aegis.workers.runtime.bola import check_bola
from aegis.workers.runtime.context import RuntimeStageError, verify_tls
from aegis.workers.runtime.discover import discover_routes
from aegis.workers.runtime.model import build_model

__all__ = [
    "CHECKS", "PatchedTarget", "RULES_DIR", "Subject", "VerifyContext", "VerifyError", "apply_to_copy", "begin",
    "check_failed", "conclude", "decide", "file_hashes", "load_subject", "make_copy", "run_check", "translate_line", "verify_fix",
]

log = get_logger("fix.verifier")

RULES_DIR = Path(__file__).resolve().parents[2] / "rules" / "semgrep"

PASSED, FAILED, SKIPPED, UNAVAILABLE, INCONCLUSIVE = "passed", "failed", "skipped", "unavailable", "inconclusive"
_HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
_TEST_FILE = re.compile(r"^(test_.*|.*_test)\.py$")
_NOT_PROJECT = {".git", ".venv", "venv", "node_modules", "__pycache__", ".tox", "site-packages"}


class VerifyError(Exception):
    """The fix attempt cannot be verified at all (unknown, or not a fresh draft)."""


@dataclass
class PatchedTarget:
    """Where the patched build answers, and whether it was built from the workspace itself.

    ``built_from_workspace=False`` means a pre-staged build (SYSTEM_DESIGN §5.7) — it shows the
    intended fix works, not necessarily this exact diff; the report says which it was.
    """

    base_url: str
    built_from_workspace: bool


@dataclass
class VerifyContext:
    store: EvidenceStore
    controller: Any  # SafetyController (tools: git, semgrep, pytest)
    workspaces_root: Path
    allowlist: Allowlist
    rules_dir: Path = RULES_DIR
    http_transport: httpx.AsyncBaseTransport | None = None
    rate_limit_rps: float = 5.0
    rate_limit_burst: int = 10
    # Start (or point at) the patched build for a workspace; None → no runtime re-test possible.
    patched_target: Callable[[Path], Awaitable[PatchedTarget | None]] | None = None


@dataclass
class Check:
    status: str
    reason: str | None = None
    detail: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {"status": self.status, "reason": self.reason, **self.detail}


# --------------------------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------------------------- #
def translate_line(diff: str, line: int) -> int:
    """Where original *line* is after applying *diff* (a removed line maps to where it was)."""
    shift = 0
    old_no = new_no = 0
    in_hunk = False
    for raw in diff.splitlines():
        m = _HUNK.match(raw)
        if m:
            old_start, new_start = int(m.group(1)), int(m.group(3))
            if old_start > line:
                break
            old_no, new_no, in_hunk = old_start, new_start, True
            shift = new_start - old_start
            continue
        if not in_hunk or raw.startswith(("--- ", "+++ ")):
            continue
        if raw.startswith("+"):
            new_no += 1
        elif raw.startswith("-"):
            if old_no == line:
                return max(new_no, 1)
            old_no += 1
        else:
            if old_no == line:
                return new_no
            old_no += 1
            new_no += 1
        shift = new_no - old_no
    return max(line + shift, 1)


def _related_findings(store: EvidenceStore, finding: Finding) -> list[Finding]:
    """The finding, what was merged into it, and its static twin (same file, same weakness)."""
    ids = {finding.id, *linked_to(store, finding.id)}
    if finding.file:
        ids |= {f.id for f in store.list_findings(finding.scan_id) if f.file == finding.file and f.type == finding.type}
    return [f for f in (store.get_finding(i) for i in sorted(ids)) if f is not None]


def _payload(ev: Evidence) -> dict:
    try:
        data = json.loads(ev.payload_json or "{}")
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}


def _semgrep_rules(store: EvidenceStore, finding: Finding) -> list[str]:
    rules: set[str] = set()
    for f in _related_findings(store, finding):
        for ev in store.evidence_for(f.id):
            payload = _payload(ev)
            if ev.tool == "semgrep" and payload.get("rule") and payload.get("file") == finding.file:
                rules.add(rule_id(payload["rule"]))
    return sorted(rules)


def _rel(path: str) -> str:
    rel = Path(path).as_posix()
    return rel[2:] if rel.startswith("./") else rel


def _has_tests(root: Path) -> bool:
    for path in root.rglob("*.py"):
        if _TEST_FILE.match(path.name) and not (_NOT_PROJECT & set(path.relative_to(root).parts)):
            return True
    return False


def _summary(result) -> str:
    text = ((result.output or {}).get("text") if isinstance(result.output, dict) else "") or ""
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    return lines[-1][:200] if lines else ""


# --------------------------------------------------------------------------------------------- #
# the checks
# --------------------------------------------------------------------------------------------- #
async def check_static(ctx: VerifyContext, finding: Finding, workspace: Path, original: str, diff: str) -> Check:
    patched_file = workspace / finding.file
    patched = patched_file.read_bytes().decode("utf-8", "replace") if patched_file.is_file() else ""

    if finding.type == "secret":
        literals = secret_literals(original, [finding.line])
        if not literals:
            return Check(UNAVAILABLE, "the flagged line has no literal value to look for")
        if any(lit in patched for lit in literals):
            return Check(FAILED, "the leaked value is still in the file", {"check": "secret_removed", "file": finding.file})
        return Check(PASSED, None, {"check": "secret_removed", "file": finding.file, "line": finding.line})

    rules = _semgrep_rules(ctx.store, finding)
    if not rules:
        return Check(SKIPPED, "no static detector reported this finding")

    new_line = translate_line(diff, finding.line)
    try:
        start, end = handler_window(patched, new_line)
    except Unparseable:
        return Check(FAILED, "the patched file does not parse")

    still: list[dict] = []
    for rule in rules:
        config = ctx.rules_dir / f"{rule}.yml"
        if not config.is_file():
            return Check(UNAVAILABLE, f"the rule '{rule}' is not available offline")
        result = await ctx.controller.run(
            ToolCall(tool="semgrep", scan_id=finding.scan_id, args={"path": str(workspace), "config": str(config), "files": [finding.file]})
        )
        if result.blocked_reason:
            return Check(UNAVAILABLE, f"semgrep could not run: {result.blocked_reason}")
        out = result.output if isinstance(result.output, dict) else {}
        if not result.ok or out.get("errors"):
            return Check(UNAVAILABLE, f"semgrep failed on the patched file: {(result.stderr_tail or str(out.get('errors')))[:200]}")
        for r in out.get("results", []):
            line = (r.get("start") or {}).get("line") or 0
            if rule_id(r.get("check_id", "")) == rule and _rel(r.get("path", "")) == finding.file and start <= line <= end:
                still.append({"rule": rule, "line": line})

    detail = {"check": "semgrep", "rules": rules, "file": finding.file, "lines": [start, end]}
    if still:
        where = ", ".join(f"{s['rule']} at line {s['line']}" for s in still)
        return Check(FAILED, f"the detector still fires in the patched code ({where})", detail)
    return Check(PASSED, None, detail)


async def _pytest(ctx: VerifyContext, scan_id: str, folder: Path):
    return await ctx.controller.run(ToolCall(tool="pytest", scan_id=scan_id, args={"workdir": str(folder)}))


async def check_tests(ctx: VerifyContext, scan_id: str, workspace: Path, source: Path) -> Check:
    if not _has_tests(workspace):
        return Check(SKIPPED, "the project has no tests")
    result = await _pytest(ctx, scan_id, workspace)
    if result.blocked_reason:
        return Check(UNAVAILABLE, f"tests could not run: {result.blocked_reason}")
    detail = {"exit_code": result.exit_code, "summary": _summary(result)}
    if result.exit_code == 0:
        return Check(PASSED, None, detail)
    if result.exit_code == 5:
        return Check(SKIPPED, "no tests were collected", detail)

    # the patched tree fails: did the tests pass before the fix?
    baseline = Path(tempfile.mkdtemp(prefix="aegis-baseline-"))
    try:
        shutil.copytree(source, baseline / "src", symlinks=True, ignore=shutil.ignore_patterns(".git", ".venv", "__pycache__"))
        before = await _pytest(ctx, scan_id, baseline / "src")
    finally:
        shutil.rmtree(baseline, ignore_errors=True)
    detail["baseline_exit_code"] = before.exit_code
    if before.exit_code == 0:
        return Check(FAILED, f"the project's tests fail with the fix and pass without it ({detail['summary']})", detail)
    return Check(INCONCLUSIVE, "the project's tests already fail without the fix, so they cannot judge it", detail)


def _same_route(template: str, route: str) -> bool:
    t_method, _, t_path = template.partition(" ")
    r_method, _, r_path = route.partition(" ")
    return t_method.upper() == r_method.upper() and normalize_path(t_path) == normalize_path(r_path)


async def check_runtime(ctx: VerifyContext, scan, finding: Finding, workspace: Path) -> Check:
    mode = getattr(scan.mode, "value", scan.mode)
    if mode != "correlated":
        return Check(SKIPPED, "runtime re-test applies to correlated (Mode 3) scans")
    if finding.type != "broken_access_control" or not finding.route:
        return Check(SKIPPED, f"no runtime re-test for a {finding.type} finding")
    if ctx.patched_target is None:
        return Check(UNAVAILABLE, "no patched build is configured to re-test against")
    try:
        target = await ctx.patched_target(workspace)
    except Exception as exc:  # noqa: BLE001 - a patched build that will not start is a failed fix
        return Check(FAILED, f"the patched build does not start ({type(exc).__name__}: {str(exc)[:160]})")
    if target is None:
        return Check(UNAVAILABLE, "no patched build is available to re-test against")

    scan_cfg = json.loads(scan.config_json or "{}")
    client = make_client(
        ctx.allowlist,
        rate_limiter=RateLimiter(ctx.rate_limit_rps, ctx.rate_limit_burst),
        inner=ctx.http_transport,
        verify=verify_tls(scan_cfg),
        timeout=10.0,
        follow_redirects=False,
    )
    detail: dict = {"route": finding.route, "target": target.base_url, "built_from_workspace": target.built_from_workspace}
    try:
        async with client:
            routes, _ = await discover_routes(client, target.base_url)
            sessions = await authenticate(client, target.base_url, load_identities(scan_cfg.get("identities")))
            model = [m for m in await build_model(client, target.base_url, routes, sessions) if _same_route(m.route.template, finding.route)]
            if not model:
                return Check(FAILED, f"the owner can no longer list or read their objects on {finding.route}", detail)
            expected = sum(len(m.owner_ids) for m in model)
            results = await check_bola(client, target.base_url, model, sessions)
    except EgressBlocked as exc:
        return Check(UNAVAILABLE, f"the patched build's host is not on the allowlist ({exc})", detail)
    except (RuntimeStageError, httpx.HTTPError) as exc:
        return Check(UNAVAILABLE, f"the patched build could not be re-tested ({type(exc).__name__}: {str(exc)[:160]})", detail)

    detail["checks"] = [
        {"object_id": r["object_id"], "owner_status": r["baseline"]["status"], "other_status": r["replay"]["status"]} for r in results
    ]
    if len(results) < expected:
        return Check(FAILED, "the owner's own requests no longer succeed on the patched build", detail)
    leaked = [r for r in results if r["vulnerable"]]
    if leaked:
        return Check(FAILED, f"identity B still reads identity A's object ({leaked[0]['path']} → {leaked[0]['replay']['status']})", detail)
    return Check(PASSED, None, detail)




# --------------------------------------------------------------------------------------------- #
# orchestration — step by step (the fix graph runs each step as a node) or all at once
# --------------------------------------------------------------------------------------------- #
CHECKS = ("static", "tests", "runtime")


@dataclass
class Subject:
    """What a fix attempt is about, loaded fresh from the store at every step."""

    attempt: Any
    finding: Finding
    scan: Any
    source: Path

    @property
    def original(self) -> str:
        path = self.source / self.finding.file
        return path.read_bytes().decode("utf-8", "replace") if path.is_file() else ""

    @property
    def diff(self) -> str:
        """The diff to apply. A secret's draft is stored with the value masked (``"<redacted>"``);
        it is restored here, in memory only, against the scanned file — the masked line is matched
        to the real one — so the copy can be patched. The restored form is never stored."""
        stored = self.attempt.diff
        if self.finding.type != "secret" or PLACEHOLDER_LITERAL not in stored:
            return stored
        text = self.original
        try:
            restored = canonicalize_diff(
                stored, path=self.finding.file, orig_text=text,
                shown=hide_untrusted(text, {self.finding.line}), window=(1, len(split_lines(text))),
            )
        except Unparseable:
            return stored
        return restored.diff if restored.diff and not restored.errors else stored


def load_subject(store: EvidenceStore, fix_id: str) -> Subject | None:
    """The attempt, its finding, scan and source — or ``None`` if any of them is gone."""
    attempt = store.get_fix_attempt(fix_id)
    if attempt is None:
        raise VerifyError(f"unknown fix attempt {fix_id}")
    finding = store.get_finding(attempt.finding_id)
    scan = store.get_scan(finding.scan_id) if finding else None
    source = Path(scan.source_path) if scan and scan.source_path else None
    if finding is None or source is None or not source.is_dir() or not finding.file or not finding.line:
        return None
    return Subject(attempt=attempt, finding=finding, scan=scan, source=source)


def file_hashes(root: Path, files: list[str]) -> dict[str, str | None]:
    out: dict[str, str | None] = {}
    for rel in files:
        path = root / rel
        out[rel] = hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None
    return out


def begin(ctx: VerifyContext, fix_id: str) -> dict:
    """Start a verification: only a fresh draft may be verified. Returns the report so far."""
    attempt = ctx.store.get_fix_attempt(fix_id)
    if attempt is None:
        raise VerifyError(f"unknown fix attempt {fix_id}")
    if attempt.status != "drafted":
        raise VerifyError(f"{fix_id} is {attempt.status}, not a fresh draft")
    log.info("fix.verify_start", fix_id=fix_id, finding_id=attempt.finding_id)
    subject = load_subject(ctx.store, fix_id)
    if subject is None:
        return {"passed": False, "reason": "the finding or its scanned source is no longer available"}
    files = changed_files(attempt.diff)
    # what the source looked like when it was copied: proves verification never wrote to it,
    # and lets a later commit refuse to overwrite a file the user has changed since
    return {"source_hash": tree_hash(subject.source), "source_files": file_hashes(subject.source, files), "files": files}


async def make_copy(ctx: VerifyContext, fix_id: str, report: dict) -> tuple[Path | None, dict]:
    subject = load_subject(ctx.store, fix_id)
    if subject is None:
        return None, {**report, "passed": False, "reason": "the finding or its scanned source is no longer available"}
    try:
        return make_workspace(subject.source, ctx.workspaces_root, fix_id), report
    except WorkspaceError as exc:
        return None, {**report, "passed": False, "reason": f"no workspace: {exc}"}


async def apply_to_copy(ctx: VerifyContext, fix_id: str, workspace: Path, report: dict) -> dict:
    subject = load_subject(ctx.store, fix_id)
    applied = await apply_diff(ctx.controller, subject.finding.scan_id, workspace, subject.diff)
    if not applied.ok:
        return {**report, "passed": False, "reason": applied.reason}
    return report


async def run_check(ctx: VerifyContext, name: str, fix_id: str, workspace: Path, report: dict) -> dict:
    """Run one check and add it to the report."""
    subject = load_subject(ctx.store, fix_id)
    if name == "static":
        check = await check_static(ctx, subject.finding, workspace, subject.original, subject.diff)
    elif name == "tests":
        check = await check_tests(ctx, subject.finding.scan_id, workspace, subject.source)
    elif name == "runtime":
        check = await check_runtime(ctx, subject.scan, subject.finding, workspace)
    else:
        raise ValueError(f"unknown check {name!r}")
    log.info("fix.verify_step", fix_id=fix_id, check=name, status=check.status, reason=check.reason)
    return {**report, name: check.as_dict()}


def check_failed(report: dict, name: str) -> bool:
    """Whether *name*'s result already decides the verification has failed."""
    status = (report.get(name) or {}).get("status")
    return status == FAILED or (name != "tests" and status == UNAVAILABLE)


def decide(report: dict) -> tuple[bool, str | None]:
    if "passed" in report and report["passed"] is False:  # decided before the checks (copy/apply)
        return False, report.get("reason")
    for name in ("static", "runtime", "tests"):
        if check_failed(report, name):
            check = report[name]
            return False, f"{name} check {check['status']}: {check['reason']}"
    if PASSED not in ((report.get("static") or {}).get("status"), (report.get("runtime") or {}).get("status")):
        return False, "nothing could prove this fix (no static detector and no runtime re-test applies)"
    return True, None


def _retest_evidence(store: EvidenceStore, finding: Finding, fix_id: str, report: dict) -> list[str]:
    ids = []
    static, runtime = report.get("static") or {}, report.get("runtime") or {}
    if static.get("status") == PASSED:
        tool = "aegis.fix" if static.get("check") == "secret_removed" else "semgrep"
        ids.append(store.add_evidence(finding.scan_id, "retest", tool, {"fix_id": fix_id, "result": "fixed", **static}, finding_id=finding.id).id)
    if runtime.get("status") == PASSED:
        ids.append(store.add_evidence(finding.scan_id, "retest", "bola", {"fix_id": fix_id, "result": "fixed", **runtime}, finding_id=finding.id).id)
    return ids


def conclude(ctx: VerifyContext, fix_id: str, report: dict, workspace: Path | None) -> dict:
    """Decide, store retest evidence for a verified fix, and record ``verified``/``failed``."""
    store = ctx.store
    attempt = store.get_fix_attempt(fix_id)
    subject = load_subject(store, fix_id)
    passed, reason = decide(report)
    if subject is not None and report.get("source_hash") and tree_hash(subject.source) != report["source_hash"]:
        passed, reason = False, "the original source changed during verification"
        log.error("fix.original_changed", fix_id=fix_id)
    final = {
        **{k: v for k, v in report.items() if k not in ("passed", "reason")},
        "passed": passed,
        "reason": reason,
        "retest_evidence_ids": [],
    }
    for name in CHECKS:
        final.setdefault(name, {"status": "not_run", "reason": None})
    if passed:
        final["retest_evidence_ids"] = _retest_evidence(store, subject.finding, fix_id, final)

    status = "verified" if passed else "failed"
    previous = json.loads(attempt.verify_report_json or "{}")
    store.update_fix_attempt(
        fix_id,
        status=status,
        workspace_path=str(workspace) if workspace else None,
        verify_report={**previous, "verify": final},
    )
    log.info("fix.verify_done", fix_id=fix_id, finding_id=attempt.finding_id, status=status, reason=reason)
    return final


async def verify_fix(ctx: VerifyContext, fix_id: str) -> dict:
    """Apply and prove a drafted fix on a copy, running every check; return the stored report."""
    report = begin(ctx, fix_id)
    if report.get("passed") is False:
        return conclude(ctx, fix_id, report, None)
    workspace, report = await make_copy(ctx, fix_id, report)
    if workspace is None:
        return conclude(ctx, fix_id, report, None)
    report = await apply_to_copy(ctx, fix_id, workspace, report)
    if report.get("passed") is False:
        return conclude(ctx, fix_id, report, workspace)
    for name in CHECKS:
        report = await run_check(ctx, name, fix_id, workspace, report)
    return conclude(ctx, fix_id, report, workspace)
