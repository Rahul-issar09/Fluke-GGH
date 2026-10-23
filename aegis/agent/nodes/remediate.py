"""remediate node (PHASES P12.4 / AG10.2) — the model drafts a fix; nothing is applied.

For a finding that has a file and line, a fix template, and source we can read:

* a **hard-coded secret** is fixed by a fixed rule, without the model (TNW-6,
  :func:`aegis.fix.draft.secret_fix`): the literal becomes ``os.environ.get("<NAME>", "")``;
* anything else goes to the model, which is shown the handler's code (at most 80 lines;
  comments, docstrings and secret literals replaced by placeholders) and a fixed hint, and
  answers with the **lines to replace and their new code** (:class:`aegis.fix.draft.FixEdit`).
  AEGIS writes the diff itself (:func:`aegis.fix.draft.edit_to_diff`) — a model copies existing
  lines badly, so it is no longer asked to. A model (or a test stand-in) that still answers with
  a unified diff (:class:`FixDraft`) is handled as before.

Either way the diff goes through :func:`aegis.fix.draft.canonicalize_diff` (right context, right
line numbers, one file only, nothing that opens a shell or the network, still valid Python), and
then ``git apply --check`` — run on a **temp copy**, as a ``git`` tool call through
SafetyController — has the last word. One corrective retry with the exact reason; if it still
fails there is no draft, which is a normal outcome.

A passing draft is stored as ``FixAttempt(status="drafted")``. This node writes nothing
else: no finding, no state, no file of the user's. (Applying a verified fix happens later,
on a copy, and committing needs the user's approval.)
"""

from __future__ import annotations

import json
import shutil
import tempfile
import time
from functools import lru_cache
from pathlib import Path
from typing import Any

from langchain_core.runnables import RunnableConfig

from aegis.agent.deps import AgentDeps, get_deps
from aegis.agent.llm import llm_unavailable, structured_call
from aegis.agent.prompt_guard import build_payload
from aegis.agent.schemas import FixDraft
from aegis.agent.validator import correlated_evidence_ids
from aegis.evidence.digest import digest
from aegis.evidence.links import visible_findings
from aegis.evidence.models import Finding, FindingState
from aegis.fix.draft import (
    CanonResult,
    FixEdit,
    Unparseable,
    canonicalize_diff,
    diff_between,
    edit_to_diff,
    handler_window,
    hide_untrusted,
    load_template,
    mask_literals,
    choose_fixed_version,
    dependency_recommendation,
    numbered,
    requirements_upgrade_diff,
    secret_fix,
    secret_literals,
    split_lines,
)
from aegis.graph.correlator import build_graph, load_handlers
from aegis.observability import get_logger
from aegis.safety.allowlist import Allowlist
from aegis.safety.controller import SafetyController
from aegis.safety.models import ToolCall
from aegis.safety.rate_limiter import RateLimiter
from aegis.safety.test_inputs import TestInputLibrary
from aegis.workers.executor import execute_tool

log = get_logger("agent.node.remediate")

_PROMPT = Path(__file__).resolve().parent.parent / "prompts" / "remediate.txt"
_MAX_SOURCE_BYTES = 1_000_000
_MAX_DIGESTS = 6
_PAYLOAD_BUDGET = 16_000  # the guard's default is for short fields; 80 lines of code need more

# a cloud model is not shown source code without the separate consent (LLM_PROVIDER_PHASES Q-3);
# the fix then comes from rules only — never from a silently substituted local model
CLOUD_SOURCE_CONSENT = "source code not shared with the cloud model (no source-code consent)"


class GitUnavailable(RuntimeError):
    """``git`` is not installed, so a diff cannot be verified (not worth a second model call)."""


@lru_cache(maxsize=1)
def _system_prompt() -> str:
    return _PROMPT.read_text(encoding="utf-8")


def _read_source(source_root: str | None, rel_file: str) -> str | None:
    """The file's text, exactly as stored (line endings kept), only from inside the source tree."""
    if not source_root:
        return None
    try:
        root = Path(source_root).resolve()
        target = (root / rel_file).resolve()
        if not target.is_relative_to(root) or not target.is_file() or target.stat().st_size > _MAX_SOURCE_BYTES:
            return None
        return target.read_bytes().decode("utf-8")
    except (OSError, ValueError, UnicodeDecodeError):
        return None


def _controller(deps: AgentDeps, allowlist: list[str] | None) -> SafetyController:
    return SafetyController(
        Allowlist(allowlist or deps.default_allowlist),
        TestInputLibrary.load(),
        RateLimiter(deps.rate_limit_rps, deps.rate_limit_burst),
        executor=deps.tool_executor or execute_tool,
        audit_sink=deps.store.add_tool_call_log,
    )


async def _git_check(controller: SafetyController, scan_id: str, rel_path: str, orig_text: str, diff: str) -> str | None:
    """``None`` if ``git apply --check`` accepts the diff on a temp copy, else the reason."""
    workdir = Path(tempfile.mkdtemp(prefix="aegis-fixcheck-"))
    try:
        target = workdir / rel_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(orig_text.encode("utf-8"))
        patch = workdir / "fix.patch"
        patch.write_bytes(diff.encode("utf-8"))
        result = await controller.run(
            ToolCall(tool="git", scan_id=scan_id, args={"op": "apply_check", "patch": str(patch), "workdir": str(workdir)})
        )
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
    if result.blocked_reason and result.blocked_reason.startswith("tool not installed"):
        raise GitUnavailable(result.blocked_reason)
    if result.blocked_reason:
        return f"the check was refused: {result.blocked_reason}"
    if not result.ok:
        return "git apply --check rejected the diff: " + (result.stderr_tail or "no details")[:300].strip()
    return None


async def _still_vulnerable(deps: AgentDeps, controller: SafetyController, finding: Finding, text: str, canon: CanonResult) -> str | None:
    """The verifier's static check, run on the drafted file in a temp folder while the model can
    still retry: if the detector that reported the finding still fires, say so. Anything else
    (no detector for this finding, the tool unavailable) is left to the real verification."""
    from aegis.fix.verifier import FAILED, VerifyContext, check_static

    if canon.new_text is None:
        return None
    folder = Path(tempfile.mkdtemp(prefix="aegis-fixprecheck-"))
    try:
        target = folder / finding.file
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(canon.new_text.encode("utf-8"))
        ctx = VerifyContext(store=deps.store, controller=controller, workspaces_root=folder, allowlist=Allowlist([]))
        check = await check_static(ctx, finding, folder, text, canon.diff)
    finally:
        shutil.rmtree(folder, ignore_errors=True)
    if check.status == FAILED:
        return f"the edit applies, but it does not fix the weakness yet: {check.reason}"
    return None


def _dependency_facts(store: Any, finding: Finding) -> dict | None:
    """Package, version, fixed_in, advisories and severities gathered from the finding's dependency
    evidence (merged across OSV and Trivy). ``None`` when there is no dependency evidence."""
    package = version = None
    fixed_in: list[str] = []
    advisories: list[str] = []
    for ev in store.evidence_for(finding.id):
        if ev.kind != "dependency":
            continue
        import json as _json

        try:
            p = _json.loads(ev.payload_json or "{}")
        except (ValueError, TypeError):
            continue
        package = package or p.get("package")
        version = version or p.get("version")
        fixed_in += [v for v in (p.get("fixed_in") or []) if v not in fixed_in]
        advisories += [a for a in (p.get("advisories") or []) if a not in advisories]
    if package is None:
        return None
    return {"package": package, "version": version, "fixed_in": fixed_in, "advisories": advisories}


def _skip_reason(store: Any, finding: Finding, source_root: str | None) -> str | None:
    if finding.state == FindingState.resolved:
        return "already resolved"
    if finding.type == "vulnerable_dependency":  # advised by a rule, not the model (TNW)
        if store.list_fix_attempts(finding.id):
            return "already has a fix attempt"
        if _dependency_facts(store, finding) is None:
            return "no dependency evidence to advise from"
        return None
    if not (finding.file and finding.line):
        return "no file and line to fix"
    template = load_template(finding.type)
    if template is None:
        return f"no fix template for '{finding.type}'"
    if not finding.file.endswith(".py"):
        return "only Python source is supported"
    if store.list_fix_attempts(finding.id):
        return "already has a fix attempt"
    if _read_source(source_root, finding.file) is None:
        return "source file not available"
    return None


def _store_draft(
    store: Any, finding: Finding, text: str, canon: CanonResult, *, description: str, source: str,
    method: str, evidence_ids: list[str], window: tuple[int, int], extra: dict | None = None,
) -> Any:
    """Keep a passing draft as ``FixAttempt(status="drafted")`` — a secret's value masked."""
    stored, masked = canon.diff, False
    if finding.type == "secret":  # the stored/displayed diff must not carry the secret value
        literals = secret_literals(text, {finding.line})
        stored, masked = mask_literals(canon.diff, literals), bool(literals)
    return store.add_fix_attempt(
        finding.id,
        stored,
        status="drafted",
        verify_report={
            "draft": {
                "description": description,
                "source": source,
                "method": method,
                "evidence_ids": evidence_ids,
                "path": finding.file,
                "hunks": canon.hunks,
                "added": canon.added,
                "removed": canon.removed,
                "window": list(window),
                "secret_masked": masked,
                **(extra or {}),
            }
        },
    )


async def _secret_by_rule(
    deps: AgentDeps, controller: SafetyController, finding: Finding, text: str, description: str
) -> dict[str, Any] | None:
    """A hard-coded secret, fixed by the fixed rule (no model). ``None`` if the rule does not
    apply to this line — the model is asked instead."""
    new_text, env = secret_fix(text, finding.line)
    if new_text is None:
        log.info("remediate.secret_rule_not_applicable", finding_id=finding.id, reason=env)
        return None
    canon = canonicalize_diff(
        diff_between(finding.file, split_lines(text), split_lines(new_text)),
        path=finding.file, orig_text=text, shown=hide_untrusted(text, {finding.line}), window=(1, len(split_lines(text))),
    )
    problem = "; ".join(canon.errors) if canon.errors else await _git_check(controller, finding.scan_id, finding.file, text, canon.diff)
    if problem:
        log.warning("remediate.secret_rule_failed", finding_id=finding.id, reason=problem[:200])
        return None
    cited = sorted(e.id for e in deps.store.evidence_for(finding.id))[:2]
    row = _store_draft(
        deps.store, finding, text, canon, description=description, source="rule", method="template",
        evidence_ids=cited, window=(finding.line, finding.line), extra={"env_var": env},
    )
    return {"drafted": True, "fix_id": row.id, "source": "rule", "hunks": canon.hunks,
            "added": canon.added, "removed": canon.removed, "audit": []}


async def _dependency_by_rule(deps: AgentDeps, controller: SafetyController, finding: Finding, source_root: str | None) -> dict[str, Any]:
    """A vulnerable dependency: advise an upgrade from the advisory's own fixed versions (no model).

    For a simple pinned requirements line, also build a diff that repins it — verifiable by applying
    it to a copy. Otherwise store the recommendation with no diff (a lockfile / range is not safe to
    repin from the advisory alone). The value or the fix is evidence-backed and never invented."""
    store = deps.store
    facts = _dependency_facts(store, finding)
    rec_text, chosen = dependency_recommendation(facts["package"], facts["version"], facts["fixed_in"], facts["advisories"])
    cited = sorted(e.id for e in store.evidence_for(finding.id))[:3]

    diff_text, method, canon = "", "recommendation", None
    text = _read_source(source_root, finding.file) if finding.file else None
    if chosen and text and finding.line:
        built = requirements_upgrade_diff(finding.file, text, finding.line, facts["package"], chosen)
        if built.diff and not built.errors:
            try:
                problem = await _git_check(controller, finding.scan_id, finding.file, text, built.diff)
            except GitUnavailable:
                problem = "git is not available to verify the diff"
            if not problem:
                diff_text, method, canon = built.diff, "dependency-upgrade", built

    row = store.add_fix_attempt(
        finding.id,
        diff_text,
        status="drafted",
        verify_report={"draft": {
            "description": rec_text,
            "source": "rule",
            "method": method,
            "evidence_ids": cited,
            "path": finding.file,
            "package": facts["package"],
            "current_version": facts["version"],
            "chosen_version": chosen,
            "fixed_in": facts["fixed_in"],
            "hunks": canon.hunks if canon else 0,
            "added": canon.added if canon else 0,
            "removed": canon.removed if canon else 0,
        }},
    )
    log.info("remediate.dependency_advised", scan_id=finding.scan_id, finding_id=finding.id,
             package=facts["package"], chosen=chosen, has_diff=bool(diff_text))
    return {"drafted": True, "fix_id": row.id, "source": "rule", "method": method,
            "chosen_version": chosen, "has_diff": bool(diff_text), "audit": []}


async def _draft_one(
    deps: AgentDeps, controller: SafetyController, finding: Finding, source_root: str, scan_mode: str, graph: Any
) -> dict[str, Any]:
    """Draft one finding's fix. Returns the outcome to record; stores the FixAttempt on success."""
    store = deps.store
    if finding.type == "vulnerable_dependency":
        return await _dependency_by_rule(deps, controller, finding, source_root)
    text = _read_source(source_root, finding.file)
    description, hint = load_template(finding.type)  # eligibility already checked
    secret_lines = {finding.line} if finding.type == "secret" else set()
    if finding.type == "secret":
        try:
            by_rule = await _secret_by_rule(deps, controller, finding, text, description)
        except GitUnavailable as exc:
            return {"drafted": False, "reason": f"git is not available to verify the diff ({exc})", "audit": []}
        if by_rule is not None:
            return by_rule

    # from here on the model would be shown the user's (masked) source code
    route = deps.llm_route(finding.scan_id)
    manager = route.get("manager")
    if manager is not None and not manager.allows_source_code(route["snapshot"]):
        log.info("remediate.source_not_shared", finding_id=finding.id, model=route["snapshot"].model)
        return {"drafted": False, "reason": CLOUD_SOURCE_CONSENT, "audit": []}

    try:
        shown = hide_untrusted(text, secret_lines)
        window = handler_window(text, finding.line)
    except Unparseable as exc:
        return {"drafted": False, "reason": f"the source does not parse ({str(exc)[:80]})", "audit": []}

    allowed = correlated_evidence_ids(store, graph, finding.id)
    evidence = {e.id: e for e in store.list_evidence(finding.scan_id) if e.id in allowed}
    payload = build_payload(
        {
            "finding_id": finding.id,
            "type": finding.type,
            "title": finding.title,
            "state": finding.state.value,
            "mode": scan_mode,
            "route": finding.route,
            "function": finding.function,
            "file": finding.file,
            "line": finding.line,
            "where": f"{finding.file}:{finding.line}",
            "evidence_ids": sorted(allowed),
            "evidence_digests": [digest(evidence[i]) for i in sorted(evidence)][:_MAX_DIGESTS],
            "fix_hint": hint,
            "handler_source": numbered(shown, *window),
        },
        max_bytes=_PAYLOAD_BUDGET,
    )

    captured: dict[str, Any] = {}
    rejected: list[tuple[FixEdit | FixDraft, list[str]]] = []

    async def validate(draft: FixEdit | FixDraft) -> list[str]:
        errors: list[str] = []
        if draft.finding_id != finding.id:
            errors.append(f"finding_id must be '{finding.id}', not '{draft.finding_id}'")
        for evidence_id in dict.fromkeys(draft.evidence_ids):
            if evidence_id not in allowed:
                errors.append(f"evidence {evidence_id} is not one of this finding's evidence_ids")
        if isinstance(draft, FixEdit):  # lines + new code: AEGIS writes the diff (TNW-6)
            canon: CanonResult = edit_to_diff(
                draft.start_line, draft.end_line, draft.replacement,
                path=finding.file, orig_text=text, shown=shown, window=window,
            )
        else:  # a unified diff, as earlier prompts asked for
            canon = canonicalize_diff(draft.unified_diff, path=finding.file, orig_text=text, shown=shown, window=window)
        errors += canon.errors
        if not errors:
            problem = await _git_check(controller, finding.scan_id, finding.file, text, canon.diff)
            if problem:
                errors.append(problem)
        if not errors:  # applies cleanly — but does it remove the weakness? (TNW-6)
            problem = await _still_vulnerable(deps, controller, finding, text, canon)
            if problem:
                errors.append(problem)
        if errors:
            rejected.append((draft, errors))
            return errors
        captured["canon"] = canon
        return []

    trace: list[dict[str, Any]] = []
    audit: list[dict[str, Any]] = []
    try:
        draft, source = await structured_call(
            FixEdit, _system_prompt(), payload, validate, trace=trace, **route,
        )
    except GitUnavailable as exc:
        return {"drafted": False, "reason": f"git is not available to verify the diff ({exc})", "audit": []}
    except Exception as exc:  # noqa: BLE001 - the model being down must never fail the scan
        log.warning("remediate.llm_unavailable", finding_id=finding.id, error=type(exc).__name__)
        return {"drafted": False, "reason": llm_unavailable(exc), "audit": []}

    rejected_iter = iter(rejected)
    for attempt in trace:  # what the model produced that was refused, and why
        out: dict[str, Any] = {"rejected": attempt["kind"]}
        if attempt["kind"] == "invalid":
            bad, _ = next(rejected_iter, (None, None))
            if isinstance(bad, FixEdit):
                out["lines"] = [bad.start_line, bad.end_line]
                out["replacement_chars"] = len(bad.replacement)
            elif bad is not None:
                out["diff_chars"] = len(bad.unified_diff)
        audit.append({"source": "llm" if attempt["attempt"] == "llm" else "llm_retry", "output": out, "error": attempt["error"]})

    if draft is None:
        reason = "; ".join(a["error"] for a in trace)[-300:] or "no usable diff"
        return {"drafted": False, "reason": f"no valid diff after a retry ({reason})", "audit": audit}

    canon: CanonResult = captured["canon"]
    cited = [e for e in dict.fromkeys(draft.evidence_ids) if e in allowed] or sorted(
        e.id for e in store.evidence_for(finding.id)
    )[:2]
    attempt_row = _store_draft(
        store, finding, text, canon, description=description, source=source,
        method="edit" if isinstance(draft, FixEdit) else "diff", evidence_ids=cited, window=window,
    )
    return {
        "drafted": True, "fix_id": attempt_row.id, "source": source, "hunks": canon.hunks,
        "added": canon.added, "removed": canon.removed, "audit": audit,
    }


async def remediate(state: dict, config: RunnableConfig) -> dict:
    scan_id = state["scan_id"]
    log.info("node.enter", node="remediate", scan_id=scan_id)
    started = time.monotonic()
    deps = get_deps(config)
    store = deps.store

    scan = store.get_scan(scan_id)
    scan_mode = scan.mode.value if scan is not None and hasattr(scan.mode, "value") else str(state.get("mode"))
    source_root = scan.source_path if scan is not None else None
    allowlist = json.loads(scan.config_json or "{}").get("allowlist") if scan is not None else None
    controller = _controller(deps, allowlist)
    graph = build_graph(store, scan_id, load_handlers(store, scan_id))

    drafted = skipped = no_draft = 0
    errors: list[str] = []
    for finding in sorted(visible_findings(store, scan_id), key=lambda f: (-f.risk, f.id)):
        reason = _skip_reason(store, finding, source_root)
        if reason:
            skipped += 1
            log.info("remediate.skipped", scan_id=scan_id, finding_id=finding.id, reason=reason)
            continue
        try:
            outcome = await _draft_one(deps, controller, finding, source_root, scan_mode, graph)
        except Exception as exc:  # noqa: BLE001 - one finding's failure must not stop the others
            reason_text = f"{type(exc).__name__}: {str(exc)[:200]}"
            log.error("remediate.failed", scan_id=scan_id, finding_id=finding.id, reason=reason_text)
            errors.append(f"remediate.{finding.id}: {reason_text}")
            outcome = {"drafted": False, "reason": reason_text, "audit": []}

        for refused in outcome.get("audit", []):
            store.add_decision(
                scan_id, "remediate", refused["source"], finding_id=finding.id,
                input_summary={"finding_id": finding.id, "file": finding.file, "line": finding.line},
                output=refused["output"], valid=False, error=refused["error"],
            )
        record = {k: v for k, v in outcome.items() if k != "audit"}
        store.add_decision(
            scan_id, "remediate", outcome.get("source", "fallback"), finding_id=finding.id,
            input_summary={"finding_id": finding.id, "file": finding.file, "line": finding.line},
            output=record, valid=True, error=None if outcome["drafted"] else record.get("reason"),
        )
        if outcome["drafted"]:
            drafted += 1
            log.info("remediate.drafted", scan_id=scan_id, finding_id=finding.id, **{k: v for k, v in record.items() if k != "drafted"})
        else:
            no_draft += 1
            log.info("remediate.no_draft", scan_id=scan_id, finding_id=finding.id, reason=record.get("reason"))

    log.info(
        "node.exit", node="remediate", scan_id=scan_id, drafted=drafted, no_draft=no_draft, skipped=skipped,
        duration_ms=int((time.monotonic() - started) * 1000),
    )
    return {"completed_stages": ["remediate"], "errors": errors}
