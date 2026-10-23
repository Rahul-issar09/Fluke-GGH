"""Deterministic helpers for drafting a fix (AG10.2) — no model, no I/O.

The model proposes a unified diff; everything that makes that proposal *safe and
applicable* happens here, in plain code:

* :func:`hide_untrusted` — what the model is shown. Comments, docstrings and (for a
  ``secret`` finding) string literals on the flagged line are replaced by placeholders,
  **line for line**. This reconciles PRD FR-S6 ("code comments never enter the prompt")
  with SD §5.6 ("the handler source goes to the model"): the code does, the text a
  scanned repository could use to talk to the model does not.
* :func:`handler_window` — which part of the file is shown: the enclosing function
  (decorators included) when it fits in 80 lines, else a window around the flagged line.
* :func:`canonicalize_diff` — turns whatever the model wrote into a diff that applies
  to the **real** file. It aligns each hunk with the real lines (a model gets line
  numbers and counts wrong all the time), restores the real text wherever the model
  copied a placeholder, merges hunks that touch, gives every hunk the trailing context
  git insists on, recomputes every header, and refuses anything that is not a small,
  in-window, single-file edit: other files, file creation/deletion/rename, a patched
  file that no longer parses, or added lines that reach for a shell, the network,
  ``eval``, deserialization and the like.

A diff that comes out of :func:`canonicalize_diff` is then checked by ``git apply --check``
on a temp copy (the authoritative gate, run by the remediate node through SafetyController).

TNW-6 — the model no longer has to write a diff at all:

* :class:`FixEdit` / :func:`edit_to_diff` — the model names the lines to replace and writes their
  new code; AEGIS builds the diff itself (``difflib``), so a model can no longer get context
  lines, removed lines or line counts wrong. A line the model copied in its *shown* form
  (with a comment placeholder) is turned back into the real line. The result then goes through
  :func:`canonicalize_diff` like any other diff: every safety check still applies.
* :func:`secret_fix` — a hard-coded secret is fixed by a fixed rule, with no model: the literal
  becomes ``os.environ.get("<NAME>", "")`` and ``import os`` is added if it is missing.
"""

from __future__ import annotations

import ast
import difflib
import io
import re
import tokenize
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

from pydantic import BaseModel, Field

__all__ = [
    "MAX_WINDOW_LINES",
    "HIDDEN_MARKERS",
    "Unparseable",
    "CanonResult",
    "split_lines",
    "hide_untrusted",
    "handler_window",
    "numbered",
    "secret_literals",
    "mask_literals",
    "canonicalize_diff",
    "FixEdit",
    "edit_to_diff",
    "diff_between",
    "secret_fix",
    "choose_fixed_version",
    "dependency_recommendation",
    "requirements_upgrade_diff",
    "load_template",
    "TEMPLATE_DIR",
]

MAX_WINDOW_LINES = 80
MAX_DIFF_CHARS = 20_000
MAX_ADDED_LINES = 60
MAX_HUNKS = 6
_MODULE_WINDOW = 15

PLACEHOLDER_COMMENT = "# [comment removed]"
PLACEHOLDER_DOCSTRING = '"""[docstring removed]"""'
PLACEHOLDER_LITERAL = '"<redacted>"'
HIDDEN_MARKERS = ("[comment removed]", "[docstring removed]", "<redacted>")

TEMPLATE_DIR = Path(__file__).resolve().parents[2] / "rules" / "fix_templates"

_DENY = (
    (re.compile(r"\b(eval|exec|compile|__import__)\s*\("), "dynamic code execution"),
    (re.compile(r"\bos\.(system|popen|exec\w*|spawn\w*)\b"), "running a shell command"),
    (re.compile(r"\bsubprocess\b"), "running a subprocess"),
    (re.compile(r"\b(pickle|marshal|shelve)\b"), "unsafe deserialization"),
    (re.compile(r"\b(socket|ctypes)\b"), "low-level system access"),
    (re.compile(r"\b(requests|urllib|httpx|aiohttp)\b|\bhttp\.client\b"), "a network call"),
    (re.compile(r"\bopen\s*\("), "file access"),
)
_LINE_NUMBER_PREFIX = re.compile(r"^\s{0,4}\d{1,5} \| ?")
_HUNK_HEADER = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
_CRLF = "\r\n"


class Unparseable(Exception):
    """The source is not valid Python, so it cannot be safely windowed or masked."""


# --------------------------------------------------------------------------- #
# lines
# --------------------------------------------------------------------------- #
def split_lines(text: str) -> list[str]:
    """Split on newline only (like git), keeping each line's own ending."""
    return re.findall(r"[^\n]*\n|[^\n]+", text)


def _body(line: str) -> str:
    return line.rstrip("\r\n")


# --------------------------------------------------------------------------- #
# what the model is shown
# --------------------------------------------------------------------------- #
def hide_untrusted(text: str, secret_lines: Iterable[int] = ()) -> list[str]:
    """The file's lines (no line endings) with untrusted text replaced, line for line."""
    lines = [_body(line) for line in split_lines(text)]
    secret = set(secret_lines)
    try:
        tokens = list(tokenize.generate_tokens(io.StringIO(text).readline))
        tree = ast.parse(text)
    except (tokenize.TokenError, SyntaxError, IndentationError, ValueError) as exc:
        raise Unparseable(str(exc)) from exc

    edits: dict[int, list[tuple[int, int, str]]] = defaultdict(list)
    for tok in tokens:
        (srow, scol), (erow, ecol) = tok.start, tok.end
        if tok.type == tokenize.COMMENT:
            edits[srow].append((scol, ecol, PLACEHOLDER_COMMENT))
        elif tok.type == tokenize.STRING and srow in secret and srow == erow:
            edits[srow].append((scol, ecol, PLACEHOLDER_LITERAL))

    shown = list(lines)
    for row, row_edits in edits.items():
        line = shown[row - 1]
        for start, end, replacement in sorted(row_edits, reverse=True):  # right to left keeps columns valid
            line = line[:start] + replacement + line[end:]
        shown[row - 1] = line

    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            first = node.body[0] if node.body else None
            if (
                isinstance(first, ast.Expr)
                and isinstance(first.value, ast.Constant)
                and isinstance(first.value.value, str)
            ):
                shown[first.lineno - 1] = " " * first.col_offset + PLACEHOLDER_DOCSTRING
                for row in range(first.lineno + 1, first.end_lineno + 1):
                    shown[row - 1] = ""
    return shown


def secret_literals(text: str, secret_lines: Iterable[int]) -> list[str]:
    """The string literals (as written in source) on the given lines."""
    rows = set(secret_lines)
    found: list[str] = []
    try:
        for tok in tokenize.generate_tokens(io.StringIO(text).readline):
            if tok.type == tokenize.STRING and tok.start[0] in rows and tok.start[0] == tok.end[0]:
                found.append(tok.string)
    except (tokenize.TokenError, SyntaxError, IndentationError):
        return []
    return found


def mask_literals(text: str, literals: Iterable[str]) -> str:
    for literal in literals:
        text = text.replace(literal, PLACEHOLDER_LITERAL)
    return text


def handler_window(text: str, line: int, max_lines: int = MAX_WINDOW_LINES) -> tuple[int, int]:
    """1-based inclusive ``(start, end)``: the function around *line*, else a window, ≤ max_lines."""
    total = len(split_lines(text))
    try:
        tree = ast.parse(text)
    except (SyntaxError, IndentationError, ValueError) as exc:
        raise Unparseable(str(exc)) from exc

    best: tuple[int, int] | None = None
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            start = min([d.lineno for d in node.decorator_list] + [node.lineno])
            if start <= line <= node.end_lineno and (best is None or node.end_lineno - start < best[1] - best[0]):
                best = (start, node.end_lineno)
    if best is not None and best[1] - best[0] + 1 <= max_lines:
        return best

    span = max_lines if best is not None else 2 * _MODULE_WINDOW + 1  # too-long function vs. module level
    start = max(1, line - span // 2)
    end = min(total, start + span - 1)
    return max(1, end - span + 1), end


def numbered(shown: list[str], start: int, end: int) -> str:
    """The window with line numbers (a reading aid; the prompt says they are not code)."""
    return "\n".join(f"{n:>4} | {shown[n - 1]}" for n in range(start, end + 1))


# --------------------------------------------------------------------------- #
# the model's diff -> a diff that applies to the real file
# --------------------------------------------------------------------------- #
@dataclass
class CanonResult:
    diff: str | None = None
    errors: list[str] = field(default_factory=list)
    new_text: str | None = None
    hunks: int = 0
    added: int = 0
    removed: int = 0


def _strip_fences(text: str) -> str:
    fenced = re.search(r"```[A-Za-z]*\n(.*?)```", text, re.DOTALL)
    if fenced:
        return fenced.group(1)
    return "\n".join(l for l in text.split("\n") if not l.strip().startswith("```"))


def _header_path(line: str) -> str:
    path = line[4:].split("\t")[0].strip()
    return path[2:] if path[:2] in ("a/", "b/") else path


def _parse(text: str, path: str) -> tuple[list[dict], list[str]]:
    """Hunks as ``{"start", "lines": [(marker, text)]}`` and any structural errors."""
    errors: list[str] = []
    lines = text.replace(_CRLF, "\n").split("\n")
    while lines and lines[-1] == "":
        lines.pop()

    hunks: list[dict] = []
    seen_headers = 0
    i = 0
    while i < len(lines):
        line = lines[i]
        if line.startswith(
            ("new file mode", "deleted file mode", "rename ", "similarity index", "old mode", "new mode", "Binary files")
        ):
            errors.append("only edits to the existing file are allowed (no create, delete, rename or mode change)")
        elif line.startswith("--- ") and i + 1 < len(lines) and lines[i + 1].startswith("+++ "):
            old, new = _header_path(line), _header_path(lines[i + 1])
            seen_headers += 1
            if "/dev/null" in (old, new):
                errors.append("only edits to the existing file are allowed (no create or delete)")
            elif seen_headers > 1:
                errors.append("only one file may be changed")
            elif old != path or new != path:
                errors.append(f"the diff targets '{new}', but the only file that may change is '{path}'")
            i += 1
        elif line.startswith("@@"):
            m = _HUNK_HEADER.match(line)
            hunks.append({"start": int(m.group(1)) if m else None, "lines": []})
        elif hunks:
            if line.startswith("\\"):
                pass  # "\ No newline at end of file"
            elif line == "":
                hunks[-1]["lines"].append((" ", ""))  # a blank context line that lost its leading space
                hunks[-1]["blank_tail"] = hunks[-1].get("blank_tail", 0) + 1
            elif line[0] in " +-":
                hunks[-1]["lines"].append((line[0], line[1:]))
                hunks[-1]["blank_tail"] = 0
            else:
                if any(l.startswith("@@") for l in lines[i:]):
                    errors.append(f"unexpected text inside the diff: '{line[:60]}'")
                tail = hunks[-1].get("blank_tail", 0)
                if tail:  # blank lines that only separated the diff from the explanation after it
                    del hunks[-1]["lines"][-tail:]
                break  # trailing explanation after the last hunk
        i += 1
    return hunks, errors


def _strip_line_numbers(hunks: list[dict]) -> None:
    """If the model copied the numbered reading aid into its diff, take it back out."""
    for marker_set in ((" ", "-"), ("+",)):
        body = [t for h in hunks for m, t in h["lines"] if m in marker_set and t != ""]
        if body and all(_LINE_NUMBER_PREFIX.match(t) for t in body):
            for h in hunks:
                h["lines"] = [
                    (m, _LINE_NUMBER_PREFIX.sub("", t, count=1) if m in marker_set and t != "" else t)
                    for m, t in h["lines"]
                ]


def _align(
    old_side: list[str], bodies: list[str], shown: list[str], lo: int, hi: int, hint: int | None, min_idx: int
) -> int | None:
    """Where in the file (0-based) the hunk's old side sits; matches the real or the shown text."""
    n = len(old_side)
    first = max(lo, min_idx)
    centre = (hint - 1) if hint else first
    for idx in sorted(range(first, hi - n + 1), key=lambda i: (abs(i - centre), i)):
        if all(old_side[k].rstrip() in (bodies[idx + k].rstrip(), shown[idx + k].rstrip()) for k in range(n)):
            return idx
    return None


def _mismatch_message(
    number: int, old_side: list[str], bodies: list[str], shown: list[str], lo: int, hi: int, hint: int | None, min_idx: int
) -> str:
    """Say which line of the hunk broke the match and what the file has there.

    The file's line is quoted in its *shown* form (comments, docstrings and secrets still hidden),
    so the message — which goes back to the model on a retry — can never reveal hidden text.
    """
    n = len(old_side)
    first = max(lo, min_idx)
    centre = (hint - 1) if hint else first
    best_idx, best_run = first, 0
    for idx in sorted(range(first, max(first, hi)), key=lambda i: (abs(i - centre), i)):
        run = 0
        while run < n and idx + run < hi and old_side[run].rstrip() in (bodies[idx + run].rstrip(), shown[idx + run].rstrip()):
            run += 1
        if run > best_run:
            best_idx, best_run = idx, run
    advice = "copy context and removed lines exactly as shown, without line numbers"
    if best_run == 0:
        wanted = next((t for t in old_side if t.strip()), old_side[0])
        return f"hunk {number}: the line '{wanted.strip()[:60]}' was not found in the lines shown; {advice}"
    if best_idx + best_run >= hi:
        return f"hunk {number}: it runs past the last line shown (line {hi}); keep the hunk inside the lines shown"
    got = old_side[best_run].strip()[:60]
    have = shown[best_idx + best_run].strip()[:60]
    return f"hunk {number}: the line '{got}' does not match the file, which has '{have}' there; {advice}"


def canonicalize_diff(
    model_diff: str,
    *,
    path: str,
    orig_text: str,
    shown: list[str],
    window: tuple[int, int],
) -> CanonResult:
    """Rebuild *model_diff* against the real file, or say precisely why that is impossible."""
    result = CanonResult()
    if not model_diff or not model_diff.strip():
        result.errors.append("the diff is empty")
        return result
    if len(model_diff) > MAX_DIFF_CHARS:
        result.errors.append(f"the diff is too large (more than {MAX_DIFF_CHARS} characters)")
        return result
    if orig_text and not orig_text.endswith("\n"):
        result.errors.append("the file has no trailing newline; such files are not supported")
        return result

    hunks, errors = _parse(_strip_fences(model_diff), path)
    if errors:
        result.errors += list(dict.fromkeys(errors))
        return result
    if not hunks:
        result.errors.append("the diff has no hunks (expected lines starting with '@@')")
        return result
    if len(hunks) > MAX_HUNKS:
        result.errors.append(f"the diff has more than {MAX_HUNKS} hunks; keep the fix small")
        return result
    _strip_line_numbers(hunks)

    orig_lines = split_lines(orig_text)
    bodies = [_body(l) for l in orig_lines]
    eol = _CRLF if sum(l.endswith(_CRLF) for l in orig_lines) > len(orig_lines) / 2 else "\n"
    lo, hi = window[0] - 1, window[1]

    # pass 1 — find where every hunk really sits (hunks must come in order and not overlap)
    min_idx = lo
    for number, hunk in enumerate(hunks, start=1):
        old_side = [t for m, t in hunk["lines"] if m in (" ", "-")]
        if not any(t.strip() for t in old_side):
            result.errors.append(f"hunk {number}: it needs at least one existing, non-blank line as context")
            return result
        idx = _align(old_side, bodies, shown, lo, hi, hunk["start"], min_idx)
        if idx is None:
            result.errors.append(_mismatch_message(number, old_side, bodies, shown, lo, hi, hunk["start"], min_idx))
            return result
        hunk.update(idx=idx, old_len=len(old_side), number=number)
        min_idx = idx + len(old_side)

    # hunks that touch are one hunk
    merged = [hunks[0]]
    for hunk in hunks[1:]:
        last = merged[-1]
        if last["idx"] + last["old_len"] == hunk["idx"]:
            last["lines"] += hunk["lines"]
            last["old_len"] += hunk["old_len"]
        else:
            merged.append(hunk)
    hunks = merged

    # git insists that a hunk with no trailing context sits at the very end of the file, and
    # models often end a diff on an added line: give such a hunk one real line to end on
    for k, hunk in enumerate(hunks):
        end = hunk["idx"] + hunk["old_len"]
        limit = hunks[k + 1]["idx"] if k + 1 < len(hunks) else len(orig_lines)
        if hunk["lines"][-1][0] != " " and end < limit:
            hunk["lines"].append((" ", ""))
            hunk["old_len"] += 1

    # pass 2 — emit the canonical hunks (context and removed lines are always the REAL lines)
    out: list[str] = []
    delta = 0  # how far new-side line numbers have drifted from old-side ones
    added = removed = 0
    for hunk in hunks:
        body_lines: list[str] = []
        pointer = hunk["idx"]
        old_count = new_count = 0
        for marker, text in hunk["lines"]:
            if marker == "+":
                if any(m in text for m in HIDDEN_MARKERS):
                    result.errors.append(f"hunk {hunk['number']}: an added line contains a hidden-content placeholder; write real code")
                    return result
                for pattern, what in (_DENY if path.endswith(".py") else ()):
                    if not text.lstrip().startswith("#") and pattern.search(text):
                        result.errors.append(
                            f"hunk {hunk['number']}: an added line uses {what}, which a security fix must not introduce"
                        )
                        return result
                body_lines.append("+" + text + eol)
                new_count += 1
                added += 1
            else:
                body_lines.append(marker + orig_lines[pointer])
                pointer += 1
                old_count += 1
                if marker == " ":
                    new_count += 1
                else:
                    removed += 1
        out.append(f"@@ -{hunk['idx'] + 1},{old_count} +{hunk['idx'] + 1 + delta},{new_count} @@\n" + "".join(body_lines))
        delta += new_count - old_count
        result.hunks += 1

    if added == 0 and removed == 0:
        result.errors.append("the diff changes nothing")
        return result
    if added > MAX_ADDED_LINES:
        result.errors.append(f"the diff adds {added} lines; keep the fix under {MAX_ADDED_LINES}")
        return result

    result.new_text = _apply(orig_lines, hunks, eol)
    if path.endswith(".py"):
        try:
            ast.parse(result.new_text)
        except SyntaxError as exc:
            result.errors.append(f"the patched file would not be valid Python ({exc.msg}, line {exc.lineno})")
            result.new_text = None
            return result

    result.added, result.removed = added, removed
    result.diff = f"--- a/{path}\n+++ b/{path}\n" + "".join(out)
    return result


def _apply(orig_lines: list[str], hunks: list[dict], eol: str) -> str:
    """Apply the already-aligned hunks to the original lines, in memory."""
    result: list[str] = []
    cursor = 0
    for hunk in hunks:
        idx = hunk["idx"]
        result.extend(orig_lines[cursor:idx])  # untouched lines stay exactly as they were
        pointer = idx
        for marker, text in hunk["lines"]:
            if marker == "+":
                result.append(text + eol)
            else:
                if marker == " ":
                    result.append(orig_lines[pointer])
                pointer += 1
        cursor = pointer
    result.extend(orig_lines[cursor:])
    return "".join(result)


# --------------------------------------------------------------------------- #
# TNW-6: the model writes the new lines, AEGIS writes the diff
# --------------------------------------------------------------------------- #
class FixEdit(BaseModel):
    """A fix as the model proposes it: replace lines ``start_line``..``end_line`` (1-based,
    inclusive) with ``replacement``. ``end_line = start_line - 1`` inserts without removing."""

    finding_id: str
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=0)
    replacement: str
    evidence_ids: list[str] = Field(default_factory=list)


_TRAILING_PLACEHOLDER = re.compile(r"\s*" + re.escape(PLACEHOLDER_COMMENT) + r"\s*$")


def diff_between(path: str, orig_lines: list[str], new_lines: list[str]) -> str:
    """A unified diff of two versions of one file (lines keep their own endings)."""
    return "".join(difflib.unified_diff(orig_lines, new_lines, f"a/{path}", f"b/{path}", n=3))


def _eol(orig_lines: list[str]) -> str:
    return _CRLF if sum(l.endswith(_CRLF) for l in orig_lines) > len(orig_lines) / 2 else "\n"


def edit_to_diff(
    start: int,
    end: int,
    replacement: str,
    *,
    path: str,
    orig_text: str,
    shown: list[str],
    window: tuple[int, int],
) -> CanonResult:
    """Turn "replace lines *start*..*end* with *replacement*" into a checked, canonical diff."""
    orig_lines = split_lines(orig_text)
    lo, hi = window
    if not (lo <= start <= hi + 1 and start - 1 <= end <= hi):
        return CanonResult(errors=[
            f"lines {start}-{end} are not inside the lines shown ({lo}-{hi}); "
            "start_line and end_line must be line numbers from handler_source"
        ])
    text = _strip_fences(replacement) if "```" in replacement else replacement
    result = _edit_once(start, end, text, path=path, orig_text=orig_text, shown=shown, orig_lines=orig_lines)
    # a model sometimes escapes its line breaks twice: two lines arrive as one, joined by a literal
    # backslash-n. Read them as line breaks only when the text as written is not usable.
    if result.errors and "\n" not in text.strip() and "\\n" in text:
        unescaped = _edit_once(start, end, text.replace("\\n", "\n"), path=path, orig_text=orig_text, shown=shown, orig_lines=orig_lines)
        if not unescaped.errors:
            return unescaped
    return result


def _edit_once(
    start: int, end: int, text: str, *, path: str, orig_text: str, shown: list[str], orig_lines: list[str]
) -> CanonResult:
    new = text.replace(_CRLF, "\n").split("\n")
    while new and new[-1].strip() == "":
        new.pop()
    body = [l for l in new if l.strip()]
    if body and all(_LINE_NUMBER_PREFIX.match(l) for l in body):  # copied the reading aid
        new = [_LINE_NUMBER_PREFIX.sub("", l, count=1) for l in new]

    # a line copied in its shown form (comment placeholder and all) is the real line, unchanged
    hidden = {
        shown[n - 1].rstrip(): _body(orig_lines[n - 1])
        for n in range(start, end + 1)
        if shown[n - 1] != _body(orig_lines[n - 1])
    }
    restored = []
    for line in new:
        if line.rstrip() in hidden:
            line = hidden[line.rstrip()]
        elif PLACEHOLDER_COMMENT in line:
            line = _TRAILING_PLACEHOLDER.sub("", line)  # a comment is not code: just drop it
        restored.append(line)

    eol = _eol(orig_lines)
    new_lines = orig_lines[: start - 1] + [l + eol for l in restored] + orig_lines[end:]
    if new_lines == orig_lines:
        return CanonResult(errors=["the edit changes nothing"])
    return canonicalize_diff(
        diff_between(path, orig_lines, new_lines), path=path, orig_text=orig_text, shown=shown,
        window=(1, len(orig_lines)),  # the edit itself was checked against the window above
    )


def choose_fixed_version(current: str | None, fixed_in: Iterable[str]) -> str | None:
    """The lowest published fixed version greater than *current* (evidence only; never invented).

    Uses PEP 440 ordering when the versions parse, else a plain sorted order. Returns ``None`` when
    *fixed_in* is empty (no fix published) so the caller recommends an upgrade without a version."""
    candidates = [str(v).strip() for v in fixed_in if str(v).strip()]
    if not candidates:
        return None
    try:
        from packaging.version import InvalidVersion, Version

        def parsed(v: str):
            try:
                return (0, Version(v))
            except InvalidVersion:
                return (1, v)  # unparseable versions sort after parseable ones, deterministically

        cur = None
        if current:
            try:
                cur = Version(str(current))
            except InvalidVersion:
                cur = None
        ahead = [v for v in candidates if cur is None or (lambda pv: pv[0] == 0 and pv[1] > cur)(parsed(v))]
        pool = ahead or candidates
        return sorted(pool, key=parsed)[0]
    except Exception:  # noqa: BLE001 - packaging missing or odd versions: fall back to a stable order
        return sorted(candidates)[0]


def dependency_recommendation(package: str, version: str | None, fixed_in: Iterable[str], advisories: Iterable[str]) -> tuple[str, str | None]:
    """``(recommendation text, chosen version | None)`` for a vulnerable dependency, from evidence only."""
    fixed = [str(v).strip() for v in fixed_in if str(v).strip()]
    advisories = [str(a) for a in advisories if a]
    chosen = choose_fixed_version(version, fixed)
    where = f"{package} {version}" if version else str(package)
    cites = (" Advisories: " + ", ".join(advisories[:5]) + ".") if advisories else ""
    if chosen:
        return (f"Upgrade {where} to {chosen} — the published fixed version"
                + (f" (fixed versions: {', '.join(fixed)})" if len(fixed) > 1 else "") + "." + cites), chosen
    return (f"No fixed version is published for {where} yet; remove, replace, or pin to a safe "
            f"version once one is available, and apply any mitigation the advisory describes." + cites), None


def requirements_upgrade_diff(path: str, orig_text: str, line: int, package: str, chosen: str) -> CanonResult:
    """A diff that repins a ``package==x`` line in a requirements file to *chosen*, or an error.

    Only a simple pinned ``name==version`` line is edited; anything else (ranges, markers, lockfiles,
    npm/go manifests) gets a recommendation with no diff, because repinning it safely is not
    something AEGIS can do from the advisory alone."""
    orig_lines = split_lines(orig_text)
    if not (1 <= line <= len(orig_lines)):
        return CanonResult(errors=["the pinned line is outside the file"])
    current = _body(orig_lines[line - 1])
    m = re.match(r"^(?P<pre>\s*)(?P<name>[A-Za-z0-9._-]+)\s*==\s*(?P<ver>[^\s;#]+)\s*$", current)
    if m is None or re.sub(r"[-_.]+", "-", m.group("name")).lower() != re.sub(r"[-_.]+", "-", str(package)).lower():
        return CanonResult(errors=["the manifest line is not a simple pinned requirement for this package"])
    new_line = f'{m.group("pre")}{m.group("name")}=={chosen}'
    new_lines = orig_lines[: line - 1] + [new_line + _eol(orig_lines)] + orig_lines[line:]
    if new_lines == orig_lines:
        return CanonResult(errors=["the edit changes nothing"])
    return canonicalize_diff(
        diff_between(path, orig_lines, new_lines), path=path, orig_text=orig_text,
        shown=[_body(l) for l in orig_lines], window=(1, len(orig_lines)),
    )


def _env_name(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9]+", "_", name).strip("_").upper() or "SECRET"


def _secret_node(tree: ast.Module, line: int) -> tuple[ast.Constant, str] | None:
    """The string literal on *line* and the name it belongs to: an assignment's target, a keyword
    argument's name, or a dict entry's key."""
    def literal(node) -> bool:
        return isinstance(node, ast.Constant) and isinstance(node.value, str) and node.lineno == line == node.end_lineno

    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign)) and literal(node.value):
            target = node.targets[0] if isinstance(node, ast.Assign) else node.target
            name = target.id if isinstance(target, ast.Name) else target.attr if isinstance(target, ast.Attribute) else None
            if name:
                return node.value, name
        elif isinstance(node, ast.keyword) and node.arg and literal(node.value):
            return node.value, node.arg
        elif isinstance(node, ast.Dict):
            for key, value in zip(node.keys, node.values):
                if isinstance(key, ast.Constant) and isinstance(key.value, str) and literal(value):
                    return value, key.value
    return None


def _imports_os(tree: ast.Module) -> bool:
    return any(
        isinstance(n, ast.Import) and any((a.name == "os" or a.name.startswith("os.")) and a.asname in (None, "os") for a in n.names)
        for n in tree.body
    )


def _import_row(tree: ast.Module) -> int:
    """0-based line index where ``import os`` goes: before the first import, else after the
    module docstring and any ``from __future__`` imports."""
    after = 0
    for n in tree.body:
        if isinstance(n, ast.ImportFrom) and n.module == "__future__":
            after = n.end_lineno
            continue
        if isinstance(n, (ast.Import, ast.ImportFrom)):
            return n.lineno - 1
        if isinstance(n, ast.Expr) and isinstance(n.value, ast.Constant) and isinstance(n.value.value, str) and after == 0 and n is tree.body[0]:
            after = n.end_lineno
            continue
        break
    return after


def secret_fix(text: str, line: int) -> tuple[str | None, str]:
    """``(new_text, env_var)`` with the secret on *line* read from the environment, or
    ``(None, reason)`` when the line has no shape this rule handles."""
    try:
        tree = ast.parse(text)
    except SyntaxError as exc:
        return None, f"the source does not parse ({exc.msg})"
    found = _secret_node(tree, line)
    if found is None:
        return None, "no string assigned to a name, keyword argument or dict key on the flagged line"
    node, name = found
    env = _env_name(name)
    lines = split_lines(text)
    raw = lines[line - 1].encode("utf-8")  # ast column offsets count UTF-8 bytes
    lookup = f'os.environ.get("{env}", "")'.encode("utf-8")
    lines[line - 1] = (raw[: node.col_offset] + lookup + raw[node.end_col_offset:]).decode("utf-8")
    if not _imports_os(tree):
        lines.insert(_import_row(tree), "import os" + _eol(lines))
    return "".join(lines), env


# --------------------------------------------------------------------------- #
# fix templates
# --------------------------------------------------------------------------- #
def load_template(type_: str, directory: Path | None = None) -> tuple[str, str] | None:
    """``(description, hint)`` for a weakness type, or ``None`` if there is no template.

    File format: a first line ``description: ...``, a blank line, then the hint text.
    """
    path = (directory or TEMPLATE_DIR) / f"{type_}.md"
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return None
    head, _, hint = text.replace(_CRLF, "\n").partition("\n\n")
    if not head.startswith("description:"):
        return None
    return head[len("description:"):].strip(), hint.strip()
