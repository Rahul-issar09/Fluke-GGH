"""Intra-function data flow (Worker 2, AG14.1) — how a handler's input reaches a finding's line.

Semgrep's free engine reports *that* a rule matched but exports no trace. This module computes
the trace itself, deterministically, from the source (parsed with ``ast``, never executed):

* the **sources** are the enclosing function's parameters (for a route handler: the request's
  path, query and body values, and ``request`` itself);
* every assignment whose value uses a tainted name taints its targets — in source order, within
  the one function;
* one call level (TNW-5, :func:`trace_through_call`): when the reported line is in a helper
  function, a route handler **in the same file** that passes its input to that helper is
  followed into it — handler parameter → the call's argument → the helper's parameter → sink.
  Calls in other files, and helpers of helpers, are not followed;
* the **sink** is the statement on the reported line; the trace exists if it uses a tainted name.

Result: ``{"source": ["search_users(name)", 12], "steps": [{"line": 15, "var": "query",
"from": ["name"]}], "sink": ["...execute(query)...", 16]}``. The evidence records that AEGIS
computed it (``"traced_by"``), so nobody mistakes it for the scanner's own output.

It is deliberately conservative: only plain names and attribute/subscript reads of them carry
taint, so a value that is passed to another function and returned is not followed (no
false flows through code it cannot see).
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field

__all__ = ["Trace", "trace_to_line", "trace_through_call", "TRACED_BY", "TRACED_BY_CALL"]

TRACED_BY = "aegis ast def-use (intra-function)"
TRACED_BY_CALL = "aegis ast def-use (one call level)"
_GENERIC_PARAMS = ("self", "cls", "request", "req", "db", "session")


@dataclass
class Trace:
    function: str
    param: str
    def_line: int
    steps: list[dict] = field(default_factory=list)
    sink_text: str = ""
    sink_line: int = 0
    traced_by: str = TRACED_BY

    def as_payload(self) -> dict:
        return {
            "source": [f"{self.function}({self.param})", self.def_line],
            "steps": self.steps,
            "sink": [self.sink_text, self.sink_line],
            "traced_by": self.traced_by,
        }


def _functions(tree: ast.Module) -> list[ast.FunctionDef | ast.AsyncFunctionDef]:
    return [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]


def _enclosing(tree: ast.Module, line: int):
    best = None
    for fn in _functions(tree):
        if fn.lineno <= line <= (fn.end_lineno or fn.lineno) and (best is None or fn.lineno > best.lineno):
            best = fn
    return best


def _params(fn) -> list[str]:
    a = fn.args
    names = [p.arg for p in (*a.posonlyargs, *a.args, *a.kwonlyargs)]
    if a.vararg:
        names.append(a.vararg.arg)
    if a.kwarg:
        names.append(a.kwarg.arg)
    return names


def _read_names(node: ast.AST) -> set[str]:
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load)}


def _target_names(target: ast.AST) -> set[str]:
    return {n.id for n in ast.walk(target) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store)}


def _assignments(fn, before: int) -> list[tuple[int, set[str], set[str]]]:
    """``(line, targets, names read)`` for each assignment in *fn* before line *before*, in order."""
    out = []
    for node in ast.walk(fn):
        line = getattr(node, "lineno", None)
        if line is None or line >= before:
            continue
        if isinstance(node, ast.Assign):
            out.append((line, set().union(*(_target_names(t) for t in node.targets)), _read_names(node.value)))
        elif isinstance(node, (ast.AnnAssign, ast.AugAssign)) and node.value is not None:
            reads = _read_names(node.value) | (_target_names(node.target) if isinstance(node, ast.AugAssign) else set())
            out.append((line, _target_names(node.target) or {getattr(node.target, "id", "")}, reads))
        elif isinstance(node, (ast.For, ast.AsyncFor, ast.comprehension)):
            out.append((getattr(node, "lineno", line), _target_names(node.target), _read_names(node.iter)))
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                if item.optional_vars is not None:
                    out.append((line, _target_names(item.optional_vars), _read_names(item.context_expr)))
    return sorted(out, key=lambda a: a[0])


def _statement_at(fn, line: int) -> ast.stmt | None:
    best = None
    for node in ast.walk(fn):
        if isinstance(node, ast.stmt) and node is not fn and node.lineno <= line <= (node.end_lineno or node.lineno):
            if best is None or (node.end_lineno or node.lineno) - node.lineno < (best.end_lineno or best.lineno) - best.lineno:
                best = node
    return best


def _flow(fn, names: set[str], before: int) -> tuple[str, list[dict]] | None:
    """``(parameter, steps)``: how one of *names*, read at line *before*, comes from *fn*'s parameters."""
    params = _params(fn)
    origin: dict[str, tuple[int, set[str]] | None] = {p: None for p in params}  # var → (line, from) | param
    for at, targets, reads in _assignments(fn, before=before):
        tainted_reads = {r for r in reads if r in origin}
        for t in targets:
            if tainted_reads:
                origin[t] = (at, tainted_reads)
            elif t in origin and origin[t] is not None:
                del origin[t]  # overwritten with something untainted

    used = [n for n in names if n in origin]
    if not used:
        return None

    def to_param(var: str, seen: frozenset = frozenset()) -> tuple[str, list[dict]] | None:
        if var in seen:
            return None
        info = origin.get(var)
        if info is None:
            return (var, []) if var in params else None
        at, froms = info
        for src in sorted(froms, key=lambda s: (s in _GENERIC_PARAMS, s)):
            found = to_param(src, seen | {var})
            if found:
                param, steps = found
                return param, [*steps, {"line": at, "var": var, "from": sorted(froms)}]
        return None

    # prefer the specific input (e.g. ``id``, ``name``) over the generic request/db handle
    for var in sorted(used, key=lambda v: (v in _GENERIC_PARAMS, v)):
        found = to_param(var)
        if found:
            return found
    return None


def _sink_text(text: str, sink: ast.stmt) -> str:
    return " ".join((ast.get_source_segment(text, sink) or "").split())[:160]


def trace_to_line(text: str, line: int, *, tree: ast.Module | None = None) -> Trace | None:
    """The flow from a parameter of the function around *line* to the statement on *line*, if any."""
    tree = tree or ast.parse(text)
    fn = _enclosing(tree, line)
    if fn is None:
        return None
    sink = _statement_at(fn, line)
    if sink is None:
        return None
    found = _flow(fn, _read_names(sink), sink.lineno)
    if found is None:
        return None
    param, steps = found
    return Trace(fn.name, param, fn.lineno, steps, _sink_text(text, sink), line)


def _argument_for(call: ast.Call, helper, param: str, method: bool) -> ast.AST | None:
    """The expression *call* passes for *helper*'s parameter *param*."""
    for kw in call.keywords:
        if kw.arg == param:
            return kw.value
    names = [p.arg for p in (*helper.args.posonlyargs, *helper.args.args)]
    if method and names and names[0] in ("self", "cls"):
        names = names[1:]
    if param in names and names.index(param) < len(call.args):
        arg = call.args[names.index(param)]
        return None if isinstance(arg, ast.Starred) else arg
    return None


def trace_through_call(text: str, line: int, handlers, *, tree: ast.Module | None = None) -> Trace | None:
    """The flow from a route handler's input, through one call into the helper around *line*, to *line*.

    *handlers* are the route-handler functions of the same file (``routes_fastapi.route_handlers``)."""
    tree = tree or ast.parse(text)
    helper = _enclosing(tree, line)
    inner = trace_to_line(text, line, tree=tree) if helper is not None else None
    if inner is None or any(h is helper for h in handlers):
        return None
    for handler in sorted(handlers, key=lambda h: h.lineno):
        for call in sorted((n for n in ast.walk(handler) if isinstance(n, ast.Call)), key=lambda n: n.lineno):
            target = call.func
            name = target.id if isinstance(target, ast.Name) else target.attr if isinstance(target, ast.Attribute) else None
            if name != helper.name:
                continue
            arg = _argument_for(call, helper, inner.param, method=isinstance(target, ast.Attribute))
            if arg is None:
                continue
            outer = _flow(handler, _read_names(arg), call.lineno)
            if outer is None:
                continue
            param, steps = outer
            hop = {"line": call.lineno, "var": f"{helper.name}({inner.param})", "from": sorted(_read_names(arg)), "call": helper.name}
            return Trace(handler.name, param, handler.lineno, [*steps, hop, *inner.steps], inner.sink_text, line, TRACED_BY_CALL)
    return None
