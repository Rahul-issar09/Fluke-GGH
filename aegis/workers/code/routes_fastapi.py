"""Route → handler extraction (Worker 2, AG14.1, PHASES P7.2).

Maps every HTTP route in the source to the function that handles it, with file and line,
so correlation can link a runtime finding to its code.

The source is **parsed, never executed**: Python's own ``ast`` reads each file (exact for
Python, no extra dependency — tree-sitter, named in the plan, is not installed; see the AG14
notes). Run it in a thread (``asyncio.to_thread``); a file that does not parse is logged and
skipped, and the scan goes on.

Recognised forms:

* FastAPI — ``@app.get("/p")``, ``@router.post(...)`` (any of get/post/put/patch/delete/
  head/options), ``@router.api_route("/p", methods=[...])``; ``APIRouter(prefix="/x")`` in the
  same module and ``app.include_router(module.router, prefix="/y")`` across modules.
* Flask — ``@app.route("/p", methods=[...])`` (default GET), ``@bp.get(...)``,
  ``Blueprint(..., url_prefix="/x")``.

Paths are kept as written (``{id}`` / ``<int:id>``); ``graph.route_normalize`` makes them
comparable with runtime routes.
"""

from __future__ import annotations

import ast
from pathlib import Path, PurePosixPath

from aegis.observability import get_logger

__all__ = ["extract_routes", "is_route_handler", "routes_in_source", "MAX_FILE_BYTES"]

log = get_logger("workers.code.routes")

MAX_FILE_BYTES = 1_000_000
_VERBS = ("get", "post", "put", "patch", "delete", "head", "options")
_SKIP_DIRS = {".git", ".hg", ".venv", "venv", "env", "node_modules", "__pycache__", "site-packages", ".tox", ".mypy_cache"}


def _const_str(node: ast.AST | None) -> str | None:
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def _kwarg(call: ast.Call, name: str) -> ast.AST | None:
    return next((k.value for k in call.keywords if k.arg == name), None)


def _methods(node: ast.AST | None) -> list[str] | None:
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        values = [_const_str(e) for e in node.elts]
        if values and all(values):
            return [v.upper() for v in values]
    return None


def _router_prefixes(tree: ast.Module) -> dict[str, str]:
    """``name = APIRouter(prefix="/x")`` / ``Blueprint(..., url_prefix="/x")`` → {name: prefix}."""
    out: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call) and len(node.targets) == 1:
            target, call = node.targets[0], node.value
            ctor = call.func.attr if isinstance(call.func, ast.Attribute) else getattr(call.func, "id", "")
            if isinstance(target, ast.Name) and ctor in ("APIRouter", "Blueprint"):
                prefix = _const_str(_kwarg(call, "prefix") or _kwarg(call, "url_prefix"))
                if prefix:
                    out[target.id] = prefix.rstrip("/")
    return out


def _route_of(decorator: ast.expr) -> tuple[str, str, list[str]] | None:
    """``(router_name, path, methods)`` for a route decorator, else None."""
    if not (isinstance(decorator, ast.Call) and isinstance(decorator.func, ast.Attribute)):
        return None
    owner, verb = decorator.func.value, decorator.func.attr
    if not isinstance(owner, ast.Name):
        return None
    path = _const_str(decorator.args[0]) if decorator.args else _const_str(_kwarg(decorator, "path"))
    if path is None:
        return None
    if verb in _VERBS:
        return owner.id, path, [verb.upper()]
    if verb in ("route", "api_route"):
        return owner.id, path, _methods(_kwarg(decorator, "methods")) or ["GET"]
    return None


def route_handlers(tree: ast.Module) -> list[ast.FunctionDef | ast.AsyncFunctionDef]:
    """The functions of a module that are decorated as HTTP route handlers."""
    return [
        node for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and any(_route_of(d) for d in node.decorator_list)
    ]


def is_route_handler(tree: ast.Module, line: int) -> bool:
    """Whether *line* is inside a function decorated as an HTTP route handler."""
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.lineno <= line <= (node.end_lineno or node.lineno):
            if any(_route_of(d) for d in node.decorator_list):
                return True
    return False


def routes_in_source(text: str, rel: str) -> list[dict]:
    """The routes defined in one module (``rel`` is its path relative to the source root)."""
    tree = ast.parse(text, filename=rel)
    prefixes = _router_prefixes(tree)
    rows: list[dict] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for decorator in node.decorator_list:
            found = _route_of(decorator)
            if found is None:
                continue
            router, path, methods = found
            rows.append(
                {
                    "path": prefixes.get(router, "") + path,
                    "methods": methods,
                    "function": node.name,
                    "qualname": f"{rel}::{node.name}",
                    "file": rel,
                    "line": node.lineno,
                    "end_line": node.end_lineno,
                    "router": router,
                }
            )
    return rows


def _include_prefixes(tree: ast.Module, rel: str) -> dict[str, str]:
    """``app.include_router(accounts.router, prefix="/v1")`` / ``register_blueprint(bp, url_prefix=)``
    → {module file (posix, relative): prefix}, resolving ``from .routes import accounts``."""
    package = PurePosixPath(rel).parent
    imported: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.level >= 1:
            base = package
            for _ in range(node.level - 1):
                base = base.parent
            if node.module:
                base = base.joinpath(*node.module.split("."))
            for alias in node.names:
                imported[alias.asname or alias.name] = str(base / f"{alias.name}.py")
    out: dict[str, str] = {}
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
            continue
        if node.func.attr not in ("include_router", "register_blueprint") or not node.args:
            continue
        prefix = _const_str(_kwarg(node, "prefix") or _kwarg(node, "url_prefix"))
        arg = node.args[0]
        module = arg.value.id if isinstance(arg, ast.Attribute) and isinstance(arg.value, ast.Name) else None
        if prefix and module in imported:
            out[imported[module]] = prefix.rstrip("/")
    return out


_JS = (".js", ".mjs", ".cjs", ".ts")  # .ts: Express in TypeScript (TNW-5)


def _source_files(root: Path, suffixes: tuple[str, ...]) -> list[Path]:
    files = []
    for path in sorted(p for p in root.rglob("*") if p.suffix in suffixes and p.is_file()):
        parts = set(path.relative_to(root).parts[:-1])
        if parts & _SKIP_DIRS or any(p.startswith(".") for p in parts):
            continue
        files.append(path)
    return files


def _read(path: Path) -> bytes:
    if path.stat().st_size > MAX_FILE_BYTES:
        raise ValueError(f"larger than {MAX_FILE_BYTES} bytes")
    return path.read_bytes()


def extract_routes(source_root: str | Path, only_file: str | None = None) -> tuple[list[dict], list[dict]]:
    """``(routes, skipped)`` for the source tree (or one file). Routes are sorted by file and line.

    Python (FastAPI, Flask, Django), JavaScript (Express) and Java (Spring) files are read; a file
    that cannot be read or parsed is skipped and reported.
    """
    from aegis.workers.code.routes_more import django_routes, express_routes, spring_routes

    root = Path(source_root)
    if only_file:
        candidates = [root / only_file]
    else:
        candidates = _source_files(root, (".py", *_JS, ".java"))
    trees: dict[str, ast.Module] = {}
    js: dict[str, bytes] = {}
    java: dict[str, bytes] = {}
    routes: list[dict] = []
    skipped: list[dict] = []
    for path in candidates:
        rel = path.relative_to(root).as_posix()
        try:
            raw = _read(path)
            if path.suffix == ".py":
                text = raw.decode("utf-8", "replace")
                trees[rel] = ast.parse(text, filename=rel)
                routes.extend(routes_in_source(text, rel))
            elif path.suffix in _JS and not path.name.endswith(".d.ts"):  # type declarations hold no routes
                js[rel] = raw
            elif path.suffix == ".java":
                java[rel] = raw
        except (SyntaxError, ValueError, OSError) as exc:
            skipped.append({"file": rel, "reason": f"{type(exc).__name__}: {str(exc)[:160]}"})
            log.warning("routes.file_skipped", file=rel, reason=type(exc).__name__)

    included: dict[str, str] = {}
    for rel, tree in trees.items():
        included.update(_include_prefixes(tree, rel))
    for row in routes:
        prefix = included.get(row["file"])
        if prefix:
            row["path"] = prefix + row["path"]
        row.pop("router", None)

    for framework, extract, sources in (("django", django_routes, trees), ("express", express_routes, js), ("spring", spring_routes, java)):
        if not sources:
            continue
        try:
            found = extract(sources)
        except Exception as exc:  # noqa: BLE001 - one framework's parser failing must not lose the others
            skipped.append({"file": f"<{framework}>", "reason": f"{type(exc).__name__}: {str(exc)[:160]}"})
            log.warning("routes.framework_failed", framework=framework, error=type(exc).__name__)
            continue
        routes.extend(found)

    routes.sort(key=lambda r: (r["file"], r["line"], r["path"]))
    frameworks = sorted({"python" if trees else "", "javascript" if js else "", "java" if java else ""} - {""})
    log.info("routes.extracted", files=len(candidates), routes=len(routes), skipped=len(skipped), languages=frameworks)
    return routes, skipped
