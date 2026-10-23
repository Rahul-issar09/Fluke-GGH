"""Route → handler extraction beyond FastAPI/Flask (Worker 2, AG14): Django, Express, Spring.

Same output as ``routes_fastapi`` (path, methods, function, qualname, file, line, end_line), so
correlation treats every framework alike. Code is parsed, never executed: Python with ``ast``,
JavaScript and Java with tree-sitter.

* **Django** — ``path()`` / ``re_path()`` / ``url()`` in a urls module, ``include()`` prefixes
  across modules, function views (methods from ``@require_http_methods`` / ``@require_GET`` /
  ``@api_view``) and class-based views (``View.as_view()``: the methods the class defines).
* **Express** — ``app.get('/p', …handler)`` (get/post/put/patch/delete/head/options/all),
  ``router.route('/p').get(h).post(h)``, and ``app.use('/prefix', router)`` where the router comes
  from ``require('./file')`` / ``import x from './file'``.
* **Spring** — ``@GetMapping`` … ``@DeleteMapping`` and ``@RequestMapping(value=…, method=…)`` on
  methods, under a class-level ``@RequestMapping`` prefix.

A route whose methods cannot be known statically lists all five common ones.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path, PurePosixPath

from aegis.observability import get_logger

__all__ = ["ANY_METHODS", "django_routes", "express_routes", "spring_routes"]

log = get_logger("workers.code.routes")

ANY_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE"]
_HTTP = ("get", "post", "put", "patch", "delete", "head", "options")


def _row(path: str, methods: list[str], function: str, rel: str, line: int, end_line: int | None) -> dict:
    return {
        "path": path if path.startswith("/") else "/" + path,
        "methods": methods,
        "function": function,
        "qualname": f"{rel}::{function}",
        "file": rel,
        "line": line,
        "end_line": end_line,
    }


# --------------------------------------------------------------------------------------------- #
# Django
# --------------------------------------------------------------------------------------------- #
_REGEX_GROUP = re.compile(r"\(\?P<(\w+)>[^)]*\)")


def _regex_route(pattern: str) -> str:
    """``^articles/(?P<year>[0-9]{4})/$`` → ``articles/{year}/``."""
    pattern = pattern.lstrip("^").rstrip("$")
    pattern = _REGEX_GROUP.sub(lambda m: "{" + m.group(1) + "}", pattern)
    return re.sub(r"[\\()?*+\[\]]", "", pattern)


def _imports(tree: ast.Module, rel: str) -> dict[str, tuple[str, str | None]]:
    """name → (module file, attribute or None) for ``from .x import y`` / ``import a.b as c``."""
    package = PurePosixPath(rel).parent
    out: dict[str, tuple[str, str | None]] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            base = package
            if node.level:
                for _ in range(node.level - 1):
                    base = base.parent
            else:
                base = PurePosixPath()
            mod = base.joinpath(*node.module.split(".")) if node.module else base
            for alias in node.names:
                # either a module (from . import views) or a name in a module (from .views import f)
                out[alias.asname or alias.name] = (str(mod / f"{alias.name}.py"), None)
                out.setdefault(f"{alias.asname or alias.name}#attr", (str(mod) + ".py", alias.name))
        elif isinstance(node, ast.Import):
            for alias in node.names:
                out[alias.asname or alias.name.split(".")[0]] = ("/".join(alias.name.split(".")) + ".py", None)
    return out


def _find_file(files: dict[str, ast.Module], module_path: str) -> str | None:
    if module_path in files:
        return module_path
    hits = [f for f in files if f.endswith("/" + module_path) or f == module_path]
    return hits[0] if len(hits) == 1 else None


def _view_target(node: ast.AST) -> tuple[str, str, bool] | None:
    """``views.fn`` → ("views", "fn", False); ``views.Cls.as_view()`` → ("views", "Cls", True); ``fn`` → ("", "fn", False)."""
    is_class = False
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "as_view":
        node, is_class = node.func.value, True
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
        return node.value.id, node.attr, is_class
    if isinstance(node, ast.Name):
        return "", node.id, is_class
    return None


def _view_methods(defn: ast.AST) -> list[str]:
    if isinstance(defn, ast.ClassDef):
        found = [n.name.upper() for n in defn.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name in _HTTP]
        return found or ANY_METHODS
    for dec in getattr(defn, "decorator_list", []):
        name = dec.func if isinstance(dec, ast.Call) else dec
        name = getattr(name, "attr", None) or getattr(name, "id", "")
        if name in ("require_GET", "require_safe"):
            return ["GET"]
        if name == "require_POST":
            return ["POST"]
        if name in ("require_http_methods", "api_view") and isinstance(dec, ast.Call) and dec.args:
            arg = dec.args[0]
            if isinstance(arg, (ast.List, ast.Tuple)):
                methods = [e.value.upper() for e in arg.elts if isinstance(e, ast.Constant) and isinstance(e.value, str)]
                if methods:
                    return methods
    return ANY_METHODS


def django_routes(files: dict[str, ast.Module]) -> list[dict]:
    """Routes from every module that calls ``path()`` / ``re_path()`` / ``url()``."""
    entries: dict[str, list[tuple[str, ast.AST]]] = {}
    for rel, tree in files.items():
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call) and len(node.args) >= 2):
                continue
            fname = getattr(node.func, "id", None) or getattr(node.func, "attr", None)
            if fname not in ("path", "re_path", "url") or not (isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str)):
                continue
            route = node.args[0].value if fname == "path" else _regex_route(node.args[0].value)
            entries.setdefault(rel, []).append((route, node.args[1]))
    if not entries:
        return []

    # include() prefixes, applied until stable (a urls module can be included by an included one)
    prefixes: dict[str, str] = {}
    includes: list[tuple[str, str, str]] = []  # (parent urls, route, child urls)
    for rel, items in entries.items():
        imports = _imports(files[rel], rel)
        for route, target in items:
            if isinstance(target, ast.Call) and getattr(target.func, "id", getattr(target.func, "attr", "")) == "include" and target.args:
                arg = target.args[0]
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    child = _find_file(files, "/".join(arg.value.split(".")) + ".py")
                elif isinstance(arg, ast.Name) and arg.id in imports:
                    child = _find_file(files, imports[arg.id][0])
                else:
                    child = None
                if child:
                    includes.append((rel, route, child))
    for _ in range(len(includes) + 1):
        for parent, route, child in includes:
            prefixes[child] = prefixes.get(parent, "") + route

    rows: list[dict] = []
    for rel, items in entries.items():
        imports = _imports(files[rel], rel)
        for route, target in items:
            ref = _view_target(target)
            if ref is None:
                continue
            module, name, is_class = ref
            if module:
                source = imports.get(module)
                view_file = _find_file(files, source[0]) if source else None
            else:  # imported name: from .views import fn
                source = imports.get(f"{name}#attr")
                view_file = _find_file(files, source[0]) if source else rel
            if not view_file:
                continue
            defn = next(
                (n for n in files[view_file].body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and n.name == name),
                None,
            )
            if defn is None:
                continue
            rows.append(_row(prefixes.get(rel, "") + route, _view_methods(defn), name, view_file, defn.lineno, defn.end_lineno))
    return rows


# --------------------------------------------------------------------------------------------- #
# tree-sitter helpers
# --------------------------------------------------------------------------------------------- #
def _parser(language: str):
    import tree_sitter

    if language == "typescript":
        import tree_sitter_typescript as grammar

        return tree_sitter.Parser(tree_sitter.Language(grammar.language_typescript()))
    if language == "javascript":
        import tree_sitter_javascript as grammar
    else:
        import tree_sitter_java as grammar
    return tree_sitter.Parser(tree_sitter.Language(grammar.language()))


def _walk(node):
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        stack.extend(reversed(current.children))


def _text(node) -> str:
    return node.text.decode("utf-8", "replace") if node is not None else ""


def _string(node) -> str | None:
    """The value of a JS/Java string literal node (plain strings only)."""
    if node is None:
        return None
    if node.type in ("string", "string_literal"):
        return _text(node)[1:-1]
    if node.type == "template_string" and "${" not in _text(node):
        return _text(node)[1:-1]
    return None


# --------------------------------------------------------------------------------------------- #
# Express
# --------------------------------------------------------------------------------------------- #
def _js_functions(root) -> dict[str, object]:
    """name → function node for ``function f(){}`` and ``const f = (…) => …`` / ``= function …``."""
    out = {}
    for node in _walk(root):
        if node.type == "function_declaration" and node.child_by_field_name("name") is not None:
            out[_text(node.child_by_field_name("name"))] = node
        elif node.type == "variable_declarator":
            value = node.child_by_field_name("value")
            if value is not None and value.type in ("arrow_function", "function_expression", "function"):
                out[_text(node.child_by_field_name("name"))] = value
    return out


def _js_requires(root) -> dict[str, str]:
    """identifier → relative module path, from ``const x = require('./p')`` and ``import x from './p'``."""
    out = {}
    for node in _walk(root):
        if node.type == "variable_declarator":
            value = node.child_by_field_name("value")
            if value is not None and value.type == "call_expression" and _text(value.child_by_field_name("function")) == "require":
                args = value.child_by_field_name("arguments")
                target = _string(args.named_children[0]) if args is not None and args.named_children else None
                if target:
                    out[_text(node.child_by_field_name("name"))] = target
        elif node.type == "import_statement":
            source = _string(node.child_by_field_name("source"))
            clause = next((c for c in node.named_children if c.type == "import_clause"), None)
            ident = next((c for c in clause.named_children if c.type == "identifier"), None) if clause is not None else None
            if source and ident is not None:
                out[_text(ident)] = source
    return out


def _resolve_js(rel: str, target: str, known: set[str]) -> str | None:
    if not target.startswith("."):
        return None
    base = PurePosixPath(rel).parent / target
    for candidate in (str(base), f"{base}.js", f"{base}.mjs", f"{base}.cjs", f"{base}.ts", f"{base}/index.js", f"{base}/index.ts"):
        normalized = str(PurePosixPath(*[p for p in PurePosixPath(candidate).parts]))
        parts: list[str] = []
        for part in PurePosixPath(normalized).parts:
            if part == "..":
                if parts:
                    parts.pop()
            elif part != ".":
                parts.append(part)
        resolved = "/".join(parts)
        if resolved in known:
            return resolved
    return None


def express_routes(files: dict[str, bytes]) -> list[dict]:
    """Express routes in JavaScript and TypeScript files (each parsed with its own grammar)."""
    parsers: dict[str, object] = {}

    def parse(rel: str, src: bytes):
        language = "typescript" if rel.endswith(".ts") else "javascript"
        if language not in parsers:
            parsers[language] = _parser(language)
        return parsers[language].parse(src)

    trees = {rel: parse(rel, src) for rel, src in files.items()}
    known = set(files)

    prefixes: dict[str, str] = {}
    for rel, tree in trees.items():
        requires = _js_requires(tree.root_node)
        for node in _walk(tree.root_node):
            if node.type != "call_expression":
                continue
            fn = node.child_by_field_name("function")
            if fn is None or fn.type != "member_expression" or _text(fn.child_by_field_name("property")) != "use":
                continue
            args = node.child_by_field_name("arguments")
            named = args.named_children if args is not None else []
            prefix = _string(named[0]) if named else None
            if not prefix or len(named) < 2:
                continue
            target = named[-1]
            module = None
            if target.type == "identifier" and _text(target) in requires:
                module = requires[_text(target)]
            elif target.type == "call_expression" and _text(target.child_by_field_name("function")) == "require":
                inner = target.child_by_field_name("arguments")
                module = _string(inner.named_children[0]) if inner is not None and inner.named_children else None
            child = _resolve_js(rel, module, known) if module else None
            if child:
                prefixes[child] = prefixes.get(rel, "") + prefix.rstrip("/")

    rows: list[dict] = []
    for rel, tree in trees.items():
        functions = _js_functions(tree.root_node)
        for node in _walk(tree.root_node):
            if node.type != "call_expression":
                continue
            fn = node.child_by_field_name("function")
            if fn is None or fn.type != "member_expression":
                continue
            verb = _text(fn.child_by_field_name("property"))
            if verb not in (*_HTTP, "all"):
                continue
            args = node.child_by_field_name("arguments")
            named = args.named_children if args is not None else []
            obj = fn.child_by_field_name("object")
            if obj is not None and obj.type == "call_expression":  # router.route('/p').get(h).post(h2)
                # walk down the chain of .get(…).post(…) calls to the .route('/p') that names the path
                while obj is not None and obj.type == "call_expression":
                    inner_fn = obj.child_by_field_name("function")
                    if inner_fn is None or inner_fn.type != "member_expression":
                        obj = None
                        break
                    if _text(inner_fn.child_by_field_name("property")) == "route":
                        break
                    obj = inner_fn.child_by_field_name("object")
                if obj is None or obj.type != "call_expression":
                    continue
                inner_args = obj.child_by_field_name("arguments")
                path = _string(inner_args.named_children[0]) if inner_args is not None and inner_args.named_children else None
                handlers = named
            else:
                path = _string(named[0]) if named else None
                handlers = named[1:]
            if path is None or not handlers:
                continue
            handler = handlers[-1]
            methods = ANY_METHODS if verb == "all" else [verb.upper()]
            if handler.type == "identifier" and _text(handler) in functions:
                target = functions[_text(handler)]
                name = _text(handler)
            elif handler.type in ("arrow_function", "function_expression", "function"):
                target = handler
                named_fn = handler.child_by_field_name("name")
                name = _text(named_fn) if named_fn is not None else f"{verb}_{re.sub(r'[^A-Za-z0-9]+', '_', path).strip('_') or 'root'}"
            else:
                continue
            rows.append(_row(prefixes.get(rel, "") + path, methods, name, rel, target.start_point[0] + 1, target.end_point[0] + 1))
    return rows


# --------------------------------------------------------------------------------------------- #
# Spring
# --------------------------------------------------------------------------------------------- #
_MAPPINGS = {"GetMapping": "GET", "PostMapping": "POST", "PutMapping": "PUT", "PatchMapping": "PATCH", "DeleteMapping": "DELETE"}


def _annotations(node):
    modifiers = next((c for c in node.children if c.type == "modifiers"), None)
    return [c for c in (modifiers.children if modifiers is not None else []) if c.type in ("annotation", "marker_annotation")]


def _annotation_args(annotation) -> tuple[list[str], dict[str, object]]:
    """Positional strings and named element values of an annotation."""
    args = annotation.child_by_field_name("arguments")
    positional: list[str] = []
    named: dict[str, object] = {}
    for child in args.named_children if args is not None else []:
        if child.type == "element_value_pair":
            named[_text(child.child_by_field_name("key"))] = child.child_by_field_name("value")
        else:
            positional += _strings(child)
    return positional, named


def _strings(node) -> list[str]:
    if node is None:
        return []
    if node.type == "string_literal":
        return [_text(node)[1:-1]]
    if node.type == "element_value_array_initializer":
        return [s for c in node.named_children for s in _strings(c)]
    return []


def _mapping(annotation) -> tuple[list[str], list[str]] | None:
    """``(paths, methods)`` for a Spring mapping annotation, else None."""
    name = _text(annotation.child_by_field_name("name")).split(".")[-1]
    if name not in _MAPPINGS and name != "RequestMapping":
        return None
    positional, named = _annotation_args(annotation)
    paths = positional or _strings(named.get("value")) or _strings(named.get("path")) or [""]
    if name in _MAPPINGS:
        return paths, [_MAPPINGS[name]]
    method_node = named.get("method")
    methods = [m.split(".")[-1].upper() for m in re.findall(r"RequestMethod\.\w+", _text(method_node))] if method_node is not None else []
    return paths, methods or ANY_METHODS


def spring_routes(files: dict[str, bytes]) -> list[dict]:
    parser = _parser("java")
    rows: list[dict] = []
    for rel, src in files.items():
        tree = parser.parse(src)
        for cls in (n for n in _walk(tree.root_node) if n.type == "class_declaration"):
            prefixes = [""]
            for annotation in _annotations(cls):
                mapping = _mapping(annotation)
                if mapping and _text(annotation.child_by_field_name("name")).endswith("RequestMapping"):
                    prefixes = [p.rstrip("/") for p in mapping[0]]
            body = cls.child_by_field_name("body")
            for method in (c for c in (body.named_children if body is not None else []) if c.type == "method_declaration"):
                for annotation in _annotations(method):
                    mapping = _mapping(annotation)
                    if mapping is None:
                        continue
                    paths, methods = mapping
                    name = _text(method.child_by_field_name("name"))
                    for prefix in prefixes:
                        for path in paths:
                            joined = prefix + ("/" + path.lstrip("/") if path else "")
                            rows.append(_row(joined or "/", methods, name, rel, method.start_point[0] + 1, method.end_point[0] + 1))
    return rows
