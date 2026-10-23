"""A small MCP test client for the AEGIS server - talks to it exactly as an editor does.

By default it launches the server **exactly as the editor config says** — the ``command``, ``args``
and ``env`` of the ``aegis`` entry in ``antigravity_mcp_config.json`` (written by
``python -m aegis.mcp.cli print-config``) — so a passing run means Antigravity will work too::

    python -m aegis.mcp.client                     # list the tools and resources, then call list_findings
    python -m aegis.mcp.client --ask "why is F-0079 a risk?"
    python -m aegis.mcp.client --call get_finding '{"finding_id": "F-0079"}'
    python -m aegis.mcp.client --config ~/.gemini/antigravity/mcp_config.json
    python -m aegis.mcp.client --no-config         # use this terminal's own AEGIS_* settings instead
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time
from pathlib import Path

__all__ = ["PROJECT_ROOT", "load_server_entry", "main", "run", "server_env", "server_params"]


def _out(text: str) -> None:
    sys.stdout.write(text + "\n")
    sys.stdout.flush()


def _result_text(result) -> str:
    structured = getattr(result, "structured_content", None)
    if structured is not None:
        return json.dumps(structured, indent=2, default=str)
    parts = [getattr(c, "text", str(c)) for c in (getattr(result, "content", None) or [])]
    return "\n".join(parts)


PROJECT_ROOT = Path(__file__).resolve().parents[2]


def server_env() -> dict[str, str]:
    """The current environment plus the project root on ``PYTHONPATH``, so the server starts from any
    working directory (editors launch it from their own) without ``aegis`` being pip-installed."""
    env = dict(os.environ)
    paths = [p for p in env.get("PYTHONPATH", "").split(os.pathsep) if p]
    if str(PROJECT_ROOT) not in paths:
        env["PYTHONPATH"] = os.pathsep.join([str(PROJECT_ROOT), *paths])
    return env


DEFAULT_CONFIG = PROJECT_ROOT / "antigravity_mcp_config.json"


def load_server_entry(path: Path, name: str = "aegis") -> dict:
    """The ``mcpServers.<name>`` entry of an editor config file."""
    data = json.loads(path.read_text(encoding="utf-8") or "{}")
    entry = (data.get("mcpServers") or {}).get(name)
    if not entry or "command" not in entry:
        raise ValueError(f"{path} has no mcpServers.{name} entry with a command")
    return entry


def server_params(config: Path | None):
    """How to launch the server: from an editor config entry, or from this terminal's environment."""
    from mcp.client.stdio import StdioServerParameters

    if config is None:
        return StdioServerParameters(command=sys.executable, args=["-m", "aegis.mcp.server"], env=server_env())
    entry = load_server_entry(config)
    env = {k: v for k, v in os.environ.items() if not k.startswith("AEGIS_") and k != "PYTHONPATH"}
    env.update(entry.get("env") or {})          # only the config's settings, as the editor would pass them
    return StdioServerParameters(command=entry["command"], args=list(entry.get("args") or []), env=env)


async def run(call: tuple[str, dict] | None = None, *, timeout_s: float = 300.0, config: Path | None = None) -> int:
    from mcp import Client

    params = server_params(config)
    _out(f"server settings from: {config if config else 'this terminal (AEGIS_* environment variables)'}")
    async with Client(params, read_timeout_seconds=timeout_s) as client:
        tools = await client.list_tools()
        _out("tools: " + ", ".join(t.name for t in tools.tools))
        templates = await client.list_resource_templates()
        _out("resources: " + ", ".join(t.uri_template for t in templates.resource_templates))
        name, args = call or ("list_findings", {"limit": 5})
        _out(f"\n> {name} {json.dumps(args)}")
        started = time.monotonic()
        result = await client.call_tool(name, args)
        took = time.monotonic() - started
        error = bool(getattr(result, "is_error", False))
        _out(_result_text(result))
        _out(f"\n({'ERROR, ' if error else ''}{took:.1f}s)")
        return 1 if error else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m aegis.mcp.client", description=__doc__.splitlines()[0])
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--ask", metavar="QUESTION", help="call the ask tool with this question")
    group.add_argument("--call", nargs=2, metavar=("TOOL", "JSON_ARGS"), help="call any tool with JSON arguments")
    parser.add_argument("--scan", metavar="SCAN_ID", help="scan id for --ask (default: latest scan)")
    parser.add_argument("--timeout", type=float, default=300.0, help="seconds to wait for one call (default 300)")
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--config", type=Path, help=f"editor config to launch the server from (default: {DEFAULT_CONFIG.name})")
    source.add_argument("--no-config", action="store_true", help="use this terminal's AEGIS_* settings instead of a config")
    args = parser.parse_args(argv)

    config = None if args.no_config else (args.config or (DEFAULT_CONFIG if DEFAULT_CONFIG.is_file() else None))
    if args.config and not args.config.is_file():
        parser.error(f"config file not found: {args.config}")

    call = None
    if args.ask:
        call = ("ask", {"question": args.ask, **({"scan_id": args.scan} if args.scan else {})})
    elif args.call:
        try:
            call = (args.call[0], json.loads(args.call[1]))
        except json.JSONDecodeError as exc:
            parser.error(f"JSON_ARGS is not valid JSON: {exc}")
    try:
        return asyncio.run(run(call, timeout_s=args.timeout, config=config))
    except Exception as exc:  # noqa: BLE001 - a CLI: report and exit non-zero
        causes = _leaf_errors(exc)
        _out("MCP client failed: " + "; ".join(f"{type(e).__name__}: {e}" for e in causes))
        _out("The server's own error (if it started) is on stderr above. Run `python -m aegis.mcp.cli doctor`.")
        return 2


def _leaf_errors(exc: BaseException) -> list[BaseException]:
    """Unwrap task-group exception groups to the errors that actually happened."""
    inner = getattr(exc, "exceptions", None)
    if not inner:
        return [exc]
    return [leaf for sub in inner for leaf in _leaf_errors(sub)]


if __name__ == "__main__":
    raise SystemExit(main())
