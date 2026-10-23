"""Setup helpers for the AEGIS MCP server (MCP_PHASES MCP12): ``print-config`` and ``doctor``.

    python -m aegis.mcp.cli print-config                 # the block to paste into Antigravity / an editor
    python -m aegis.mcp.cli print-config --out FILE      # ... or write it to a file
    python -m aegis.mcp.cli doctor                       # what works, and what to fix

``print-config`` uses absolute paths only: an editor starts the server from its own working
directory and outside your virtualenv. The block holds no secrets - AEGIS uses local models only,
so there is no API key to configure. Nothing here edits an editor's settings.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sqlite3
import sys
from pathlib import Path

__all__ = ["build_config", "doctor", "main"]

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _out(text: str = "") -> None:
    sys.stdout.write(text + "\n")


def build_config(*, name: str = "aegis", python: str | None = None, data_dir: str | None = None,
                 model: str | None = None, ollama_url: str | None = None,
                 embed_model: str | None = None, embed_dim: int | None = None) -> dict:
    """The ``mcpServers`` block for this machine, from the current settings plus any overrides."""
    from aegis.config import get_app_settings

    app = get_app_settings()
    env = {
        "PYTHONPATH": str(PROJECT_ROOT),
        "AEGIS_DATA_DIR": str(Path(data_dir or app.data_dir).resolve()),
        "AEGIS_OLLAMA_URL": ollama_url or app.model.ollama_url,
        "AEGIS_MODEL": model or app.model.name,
        "AEGIS_CHAT__EMBED_MODEL": embed_model or app.chat.embed_model,
        "AEGIS_CHAT__EMBED_DIM": str(embed_dim or app.chat.embed_dim),
    }
    if app.chat.embed_url and app.chat.embed_url != env["AEGIS_OLLAMA_URL"]:
        env["AEGIS_CHAT__EMBED_URL"] = app.chat.embed_url  # embeddings run elsewhere than the chat model (LP4)
    return {"mcpServers": {name: {
        "command": str(Path(python or sys.executable).resolve()),
        "args": ["-m", "aegis.mcp.server"],
        "env": env,
    }}}


# ------------------------------------------------------------------------------------------ doctor
def _ai_model_lines(rep, app, data: Path) -> None:
    """Which model this server's ``ask`` will use (LLM_PROVIDER_PHASES LP10) — never anything about a key."""
    try:
        from aegis.llm.manager import ProviderManager

        st = ProviderManager(app, data, read_only=True).status()
    except Exception as exc:  # noqa: BLE001 - a broken config is reported, never fatal here
        rep.line("WARN", "AI model", f"could not read the model configuration: {type(exc).__name__}")
        return
    if st.get("awaiting_key"):
        rep.line("WARN", "AI model", f"Online (Gemini {st.get('online_model')}) is chosen in AEGIS, but the key is typed "
                 f"into the AEGIS app each run and never saved, so this server answers with the offline model {st['model']}")
    elif st["location"] == "cloud":
        rep.line("OK", "AI model", f"Gemini {st['model']} (online: questions asked through MCP go to Google)")
    else:
        rep.line("OK", "AI model", f"{st['model']} (offline, this machine)")


class _Report:
    def __init__(self):
        self.failed = 0
        self.warned = 0

    def line(self, status: str, what: str, detail: str = "") -> None:
        if status == "FAIL":
            self.failed += 1
        elif status == "WARN":
            self.warned += 1
        _out(f"[{status:<4}] {what}" + (f" - {detail}" if detail else ""))


def doctor() -> int:
    """Check everything the MCP server needs; non-zero exit if anything FAILs."""
    from aegis.config import get_app_settings

    rep = _Report()
    app = get_app_settings()

    rep.line("OK" if sys.version_info >= (3, 10) else "FAIL", "Python", sys.version.split()[0])
    try:
        import importlib.metadata as md

        rep.line("OK", "MCP SDK", md.version("mcp"))
    except Exception:  # noqa: BLE001
        rep.line("FAIL", "MCP SDK", "not installed: pip install mcp")

    data = Path(app.data_dir).resolve()
    db = data / "aegis.db"
    latest = None
    if not db.is_file():
        rep.line("FAIL", "AEGIS data", f"no aegis.db in {data} - set AEGIS_DATA_DIR to the folder that holds it")
    else:
        con = sqlite3.connect(db.as_uri() + "?mode=ro", uri=True)
        try:
            n = con.execute("select count(*) from scan").fetchone()[0]
            row = con.execute("select id, status from scan order by created_at desc, id desc limit 1").fetchone()
        finally:
            con.close()
        latest = row[0] if row else None
        if n:
            rep.line("OK", "AEGIS data", f"{data} - {n} scans, latest {row[0]} ({row[1]})")
        else:
            rep.line("WARN", "AEGIS data", f"{data} has no scans yet - run a scan with the AEGIS API first")

    _ai_model_lines(rep, app, data)

    from aegis.safety.model_host import ModelHostRefused, check_model_url

    url = app.model.ollama_url
    try:
        check_model_url(url)
        rep.line("OK", "Model URL is local", url)
    except ModelHostRefused as exc:
        rep.line("FAIL", "Model URL is local", str(exc))
        url = None

    if url:
        from aegis.api.routers.health import probe_ollama

        chat = asyncio.run(probe_ollama(url, app.model.name))
        if not chat["reachable"]:
            rep.line("FAIL", "Ollama", f"not reachable at {url} ({chat.get('error')}) - start Ollama, or set AEGIS_OLLAMA_URL")
        else:
            rep.line("OK", "Ollama", url)
            embed_url = app.chat.embed_url or url   # embeddings may run on their own Ollama (LP4)
            if embed_url != url:
                try:
                    check_model_url(embed_url)
                    rep.line("OK", "Embedding URL is local", embed_url)
                except ModelHostRefused as exc:
                    rep.line("FAIL", "Embedding URL is local", str(exc))
            embed = asyncio.run(probe_ollama(embed_url, app.chat.embed_model))
            for label, probe in (("Chat model", chat), ("Embedding model", embed)):
                if probe["model_present"]:
                    rep.line("OK", label, probe["model"])
                else:
                    rep.line("FAIL", label, f"{probe['model']} is not pulled - run: ollama pull {probe['model']}")

    if latest and db.is_file():
        try:
            from aegis.chat.chroma_store import ChromaStore

            chunks = len(ChromaStore(str(data / "chroma"), app.chat.collection).all_for_scan(latest))
            if chunks:
                rep.line("OK", "Chat index", f"{latest}: {chunks} chunks")
            else:
                rep.line("WARN", "Chat index", f"{latest} is not indexed (ask falls back to keyword search) - run: "
                         f"python -m aegis.chat reindex {latest}  (with AEGIS_CHAT__EMBED_MODEL={app.chat.embed_model})")
        except Exception as exc:  # noqa: BLE001
            rep.line("WARN", "Chat index", f"could not open the index: {type(exc).__name__}: {exc}")

    _out()
    _out(f"{rep.failed} failed, {rep.warned} warnings." + ("" if rep.failed else " The MCP server can start."))
    return 1 if rep.failed else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m aegis.mcp.cli", description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)

    pc = sub.add_parser("print-config", help="print the mcpServers block for an editor (Antigravity)")
    pc.add_argument("--name", default="aegis", help="server name shown in the editor (default: aegis)")
    pc.add_argument("--data-dir", help="AEGIS data folder (default: AEGIS_DATA_DIR or ./data)")
    pc.add_argument("--model", help="local Ollama chat model (default: AEGIS_MODEL or qwen2.5:7b)")
    pc.add_argument("--ollama-url", help="Ollama URL (default: AEGIS_OLLAMA_URL)")
    pc.add_argument("--embed-model", help="local embedding model (must match the chat index)")
    pc.add_argument("--embed-dim", type=int, help="embedding size of that model (bge-m3 = 1024, nomic-embed-text = 768)")
    pc.add_argument("--out", help="write the block to this file instead of printing it")

    sub.add_parser("doctor", help="check the setup and say what to fix")
    args = parser.parse_args(argv)

    if args.command == "doctor":
        from aegis.observability import configure_logging

        configure_logging("ERROR", True, stream=sys.stderr)
        return doctor()

    block = build_config(name=args.name, data_dir=args.data_dir, model=args.model, ollama_url=args.ollama_url,
                         embed_model=args.embed_model, embed_dim=args.embed_dim)
    text = json.dumps(block, indent=2)
    if args.out:
        Path(args.out).write_text(text + "\n", encoding="utf-8")
        _out(f"wrote {Path(args.out).resolve()}")
    else:
        _out(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
