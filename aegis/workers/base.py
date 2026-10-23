"""Worker base: ToolRunner + heavy-stage semaphore (PHASES P4.1, P4.2).

This is the ONLY module allowed to spawn subprocesses (STRUCTURE boundary
B-1). Binaries are run with ``asyncio.create_subprocess_exec`` — never a shell,
never ``shell=True``. A timeout kills the process and returns a failed result;
the scan continues.

P4.2's "a tool failure becomes ``Evidence(kind=tool_error)``" is performed by
the caller through the evidence store (wired in AG04); here a failure is
surfaced as ``ToolResult(ok=False, ...)``.
"""

from __future__ import annotations

import asyncio
import json
import os
import time
from collections.abc import AsyncIterator, Sequence
from contextlib import asynccontextmanager
from pathlib import Path

from aegis.observability import get_logger
from aegis.safety.models import ToolResult

__all__ = ["run_tool", "heavy_stage", "HEAVY_SEMAPHORE"]

log = get_logger("workers.base")

# Only one heavy tool stage runs at a time (24 GB / 4 GB VRAM budget, SD §1).
HEAVY_SEMAPHORE = asyncio.Semaphore(1)


@asynccontextmanager
async def heavy_stage(name: str = "") -> AsyncIterator[None]:
    """Serialize heavy tool stages behind the global semaphore."""
    await HEAVY_SEMAPHORE.acquire()
    log.info("heavy_stage.enter", stage=name)
    try:
        yield
    finally:
        HEAVY_SEMAPHORE.release()
        log.info("heavy_stage.exit", stage=name)


def _parse(stdout: str, parse: str):
    if parse == "json":
        return json.loads(stdout) if stdout.strip() else None
    if parse == "jsonl":
        return [json.loads(ln) for ln in stdout.splitlines() if ln.strip()]
    return {"text": stdout}  # "text" — wrapped to satisfy ToolResult.output (dict|list|None)


async def run_tool(
    tool: str,
    argv: Sequence[str],
    *,
    timeout: float = 60.0,
    parse: str = "json",
    cwd: str | None = None,
    output_file: str | None = None,
    env: dict[str, str] | None = None,
    ok_exit_codes: Sequence[int] = (0,),
) -> ToolResult:
    """Run *argv* and return a :class:`ToolResult`.

    ``parse``: ``"json"`` (whole stdout), ``"jsonl"`` (one object per line),
    ``"text"`` (raw), or ``"file"`` (read+json-parse ``output_file``).

    ``env`` is merged over the parent environment. ``ok_exit_codes`` lists exit
    codes that mean "the tool ran" — some scanners exit non-zero precisely when
    they *found* something (e.g. Schemathesis exits 1 on failures).
    """
    start = time.monotonic()
    log.info("tool.start", tool=tool, argv_len=len(argv))
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            # no tool reads input from AEGIS; an inherited stdin made Katana wait for targets on it
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd,
            env={**os.environ, **env} if env else None,
        )
    except (OSError, ValueError) as exc:
        dur = int((time.monotonic() - start) * 1000)
        log.error("tool.spawn_failed", tool=tool, error=str(exc)[:200])
        return ToolResult(
            ok=False, tool=tool, exit_code=None, duration_ms=dur, stderr_tail=str(exc)[:500]
        )

    try:
        out_b, err_b = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        dur = int((time.monotonic() - start) * 1000)
        log.error("tool.timeout", tool=tool, timeout=timeout)
        return ToolResult(
            ok=False, tool=tool, exit_code=None, duration_ms=dur, stderr_tail="timeout"
        )

    dur = int((time.monotonic() - start) * 1000)
    stdout = out_b.decode("utf-8", "replace")
    stderr_tail = err_b.decode("utf-8", "replace")[-500:] or None
    exit_code = proc.returncode

    output = None
    ok = exit_code in tuple(ok_exit_codes)
    try:
        if parse == "file":
            if output_file and Path(output_file).exists():
                output = json.loads(Path(output_file).read_text(encoding="utf-8"))
            else:
                ok = False
                stderr_tail = (stderr_tail or "") + " [output file missing]"
        else:
            output = _parse(stdout, parse)
    except (json.JSONDecodeError, ValueError) as exc:
        ok = False
        stderr_tail = (stderr_tail or "") + f" [parse error: {exc}]"

    log.info("tool.done", tool=tool, ok=ok, exit_code=exit_code, duration_ms=dur)
    return ToolResult(
        ok=ok,
        tool=tool,
        exit_code=exit_code,
        duration_ms=dur,
        output=output,
        stderr_tail=stderr_tail,
    )
