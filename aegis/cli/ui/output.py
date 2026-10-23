"""How the CLI writes (CLI_PHASES.md section 6).

* **Human output** — tables and key/value blocks on stdout (Rich), with colour only on a terminal.
* **``--json``** — exactly one JSON document on stdout and nothing else, built from the same Pydantic
  models the REST API returns, so scripts and CI can parse it. It is ASCII-escaped, so it is valid on
  any console code page.
* **Errors and notes** — always on **stderr**, in both modes, so ``aegis … --json > out.json`` stays clean.
* **Any console** — text is made printable on the stream's encoding (``theme.safe_text``); tables
  fall back to ASCII borders where box-drawing characters cannot be shown.
"""

from __future__ import annotations

import dataclasses
import json
import sys
from typing import Any, Callable, Iterable, Sequence

from rich import box
from rich.console import Console
from rich.table import Table
from rich.text import Text

from aegis.cli.ui.theme import safe_text, supports_unicode, symbols

__all__ = ["Output", "PIPE_WIDTH", "to_jsonable"]

PIPE_WIDTH = 160


def to_jsonable(value: Any) -> Any:
    """Pydantic models, dataclasses, containers and paths → plain JSON values."""
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json")
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return to_jsonable(dataclasses.asdict(value))
    if isinstance(value, dict):
        return {str(k): to_jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [to_jsonable(v) for v in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


class Output:
    def __init__(self, *, json_mode: bool = False, color: bool | None = None, quiet: bool = False,
                 stdout: Any = None, stderr: Any = None):
        self.json_mode = json_mode
        self.quiet = quiet
        self.stdout = stdout if stdout is not None else sys.stdout
        self.stderr = stderr if stderr is not None else sys.stderr
        if color is None:
            color = bool(getattr(self.stdout, "isatty", lambda: False)())
        self.color = color
        self.unicode = supports_unicode(self.stdout)
        self.sym = symbols(self.stdout)
        is_tty = bool(getattr(self.stdout, "isatty", lambda: False)())
        # a terminal reports its own width; a file or pipe gets a wide fixed width so tables do not wrap
        self._console = Console(file=self.stdout, no_color=not color, color_system="auto" if color else None,
                                highlight=False, emoji=False, soft_wrap=True, legacy_windows=False,
                                width=None if is_tty else PIPE_WIDTH)

    # ------------------------------------------------------------------ data
    def emit(self, payload: Any, render: Callable[["Output"], None]) -> None:
        """``--json`` → *payload* as one JSON document; otherwise *render* draws it for a person."""
        if self.json_mode:
            self.json(payload)
        else:
            render(self)

    def json(self, payload: Any) -> None:
        self.stdout.write(json.dumps(to_jsonable(payload), indent=2, ensure_ascii=True, sort_keys=False) + "\n")
        self.stdout.flush()

    # ------------------------------------------------------------------ human output (stdout)
    def line(self, text: str = "") -> None:
        self._console.print(self._safe(text), markup=False)

    def heading(self, text: str) -> None:
        self._console.print(self._safe(text), style="bold", markup=False)

    def kv(self, pairs: Iterable[tuple[str, Any]], title: str | None = None) -> None:
        rows = [(str(k), "" if v is None else str(v)) for k, v in pairs]
        if title:
            self.heading(title)
        width = max((len(k) for k, _ in rows), default=0)
        for key, value in rows:
            self._console.print(self._safe(f"  {key.ljust(width)}  {value}"), markup=False)

    def table(self, columns: Sequence[str], rows: Iterable[Sequence[Any]], title: str | None = None) -> None:
        table = Table(title=self._safe(title) if title else None, box=box.SIMPLE if self.unicode else box.ASCII,
                      show_edge=False, header_style="bold" if self.color else None, title_justify="left")
        # short columns (ids, numbers, states) never wrap; only the last, descriptive column may
        for i, column in enumerate(columns):
            last = i == len(columns) - 1
            table.add_column(self._safe(column), no_wrap=not last, overflow="fold" if last else "ellipsis")
        for row in rows:
            # Text, not str: a cell is data, so "[gemini]" or "[x]" in it is printed, not read as Rich markup
            table.add_row(*(Text(self._safe("" if cell is None else str(cell))) for cell in row))
        self._console.print(table)

    # ------------------------------------------------------------------ messages (stderr)
    def note(self, text: str) -> None:
        """Informational message for a person; silent with ``--quiet`` or ``--json``."""
        if not (self.quiet or self.json_mode):
            self._err(text)

    def warn(self, text: str) -> None:
        self._err(f"warning: {text}")

    def error(self, message: str, hint: str | None = None) -> None:
        self._err(f"error: {message}")
        if hint:
            self._err(f"  {self.sym['arrow']} {hint}")

    def _err(self, text: str) -> None:
        self.stderr.write(safe_text(text, self.stderr) + "\n")
        self.stderr.flush()

    def _safe(self, text: str) -> str:
        return safe_text(text, self.stdout)
