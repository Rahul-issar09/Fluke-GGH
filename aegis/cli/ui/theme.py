"""Symbols the console can actually show.

A Windows console redirected to a pipe or a file uses the legacy code page (cp1252 here), where
characters like ``—`` or ``✓`` print as ``�`` or fail. So the symbol set and any text written are
chosen by what the output stream can encode, never by the operating system's name.
"""

from __future__ import annotations

from typing import Any

__all__ = ["ASCII", "UNICODE", "safe_text", "supports_unicode", "symbols"]

UNICODE = {"ok": "✓", "fail": "✗", "warn": "!", "arrow": "→", "dash": "—", "bullet": "•", "ellipsis": "…"}
ASCII = {"ok": "OK", "fail": "X", "warn": "!", "arrow": "->", "dash": "-", "bullet": "*", "ellipsis": "..."}

# what each non-ASCII character becomes on a console that cannot show it
_FALLBACK = {"—": "-", "–": "-", "→": "->", "←": "<-", "✓": "OK", "✗": "X", "•": "*", "…": "...",
             "“": '"', "”": '"', "‘": "'", "’": "'", "≥": ">=", "≤": "<=", "×": "x", "─": "-", "│": "|"}


def supports_unicode(stream: Any) -> bool:
    """True when *stream* can encode the symbols in :data:`UNICODE` and box-drawing lines."""
    encoding = getattr(stream, "encoding", None) or "ascii"
    try:
        ("".join(UNICODE.values()) + "─│┌┐└┘").encode(encoding)
        return True
    except (UnicodeEncodeError, LookupError):
        return False


def symbols(stream: Any) -> dict[str, str]:
    return UNICODE if supports_unicode(stream) else ASCII


def safe_text(text: str, stream: Any) -> str:
    """*text* made printable on *stream*: known symbols get ASCII stand-ins, anything else ``?``."""
    encoding = getattr(stream, "encoding", None) or "ascii"
    try:
        text.encode(encoding)
        return text
    except (UnicodeEncodeError, LookupError):
        pass
    for char, stand_in in _FALLBACK.items():
        text = text.replace(char, stand_in)
    try:
        return text.encode(encoding, errors="replace").decode(encoding)
    except LookupError:
        return text.encode("ascii", errors="replace").decode("ascii")
