"""What the user agrees to before AEGIS sends anything to a cloud model (LLM_PROVIDER_PHASES §9.1–9.2).

One versioned text, shown word for word by every interface (web console, CLI, API), so consent
always refers to the same words. Changing the text means bumping ``DISCLOSURE_VERSION``: every
earlier consent then stops counting and Online mode falls back to Offline until the user agrees
again.

Source code is a **separate** agreement (decision Q-3, off by default): without it, fix drafting
never sends the handler's code to the cloud model.

Operators of headless installs (CI, Docker) can give the same agreement through the environment:
``AEGIS_LLM__CLOUD_CONSENT=<DISCLOSURE_VERSION>`` (and ``AEGIS_LLM__CLOUD_SOURCE_CONSENT=true``).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

__all__ = ["DISCLOSURE_TEXT", "DISCLOSURE_VERSION", "SOURCE_CODE_TEXT", "ConsentInput", "disclosure"]

DISCLOSURE_VERSION = "2026-10-22.1"

DISCLOSURE_TEXT = (
    "Online mode sends parts of your security findings to Google's Gemini API: vulnerability "
    "descriptions, file paths, routes, evidence summaries and your chat questions. Google processes "
    "this under the terms of your own API key and account. This is not offline, and AEGIS cannot "
    "control how Google stores or uses the data. Raw HTTP traffic, full files, secret values and "
    "credentials are never sent. Embeddings and the search index stay on this machine. You can "
    "switch back to Offline at any time; it takes effect immediately, including for a scan that is "
    "already running."
)

SOURCE_CODE_TEXT = (
    "Also allow short excerpts of your source code (up to 80 lines of the affected handler, with "
    "comments, docstrings and secret values removed) to be sent to Gemini so it can draft fixes. "
    "Without this, Online mode drafts fixes from rules only."
)


@dataclass(frozen=True)
class ConsentInput:
    """What the user answered when shown :func:`disclosure` (from the UI, the CLI or the API)."""

    disclosure_version: str
    accepted: bool
    allow_source_code: bool = False


def disclosure() -> dict[str, Any]:
    """The text every interface shows before cloud processing is switched on."""
    return {"version": DISCLOSURE_VERSION, "text": DISCLOSURE_TEXT, "source_code_text": SOURCE_CODE_TEXT}
