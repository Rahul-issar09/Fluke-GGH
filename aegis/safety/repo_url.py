"""Git repository URLs a scan may clone (TNW-1).

Only one shape is accepted: ``https://<host>[:port]/<owner>/<name>[.git]`` (deeper paths are
allowed for GitLab-style groups). Refused: any other scheme (``ssh``, ``git``, ``file``,
``ext::`` — git's remote helpers can run commands), credentials in the URL, a query or fragment,
``..`` segments, and anything git could read as an option. The clone host must also be in the
configured git hosts (``safety.git_hosts``); that is checked by the SafetyController's allowlist.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlsplit

__all__ = ["RepoUrl", "parse_repo_url", "repo_target"]

_HOST = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?)*$")
_SEGMENT = re.compile(r"^[A-Za-z0-9_.][A-Za-z0-9_.-]{0,99}$")
_MAX_LEN = 300


@dataclass(frozen=True)
class RepoUrl:
    host: str
    port: int
    path: str  # "/owner/name" or "/owner/name.git", as given

    @property
    def target(self) -> str:
        """``host:port`` — the allowlist entry the clone needs."""
        return f"{self.host}:{self.port}"

    @property
    def name(self) -> str:
        """``owner/name`` without ``.git`` — for reports."""
        path = self.path.strip("/")
        return path[:-4] if path.endswith(".git") else path


def parse_repo_url(url: str) -> RepoUrl:
    """Return the parsed URL, or raise ``ValueError`` saying what is wrong with it."""
    if not isinstance(url, str) or not url.strip():
        raise ValueError("repo URL is empty")
    url = url.strip()
    if len(url) > _MAX_LEN:
        raise ValueError(f"repo URL is longer than {_MAX_LEN} characters")
    if any(c.isspace() or ord(c) < 32 or c in "\\\"'`<>|^{}" for c in url):
        raise ValueError("repo URL contains characters that are not allowed")
    parts = urlsplit(url)
    if parts.scheme != "https":
        raise ValueError("repo URL must start with https:// (ssh, git and file URLs are not allowed)")
    if "@" in parts.netloc:
        raise ValueError("repo URL must not contain a user name or token; only public https repos can be cloned")
    if parts.query or parts.fragment or url.endswith(("?", "#")):
        raise ValueError("repo URL must not have a query (?) or fragment (#)")
    host = (parts.hostname or "").lower()
    if not _HOST.match(host):
        raise ValueError("repo URL has an invalid host")
    try:
        port = parts.port or 443
    except ValueError as exc:
        raise ValueError("repo URL has an invalid port") from exc
    segments = [s for s in parts.path.split("/") if s]
    if len(segments) < 2:
        raise ValueError("repo URL must name a repository, e.g. https://github.com/<owner>/<name>")
    for segment in segments:
        if segment in (".", "..") or not _SEGMENT.match(segment):
            raise ValueError(f"repo URL has an invalid path part: {segment!r}")
    return RepoUrl(host=host, port=port, path="/" + "/".join(segments))


def repo_target(url: str) -> str:
    """``host:port`` of a valid repo URL (raises ``ValueError`` otherwise)."""
    return parse_repo_url(url).target
