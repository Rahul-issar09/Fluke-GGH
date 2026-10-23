"""Per-tool argument policies (PHASES P2.2).

Each tool accepts only its declared arguments: one Pydantic model per tool with
``extra="forbid"``. Unknown args and wrong types are rejected before anything
runs. This is where "the agent cannot pass arbitrary flags" is enforced.
"""

from __future__ import annotations

from typing import Literal

from pathlib import Path
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, ValidationError, field_validator, model_validator

from aegis.safety.repo_url import parse_repo_url

__all__ = ["PolicyError", "validate_args", "required_target", "POLICIES"]


class PolicyError(ValueError):
    """A tool call's arguments violate the tool's policy."""


class _Policy(BaseModel):
    model_config = ConfigDict(extra="forbid")


class HttpxArgs(_Policy):
    url: str
    method: str = "GET"
    headers: dict[str, str] = {}
    identity: str | None = None


_CREDENTIAL_HEADERS = ("cookie", "authorization")


def _http_url(url: str, what: str) -> None:
    if not url.startswith(("http://", "https://")):
        raise ValueError(f"{what} must be http(s)")


class KatanaArgs(_Policy):
    """A crawl of one target (TNW-4); the executor fixes everything else (scope, no forms, …)."""

    url: str
    depth: int = 3
    rate_limit: int = 5
    crawl_seconds: int = 60
    headers: dict[str, str] | None = None  # the logged-in identity's credentials, nothing else

    @model_validator(mode="after")
    def _check(self):
        _http_url(self.url, "katana url")
        if not 1 <= self.depth <= 5:
            raise ValueError("depth must be between 1 and 5")
        if not 1 <= self.rate_limit <= 100:
            raise ValueError("rate_limit must be between 1 and 100 requests per second")
        if not 10 <= self.crawl_seconds <= 600:
            raise ValueError("crawl_seconds must be between 10 and 600")
        bad = {k for k in (self.headers or {}) if k.lower() not in _CREDENTIAL_HEADERS}
        if bad:
            raise ValueError(f"header not allowed: {sorted(bad)}")
        return self


class PlaywrightArgs(_Policy):
    """A browser login for one identity (TNW-4). The credentials stay in the identities file."""

    login_url: str
    identity: str
    identities: str
    allow: list[str]  # the hosts the browser may reach: the scan's allowlist
    verify_tls: bool = True

    @model_validator(mode="after")
    def _check(self):
        _http_url(self.login_url, "login_url")
        if self.identity not in ("A", "B"):
            raise ValueError("identity must be A or B")
        if not Path(self.identities).is_file():
            raise ValueError("identities must be an existing file")
        if not self.allow:
            raise ValueError("allow must list the scan's allowlisted hosts")
        return self


class BolaArgs(_Policy):
    route: str
    object_id: str | int
    identities: list[str] = []


class SsrfArgs(_Policy):
    param: str
    test_input_id: str


class NucleiArgs(_Policy):
    url: str
    templates: str  # the pre-staged ``nuclei-templates`` folder (the executor picks the profile in it)
    rate_limit: int = 5  # requests per second: the scan's rate limit

    @model_validator(mode="after")
    def _check(self):
        if not self.url.startswith(("http://", "https://")):
            raise ValueError("nuclei url must be http(s)")
        if Path(self.templates).name != "nuclei-templates" or not Path(self.templates).is_dir():
            raise ValueError("templates must be the staged nuclei-templates folder")
        if not 1 <= self.rate_limit <= 100:
            raise ValueError("rate_limit must be between 1 and 100 requests per second")
        return self


class SchemathesisArgs(_Policy):
    openapi: str
    url: str
    tls_verify: bool = True  # false: the scan accepts the target's self-signed certificate
    # Only credential headers, so an identity's session can be used and nothing else.
    headers: dict[str, str] | None = None

    @field_validator("headers")
    @classmethod
    def _credential_headers_only(cls, value):
        if value is None:
            return value
        bad = {k for k in value if k.lower() not in ("cookie", "authorization")}
        if bad:
            raise ValueError(f"header not allowed: {sorted(bad)}")
        return value


class SemgrepArgs(_Policy):
    path: str
    config: str = "rules/semgrep"
    files: list[str] | None = None

    @model_validator(mode="after")
    def _local_only(self):
        # A registry name ("auto", "p/…", "r/…") or URL would make semgrep download rules.
        if self.config == "auto" or "://" in self.config or self.config.startswith(("p/", "r/", "s/")):
            raise ValueError("config must be a local rules file or folder")
        if not Path(self.config).exists():
            raise ValueError("config does not exist")
        root = Path(self.path).resolve()
        for name in self.files or []:
            if Path(name).is_absolute() or not (root / name).resolve().is_relative_to(root):
                raise ValueError("files must be inside path")
        return self


class GitleaksArgs(_Policy):
    path: str
    history: bool = False


class TrufflehogArgs(_Policy):
    path: str
    # Verification would send each found secret to its service to test it: network access and
    # use of someone's credential. Never allowed.
    verify: Literal[False] = False


class _OfflineDbArgs(_Policy):
    """A scanner that reads a pre-staged vulnerability database instead of the internet."""

    path: str
    db_dir: str

    @model_validator(mode="after")
    def _db_present(self):
        if not Path(self.db_dir).is_dir():
            raise ValueError("the offline database is not staged (run scripts/stage_offline once while online)")
        return self


class OsvArgs(_OfflineDbArgs):
    pass


class TrivyArgs(_OfflineDbArgs):
    pass


class SyftArgs(_Policy):
    path: str


class TreesitterArgs(_Policy):
    path: str | None = None
    files: list[str] | None = None


class CbomArgs(_Policy):
    path: str


class SslyzeArgs(_Policy):
    host: str  # host:port of one TLS endpoint (the SafetyController checks it against the allowlist)

    @field_validator("host")
    @classmethod
    def _host_port(cls, value: str) -> str:
        import re

        if not re.fullmatch(r"[A-Za-z0-9.-]+:\d{1,5}", value):
            raise ValueError("host must be host:port")
        return value


class PytestArgs(_Policy):
    """The project's own tests, run in a fix workspace — a folder and nothing else."""

    workdir: str


class GitArgs(_Policy):
    # apply_check: read-only check; apply: patch files under workdir (only ever a fix workspace)
    op: Literal["clone", "apply_check", "apply"]
    # clone
    repo: str | None = None
    dest: str | None = None
    depth: int = 1
    # apply_check — a read-only ``git apply --check`` of ``patch`` against files under ``workdir``
    patch: str | None = None
    workdir: str | None = None

    @model_validator(mode="after")
    def _per_operation(self):
        if self.op == "clone":
            if not (self.repo and self.dest):
                raise ValueError("clone needs repo and dest")
            if self.patch or self.workdir:
                raise ValueError("clone does not take patch/workdir")
            parse_repo_url(self.repo)  # https only, no credentials / query / odd paths
            if self.depth != 1:
                raise ValueError("clone is always shallow (depth 1)")
            dest = Path(self.dest)
            if not dest.is_absolute():
                raise ValueError("clone dest must be an absolute path")
            if dest.exists():
                raise ValueError("clone dest must not exist yet")
            if not dest.parent.is_dir():
                raise ValueError("clone dest's parent folder must exist")
        else:
            if not (self.patch and self.workdir):
                raise ValueError(f"{self.op} needs patch and workdir")
            if self.repo or self.dest:
                raise ValueError(f"{self.op} does not take repo/dest")
            workdir = Path(self.workdir).resolve()
            if not Path(self.patch).resolve().is_relative_to(workdir):
                raise ValueError("patch must be inside workdir")
            # writing a patch is only ever done to a fix workspace (<root>/workspaces/<fix_id>),
            # never to the user's tree
            if self.op == "apply" and workdir.parent.name != "workspaces":
                raise ValueError("apply only patches a fix workspace")
        return self


POLICIES: dict[str, type[_Policy]] = {
    "httpx": HttpxArgs,
    "katana": KatanaArgs,
    "playwright": PlaywrightArgs,
    "bola": BolaArgs,
    "ssrf": SsrfArgs,
    "nuclei": NucleiArgs,
    "schemathesis": SchemathesisArgs,
    "semgrep": SemgrepArgs,
    "gitleaks": GitleaksArgs,
    "trufflehog": TrufflehogArgs,
    "osv": OsvArgs,
    "trivy": TrivyArgs,
    "syft": SyftArgs,
    "treesitter": TreesitterArgs,
    "cbom": CbomArgs,
    "sslyze": SslyzeArgs,
    "git": GitArgs,
    "pytest": PytestArgs,
}


def validate_args(tool: str, args: dict) -> dict:
    """Validate ``args`` against *tool*'s policy; return the normalized dict."""
    model = POLICIES.get(tool)
    if model is None:
        raise PolicyError(f"no argument policy for tool '{tool}'")
    try:
        validated = model(**args)
    except ValidationError as exc:
        first = exc.errors()[0]
        loc = ".".join(str(p) for p in first.get("loc", ()))
        raise PolicyError(f"invalid args for {tool}: '{loc}' {first.get('msg')}") from exc
    return validated.model_dump(exclude_none=True)


def required_target(tool: str, args: dict) -> str | None:
    """The ``host:port`` a validated call must name as its ``target_host``, when its args imply one.

    A git clone contacts the repo's host, so the call must declare exactly that host — that is
    what the allowlist checks. Without this a clone could be sent with no ``target_host`` at all."""
    if tool == "git" and args.get("op") == "clone":
        return parse_repo_url(args["repo"]).target
    if tool == "playwright":  # the browser opens the login page first: that host is the target
        parsed = urlsplit(args["login_url"])
        return f"{(parsed.hostname or '').lower()}:{parsed.port or (443 if parsed.scheme == 'https' else 80)}"
    return None
