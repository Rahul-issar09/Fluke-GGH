"""``aegis llm …`` — the model AEGIS reasons with (LLM_PROVIDER_PHASES LP9).

    aegis llm status                     the active model, key status (never the key), consent
    aegis llm providers                  Ollama (offline) and Gemini (online): installed / allowed
    aegis llm models [--provider P]      models to choose from (Gemini: for this run's key)
    aegis llm configure                  a wizard; or --provider/--model/... for scripts
    aegis llm offline [--model M]        back to the local model now
    aegis llm test                       one small check of the active model
    aegis llm forget-key                 forget this run's Gemini key (goes offline first)

Everything goes through the AEGIS API, which holds the Gemini key **in memory for this run only**
(decision Q-4): every run asks for it again. The key is read from a hidden prompt, from stdin
(``--api-key-stdin``) or from a named environment variable (``--api-key-env NAME``) — never from a
command-line argument, so it never lands in shell history or a process list. It is never printed.

:func:`ensure_session_key` is used by ``scan run``, ``ask``, ``chat`` and the menu: when Online mode
waits for this run's key, an interactive terminal is asked for it (Enter continues offline).
:func:`choose_scan_model` is ``scan run``'s "AI for this scan" question in a terminal.
"""

from __future__ import annotations

import os
import sys
from typing import Any, Callable, Optional

import typer

from aegis.cli.context import current
from aegis.cli.errors import CONFLICT, USAGE, CliError, cli_command

__all__ = ["BUILT", "choose_scan_model", "ensure_session_key", "model_label", "register"]

BUILT = {("llm", "status"), ("llm", "providers"), ("llm", "models"), ("llm", "configure"), ("llm", "offline"),
         ("llm", "test"), ("llm", "forget-key")}

INTENT = {"X-AEGIS-Intent": "llm-config", "X-AEGIS-Client": "cli"}
KEY_PROMPT = "Gemini API key (asked every run, never saved)"


def _interactive() -> bool:
    return bool(getattr(sys.stdin, "isatty", lambda: False)() and getattr(sys.stdout, "isatty", lambda: False)())


# ------------------------------------------------------------------ API calls
def get_config(api) -> dict:
    return api.get("/api/llm/config")


def check_key_transport(base_url: str) -> None:
    """Never send a key over plain HTTP to another machine (LP11): only https, or this machine."""
    import ipaddress
    from urllib.parse import urlsplit

    parts = urlsplit(base_url)
    host = (parts.hostname or "").lower()
    try:
        local = host == "localhost" or ipaddress.ip_address(host).is_loopback
    except ValueError:
        local = False
    if parts.scheme != "https" and not local:
        raise CliError(f"refusing to send the Gemini key over plain HTTP to {host}: it would cross the network "
                       "unencrypted", USAGE, hint="use an https:// address for a remote AEGIS API, or run the CLI "
                                                 "on the machine where the API runs")


def _send(api, method: str, path: str, body: Optional[dict] = None, *, timeout: float = 60.0) -> dict:
    if body and body.get("api_key"):
        check_key_transport(api.base_url)
    kwargs: dict[str, Any] = {"headers": INTENT, "timeout": timeout}
    if body is not None:
        kwargs["json"] = body
    response = api.request(method, path, **kwargs)
    return response.json() if response.content else {}


def read_key(*, from_stdin: bool, env_name: Optional[str], ask: bool) -> Optional[str]:
    """The candidate key, or ``None``. Never from an argument; never echoed."""
    if env_name:
        value = (os.environ.get(env_name) or "").strip()
        if not value:
            raise CliError(f"the environment variable {env_name} is empty or not set", USAGE)
        return value
    if from_stdin:
        value = sys.stdin.read().strip()
        if not value:
            raise CliError("--api-key-stdin: nothing was read from stdin", USAGE)
        return value
    if ask:
        return typer.prompt(KEY_PROMPT, hide_input=True).strip()
    return None


def _no_key_hint() -> str:
    return "give the key with --api-key-stdin or --api-key-env NAME (it is never accepted as an argument)"


def activate_gemini(ctx, api, model: str, key: Optional[str], *, interactive: bool, accept_version: Optional[str],
                    allow_source_code: Optional[bool], deep: bool = False,
                    ask_consent: Optional[Callable[[dict], bool]] = None) -> dict:
    """Validate *model* (with *key*), get consent if none is on record for this key, switch.

    ``ask_consent(disclosure)`` (the menu's own prompts) returns whether source code may be sent, or
    raises :class:`CliError` if the notice was not accepted; by default Typer prompts are used."""
    body: dict[str, Any] = {"provider": "gemini", "model": model, "deep": deep}
    if key:
        body["api_key"] = key
    if not ctx.out.json_mode:
        ctx.out.line(f"Checking {model} with a tiny test request ...")
    out = _send(api, "POST", "/api/llm/validate", body, timeout=180.0)
    for warning in out.get("warnings") or []:
        ctx.out.warn(warning)
    switch: dict[str, Any] = {"provider": "gemini", "model": model, "validation_id": out["validation_id"]}
    if not out.get("consent_on_record"):
        disclosure = out["disclosure"]
        if accept_version:
            if accept_version != disclosure["version"]:
                raise CliError(f"--accept-cloud-disclosure {accept_version} is not the current privacy notice "
                               f"({disclosure['version']})", CONFLICT, hint="read it with: aegis llm status --json")
            allow = bool(allow_source_code)
        elif interactive and ask_consent is not None:
            allow = ask_consent(disclosure)
        elif interactive:
            ctx.out.heading("Before switching to Online mode")
            ctx.out.line(disclosure["text"])
            ctx.out.line()
            allow = allow_source_code if allow_source_code is not None else typer.confirm(
                disclosure["source_code_text"], default=False)
            typed = typer.prompt(f"Type YES to agree (privacy notice {disclosure['version']})", default="",
                                 show_default=False)
            if typed.strip().upper() != "YES":
                raise CliError("not switched: the privacy notice was not accepted (AEGIS stays as it was)", CONFLICT)
        else:
            raise CliError("Online mode needs your agreement to the privacy notice", CONFLICT,
                           hint=f"run interactively, or pass --accept-cloud-disclosure {disclosure['version']} "
                                "after reading it (aegis llm status --json)")
        switch["consent"] = {"disclosure_version": disclosure["version"], "accepted": True, "allow_source_code": allow}
    return _send(api, "PUT", "/api/llm/config", switch)


def ensure_session_key(ctx, api) -> Optional[dict]:
    """If Online mode waits for this run's key, ask for it (interactive) or say this run is offline.
    Returns the configuration in effect afterwards (``None`` for an API without model configuration)."""
    try:
        cfg = get_config(api)
    except CliError:
        return None
    if not cfg.get("awaiting_key"):
        return cfg
    model = cfg.get("online_model") or "?"
    if not _interactive() or ctx.out.json_mode:
        ctx.out.warn(f"Online mode (Gemini {model}) is waiting for this run's API key, so this run uses the "
                     f"offline model {cfg['model']}. Enter the key with: aegis llm configure")
        return cfg
    ctx.out.warn(f"Online mode (Gemini {model}) is waiting for this run's API key "
                 "(AEGIS asks for it every run and never saves it).")
    key = typer.prompt(f"{KEY_PROMPT} - Enter continues offline", hide_input=True, default="", show_default=False)
    if not key.strip():
        ctx.out.note(f"Continuing offline with {cfg['model']}.")
        return cfg
    try:
        cfg = activate_gemini(ctx, api, model, key.strip(), interactive=True, accept_version=None,
                              allow_source_code=None)
        ctx.out.note(f"Online mode resumed: Gemini {model}.")
    except CliError as exc:
        ctx.out.warn(f"Online mode not resumed ({exc}); continuing offline.")
    return cfg


def before_model_use(ctx, be) -> Optional[dict]:
    """For commands that make AEGIS use its model (a scan, a question): ask for this run's key if
    Online mode waits for it, and say on stderr what will be sent to the cloud, if anything."""
    api = getattr(be, "api", None)
    if api is None:
        return None
    cfg = ensure_session_key(ctx, api)
    notice = online_notice(cfg)
    if notice:
        ctx.out.warn(notice)
    return cfg


def model_label(cfg: dict) -> str:
    """The model in effect, in words: ``qwen2.5:7b (offline, this machine)``."""
    if cfg.get("awaiting_key"):
        return f"{cfg['model']} (offline; Online Gemini {cfg.get('online_model')} waits for this run's key)"
    if cfg.get("location") == "cloud":
        return f"Gemini {cfg['model']} (online)"
    return f"{cfg['model']} (offline, this machine)"


def choose_scan_model(ctx, api) -> dict:
    """Ask which model a scan uses, before it starts. The scan keeps that model to the end, and the
    questions asked about it afterwards go to the active model, so it answers those too. Enter keeps
    the active model; a switch that fails says why and asks again. Returns the configuration in effect."""
    cfg = get_config(api)
    ctx.out.heading("AI for this scan")
    ctx.out.line(f"  Enter  keep {model_label(cfg)}")
    ctx.out.line("  1      Offline - choose a local model")
    ctx.out.line("  2      Online - Google Gemini (the key is asked every run, never saved)")
    while True:
        choice = typer.prompt("Choose", default="", show_default=False).strip()
        try:
            if not choice:
                return cfg
            if choice == "1":
                local = _chat_models(api.get("/api/llm/models", params={"provider": "ollama"})["models"])
                model = _pick(ctx, "local models", local, cfg["model"] if cfg["provider"] == "ollama" else None)
                return _send(api, "PUT", "/api/llm/config", {"provider": "ollama", "model": model})
            if choice == "2":
                has_key = (cfg.get("key") or {}).get("configured")
                key = typer.prompt(KEY_PROMPT + (" - Enter uses this run's key" if has_key else ""), hide_input=True,
                                   default="" if has_key else None, show_default=False).strip()
                found = _send(api, "POST", "/api/llm/discover", {"provider": "gemini", **({"api_key": key} if key else {})})
                model = _pick(ctx, "Gemini models", _chat_models(found["models"]), cfg.get("online_model"))
                return activate_gemini(ctx, api, model, key or None, interactive=True, accept_version=None,
                                       allow_source_code=None)
            ctx.out.error("type 1 or 2, or press Enter to keep the current model")
        except CliError as exc:
            ctx.out.warn(f"{exc} - choose again (Enter keeps {model_label(cfg)})")


def online_notice(cfg: Optional[dict]) -> Optional[str]:
    """What a scan or a question sends to the cloud model, when Online mode is in effect."""
    if not cfg or cfg.get("location") != "cloud":
        return None
    code = ", and masked source-code excerpts for fix drafts" if cfg.get("allow_source_code") else ""
    return (f"AI processing: Gemini {cfg['model']} (online). Finding descriptions, file paths, routes and evidence "
            f"summaries{code} are sent to Google.")


# ------------------------------------------------------------------ views
def status_view(cfg: dict):
    def render(out) -> None:
        if cfg.get("awaiting_key"):
            mode = f"Online chosen (Gemini {cfg.get('online_model')}) - waiting for this run's key; running offline"
        elif cfg["location"] == "cloud":
            mode = "Online - Google Gemini (findings are sent to Google)"
        else:
            mode = "Offline - this machine"
        key = cfg.get("key") or {}
        if key.get("configured"):
            where = {"session": "entered this run, memory only", "env": "from the API's environment",
                     "file": "from the API's key file"}.get(key.get("source"), key.get("source"))
            key_text = f"...{key.get('last4') or '????'} ({where})"
        else:
            key_text = "none (asked every run, never saved)"
        consent = cfg.get("consent")
        consent_text = (f"given via {consent.get('via')} (notice {consent.get('disclosure_version')}); source code: "
                        f"{'yes' if consent.get('allow_source_code') else 'no'}") if consent else "-"
        emb = cfg.get("embeddings") or {}
        rows = [("Mode", mode), ("Model", f"{cfg['provider']} - {cfg['model']}"), ("Gemini key", key_text),
                ("Consent", consent_text),
                ("Embeddings", f"{emb.get('model')} ({emb.get('dim')} dims), always local" if emb else "-")]
        if cfg.get("managed_by", {}).get("provider") == "env":
            rows.append(("Note", "the provider is fixed by AEGIS_LLM__PROVIDER on the API"))
        out.heading("AI model")
        out.kv(rows)
        if cfg.get("config_error") and not cfg.get("awaiting_key"):
            out.warn(cfg["config_error"])
    return render


def _models_view(provider: str, models: list[dict]):
    def render(out) -> None:
        rows = [(m["id"], m.get("stage") or "", (str(m["input_token_limit"]) if m.get("input_token_limit") else ""),
                 "yes" if m.get("thinking") else "", ", ".join(m.get("capabilities") or [])) for m in models]
        out.table(("Model", "Stage", "Context", "Thinking", "Can"), rows, title=f"{provider} models")
    return render


def _chat_models(models: list[dict]) -> list[dict]:
    return [m for m in models if not m.get("capabilities") or "generate" in m["capabilities"]]


def _pick(ctx, title: str, models: list[dict], default_id: Optional[str]) -> str:
    if not models:
        raise CliError(f"no {title} to choose from", USAGE)
    ids = [m["id"] for m in models]
    default = ids.index(default_id) + 1 if default_id in ids else 1
    for i, m in enumerate(models, 1):
        extra = f"  ({m['stage']})" if m.get("stage") not in (None, "stable") else ""
        ctx.out.line(f"  {i:>2}  {m['id']}{extra}")
    choice = typer.prompt(f"Choose a {title[:-1]}", default=str(default))
    if not choice.strip().isdigit() or not 1 <= int(choice) <= len(ids):
        raise CliError(f"{choice!r} is not one of 1-{len(ids)}", USAGE)
    return ids[int(choice) - 1]


def _api_only(ctx) -> None:
    if ctx.local:
        raise CliError("model configuration goes through the AEGIS API; remove --local", USAGE)


# ------------------------------------------------------------------ commands
def register(app: typer.Typer, groups: dict[str, typer.Typer]) -> None:
    llm = groups["llm"]
    key_stdin = typer.Option(False, "--api-key-stdin", help="Read the Gemini key from stdin (never from an argument).")
    key_env = typer.Option(None, "--api-key-env", metavar="NAME", help="Read the Gemini key from this environment variable.")

    @llm.command("status", help="The active model, where it runs, the key status (never the key) and consent.")
    @cli_command
    def status(typer_ctx: typer.Context) -> None:
        ctx = current(typer_ctx)
        if ctx.local:
            cfg = _local_status(ctx.settings)
        else:
            with ctx.api_client() as api:
                cfg = get_config(api)
        ctx.out.emit(cfg, status_view(cfg))

    @llm.command("providers", help="Ollama (offline) and Gemini (online): installed, allowed, active.")
    @cli_command
    def providers(typer_ctx: typer.Context) -> None:
        ctx = current(typer_ctx)
        _api_only(ctx)
        with ctx.api_client() as api:
            rows = api.get("/api/llm/providers")
        ctx.out.emit(rows, lambda out: out.table(
            ("Provider", "Where", "Installed", "Allowed", "Active", "Note"),
            [(p["name"], p["location"], "yes" if p["installed"] else "no", "yes" if p["allowed"] else "no",
              "yes" if p["active"] else "", p.get("reason") or "") for p in rows]))

    @llm.command("models", help="Models to choose from. Gemini lists what this run's key can use.")
    @cli_command
    def models(typer_ctx: typer.Context,
               provider: str = typer.Option("ollama", "--provider", "-p", help="ollama or gemini."),
               api_key_stdin: bool = key_stdin, api_key_env: Optional[str] = key_env) -> None:
        ctx = current(typer_ctx)
        _api_only(ctx)
        if provider not in ("ollama", "gemini"):
            raise CliError("--provider is ollama or gemini", USAGE)
        with ctx.api_client() as api:
            if provider == "ollama":
                found = api.get("/api/llm/models", params={"provider": "ollama"})["models"]
            else:
                has_key = (get_config(api).get("key") or {}).get("configured")
                key = read_key(from_stdin=api_key_stdin, env_name=api_key_env, ask=not has_key and _interactive())
                if not key and not has_key:
                    raise CliError("no Gemini key in this run", USAGE, hint=_no_key_hint())
                found = _send(api, "POST", "/api/llm/discover", {"provider": "gemini", **({"api_key": key} if key else {})})["models"]
        ctx.out.emit({"provider": provider, "models": found}, _models_view(provider, found))

    @llm.command("configure", help="Choose Offline or Online (a wizard), or script it with --provider/--model.")
    @cli_command
    def configure(
        typer_ctx: typer.Context,
        provider: Optional[str] = typer.Option(None, "--provider", "-p", help="ollama (offline) or gemini (online)."),
        model: Optional[str] = typer.Option(None, "--model", "-m", help="Model id (see: aegis llm models)."),
        api_key_stdin: bool = key_stdin,
        api_key_env: Optional[str] = key_env,
        accept_version: Optional[str] = typer.Option(None, "--accept-cloud-disclosure", metavar="VERSION",
                                                     help="Agree to the privacy notice of this version (scripts)."),
        allow_source_code: Optional[bool] = typer.Option(None, "--allow-source-code/--no-source-code",
                                                         help="Also send masked source excerpts for fix drafts."),
        deep: bool = typer.Option(False, "--deep", help="Also try every AEGIS answer format during validation."),
    ) -> None:
        ctx = current(typer_ctx)
        _api_only(ctx)
        wizard = provider is None
        with ctx.api_client() as api:
            cfg = get_config(api)
            key: Optional[str] = None
            if wizard:
                if not ctx.out.json_mode:
                    status_view(cfg)(ctx.out)
                if cfg.get("awaiting_key") and typer.confirm(
                        f"Online mode (Gemini {cfg.get('online_model')}) is waiting for this run's key. Enter it now?",
                        default=True):
                    provider, model = "gemini", cfg.get("online_model")
                    key = read_key(from_stdin=False, env_name=None, ask=True)
                else:
                    choice = typer.prompt("1 Offline (Ollama, this machine)  2 Online (Google Gemini)  0 Cancel", default="0")
                    provider = {"1": "ollama", "2": "gemini"}.get(choice.strip())
                    if provider is None:
                        ctx.out.note("Nothing changed.")
                        return
            if provider not in ("ollama", "gemini"):
                raise CliError("--provider is ollama or gemini", USAGE)
            if provider == "ollama":
                if wizard and not model:
                    local = _chat_models(api.get("/api/llm/models", params={"provider": "ollama"})["models"])
                    model = _pick(ctx, "local models", local, cfg["model"] if cfg["provider"] == "ollama" else None)
                result = _send(api, "PUT", "/api/llm/config", {"provider": "ollama", **({"model": model} if model else {})})
            else:
                has_key = (cfg.get("key") or {}).get("configured") and cfg["key"].get("source") != "session"
                if key is None:
                    key = read_key(from_stdin=api_key_stdin, env_name=api_key_env, ask=(wizard or _interactive()) and not has_key)
                if not key and not has_key:
                    raise CliError("no Gemini key given", USAGE, hint=_no_key_hint())
                if not model:
                    if not (wizard or _interactive()):
                        raise CliError("--model is needed with --provider gemini", USAGE, hint="see: aegis llm models -p gemini")
                    found = _send(api, "POST", "/api/llm/discover", {"provider": "gemini", **({"api_key": key} if key else {})})
                    model = _pick(ctx, "Gemini models", found["models"], cfg.get("online_model"))
                result = activate_gemini(ctx, api, model, key, interactive=wizard or _interactive(),
                                         accept_version=accept_version, allow_source_code=allow_source_code, deep=deep)
        ctx.out.emit(result, status_view(result))

    @llm.command("offline", help="Use the local model now (optionally another local model).")
    @cli_command
    def offline(typer_ctx: typer.Context,
                model: Optional[str] = typer.Option(None, "--model", "-m", help="A local model, e.g. qwen2.5:7b.")) -> None:
        ctx = current(typer_ctx)
        _api_only(ctx)
        with ctx.api_client() as api:
            result = _send(api, "PUT", "/api/llm/config", {"provider": "ollama", **({"model": model} if model else {})})
        ctx.out.emit(result, status_view(result))

    @llm.command("test", help="One small check of the active model (at most every 10 s).")
    @cli_command
    def test(typer_ctx: typer.Context) -> None:
        ctx = current(typer_ctx)
        _api_only(ctx)
        with ctx.api_client() as api:
            result = _send(api, "POST", "/api/llm/test", timeout=180.0)
        ctx.out.emit(result, lambda out: out.line(
            f"{result['provider']} {result['model']}: " + ("works" if result["ok"] else f"failed - {result.get('error')}")))
        if not result["ok"]:
            raise typer.Exit(1)

    @llm.command("forget-key", help="Forget this run's Gemini key now (goes offline first).")
    @cli_command
    def forget_key(typer_ctx: typer.Context,
                   yes: bool = typer.Option(False, "--yes", "-y", help="Do not ask to confirm.")) -> None:
        ctx = current(typer_ctx)
        _api_only(ctx)
        if not yes and not typer.confirm("Forget the Gemini key for this run (and go offline)?", default=False):
            ctx.out.note("Nothing changed.")
            return
        with ctx.api_client() as api:
            result = _send(api, "DELETE", "/api/llm/credentials/gemini")
        ctx.out.emit(result, status_view(result))


def _local_status(settings) -> dict:
    """``--local``: this machine's configuration, read-only (no API; a key typed into the API is not visible)."""
    from aegis.config import resolve_chat_settings
    from aegis.llm.consent import disclosure
    from aegis.llm.manager import ProviderManager

    status = ProviderManager(settings, read_only=True).status()
    chat = resolve_chat_settings(settings)
    return {**status, "disclosure": disclosure(),
            "embeddings": {"provider": "ollama", "location": "local", "model": chat.embed_model, "dim": chat.embed_dim}}
