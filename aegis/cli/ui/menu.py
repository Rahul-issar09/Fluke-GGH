"""The interactive menu: typing just ``aegis`` (cli_new_phases.md N4).

    1 Scan  -> M1 / M2 / M3 (each explained) -> inputs -> review -> AI for this scan -> live progress
            -> summary -> questions
    2 Ask questions   3 Results   4 Report & gate   5 Scan history   0 Exit

It only composes commands that already exist (``scan run`` / ``ask`` / ``findings`` / ``report`` /
``gate``), all through the AEGIS API. Plain numbered prompts: they work in PowerShell, cmd, Windows
Terminal and Linux terminals with no extra library. ``0`` (or ``back``) returns to the previous
screen; Ctrl+C leaves the current screen.
"""

from __future__ import annotations

from pathlib import Path
from typing import Callable

import typer

from aegis.cli.commands._common import check_id
from aegis.cli.commands.chat import chat_loop, save_report
from aegis.cli.commands.llm import _send, activate_gemini, before_model_use, get_config, model_label, status_view
from aegis.cli.commands.scan_run import AUTH_NOTE, build_request, follow, mode_of
from aegis.cli.errors import CliError
from aegis.cli.ui.progress import MODE_LABELS
from aegis.cli.ui.views import finding_view, findings_view, gate_view, scans_view, to_data

__all__ = ["run_menu"]

Reader = Callable[[str], str]

MAIN = """
  1  Scan               run a new scan (M1 / M2 / M3)
  2  Ask questions      about a scan's findings
  3  Results            findings of a scan, one finding in detail
  4  Report & gate      the report, and the CI verdict
  5  Scan history       recent scans and their status
  6  AI model           offline (Ollama) or online (Gemini; the key is asked every run)
  0  Exit"""

MODES = """
 Which kind of scan?

  1  M1 - Live app only
        A live link (https://app.example.com) or a local link (http://127.0.0.1:5000).
        AEGIS tests the RUNNING app from the outside as two test users (owner A, attacker B):
        access control, SSRF, misconfiguration, API conformance, TLS.
        Needs: the URL + an identities file with the two test accounts.

  2  M2 - Code only
        A GitHub repo link (https://github.com/owner/repo) OR a local code folder - not both.
        AEGIS reads the code without running it: code weaknesses, hard-coded secrets,
        vulnerable dependencies, cryptography.
        Needs: the repo link or the folder.

  3  M3 - Full (code + running app)
        Both of the above for the SAME application: AEGIS proves issues on the running app and
        links each one to the exact line of code that causes it.
        Needs: the URL + identities file + the repo link or folder.

  0  Back"""

# a refusal from the API → the API setting that controls it (cli_new_phases.md section 3)
_SETTING_HINTS = (
    ("allowed source roots", "the API allows folders listed in AEGIS_API__ALLOWED_SOURCE_ROOTS (set where the API starts, e.g. run_local.cmd)"),
    ("allowlist", "the API scans only hosts in AEGIS_SAFETY__ALLOWLIST (host:port; set where the API starts)"),
    ("git host", "repo scans need the host in AEGIS_SAFETY__GIT_HOSTS, e.g. github.com:443"),
    ("not enabled", "repo scans need the host in AEGIS_SAFETY__GIT_HOSTS, e.g. github.com:443"),
    ("identities", "M1/M3 need an identities file with two test accounts (see demo-app/identities.yml)"),
    ("still running", "one scan runs at a time; wait for it, or cancel it: aegis scan cancel <SCAN>"),
)

_FINISHED = ("completed", "awaiting_approval")


class _Back(Exception):
    """The user asked to go back one screen."""


def _setting_hint(message: str) -> str | None:
    low = message.lower()
    return next((hint for key, hint in _SETTING_HINTS if key in low), None)


def _hidden(prompt: str) -> str:
    """A prompt that does not echo what is typed (for the Gemini key)."""
    return typer.prompt(prompt, hide_input=True, default="", show_default=False)


class Menu:
    def __init__(self, ctx, be, read: Reader, secret: Reader = _hidden):
        self.ctx, self.be, self.read, self.out = ctx, be, read, ctx.out
        self.secret = secret   # never ``read``: that one echoes

    # ------------------------------------------------------------------ prompts
    def ask(self, prompt: str, *, default: str | None = None, allow_back: bool = True) -> str:
        shown = f"{prompt} [{default}]: " if default else f"{prompt}: "
        answer = self.read(shown).strip()
        if allow_back and answer.lower() in ("0", "back", "b"):
            raise _Back()
        return answer or (default or "")

    def choose(self, prompt: str, options: str) -> str:
        while True:
            answer = self.read(f"{prompt} [{options}]: ").strip().lower()
            if answer in options.split("/") or answer in options:
                return answer
            self.out.error(f"please type one of: {options}")

    def confirm(self, prompt: str, *, default: bool) -> bool:
        suffix = "[Y/n]" if default else "[y/N]"
        answer = self.read(f"{prompt} {suffix}: ").strip().lower()
        return default if not answer else answer in ("y", "yes")

    def field(self, prompt: str, check: Callable[[str], str | None], *, required: bool = True) -> str | None:
        """Ask until *check* accepts the answer (it returns an error message, or ``None``)."""
        while True:
            value = self.ask(prompt).strip().strip('"').strip("'")
            if not value and not required:
                return None
            problem = check(value) if value else "this is required (0 = back)"
            if problem is None:
                return value
            self.out.error(problem)

    # ------------------------------------------------------------------ helpers
    def finished_scans(self) -> list[dict]:
        return [s for s in to_data(self.be.list_scans(50)) if s.get("status") in _FINISHED]

    def pick_scan(self) -> str:
        scans = self.finished_scans()
        if not scans:
            raise CliError("there is no finished scan yet - choose 1 (Scan) first")
        default = scans[0]["id"]
        while True:
            value = self.ask("Scan", default=default)
            try:
                sid = check_id("scan", value)
                self.be.scan_status(sid)
                return sid
            except (typer.BadParameter, CliError) as exc:
                self.out.error(str(exc))

    # ------------------------------------------------------------------ screens
    def header(self) -> bool:
        """Show the API status; return whether it answers."""
        try:
            health = self.ctx.api_client().health()
            ollama = (health.get("ollama") or {})
            model = "model ok" if ollama.get("model_present") else "model not available (questions use fallbacks)"
            self.out.heading(f" AEGIS  (API: {self.ctx_api()}  OK, {model})")
            return True
        except CliError as exc:
            self.out.heading(f" AEGIS  (API: {self.ctx_api()}  NOT RUNNING)")
            self.out.error(str(exc), exc.hint)
            return False

    def ctx_api(self) -> str:
        from aegis.cli.remote import api_url

        return api_url(self.ctx.api)

    def main(self) -> int:
        before_model_use(self.ctx, self.be)   # once per run: this run's Gemini key, if Online mode waits for it
        while True:
            self.out.line()
            if not self.header():
                if self.choose("r = retry, 0 = exit", "r/0") == "0":
                    return 5
                continue
            has_scan = bool(self.finished_scans())
            for line in MAIN.splitlines():
                needs = line.strip()[:1] in ("2", "3", "4")
                self.out.line(line + ("   (needs a scan - choose 1 first)" if needs and not has_scan else ""))
            choice = self.read("\n Choose [0-6]: ").strip()
            actions = {"1": self.scan, "2": self.questions, "3": self.results, "4": self.report_gate, "5": self.history,
                       "6": self.ai_model}
            if choice in ("0", "q", "quit", "exit"):
                return 0
            if choice not in actions:
                self.out.error("type a number from 0 to 6")
                continue
            try:
                actions[choice]()
            except _Back:
                continue
            except (EOFError, KeyboardInterrupt):
                raise
            except typer.Exit:                      # Ctrl+C while following a scan: back to the menu
                continue
            except (CliError, typer.BadParameter) as exc:
                self.out.error(str(exc), getattr(exc, "hint", None))

    def ai_model(self) -> None:
        """6: the model AEGIS reasons with (LLM_PROVIDER_PHASES LP9)."""
        api = self.be.api
        cfg = get_config(api)
        status_view(cfg)(self.out)
        for line in ("", "  1  Offline - choose a local model", "  2  Online - Google Gemini (the key is asked every run)",
                     "  3  Go offline now", "  0  Back"):
            self.out.line(line)
        choice = self.read("\n Choose [0-3]: ").strip()
        if choice in ("", "0"):
            return
        if choice == "3":
            status_view(_send(api, "PUT", "/api/llm/config", {"provider": "ollama"}))(self.out)
            return
        if choice not in ("1", "2"):
            raise CliError("type 1, 2, 3 or 0")
        result = self.switch_model(choice, cfg)
        if result:
            status_view(result)(self.out)

    def switch_model(self, choice: str, cfg: dict) -> dict | None:
        """1 = a local model, 2 = Gemini. The configuration in effect afterwards, or ``None`` if nothing changed."""
        api = self.be.api
        if choice == "1":
            local = [m for m in api.get("/api/llm/models", params={"provider": "ollama"})["models"]
                     if not m.get("capabilities") or "generate" in m["capabilities"]]
            for i, m in enumerate(local, 1):
                self.out.line(f"  {i:>2}  {m['id']}")
            pick = self.ask("Local model number", default="1")
            if not pick.isdigit() or not 1 <= int(pick) <= len(local):
                raise CliError(f"{pick!r} is not one of 1-{len(local)}")
            return _send(api, "PUT", "/api/llm/config", {"provider": "ollama", "model": local[int(pick) - 1]["id"]})
        key = self.secret("Gemini API key (asked every run, never saved)").strip()
        if not key and not (cfg.get("key") or {}).get("configured"):
            self.out.note("No key entered; nothing changed.")
            return None
        found = _send(api, "POST", "/api/llm/discover", {"provider": "gemini", **({"api_key": key} if key else {})})["models"]
        ids = [m["id"] for m in found]
        for i, m in enumerate(found, 1):
            self.out.line(f"  {i:>2}  {m['id']}" + (f"  ({m['stage']})" if m.get("stage") not in (None, "stable") else ""))
        default = str(ids.index(cfg["online_model"]) + 1) if cfg.get("online_model") in ids else "1"
        pick = self.ask("Gemini model number", default=default)
        if not pick.isdigit() or not 1 <= int(pick) <= len(ids):
            raise CliError(f"{pick!r} is not one of 1-{len(ids)}")

        def consent(disclosure: dict) -> bool:
            self.out.heading("Before switching to Online mode")
            self.out.line(disclosure["text"])
            allow = self.confirm(disclosure["source_code_text"], default=False)
            if self.read(f"Type YES to agree (privacy notice {disclosure['version']}): ").strip().upper() != "YES":
                raise CliError("not switched: the privacy notice was not accepted")
            return allow

        return activate_gemini(self.ctx, api, ids[int(pick) - 1], key or None, interactive=True, accept_version=None,
                               allow_source_code=None, ask_consent=consent)

    def scan_model(self) -> None:
        """Which model the scan uses ("AI for this scan"); it keeps it to the end. Enter keeps the active one."""
        cfg = get_config(self.be.api)
        self.out.line()
        self.out.heading("AI for this scan")
        for line in (f"  Enter  keep {model_label(cfg)}", "  1      Offline - choose a local model",
                     "  2      Online - Google Gemini (the key is asked every run)", "  0      Back"):
            self.out.line(line)
        while True:
            choice = self.read("\n Choose [Enter/1/2/0]: ").strip()
            if choice in ("0", "back", "b"):
                raise _Back()
            if not choice:
                break
            if choice not in ("1", "2"):
                self.out.error("type 1, 2 or 0, or press Enter to keep the current model")
                continue
            try:
                cfg = self.switch_model(choice, cfg) or cfg
                break
            except CliError as exc:
                self.out.error(f"{exc} - choose again (Enter keeps {model_label(cfg)})", getattr(exc, "hint", None))
        self.out.line(f"  AI for this scan: {model_label(cfg)}")

    def scan(self) -> None:
        while True:
            for line in MODES.splitlines():
                self.out.line(line)
            choice = self.read("\n Choose [0-3]: ").strip()
            if choice == "0":
                return
            if choice not in ("1", "2", "3"):
                self.out.error("type 1, 2, 3 or 0")
                continue
            try:
                body = self.inputs(choice)
            except _Back:
                continue
            if body is None:
                continue
            sid = self.start(body)
            if sid is None:
                continue
            code = follow(self.ctx, self.be, sid)
            if code == 0:
                self.out.line()
                chat_loop(self.ctx, self.be, sid, read=self.read)
            return

    def inputs(self, choice: str) -> dict | None:
        url = identities = folder = repo = None
        if choice in ("1", "3"):
            url = self.field("App URL (http://... or https://...)",
                             lambda v: None if v.startswith(("http://", "https://")) else "the URL must start with http:// or https://")
            identities = self.field("Identities file (two test accounts)",
                                    lambda v: None if Path(v).expanduser().is_file() else f"file not found: {v}")
        if choice in ("2", "3"):
            kind = self.choose("Code from: 1 = GitHub repo link, 2 = local folder", "1/2")
            if kind == "1":
                repo = self.field("Repo link (https://github.com/owner/name)",
                                  lambda v: None if v.startswith("https://") else "the repo link must start with https://")
            else:
                folder = self.field("Code folder",
                                    lambda v: None if Path(v).expanduser().is_dir() else f"folder not found: {v}")
        body = build_request(url, folder, repo, identities)
        mode = mode_of(body)
        self.out.line()
        self.out.heading("Ready to scan")
        self.out.kv([("Mode", MODE_LABELS[mode]), ("App URL", body.get("url") or "-"),
                     ("Identities", body.get("identities") or "-"), ("Code", body.get("folder") or body.get("repo") or "-")])
        if body.get("url"):
            self.out.line()
            self.out.line(f"  {AUTH_NOTE}")
            if not self.confirm("  I own this app or am authorised to test it", default=False):
                self.out.line("Not started.")
                return None
        self.scan_model()
        if not self.confirm("Start the scan?", default=True):
            return None
        return body

    def start(self, body: dict) -> str | None:
        try:
            return self.be.start_scan(body)
        except CliError as exc:
            self.out.error(f"the AEGIS API refused the scan: {exc}", exc.hint or _setting_hint(str(exc)))
            return None

    def questions(self) -> None:
        chat_loop(self.ctx, self.be, self.pick_scan(), read=self.read)

    def results(self) -> None:
        sid = self.pick_scan()
        found = to_data(self.be.list_findings(sid))
        findings_view(sid, found, len(found))(self.out)
        while True:
            value = self.ask("Finding to open (Enter = back)", allow_back=True)
            if not value:
                return
            try:
                finding_view(to_data(self.be.get_finding(check_id("finding", value))))(self.out)
            except (typer.BadParameter, CliError) as exc:
                self.out.error(str(exc))

    def report_gate(self) -> None:
        sid = self.pick_scan()
        verdict = to_data(self.be.gate(sid))
        details = {f["id"]: f for f in to_data(self.be.list_findings(sid))} if verdict["blocking_findings"] else {}
        gate_view(sid, verdict, details, None)(self.out)
        path = save_report(self.be, sid)
        self.out.line(f"Report: {path}")
        if self.confirm("Open the report in the browser?", default=False):
            import webbrowser

            webbrowser.open(Path(path).as_uri())

    def history(self) -> None:
        scans_view(to_data(self.be.list_scans(15)))(self.out)


def run_menu(ctx, read: Reader = input) -> int:
    """Run the menu until the user exits; returns the exit code."""
    if ctx.local:
        raise CliError("the menu works through the AEGIS API; remove --local")
    with ctx.backend() as be:
        try:
            return Menu(ctx, be, read).main()
        except (EOFError, KeyboardInterrupt):
            ctx.out.line()
            return 0
