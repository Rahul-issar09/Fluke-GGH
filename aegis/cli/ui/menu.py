"""The interactive menu: typing just ``aegis`` (cli_new_phases.md N4).

    1 Scan  -> M1 / M2 / M3 (each explained) -> inputs -> review -> live progress -> summary -> questions
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


class Menu:
    def __init__(self, ctx, be, read: Reader):
        self.ctx, self.be, self.read, self.out = ctx, be, read, ctx.out

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
            choice = self.read("\n Choose [0-5]: ").strip()
            actions = {"1": self.scan, "2": self.questions, "3": self.results, "4": self.report_gate, "5": self.history}
            if choice in ("0", "q", "quit", "exit"):
                return 0
            if choice not in actions:
                self.out.error("type a number from 0 to 5")
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
