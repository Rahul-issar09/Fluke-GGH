# Fluke-GGH — AEGIS

**Prove it. Fix it. Learn from it. — and now: Prompt it. Secure it.**

**AEGIS is an offline-first, evidence-first AI security agent.** It scans your web app and your source code, *proves* which vulnerabilities are real, drafts a fix and verifies it on a copy of your code, and lets you ask questions about your own findings. By default everything runs on **local models (Ollama)**: no cloud, no API keys, and nothing leaves your machine. An optional **Online mode** uses Google Gemini with your own key; it is off until you switch it on and agree to what it sends, and the key is asked for every run and never saved.

> ⚠️ **Authorised use only.** Scan only systems you own or have written permission to test. AEGIS enforces a target allow-list and a request rate limit for this reason.

---

## Why AEGIS

| The usual problem | What AEGIS does |
|---|---|
| Scanners report hundreds of *possible* issues; teams can't tell which are real | Correlates code findings with live behaviour, moving each one from **candidate → corroborated → confirmed**, with evidence |
| A report says *what* is wrong, not how to fix it in your code | Drafts a patch, **verifies it on a copy of the code**, and waits for **your approval** |
| Pasting code into cloud AI leaks your weakest points | **Offline by default**: `qwen2.5:7b` for reasoning, `bge-m3` for search. Online mode (Gemini) only by explicit opt-in |
| Security knowledge is disconnected from your own bugs | Learn and Community sections link back to the bug types in **your latest scan** |

---

## Features

### 🔍 Scan, in three modes
- **M1 — Live app:** runtime testing of a running web app (OpenAPI or a crawler, with identities for access-control checks).
- **M2 — Source code:** a local folder or a public GitHub repo link.
- **M3 — Both, correlated:** a code-level finding is confirmed against live behaviour, giving the exact **file, line and route**, a risk score and the evidence.

Runs proven open-source scanners under a **safety controller**: Semgrep, Gitleaks, TruffleHog, OSV-Scanner, Trivy, Syft, Nuclei and Katana. sslyze is optional, for TLS. Vulnerability databases are staged **once** and then used offline.

### 🛠️ Fix, with a human in the loop
- AEGIS drafts a fix for a finding and **verifies** it on a separate copy of the code.
- You review the diff, then approve it as a **patch** or **apply** it.
- Nothing changes without approval.

### 💬 Ask about *your* findings
- A RAG chatbot answers with **citations** from your scan, using hybrid retrieval (vector and keyword).
- A **scope gate** refuses unrelated questions (*"what is k8s?"* → *"No finding matches"*) instead of hallucinating.

### 🤖 Choose the AI model: Offline or Online
- **Offline (default):** Ollama on this machine, `qwen2.5:7b` or any local model you pick. Nothing leaves your machine.
- **Online (opt-in):** Google Gemini with **your own API key**. The model list comes from Google for your key (nothing hard-coded), and a tiny test request proves the key and model work before anything else is sent.
- **The key is asked for every run and never saved:** not in a file, the database, the browser or a key store. After a restart AEGIS runs offline until you enter it again; the same key resumes without new questions.
- **Before going online you agree to a privacy notice** saying exactly what is sent (finding descriptions, file paths, routes, evidence summaries, your questions). Sending **source-code excerpts** for fix drafts is a separate choice, off by default.
- **Go offline any time**, even during a scan; it takes effect at once. Each scan keeps the model it started with, and AEGIS never switches between local and cloud on its own.
- Embeddings and the search index **always stay local**, whichever model answers.
- Set it up in the web console (**AI model**, or **AI for this scan** on **New scan**), with `aegis llm configure`, or through `/api/llm/*`. A scan starts only on the mode shown as selected.

### 🛡️ Secure Prompt (Online mode, Gemini)
Ask for code in plain words and get code written with security in mind, plus plain reasons why it is safer, each mapped to the **OWASP Top 10 (2021)**.

- **One Gemini call** returns the code, the reasons (each tagged A01-A10) and an honest "not covered" list. Open **Secure prompt** in the web console, or call `POST /api/secure-prompt`.
- **Gemini Online mode only.** With the offline model active, the API answers `409 online_required` and nothing is sent anywhere. There is no silent fallback to Ollama.
- **Only your request text is sent**, with known secrets scrubbed out first. No code, scan results or files leave your machine. Every call is audited (prompt length and outcome, never the prompt text or the key).
- **Checked output:** the answer needs at least 3 reasons with valid OWASP ids and a "not covered" list, and is rejected if it claims the code is "100% secure". One corrective retry, then a clear error.
- **Not verified, on purpose.** The generated code is **not scanned or run** by AEGIS, so the reasons are the model's claims, not proof. The response carries `verified: false` and the page says so. To check code you generate, scan it with AEGIS (M2) like any other code.
- **Coverage grid:** each of A01-A10 is shown as covered, not applicable, or not covered, so a snippet never claims more than it does.

### 🔐 Crypto & post-quantum readiness
- **CBOM** (CycloneDX) of the cryptography in your app.
- Broken, weak and quantum-vulnerable algorithms are flagged, with a readiness score and a migration checklist.

### 🧭 Attack paths, reports and CI gate
- Attack-path graph: endpoint → handler → sink → finding.
- HTML, JSON and CBOM reports.
- `aegis gate` returns a CI verdict through its exit code.

### 🧰 Works where you work
- **Web console** (React + Vite).
- **Cross-platform CLI** (Windows and Linux) with an interactive menu.
- **MCP server**, so code editors such as **Antigravity** can query AEGIS directly. It is read-only, audited and redacted.

### 📚 Learn
- **Overview:** "From your latest scan", plus your weak areas.
- **Threat Pulse:** an offline KEV / NVD / EPSS / OSV snapshot with filters and "Check my scans".
- **Crypto & PQC:** algorithm status, safe replacements in Python, JS and Java, and the HNDL explainer.
- **Breach case studies**, each answering "Would AEGIS catch it?"
- **Fix-it practice:** 8 hands-on challenges with hints.
- **Cheat sheets** for Python, JavaScript, Java and Go, with copy buttons and a print view.
- **Quizzes:** 7 questions per bug type, plus "Quiz from my scan".

### 🤝 Community (preview)
- Feed, Q&A, Resources, Jobs, profiles with reputation and badges, notifications, and moderation.
- **Safety built in:**
  - posts containing API keys or tokens are **blocked**;
  - Markdown renders without raw HTML, so posts can't inject script;
  - images are checked by their real file type, and SVG is rejected;
  - shared findings have **paths and hosts hidden**.
- An optional **AI draft answer** from the local model is labelled *verify* and kept apart from human answers.
- *Preview:* data is stored in each browser until a shared community server is added.

---

## Architecture

```
          Web console (React/Vite)    CLI (Typer + Rich)    MCP server (stdio)
                     \                    |                    /
                      +----------- FastAPI REST API -----------+
                                          |
                  LangGraph agent  ─  safety controller  ─  scanners (offline)
                                          |
             SQLite (scans, findings, evidence)   ChromaDB (RAG index)
                                          |
                         Ollama:  qwen2.5:7b  ·  bge-m3 (1024-dim)
                         optional, opt-in:  Google Gemini (reasoning only)
```

**Stack:** Python 3.10, FastAPI, LangGraph, LangChain-Ollama (and, optionally, LangChain-Google-GenAI), ChromaDB, SQLModel/SQLite, tree-sitter, MCP SDK 2.x, Typer and Rich, React 18 and Vite.

---

## Getting started

### Requirements
- **Python 3.10+**
- **Node.js 18+**, for the web console
- **[Ollama](https://ollama.com)** with two models:
  ```bash
  ollama pull qwen2.5:7b
  ollama pull bge-m3
  ```

### Install
```bash
python -m venv .venv
# Windows: .venv\Scripts\activate      Linux: source .venv/bin/activate
pip install -e ".[dev]"            # add ,browser for browser logins, ,tls for TLS checks, ,gemini for Online mode
cd frontend && npm install && cd ..
```

### Stage the offline databases (the only online step, once)
```bash
scripts\stage_offline.cmd          # Windows
scripts/stage_offline.sh           # Linux
```

### Run the demo
**Windows:** run `scripts\run_local.cmd`. It starts:

| What | Address |
|---|---|
| Deliberately vulnerable demo app | http://127.0.0.1:5000 |
| Demo app over HTTPS (weak TLS) | https://127.0.0.1:5443 |
| Demo app without OpenAPI (crawler + browser login) | http://127.0.0.1:5001 |
| Callback listener (SSRF witness) | http://127.0.0.1:8080 |
| AEGIS API + Swagger | http://127.0.0.1:8000/docs |
| AEGIS web console | http://127.0.0.1:5173 |

**Linux / manual:** start the API and the console yourself:
```bash
uvicorn aegis.main:app --host 127.0.0.1 --port 8000      # API + Swagger at /docs
cd frontend && npm run dev                                # console at http://127.0.0.1:5173
```
Set `AEGIS_SAFETY__ALLOWLIST` to the host and port of the app you are allowed to scan (see `scripts/run_local.cmd` for the full set of demo settings).

The demo app is scanned from a fresh copy in `data/scan/demo-app`, so an applied fix never changes the original.

---

## CLI

```bash
aegis doctor                     # check API, database, Ollama/model and scanners; says what to fix
aegis                            # interactive menu: 1 = Scan -> M1 / M2 / M3 -> run -> ask questions

# scan (asks you to confirm you are authorised)
aegis scan run --url http://127.0.0.1:5000 --identities demo-app/identities.yml    # M1 live app
aegis scan run --folder ./my-app                                                    # M2 source folder
aegis scan run --repo https://github.com/owner/name                                 # M2 public repo
aegis scan run --url http://127.0.0.1:5000 --identities demo-app/identities.yml --folder ./my-app   # M3
#   before it starts, a scan asks "AI for this scan": Enter keeps the active model, 1 = a local model,
#   2 = Gemini. The scan keeps that model to the end. --model qwen2.5:7b picks a local one without asking.
aegis scan list | status | watch | audit | cancel

# results (latest scan by default; --scan S-0017 for another)
aegis findings list --owasp A01 --state confirmed
aegis findings show F-0127 --diff        # one finding explained, with the drafted fix's diff
aegis evidence show <evidence-id> --raw  # payload with secrets redacted
aegis graph | cbom | report | gate

# the AI model: offline (Ollama) or online (Gemini; the key is asked every run, never saved)
aegis llm status                         # what is active, the key's last 4 characters, consent
aegis llm models [-p gemini]             # local models, or the Gemini models your key can use
aegis llm configure                      # a wizard: offline/online, model, key (hidden prompt), agreement
aegis llm offline [--model qwen2.5:7b]   # back to a local model now
aegis llm test | providers | forget-key

# questions, answered by the active model with citations
aegis ask "Why is F-0127 exploitable?"
aegis chat                               # one question after another (/quit to stop)
```

The CLI is a thin client of the running API (`--api`, or `AEGIS_API_URL`). `--json` prints machine-readable output, and `--local` reads results from the data folder without the API.

Exit codes: `0` ok · `1` failed or blocking findings · `2` usage error or scan not complete · `3` not found · `4` conflict · `5` unavailable · `130` interrupted.

**The Gemini key in the CLI** is never a command-line argument (so it never lands in your shell history): it comes from a hidden prompt, from stdin (`--api-key-stdin`), or from an environment variable you name (`--api-key-env NAME`). If Online mode is waiting for this run's key, `scan run`, `ask`, `chat` and the menu ask for it (Enter continues offline). For scripts: `aegis llm configure -p gemini -m <model> --api-key-env MY_KEY --accept-cloud-disclosure <version>` (the version is shown by `aegis llm status --json`).

Fixes are verified and approved in the **web console** (or through the REST API at `/docs`). After changing the embedding model, rebuild a scan's chat index with `python -m aegis.chat reindex S-0017` (or `--all`).

---

## Use AEGIS from your code editor (MCP)

```bash
python -m aegis.mcp.cli print-config     # prints the block to paste into your editor's mcp_config.json
python -m aegis.mcp.cli doctor           # what works, and what to fix
```

Example config for Antigravity (adjust the paths):
```json
{
  "mcpServers": {
    "aegis": {
      "command": "<project>/.venv/Scripts/python.exe",
      "args": ["-m", "aegis.mcp.server"],
      "env": {
        "PYTHONPATH": "<project>",
        "AEGIS_DATA_DIR": "<project>/data",
        "AEGIS_OLLAMA_URL": "http://127.0.0.1:11434",
        "AEGIS_MODEL": "qwen2.5:7b",
        "AEGIS_CHAT__EMBED_MODEL": "bge-m3",
        "AEGIS_CHAT__EMBED_DIM": "1024"
      }
    }
  }
}
```

**Tools (read-only):**
- `list_findings`, `get_finding`, `get_evidence`
- `get_attack_paths`, `get_cbom`
- `scan_status`, `ask` (the answer says which model answered)
- `llm_status`: which model AEGIS uses (offline/online); never anything about a key

**Resources:** findings, graph, CBOM, report, and `aegis://config/llm`.

The model is chosen in AEGIS, never by the editor. In Online mode the MCP server, a separate process, does not have the key you typed into AEGIS (it is never saved), so it answers with the offline model and says so. Note that your editor's **own** chat model may be a cloud model: whatever the tools return goes to it.

---

## Configuration

Settings come from environment variables prefixed `AEGIS_`, with nested keys joined by `__`. Run `aegis version` to see the values in effect.

| Variable | Purpose |
|---|---|
| `AEGIS_OLLAMA_URL` | Ollama address (use `http://127.0.0.1:11434`) |
| `AEGIS_MODEL` | Reasoning model, e.g. `qwen2.5:7b` |
| `AEGIS_CHAT__EMBED_MODEL` / `AEGIS_CHAT__EMBED_DIM` | Embeddings, e.g. `bge-m3` / `1024` (the defaults) |
| `AEGIS_CHAT__EMBED_URL` | Where the embedding model runs (default: the Ollama URL); always local |
| `AEGIS_LLM__ALLOW_CLOUD` | `false` makes Online mode impossible on this install (an admin kill-switch) |
| `AEGIS_LLM__PROVIDER` / `AEGIS_LLM__GEMINI__MODEL` | Pin the provider / Gemini model (then the UI and CLI cannot change them) |
| `AEGIS_LLM__GEMINI__RPM` / `__THINKING_BUDGET` / `__MAX_OUTPUT_TOKENS` | Gemini request rate (default 10/min), thinking budget, answer length |
| `AEGIS_LLM__GEMINI__API_KEY` / `AEGIS_LLM__GEMINI__API_KEY_FILE` | For servers/CI only: an operator-supplied key (otherwise the key is asked every run) |
| `AEGIS_LLM__CLOUD_CONSENT` / `AEGIS_LLM__CLOUD_SOURCE_CONSENT` | For headless installs: the privacy-notice version agreed to, and whether source excerpts may be sent |
| `AEGIS_API__AUTH_TOKEN` | Require a bearer token for `/api` and `/mcp` |
| `AEGIS_API__ALLOWED_HOSTS` | Extra host names the API answers to without a token (default: localhost only) |
| `AEGIS_SAFETY__ALLOWLIST` | Hosts a scan may reach, e.g. `127.0.0.1:5000` |
| `AEGIS_SCAN__RATE_LIMIT_RPS` | Request rate limit (default 5) |
| `AEGIS_API__ALLOWED_SOURCE_ROOTS` | Folders that may be scanned as source |
| `AEGIS_OFFLINE_DB_DIR` | Location of the staged vulnerability databases |

---

## Tests

```bash
pytest                                        # backend, CLI and MCP tests (no test may reach the network)
pytest -m ollama                              # with the real local model
pytest -m gemini                              # with real Gemini: set AEGIS_TEST_GEMINI_API_KEY (uses a little quota)
cd frontend && node --test src/community/__tests__/ src/llm/__tests__/   # frontend logic (no extra packages)
cd frontend && npx vite build                 # frontend build
```

---

## Safety by design
- **Offline by default:** local LLM and embeddings. Scans use pre-staged databases and never download anything.
- **Online only by consent:** Gemini needs a validated key, your agreement to the current privacy notice, and is refused if an admin turned cloud off. The key is never saved, never shown (last 4 characters at most), and scrubbed from every log, error and audit line.
- **The local API answers only this machine** unless you set a token (protection against malicious web pages, including DNS rebinding).
- **Allow-list and rate limit** on every outbound request, through a single safety controller.
- **Evidence is redacted** before it is shown, exported or served over MCP.
- **Human approval** before any fix is applied.
- **The prompt guard** treats scanned content as data, never as instructions.

---

## Project layout

```
aegis/          backend (incl. secure_prompt/ for Secure Prompt): api, agent (LangGraph), chat (RAG), fix, graph, risk, safety, reports, cli, mcp
frontend/       web console: landing, console, learn, community
demo-app/       deliberately vulnerable demo target (do not deploy)
callback-listener/   SSRF witness used by runtime scans
rules/          detection rules and fix templates
scripts/        run_local.cmd, offline staging
tests/          pytest suites (backend, CLI, MCP)
```

---

*Built for HackBios. AEGIS is a security tool: use it responsibly, and only on systems you are authorised to test.*
