# Fluke-GGH — AEGIS backend

**Prompt it. Secure it. Prove it.**

AEGIS is an evidence-first AI security agent. It scans a web app and its source code, *proves* which vulnerabilities are real, drafts a fix and verifies it on a copy of the code, and answers questions about your own findings. This repository holds the **backend** (API, agent, scanners integration, CLI and MCP server).

> ⚠️ **Authorised use only.** Scan only systems you own or have written permission to test. AEGIS enforces a target allow-list and a request rate limit for this reason.

---

## How Gemini fits in

AEGIS has two model modes behind one switch. The pipeline, JSON schemas, prompt guard, scanners and fix verifier are the same in both; only the model provider changes.

| Mode | Model | Status | Use it for |
|---|---|---|---|
| **Offline** | Ollama: `qwen2.5:7b` (reasoning), `bge-m3` (embeddings) | **Implemented** | Sensitive code, no internet. Nothing leaves the machine. |
| **Online** | **Google Gemini** (Flash model, set by env var) | **Planned for the Google Gemini Hackathon, not in this commit** | Larger context and stronger code generation on non-sensitive code. |

### What exists today
- All LLM calls go through one factory, `make_llm()` in `aegis/agent/llm.py`, which currently returns a local `ChatOllama`. There is **no Gemini code in this repository yet**.
- The safety layer rejects any non-local model host (`aegis/safety/model_host.py`), so offline is the enforced default.
- The MCP server works with **Antigravity**, Google's Gemini-powered editor, so Gemini-based editors can query AEGIS findings today. The server is read-only, audited and redacted.

### What Gemini will do in online mode
1. **Prompt Shield:** rewrite a lazy prompt ("make a login") into a secure spec (hashed passwords, parameterised queries, rate limits, no hard-coded secrets, mapped to OWASP ASVS) using system instructions and structured JSON output.
2. **Secure code generation** under a security-first system prompt.
3. **Auto-fix loop:** feed scanner findings back to the model, patch, and rescan until clean. This reuses the existing fix drafter and verifier.
4. **Explain and teach:** plain-language explanation of each fix, plus a quiz question from the user's own bug.
5. **Google Search grounding** for new exploits in a dependency or CVE, which the offline snapshot cannot know. This is online-only.
6. *Stretch:* multimodal input (an architecture diagram or login-page screenshot) and long-context fixes over a whole module.

### Privacy rules for online mode
- Opt-in and visibly marked ("ONLINE — Gemini" versus "OFFLINE — local"); it never silently weakens the offline guarantee.
- The existing prompt guard applies: whitelisted fields only, a byte budget, and no raw evidence or code.
- Secrets are redacted before anything is sent, and every outbound call is audited.
- The API key comes from an environment variable and is never committed.

---

## Why AEGIS

| The usual problem | What AEGIS does |
|---|---|
| Scanners report hundreds of *possible* issues | Correlates code findings with live behaviour: **candidate → corroborated → confirmed**, with evidence |
| A report says *what* is wrong, not how to fix it | Drafts a patch, **verifies it on a copy of the code**, and waits for **your approval** |
| Pasting code into cloud AI leaks your weakest points | Runs **fully offline** by default |
| AI assistants write code that works but isn't safe | Planned: Prompt Shield and a generate → scan → fix loop (see above) |

## Features

- **Scan in three modes:** M1 live app, M2 source code (folder or public GitHub repo), M3 both, correlated to the exact file, line and route.
- **Scanners behind a safety controller:** Semgrep, Gitleaks, TruffleHog, OSV-Scanner, Trivy, Syft, Nuclei and Katana. sslyze is optional. Vulnerability databases are staged once, then used offline.
- **Fix with a human in the loop:** drafted fixes are verified on a separate copy; nothing changes without approval.
- **Ask about your findings:** a RAG chatbot (hybrid vector and keyword retrieval) answers with citations, and a scope gate refuses unrelated questions.
- **Crypto and post-quantum readiness:** CycloneDX CBOM, weak-algorithm flags, and a migration checklist.
- **Attack paths and reports:** endpoint → handler → sink → finding graph, HTML/JSON/CBOM reports, and `aegis gate` as a CI verdict.
- **Interfaces:** FastAPI REST API, Typer CLI, and an MCP server.

## Architecture

```
            CLI (Typer + Rich)            MCP server (stdio)
                      \                      /
                       +--- FastAPI REST API ---+
                                  |
          LangGraph agent  ─  safety controller  ─  scanners
                                  |
            SQLite (scans, findings, evidence)   ChromaDB (RAG index)
                                  |
                  make_llm():  Ollama (offline)  |  Gemini (online, planned)
```

**Stack:** Python 3.10, FastAPI, LangGraph, LangChain-Ollama, ChromaDB, SQLModel/SQLite, tree-sitter, MCP SDK, Typer and Rich.

## Getting started

### Requirements
- Python 3.10+
- [Ollama](https://ollama.com) with two models:
  ```bash
  ollama pull qwen2.5:7b
  ollama pull bge-m3
  ```

### Install
```bash
python -m venv .venv
# Windows: .venv\Scripts\activate      Linux: source .venv/bin/activate
pip install -e ".[dev]"
```

### Stage the offline databases (the only online step, once)
```bash
scripts\stage_offline.cmd          # Windows
scripts/stage_offline.sh           # Linux
```

### Run the API
```bash
uvicorn aegis.main:app --host 127.0.0.1 --port 8000      # Swagger at /docs
```
Set `AEGIS_SAFETY__ALLOWLIST` to the host and port of the app you are allowed to scan.

## CLI

```bash
aegis doctor                     # check API, database, Ollama/model and scanners
aegis                            # interactive menu

aegis scan run --url http://127.0.0.1:5000 --identities identities.yml   # M1 live app
aegis scan run --folder ./my-app                                          # M2 source folder
aegis scan run --repo https://github.com/owner/name                       # M2 public repo
aegis scan list | status | watch | audit | cancel

aegis findings list --owasp A01 --state confirmed
aegis findings show F-0127 --diff
aegis graph | cbom | report | gate
aegis ask "Why is F-0127 exploitable?"
aegis chat
```

Exit codes: `0` ok · `1` failed or blocking findings · `2` usage error or scan not complete · `3` not found · `4` conflict · `5` unavailable · `130` interrupted.

## Use AEGIS from your editor (MCP)

```bash
python -m aegis.mcp.cli print-config     # prints the block to paste into mcp_config.json
python -m aegis.mcp.cli doctor
```

Read-only tools: `list_findings`, `get_finding`, `get_evidence`, `get_attack_paths`, `get_cbom`, `scan_status`, `ask`.

## Configuration

Environment variables are prefixed `AEGIS_`, with nested keys joined by `__`.

| Variable | Purpose |
|---|---|
| `AEGIS_OLLAMA_URL` | Ollama address, e.g. `http://127.0.0.1:11434` |
| `AEGIS_MODEL` | Reasoning model, e.g. `qwen2.5:7b` |
| `AEGIS_CHAT__EMBED_MODEL` / `AEGIS_CHAT__EMBED_DIM` | Embeddings, e.g. `bge-m3` / `1024` |
| `AEGIS_SAFETY__ALLOWLIST` | Hosts a scan may reach |
| `AEGIS_SCAN__RATE_LIMIT_RPS` | Request rate limit (default 5) |
| `AEGIS_API__ALLOWED_SOURCE_ROOTS` | Folders that may be scanned as source |
| `AEGIS_OFFLINE_DB_DIR` | Location of the staged vulnerability databases |

## Safety by design
- **Offline by default:** local LLM and embeddings; scans use pre-staged databases.
- **Allow-list and rate limit** on every outbound request, through one safety controller.
- **Evidence is redacted** before it is shown, exported or served over MCP.
- **Human approval** before any fix is applied.
- **Prompt guard:** scanned content is treated as data, never as instructions.

## Layout

```
aegis/      api, agent (LangGraph), chat (RAG), fix, graph, risk, safety, reports, cli, mcp
rules/      detection rules and fix templates
data/       bundled data files
scripts/    offline staging and local run helpers
```

This repo contains the backend only. The web console, tests and demo apps live in the full AEGIS project.

---

*Built for HackBios; the Gemini online mode is the work for the Google Gemini Hackathon. AEGIS is a security tool: use it responsibly, and only on systems you are authorised to test.*
