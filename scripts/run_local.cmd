@echo off
rem AEGIS local demo (no Docker): opens the demo targets, AEGIS and the web UI with the right settings.
rem   1. the deliberately vulnerable demo app      http://127.0.0.1:5000
rem      its browsable frontend (backend + UI)     http://127.0.0.1:5000/ui
rem   2. the same demo app over HTTPS (weak TLS)   https://127.0.0.1:5443
rem   2b. the demo app without OpenAPI (crawler + browser login)  http://127.0.0.1:5001
rem   3. the callback listener (SSRF witness)      http://127.0.0.1:8080
rem   4. the AEGIS backend + Swagger               http://127.0.0.1:8000/docs
rem   5. the AEGIS web UI (frontend\, Node.js)     http://127.0.0.1:5173  (after: cd frontend & npm install)
rem Close a window (or press Ctrl+C in it) to stop that part.
rem
rem The demo app is served from a fresh COPY in data\scan\demo-app, and only that copy may be
rem scanned as a folder: an approved "apply" fix changes the copy, never the project's demo-app.
rem Restart the launcher to get a clean, vulnerable copy again.
rem
rem No ( ) blocks and no labels in this file: the project path itself contains parentheses,
rem e.g. "Hackbios(HGC)", and cmd would read its ")" as the end of a block.
setlocal
for %%I in ("%~dp0..") do set "ROOT=%%~fI"
set "PY=%ROOT%\.venv\Scripts\python.exe"
if not exist "%PY%" echo The virtual environment is missing: "%PY%" & exit /b 1

set "SCAN=%ROOT%\data\scan\demo-app"
if exist "%SCAN%" rmdir /s /q "%SCAN%"
xcopy "%ROOT%\demo-app" "%SCAN%\" /e /i /q /exclude:%~dp0copy_exclude.txt >nul

start "AEGIS demo app :5000" /D "%SCAN%" "%PY%" -m uvicorn --factory app.main:create_app --host 127.0.0.1 --port 5000
rem the same demo without its OpenAPI document (Katana crawls it) and with the browser login form
set "DEMO_OPENAPI=0"
start "AEGIS demo app, no OpenAPI :5001" /D "%SCAN%" "%PY%" -m uvicorn --factory app.main:create_app --host 127.0.0.1 --port 5001
set "DEMO_OPENAPI="
start "AEGIS demo app HTTPS :5443" /D "%SCAN%" "%PY%" serve_https.py --port 5443
start "AEGIS callback listener :8080" /D "%ROOT%\callback-listener" "%PY%" -m uvicorn --factory app:create_app --host 127.0.0.1 --port 8080

rem 127.0.0.1, not localhost: on Windows "localhost" can reach a different Ollama (e.g. a Docker one) over IPv6
set "AEGIS_OLLAMA_URL=http://127.0.0.1:11434"
rem the embedding model that builds the chat index: it must be the one that built data\chroma
rem (bge-m3, 1024 dims; after changing it run: python -m aegis.chat reindex --all)
set "AEGIS_CHAT__EMBED_MODEL=bge-m3"
set "AEGIS_CHAT__EMBED_DIM=1024"
set "AEGIS_SAFETY__ALLOWLIST=127.0.0.1:5000,127.0.0.1:5001,127.0.0.1:5443"
set "AEGIS_SAFETY__CALLBACK_URL=http://127.0.0.1:8080"
rem repo scans: the only host a scan may clone from (a shallow, public https clone; everything else stays offline)
set "AEGIS_SAFETY__GIT_HOSTS=github.com:443"
set "AEGIS_API__ALLOWED_SOURCE_ROOTS=%SCAN%"
set "AEGIS_TOOL_DIRS=%ROOT%\.tools\semgrep\Scripts;%ROOT%\.tools\gitleaks;%ROOT%\.tools\trufflehog;%ROOT%\.tools\osv-scanner;%ROOT%\.tools\trivy;%ROOT%\.tools\syft;%ROOT%\.tools\nuclei;%ROOT%\.tools\katana"
set "AEGIS_OFFLINE_DB_DIR=%ROOT%\offline-db"
rem the targets here are local test apps: 50 requests/s (Nuclei takes about a minute); keep the default 5 for anything live
set "AEGIS_SCAN__RATE_LIMIT_RPS=50"
set "AEGIS_LOGGING__JSON=false"
start "AEGIS backend :8000" /D "%ROOT%" "%PY%" -m uvicorn aegis.main:app --host 127.0.0.1 --port 8000
if exist "%ROOT%\frontend\node_modules" start "AEGIS UI :5173" /D "%ROOT%\frontend" cmd /k npm run dev

set "FOLDER=%SCAN:\=/%"
echo.
echo Web UI: http://127.0.0.1:5173   (if it did not open: cd frontend, npm install, then run this again)
echo Or use Swagger at http://127.0.0.1:8000/docs and run POST /api/scans with
echo   runtime only:  {"url": "http://127.0.0.1:5000", "identities": "%FOLDER%/identities.yml"}
echo   everything:    {"url": "http://127.0.0.1:5000", "folder": "%FOLDER%", "identities": "%FOLDER%/identities.yml", "options": {"tls_targets": ["127.0.0.1:5443"]}}
echo   GitHub repo:   {"repo": "https://github.com/owner/name"}
echo   no OpenAPI + browser login:  {"url": "http://127.0.0.1:5001", "identities": "%FOLDER%/identities-browser.yml"}
echo.
endlocal
