@echo off
rem Stage the offline vulnerability databases ONCE, while online (Windows, local setup).
rem   offline-db\osv    OSV-Scanner's local database (PyPI and any other ecosystem it finds)
rem   offline-db\trivy  Trivy's vulnerability database
rem   offline-db\nuclei-templates + .tools\nuclei   the pinned Nuclei release and templates (checksum-verified)
rem   .tools\katana + .tools\ms-playwright   the crawler and the browser for browser logins
rem Scans never download anything: OSV runs with --offline, Trivy with --offline-scan.
rem Re-run to refresh; each scan records the database dates it used.
setlocal
for %%I in ("%~dp0..") do set "ROOT=%%~fI"
set "DB=%ROOT%\offline-db"
if not exist "%DB%\osv" mkdir "%DB%\osv"
if not exist "%DB%\trivy" mkdir "%DB%\trivy"

echo Staging the OSV database (for the ecosystems in demo-app; scan your own project folder to add others)...
set "OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=%DB%\osv"
"%ROOT%\.tools\osv-scanner\osv-scanner.exe" scan source --offline-vulnerabilities --download-offline-databases --no-resolve -r "%ROOT%\demo-app" >nul 2>&1
echo Staging the Trivy database...
"%ROOT%\.tools\trivy\trivy.exe" image --download-db-only --cache-dir "%DB%\trivy" --quiet
echo Staging Nuclei and its templates...
"%ROOT%\.venv\Scripts\python.exe" "%ROOT%\scripts\stage_nuclei.py" --db-dir "%DB%"
echo Staging Katana and Playwright (headless Chromium)...
"%ROOT%\.venv\Scripts\python.exe" "%ROOT%\scripts\stage_crawl_login.py"
echo Done. Databases are in %DB%
endlocal
