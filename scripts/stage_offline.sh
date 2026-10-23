#!/usr/bin/env sh
# Stage the offline vulnerability databases ONCE, while online (Linux / Docker image build).
#   offline-db/osv    OSV-Scanner's local database
#   offline-db/trivy  Trivy's vulnerability database
#   offline-db/nuclei-templates + .tools/nuclei   the pinned Nuclei release and templates (checksum-verified)
#   .tools/katana + .tools/ms-playwright   the crawler and the browser for browser logins
# Scans never download anything: OSV runs with --offline, Trivy with --offline-scan.
# Usage: scripts/stage_offline.sh [project-folder-to-cover]   (default: demo-app)
set -eu
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DB="${AEGIS_OFFLINE_DB_DIR:-$ROOT/offline-db}"
TARGET="${1:-$ROOT/demo-app}"
mkdir -p "$DB/osv" "$DB/trivy"

echo "Staging the OSV database for the ecosystems in $TARGET ..."
OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY="$DB/osv" \
  osv-scanner scan source --offline-vulnerabilities --download-offline-databases --no-resolve -r "$TARGET" >/dev/null 2>&1 || true
echo "Staging the Trivy database ..."
trivy image --download-db-only --cache-dir "$DB/trivy" --quiet
echo "Staging Nuclei and its templates ..."
python3 "$ROOT/scripts/stage_nuclei.py" --db-dir "$DB"
echo "Staging Katana and Playwright (headless Chromium) ..."
python3 "$ROOT/scripts/stage_crawl_login.py"
echo "Done. Databases are in $DB"
