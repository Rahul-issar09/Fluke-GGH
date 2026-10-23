// Threat Pulse feed sync. Run it by hand while online:  npm run sync:feeds
// Writes public/learn/feed.json (the page itself never calls the internet).
//   KEV   CISA Known Exploited Vulnerabilities, everything added in the last 90 days
//   NVD   CVEs published in the last 30 days with CVSS v3 >= 7.0 (HIGH + CRITICAL), no-key rate limit respected
//   EPSS  FIRST exploit-prediction score for every collected CVE (the previous score is kept as epss_prev)
//   OSV   the newest modified advisories for npm, PyPI, Go and Maven (from OSV's per-ecosystem index)
// A source that fails keeps its items from the previous file; the script never exits with an error for that.

import { mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const OUT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "public", "learn", "feed.json");
const DAY = 86400000;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const log = (...a) => console.log("[sync]", ...a);
const warn = (...a) => console.warn("[sync] WARNING:", ...a);

async function get(url, { json = true, headers = {}, retries = 2 } = {}) {
  for (let attempt = 0; ; attempt++) {
    try {
      const resp = await fetch(url, { headers: { "User-Agent": "aegis-learn-sync", ...headers }, signal: AbortSignal.timeout(90000) });
      if (!resp.ok && resp.status !== 206) throw new Error(`HTTP ${resp.status}`);
      return json ? await resp.json() : await resp.text();
    } catch (err) {
      if (attempt >= retries) throw err;
      await sleep(10000);
    }
  }
}

// CWE → OWASP Top 10 (2021) category. A static table: CWEs that are not in it get owasp: null.
const OWASP_CWES = {
  A01: [22, 23, 35, 59, 200, 201, 219, 264, 275, 276, 284, 285, 352, 359, 377, 402, 425, 441, 497, 538, 540, 548, 552, 566, 601, 639, 651, 668, 706, 862, 863, 913, 922, 1275],
  A02: [259, 261, 296, 310, 319, 321, 322, 323, 324, 325, 326, 327, 328, 329, 330, 331, 335, 336, 337, 338, 340, 347, 523, 720, 757, 759, 760, 780, 818, 916],
  A03: [20, 74, 75, 77, 78, 79, 80, 83, 87, 88, 89, 90, 91, 93, 94, 95, 96, 97, 98, 99, 100, 113, 116, 138, 184, 470, 471, 564, 610, 643, 644, 652, 917],
  A04: [73, 183, 209, 213, 235, 256, 257, 266, 269, 280, 311, 312, 313, 316, 419, 430, 434, 444, 451, 472, 501, 522, 525, 539, 579, 598, 602, 642, 646, 650, 653, 656, 657, 799, 807, 840, 841, 927, 1021, 1173],
  A05: [2, 11, 13, 15, 16, 260, 315, 520, 526, 537, 541, 547, 611, 614, 756, 776, 942, 1004, 1032, 1174],
  A06: [937, 1035, 1104],
  A07: [255, 287, 288, 290, 294, 295, 297, 300, 302, 304, 306, 307, 346, 384, 521, 613, 620, 640, 798, 940, 1216],
  A08: [345, 353, 426, 494, 502, 565, 784, 829, 830, 915],
  A09: [117, 223, 532, 778],
  A10: [918],
};
const CWE_TO_OWASP = new Map(Object.entries(OWASP_CWES).flatMap(([cat, cwes]) => cwes.map((n) => [n, cat])));
const owaspOf = (cwe) => (cwe && CWE_TO_OWASP.get(Number(String(cwe).replace(/\D/g, "")))) || null;
const cweOf = (list) => (list || []).find((c) => /^CWE-\d+$/.test(c)) || null;
const clip = (text, n = 700) => (text && text.length > n ? text.slice(0, n - 1).trimEnd() + "…" : text || "");

let previous = { items: [] };
try {
  previous = JSON.parse(readFileSync(OUT, "utf8"));
} catch {
  /* first run */
}
const prevBySource = (source) => previous.items.filter((i) => i.source === source);
const prevEpss = new Map(previous.items.filter((i) => typeof i.epss === "number").map((i) => [i.id, i.epss]));

const blank = { description: "", exploited: false, cvss: null, severity: null, epss: null, epss_prev: null, cwe: null, owasp: null, vendor: null, product: null, ecosystem: null, package: null, date_added: null, kev_due_date: null, refs: [] };

async function fromKev() {
  const feed = await get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json");
  const since = Date.now() - 90 * DAY;
  return feed.vulnerabilities
    .filter((v) => Date.parse(v.dateAdded) >= since)
    .map((v) => {
      const cwe = cweOf(v.cwes);
      return { ...blank, id: v.cveID, title: v.vulnerabilityName, description: clip(v.shortDescription), source: "KEV", exploited: true, cwe, owasp: owaspOf(cwe), vendor: v.vendorProject, product: v.product, date_added: v.dateAdded, kev_due_date: v.dueDate, refs: [`https://nvd.nist.gov/vuln/detail/${v.cveID}`] };
    });
}

async function fromNvd() {
  const end = new Date();
  const start = new Date(Date.now() - 30 * DAY);
  const items = [];
  for (const severity of ["CRITICAL", "HIGH"]) {
    for (let index = 0; ; ) {
      const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=${start.toISOString().slice(0, -1)}&pubEndDate=${end.toISOString().slice(0, -1)}&cvssV3Severity=${severity}&resultsPerPage=2000&startIndex=${index}`;
      const page = await get(url, { retries: 3 });
      for (const { cve } of page.vulnerabilities) {
        const m = cve.metrics?.cvssMetricV31?.[0] || cve.metrics?.cvssMetricV30?.[0];
        if (!m || m.cvssData.baseScore < 7) continue;
        const cwe = cweOf((cve.weaknesses || []).flatMap((w) => w.description.map((d) => d.value)));
        const cpe = cve.configurations?.[0]?.nodes?.[0]?.cpeMatch?.[0]?.criteria?.split(":");
        const text = cve.descriptions.find((d) => d.lang === "en")?.value || "";
        items.push({ ...blank, id: cve.id, title: clip(text.split(/(?<=\.)\s/)[0], 140), description: clip(text), source: "NVD", cvss: m.cvssData.baseScore, severity: m.cvssData.baseSeverity, cwe, owasp: owaspOf(cwe), vendor: cpe?.[3] || null, product: cpe?.[4] || null, date_added: cve.published.slice(0, 10), refs: (cve.references || []).slice(0, 5).map((r) => r.url) });
      }
      index += page.resultsPerPage;
      if (index >= page.totalResults) break;
      await sleep(6000); // NVD: no API key, one request per 6 seconds
    }
    await sleep(6000);
  }
  return items;
}

const OSV_ECOSYSTEMS = ["npm", "PyPI", "Go", "Maven"];
async function fromOsv(perEcosystem = 25) {
  const items = [];
  for (const eco of OSV_ECOSYSTEMS) {
    const csv = await get(`https://osv-vulnerabilities.storage.googleapis.com/${eco}/modified_id.csv`, { json: false, headers: { Range: "bytes=0-6000" } });
    const ids = csv.split("\n").slice(0, -1).filter(Boolean).slice(0, perEcosystem).map((line) => line.split(",")[1]);
    for (const osvId of ids) {
      const v = await get(`https://api.osv.dev/v1/vulns/${encodeURIComponent(osvId)}`);
      const cve = (v.aliases || []).find((a) => a.startsWith("CVE-"));
      const cwe = cweOf(v.database_specific?.cwe_ids);
      const sev = v.database_specific?.severity;
      const details = (v.details || "").replace(/\n?-{3}\n_-=[^\n]*=-_\n+/g, "\n").trim(); // OSV malware reports start with a boilerplate header
      items.push({ ...blank, id: cve || v.id, title: clip(v.summary || v.id, 140), description: clip(details || v.summary), source: "OSV", severity: sev === "MODERATE" ? "MEDIUM" : sev || null, cwe, owasp: owaspOf(cwe) || "A06", ecosystem: eco, package: v.affected?.[0]?.package?.name || null, date_added: (v.published || v.modified || "").slice(0, 10), refs: (v.references || []).slice(0, 5).map((r) => r.url) });
    }
  }
  return items;
}

async function epssFor(ids) {
  const scores = new Map();
  const cves = [...new Set(ids.filter((i) => i.startsWith("CVE-")))];
  for (let i = 0; i < cves.length; i += 100) {
    const res = await get(`https://api.first.org/data/v1/epss?cve=${cves.slice(i, i + 100).join(",")}`);
    for (const row of res.data) scores.set(row.cve, Number(row.epss));
  }
  return scores;
}

const sources = { KEV: fromKev, NVD: fromNvd, OSV: fromOsv };
let items = [];
for (const [name, run] of Object.entries(sources)) {
  try {
    const got = await run();
    log(`${name}: ${got.length} items`);
    items.push(...got);
  } catch (err) {
    warn(`${name} failed (${err.message}); keeping its ${prevBySource(name).length} previous items`);
    items.push(...prevBySource(name));
  }
}

// one entry per id: a KEV entry (exploited) wins over the same CVE from NVD or OSV
const rank = { KEV: 0, NVD: 1, OSV: 2 };
const byId = new Map();
for (const item of items.sort((a, b) => rank[a.source] - rank[b.source])) {
  const have = byId.get(item.id);
  if (!have) byId.set(item.id, item);
  else for (const k of ["cvss", "severity", "cwe", "owasp"]) have[k] ??= item[k];
}
items = [...byId.values()];

try {
  const scores = await epssFor(items.map((i) => i.id));
  log(`EPSS: ${scores.size} scores`);
  for (const item of items) {
    if (scores.has(item.id)) {
      item.epss = scores.get(item.id);
      item.epss_prev = prevEpss.get(item.id) ?? null;
    }
  }
} catch (err) {
  warn(`EPSS failed (${err.message}); keeping the previous scores`);
  for (const item of items) {
    item.epss = previous.items.find((p) => p.id === item.id)?.epss ?? null;
    item.epss_prev = prevEpss.get(item.id) ?? null;
  }
}

items.sort((a, b) => (b.date_added || "").localeCompare(a.date_added || "") || b.exploited - a.exploited);
mkdirSync(path.dirname(OUT), { recursive: true });
writeFileSync(OUT + ".tmp", JSON.stringify({ synced_at: new Date().toISOString(), items }, null, 0));
renameSync(OUT + ".tmp", OUT);
log(`wrote ${items.length} items → ${OUT}`);
