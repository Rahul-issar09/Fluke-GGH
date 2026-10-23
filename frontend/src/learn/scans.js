// What the Learn page reads from your own scans, through the same API calls the console uses.
// Every call can fail (backend stopped): callers show a note instead of breaking the page.
// Results are cached for a minute so switching tabs does not hit the backend again.
import { api } from "../api.js";

const FINISHED = new Set(["completed", "awaiting_approval"]);
const TTL_MS = 60_000;
const cache = new Map();

function cached(key, loader) {
  const hit = cache.get(key);
  if (hit && Date.now() - hit.at < TTL_MS) return hit.promise;
  const promise = loader().catch((error) => {
    cache.delete(key); // do not keep a failure: the next visit tries again
    throw error;
  });
  cache.set(key, { at: Date.now(), promise });
  return promise;
}

/** Finished scans, newest first. */
export const finishedScans = (n = 20) =>
  cached(`scans:${n}`, async () => (await api.scans(100)).filter((s) => FINISHED.has(s.status)).slice(0, n));

/** The newest completed scan and its findings: { scan, findings } (scan is null when there is none). */
export const loadLatestScan = () =>
  cached("latest", async () => {
    const scans = await api.scans(100);
    const scan = scans.find((s) => s.status === "completed");
    if (!scan) return { scan: null, findings: [] };
    return { scan, findings: await api.findings(scan.id) };
  });

/** OWASP categories seen in recent finished scans: Map(category -> [scan ids]). */
export const scanCategories = (n = 10) =>
  cached(`categories:${n}`, async () => {
    const out = new Map();
    for (const scan of await finishedScans(n)) {
      for (const f of await api.findings(scan.id)) {
        if (!f.owasp || f.state === "resolved") continue;
        if (!out.has(f.owasp)) out.set(f.owasp, []);
        if (!out.get(f.owasp).includes(scan.id)) out.get(f.owasp).push(scan.id);
      }
    }
    return out;
  });

/**
 * Vulnerable dependencies found in recent scans, from each finding's dependency evidence:
 * [{ scanId, findingId, package, version, ecosystem, advisories: ["CVE-..."] }]
 */
export const dependencyAdvisories = (n = 20) =>
  cached(`deps:${n}`, async () => {
    const out = [];
    for (const scan of await finishedScans(n)) {
      const deps = (await api.findings(scan.id)).filter((f) => f.type === "vulnerable_dependency");
      for (const f of deps) {
        const detail = await api.finding(f.id);
        for (const id of detail.evidence_ids || []) {
          const ev = await api.evidence(id);
          if (ev.kind !== "dependency" || !ev.payload) continue;
          const p = ev.payload;
          out.push({ scanId: scan.id, findingId: f.id, package: p.package, version: p.version, ecosystem: p.ecosystem, advisories: p.advisories || [] });
        }
      }
    }
    return out;
  });

/** The latest finished scan that has a cryptography bill of materials: { scan, cbom } or null. */
export const latestCbom = () =>
  cached("cbom", async () => {
    for (const scan of await finishedScans(10)) {
      if (scan.mode === "runtime") continue; // only code and correlated scans have a crypto stage
      try {
        return { scan, cbom: await api.cbom(scan.id) };
      } catch (error) {
        if (error.status !== 404) throw error; // 404: this scan has no CBOM, try an older one
      }
    }
    return null;
  });

/** A short message for a failed backend call (a stopped backend shows up as a proxy error). */
export const backendHint = (error) =>
  `Couldn't reach your scans${error?.status ? ` (HTTP ${error.status})` : ""} - is the backend running?`;
