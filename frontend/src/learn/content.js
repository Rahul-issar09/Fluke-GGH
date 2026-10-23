// Static learning content lives in public/learn/*.json. A file that is not there yet (or is not JSON,
// which is what a dev server answers for a missing file) is reported as null, never invented.

const loaded = new Map(); // one download per file per page view

export function loadContent(name) {
  if (!loaded.has(name)) {
    loaded.set(name, (async () => {
      try {
        const resp = await fetch(`/learn/${name}.json`);
        return resp.ok ? await resp.json() : null;
      } catch {
        return null;
      }
    })());
  }
  return loaded.get(name);
}

// quiz categories and cheat-sheet topics that exist in the data (others get no link)
export const QUIZ_CATEGORIES = ["A01", "A02", "A03", "A05", "A06", "A07", "A10", "XSS"];
export const CHEAT_TOPICS = ["A01", "A02", "A03", "A05", "A06", "A07", "A10", "XSS", "auth", "sessions", "crypto", "upload", "logging"];

const rows = (d) => (Array.isArray(d) ? d : Array.isArray(d?.items) ? d.items : null);

// OWASP Top 10 (2021) names, plus the extra quiz category
export const CATEGORY_NAMES = {
  A01: "Broken Access Control",
  A02: "Cryptographic Failures",
  A03: "Injection",
  A04: "Insecure Design",
  A05: "Security Misconfiguration",
  A06: "Vulnerable and Outdated Components",
  A07: "Identification and Authentication Failures",
  A08: "Software and Data Integrity Failures",
  A09: "Security Logging and Monitoring Failures",
  A10: "Server-Side Request Forgery",
  XSS: "Cross-Site Scripting",
};

export const TABS = [
  ["overview", "Overview"],
  ["pulse", "Threat Pulse"],
  ["crypto", "Crypto & PQC"],
  ["cases", "Case studies"],
  ["practice", "Practice"],
  ["cheatsheets", "Cheat sheets"],
  ["quizzes", "Quizzes"],
];

// one tile per tab on the Overview; `count` reads the real number out of the tab's JSON file
export const TILES = [
  { tab: "pulse", file: "feed", unit: "advisories", text: "Recent CVEs: exploited in the wild, severity and EPSS, checked against your scans.", count: (d) => rows(d)?.length },
  { tab: "crypto", file: "crypto", unit: "algorithms", text: "Broken, weak and quantum-vulnerable algorithms, and what replaces them.", count: (d) => rows(d)?.length },
  { tab: "cases", file: "cases", unit: "case studies", text: "Real breaches, what went wrong, and whether AEGIS would catch it.", count: (d) => rows(d)?.length },
  { tab: "practice", file: "challenges", unit: "challenges", text: "Fix vulnerable code in the browser and check your answer.", count: (d) => rows(d)?.length },
  { tab: "cheatsheets", file: "cheatsheets", unit: "cheat sheets", text: "Don't / Do code pairs per language and weakness.", count: (d) => rows(d)?.length },
  { tab: "quizzes", file: "quizzes", unit: "quizzes", text: "Short quizzes per weakness category, with explanations.", count: (d) => (rows(d) ? new Set(rows(d).map((q) => q.category)).size : undefined) },
];

export async function loadTileCounts() {
  const out = {};
  await Promise.all(
    TILES.map(async (t) => {
      const n = t.count(await loadContent(t.file));
      out[t.tab] = typeof n === "number" ? n : null;
    }),
  );
  return out;
}
