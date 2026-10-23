// Secret guard: finds things that look like live credentials in text a user is about to post.
// A pure function with no browser APIs, so the real backend can run the same rules on its side.

const RULES = [
  { type: "AWS access key", re: /\b(AKIA|ASIA)[0-9A-Z]{16}\b/ },
  { type: "AWS secret key", re: /\baws_?secret_?(access_?)?key\b\s*[:=]\s*["']?[A-Za-z0-9/+=]{40}\b/i },
  { type: "Stripe key", re: /\b(sk|rk)_live_[0-9A-Za-z]{16,}\b/ },
  { type: "GitHub token", re: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/ },
  { type: "Slack token", re: /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/ },
  { type: "Google API key", re: /\bAIza[0-9A-Za-z_-]{35}\b/ },
  { type: "private key", re: /-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----/ },
  { type: "JSON Web Token", re: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/ },
  { type: "hard-coded secret", re: /\b(?:password|passwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token)\b\s*[:=]\s*["'][^"'\s]{12,}["']/i },
];

// A short, masked preview: the first characters only, so the warning does not repeat the secret.
const preview = (match) => `${match.slice(0, 7)}…`;

/** @returns {{line: number, type: string, preview: string}[]} one entry per hit, line numbers start at 1 */
export function scanForSecrets(text) {
  const hits = [];
  String(text || "").split(/\r?\n/).forEach((line, i) => {
    for (const { type, re } of RULES) {
      const m = line.match(re);
      if (m) {
        hits.push({ line: i + 1, type, preview: preview(m[0]) });
        break; // one hit per line is enough to flag it
      }
    }
  });
  return hits;
}
