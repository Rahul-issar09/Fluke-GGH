// Secure Prompt rules as plain functions, so they can be tested with `node --test` without a browser:
//   * the feature works only in Gemini Online mode, with this run's key entered;
//   * only the request text goes to Gemini (the page says so);
//   * the code is never scanned or run, so the page never calls it "verified" or "secure".

export const MAX_PROMPT = 2000;
export const MIN_PROMPT = 3;

export const LANGUAGES = [
  { id: "python", label: "Python" },
  { id: "flask", label: "Python · Flask" },
  { id: "fastapi", label: "Python · FastAPI" },
  { id: "django", label: "Python · Django" },
  { id: "node", label: "JavaScript · Node/Express" },
  { id: "java", label: "Java · Spring" },
  { id: "go", label: "Go" },
];

export const EXAMPLES = [
  "make a login API with email and password",
  "a file upload endpoint for profile pictures",
  "a search endpoint that reads from a SQL database",
  "a password reset flow sent by email",
];

const EXTENSIONS = { python: "py", flask: "py", fastapi: "py", django: "py", node: "js", java: "java", go: "go" };
export const extensionFor = (language) => EXTENSIONS[String(language || "").toLowerCase()] || "txt";

// Is Gemini Online mode usable right now? `cfg` is GET /api/llm/config.
export function onlineState(cfg) {
  if (!cfg) return { ready: false, reason: "loading" };
  if (cfg.awaiting_key) return { ready: false, reason: "key" };
  if (cfg.location === "cloud" && cfg.provider === "gemini") return { ready: true, reason: null };
  return { ready: false, reason: "offline" };
}

export function lockedText(reason) {
  if (reason === "loading") return "Checking the AI model…";
  if (reason === "key") return "Online mode is chosen, but this run's Gemini key has not been entered yet. Enter it on the AI model page.";
  return "Secure Prompt needs Gemini Online mode. AEGIS is running offline, so nothing is sent anywhere. Switch on the AI model page.";
}

export function promptProblem(text) {
  const t = (text || "").trim();
  if (t.length < MIN_PROMPT) return `Describe what to build (at least ${MIN_PROMPT} characters).`;
  if ((text || "").length > MAX_PROMPT) return `Keep the request under ${MAX_PROMPT} characters.`;
  return null;
}

export function sendNotice(cfg) {
  const model = cfg?.model ? `Gemini ${cfg.model}` : "Google Gemini";
  return `Only the text of your request is sent to ${model} (online). No code, scan results or files are sent.`;
}

// Bullets grouped by OWASP id, in OWASP order.
export function groupBullets(bullets) {
  const groups = new Map();
  for (const b of bullets || []) {
    if (!groups.has(b.owasp)) groups.set(b.owasp, { id: b.owasp, name: b.category, items: [] });
    groups.get(b.owasp).items.push(b);
  }
  return [...groups.values()].sort((a, b) => a.id.localeCompare(b.id));
}

export function coverageSummary(coverage) {
  const count = (status) => (coverage || []).filter((c) => c.status === status).length;
  return { covered: count("covered"), notApplicable: count("not_applicable"), notCovered: count("not_covered") };
}

const MESSAGES = {
  online_required: "Secure Prompt needs Gemini Online mode. Switch on the AI model page.",
  generation_failed: "Gemini did not return usable secure code. Try again, or describe the request differently.",
  provider_rate_limited: "Gemini is rate-limiting this key. Wait a moment and try again.",
  provider_quota_exhausted: "The Gemini quota for this key is used up. Try again later.",
  provider_unreachable: "Gemini cannot be reached (network or DNS).",
  invalid_api_key: "Gemini refused this API key. Enter it again on the AI model page.",
  revoked: "Online mode was switched off while the request ran. Switch it on again to retry.",
};

export function secureErrorText(error) {
  if (!error) return null;
  const code = error.body?.error;
  if (MESSAGES[code]) return MESSAGES[code];
  if (error.status === 422) return "The request was refused: check the text and language.";
  return error.body?.detail || error.message || "Something went wrong.";
}

// Plain text of a result, for copy and download of the reasons.
export function bulletsAsText(result) {
  return groupBullets(result.bullets)
    .map((g) => `${g.id} ${g.name}\n${g.items.map((i) => `  - ${i.action} (${i.why})`).join("\n")}`)
    .join("\n\n");
}
