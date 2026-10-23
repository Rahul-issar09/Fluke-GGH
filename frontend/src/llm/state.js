// The AI-model settings flow as plain functions (LLM_PROVIDER_PHASES LP8), so the rules that matter
// can be tested with `node --test` without a browser:
//   * the Gemini key lives in this state only while it is needed: it is dropped the moment the
//     server has validated it (the server then holds it for this run, in memory), on every reset and
//     when switching to Offline. It is never put in browser storage, a URL, the console or an error;
//   * the key is asked for every run (decision Q-4): after an AEGIS restart the config says
//     `awaiting_key`, and re-entering the same key needs no new consent (`consent_on_record`).

export const initialSettings = {
  mode: "offline",          // what the user is setting up: "offline" | "online"
  apiKey: "",               // the candidate key — only until the server has validated it
  models: [],               // Gemini models the key can use (from the server, never hard-coded)
  model: "",
  validation: null,         // { id, consentOnRecord, disclosure, warnings } after a successful validate
  busy: null,               // "loading" | "validating" | "activating" | null
  error: null,
};

export function settingsReducer(state, action) {
  switch (action.type) {
    case "mode":
      return { ...initialSettings, mode: action.mode };                  // a fresh start drops the key
    case "key":
      return { ...state, apiKey: action.value, models: [], model: "", validation: null, error: null };
    case "busy":
      return { ...state, busy: action.what, error: null };
    case "models": {                                                     // keep the model chosen before, if offered
      const preferred = action.models.find((m) => m.id === action.prefer);
      return { ...state, busy: null, models: action.models, model: (preferred || action.models[0])?.id || "" };
    }
    case "model":
      return { ...state, model: action.model, validation: null };
    case "validated":                                                    // the server holds the key now
      return { ...state, busy: null, apiKey: "", validation: action.validation };
    case "error":
      return { ...state, busy: null, error: action.error };
    case "done":
    case "reset":
      return { ...initialSettings, mode: state.mode };
    default:
      return state;
  }
}

// What may be shown, logged or kept: everything but the key.
export function visibleSettings(state) {
  const { apiKey, ...rest } = state;
  return { ...rest, keyEntered: Boolean(apiKey) };
}

export const KEY_PATTERN = /^[A-Za-z0-9_\-.]{20,200}$/;
export const keyLooksValid = (key) => KEY_PATTERN.test((key || "").trim());

// Chat models only: an embedding model cannot answer.
export const chatModels = (models) => (models || []).filter((m) => !m.capabilities?.length || m.capabilities.includes("generate"));

export function badgeFor(cfg) {
  if (!cfg) return { text: "model …", kind: "muted", title: "" };
  if (cfg.awaiting_key) {
    return { text: "online · key needed", kind: "warn",
             title: "Online mode is chosen, but the Gemini key was not entered since AEGIS started. Until then AEGIS runs offline." };
  }
  if (cfg.location === "cloud") {
    return { text: `${cfg.model} · online`, kind: "warn",
             title: "Findings are sent to Google Gemini for explanations and answers." };
  }
  return { text: `${cfg.model} · offline`, kind: "ok", title: "Everything stays on this machine." };
}

// New scan: may the scan start with the mode selected there, and must AEGIS go offline first?
// A scan never starts on a mode other than the one shown as selected.
export function scanStart(mode, cfg) {
  if (!cfg || !mode) return { ok: false, goOffline: false, reason: null };   // still loading
  if (mode === "offline") return { ok: true, goOffline: cfg.location === "cloud" || Boolean(cfg.awaiting_key), reason: null };
  if (cfg.location === "cloud") return { ok: true, goOffline: false, reason: null };
  return { ok: false, goOffline: false,
           reason: "Online mode is not ready: enter this run's Gemini key, load the models and choose \"Validate and switch\" above, or choose Offline." };
}

// Under the Ask box: where a question goes, true even when the model is down and the answer is
// built from the findings without it (the API's answer does not say which happened).
export function askRoute(cfg) {
  if (!cfg) return null;
  const where = cfg.location === "cloud" ? `Questions are sent to Gemini ${cfg.model} (online).`
                                         : `Questions are answered on this machine by ${cfg.model} (offline).`;
  return `${where} If the model is unavailable, the answer is put together from the findings without AI.`;
}

export function onlineNotice(cfg) {
  if (!cfg || cfg.location !== "cloud") return null;
  const code = cfg.allow_source_code ? ", and short excerpts of source code for fix drafts" : "";
  return `AI processing: Gemini ${cfg.model} (online). Finding descriptions, file paths, routes and evidence summaries${code} are sent to Google.`;
}

const MESSAGES = {
  invalid_api_key: "Gemini refused this API key. Check it in Google AI Studio and enter it again.",
  model_not_found: "This key cannot use that model. Load the models again and pick another.",
  permission_denied: "This key is not allowed to use the Gemini API or that model.",
  billing_required: "Gemini needs billing (or prepaid credit) for this key.",
  provider_rate_limited: "Gemini is rate-limiting this key. Wait a moment and try again.",
  provider_quota_exhausted: "The daily Gemini quota for this key is used up. Try again tomorrow or use Offline mode.",
  provider_unreachable: "Gemini cannot be reached (network or DNS). Offline mode still works.",
  consent_required: "Online mode needs your agreement to the privacy notice.",
  validation_expired: "The validation expired (they last 10 minutes and can be used once). Enter the key again.",
  cloud_disabled: "Online mode is disabled on this install by the administrator (AEGIS_LLM__ALLOW_CLOUD=false).",
  managed_by_environment: "This setting is fixed by an environment variable on the server.",
  config_api_forbidden: "The model can only be changed from the machine AEGIS runs on (or with the API token).",
  provider_unavailable: "The Gemini support is not installed on the server (pip install -e \".[gemini]\").",
};

export function errorText(error) {
  if (!error) return null;
  const code = error.body?.error;
  const detail = error.body?.detail;
  if (MESSAGES[code]) return detail && code !== "consent_required" ? `${MESSAGES[code]} (${detail})` : MESSAGES[code];
  if (error.status === 422 && code === "invalid request") return `The request was refused: ${detail || "check the fields"}.`;
  return detail || error.message || "Something went wrong.";
}

// LP11: a key must not cross the network unencrypted. Fine over https, or when this page comes from
// this machine (the Vite proxy / a local API); otherwise the key field is disabled with this reason.
const LOOPBACK = new Set(["localhost", "127.0.0.1", "[::1]", "::1"]);
export function keyTransportProblem(loc) {
  if (!loc || loc.protocol === "https:" || LOOPBACK.has(loc.hostname)) return null;
  return `This page comes from ${loc.hostname} over plain HTTP, so a key typed here would cross the network ` +
    "unencrypted. Open AEGIS over https://, or on the machine it runs on.";
}

export function consentBody(disclosure, allowSourceCode) {
  return { disclosure_version: disclosure.version, accepted: true, allow_source_code: Boolean(allowSourceCode) };
}
