// Thin client for the AEGIS REST API. Every call goes to /api/... (proxied to the backend by Vite).
// If the backend was started with AEGIS_API__AUTH_TOKEN, paste the token in the header bar.

const TOKEN_KEY = "aegis.token";

export function getToken() {
  try {
    return localStorage.getItem(TOKEN_KEY) || "";
  } catch {
    return "";
  }
}

export function setToken(token) {
  try {
    if (token) localStorage.setItem(TOKEN_KEY, token);
    else localStorage.removeItem(TOKEN_KEY);
  } catch {
    /* private mode: the token just isn't remembered */
  }
}

export class ApiError extends Error {
  constructor(status, body) {
    super(body?.detail || body?.error || `HTTP ${status}`);
    this.status = status;
    this.body = body;
  }
}

async function request(method, path, body, extraHeaders = {}) {
  const headers = { Accept: "application/json", ...extraHeaders };
  const token = getToken();
  if (token) headers.Authorization = `Bearer ${token}`;
  if (body !== undefined) headers["Content-Type"] = "application/json";
  const resp = await fetch(path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
  const text = await resp.text();
  let data = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = { detail: text };
  }
  if (!resp.ok) throw new ApiError(resp.status, data);
  return data;
}

const q = (params) => {
  const s = new URLSearchParams();
  Object.entries(params).forEach(([k, v]) => {
    if (v !== undefined && v !== null && v !== "") s.set(k, v);
  });
  const str = s.toString();
  return str ? `?${str}` : "";
};

export const api = {
  health: () => request("GET", "/api/health"),
  scans: (limit = 50) => request("GET", `/api/scans${q({ limit })}`),
  startScan: (body) => request("POST", "/api/scans", body),
  scan: (id) => request("GET", `/api/scans/${id}`),
  cancel: (id) => request("POST", `/api/scans/${id}/cancel`),
  gate: (id, threshold) => request("GET", `/api/scans/${id}/gate${q({ severity_threshold: threshold })}`),
  audit: (id) => request("GET", `/api/scans/${id}/audit`),
  findings: (scanId, filters = {}) => request("GET", `/api/findings${q({ scan_id: scanId, ...filters })}`),
  finding: (id) => request("GET", `/api/findings/${id}`),
  evidence: (id) => request("GET", `/api/evidence/${id}`),
  graph: (scanId) => request("GET", `/api/graph${q({ scan_id: scanId })}`),
  cbom: (scanId) => request("GET", `/api/cbom${q({ scan_id: scanId })}`),
  startFix: (findingId) => request("POST", `/api/findings/${findingId}/fix`),
  fix: (fixId) => request("GET", `/api/fixes/${fixId}`),
  commitFix: (fixId, mode) => request("POST", `/api/fixes/${fixId}/commit`, { mode }),
  ask: (scanId, question) => request("POST", "/api/ask", { scan_id: scanId, question }),
  // Secure Prompt (Gemini Online mode only): only the request text is sent.
  securePrompt: (prompt, language) => request("POST", "/api/secure-prompt", { prompt, language }),

  // The AI model (LLM_PROVIDER_PHASES LP8). A Gemini key travels only in a POST body — never a URL —
  // and is never stored here: the server keeps it in memory for this run. Changes send the intent
  // header the server requires (a page on another site cannot send it).
  llmConfig: () => request("GET", "/api/llm/config"),
  llmProviders: () => request("GET", "/api/llm/providers"),
  llmModels: (provider) => request("GET", `/api/llm/models${q({ provider })}`),
  llmDiscover: (apiKey) => request("POST", "/api/llm/discover", { provider: "gemini", api_key: apiKey || undefined }, LLM_INTENT),
  llmValidate: (provider, model, apiKey) =>
    request("POST", "/api/llm/validate", { provider, model, api_key: apiKey || undefined }, LLM_INTENT),
  llmActivate: (body) => request("PUT", "/api/llm/config", body, LLM_INTENT),
  llmOffline: (model) => request("PUT", "/api/llm/config", { provider: "ollama", model: model || undefined }, LLM_INTENT),
  llmForgetKey: () => request("DELETE", "/api/llm/credentials/gemini", undefined, LLM_INTENT),
  llmTest: () => request("POST", "/api/llm/test", undefined, LLM_INTENT),
};

const LLM_INTENT = { "X-AEGIS-Intent": "llm-config", "X-AEGIS-Client": "ui" };

export const reportUrl = (scanId, format = "html") => `/api/reports${q({ scan_id: scanId, format })}`;
export const eventsUrl = (scanId) => `/api/scans/${scanId}/events`;
