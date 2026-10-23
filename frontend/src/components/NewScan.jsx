import React from "react";
import { api } from "../api.js";
import { onlineNotice, scanStart } from "../llm/state.js";
import LlmSettings from "./LlmSettings.jsx";
import { ErrorBox } from "./ui.jsx";

// The launcher (scripts\run_local.cmd) serves the demo from a copy in data\scan\demo-app.
const DEMO_FOLDER = "C:/Users/hp/Desktop/Hackbios(HGC)/data/scan/demo-app";
const PRESETS = {
  runtime: { label: "Running app (M1)", url: "http://127.0.0.1:5000", folder: "", repo: "", identities: `${DEMO_FOLDER}/identities.yml`, tls: "" },
  crawl: { label: "No OpenAPI + browser login (M1)", url: "http://127.0.0.1:5001", folder: "", repo: "", identities: `${DEMO_FOLDER}/identities-browser.yml`, tls: "" },
  https: { label: "Running app over HTTPS (M1 + TLS)", url: "https://127.0.0.1:5443", folder: "", repo: "", identities: `${DEMO_FOLDER}/identities.yml`, tls: "", insecure: true },
  code: { label: "Source folder (M2)", url: "", folder: DEMO_FOLDER, repo: "", identities: "", tls: "" },
  everything: { label: "Everything (M3 + TLS)", url: "http://127.0.0.1:5000", folder: DEMO_FOLDER, repo: "", identities: `${DEMO_FOLDER}/identities.yml`, tls: "127.0.0.1:5443" },
  repo: { label: "GitHub repo (M2)", url: "", folder: "", repo: "https://github.com/", identities: "", tls: "" },
};

export default function NewScan({ onStarted, llm, onLlmChanged }) {
  const [form, setForm] = React.useState(PRESETS.everything);
  const [error, setError] = React.useState(null);
  const [busy, setBusy] = React.useState(false);
  const [aiMode, setAiMode] = React.useState(null);   // what "AI for this scan" shows as selected

  const set = (key) => (e) => setForm({ ...form, [key]: e.target.value });
  const start = scanStart(aiMode, llm);

  async function submit(e) {
    e.preventDefault();
    if (!start.ok) return;
    setBusy(true);
    setError(null);
    const body = {};
    if (form.url.trim()) body.url = form.url.trim();
    if (form.folder.trim()) body.folder = form.folder.trim();
    if (form.repo.trim()) body.repo = form.repo.trim();
    if (form.identities.trim()) body.identities = form.identities.trim();
    const tls = form.tls.split(",").map((t) => t.trim()).filter(Boolean);
    const options = {};
    if (tls.length) options.tls_targets = tls;
    if (form.insecure) options.verify_tls = false;
    if (Object.keys(options).length) body.options = options;
    try {
      if (start.goOffline) onLlmChanged?.(await api.llmOffline());   // Offline is selected: switch before the scan pins a model
      const { scan_id } = await api.startScan(body);
      onStarted(scan_id);
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  }

  // what the scan will be and which checks it will run, from what is filled in
  const hasUrl = !!form.url.trim();
  const hasCode = !!(form.folder.trim() || form.repo.trim());
  const mode = hasUrl && hasCode ? "M3" : hasUrl ? "M1" : hasCode ? "M2" : "—";
  const modeName = { M1: "Running app", M2: "Source code", M3: "Both, correlated", "—": "Nothing to scan yet" }[mode];
  const run = [
    ["Runtime checks", "Nuclei · API fuzzing · BOLA · SSRF", hasUrl],
    ["Code checks", "Semgrep · Gitleaks · TruffleHog", hasCode],
    ["Dependencies", "OSV-Scanner · Trivy · Syft", hasCode],
    ["Correlation", "code finding ↔ live route", hasUrl && hasCode],
    ["Crypto / TLS", "CBOM · sslyze", hasCode || !!form.tls.trim()],
  ];
  const active = Object.entries(PRESETS).find(([, p]) => p === form)?.[0];

  return (
    <section>
      <div className="pg-head">
        <div>
          <div className="lbl">Scan &amp; Fix · 02</div>
          <h2>New scan</h2>
          <p>Point AEGIS at a running app, a source folder or a GitHub repo. Give it both and it matches code findings to live behaviour.</p>
        </div>
      </div>
      <div className="ns">
        <div>
          <form className="ns-form" id="scan-form" onSubmit={submit}>
            <div className="ns-group">
              <span className="lbl">Quick fill</span>
              <div className="presets">
                {Object.entries(PRESETS).map(([key, p]) => (
                  <button key={key} type="button" className={active === key ? "on" : ""} onClick={() => setForm(p)}>{p.label}</button>
                ))}
              </div>
            </div>
            <div className="ns-group">
              <span className="lbl">What to scan</span>
              <label>
                <span>Target URL <i className="ns-tag">M1</i> <span className="muted small">the running app, runtime checks</span></span>
                <input value={form.url} onChange={set("url")} placeholder="http://127.0.0.1:5000" />
              </label>
              <label>
                <span>Source folder <i className="ns-tag">M2</i> <span className="muted small">code + crypto checks; inside the allowed source roots</span></span>
                <input value={form.folder} onChange={set("folder")} placeholder="C:/path/to/project" />
              </label>
              <label>
                <span>Repository URL <i className="ns-tag">M2</i> <span className="muted small">instead of a folder: a public https repo on an allowed git host, cloned shallow; fixes are offered as patches</span></span>
                <input value={form.repo} onChange={set("repo")} placeholder="https://github.com/owner/name" />
              </label>
            </div>
            <div className="ns-group">
              <span className="lbl">Access and options</span>
              <label>
                <span>Identities file <span className="muted small">two test users A and B, required with a URL</span></span>
                <input value={form.identities} onChange={set("identities")} placeholder="C:/path/to/identities.yml" />
              </label>
              <label>
                <span>TLS endpoints <span className="muted small">host:port, comma-separated; each must be allowlisted</span></span>
                <input value={form.tls} onChange={set("tls")} placeholder="127.0.0.1:5443" />
              </label>
              <label className="inline">
                <input type="checkbox" checked={!!form.insecure} onChange={(e) => setForm({ ...form, insecure: e.target.checked })} />
                <span>Accept a self-signed certificate <span className="muted small">test targets only; the TLS check still reports the certificate</span></span>
              </label>
            </div>
            <ErrorBox error={error} />
          </form>

          {/* outside the scan form: its own forms (key, model) must not submit the scan */}
          <LlmSettings compact onChanged={onLlmChanged} onModeChange={setAiMode} />
        </div>

        <aside className="ns-side">
          <span className="lbl">This scan will be</span>
          <div className="mode">{mode}</div>
          <div className="mode-name">{modeName}</div>
          <ul>
            {run.map(([a, b, on]) => (
              <li key={a} className={on ? "" : "off"}><span>{a}</span><span>{b}</span></li>
            ))}
          </ul>
          {aiMode === "online" && onlineNotice(llm) && <p className="warning small" role="note">{onlineNotice(llm)}</p>}
          {start.reason && <p className="warning small" role="note">{start.reason}</p>}
          <button className="primary go" type="submit" form="scan-form" disabled={busy || mode === "—" || !start.ok}>
            {busy ? "Starting…" : aiMode === "offline" ? "Start scan (offline)" : aiMode === "online" ? "Start scan (online)" : "Start scan"}
          </button>
          <p className="note">One scan runs at a time. Scan only systems you own or have written permission to test; AEGIS enforces a target allow-list and a rate limit.</p>
        </aside>
      </div>
    </section>
  );
}
