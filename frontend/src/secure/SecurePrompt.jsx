import React from "react";
import { api } from "../api.js";
import { Badge } from "../components/ui.jsx";
import {
  EXAMPLES, LANGUAGES, MAX_PROMPT, bulletsAsText, coverageSummary, extensionFor, groupBullets, lockedText, onlineState,
  promptProblem, secureErrorText, sendNotice,
} from "./state.js";
import "./secure.css";

// Secure Prompt: a plain code request in, secure code out, with the reasons it is safe mapped to the
// OWASP Top 10. Gemini Online mode only. The code is not scanned or run, so the reasons are the
// model's claims and the page says so.
export default function SecurePrompt({ llm, onOpenModel }) {
  const [prompt, setPrompt] = React.useState("");
  const [language, setLanguage] = React.useState("python");
  const [busy, setBusy] = React.useState(false);
  const [error, setError] = React.useState(null);
  const [result, setResult] = React.useState(null);
  const [copied, setCopied] = React.useState(null);

  const online = onlineState(llm);
  const problem = prompt ? promptProblem(prompt) : null;
  const canSubmit = online.ready && !busy && !promptProblem(prompt);

  async function submit(e) {
    e.preventDefault();
    if (!canSubmit) return;
    setBusy(true);
    setError(null);
    setResult(null);
    try {
      setResult(await api.securePrompt(prompt.trim(), language));
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  }

  async function copy(what, text) {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(what);
      setTimeout(() => setCopied(null), 1500);
    } catch {
      setCopied(null);   // clipboard blocked: the text can still be selected by hand
    }
  }

  function download() {
    const url = URL.createObjectURL(new Blob([result.code], { type: "text/plain" }));
    const a = Object.assign(document.createElement("a"), { href: url, download: `secure-code.${extensionFor(result.language)}` });
    a.click();
    URL.revokeObjectURL(url);
  }

  const groups = result ? groupBullets(result.bullets) : [];
  const summary = result ? coverageSummary(result.coverage) : null;

  return (
    <div className="secure">
      <h1 className="secure-title">Secure prompt</h1>
      <p className="muted">Describe what to build. You get code written with security in mind, and plain reasons why it is safer, each mapped to the OWASP Top 10.</p>

      {!online.ready && (
        <div className="secure-locked" role="status">
          <strong>Online mode needed</strong>
          <p>{lockedText(online.reason)}</p>
          {online.reason !== "loading" && <button className="primary" onClick={onOpenModel}>Open AI model settings</button>}
        </div>
      )}

      <form onSubmit={submit} className="secure-form">
        <label htmlFor="sp-prompt" className="secure-label">What should it build?</label>
        <textarea id="sp-prompt" rows={4} maxLength={MAX_PROMPT} value={prompt} disabled={!online.ready}
                  placeholder="e.g. make a login API with email and password" onChange={(e) => setPrompt(e.target.value)} />
        <div className="row between small muted">
          <span className={problem ? "error-text" : ""}>{problem || `${prompt.length}/${MAX_PROMPT}`}</span>
          <span className="secure-examples">
            {EXAMPLES.map((ex) => (
              <button type="button" key={ex} className="link" disabled={!online.ready} onClick={() => setPrompt(ex)}>{ex.split(" ").slice(0, 3).join(" ")}…</button>
            ))}
          </span>
        </div>
        <div className="row gap secure-actions">
          <label className="secure-label inline" htmlFor="sp-lang">Language</label>
          <select id="sp-lang" value={language} disabled={!online.ready} onChange={(e) => setLanguage(e.target.value)}>
            {LANGUAGES.map((l) => <option key={l.id} value={l.id}>{l.label}</option>)}
          </select>
          <button type="submit" className="primary" disabled={!canSubmit}>{busy ? "Writing secure code…" : "Write secure code"}</button>
        </div>
        {online.ready && <p className="small muted">{sendNotice(llm)}</p>}
      </form>

      {error && <div className="error" role="alert">{secureErrorText(error)}</div>}

      {result && (
        <section className="secure-result" aria-live="polite">
          <div className="secure-disclaimer" role="note">
            <Badge kind="warn">not verified</Badge> {result.disclaimer}
          </div>

          <div className="secure-card">
            <div className="row between">
              <h2>Code <span className="muted small">· {result.language} · by {result.model}</span></h2>
              <span className="row gap">
                <button onClick={() => copy("code", result.code)}>{copied === "code" ? "Copied" : "Copy"}</button>
                <button onClick={download}>Download</button>
              </span>
            </div>
            <pre className="secure-code"><code>{result.code}</code></pre>
          </div>

          <div className="secure-card">
            <div className="row between">
              <h2>Why it is safer <span className="muted small">· OWASP Top 10 {result.owasp_version} · the model's claims</span></h2>
              <button onClick={() => copy("why", bulletsAsText(result))}>{copied === "why" ? "Copied" : "Copy"}</button>
            </div>
            {groups.map((g) => (
              <div key={g.id} className="secure-group">
                <div className="secure-group-head"><span className="secure-chip">{g.id}</span> {g.name}</div>
                <ul>
                  {g.items.map((b, i) => (
                    <li key={i}><strong>{b.action}</strong> <span className="muted">{b.why}</span></li>
                  ))}
                </ul>
              </div>
            ))}
          </div>

          <div className="secure-card">
            <h2>OWASP coverage <span className="muted small">· {summary.covered} covered · {summary.notApplicable} not applicable · {summary.notCovered} not covered</span></h2>
            <div className="secure-coverage" role="list">
              {result.coverage.map((c) => (
                <div key={c.id} role="listitem" className={`secure-cell secure-${c.status}`} title={`${c.id} ${c.name}: ${c.status.replace("_", " ")}`}>
                  <span className="secure-cell-id">{c.id}</span>
                  <span className="secure-cell-name">{c.name}</span>
                  <span className="secure-cell-status">{c.status.replace("_", " ")}</span>
                </div>
              ))}
            </div>
            {result.not_covered.length > 0 && (
              <div className="secure-limits">
                <strong>Not covered by this answer</strong>
                <ul>{result.not_covered.map((n, i) => <li key={i}>{n}</li>)}</ul>
              </div>
            )}
          </div>
        </section>
      )}
    </div>
  );
}
