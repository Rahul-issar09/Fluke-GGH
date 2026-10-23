import React from "react";
import { api } from "../api.js";
import { Badge, ErrorBox, Loading, useLoad } from "./ui.jsx";

export default function Health() {
  const { data, error, loading, reload } = useLoad(() => api.health(), []);
  const tools = data ? Object.entries(data.tools) : [];
  const found = tools.filter(([, t]) => t.found).length;
  return (
    <section>
      <div className="pg-head">
        <div>
          <div className="lbl">Scan &amp; Fix · 03</div>
          <h2>Health</h2>
          <p>Is everything a scan needs up: the backend, the database, the local model and the scanners.</p>
        </div>
        <div className="pg-actions"><button onClick={reload}>Refresh</button></div>
      </div>
      <ErrorBox error={error} />
      {loading && !data && <Loading />}
      {data && (
        <>
          <div className="hl">
            <div>
              <div className="card-label">Backend</div>
              <b><span className={`dot ${data.status === "ok" ? "dot-ok" : "dot-bad"}`} />{data.status}</b>
              <span className="muted small">database {data.database ? "answering" : "down"}</span>
            </div>
            <div>
              <div className="card-label">Local model</div>
              <b><span className={`dot ${data.ollama.reachable && data.ollama.model_present ? "dot-ok" : "dot-bad"}`} />{data.ollama.reachable ? (data.ollama.model_present ? "ready" : "model missing") : "unreachable"}</b>
              <span className="muted small mono">{data.ollama.model} · {data.ollama.url}</span>
              {!data.ollama.model_present && data.ollama.models?.length > 0 && (
                <div className="muted small">available: {data.ollama.models.join(", ")}</div>
              )}
            </div>
            <div>
              <div className="card-label">Scanners</div>
              <b><span className={`dot ${found === tools.length ? "dot-ok" : found === 0 ? "dot-bad" : "dot-warn"}`} />{found} of {tools.length}</b>
              <span className="muted small">found on this machine</span>
            </div>
          </div>

          {(data.llm || data.embeddings) && (
            <>
              <h3>AI model</h3>
              <div className="tools">
                {data.llm && (
                  <div className="tool">
                    <b><span className={`dot ${data.llm.ready ? "dot-ok" : data.llm.ready === false ? "dot-bad" : "dot-warn"}`} />
                      AI model ({data.llm.location === "cloud" ? "online" : "offline"})</b>
                    <span className="mono">{data.llm.provider} · {data.llm.model}</span>
                    {data.llm.reason && <span className="muted small">{data.llm.reason}</span>}
                  </div>
                )}
                {data.embeddings && (
                  <div className="tool">
                    <b><span className={`dot ${data.embeddings.model_present ? "dot-ok" : "dot-warn"}`} />Embeddings (always local)</b>
                    <span className="mono">{data.embeddings.model} · {data.embeddings.dim}</span>
                    {data.embeddings.index?.compatible === false && <Badge kind="bad">index built by another model</Badge>}
                    {data.embeddings.index?.reason && <span className="muted small">{data.embeddings.index.reason}</span>}
                  </div>
                )}
              </div>
            </>
          )}

          <h3>Scanners</h3>
          <div className="tools">
            {tools.map(([name, t]) => (
              <div key={name} className={t.found ? "tool" : "tool missing"}>
                <b><span className={`dot ${t.found ? "dot-ok" : "dot-bad"}`} />{name}</b>
                <span className="mono">{t.found ? t.path || "found" : "missing"}</span>
              </div>
            ))}
          </div>

          <h3>Offline vulnerability databases</h3>
          <table>
            <thead>
              <tr><th>Database</th><th>Snapshot date</th></tr>
            </thead>
            <tbody>
              {Object.entries(data.db_snapshot_dates).map(([db, date]) => (
                <tr key={db}><td>{db}</td><td className="mono">{date || <span className="muted">not staged</span>}</td></tr>
              ))}
            </tbody>
          </table>

          <h3>Repository scans</h3>
          {data.repo_scans?.enabled ? (
            <p><Badge kind="ok">on</Badge> <span className="small">clones from {data.repo_scans.git_hosts.join(", ")}</span></p>
          ) : (
            <p><Badge kind="muted">off</Badge> <span className="muted small">set AEGIS_SAFETY__GIT_HOSTS (e.g. github.com:443) and restart the backend</span></p>
          )}
        </>
      )}
    </section>
  );
}
