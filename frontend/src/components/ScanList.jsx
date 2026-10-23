import React from "react";
import { api } from "../api.js";
import { Empty, ErrorBox, Loading, RiskPill, StatusBadge, useLoad } from "./ui.jsx";

const ACTIVE = new Set(["queued", "running", "awaiting_approval"]);

export default function ScanList({ onOpen, onNew }) {
  const { data, error, loading, reload } = useLoad(() => api.scans(100), []);
  React.useEffect(() => {
    const t = setInterval(reload, 5000);
    return () => clearInterval(t);
  }, [reload]);

  const scans = data || [];
  const active = scans.filter((s) => ACTIVE.has(s.status)).length;
  const findings = scans.reduce((n, s) => n + (s.findings || 0), 0);
  const topRisk = scans.reduce((m, s) => Math.max(m, s.top_risk || 0), 0);

  return (
    <section>
      <div className="pg-head">
        <div>
          <div className="lbl">Scan &amp; Fix · 01</div>
          <h2>Scans</h2>
          <p>Every scan of a running app, a folder or a repo. Open one to see its findings, evidence, attack paths and fixes.</p>
        </div>
        <div className="pg-actions">
          <button onClick={reload}>Refresh</button>
          {onNew && <button className="primary" onClick={onNew}>New scan</button>}
        </div>
      </div>
      <ErrorBox error={error} />
      {loading && !data && <Loading />}
      {data && (
        <div className="strip">
          <div><b>{scans.length}</b><span>scans</span></div>
          <div><b>{active}</b><span>running now</span></div>
          <div><b>{findings}</b><span>findings</span></div>
          <div className={topRisk >= 0.7 ? "hot" : ""}><b>{topRisk.toFixed(2)}</b><span>top risk</span></div>
        </div>
      )}
      {data && data.length === 0 && <Empty>No scans yet. Start one from “New scan”.</Empty>}
      {data && data.length > 0 && (
        <table className="clickable">
          <thead>
            <tr><th>Scan</th><th>Mode</th><th>Status</th><th>Target / source</th><th className="num">Findings</th><th className="num">Top risk</th><th>Started</th></tr>
          </thead>
          <tbody>
            {data.map((s) => (
              <tr key={s.id} onClick={() => onOpen(s.id)}>
                <td className="mono">{s.id}</td>
                <td>{s.mode}</td>
                <td><StatusBadge status={s.status} /></td>
                <td className="small">{s.target_url}{s.target_url && s.source ? " + " : ""}{s.source ? s.source.split(/[\\/]/).slice(-1)[0] : ""}</td>
                <td className="num">{s.findings}</td>
                <td className="num"><RiskPill risk={s.top_risk} /></td>
                <td className="small muted">{s.created_at ? new Date(s.created_at).toLocaleString() : ""}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}
