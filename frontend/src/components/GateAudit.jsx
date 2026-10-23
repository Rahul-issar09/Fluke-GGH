import React from "react";
import { api } from "../api.js";
import { Badge, ErrorBox, Loading, useLoad } from "./ui.jsx";

export default function GateAudit({ scanId, refreshKey }) {
  const [threshold, setThreshold] = React.useState(0.7);
  const gate = useLoad(() => api.gate(scanId, threshold), [scanId, threshold, refreshKey]);
  const audit = useLoad(() => api.audit(scanId), [scanId, refreshKey]);

  return (
    <div>
      <h3>CI gate</h3>
      <div className="row gap">
        <label className="inline">
          Risk threshold <input type="range" min="0" max="1" step="0.05" value={threshold} onChange={(e) => setThreshold(Number(e.target.value))} /> {threshold.toFixed(2)}
        </label>
      </div>
      <ErrorBox error={gate.error} />
      {gate.data && (
        <p className={`verdict ${gate.data.exit_code === 0 ? "pass" : gate.data.exit_code === 1 ? "block" : ""}`}>
          <Badge kind={gate.data.exit_code === 0 ? "ok" : gate.data.exit_code === 1 ? "bad" : "muted"}>exit code {gate.data.exit_code}</Badge>{" "}
          {gate.data.exit_code === 0 && "clean — nothing blocks"}
          {gate.data.exit_code === 1 && <>blocked by <span className="mono">{gate.data.blocking_findings.join(", ")}</span></>}
          {gate.data.exit_code === 2 && "the scan did not complete"}
        </p>
      )}

      <h3>Audit trail</h3>
      <ErrorBox error={audit.error} />
      {audit.loading && !audit.data && <Loading />}
      {audit.data && (
        <>
          <h4>Agent decisions ({audit.data.decisions.length})</h4>
          <table className="compact">
            <thead><tr><th>Id</th><th>Node</th><th>Finding</th><th>Source</th><th>Valid</th><th>Detail</th></tr></thead>
            <tbody>
              {audit.data.decisions.map((d) => (
                <tr key={d.id}>
                  <td className="mono small">{d.id}</td>
                  <td>{d.node}</td>
                  <td className="mono small">{d.finding_id}</td>
                  <td><Badge kind={d.source === "rule" ? "muted" : d.source === "fallback" ? "warn" : "info"}>{d.source}</Badge></td>
                  <td>{d.valid ? <Badge kind="ok">valid</Badge> : <Badge kind="bad">rejected</Badge>}</td>
                  <td className="small">{d.error || d.output?.next_step || (d.output?.drafted === false ? "no draft" : "")}</td>
                </tr>
              ))}
            </tbody>
          </table>

          <h4>Tool calls through the safety layer ({audit.data.tool_calls.length})</h4>
          <table className="compact">
            <thead><tr><th>Tool</th><th>Target</th><th className="num">ms</th><th>Exit</th><th>Blocked</th></tr></thead>
            <tbody>
              {audit.data.tool_calls.map((t, i) => (
                <tr key={i}>
                  <td>{t.tool}</td><td className="mono small">{t.target_host || "—"}</td><td className="num">{t.duration_ms}</td>
                  <td>{t.exit_code ?? "—"}</td><td className="small">{t.blocked_reason ? <span className="bad">{t.blocked_reason}</span> : ""}</td>
                </tr>
              ))}
            </tbody>
          </table>

          <h4>Finding state changes ({audit.data.transitions.length})</h4>
          <table className="compact">
            <thead><tr><th>Finding</th><th>From</th><th>To</th><th>By</th><th>Why</th></tr></thead>
            <tbody>
              {audit.data.transitions.map((t, i) => (
                <tr key={i}>
                  <td className="mono small">{t.finding_id}</td><td>{t.from || "—"}</td><td>{t.to}</td><td>{t.actor}</td><td className="small">{t.reason}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}
    </div>
  );
}
