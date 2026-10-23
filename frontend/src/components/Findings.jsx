import React from "react";
import { api } from "../api.js";
import { EvidenceLink } from "./Evidence.jsx";
import FixPanel from "./FixPanel.jsx";
import { Empty, ErrorBox, Loading, RiskPill, StateBadge, useLoad } from "./ui.jsx";

export default function Findings({ scanId, refreshKey }) {
  const [filters, setFilters] = React.useState({ state: "", owasp: "" });
  const [selected, setSelected] = React.useState(null);
  const { data, error, loading, reload } = useLoad(() => api.findings(scanId, filters), [scanId, filters.state, filters.owasp, refreshKey]);

  return (
    <div className="split">
      <div className="list-pane">
        <div className="filters">
          <select value={filters.state} onChange={(e) => setFilters({ ...filters, state: e.target.value })}>
            <option value="">all states</option>
            <option value="confirmed">confirmed</option>
            <option value="corroborated">corroborated</option>
            <option value="candidate">candidate</option>
            <option value="resolved">resolved</option>
          </select>
          <select value={filters.owasp} onChange={(e) => setFilters({ ...filters, owasp: e.target.value })}>
            <option value="">all OWASP</option>
            {["A01", "A02", "A03", "A05", "A06", "A08", "A10"].map((o) => <option key={o} value={o}>{o}</option>)}
          </select>
          <button onClick={reload}>Refresh</button>
        </div>
        <ErrorBox error={error} />
        {loading && !data && <Loading />}
        {data && data.length === 0 && <Empty>No findings match.</Empty>}
        {data && data.length > 0 && (
          <table className="clickable">
            <thead><tr><th className="num">#</th><th>Finding</th><th>State</th><th className="num">Risk</th><th>Where</th></tr></thead>
            <tbody>
              {data.map((f, i) => (
                <tr key={f.id} className={`st-${f.state} ${selected === f.id ? "selected" : ""}`} onClick={() => setSelected(f.id)}>
                  <td className="num">{i + 1}</td>
                  <td>
                    <div className="mono small">{f.id} · {f.type}{f.owasp ? ` · ${f.owasp}` : ""}</div>
                    <div>{f.title}</div>
                  </td>
                  <td><StateBadge state={f.state} /></td>
                  <td className="num"><RiskPill risk={f.risk} /><span className="bar"><i style={{ width: `${Math.round(Math.min(1, f.risk || 0) * 100)}%` }} /></span></td>
                  <td className="small">
                    {f.route && <div className="mono">{f.route}</div>}
                    {f.file && <div className="mono">{f.file}{f.line ? `:${f.line}` : ""}</div>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
      <div className="detail-pane">
        {selected ? <FindingDetail id={selected} onChanged={reload} /> : <Empty>Select a finding to see its explanation, evidence, risk and fix.</Empty>}
      </div>
    </div>
  );
}

function FindingDetail({ id, onChanged }) {
  const { data: f, error, loading, reload } = useLoad(() => api.finding(id), [id]);
  if (error) return <ErrorBox error={error} />;
  if (loading && !f) return <Loading />;
  const s = f.scores || {};
  return (
    <div className="finding">
      <div className="row between">
        <h3>{f.id} · {f.type}</h3>
        <StateBadge state={f.state} />
      </div>
      <p>{f.title}</p>
      <div className="small muted">
        {f.owasp && <>OWASP {f.owasp} · </>}risk <RiskPill risk={f.risk} />
        {f.correlation_score != null && <> · correlation {f.correlation_score}</>}
        {f.sources?.length > 0 && <> · sources: {f.sources.join(", ")}</>}
      </div>

      <div className="facts">
        <div><h4>What</h4><p>{f.what || <span className="muted">—</span>}</p></div>
        <div><h4>Impact</h4><p>{f.impact || <span className="muted">—</span>}</p></div>
        <div><h4>Exploit</h4><p>{f.exploit || <span className="muted">—</span>}</p></div>
        <div><h4>Where</h4>{f.where ? <pre>{f.where}</pre> : <p className="muted">—</p>}</div>
      </div>

      {f.claims?.length > 0 && (
        <>
          <h4>Claims and the evidence behind them</h4>
          <ul className="claims">
            {f.claims.map((c, i) => (
              <li key={i}>
                <strong>{c.field}</strong>: {c.text}{" "}
                {c.evidence_ids.map((e) => <EvidenceLink key={e} id={e} />)}
              </li>
            ))}
          </ul>
        </>
      )}

      <h4>Risk factors</h4>
      <div className="factors">
        {[["Severity", f.severity], ["Confidence", s.confidence], ["Exploitability", s.exploitability], ["Exposure", s.exposure], ["Criticality", s.criticality], ["Path", s.path_factor]].map(([k, v]) => (
          <div key={k}><span>{k}</span><b>{v ?? "—"}</b></div>
        ))}
        <div className="total"><span>Risk</span><b><RiskPill risk={s.risk} /></b></div>
      </div>
      <p className="muted small">Risk = Severity × Confidence × (1 + Exploitability + Exposure + Criticality + PathFactor) / 5</p>

      <h4>Evidence</h4>
      <div className="chips">{f.evidence_ids.length ? f.evidence_ids.map((e) => <EvidenceLink key={e} id={e} />) : <span className="muted">none of its own</span>}</div>

      <h4>Fix</h4>
      <FixPanel finding={f} onChanged={() => { reload(); onChanged?.(); }} />
    </div>
  );
}
