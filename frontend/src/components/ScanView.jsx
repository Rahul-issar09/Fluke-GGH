import React from "react";
import { api, reportUrl } from "../api.js";
import Crypto from "./Crypto.jsx";
import Findings from "./Findings.jsx";
import GateAudit from "./GateAudit.jsx";
import Graph from "./Graph.jsx";
import LiveEvents from "./LiveEvents.jsx";
import { ErrorBox, Loading, StatusBadge, Tabs } from "./ui.jsx";
import { askRoute, onlineNotice } from "../llm/state.js";

const TABS = [
  ["live", "Live"],
  ["findings", "Findings"],
  ["graph", "Graph"],
  ["crypto", "Crypto (CBOM)"],
  ["gate", "Gate & audit"],
  ["report", "Report"],
  ["ask", "Ask"],
];
const RUNNING = new Set(["queued", "running"]);

export default function ScanView({ scanId, llm, onBack }) {
  const [scan, setScan] = React.useState(null);
  const [error, setError] = React.useState(null);
  const [tab, setTab] = React.useState("live");
  const [refreshKey, setRefreshKey] = React.useState(0);

  const load = React.useCallback(() => api.scan(scanId).then(setScan).catch(setError), [scanId]);

  React.useEffect(() => {
    setScan(null);
    setError(null);
    setTab("live");
    load();
  }, [scanId, load]);

  React.useEffect(() => {
    if (!scan || !RUNNING.has(scan.status)) return undefined;
    const t = setInterval(load, 3000);
    return () => clearInterval(t);
  }, [scan, load]);

  if (error) return <ErrorBox error={error} />;
  if (!scan) return <Loading />;

  const done = scan.completed_stages || [];
  return (
    <section>
      {onBack && <button className="link" onClick={onBack}>← All scans</button>}
      <div className="row between">
        <div>
          <div className="lbl">Scan</div>
          <h2>{scan.id} <StatusBadge status={scan.status} /></h2>
          <div className="meta">
            <span>mode <b>{scan.mode}</b></span>
            <span><b>{scan.counts?.findings ?? 0}</b> findings</span>
            <span><b>{scan.counts?.evidence ?? 0}</b> evidence records</span>
          </div>
        </div>
        <div className="row gap">
          {RUNNING.has(scan.status) && <button onClick={() => api.cancel(scanId).then(load)}>Cancel scan</button>}
          <button onClick={() => { load(); setRefreshKey((k) => k + 1); }}>Refresh</button>
        </div>
      </div>
      <div className="stages">
        {(scan.stages || []).map((s) => <span key={s} className={done.includes(s) ? "stage done" : "stage"}>{s}</span>)}
        <span className={done.includes("finalize") ? "stage done" : "stage"}>report</span>
      </div>

      <Tabs tabs={TABS} active={tab} onChange={setTab} />
      <div className="tab-body">
        {tab === "live" && <LiveEvents scanId={scanId} onFinished={() => { load(); setRefreshKey((k) => k + 1); }} />}
        {tab === "findings" && <Findings scanId={scanId} refreshKey={refreshKey} />}
        {tab === "graph" && <Graph scanId={scanId} refreshKey={refreshKey} />}
        {tab === "crypto" && <Crypto scanId={scanId} refreshKey={refreshKey} />}
        {tab === "gate" && <GateAudit scanId={scanId} refreshKey={refreshKey} />}
        {tab === "report" && <Report scanId={scanId} finished={!RUNNING.has(scan.status)} />}
        {tab === "ask" && <Ask scanId={scanId} llm={llm} />}
      </div>
    </section>
  );
}

function Report({ scanId, finished }) {
  if (!finished) return <p className="muted">The report is written when the scan finishes.</p>;
  return (
    <div>
      <div className="row gap">
        <a className="button primary" href={reportUrl(scanId, "html")} target="_blank" rel="noreferrer">Open the HTML report</a>
        <a className="button" href={reportUrl(scanId, "json")}>Download JSON</a>
        <a className="button" href={reportUrl(scanId, "cbom")}>Download CBOM</a>
      </div>
      <iframe className="report-frame" title="Report" src={reportUrl(scanId, "html")} sandbox="" />
    </div>
  );
}

function Ask({ scanId, llm }) {
  const [question, setQuestion] = React.useState("What are the critical issues?");
  const [answer, setAnswer] = React.useState(null);
  const [error, setError] = React.useState(null);
  return (
    <div>
      <form className="row gap" onSubmit={(e) => { e.preventDefault(); setError(null); api.ask(scanId, question).then(setAnswer).catch(setError); }}>
        <input className="grow" value={question} onChange={(e) => setQuestion(e.target.value)} />
        <button className="primary" type="submit">Ask</button>
      </form>
      {askRoute(llm) && <p className="muted small">{askRoute(llm)}</p>}
      {onlineNotice(llm) && <p className="warning small" role="note">{onlineNotice(llm)}</p>}
      <ErrorBox error={error} />
      {answer && <p className="answer">{answer.answer}</p>}
    </div>
  );
}
