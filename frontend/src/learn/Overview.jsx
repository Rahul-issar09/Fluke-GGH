import React from "react";
import { api } from "../api.js";
import { Badge, Loading, useLoad } from "../components/ui.jsx";
import { CATEGORY_NAMES, TABS, TILES, loadTileCounts } from "./content.js";

const STATES = ["confirmed", "corroborated", "candidate"];
const tabLabel = (tab) => TABS.find(([key]) => key === tab)?.[1] || tab;

// the newest completed scan and its findings, read the same way the console's Scans and Findings tabs do
async function loadLatestScan() {
  const scans = await api.scans(100);
  const scan = scans.find((s) => s.status === "completed");
  if (!scan) return { scan: null, findings: [] };
  return { scan, findings: await api.findings(scan.id) };
}

function groupByCategory(findings) {
  const groups = new Map();
  for (const f of findings) {
    const key = f.owasp || "";
    if (!groups.has(key)) groups.set(key, { key, confirmed: 0, corroborated: 0, candidate: 0 });
    const g = groups.get(key);
    if (g[f.state] !== undefined) g[f.state] += 1;
  }
  return [...groups.values()].filter((g) => STATES.some((s) => g[s] > 0)).sort((a, b) => (a.key || "~").localeCompare(b.key || "~"));
}

export default function Overview({ progress, onTab, onNavigate }) {
  const scan = useLoad(loadLatestScan, []);
  const counts = useLoad(loadTileCounts, []);
  const weak = Object.entries(progress.quiz || {}).filter(([, score]) => score < 60).sort((a, b) => a[1] - b[1]);

  return (
    <div className="lr-overview">
      <div className="lr-block">
        <h3 className="lr-h">From your latest scan</h3>
        {scan.error && (
          // a stopped backend shows up as a proxy error (HTTP 500/502/504): say that, not a raw error box
          <div className="lr-note">
            <span>Couldn't load your latest scan{scan.error.status ? ` (HTTP ${scan.error.status})` : ""} — is the backend running?</span>
            <button onClick={scan.reload}>Retry</button>
          </div>
        )}
        {scan.loading && !scan.data && <Loading />}
        {scan.data && !scan.data.scan && (
          <div className="lr-note">
            <span>Run a scan to personalise this page.</span>
            <button className="primary" onClick={() => onNavigate("new")}>New scan</button>
          </div>
        )}
        {scan.data?.scan && (
          <>
            <div className="lr-scan-head muted small">
              <span className="mono">{scan.data.scan.id}</span> · {scan.data.scan.mode} · {scan.data.findings.length} findings
            </div>
            {groupByCategory(scan.data.findings).length === 0 && <div className="lr-note"><span>This scan has no open findings to learn from.</span></div>}
            <div className="lr-cats">
              {groupByCategory(scan.data.findings).map((g) => (
                <div key={g.key} className="lr-cat">
                  <div className="lr-cat-title">
                    {g.key ? <><span className="mono">{g.key}</span> · {CATEGORY_NAMES[g.key] || "OWASP category"}</> : "Uncategorised"}
                  </div>
                  <div className="lr-cat-badges">
                    {STATES.filter((s) => g[s] > 0).map((s) => <Badge key={s} kind={s}>{g[s]} {s}</Badge>)}
                  </div>
                  {g.key && (
                    <div className="lr-cat-links">
                      <button className="link" onClick={() => onTab("cheatsheets", g.key)}>Cheat sheet</button>
                      <button className="link" onClick={() => onTab("practice", g.key)}>Practice</button>
                      <button className="link" onClick={() => onTab("quizzes", g.key)}>Quiz</button>
                    </div>
                  )}
                </div>
              ))}
            </div>
          </>
        )}
      </div>

      <div className="lr-block">
        <h3 className="lr-h">What's inside</h3>
        <div className="lr-tiles">
          {TILES.map((t) => (
            <button key={t.tab} className="lr-tile" onClick={() => onTab(t.tab)}>
              <span className="lr-tile-title">{tabLabel(t.tab)}</span>
              <span className="lr-tile-text">{t.text}</span>
              <span className="lr-tile-count mono">
                {!counts.data ? "…" : counts.data[t.tab] == null ? "Not added yet" : `${counts.data[t.tab]} ${t.unit}`}
              </span>
            </button>
          ))}
        </div>
      </div>

      {weak.length > 0 && (
        <div className="lr-block lr-weak">
          <h3 className="lr-h">Weak areas</h3>
          <div className="lr-cats">
            {weak.map(([key, score]) => (
              <div key={key} className="lr-cat">
                <div className="lr-cat-title"><span className="mono">{key}</span> · {CATEGORY_NAMES[key] || key}</div>
                <div className="lr-cat-badges"><Badge kind="warn">best {score}%</Badge></div>
                <div className="lr-cat-links"><button className="link" onClick={() => onTab("quizzes", key)}>Quiz again</button></div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
