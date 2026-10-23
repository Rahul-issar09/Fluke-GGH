// Threat Pulse: recent vulnerabilities from CISA KEV (exploited in the wild), NVD (new CVEs),
// FIRST EPSS (exploit likelihood) and OSV (package advisories). The data is a snapshot saved by
// `npm run sync:feeds` into public/learn/feed.json, so the page works offline and shows its age.
import React from "react";
import { Badge } from "../components/ui.jsx";
import { CATEGORY_NAMES, CHEAT_TOPICS, QUIZ_CATEGORIES } from "./content.js";
import { BackendNote, WithContent, useAsync, useContent } from "./parts.jsx";
import { backendHint, dependencyAdvisories } from "./scans.js";

const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
const DATES = [["", "Any date"], ["7", "Last 7 days"], ["30", "Last 30 days"], ["90", "Last 90 days"]];
const PAGE = 60;
const sevKind = { CRITICAL: "bad", HIGH: "bad", MEDIUM: "warn", LOW: "muted" };

const sourceLink = (item) =>
  item.source === "OSV" || !/^CVE-/i.test(item.id)
    ? `https://osv.dev/vulnerability/${encodeURIComponent(item.id)}`
    : `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(item.id)}`;

const isHttp = (r) => typeof r === "string" && /^https?:///i.test(r);
const hostOf = (r) => {
  try {
    return new URL(r).hostname;
  } catch {
    return r;
  }
};

function matches(item, f, since) {
  if (f.source && item.source !== f.source) return false;
  if (f.severity && item.severity !== f.severity) return false;
  if (f.ecosystem && item.ecosystem !== f.ecosystem) return false;
  if (f.exploited && !item.exploited) return false;
  if (since && (!item.date_added || item.date_added < since)) return false;
  if (f.q) {
    const hay = `${item.id} ${item.title} ${item.description} ${item.vendor} ${item.product} ${item.package} ${item.cwe}`.toLowerCase();
    if (!hay.includes(f.q.toLowerCase())) return false;
  }
  return true;
}

export default function Pulse({ onTab }) {
  const feed = useContent("feed");
  return (
    <WithContent state={feed} what="The threat feed">
      {(data) => <PulseBody data={data} onTab={onTab} />}
    </WithContent>
  );
}

function PulseBody({ data, onTab }) {
  const items = data.items || [];
  const [f, setF] = React.useState({ source: "", severity: "", ecosystem: "", days: "", exploited: false, q: "" });
  const [limit, setLimit] = React.useState(PAGE);
  const [selected, setSelected] = React.useState(null);
  const set = (k) => (e) => { setF({ ...f, [k]: e.target.type === "checkbox" ? e.target.checked : e.target.value }); setLimit(PAGE); };

  const ecosystems = [...new Set(items.map((i) => i.ecosystem).filter(Boolean))].sort();
  // "last N days" counts back from the snapshot, so an old offline snapshot still filters sensibly
  const since = f.days ? new Date(new Date(data.synced_at).getTime() - Number(f.days) * 86400_000).toISOString().slice(0, 10) : "";
  const shown = items.filter((i) => matches(i, f, since));
  const item = shown.find((i) => i.id === selected) || null;

  return (
    <div>
      <div className="lr-snapshot muted small">
        Snapshot from {new Date(data.synced_at).toLocaleString()} · {items.length} items · refresh with <span className="mono">npm run sync:feeds</span> (needs internet)
      </div>
      <div className="lr-filters">
        <select value={f.source} onChange={set("source")} aria-label="Source">
          <option value="">All sources</option>
          <option value="KEV">CISA KEV (exploited)</option>
          <option value="NVD">NVD (new CVEs)</option>
          <option value="OSV">OSV (packages)</option>
        </select>
        <select value={f.severity} onChange={set("severity")} aria-label="Severity">
          <option value="">Any severity</option>
          {SEVERITIES.map((s) => <option key={s} value={s}>{s.toLowerCase()}</option>)}
        </select>
        <select value={f.ecosystem} onChange={set("ecosystem")} aria-label="Ecosystem">
          <option value="">Any ecosystem</option>
          {ecosystems.map((e) => <option key={e} value={e}>{e}</option>)}
        </select>
        <select value={f.days} onChange={set("days")} aria-label="Date">
          {DATES.map(([v, label]) => <option key={v} value={v}>{label}</option>)}
        </select>
        <label className="inline small"><input type="checkbox" checked={f.exploited} onChange={set("exploited")} /> Exploited only</label>
        <input className="grow" placeholder="Search CVE, product, package, CWE…" value={f.q} onChange={set("q")} aria-label="Search" />
      </div>
      <div className="muted small">{shown.length} match{shown.length === 1 ? "" : "es"}</div>

      <div className="split lr-split">
        <div>
          <table className="clickable compact">
            <thead><tr><th>ID</th><th>Title</th><th>Severity</th><th>Source</th><th>Added</th></tr></thead>
            <tbody>
              {shown.slice(0, limit).map((i) => (
                <tr key={`${i.source}-${i.id}`} className={i.id === selected ? "selected" : ""} onClick={() => setSelected(i.id)}>
                  <td className="mono">{i.id}{i.exploited && <> <Badge kind="bad">exploited</Badge></>}</td>
                  <td>{(i.title || "").trim().slice(0, 90)}</td>
                  <td>{i.severity ? <Badge kind={sevKind[i.severity] || "muted"}>{i.severity.toLowerCase()}</Badge> : <span className="muted">-</span>}</td>
                  <td>{i.source}</td>
                  <td className="mono">{i.date_added || ""}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {shown.length > limit && <button onClick={() => setLimit(limit + PAGE)}>Show more ({shown.length - limit} left)</button>}
        </div>
        <div className="detail-pane">
          {item ? <PulseDetail item={item} onTab={onTab} /> : <div className="empty">Pick an item to see its details.</div>}
        </div>
      </div>
    </div>
  );
}

function PulseDetail({ item, onTab }) {
  const product = item.package ? `${item.package} (${item.ecosystem})` : [item.vendor, item.product].filter(Boolean).join(" ") || "-";
  return (
    <div className="lr-detail">
      <h3 className="lr-h mono">{item.id}</h3>
      <div className="row gap wrap">
        <Badge kind="info">{item.source}</Badge>
        {item.exploited && <Badge kind="bad">exploited in the wild</Badge>}
        {item.severity && <Badge kind={sevKind[item.severity] || "muted"}>{item.severity.toLowerCase()}</Badge>}
        {item.cvss != null && <span className="small">CVSS <strong>{item.cvss}</strong></span>}
        {item.epss != null && <span className="small">EPSS <strong>{(item.epss * 100).toFixed(1)}%</strong> chance of exploitation in 30 days</span>}
      </div>
      <p><strong>{(item.title || "").trim()}</strong></p>
      <div className="lr-desc">{item.description || "No description."}</div>
      <table className="compact">
        <tbody>
          <tr><th>Affected</th><td>{product}</td></tr>
          <tr><th>Weakness</th><td>{item.cwe || "-"}{item.owasp && <> · <span className="mono">{item.owasp}</span> {CATEGORY_NAMES[item.owasp] || ""}</>}</td></tr>
          {item.kev_due_date && <tr><th>Fix deadline</th><td>{item.kev_due_date} <span className="muted small">(CISA's deadline for US federal agencies)</span></td></tr>}
          <tr><th>Added</th><td>{item.date_added || "-"}</td></tr>
        </tbody>
      </table>
      <div className="row gap wrap">
        <a href={sourceLink(item)} target="_blank" rel="noreferrer">Source record</a>
        {(item.refs || []).filter(isHttp).slice(0, 4).map((r) => <a key={r} href={r} target="_blank" rel="noreferrer" className="small">{hostOf(r)}</a>)}
      </div>
      {item.owasp && (CHEAT_TOPICS.includes(item.owasp) || QUIZ_CATEGORIES.includes(item.owasp)) && (
        <div className="row gap lr-links">
          {CHEAT_TOPICS.includes(item.owasp) && <button className="link" onClick={() => onTab("cheatsheets", item.owasp)}>Cheat sheet</button>}
          {QUIZ_CATEGORIES.includes(item.owasp) && <button className="link" onClick={() => onTab("quizzes", item.owasp)}>Quiz</button>}
        </div>
      )}
      <CheckMyScans item={item} />
    </div>
  );
}

function CheckMyScans({ item }) {
  const deps = useAsync(() => dependencyAdvisories(20), { auto: false });
  const exact = (deps.data || []).filter((d) => d.advisories.includes(item.id));
  const samePackage = item.package
    ? (deps.data || []).filter((d) => !exact.includes(d) && d.package?.toLowerCase() === item.package.toLowerCase())
    : [];
  return (
    <div className="lr-check">
      <button onClick={deps.run} disabled={deps.loading}>{deps.loading ? "Checking your scans…" : "Check my scans"}</button>
      {deps.error && <BackendNote text={backendHint(deps.error)} onRetry={deps.run} />}
      {deps.data && (
        <div className="small">
          {exact.length > 0 && (
            <div className="warning">
              <strong>{item.id} is listed for your code:</strong>
              <ul>{exact.map((d) => <li key={`${d.scanId}-${d.findingId}`}><span className="mono">{d.scanId}</span> · {d.package} {d.version} ({d.ecosystem}) · finding <span className="mono">{d.findingId}</span></li>)}</ul>
            </div>
          )}
          {samePackage.length > 0 && (
            <div className="lr-note">
              <span>The package {item.package} is used in {[...new Set(samePackage.map((d) => d.scanId))].join(", ")}; check whether your version is affected.</span>
            </div>
          )}
          {exact.length === 0 && samePackage.length === 0 && (
            <div className="muted">Not found in the dependency results of your recent scans (up to 20).</div>
          )}
        </div>
      )}
    </div>
  );
}
