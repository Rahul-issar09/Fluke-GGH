// Jobs board: internship, junior and mid-level security roles. Filter by level and remote; every post
// expires after 7, 14 or 30 days and is then hidden automatically.
import React from "react";
import { Badge, Loading } from "../components/ui.jsx";
import * as cm from "./api.js";
import { useCommunity } from "./context.js";
import { JOB_LEVELS } from "./types.js";
import { AuthorLine, ErrorNote, ReportButton, useAction, useDebounced } from "./widgets.jsx";

const LEVEL_LABEL = { intern: "Internship", junior: "Junior", mid: "Mid-level", senior: "Senior" };
const daysLeft = (iso) => Math.max(0, Math.ceil((Date.parse(iso) - Date.now()) / 86400e3));

export default function Jobs() {
  const { user, version, requireAuth } = useCommunity();
  const [level, setLevel] = React.useState("");
  const [remote, setRemote] = React.useState("");
  const [q, setQ] = React.useState("");
  const query = useDebounced(q);
  const [items, setItems] = React.useState(null);
  const [adding, setAdding] = React.useState(false);
  const list = useAction();

  const load = React.useCallback(() => list.run(async () => setItems(await cm.listJobs({ level, remote, q: query.trim() }))), [level, remote, query, list.run]); // eslint-disable-line react-hooks/exhaustive-deps
  React.useEffect(() => { load(); }, [load, version]);

  return (
    <div className="cm-col">
      <div className="cm-filters">
        <select value={level} onChange={(e) => setLevel(e.target.value)} aria-label="Level">
          <option value="">All levels</option>
          {JOB_LEVELS.map((l) => <option key={l} value={l}>{LEVEL_LABEL[l]}</option>)}
        </select>
        <select value={remote} onChange={(e) => setRemote(e.target.value)} aria-label="Remote">
          <option value="">Remote or on-site</option>
          <option value="true">Remote only</option>
          <option value="false">On-site only</option>
        </select>
        <input className="grow" value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search role, company or place…" aria-label="Search jobs" />
        <button type="button" className="primary" onClick={() => requireAuth(() => setAdding(true))}>Post a job</button>
      </div>
      {adding && <AddJob onDone={(j) => { setAdding(false); if (j) setItems((all) => [j, ...(all || [])]); }} />}
      <ErrorNote error={list.error} />
      {items === null ? <Loading /> : items.length === 0 ? <div className="empty">No open jobs match.</div> : items.map((j) => {
        const left = daysLeft(j.expiresAt);
        return (
          <div key={j.id} className="cm-card cm-job">
            <div className="row between gap wrap">
              <div>
                <div className="cm-job-role">{j.role}</div>
                <div className="muted">{j.company} · {j.location}</div>
              </div>
              <a className="button primary" href={j.url} target="_blank" rel="noopener noreferrer nofollow">Apply</a>
            </div>
            <div className="row gap wrap">
              <Badge kind="info">{LEVEL_LABEL[j.level] || j.level}</Badge>
              {j.remote ? <Badge kind="ok">remote</Badge> : <Badge kind="muted">on-site</Badge>}
              <span className={left <= 3 ? "small cm-expiring" : "small muted"}>expires in {left} day{left === 1 ? "" : "s"}</span>
            </div>
            <div className="cm-actions">
              <AuthorLine user={j.author} at={j.postedAt} />
              <span className="grow" />
              {!(user && user.id === j.author.id) && <ReportButton kind="job" id={j.id} />}
            </div>
          </div>
        );
      })}
    </div>
  );
}

function AddJob({ onDone }) {
  const [f, setF] = React.useState({ role: "", company: "", location: "", remote: false, level: "junior", url: "https://", expiryDays: 30 });
  const set = (k) => (e) => setF({ ...f, [k]: e.target.type === "checkbox" ? e.target.checked : e.target.value });
  const act = useAction();
  const save = (e) => { e.preventDefault(); act.run(async () => onDone(await cm.addJob({ ...f, expiryDays: Number(f.expiryDays) }))); };
  return (
    <form className="cm-card cm-col" onSubmit={save}>
      <h4 className="cm-h">Post a job</h4>
      <div className="cm-grid2">
        <input value={f.role} onChange={set("role")} placeholder="Role, e.g. Junior AppSec Engineer" aria-label="Role" />
        <input value={f.company} onChange={set("company")} placeholder="Company" aria-label="Company" />
        <input value={f.location} onChange={set("location")} placeholder="Location" aria-label="Location" />
        <input value={f.url} onChange={set("url")} placeholder="https://… (where to apply)" aria-label="Apply link" />
      </div>
      <div className="row gap wrap">
        <select value={f.level} onChange={set("level")} aria-label="Level">{JOB_LEVELS.map((l) => <option key={l} value={l}>{LEVEL_LABEL[l]}</option>)}</select>
        <label className="inline cm-check"><input type="checkbox" checked={f.remote} onChange={set("remote")} /> Remote</label>
        <select value={f.expiryDays} onChange={set("expiryDays")} aria-label="Expires after">{[7, 14, 30].map((d) => <option key={d} value={d}>Expires after {d} days</option>)}</select>
      </div>
      <ErrorNote error={act.error} />
      <div className="row gap">
        <button className="primary" type="submit" disabled={act.busy}>Post job</button>
        <button type="button" onClick={() => onDone(null)}>Cancel</button>
      </div>
    </form>
  );
}
