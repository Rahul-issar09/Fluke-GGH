// Resources: shared tools, writeups, courses, cheat sheets and videos, with tags and upvotes.
import React from "react";
import { Badge, Loading } from "../components/ui.jsx";
import * as cm from "./api.js";
import { useCommunity } from "./context.js";
import { RESOURCE_KINDS } from "./types.js";
import { AuthorLine, ErrorNote, ReportButton, Tags, parseTags, useAction, useDebounced } from "./widgets.jsx";

const hostOf = (url) => { try { return new URL(url).host; } catch { return ""; } };

export default function Resources() {
  const { user, version, requireAuth } = useCommunity();
  const [kind, setKind] = React.useState("");
  const [tag, setTag] = React.useState("");
  const [q, setQ] = React.useState("");
  const query = useDebounced(q);
  const [items, setItems] = React.useState(null);
  const [adding, setAdding] = React.useState(false);
  const list = useAction();
  const vote = useAction();

  const load = React.useCallback(() => list.run(async () => setItems(await cm.listResources({ kind, tag, q: query.trim() }))), [kind, tag, query, list.run]); // eslint-disable-line react-hooks/exhaustive-deps
  React.useEffect(() => { load(); }, [load, version]);

  const toggle = (r) => requireAuth(() => vote.run(async () => {
    const res = await cm.voteResource(r.id);
    setItems((all) => all.map((x) => (x.id === r.id ? { ...x, ...res } : x)));
  }));

  return (
    <div className="cm-col">
      <div className="cm-filters">
        <select value={kind} onChange={(e) => setKind(e.target.value)} aria-label="Kind">
          <option value="">All kinds</option>
          {RESOURCE_KINDS.map((k) => <option key={k} value={k}>{k}</option>)}
        </select>
        <input className="grow" value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search resources…" aria-label="Search resources" />
        {tag && <button type="button" className="cm-tag cm-tag-on" onClick={() => setTag("")}>#{tag} ×</button>}
        <button type="button" className="primary" onClick={() => requireAuth(() => setAdding(true))}>Share a resource</button>
      </div>
      {adding && <AddResource onDone={(r) => { setAdding(false); if (r) setItems((all) => [r, ...(all || [])]); }} />}
      <ErrorNote error={list.error || vote.error} />
      {items === null ? <Loading /> : items.length === 0 ? <div className="empty">No resources match.</div> : items.map((r) => {
        const own = user && user.id === r.author.id;
        return (
          <div key={r.id} className="cm-card cm-res">
            <button type="button" className={r.votedByMe ? "cm-upvote cm-voted" : "cm-upvote"} disabled={own} title={own ? "You cannot vote for your own resource" : "Upvote"} aria-pressed={r.votedByMe} onClick={() => toggle(r)}>▲<strong>{r.votes}</strong></button>
            <div className="cm-res-main">
              <div className="row gap wrap">
                <a href={r.url} target="_blank" rel="noopener noreferrer nofollow" className="cm-res-title">{r.title}</a>
                <Badge kind="info">{r.kind}</Badge>
                <span className="muted small mono">{hostOf(r.url)}</span>
              </div>
              <Tags tags={r.tags} onTag={setTag} />
              <div className="cm-actions">
                <AuthorLine user={r.author} at={r.createdAt} />
                <span className="grow" />
                {!own && <ReportButton kind="resource" id={r.id} />}
              </div>
            </div>
          </div>
        );
      })}
    </div>
  );
}

function AddResource({ onDone }) {
  const [title, setTitle] = React.useState("");
  const [url, setUrl] = React.useState("https://");
  const [kind, setKind] = React.useState(RESOURCE_KINDS[0]);
  const [tags, setTags] = React.useState("");
  const act = useAction();
  const save = (e) => { e.preventDefault(); act.run(async () => onDone(await cm.addResource({ title, url, kind, tags: parseTags(tags) }))); };
  return (
    <form className="cm-card cm-col" onSubmit={save}>
      <h4 className="cm-h">Share a resource</h4>
      <input value={title} onChange={(e) => setTitle(e.target.value)} placeholder="Title" aria-label="Title" maxLength={150} />
      <input value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://…" aria-label="Link" />
      <div className="row gap wrap">
        <select value={kind} onChange={(e) => setKind(e.target.value)} aria-label="Kind">{RESOURCE_KINDS.map((k) => <option key={k}>{k}</option>)}</select>
        <input className="grow" value={tags} onChange={(e) => setTags(e.target.value)} placeholder="Tags, e.g. ssrf, tools" aria-label="Tags" />
      </div>
      <ErrorNote error={act.error} />
      <div className="row gap">
        <button className="primary" type="submit" disabled={act.busy}>Share</button>
        <button type="button" onClick={() => onDone(null)}>Cancel</button>
        <span className="muted small">https links only.</span>
      </div>
    </form>
  );
}
