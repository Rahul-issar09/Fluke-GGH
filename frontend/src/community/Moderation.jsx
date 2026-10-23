// Moderator queue: reported items, grouped per item. Dismiss keeps it; Remove deletes it.
// Only moderators see this tab, and the data layer refuses everyone else.
import React from "react";
import { Badge, Loading, useLoad } from "../components/ui.jsx";
import * as cm from "./api.js";
import { useCommunity } from "./context.js";
import { Avatar, timeAgo } from "./parts.jsx";
import { ErrorNote, useAction } from "./widgets.jsx";

export default function Moderation() {
  const { user, version, go } = useCommunity();
  const { data, error, reload } = useLoad(() => (user?.moderator ? cm.listReports() : Promise.resolve(null)), [user?.id, version]);
  const act = useAction();
  if (!user?.moderator) return <div className="empty">Moderators only.</div>;
  if (error) return <ErrorNote error={error} />;
  if (!data) return <Loading />;

  const resolve = (g, action) => {
    if (action === "remove" && !window.confirm(`Remove this ${g.kind}? This cannot be undone.`)) return;
    act.run(async () => { await cm.resolveReport(g.id, action); reload(); });
  };

  return (
    <div className="cm-col">
      <div className="muted small">{data.length} item{data.length === 1 ? "" : "s"} waiting for review.</div>
      <ErrorNote error={act.error} />
      {data.length === 0 && <div className="empty">The queue is empty.</div>}
      {data.map((g) => (
        <div key={g.id} className="cm-card cm-col cm-gap-sm">
          <div className="row gap wrap">
            <Badge kind="warn">{g.count} report{g.count === 1 ? "" : "s"}</Badge>
            <Badge kind="muted">{g.kind}</Badge>
            {g.reasons.map((r) => <span key={r} className="cm-tag">{r}</span>)}
            <span className="muted small">by {g.reporters.join(", ")} · {timeAgo(g.createdAt)}</span>
          </div>
          {g.target.exists ? (
            <div className="cm-mod-target">
              <span className="row gap"><Avatar user={g.target.author} size={22} /><strong>{g.target.author.name}</strong></span>
              <div>{g.target.excerpt}</div>
              <button type="button" className="link small" onClick={() => go(g.target.link)}>Open in context</button>
            </div>
          ) : <div className="muted small">The item no longer exists.</div>}
          <div className="row gap">
            <button type="button" onClick={() => resolve(g, "dismiss")} disabled={act.busy}>Dismiss</button>
            {g.target.exists && <button type="button" className="cm-danger" onClick={() => resolve(g, "remove")} disabled={act.busy}>Remove {g.kind}</button>}
          </div>
        </div>
      ))}
    </div>
  );
}
