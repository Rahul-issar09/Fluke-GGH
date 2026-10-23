// Pieces shared by the Community screens: errors (with the secret guard's block), tags, author line,
// votes, report button, image picker, finding picker and code view.
import React from "react";
import { api } from "../api.js";
import { Badge } from "../components/ui.jsx";
import * as cm from "./api.js";
import { useCommunity } from "./context.js";
import { MAX_IMAGES, readImageFile } from "./images.js";
import { Avatar, timeAgo } from "./parts.jsx";
import { redactFinding } from "./redact.js";
import { REPORT_REASONS } from "./types.js";

/** run(fn) catches the error for display; busy is true while fn runs */
export function useAction() {
  const [busy, setBusy] = React.useState(false);
  const [error, setError] = React.useState(null);
  const run = React.useCallback(async (fn) => {
    setBusy(true);
    setError(null);
    try {
      return await fn();
    } catch (err) {
      setError(err);
      return undefined;
    } finally {
      setBusy(false);
    }
  }, []);
  return { busy, error, setError, run };
}

/** "SECRET_FOUND" is a hard block: the UI never offers to post anyway. */
export function ErrorNote({ error }) {
  if (!error) return null;
  if (error.code === "SECRET_FOUND") {
    return (
      <div className="cm-error cm-secret" role="alert">
        <strong>Blocked: this looks like a live secret.</strong> Remove it before posting, and rotate it if it was real.
        <ul>{(error.hits || []).map((h, i) => <li key={i}>Line {h.line}: {h.type} <span className="mono">({h.preview})</span></li>)}</ul>
      </div>
    );
  }
  return <div className="cm-error" role="alert">{error.message || "Something went wrong."}</div>;
}

/** "a, b c" -> ["a", "b", "c"] */
export const parseTags = (text) => String(text || "").split(/[\s,]+/).map((t) => t.trim().replace(/^#/, "").toLowerCase()).filter(Boolean);

export function Tags({ tags, onTag }) {
  if (!tags?.length) return null;
  return (
    <span className="cm-tags">
      {tags.map((t) => (onTag ? <button key={t} type="button" className="cm-tag" onClick={() => onTag(t)}>#{t}</button> : <span key={t} className="cm-tag">#{t}</span>))}
    </span>
  );
}

export function AuthorLine({ user, at, children }) {
  const { go } = useCommunity();
  return (
    <div className="cm-author">
      <Avatar user={user} size={30} />
      <div className="cm-author-text">
        <span>
          <button type="button" className="link cm-name" onClick={() => go(`u/${user.name}`)}>{user.name}</button>
          <span className="muted small"> · {user.reputation} rep{user.moderator ? " · moderator" : ""}</span>
        </span>
        {at && <span className="muted small">{timeAgo(at)}{children}</span>}
      </div>
    </div>
  );
}

export function FindingCard({ finding }) {
  if (!finding) return null;
  return (
    <div className="cm-finding">
      <div className="row gap wrap">
        <Badge kind="info">{finding.owasp || "finding"}</Badge>
        <Badge kind={finding.state}>{finding.state}</Badge>
        <span className="mono small">{finding.category}</span>
        <span className="muted small">from a scan · details hidden</span>
      </div>
      <div className="cm-finding-sum">{finding.summary}</div>
    </div>
  );
}

export function CodeView({ code }) {
  const [copied, setCopied] = React.useState(false);
  const copy = async () => {
    try { await navigator.clipboard.writeText(code.source); setCopied(true); setTimeout(() => setCopied(false), 1500); } catch { /* clipboard blocked */ }
  };
  return (
    <div className="cm-codeview">
      <div className="cm-codeview-head"><span className="mono small">{code.lang}</span><button type="button" className="link small" onClick={copy}>{copied ? "Copied" : "Copy"}</button></div>
      <pre className="cm-pre">{code.source}</pre>
    </div>
  );
}

/** up / down vote. myVote is -1, 0 or 1; pressing the same arrow again clears the vote. */
export function VoteBox({ votes, myVote, own, onVote }) {
  const { requireAuth } = useCommunity();
  const press = (v) => requireAuth(() => onVote(myVote === v ? 0 : v));
  const why = own ? "You cannot vote on your own post" : undefined;
  return (
    <div className="cm-vote">
      <button type="button" className={myVote === 1 ? "cm-voted" : ""} disabled={own} title={why || "Useful"} aria-label="Vote up" onClick={() => press(1)}>▲</button>
      <strong>{votes}</strong>
      <button type="button" className={myVote === -1 ? "cm-voted" : ""} disabled={own} title={why || "Not useful"} aria-label="Vote down" onClick={() => press(-1)}>▼</button>
    </div>
  );
}

export function ReportButton({ kind, id }) {
  const { requireAuth } = useCommunity();
  const [open, setOpen] = React.useState(false);
  const [reason, setReason] = React.useState(REPORT_REASONS[0]);
  const [done, setDone] = React.useState(false);
  const act = useAction();
  if (done) return <span className="muted small">Reported. A moderator will look at it.</span>;
  if (!open) return <button type="button" className="link small cm-report" onClick={() => requireAuth(() => setOpen(true))}>Report</button>;
  const send = () => act.run(async () => { await cm.report(kind, id, reason); setDone(true); });
  return (
    <span className="cm-report-box">
      <select value={reason} onChange={(e) => setReason(e.target.value)} aria-label="Reason">
        {REPORT_REASONS.map((r) => <option key={r} value={r}>{r}</option>)}
      </select>
      <button type="button" onClick={send} disabled={act.busy}>Send report</button>
      <button type="button" className="link small" onClick={() => setOpen(false)}>Cancel</button>
      <ErrorNote error={act.error} />
    </span>
  );
}

/** Picks images, checked by their real bytes (PNG, JPEG or WebP; 5 MB each; no SVG). */
export function ImagePicker({ images, onChange, max = MAX_IMAGES }) {
  const [error, setError] = React.useState("");
  const add = async (e) => {
    const files = [...(e.target.files || [])];
    e.target.value = "";
    setError("");
    const out = [...images];
    for (const f of files) {
      if (out.length >= max) { setError(`At most ${max} image${max === 1 ? "" : "s"}.`); break; }
      try { out.push(await readImageFile(f)); } catch (err) { setError(err.message); }
    }
    onChange(out);
  };
  return (
    <div className="cm-images-pick">
      <div className="cm-thumbs">
        {images.map((src, i) => (
          <span key={i} className="cm-thumb">
            <img src={src} alt={`image ${i + 1}`} />
            <button type="button" aria-label="Remove image" onClick={() => onChange(images.filter((_, j) => j !== i))}>×</button>
          </span>
        ))}
      </div>
      {images.length < max && (
        <label className="button cm-file">
          Add image{max > 1 ? "s" : ""}
          <input type="file" accept="image/png,image/jpeg,image/webp" multiple={max > 1} onChange={add} hidden />
        </label>
      )}
      <span className="muted small"> PNG, JPEG or WebP · up to 5 MB · {max === 1 ? "one cover image" : `up to ${max}`}</span>
      {error && <div className="cm-error">{error}</div>}
    </div>
  );
}

/** Lets you pick a finding from your own scans (read-only API calls) and shows exactly what will be shared. */
export function FindingPicker({ value, onChange }) {
  const [scans, setScans] = React.useState(null);
  const [scanId, setScanId] = React.useState("");
  const [findings, setFindings] = React.useState(null);
  const [error, setError] = React.useState("");

  React.useEffect(() => {
    let live = true;
    api.scans(50)
      .then((list) => { if (!live) return; const done = list.filter((s) => s.status === "completed" || s.status === "awaiting_approval"); setScans(done); if (done[0]) setScanId(done[0].id); })
      .catch(() => live && setError("The AEGIS backend is not reachable, so your scans cannot be listed. Start it and try again."));
    return () => { live = false; };
  }, []);
  React.useEffect(() => {
    if (!scanId) return undefined;
    let live = true;
    setFindings(null);
    api.findings(scanId).then((f) => live && setFindings(f)).catch(() => live && setError("Could not read this scan's findings."));
    return () => { live = false; };
  }, [scanId]);

  if (error) return <div className="warning small">{error}</div>;
  if (!scans) return <div className="muted small">Reading your scans…</div>;
  if (!scans.length) return <div className="muted small">No finished scans yet. Run a scan first.</div>;
  return (
    <div className="cm-finding-pick">
      <div className="row gap wrap">
        <select value={scanId} onChange={(e) => { setScanId(e.target.value); onChange(null); }} aria-label="Scan">
          {scans.map((s) => <option key={s.id} value={s.id}>{s.id} · {s.findings} findings</option>)}
        </select>
        <select value={value?.id || ""} onChange={(e) => { const f = (findings || []).find((x) => x.id === e.target.value); onChange(f ? redactFinding(f, scanId) : null); }} aria-label="Finding" disabled={!findings}>
          <option value="">{findings ? "Pick a finding…" : "Loading…"}</option>
          {(findings || []).map((f) => <option key={f.id} value={f.id}>{f.owasp || "?"} · {f.state} · {(f.title || f.type).slice(0, 80)}</option>)}
        </select>
      </div>
      {value && (
        <div className="cm-share-preview">
          <div className="muted small">This is exactly what will be shared (paths shortened, hosts hidden, no evidence or code):</div>
          <FindingCard finding={value} />
        </div>
      )}
    </div>
  );
}

export function LoadMore({ cursor, busy, onMore }) {
  if (!cursor) return null;
  return <div className="cm-more"><button type="button" onClick={onMore} disabled={busy}>{busy ? "Loading…" : "Load more"}</button></div>;
}

/** debounced value: changes `ms` after the input stops changing */
export function useDebounced(value, ms = 300) {
  const [v, setV] = React.useState(value);
  React.useEffect(() => {
    const t = setTimeout(() => setV(value), ms);
    return () => clearTimeout(t);
  }, [value, ms]);
  return v;
}
