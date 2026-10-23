// Breach case studies: what happened, the root cause, the impact, whether AEGIS would catch it,
// lessons and sources - and a "Seen in your scans" badge when the same bug type is in your scans.
import React from "react";
import { Badge } from "../components/ui.jsx";
import { CATEGORY_NAMES, CHEAT_TOPICS, QUIZ_CATEGORIES } from "./content.js";
import { BackendNote, WithContent, useAsync, useContent } from "./parts.jsx";
import { backendHint, scanCategories } from "./scans.js";

export default function Cases({ onTab }) {
  const cases = useContent("cases");
  return (
    <WithContent state={cases} what="The case studies">
      {(data) => <CasesBody data={data} onTab={onTab} />}
    </WithContent>
  );
}

function CasesBody({ data, onTab }) {
  const items = data.items || [];
  const [selected, setSelected] = React.useState(items[0]?.id || null);
  const seen = useAsync(() => scanCategories(10));
  const seenIn = (c) => seen.data?.get(c.owasp) || [];
  const item = items.find((c) => c.id === selected);

  return (
    <div>
      {data.note && <div className="muted small lr-snapshot">{data.note}</div>}
      {seen.error && <BackendNote text={`${backendHint(seen.error)} The "Seen in your scans" badges need it.`} onRetry={seen.run} />}
      <div className="split lr-split">
        <div className="lr-cards">
          {items.map((c) => (
            <button key={c.id} className={`lr-card ${c.id === selected ? "lr-card-active" : ""}`} onClick={() => setSelected(c.id)}>
              <span className="row gap wrap">
                <strong>{c.title}</strong>
                <span className="muted small">{c.year}</span>
                <span className="mono small lr-accent">{c.owasp}</span>
                {seenIn(c).length > 0 && <Badge kind="warn">seen in your scans</Badge>}
              </span>
              <span className="small muted">{c.summary}</span>
            </button>
          ))}
        </div>
        <div className="detail-pane">
          {item ? <CaseDetail c={item} seenIn={seenIn(item)} onTab={onTab} /> : <div className="empty">Pick a case.</div>}
        </div>
      </div>
    </div>
  );
}

function CaseDetail({ c, seenIn, onTab }) {
  return (
    <div className="lr-detail">
      <div className="row gap wrap">
        <h3 className="lr-h">{c.title} ({c.year})</h3>
        <Badge kind="info">{c.owasp} · {CATEGORY_NAMES[c.owasp] || "OWASP"}</Badge>
        {c.cwe && <span className="mono small">{c.cwe}</span>}
      </div>
      {seenIn.length > 0 && (
        <div className="warning small">The same bug type ({c.owasp}) appears in your scans: <span className="mono">{seenIn.join(", ")}</span></div>
      )}
      <p>{c.summary}</p>
      {(c.timeline || []).length > 0 && (
        <>
          <h4>Timeline</h4>
          <ul className="lr-timeline">{c.timeline.map((t, i) => <li key={i}><span className="mono small">{t.when}</span> - {t.what}</li>)}</ul>
        </>
      )}
      {c.root_cause && <><h4>Root cause</h4><p>{c.root_cause}</p></>}
      {c.impact && <><h4>Impact</h4><p>{c.impact}</p></>}
      {c.aegis_check && <><h4>Would AEGIS catch it?</h4><div className="answer">{c.aegis_check}</div></>}
      {(c.lessons || []).length > 0 && (
        <>
          <h4>Lessons</h4>
          <ul>{c.lessons.map((l, i) => <li key={i}>{l}</li>)}</ul>
        </>
      )}
      {(c.sources || []).length > 0 && (
        <>
          <h4>Sources</h4>
          <ul className="small">{c.sources.map((s) => <li key={s}><a href={s} target="_blank" rel="noreferrer">{s}</a></li>)}</ul>
        </>
      )}
      <div className="row gap lr-links">
        {CHEAT_TOPICS.includes(c.owasp) && <button className="link" onClick={() => onTab("cheatsheets", c.owasp)}>Cheat sheet</button>}
        <button className="link" onClick={() => onTab("practice", c.owasp)}>Practice</button>
        {QUIZ_CATEGORIES.includes(c.owasp) && <button className="link" onClick={() => onTab("quizzes", c.owasp)}>Quiz</button>}
      </div>
    </div>
  );
}
