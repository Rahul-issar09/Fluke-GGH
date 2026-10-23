// Cheat sheets: "Don't / Do" code pairs per language and topic, with copy buttons and the safe
// libraries to use. Search across all sheets; Print gives a clean, print-friendly page.
import React from "react";
import { Badge } from "../components/ui.jsx";
import { Code, WithContent, useContent } from "./parts.jsx";

export default function Cheatsheets({ filter }) {
  const sheets = useContent("cheatsheets");
  return (
    <WithContent state={sheets} what="The cheat sheets">
      {(data) => <SheetsBody data={data} filter={filter} />}
    </WithContent>
  );
}

const haystack = (s) =>
  [s.title, s.summary, s.lang, s.topic, s.owasp, s.cwe, ...(s.safe_apis || []),
    ...(s.pairs || []).flatMap((p) => [p.dont, p.do, p.note])].filter(Boolean).join(" ").toLowerCase();

function SheetsBody({ data, filter }) {
  const items = data.items || [];
  const topics = data.topics || [];
  const langs = [...new Set(items.map((s) => s.lang))];
  const [lang, setLang] = React.useState("");
  const [topic, setTopic] = React.useState(topics.some((t) => t.id === filter) ? filter : "");
  const [q, setQ] = React.useState("");

  const needle = q.trim().toLowerCase();
  const shown = items.filter((s) => (!lang || s.lang === lang) && (!topic || s.topic === topic) && (!needle || haystack(s).includes(needle)));
  const topicTitle = (id) => topics.find((t) => t.id === id)?.title || id;

  return (
    <div className="lr-sheets">
      <div className="lr-filters lr-no-print">
        <select value={lang} onChange={(e) => setLang(e.target.value)} aria-label="Language">
          <option value="">All languages</option>
          {langs.map((l) => <option key={l} value={l}>{l}</option>)}
        </select>
        <select value={topic} onChange={(e) => setTopic(e.target.value)} aria-label="Topic">
          <option value="">All topics</option>
          {topics.map((t) => <option key={t.id} value={t.id}>{t.title}</option>)}
        </select>
        <input className="grow" placeholder="Search all sheets: parameterized, bcrypt, path…" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Search" />
        <button onClick={() => window.print()}>Print</button>
      </div>
      <div className="muted small lr-no-print">{shown.length} sheet{shown.length === 1 ? "" : "s"}</div>
      {shown.length === 0 && <div className="empty">No sheet matches.</div>}
      {shown.map((s) => (
        <article key={s.id} className="lr-sheet">
          <div className="row gap wrap">
            <h3 className="lr-h">{s.title}</h3>
            <Badge kind="info">{s.lang}</Badge>
            <span className="small muted">{topicTitle(s.topic)}{s.cwe ? ` · ${s.cwe}` : ""}</span>
          </div>
          {s.summary && <p>{s.summary}</p>}
          {(s.pairs || []).map((p, i) => (
            <div key={i} className="lr-pair">
              <Code code={p.dont} label="Don't ✗" tone="dont" />
              <Code code={p.do} label="Do ✓" tone="do" />
              {p.note && <div className="small muted lr-pair-note">{p.note}</div>}
            </div>
          ))}
          {(s.safe_apis || []).length > 0 && (
            <div className="row gap wrap small">
              <span className="muted">Safe to use:</span>
              {s.safe_apis.map((a) => <code key={a} className="lr-chip">{a}</code>)}
            </div>
          )}
        </article>
      ))}
    </div>
  );
}
