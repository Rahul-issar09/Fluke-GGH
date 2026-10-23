// Fix-it practice: edit vulnerable code in the browser, then run the challenge's pattern checks.
// Hints unlock one at a time; the solution appears after two failed tries. Completed challenges
// are remembered in this browser. "Practice this" links come from your latest scan's findings.
import React from "react";
import { Badge } from "../components/ui.jsx";
import { CATEGORY_NAMES } from "./content.js";
import { BackendNote, Code, WithContent, useAsync, useContent } from "./parts.jsx";
import { backendHint, loadLatestScan } from "./scans.js";

const SOLUTION_AFTER = 2; // failed tries before the solution is shown

/** Run a challenge's checks on some code: [{ label, pass }]. A "must" pattern has to match, a "must_not" must not. */
export function runChecks(challenge, code) {
  return challenge.checks.map((check) => {
    let hit;
    try {
      hit = new RegExp(check.regex, "m").test(code);
    } catch {
      return { label: check.label, pass: false };
    }
    return { label: check.label, pass: check.type === "must_not" ? !hit : hit };
  });
}

export default function Practice({ filter, progress, onProgress }) {
  const challenges = useContent("challenges");
  return (
    <WithContent state={challenges} what="The practice challenges">
      {(data) => <PracticeBody items={data.items || []} filter={filter} progress={progress} onProgress={onProgress} />}
    </WithContent>
  );
}

function PracticeBody({ items, filter, progress, onProgress }) {
  const [category, setCategory] = React.useState(filter || "");
  const shown = category ? items.filter((c) => c.owasp === category) : items;
  const [selected, setSelected] = React.useState((shown[0] || items[0])?.id || null);
  const challenge = items.find((c) => c.id === selected);
  const done = progress.challenges || {};

  const pick = (cat) => {
    setCategory(cat);
    const first = items.find((c) => !cat || c.owasp === cat);
    if (first) setSelected(first.id);
  };

  return (
    <div className="lr-stack">
      <FromYourScan items={items} onPick={pick} />
      <div className="split lr-split">
        <div>
          <div className="row gap wrap lr-filters">
            <select value={category} onChange={(e) => pick(e.target.value)} aria-label="Category">
              <option value="">All categories</option>
              {[...new Set(items.map((c) => c.owasp))].sort().map((k) => <option key={k} value={k}>{k} · {CATEGORY_NAMES[k] || k}</option>)}
            </select>
            <span className="muted small">{Object.keys(done).filter((k) => done[k]).length} of {items.length} completed</span>
          </div>
          <div className="lr-cards">
            {shown.map((c) => (
              <button key={c.id} className={`lr-card ${c.id === selected ? "lr-card-active" : ""}`} onClick={() => setSelected(c.id)}>
                <span className="row gap wrap">
                  <strong>{c.title}</strong>
                  {done[c.id] && <Badge kind="ok">done</Badge>}
                </span>
                <span className="small muted">{c.owasp} · {c.lang} · {c.difficulty}</span>
              </button>
            ))}
          </div>
        </div>
        <div className="detail-pane">
          {challenge ? (
            <Challenge key={challenge.id} challenge={challenge}
              onSolved={() => onProgress({ challenges: { ...done, [challenge.id]: true } })} />
          ) : <div className="empty">Pick a challenge.</div>}
        </div>
      </div>
    </div>
  );
}

function FromYourScan({ items, onPick }) {
  const scan = useAsync(loadLatestScan);
  if (scan.loading) return null;
  if (scan.error) return <BackendNote text={`${backendHint(scan.error)} "Practice this" links need your latest scan.`} onRetry={scan.run} />;
  const found = new Set((scan.data?.findings || []).filter((f) => f.state !== "resolved").map((f) => f.owasp));
  const cats = [...new Set(items.map((c) => c.owasp))].filter((k) => found.has(k)).sort();
  if (!cats.length) return null;
  return (
    <div className="lr-note">
      <span>From your latest scan <span className="mono">{scan.data.scan.id}</span>:</span>
      <span className="row gap wrap">
        {cats.map((k) => <button key={k} onClick={() => onPick(k)}>Practice this: {k} · {CATEGORY_NAMES[k] || k}</button>)}
      </span>
    </div>
  );
}

function Challenge({ challenge, onSolved }) {
  const [code, setCode] = React.useState(challenge.code);
  const [results, setResults] = React.useState(null);
  const [failed, setFailed] = React.useState(0);
  const [hints, setHints] = React.useState(0);
  const [showSolution, setShowSolution] = React.useState(false);
  const passed = results && results.every((r) => r.pass);

  const run = () => {
    const r = runChecks(challenge, code);
    setResults(r);
    if (r.every((x) => x.pass)) onSolved();
    else setFailed((n) => n + 1);
  };
  const reset = () => { setCode(challenge.code); setResults(null); };
  // Tab inserts four spaces instead of leaving the editor
  const onKeyDown = (e) => {
    if (e.key !== "Tab") return;
    e.preventDefault();
    const el = e.target;
    const { selectionStart: a, selectionEnd: b } = el;
    const next = code.slice(0, a) + "    " + code.slice(b);
    setCode(next);
    requestAnimationFrame(() => { el.selectionStart = el.selectionEnd = a + 4; });
  };

  return (
    <div className="lr-detail">
      <div className="row gap wrap">
        <h3 className="lr-h">{challenge.title}</h3>
        <Badge kind="info">{challenge.owasp}</Badge>
        <span className="small muted">{challenge.lang} · {challenge.difficulty}</span>
      </div>
      <p>{challenge.task}</p>
      <textarea className="lr-editor" value={code} onChange={(e) => setCode(e.target.value)} onKeyDown={onKeyDown}
        spellCheck={false} rows={Math.min(24, Math.max(8, code.split("\n").length + 2))} aria-label="Code editor" />
      <div className="row gap">
        <button className="primary" onClick={run}>Run checks</button>
        <button onClick={reset}>Reset code</button>
        {challenge.hints?.length > 0 && hints < challenge.hints.length && (
          <button onClick={() => setHints(hints + 1)}>Show hint ({challenge.hints.length - hints} left)</button>
        )}
      </div>
      {results && (
        <ul className="lr-results">
          {results.map((r) => <li key={r.label} className={r.pass ? "lr-pass" : "lr-fail"}>{r.pass ? "PASS" : "FAIL"} - {r.label}</li>)}
        </ul>
      )}
      {passed && <div className="answer">All checks pass. Solved!</div>}
      {hints > 0 && (
        <ol className="lr-hints">{challenge.hints.slice(0, hints).map((h, i) => <li key={i}>{h}</li>)}</ol>
      )}
      {!passed && failed >= SOLUTION_AFTER && (
        showSolution
          ? <Code code={challenge.solution} label="A solution" tone="do" />
          : <button onClick={() => setShowSolution(true)}>Show the solution ({failed} failed tries)</button>
      )}
      {!passed && failed > 0 && failed < SOLUTION_AFTER && (
        <div className="muted small">The solution unlocks after {SOLUTION_AFTER} failed tries.</div>
      )}
    </div>
  );
}
