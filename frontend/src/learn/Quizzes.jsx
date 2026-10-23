// Quizzes: one per bug type (7 questions each), with an explanation after every answer. Best scores
// are saved in this browser; a wrong answer links to the right cheat sheet. "Quiz from my scan"
// mixes questions from the bug types found in your latest scan.
import React from "react";
import { Badge } from "../components/ui.jsx";
import { CATEGORY_NAMES } from "./content.js";
import { BackendNote, WithContent, useAsync, useContent } from "./parts.jsx";
import { backendHint, loadLatestScan } from "./scans.js";

const MIXED_SIZE = 10;

export default function Quizzes({ filter, progress, onProgress, onTab }) {
  const quizzes = useContent("quizzes");
  return (
    <WithContent state={quizzes} what="The quizzes">
      {(data) => <QuizzesBody questions={data.items || []} filter={filter} progress={progress} onProgress={onProgress} onTab={onTab} />}
    </WithContent>
  );
}

function shuffle(list) {
  const a = [...list];
  for (let i = a.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}

function QuizzesBody({ questions, filter, progress, onProgress, onTab }) {
  const categories = [...new Set(questions.map((q) => q.category))];
  // a link like #learn/quizzes/A01 opens that quiz directly
  const [run, setRun] = React.useState(() =>
    categories.includes(filter) ? { title: CATEGORY_NAMES[filter] || filter, category: filter, questions: questions.filter((q) => q.category === filter) } : null);
  const best = progress.quiz || {};

  const start = (category) => setRun({ title: CATEGORY_NAMES[category] || category, category, questions: questions.filter((q) => q.category === category) });
  const startMixed = (cats) => setRun({ title: "Quiz from your scan", category: null, questions: shuffle(questions.filter((q) => cats.includes(q.category))).slice(0, MIXED_SIZE) });

  const finish = (category, score) => {
    if (category && (best[category] == null || score > best[category])) onProgress({ quiz: { ...best, [category]: score } });
  };

  if (run) return <QuizRun key={`${run.title}-${run.questions.map((q) => q.id).join()}`} run={run} best={run.category ? best[run.category] : null} onFinish={finish} onBack={() => setRun(null)} onTab={onTab} />;

  return (
    <div className="lr-stack">
      <FromYourScan categories={categories} onStart={startMixed} />
      <div className="lr-tiles">
        {categories.map((c) => (
          <button key={c} className="lr-tile" onClick={() => start(c)}>
            <span className="lr-tile-title"><span className="mono lr-accent">{c}</span> · {CATEGORY_NAMES[c] || c}</span>
            <span className="lr-tile-text">{questions.filter((q) => q.category === c).length} questions</span>
            <span className="lr-tile-count">{best[c] != null ? <Badge kind={best[c] >= 60 ? "ok" : "warn"}>best {best[c]}%</Badge> : "not taken yet"}</span>
          </button>
        ))}
      </div>
    </div>
  );
}

function FromYourScan({ categories, onStart }) {
  const scan = useAsync(loadLatestScan);
  if (scan.loading) return null;
  if (scan.error) return <BackendNote text={`${backendHint(scan.error)} "Quiz from my scan" needs your latest scan.`} onRetry={scan.run} />;
  if (!scan.data?.scan) return null;
  const found = new Set(scan.data.findings.filter((f) => f.state !== "resolved").map((f) => f.owasp));
  const cats = categories.filter((c) => found.has(c));
  if (!cats.length) return null;
  return (
    <div className="lr-note">
      <span>Your latest scan <span className="mono">{scan.data.scan.id}</span> found: {cats.join(", ")}.</span>
      <button className="primary" onClick={() => onStart(cats)}>Quiz from my scan</button>
    </div>
  );
}

function QuizRun({ run, best, onFinish, onBack, onTab }) {
  const [index, setIndex] = React.useState(0);
  const [picked, setPicked] = React.useState(null);
  const [correct, setCorrect] = React.useState(0);
  const [done, setDone] = React.useState(false);
  const q = run.questions[index];
  const total = run.questions.length;

  const choose = (i) => {
    if (picked !== null) return;
    setPicked(i);
    if (i === q.answer) setCorrect((n) => n + 1);
  };
  const next = () => {
    if (index + 1 < total) {
      setIndex(index + 1);
      setPicked(null);
      return;
    }
    const score = Math.round((100 * correct) / total);
    setDone(true);
    onFinish(run.category, score);
  };

  if (done) {
    const score = Math.round((100 * correct) / total);
    return (
      <div className="lr-quiz">
        <h3 className="lr-h">{run.title}: {correct} of {total} ({score}%)</h3>
        {run.category && <div className="muted small">{best == null || score > best ? "New best score, saved in this browser." : `Your best is ${best}%.`}</div>}
        {score < 60 && <div className="warning small">Below 60% - this topic shows under "Weak areas" on the Overview until you improve it.</div>}
        <div className="row gap lr-links">
          <button onClick={onBack}>All quizzes</button>
          {run.category && <button className="link" onClick={() => onTab("cheatsheets", run.category)}>Read the cheat sheet</button>}
        </div>
      </div>
    );
  }

  return (
    <div className="lr-quiz">
      <div className="row between">
        <h3 className="lr-h">{run.title}</h3>
        <span className="muted small">Question {index + 1} of {total} · {correct} correct</span>
      </div>
      <p className="lr-question">{q.q}</p>
      <div className="lr-options">
        {q.options.map((opt, i) => {
          const state = picked === null ? "" : i === q.answer ? "lr-right" : i === picked ? "lr-wrong" : "lr-dim";
          return <button key={i} className={`lr-option ${state}`} onClick={() => choose(i)} disabled={picked !== null && state === "lr-dim"}>{opt}</button>;
        })}
      </div>
      {picked !== null && (
        <div className={picked === q.answer ? "answer" : "warning"}>
          <strong>{picked === q.answer ? "Correct." : "Not quite."}</strong> {q.explanation}
          {picked !== q.answer && q.cheatsheet_ref && (
            <div><button className="link" onClick={() => onTab("cheatsheets", q.cheatsheet_ref)}>Read the {q.cheatsheet_ref} cheat sheet</button></div>
          )}
        </div>
      )}
      <div className="row gap lr-links">
        <button onClick={onBack}>Quit</button>
        {picked !== null && <button className="primary" onClick={next}>{index + 1 < total ? "Next question" : "See my score"}</button>}
      </div>
    </div>
  );
}
