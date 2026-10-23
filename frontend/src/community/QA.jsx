// Q&A: anyone can read. Signed-in people ask (with code, tags, a "Beginner question" flag and an optional
// finding), answer, vote up/down, and the asker accepts the best answer. Similar questions show while you
// type a title. An optional AI draft from the local model is shown apart from human answers, marked "verify".
import React from "react";
import { Badge, Loading, useLoad } from "../components/ui.jsx";
import { AI_MODEL, draftAnswer } from "./ai.js";
import * as cm from "./api.js";
import { useCommunity } from "./context.js";
import { Markdown } from "./Markdown.jsx";
import { timeAgo } from "./parts.jsx";
import {
  AuthorLine, ErrorNote, FindingCard, FindingPicker, LoadMore, ReportButton, Tags, VoteBox,
  parseTags, useAction, useDebounced,
} from "./widgets.jsx";

const AI_TIMEOUT_MS = 180_000;

// "#community/qa" list · "#community/qa/ask" form · "#community/qa/q-3" one question
export default function QA({ rest }) {
  if (rest[0] === "ask") return <AskForm />;
  if (rest[0]) return <QuestionView key={rest[0]} id={rest[0]} />;
  return <QuestionList />;
}

function QuestionList() {
  const { version, requireAuth, go } = useCommunity();
  const [tab, setTab] = React.useState("newest");
  const [tag, setTag] = React.useState("");
  const [q, setQ] = React.useState("");
  const query = useDebounced(q);
  const [items, setItems] = React.useState(null);
  const [cursor, setCursor] = React.useState(null);
  const [busy, setBusy] = React.useState(false);
  const [error, setError] = React.useState(null);
  const ticket = React.useRef(0);

  const load = React.useCallback(async (from) => {
    const mine = ++ticket.current;
    setBusy(true);
    setError(null);
    try {
      const r = await cm.listQuestions({ tab, tag, q: query.trim(), cursor: from || undefined });
      if (mine !== ticket.current) return;
      setItems((old) => (from ? [...(old || []), ...r.items] : r.items));
      setCursor(r.nextCursor);
    } catch (err) {
      if (mine === ticket.current) setError(err);
    } finally {
      if (mine === ticket.current) setBusy(false);
    }
  }, [tab, tag, query]);
  React.useEffect(() => { load(null); }, [load, version]);

  return (
    <div className="cm-col">
      <div className="row between gap wrap">
        <div className="cm-seg" role="tablist" aria-label="Questions">
          {[["newest", "Newest"], ["unanswered", "Unanswered"], ["top", "Top"]].map(([k, v]) => (
            <button key={k} type="button" role="tab" aria-selected={tab === k} className={tab === k ? "cm-seg-on" : ""} onClick={() => setTab(k)}>{v}</button>
          ))}
        </div>
        <button type="button" className="primary" onClick={() => requireAuth(() => go("qa/ask"))}>Ask a question</button>
      </div>
      <div className="cm-filters">
        <input className="grow" value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search questions…" aria-label="Search questions" />
        {tag && <button type="button" className="cm-tag cm-tag-on" onClick={() => setTag("")} title="Clear tag filter">#{tag} ×</button>}
      </div>
      <ErrorNote error={error} />
      {items === null ? <Loading /> : items.length === 0 ? <div className="empty">No questions match.</div> : (
        <div className="cm-qlist">
          {items.map((x) => (
            <div key={x.id} className="cm-card cm-qrow">
              <div className="cm-qstats">
                <span><strong>{x.votes}</strong> votes</span>
                <span className={x.acceptedAnswerId ? "cm-answered cm-accepted" : x.answerCount ? "cm-answered" : ""}><strong>{x.answerCount}</strong> answers</span>
              </div>
              <div className="cm-qmain">
                <button type="button" className="link cm-qtitle" onClick={() => go(`qa/${x.id}`)}>{x.title}</button>
                <div className="row gap wrap">
                  {x.beginner && <Badge kind="ok">Beginner question</Badge>}
                  {x.finding && <Badge kind="info">finding attached</Badge>}
                  <Tags tags={x.tags} onTag={setTag} />
                  <span className="muted small">asked by {x.author.name} · {timeAgo(x.createdAt)}</span>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
      <LoadMore cursor={cursor} busy={busy} onMore={() => load(cursor)} />
    </div>
  );
}

function AskForm() {
  const { user, requireAuth, go } = useCommunity();
  const [title, setTitle] = React.useState("");
  const [body, setBody] = React.useState("");
  const [tags, setTags] = React.useState("");
  const [beginner, setBeginner] = React.useState(false);
  const [attach, setAttach] = React.useState(false);
  const [finding, setFinding] = React.useState(null);
  const [similar, setSimilar] = React.useState([]);
  const typed = useDebounced(title, 300);
  const act = useAction();

  React.useEffect(() => {
    if (typed.trim().length < 8) { setSimilar([]); return undefined; }
    let live = true;
    cm.similarQuestions(typed).then((r) => live && setSimilar(r)).catch(() => live && setSimilar([]));
    return () => { live = false; };
  }, [typed]);

  if (!user) {
    return (
      <div className="empty">
        <div className="cm-soon-title">Sign in to ask a question</div>
        <button type="button" className="primary" onClick={() => requireAuth(() => {})}>Sign in</button>
      </div>
    );
  }
  const submit = (e) => {
    e.preventDefault();
    act.run(async () => {
      const q = await cm.askQuestion({ title, body, tags: parseTags(tags), beginner, ...(attach && finding ? { finding } : {}) });
      go(`qa/${q.id}`);
    });
  };
  return (
    <form className="cm-card cm-col cm-ask" onSubmit={submit}>
      <div><button type="button" className="link" onClick={() => go("qa")}>← All questions</button></div>
      <h3 className="cm-h">Ask a question</h3>
      <label className="cm-field">Title
        <input value={title} onChange={(e) => setTitle(e.target.value)} placeholder="e.g. How do I stop IDOR when IDs are in the URL?" maxLength={150} />
        <span className="muted small">15-150 characters. Be specific.</span>
      </label>
      {similar.length > 0 && (
        <div className="cm-similar">
          <div className="small"><strong>Similar questions</strong>, maybe already answered:</div>
          <ul>{similar.map((s) => <li key={s.id}><button type="button" className="link" onClick={() => go(`qa/${s.id}`)}>{s.title}</button> <span className="muted small">{s.answerCount} answers · {s.votes} votes</span></li>)}</ul>
        </div>
      )}
      <label className="cm-field">Details
        <textarea rows={8} value={body} onChange={(e) => setBody(e.target.value)} placeholder={"What did you try? Paste code in a block:\n```python\n...\n```"} />
      </label>
      <label className="cm-field">Tags
        <input value={tags} onChange={(e) => setTags(e.target.value)} placeholder="1 to 5 tags, e.g. access-control, python" />
      </label>
      <label className="inline cm-check"><input type="checkbox" checked={beginner} onChange={(e) => setBeginner(e.target.checked)} /> Beginner question — new to security? Say so; nobody minds.</label>
      <label className="inline cm-check"><input type="checkbox" checked={attach} onChange={(e) => { setAttach(e.target.checked); if (!e.target.checked) setFinding(null); }} /> Attach a finding from my scan</label>
      {attach && <FindingPicker value={finding} onChange={setFinding} />}
      <ErrorNote error={act.error} />
      <div className="row gap">
        <button className="primary" type="submit" disabled={act.busy || (attach && !finding)}>{act.busy ? "Posting…" : "Post question"}</button>
        <span className="muted small">Questions are checked for API keys and tokens before they are saved.</span>
      </div>
    </form>
  );
}

function QuestionView({ id }) {
  const { user, version, go } = useCommunity();
  const { data, error, loading, reload } = useLoad(() => cm.getQuestion(id), [id, version]);
  const [q, setQ] = React.useState(null);
  const act = useAction();
  React.useEffect(() => { if (data) setQ(data); }, [data]);

  if ((loading && !q) || (!q && !error)) return <Loading />;
  if (error && !q) return <div className="cm-col"><div><button type="button" className="link" onClick={() => go("qa")}>← All questions</button></div><div className="empty">{error.code === "NOT_FOUND" ? "This question does not exist any more." : error.message}</div></div>;

  const asker = user && user.id === q.author.id;
  const voteQ = (v) => act.run(async () => { const r = await cm.voteQuestion(q.id, v); setQ({ ...q, ...r }); });
  const voteA = (aid, v) => act.run(async () => { const r = await cm.voteAnswer(aid, v); setQ({ ...q, answers: q.answers.map((a) => (a.id === aid ? { ...a, ...r } : a)) }); });
  const accept = (aid) => act.run(async () => { await cm.acceptAnswer(q.id, aid); reload(); });

  return (
    <div className="cm-col">
      <div><button type="button" className="link" onClick={() => go("qa")}>← All questions</button></div>
      <article className="cm-card cm-qa">
        <VoteBox votes={q.votes} myVote={q.myVote} own={asker} onVote={voteQ} />
        <div className="cm-qa-main">
          <h3 className="cm-post-title">{q.title}</h3>
          <div className="row gap wrap">
            {q.beginner && <Badge kind="ok">Beginner question</Badge>}
            <Tags tags={q.tags} />
          </div>
          <Markdown text={q.body} />
          {q.finding && <FindingCard finding={q.finding} />}
          <div className="cm-actions">
            <AuthorLine user={q.author} at={q.createdAt} />
            <span className="grow" />
            {!asker && <ReportButton kind="question" id={q.id} />}
          </div>
        </div>
      </article>
      <ErrorNote error={act.error} />

      <AiDraft question={q} />

      <h4 className="cm-h">{q.answers.length} answer{q.answers.length === 1 ? "" : "s"} from people</h4>
      {q.answers.map((a) => {
        const own = user && user.id === a.author.id;
        return (
          <article key={a.id} className={a.accepted ? "cm-card cm-qa cm-accepted-answer" : "cm-card cm-qa"}>
            <VoteBox votes={a.votes} myVote={a.myVote} own={own} onVote={(v) => voteA(a.id, v)} />
            <div className="cm-qa-main">
              {a.accepted && <div className="cm-accepted-label">✓ Accepted answer</div>}
              <Markdown text={a.body} />
              <div className="cm-actions">
                <AuthorLine user={a.author} at={a.createdAt} />
                <span className="grow" />
                {asker && !a.accepted && <button type="button" onClick={() => accept(a.id)}>Accept this answer</button>}
                {!own && <ReportButton kind="answer" id={a.id} />}
              </div>
            </div>
          </article>
        );
      })}
      <AnswerForm questionId={q.id} onDone={reload} />
    </div>
  );
}

function AnswerForm({ questionId, onDone }) {
  const { user, requireAuth } = useCommunity();
  const [body, setBody] = React.useState("");
  const act = useAction();
  const send = (e) => {
    e.preventDefault();
    requireAuth(() => act.run(async () => { await cm.addAnswer(questionId, body); setBody(""); onDone(); }));
  };
  return (
    <form className="cm-card cm-col" onSubmit={send}>
      <h4 className="cm-h">Your answer</h4>
      <textarea rows={6} value={body} onChange={(e) => setBody(e.target.value)} placeholder={user ? "Explain the fix. Markdown and ``` code blocks work." : "Sign in to answer."} onFocus={() => !user && requireAuth(() => {})} />
      <ErrorNote error={act.error} />
      <div><button className="primary" type="submit" disabled={act.busy || body.trim().length < 10}>Post answer</button></div>
    </form>
  );
}

// Shown apart from human answers; never saved, never scored.
function AiDraft({ question }) {
  const [state, setState] = React.useState({ status: "idle" });
  const ctrl = React.useRef(null);
  React.useEffect(() => () => ctrl.current?.abort(), []);

  const start = async () => {
    const c = new AbortController();
    ctrl.current = c;
    const timer = setTimeout(() => c.abort(), AI_TIMEOUT_MS);
    setState({ status: "running" });
    try {
      setState({ status: "done", text: await draftAnswer(question, c.signal) });
    } catch (err) {
      setState(err?.name === "AbortError" ? { status: "error", message: "The draft was stopped." } : { status: "error", message: err.message });
    } finally {
      clearTimeout(timer);
    }
  };

  return (
    <section className="cm-ai">
      <div className="row between gap wrap">
        <div>
          <strong>AI draft answer</strong> <Badge kind="warn">verify</Badge>
          <div className="muted small">Written by the local model {AI_MODEL} on this computer. Not a human answer: check it before you trust it. It is not saved and earns no points.</div>
        </div>
        {state.status === "running" ? (
          <button type="button" onClick={() => ctrl.current?.abort()}>Stop</button>
        ) : (
          <button type="button" onClick={start}>{state.status === "done" ? "Draft again" : "Draft an AI answer"}</button>
        )}
      </div>
      {state.status === "running" && <div className="muted small">The local model is writing a draft…</div>}
      {state.status === "error" && <div className="warning small">{state.message}</div>}
      {state.status === "done" && <div className="cm-ai-text"><Markdown text={state.text} /></div>}
    </section>
  );
}
