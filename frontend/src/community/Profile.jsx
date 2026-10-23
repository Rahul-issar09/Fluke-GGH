// Profiles and reputation: anyone's profile at #community/u/<name>; yours at #community/profile.
// Reputation and badges are computed by the data layer; the rules are shown so people know how to earn them.
import React from "react";
import { Badge, Loading, useLoad } from "../components/ui.jsx";
import * as cm from "./api.js";
import { useCommunity } from "./context.js";
import { plainText } from "./Markdown.jsx";
import { Avatar, timeAgo } from "./parts.jsx";

const BADGES = [
  ["First post", "Shared a first post"],
  ["First answer", "Answered a question"],
  ["Helper", "5 accepted answers"],
  ["Bug hunter", "Shared 3 findings from scans"],
];
const POINTS = "+15 accepted answer · +10 answer upvote · +5 question upvote · +2 post like · −2 per downvote";

// rest: [] (my profile) or ["u", name]
export default function Profile({ rest, onSignIn }) {
  const { user } = useCommunity();
  const name = rest[0] === "u" && rest[1] ? decodeURIComponent(rest[1]) : user?.name;
  if (!name) {
    return (
      <div className="empty">
        <div className="cm-soon-title">Sign in to see your profile</div>
        <button type="button" className="primary" onClick={onSignIn}>Sign in</button>
      </div>
    );
  }
  return <ProfileView key={name} name={name} />;
}

function ProfileView({ name }) {
  const { user, version, go } = useCommunity();
  const { data, error, loading } = useLoad(() => cm.getProfile(name), [name, version]);
  const [tab, setTab] = React.useState("posts");
  if (loading && !data) return <Loading />;
  if (error) return <div className="empty">{error.code === "NOT_FOUND" ? `There is no member called ${name}.` : error.message}</div>;
  const p = data;
  const me = user && user.id === p.user.id;
  const lists = { posts: p.posts, questions: p.questions, answers: p.answers };

  return (
    <div className="cm-col">
      <div className="cm-card cm-profile">
        <Avatar user={p.user} size={64} />
        <div className="cm-col cm-gap-sm">
          <div className="row gap wrap">
            <span className="cm-profile-name">{p.user.name}</span>
            {p.user.moderator && <Badge kind="info">moderator</Badge>}
            {me && <span className="muted small">(you)</span>}
          </div>
          <div className="muted small">Joined {new Date(p.user.joinedAt).toLocaleDateString()}</div>
          <div><span className="cm-rep">{p.user.reputation}</span> <span className="muted">reputation</span></div>
          <div className="muted small">{POINTS}</div>
          <div className="cm-badges">
            {BADGES.map(([b, how]) => (
              <span key={b} className={p.user.badges.includes(b) ? "cm-badge cm-badge-on" : "cm-badge"} title={how}>
                {p.user.badges.includes(b) ? "★" : "☆"} {b} <span className="muted small">· {how}</span>
              </span>
            ))}
          </div>
          <div className="muted small">{p.stats.posts} posts · {p.stats.questions} questions · {p.stats.answers} answers ({p.stats.acceptedAnswers} accepted)</div>
        </div>
      </div>

      <div className="cm-seg" role="tablist" aria-label="Activity">
        {[["posts", "Posts"], ["questions", "Questions"], ["answers", "Answers"]].map(([k, v]) => (
          <button key={k} type="button" role="tab" aria-selected={tab === k} className={tab === k ? "cm-seg-on" : ""} onClick={() => setTab(k)}>{v} ({lists[k].length})</button>
        ))}
      </div>
      {lists[tab].length === 0 && <div className="empty">Nothing here yet.</div>}
      {tab === "posts" && p.posts.map((x) => (
        <button key={x.id} type="button" className="cm-card cm-line" onClick={() => go(`post/${x.id}`)}>
          <span className="muted small">{x.type} · {timeAgo(x.createdAt)} · ♥ {x.likeCount} · 💬 {x.commentCount}</span>
          <span>{x.title || (x.type === "finding" ? x.finding?.summary : x.type === "repost" ? `Reposted: ${x.repostOf?.title || plainText(x.repostOf?.body || "", 100) || "a removed post"}` : plainText(x.body, 140)) || `${x.code?.lang || ""} snippet`}</span>
        </button>
      ))}
      {tab === "questions" && p.questions.map((x) => (
        <button key={x.id} type="button" className="cm-card cm-line" onClick={() => go(`qa/${x.id}`)}>
          <span className="muted small">{x.votes} votes · {x.answerCount} answers{x.acceptedAnswerId ? " · solved" : ""} · {timeAgo(x.createdAt)}</span>
          <span>{x.title}</span>
        </button>
      ))}
      {tab === "answers" && p.answers.map((x) => (
        <button key={x.id} type="button" className="cm-card cm-line" onClick={() => go(`qa/${x.questionId}`)}>
          <span className="muted small">{x.votes} votes{x.accepted ? " · ✓ accepted" : ""} · {timeAgo(x.createdAt)}</span>
          <span>{x.questionTitle || "a question"}</span>
        </button>
      ))}
    </div>
  );
}
