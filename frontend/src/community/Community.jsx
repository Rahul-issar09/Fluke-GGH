import React from "react";
import { Tabs, useLoad } from "../components/ui.jsx";
import * as cm from "./api.js";
import "./community.css";
import { CommunityContext } from "./context.js";
import Feed from "./Feed.jsx";
import Jobs from "./Jobs.jsx";
import Moderation from "./Moderation.jsx";
import { Avatar, timeAgo } from "./parts.jsx";
import Profile from "./Profile.jsx";
import QA from "./QA.jsx";
import Resources from "./Resources.jsx";
import SignInModal from "./SignInModal.jsx";

const TABS = [
  ["feed", "Feed"],
  ["qa", "Q&A"],
  ["resources", "Resources"],
  ["jobs", "Jobs"],
  ["profile", "Profile"],
];
const MOD_TAB = ["mod", "Moderation"]; // shown to moderators only
const ALL_TABS = [...TABS, MOD_TAB];

// "#community/qa/q-3" -> { tab: "qa", rest: ["q-3"] }; "#community/post/p-1" belongs to the Feed and
// "#community/u/demo_ana" to Profile.
const ALIAS = { post: "feed", u: "profile" };
function fromHash() {
  const [, first, ...rest] = location.hash.replace(/^#/, "").split("/");
  const known = ALL_TABS.some(([key]) => key === first);
  const tab = known ? first : ALIAS[first] || "feed";
  return { tab, rest: known ? rest : first ? [first, ...rest] : [] };
}

const NOTE = {
  like: "liked your post",
  comment: "commented on your post",
  answer: "answered your question",
  accepted: "accepted your answer",
  mention: "mentioned you",
};

// onNavigate(page) opens another view: "landing", "scans" or "learn"
export default function Community({ onNavigate }) {
  const [nav, setNav] = React.useState(fromHash);
  const [user, setUser] = React.useState(undefined); // undefined while the first me() call is running
  const [version, setVersion] = React.useState(0);
  const [signIn, setSignIn] = React.useState(null); // null = closed, otherwise { after }
  const reload = React.useCallback(() => setVersion((v) => v + 1), []);

  React.useEffect(() => {
    cm.me().then(setUser).catch(() => setUser(null));
  }, []);
  React.useEffect(() => {
    // Back/Forward inside the Community: the app keeps this page (state.page is "community"), we re-read the hash
    const onHash = () => location.hash.startsWith("#community") && setNav(fromHash());
    window.addEventListener("hashchange", onHash);
    window.addEventListener("popstate", onHash);
    return () => { window.removeEventListener("hashchange", onHash); window.removeEventListener("popstate", onHash); };
  }, []);

  const open = (tab) => {
    history.replaceState({ page: "community" }, "", `#community/${tab}`);
    setNav({ tab, rest: [] });
  };
  // a screen inside the Community (a post, a question, a profile); Back returns to the previous one
  const go = React.useCallback((path) => {
    history.pushState({ page: "community" }, "", `#community/${path}`);
    setNav(fromHash());
    window.scrollTo(0, 0);
  }, []);
  const requireAuth = React.useCallback((fn) => (user ? fn() : setSignIn({ after: fn })), [user]);
  const ctx = React.useMemo(() => ({ user: user || null, requireAuth, version, reload, go }), [user, requireAuth, version, reload, go]);
  const tabs = user?.moderator ? ALL_TABS : TABS;

  const signedIn = (u) => {
    const after = signIn?.after;
    setUser(u);
    setSignIn(null);
    reload();
    if (after) setTimeout(after, 0);
  };
  const signedOut = async () => {
    await cm.signOut();
    setUser(null);
    reload();
  };
  const resetDemo = async () => {
    await cm.resetDemoData();
    setUser(null);
    reload();
  };

  return (
    <CommunityContext.Provider value={ctx}>
      <div className="app cm-root">
        <header className="topbar cm-topbar">
          <div className="brand" role="button" tabIndex={0} style={{ cursor: "pointer" }} onClick={() => onNavigate("landing")} onKeyDown={(e) => e.key === "Enter" && onNavigate("landing")}>
            AEGIS <span className="muted">community</span>
          </div>
          <div className="cm-bar-right">
            <button onClick={() => onNavigate("scans")}>Scan &amp; Fix</button>
            <button onClick={() => onNavigate("learn")}>Learn</button>
            <Bell user={user} version={version} reload={reload} onSignIn={() => setSignIn({})} />
            {user === undefined ? null : user ? (
              <UserMenu user={user} onProfile={() => open("profile")} onReset={resetDemo} onSignOut={signedOut} />
            ) : (
              <button className="primary" onClick={() => setSignIn({})}>Sign in</button>
            )}
          </div>
        </header>
        <main>
          <section>
            <h2 className="cm-title">Community</h2>
            <p className="cm-sub">Ask, share and learn with other builders.</p>
            <Tabs tabs={tabs} active={nav.tab} onChange={open} />
            <div className="tab-body">
              {nav.tab === "feed" && <Feed rest={nav.rest} />}
              {nav.tab === "qa" && <QA rest={nav.rest} />}
              {nav.tab === "resources" && <Resources />}
              {nav.tab === "jobs" && <Jobs />}
              {nav.tab === "profile" && (user === undefined && !nav.rest.length ? null : <Profile rest={nav.rest} onSignIn={() => setSignIn({})} />)}
              {nav.tab === "mod" && user !== undefined && <Moderation />}
            </div>
          </section>
        </main>
        {signIn && <SignInModal onDone={signedIn} onClose={() => setSignIn(null)} />}
      </div>
    </CommunityContext.Provider>
  );
}

function useOutsideClose(open, close) {
  const ref = React.useRef(null);
  React.useEffect(() => {
    if (!open) return undefined;
    const onDown = (e) => ref.current && !ref.current.contains(e.target) && close();
    const onKey = (e) => e.key === "Escape" && close();
    document.addEventListener("mousedown", onDown);
    document.addEventListener("keydown", onKey);
    return () => { document.removeEventListener("mousedown", onDown); document.removeEventListener("keydown", onKey); };
  }, [open, close]);
  return ref;
}

function Bell({ user, version, reload, onSignIn }) {
  const [open, setOpen] = React.useState(false);
  const close = React.useCallback(() => setOpen(false), []);
  const ref = useOutsideClose(open, close);
  const { data } = useLoad(() => (user ? cm.listNotifications() : Promise.resolve([])), [user?.id, version]);
  const list = data || [];
  const unread = list.filter((n) => !n.read);
  const markAll = async () => { await cm.markRead(unread.map((n) => n.id)); reload(); };
  const { go } = React.useContext(CommunityContext);
  // opens what the notification is about and marks it read
  const openNote = async (n) => {
    setOpen(false);
    go(n.targetType === "question" ? `qa/${n.targetId}` : `post/${n.targetId}`);
    if (!n.read) { await cm.markRead([n.id]).catch(() => null); reload(); }
  };
  return (
    <div className="cm-menu-wrap" ref={ref}>
      <button className="cm-bell" aria-label={`Notifications${unread.length ? `, ${unread.length} unread` : ""}`} aria-expanded={open} onClick={() => (user ? setOpen(!open) : onSignIn())}>
        <span aria-hidden="true">🔔</span>
        {unread.length > 0 && <span className="cm-count">{unread.length}</span>}
      </button>
      {open && (
        <div className="cm-pop" role="menu">
          <div className="cm-pop-head">
            <strong>Notifications</strong>
            {unread.length > 0 && <button className="link" onClick={markAll}>Mark all read</button>}
          </div>
          {list.length === 0 && <div className="muted small cm-pop-empty">Nothing yet.</div>}
          {list.slice(0, 10).map((n) => (
            <button key={n.id} type="button" className={n.read ? "cm-note" : "cm-note cm-unread"} onClick={() => openNote(n)}>
              <Avatar user={n.actor} size={24} />
              <span><strong>{n.actor.name}</strong> {NOTE[n.kind]}<br /><span className="muted small">{timeAgo(n.createdAt)}</span></span>
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

function UserMenu({ user, onProfile, onReset, onSignOut }) {
  const [open, setOpen] = React.useState(false);
  const close = React.useCallback(() => setOpen(false), []);
  const ref = useOutsideClose(open, close);
  const run = (fn) => () => { setOpen(false); fn(); };
  return (
    <div className="cm-menu-wrap" ref={ref}>
      <button className="cm-user" aria-haspopup="menu" aria-expanded={open} onClick={() => setOpen(!open)}>
        <Avatar user={user} size={24} />
        <span>{user.name}</span>
      </button>
      {open && (
        <div className="cm-pop cm-pop-menu" role="menu">
          <button role="menuitem" onClick={run(onProfile)}>Profile</button>
          {cm.isMock && <button role="menuitem" onClick={run(onReset)}>Reset demo data</button>}
          <button role="menuitem" onClick={run(onSignOut)}>Sign out</button>
        </div>
      )}
    </div>
  );
}
