import React from "react";
import { api } from "../api.js";
import { Tabs } from "../components/ui.jsx";
import Cases from "./Cases.jsx";
import Cheatsheets from "./Cheatsheets.jsx";
import { TABS } from "./content.js";
import CryptoPQC from "./CryptoPQC.jsx";
import "./learn.css";
import Overview from "./Overview.jsx";
import Practice from "./Practice.jsx";
import { loadProgress, saveProgress } from "./progress.js";
import Pulse from "./Pulse.jsx";
import Quizzes from "./Quizzes.jsx";

// The tab (and an optional category filter) live in the URL hash, "#learn/quizzes/A01", so a refresh
// reopens the same tab.
function fromHash() {
  const m = location.hash.match(/^#learn\/([a-z]+)(?:\/([A-Za-z0-9]+))?/);
  const tab = m && TABS.some(([key]) => key === m[1]) ? m[1] : "overview";
  return { tab, filter: (m && m[2]) || "" };
}

// onNavigate(page) opens another view: "landing", "scans" or "new"
export default function Learn({ onNavigate }) {
  const [nav, setNav] = React.useState(fromHash);
  const [progress, setProgress] = React.useState(loadProgress);
  const [health, setHealth] = React.useState(null);

  React.useEffect(() => {
    api.health().then(setHealth).catch(() => setHealth({ status: "down" }));
  }, []);

  React.useEffect(() => {
    const onHash = () => setNav(fromHash());
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, []);

  const open = (tab, filter = "") => {
    history.replaceState({ page: "learn" }, "", `#learn/${tab}${filter ? `/${filter}` : ""}`);
    setNav({ tab, filter });
    window.scrollTo(0, 0);
  };
  const onProgress = (change) => setProgress(saveProgress(change));
  // a tab is re-created when the hash filter changes, so a link like #learn/quizzes/A01 always applies
  const tabKey = `${nav.tab}/${nav.filter}`;

  return (
    <div className="app lr-root">
      <header className="topbar">
        <div className="brand" role="button" tabIndex={0} style={{ cursor: "pointer" }} onClick={() => onNavigate("landing")} onKeyDown={(e) => e.key === "Enter" && onNavigate("landing")}>
          AEGIS <span className="muted">learn</span>
        </div>
        <div className="row gap">
          <button onClick={() => onNavigate("scans")}>Scan &amp; Fix</button>
          <div className="chip">
            <span className={`dot ${health?.status === "ok" ? "dot-ok" : "dot-bad"}`} title={`backend ${health?.status || "…"}`} />
            <span className="small muted">{health?.status === "ok" ? "backend ok" : health ? "backend unreachable" : "…"}</span>
          </div>
        </div>
      </header>
      <main>
        <section>
          <h2 className="lr-title">Learn</h2>
          <p className="lr-sub">Threats, crypto, real breaches, practice — offline.</p>
          <Tabs tabs={TABS} active={nav.tab} onChange={(tab) => open(tab)} />
          <div className="tab-body">
            {nav.tab === "overview" && <Overview progress={progress} onTab={open} onNavigate={onNavigate} />}
            {nav.tab === "pulse" && <Pulse key={tabKey} onTab={open} />}
            {nav.tab === "crypto" && <CryptoPQC key={tabKey} progress={progress} onProgress={onProgress} />}
            {nav.tab === "cases" && <Cases key={tabKey} onTab={open} />}
            {nav.tab === "practice" && <Practice key={tabKey} filter={nav.filter} progress={progress} onProgress={onProgress} />}
            {nav.tab === "cheatsheets" && <Cheatsheets key={tabKey} filter={nav.filter} />}
            {nav.tab === "quizzes" && <Quizzes key={tabKey} filter={nav.filter} progress={progress} onProgress={onProgress} onTab={open} />}
          </div>
        </section>
      </main>
    </div>
  );
}
