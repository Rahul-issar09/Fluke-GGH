import React from "react";
import { api, getToken, setToken } from "./api.js";
import Health from "./components/Health.jsx";
import LlmSettings from "./components/LlmSettings.jsx";
import NewScan from "./components/NewScan.jsx";
import ScanList from "./components/ScanList.jsx";
import ScanView from "./components/ScanView.jsx";
import Community from "./community/Community.jsx";
import Landing from "./landing/Landing.jsx";
import Learn from "./learn/Learn.jsx";
import { badgeFor } from "./llm/state.js";
import SecurePrompt from "./secure/SecurePrompt.jsx";

export default function App() {
  const [view, setView] = React.useState({ page: location.hash.startsWith("#learn") ? "learn" : location.hash.startsWith("#community") ? "community" : "landing" });
  const [token, setTokenState] = React.useState(getToken());
  const [health, setHealth] = React.useState(null);
  const [llm, setLlm] = React.useState(null);   // the active AI model, shown in the header on every page

  React.useEffect(() => {
    api.health().then(setHealth).catch(() => setHealth({ status: "down" }));
  }, [token]);

  // the model can change outside this page (the CLI, or an API restart that forgets this run's key),
  // so the badge is re-read on every page change and whenever the tab comes back into view
  React.useEffect(() => {
    const refresh = () => api.llmConfig().then(setLlm).catch(() => setLlm(null));
    refresh();
    const onVisible = () => document.visibilityState === "visible" && refresh();
    document.addEventListener("visibilitychange", onVisible);
    return () => document.removeEventListener("visibilitychange", onVisible);
  }, [token, view.page]);

  const open = (scanId) => setView({ page: "scan", scanId });

  // Landing ↔ console. Leaving the landing adds a history entry, so the browser's Back returns to it.
  const enter = (page) => { history.pushState({ page }, "", page === "learn" || page === "community" ? `#${page}` : location.pathname + location.search); setView({ page }); };
  const toLanding = () => (history.state?.page ? history.back() : setView({ page: "landing" }));
  React.useEffect(() => {
    const onPop = (e) => setView({ page: e.state?.page || "landing" });
    window.addEventListener("popstate", onPop);
    return () => window.removeEventListener("popstate", onPop);
  }, []);

  if (view.page === "landing") return <Landing onNavigate={enter} />;
  if (view.page === "learn") return <Learn onNavigate={enter} />;
  if (view.page === "community") return <Community onNavigate={enter} />;

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand" role="button" tabIndex={0} style={{ cursor: "pointer" }} onClick={toLanding} onKeyDown={(e) => e.key === "Enter" && toLanding()}>
          <span className="mark"><svg width="14" height="14" viewBox="0 0 16 16" aria-hidden="true"><path d="M3 8.5l3.2 3.2L13 4.5" fill="none" stroke="#f7f3ea" strokeWidth="2.6" strokeLinecap="square" /></svg></span>
          AEGIS <span className="muted">console</span>
        </div>
        <nav aria-label="Console">
          <button className={view.page === "scans" || view.page === "scan" ? "nav active" : "nav"} onClick={() => setView({ page: "scans" })}>Scans</button>
          <button className={view.page === "new" ? "nav active" : "nav"} onClick={() => setView({ page: "new" })}>New scan</button>
          <button className={view.page === "secure" ? "nav active" : "nav"} onClick={() => setView({ page: "secure" })}>Secure prompt</button>
          <button className={view.page === "health" ? "nav active" : "nav"} onClick={() => setView({ page: "health" })}>Health</button>
          <button className={view.page === "llm" ? "nav active" : "nav"} onClick={() => setView({ page: "llm" })}>AI model</button>
        </nav>
        <div className="row gap">
          <span className={`dot ${health?.status === "ok" ? "dot-ok" : "dot-bad"}`} title={`backend ${health?.status || "…"}`} />
          <span className="small muted">{health?.status === "ok" ? "backend ok" : "backend unreachable"}</span>
          {llm && (
            <button className={`badge badge-${badgeFor(llm).kind} badge-button`} title={badgeFor(llm).title}
                    onClick={() => setView({ page: "llm" })}>{badgeFor(llm).text}</button>
          )}
          <input
            className="token"
            type="password"
            placeholder="API token (optional)"
            value={token}
            onChange={(e) => { setToken(e.target.value); setTokenState(e.target.value); }}
          />
        </div>
      </header>
      <main>
        {view.page === "scans" && <ScanList onOpen={open} onNew={() => setView({ page: "new" })} />}
        {view.page === "new" && <NewScan onStarted={open} llm={llm} onLlmChanged={setLlm} />}
        {view.page === "secure" && <SecurePrompt llm={llm} onOpenModel={() => setView({ page: "llm" })} />}
        {view.page === "health" && <Health />}
        {view.page === "llm" && <LlmSettings onChanged={setLlm} />}
        {view.page === "scan" && <ScanView scanId={view.scanId} llm={llm} onBack={() => setView({ page: "scans" })} />}
      </main>
    </div>
  );
}
