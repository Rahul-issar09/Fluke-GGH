// Landing page in front of the console: one scroll-driven 3D film that shows what AEGIS does, with a short
// caption per scene instead of sections of text. Fonts are bundled (@fontsource) and the scene (Scene3D) is drawn
// with three.js from canvas textures, so nothing here is fetched from another origin. Scene3D loads lazily.
import "@fontsource/instrument-serif/400.css";
import "@fontsource/instrument-serif/400-italic.css";
import "@fontsource/inter/400.css";
import "@fontsource/inter/500.css";
import "@fontsource/inter/600.css";
import "./landing.css";

import { lazy, Suspense, useEffect, useRef, useState } from "react";

const Scene3D = lazy(() => import("./Scene3D.jsx"));

// `page` is the console view to open ("scans", "new", "learn", "community")
const NAV = [
  { label: "Scan & Fix", page: "scans" },
  { label: "Learn", page: "learn" },
  { label: "Community", page: "community" },
];

// one caption per chapter of the film (chapter 0 is the hero); the scene in Scene3D.jsx has the same eight chapters
const CHAPTERS = [
  { name: "Prove it" },
  { name: "Targets", h: "Point it at anything.", p: "A running app, a source folder or a GitHub repo, from the CLI or the web.", chips: ["Running app", "Folder", "GitHub repo"] },
  { name: "Scan", h: "Eight scanners. One verdict.", p: "Semgrep, Gitleaks, Trivy, Nuclei and more, offline, under one safety controller." },
  { name: "Evidence", h: "Alerts become evidence.", p: "Code and live app agree: candidate, corroborated, confirmed." },
  { name: "Fix", h: "Fixed. Verified on a copy.", p: "The patch is re-scanned and tested. Your code stays untouched." },
  { name: "Approve", h: "You approve.", p: "Nothing changes without a human saying yes." },
  { name: "Modes", h: "Offline, or Gemini.", p: "Same pipeline. Local by default, Gemini when you opt in.", chips: ["Offline", "Gemini"] },
  { name: "Start", h: "Know what’s really exploitable.", p: "", cta: true },
];

const reducedMotion = () => !!window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;

// shown while the 3D scene loads, and instead of it when WebGL is not available
function Ledger() {
  return (
    <div className="ln-ledger" aria-hidden="true">
      <div className="ln-lh"><span>F-0127 · SQL injection · GET /api/search</span><i>OWASP A03</i></div>
      <div className="ln-ladder"><b>Candidate</b><b>Corroborated</b><b className="ln-on">Confirmed</b></div>
      <div className="ln-code">
        <p><s>14</s><span>def search(term):</span></p>
        <p className="ln-rm"><s>15</s><span>− q = "SELECT * FROM items WHERE t='" + term + "'"</span></p>
        <p className="ln-ad"><s>15</s><span>+ q = "SELECT * FROM items WHERE t = ?"</span></p>
        <p className="ln-ad"><s>16</s><span>+ rows = db.execute(q, (term,)).fetchall()</span></p>
      </div>
      <div className="ln-lf"><span>✓ re-scan on copy: 0 findings · tests pass</span></div>
    </div>
  );
}

function Stage({ progressRef, still }) {
  const [failed, setFailed] = useState(false);
  if (failed) return <Ledger />;
  return (
    <Suspense fallback={<Ledger />}>
      <Scene3D progressRef={progressRef} still={still} onFail={() => setFailed(true)} />
    </Suspense>
  );
}

export default function Landing({ onNavigate }) {
  const root = useRef(null);
  const trackRef = useRef(null);
  const progress = useRef(0);
  const [chapter, setChapter] = useState(0);
  const [still] = useState(reducedMotion);

  // the brief's body colour, for as long as the landing page is shown
  useEffect(() => {
    const before = document.body.style.background;
    document.body.style.background = "#eee9dd";
    return () => {
      document.body.style.background = before;
    };
  }, []);

  // film progress from how far the tall track has been scrolled
  useEffect(() => {
    const el = root.current;
    if (!el || still) return undefined;
    const update = () => {
      const r = trackRef.current?.getBoundingClientRect();
      if (!r) return;
      const span = Math.max(1, r.height - el.clientHeight);
      const p = Math.min(1, Math.max(0, -r.top / span));
      progress.current = p;
      const k = Math.min(CHAPTERS.length - 1, Math.floor(p * CHAPTERS.length));
      setChapter((cur) => (cur === k ? cur : k));
    };
    update();
    el.addEventListener("scroll", update, { passive: true });
    window.addEventListener("resize", update);
    return () => {
      el.removeEventListener("scroll", update);
      window.removeEventListener("resize", update);
    };
  }, [still]);

  const toChapter = (i) => {
    const el = root.current;
    const t = trackRef.current;
    if (!el || !t) return;
    const span = Math.max(1, t.offsetHeight - el.clientHeight);
    el.scrollTo({ top: t.offsetTop + ((i + 0.5) / CHAPTERS.length) * span, behavior: still ? "auto" : "smooth" });
  };

  const hero = (
    <div className="ln-hero-text">
      <div className="ln-lbl">Offline AI security agent · CLI + Web</div>
      <h1 className="ln-disp">Prove it.<br />Fix it.<br /><em>Learn from it.</em></h1>
      <p className="ln-sub">Scan a running app, a folder or a repo. See what’s really exploitable. Fix it safely.</p>
      <div className="ln-cta">
        <button className="ln-btn ln-btn-p" onClick={() => onNavigate("new")}>Start a scan →</button>
        {!still && <button className="ln-btn ln-btn-g" onClick={() => toChapter(1)}>Watch it work ↓</button>}
      </div>
      <div className="ln-term"><span>$</span> aegis scan run --url http://127.0.0.1:5000 --folder ./my-app</div>
    </div>
  );

  const caption = (c, i) => (
    <div className="ln-capbox" key={i}>
      <span className="ln-step ln-disp">{String(i).padStart(2, "0")}</span>
      <h2 className="ln-disp">{c.h}</h2>
      {c.p && <p>{c.p}</p>}
      {c.chips && <div className="ln-chips">{c.chips.map((x) => <i key={x}>{x}</i>)}</div>}
      {c.cta && (
        <div className="ln-cta">
          <button className="ln-btn ln-btn-p" onClick={() => onNavigate("new")}>Start a scan</button>
          <button className="ln-btn ln-btn-g" onClick={() => onNavigate("scans")}>Open the console</button>
          <button className="ln-btn ln-btn-g" onClick={() => onNavigate("learn")}>Learn security</button>
        </div>
      )}
    </div>
  );

  return (
    <div className="ln-root" ref={root}>
      <nav className="ln-nav" aria-label="Main">
        <button className="ln-logo" onClick={() => root.current?.scrollTo({ top: 0, behavior: still ? "auto" : "smooth" })}>
          <span className="ln-mark"><svg width="16" height="16" viewBox="0 0 16 16" aria-hidden="true"><path d="M3 8.5l3.2 3.2L13 4.5" fill="none" stroke="#f7f3ea" strokeWidth="2.6" strokeLinecap="square" /></svg></span>
          AEGIS
        </button>
        <div className="ln-links">
          {NAV.map((n) => (
            <button key={n.label} onClick={() => onNavigate(n.page)}>{n.label}</button>
          ))}
        </div>
        <span className="ln-pill"><i />OFFLINE · local model</span>
        <button className="ln-btn ln-btn-p ln-nav-btn" onClick={() => onNavigate("new")}>Start a scan</button>
      </nav>

      <section className={`ln-track ${still ? "ln-still" : ""}`} ref={trackRef} aria-label="How AEGIS works">
        <div className="ln-pin">
          <div className="ln-canvas"><Stage progressRef={progress} still={still} /></div>
          <div className="ln-overlay">
            {still || chapter === 0 ? <div className="ln-cap ln-cap-hero" key="hero">{hero}</div> : <div className="ln-cap" key={chapter}>{caption(CHAPTERS[chapter], chapter)}</div>}
          </div>
          {!still && (
            <ol className="ln-rail" aria-label="Chapters">
              {CHAPTERS.map((c, i) => (
                <li key={c.name}>
                  <button className={i === chapter ? "ln-on" : ""} onClick={() => toChapter(i)} aria-label={c.name} aria-current={i === chapter}>
                    <span>{c.name}</span><i />
                  </button>
                </li>
              ))}
            </ol>
          )}
          {!still && chapter === 0 && <div className="ln-scroll" aria-hidden="true">Scroll</div>}
        </div>
      </section>

      {still && (
        <section className="ln-list">
          {CHAPTERS.slice(1).map((c, i) => (
            <div key={c.name}>{caption(c, i + 1)}</div>
          ))}
        </section>
      )}

      <footer>
        <div className="ln-foot"><span>AEGIS — Offline AI Security Copilot</span><span>Authorised use only · Built for the Google Gemini Hackathon</span></div>
      </footer>
    </div>
  );
}
