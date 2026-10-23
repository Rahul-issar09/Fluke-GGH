// Small pieces shared by the Learn tabs.
import React from "react";
import { Loading } from "../components/ui.jsx";
import { loadContent } from "./content.js";

/** Load public/learn/<name>.json once per page view. */
export function useContent(name) {
  const [state, setState] = React.useState({ data: null, loading: true });
  React.useEffect(() => {
    let alive = true;
    loadContent(name).then((data) => alive && setState({ data, loading: false }));
    return () => {
      alive = false;
    };
  }, [name]);
  return state;
}

/** Shows a loading line, or a note when the file is missing, else renders children(data). */
export function WithContent({ state, what, children }) {
  if (state.loading) return <Loading />;
  if (!state.data) return <div className="lr-note"><span>{what} is not available yet (public/learn/ has no data for it).</span></div>;
  return children(state.data);
}

/** A code block with a copy button. */
export function Code({ code, label, tone }) {
  const [copied, setCopied] = React.useState(false);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(code);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* clipboard blocked: the code is still selectable */
    }
  };
  return (
    <div className={`lr-code ${tone ? `lr-code-${tone}` : ""}`}>
      <div className="lr-code-head">
        <span className="small">{label}</span>
        <button className="link small lr-no-print" onClick={copy}>{copied ? "Copied" : "Copy"}</button>
      </div>
      <pre>{code}</pre>
    </div>
  );
}

/** A note for something that needs the backend, with a retry button. */
export function BackendNote({ text, onRetry }) {
  return (
    <div className="lr-note">
      <span>{text}</span>
      {onRetry && <button onClick={onRetry}>Retry</button>}
    </div>
  );
}

/** Async loader state for things read from your scans; `run` starts it (on mount when auto). */
export function useAsync(loader, { auto = true } = {}) {
  const [state, setState] = React.useState({ data: null, error: null, loading: auto });
  const run = React.useCallback(() => {
    setState((s) => ({ ...s, loading: true, error: null }));
    return loader()
      .then((data) => setState({ data, error: null, loading: false }))
      .catch((error) => setState({ data: null, error, loading: false }));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  React.useEffect(() => {
    if (auto) run();
  }, [auto, run]);
  return { ...state, run };
}
