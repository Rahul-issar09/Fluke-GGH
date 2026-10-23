// Small shared pieces: state badges, risk pills, errors, loading, JSON viewer, tabs.
import React from "react";

export const STATE_LABEL = { candidate: "candidate", corroborated: "corroborated", confirmed: "confirmed", resolved: "resolved" };

export function Badge({ kind, children }) {
  return <span className={`badge badge-${kind}`}>{children}</span>;
}

export function StateBadge({ state }) {
  return <Badge kind={state}>{STATE_LABEL[state] || state}</Badge>;
}

export function StatusBadge({ status }) {
  const kind = { completed: "ok", running: "info", queued: "muted", failed: "bad", cancelled: "muted", awaiting_approval: "warn" }[status] || "muted";
  return <Badge kind={kind}>{status?.replace("_", " ")}</Badge>;
}

export function RiskPill({ risk }) {
  const level = risk >= 0.7 ? "high" : risk >= 0.4 ? "medium" : risk > 0 ? "low" : "none";
  return <span className={`risk risk-${level}`}>{Number(risk || 0).toFixed(3)}</span>;
}

export function ErrorBox({ error }) {
  if (!error) return null;
  const status = error.status ? `HTTP ${error.status} · ` : "";
  return (
    <div className="error">
      <strong>{status}{error.body?.error || "error"}</strong>
      {error.message && <div>{error.message}</div>}
    </div>
  );
}

export function Loading({ what = "Loading" }) {
  return <div className="muted">{what}…</div>;
}

export function Json({ value }) {
  return <pre className="json">{JSON.stringify(value, null, 2)}</pre>;
}

export function Tabs({ tabs, active, onChange }) {
  return (
    <div className="tabs" role="tablist">
      {tabs.map(([key, label]) => (
        <button key={key} role="tab" aria-selected={active === key} className={active === key ? "tab active" : "tab"} onClick={() => onChange(key)}>
          {label}
        </button>
      ))}
    </div>
  );
}

export function Empty({ children }) {
  return <div className="empty">{children}</div>;
}

// A fetch-on-mount hook with reload; `deps` re-runs it.
export function useLoad(loader, deps) {
  const [state, setState] = React.useState({ data: null, error: null, loading: true });
  const reload = React.useCallback(() => {
    setState((s) => ({ ...s, loading: true }));
    return loader()
      .then((data) => setState({ data, error: null, loading: false }))
      .catch((error) => setState({ data: null, error, loading: false }));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);
  React.useEffect(() => {
    reload();
  }, [reload]);
  return { ...state, reload };
}
