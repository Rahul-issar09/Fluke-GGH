import React from "react";
import { api } from "../api.js";
import { ErrorBox, Json, Loading } from "./ui.jsx";

// A clickable evidence id; opens the raw evidence record in a dialog.
export function EvidenceLink({ id }) {
  const [open, setOpen] = React.useState(false);
  return (
    <>
      <button className="link mono" onClick={() => setOpen(true)}>{id}</button>
      {open && <EvidenceDialog id={id} onClose={() => setOpen(false)} />}
    </>
  );
}

function EvidenceDialog({ id, onClose }) {
  const [state, setState] = React.useState({ data: null, error: null });
  React.useEffect(() => {
    api.evidence(id).then((data) => setState({ data, error: null })).catch((error) => setState({ data: null, error }));
  }, [id]);
  React.useEffect(() => {
    const onKey = (e) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);
  const ev = state.data;
  return (
    <div className="overlay" onClick={onClose}>
      <div className="dialog" role="dialog" aria-label={`Evidence ${id}`} onClick={(e) => e.stopPropagation()}>
        <div className="row between">
          <h3>Evidence {id}</h3>
          <button onClick={onClose}>Close</button>
        </div>
        <ErrorBox error={state.error} />
        {!ev && !state.error && <Loading />}
        {ev && (
          <>
            <p className="small">
              <strong>{ev.kind}</strong> from <strong>{ev.tool}</strong>{ev.tool_version ? ` ${ev.tool_version}` : ""}
              {ev.finding_id && <> · finding <span className="mono">{ev.finding_id}</span></>}
              {ev.db_date && <> · database {ev.db_date}</>}
            </p>
            <Json value={ev.payload} />
          </>
        )}
      </div>
    </div>
  );
}
