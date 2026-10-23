import React from "react";
import { eventsUrl, getToken } from "../api.js";
import { Badge } from "./ui.jsx";

const TERMINAL = new Set(["completed", "failed", "cancelled"]);

// Follows GET /api/scans/{id}/events (server-sent events). The server replays the scan's history
// first, so opening this on a finished scan shows what happened, then the final status.
export default function LiveEvents({ scanId, onFinished }) {
  const [events, setEvents] = React.useState([]);
  const [state, setState] = React.useState("connecting");

  React.useEffect(() => {
    setEvents([]);
    if (getToken()) {
      setState("unavailable");  // EventSource cannot send an Authorization header
      return undefined;
    }
    const source = new EventSource(eventsUrl(scanId));
    setState("live");
    source.addEventListener("progress", (msg) => {
      const event = JSON.parse(msg.data);
      setEvents((prev) => [...prev, event]);
      if (event.stage === "scan" && TERMINAL.has(event.status)) {
        setState(event.status);
        source.close();
        onFinished?.(event.status);
      }
    });
    source.onerror = () => {
      setState((s) => (TERMINAL.has(s) ? s : "disconnected"));
      source.close();
    };
    return () => source.close();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scanId]);

  const stages = [];
  for (const e of events) {
    if (e.stage !== "scan" && !stages.includes(e.stage)) stages.push(e.stage);
  }

  return (
    <div>
      <div className="row gap">
        <strong>Live progress</strong>
        <Badge kind={state === "completed" ? "ok" : state === "live" ? "info" : state === "failed" ? "bad" : "muted"}>{state}</Badge>
      </div>
      {state === "unavailable" && <p className="muted">Live events need an open API (no token); the status above refreshes instead.</p>}
      <div className="stages">
        {stages.map((s) => <span key={s} className="stage">{s}</span>)}
      </div>
      <ol className="events">
        {events.map((e, i) => (
          <li key={i}>
            <span className="mono small muted">{new Date(e.at).toLocaleTimeString()}</span>{" "}
            <span className="stage-tag">{e.stage}</span> <span className="mono">{e.node}</span>{" "}
            <Badge kind={e.status === "done" || e.status === "completed" ? "ok" : e.status === "failed" ? "bad" : "info"}>{e.status}</Badge>
            {e.ms != null && <span className="muted small"> {e.ms} ms</span>}
          </li>
        ))}
      </ol>
    </div>
  );
}
