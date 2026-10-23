import React from "react";
import { api } from "../api.js";
import { Empty, ErrorBox, Loading, useLoad } from "./ui.jsx";

export default function Graph({ scanId, refreshKey }) {
  const { data, error, loading } = useLoad(() => api.graph(scanId), [scanId, refreshKey]);
  if (error) return <ErrorBox error={error} />;
  if (loading && !data) return <Loading />;

  const counts = {};
  data.nodes.forEach((n) => { counts[n.data.type] = (counts[n.data.type] || 0) + 1; });
  const links = data.edges.filter((e) => e.data.kind === "HANDLED_BY");

  return (
    <div>
      <div className="cards">
        {Object.entries(counts).map(([type, n]) => (
          <div className="card" key={type}><div className="card-label">{type}</div><strong>{n}</strong></div>
        ))}
      </div>

      <h3>Attack paths</h3>
      {data.attack_paths.length === 0 && <Empty>No finding is linked to an endpoint or code path yet.</Empty>}
      <ul className="paths">
        {data.attack_paths.map((path, i) => (
          <li key={i}>
            {path.map((step, j) => (
              <React.Fragment key={j}>
                <span className={step.startsWith("F-") ? "path-step finding" : "path-step"}>{step}</span>
                {j < path.length - 1 && <span className="arrow">→</span>}
              </React.Fragment>
            ))}
          </li>
        ))}
      </ul>

      <h3>Runtime ↔ code links (correlation)</h3>
      {links.length === 0 && <Empty>No runtime route was linked to a handler.</Empty>}
      {links.length > 0 && (
        <table>
          <thead><tr><th>Endpoint</th><th>Handler</th><th className="num">Score</th><th>Signals</th></tr></thead>
          <tbody>
            {links.map((e) => (
              <tr key={e.data.id}>
                <td className="mono">{e.data.source}</td>
                <td className="mono small">{e.data.target}</td>
                <td className="num"><strong>{e.data.score}</strong></td>
                <td className="small">{Object.entries(e.data.signals || {}).filter(([, v]) => v === true).map(([k]) => k).join(" + ")}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
