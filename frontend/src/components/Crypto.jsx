import React from "react";
import { api, reportUrl } from "../api.js";
import { Badge, Empty, ErrorBox, Loading, useLoad } from "./ui.jsx";

const prop = (c, name) => (c.properties || []).find((p) => p.name === name)?.value;

export default function Crypto({ scanId, refreshKey }) {
  const { data, error, loading } = useLoad(() => api.cbom(scanId), [scanId, refreshKey]);
  if (error) return <ErrorBox error={error} />;
  if (loading && !data) return <Loading />;

  const components = data.components || [];
  const classical = components.filter((c) => prop(c, "aegis:classical_risk") !== "none").length;
  const quantum = components.filter((c) => prop(c, "aegis:quantum_risk") !== "none").length;

  return (
    <div>
      <div className="row between">
        <div className="cards">
          <div className="card"><div className="card-label">Crypto assets</div><strong>{components.length}</strong></div>
          <div className="card"><div className="card-label">Classical risk</div><strong className={classical ? "bad" : ""}>{classical}</strong></div>
          <div className="card"><div className="card-label">Quantum risk</div><strong className={quantum ? "warn" : ""}>{quantum}</strong></div>
        </div>
        <a className="button" href={reportUrl(scanId, "cbom")}>Download CBOM (CycloneDX {data.specVersion})</a>
      </div>
      {components.length === 0 && <Empty>No cryptography was found.</Empty>}
      {components.length > 0 && (
        <table>
          <thead><tr><th>Asset</th><th>Where</th><th>Usage</th><th>Classical risk</th><th>Quantum risk</th></tr></thead>
          <tbody>
            {components.map((c) => {
              const where = c.evidence?.occurrences?.[0];
              const cr = prop(c, "aegis:classical_risk");
              const qr = prop(c, "aegis:quantum_risk");
              const algo = c.cryptoProperties?.algorithmProperties;
              const proto = c.cryptoProperties?.protocolProperties;
              return (
                <tr key={c["bom-ref"]}>
                  <td>
                    <strong>{c.name}</strong>
                    <div className="small muted">
                      {algo && <>{algo.primitive}{algo.parameterSetIdentifier ? ` · ${algo.parameterSetIdentifier} bits` : ""}{algo.mode ? ` · ${algo.mode}` : ""}</>}
                      {proto && <>{proto.type} {proto.version}</>}
                    </div>
                  </td>
                  <td className="mono small">{where ? `${where.location}:${where.line}` : prop(c, "aegis:endpoint") || "—"}</td>
                  <td className="small">{prop(c, "aegis:usage") || "—"}</td>
                  <td className="small">{cr === "none" ? <Badge kind="ok">none</Badge> : <span className="bad">{cr}</span>}</td>
                  <td className="small">{qr === "none" ? <Badge kind="ok">none</Badge> : <span className="warn">{qr}</span>}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}
    </div>
  );
}
