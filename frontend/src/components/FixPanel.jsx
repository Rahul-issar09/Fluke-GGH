import React from "react";
import { api } from "../api.js";
import { Badge, ErrorBox } from "./ui.jsx";

const WAITING = new Set(["drafted", "verifying"]);

// The human-in-the-loop fix flow: verify the drafted fix on a copy, then approve patch / apply.
export default function FixPanel({ finding, onChanged }) {
  const draft = finding.fix;
  const [fixId, setFixId] = React.useState(draft?.fix_id || null);
  const [fix, setFix] = React.useState(null);
  const [error, setError] = React.useState(null);
  const [busy, setBusy] = React.useState(false);

  const load = React.useCallback(async (id) => {
    try {
      const data = await api.fix(id);
      setFix(data);
      return data;
    } catch (err) {
      setError(err);
      return null;
    }
  }, []);

  React.useEffect(() => {
    if (fixId) load(fixId);
  }, [fixId, load]);

  // poll while it is being verified
  React.useEffect(() => {
    if (!fix || !WAITING.has(fix.status) || fix.status === "drafted" && !busy) return undefined;
    const t = setInterval(() => load(fixId), 1500);
    return () => clearInterval(t);
  }, [fix, fixId, load, busy]);

  async function verify() {
    setError(null);
    setBusy(true);
    try {
      const { fix_id } = await api.startFix(finding.id);
      setFixId(fix_id);
      let current = await load(fix_id);
      while (current && WAITING.has(current.status)) {
        await new Promise((r) => setTimeout(r, 1500));
        current = await load(fix_id);
      }
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  }

  async function commit(mode) {
    setError(null);
    setBusy(true);
    try {
      setFix(await api.commitFix(fixId, mode));
      onChanged?.();
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  }

  if (!draft) return <p className="muted">No fix was drafted for this finding (it needs a file and line, and a fix template for its type).</p>;

  const report = fix?.verify_report || {};
  const approval = report.approval;
  const status = fix?.status || draft.status;
  // where the fix is in the human-in-the-loop flow: drafted -> verified on a copy -> approved -> committed
  const n = { drafted: 0, verifying: 1, awaiting_approval: 2, committed: 4 }[status] ?? 0; // steps already done
  const steps = ["Drafted", "Verified on a copy", "Approved", "Committed"];
  const stepClass = (i) => (status === "failed" ? (i === 1 ? "bad" : i < 1 ? "done" : "") : i < n ? "done" : i === n ? "now" : "");

  return (
    <div className="fix">
      <ol className="flow">
        {steps.map((s, i) => (
          <li key={s} className={stepClass(i)}><span>{i + 1}</span>{s}</li>
        ))}
      </ol>
      <div className="row gap">
        <span className="mono">{draft.fix_id}</span>
        <Badge kind={status === "committed" ? "ok" : status === "failed" ? "bad" : status === "awaiting_approval" ? "warn" : "info"}>{status?.replace("_", " ")}</Badge>
        {status === "drafted" && (
          <button className="primary" onClick={verify} disabled={busy}>{busy ? "Verifying on a copy…" : "Verify this fix"}</button>
        )}
      </div>
      {draft.description && <p>{draft.description}</p>}
      {draft.secret_masked && <p className="muted small">The secret value is masked in this diff.</p>}
      <pre className="diff">{(fix?.diff || draft.diff || "").split("\n").map((line, i) => (
        <span key={i} className={line.startsWith("+") && !line.startsWith("+++") ? "add" : line.startsWith("-") && !line.startsWith("---") ? "del" : ""}>{line + "\n"}</span>
      ))}</pre>

      {report.passed !== undefined && (
        <>
          <h4>Verification {report.passed ? <Badge kind="ok">passed</Badge> : <Badge kind="bad">failed</Badge>}</h4>
          {report.reason && <p className="error-text">{report.reason}</p>}
          <table>
            <thead><tr><th>Check</th><th>Status</th><th>Details</th></tr></thead>
            <tbody>
              {["static", "tests", "runtime"].map((name) => (
                <tr key={name}>
                  <td>{name}</td>
                  <td><Badge kind={report[name]?.status === "passed" ? "ok" : report[name]?.status === "failed" ? "bad" : "muted"}>{report[name]?.status || "—"}</Badge></td>
                  <td className="small">{report[name]?.reason || (name === "runtime" && report.runtime?.checks ? report.runtime.checks.map((c) => `object ${c.object_id}: owner ${c.owner_status}, other user ${c.other_status}`).join("; ") : "")}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}

      {status === "awaiting_approval" && (
        <div className="approval">
          <h4>Approve the commit</h4>
          {approval?.refused && <p className="error-text">Last attempt refused: {approval.refused}</p>}
          <div className="row gap">
            <button onClick={() => commit("patch")} disabled={busy}>Approve as patch (.diff file)</button>
            <button className="primary" onClick={() => commit("apply")} disabled={busy}>Approve and apply to the code</button>
            <button disabled title="Needs the gh tool in the tool contract (C6) and an online mode">Open a PR (not available)</button>
          </div>
        </div>
      )}

      {status === "committed" && report.resolution && (
        <p>
          {report.resolution.resolved ? <Badge kind="ok">finding resolved</Badge> : <Badge kind="warn">committed, not resolved</Badge>}{" "}
          {report.resolution.reason || (report.commit_mode ? `committed as ${report.commit_mode}` : "")}
        </p>
      )}
      {report.commit?.warnings?.map((w) => <p key={w} className="warning">{w}</p>)}
      <ErrorBox error={error} />
    </div>
  );
}
