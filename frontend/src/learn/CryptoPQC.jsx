// Crypto & post-quantum: which algorithms are broken, weak, quantum-vulnerable, fine or post-quantum
// safe; what replaces each one; a "harvest now, decrypt later" explainer; your latest scan's
// cryptography inventory (CBOM) with a readiness score; and a migration checklist.
import React from "react";
import { Badge } from "../components/ui.jsx";
import { BackendNote, Code, WithContent, useAsync, useContent } from "./parts.jsx";
import { backendHint, latestCbom } from "./scans.js";

const STATUS = {
  BROKEN: ["bad", "broken"],
  WEAK: ["warn", "weak"],
  "QUANTUM-VULNERABLE": ["warn", "quantum-vulnerable"],
  OK: ["ok", "ok"],
  "PQ-SAFE": ["info", "post-quantum safe"],
};
const LANGS = [["python", "Python"], ["js", "JavaScript"], ["java", "Java"]];

const CHECKLIST = [
  ["inventory", "Know what you use: keep an up-to-date cryptography inventory (AEGIS writes a CBOM for every code scan)."],
  ["broken", "Remove broken algorithms first: MD5, SHA-1, DES / 3DES and RC4."],
  ["passwords", "Store passwords with argon2id or bcrypt - never with a plain or fast hash."],
  ["tls", "Allow only TLS 1.2 and 1.3 with modern cipher suites."],
  ["keys", "Use RSA of at least 2048 bits or ECC P-256 or stronger today, and plan their replacement."],
  ["long-lived", "Find data that must stay secret for 10+ years: it is the first target of harvest-now, decrypt-later."],
  ["hybrid", "Move key exchange to hybrid post-quantum (for example X25519 + ML-KEM) where your libraries support it."],
  ["signatures", "Plan signatures and certificates for ML-DSA or SLH-DSA as your CAs and libraries add support."],
  ["agility", "Keep algorithms configurable (crypto agility), so a future swap is a configuration change, not a rewrite."],
];

const statusBadge = (s) => {
  const [kind, label] = STATUS[s] || ["muted", (s || "").toLowerCase()];
  return <Badge kind={kind}>{label}</Badge>;
};

export default function CryptoPQC({ progress, onProgress }) {
  const crypto = useContent("crypto");
  return (
    <WithContent state={crypto} what="The algorithm guide">
      {(data) => <CryptoBody algos={data.items || []} progress={progress} onProgress={onProgress} />}
    </WithContent>
  );
}

function CryptoBody({ algos, progress, onProgress }) {
  const [selected, setSelected] = React.useState(algos[0]?.name || null);
  const [lang, setLang] = React.useState("python");
  const algo = algos.find((a) => a.name === selected);

  return (
    <div className="lr-stack">
      <div className="split lr-split">
        <div>
          <table className="clickable compact">
            <thead><tr><th>Algorithm</th><th>Kind</th><th>Status</th><th>Replace with</th></tr></thead>
            <tbody>
              {algos.map((a) => (
                <tr key={a.name} className={a.name === selected ? "selected" : ""} onClick={() => setSelected(a.name)}>
                  <td><strong>{a.name}</strong></td>
                  <td className="small">{a.kind}</td>
                  <td>{statusBadge(a.status)}</td>
                  <td className="small">{a.replace_with}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="detail-pane">
          {algo ? (
            <div className="lr-detail">
              <div className="row gap"><h3 className="lr-h">{algo.name}</h3>{statusBadge(algo.status)}</div>
              <h4>Why</h4>
              <p>{algo.why}</p>
              <h4>Use instead</h4>
              <p>{algo.replace_with}</p>
              {algo.examples && (
                <>
                  <div className="row gap lr-langs">
                    {LANGS.filter(([k]) => algo.examples[k]).map(([k, label]) => (
                      <button key={k} className={lang === k ? "nav active" : "nav"} onClick={() => setLang(k)}>{label}</button>
                    ))}
                  </div>
                  {algo.examples[lang] && <Code code={algo.examples[lang]} label={`${LANGS.find(([k]) => k === lang)[1]} - the recommended way`} tone="do" />}
                </>
              )}
              {(algo.refs || []).length > 0 && (
                <div className="row gap wrap small">{algo.refs.map((r) => <a key={r} href={r} target="_blank" rel="noreferrer">{r}</a>)}</div>
              )}
            </div>
          ) : <div className="empty">Pick an algorithm.</div>}
        </div>
      </div>

      <div className="lr-block">
        <h3 className="lr-h">Harvest now, decrypt later</h3>
        <div className="lr-prose">
          <p>An attacker can record encrypted traffic or steal encrypted files <strong>today</strong> and keep them. They cannot read them yet.</p>
          <p>A large enough quantum computer running Shor's algorithm would break RSA, Diffie-Hellman and elliptic-curve cryptography, whatever the key size. Recorded data protected only by those algorithms could then be decrypted.</p>
          <p>So the risk depends on <strong>how long the data must stay secret</strong> and <strong>how long your migration takes</strong>: if the two together reach past the day such a computer exists, the data is already at risk. Symmetric ciphers (AES) and hashes (SHA-2) are only weakened, not broken - use 256-bit keys.</p>
          <p>The fix is post-quantum algorithms standardised by NIST in 2024: <strong>ML-KEM</strong> (FIPS 203) for key exchange, <strong>ML-DSA</strong> (FIPS 204) and <strong>SLH-DSA</strong> (FIPS 205) for signatures - usually deployed in hybrid with today's algorithms first.</p>
        </div>
      </div>

      <YourScanCrypto algos={algos} />

      <div className="lr-block">
        <h3 className="lr-h">Migration checklist</h3>
        <ul className="lr-checklist">
          {CHECKLIST.map(([key, text]) => (
            <li key={key}>
              <label className="inline">
                <input type="checkbox" checked={!!progress.checklist?.[key]} onChange={(e) => onProgress({ checklist: { ...progress.checklist, [key]: e.target.checked } })} />
                <span className={progress.checklist?.[key] ? "muted" : ""}>{text}</span>
              </label>
            </li>
          ))}
        </ul>
        <div className="muted small">{CHECKLIST.filter(([k]) => progress.checklist?.[k]).length} of {CHECKLIST.length} done · saved in this browser</div>
      </div>
    </div>
  );
}

const prop = (c, name) => (c.properties || []).find((p) => p.name === name)?.value || "";
const risky = (v) => v && v !== "none";

function guideFor(name, algos) {
  const low = (name || "").toLowerCase();
  return algos.find((a) => (a.match || []).some((m) => low.includes(m)));
}

function YourScanCrypto({ algos }) {
  const cbom = useAsync(latestCbom);
  if (cbom.loading) return <div className="lr-block"><h3 className="lr-h">Your scan's crypto</h3><div className="muted">Loading…</div></div>;
  return (
    <div className="lr-block">
      <h3 className="lr-h">Your scan's crypto</h3>
      {cbom.error && <BackendNote text={backendHint(cbom.error)} onRetry={cbom.run} />}
      {!cbom.error && !cbom.data && <div className="lr-note"><span>No cryptography inventory yet: run a code (M2) or full (M3) scan.</span></div>}
      {cbom.data && <ScanCryptoTable scan={cbom.data.scan} cbom={cbom.data.cbom} algos={algos} />}
    </div>
  );
}

function ScanCryptoTable({ scan, cbom, algos }) {
  const assets = (cbom.components || []).map((c) => {
    const classical = prop(c, "aegis:classical_risk");
    const quantum = prop(c, "aegis:quantum_risk");
    const occ = (c.evidence?.occurrences || [])[0] || {};
    return {
      name: c.name,
      where: occ.location ? `${occ.location}${occ.line ? `:${occ.line}` : ""}` : "",
      classical: risky(classical) ? classical : "",
      quantum: risky(quantum) ? quantum : "",
      guide: guideFor(c.name, algos),
    };
  });
  // readiness: an asset with no risk counts 1, one only at quantum risk 0.5, one broken today 0
  const points = assets.map((a) => (a.classical ? 0 : a.quantum ? 0.5 : 1));
  const score = assets.length ? Math.round((100 * points.reduce((x, y) => x + y, 0)) / assets.length) : null;
  const level = score == null ? "muted" : score >= 80 ? "ok" : score >= 50 ? "warn" : "bad";

  return (
    <div>
      <div className="row gap wrap">
        <span className="mono">{scan.id}</span>
        <span className="muted small">{assets.length} cryptographic assets</span>
        {score != null && <Badge kind={level}>readiness {score}/100</Badge>}
      </div>
      <div className="muted small lr-formula">Readiness: each asset scores 1 with no risk, 0.5 when it is only quantum-vulnerable, 0 when it is broken today; the score is the average × 100.</div>
      {assets.length > 0 && (
        <table className="compact">
          <thead><tr><th>Asset</th><th>Where</th><th>Today</th><th>Quantum</th><th>Replace with</th></tr></thead>
          <tbody>
            {assets.map((a, i) => (
              <tr key={`${a.name}-${i}`}>
                <td><strong>{a.name}</strong></td>
                <td className="mono small">{a.where}</td>
                <td className="small">{a.classical ? <span className="bad">{a.classical}</span> : <span className="muted">ok</span>}</td>
                <td className="small">{a.quantum ? <span className="warn">at risk</span> : <span className="muted">ok</span>}</td>
                <td className="small">{a.guide?.replace_with || "-"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
