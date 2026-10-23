// Before anything is sent to a cloud model: the server's privacy notice, word for word, and an
// explicit agreement (LLM_PROVIDER_PHASES §9.1–9.2). Source code is a separate, unticked choice.
import React from "react";

export default function CloudConsent({ disclosure, model, onAccept, onCancel }) {
  const [confirm, setConfirm] = React.useState("");
  const [allowCode, setAllowCode] = React.useState(false);
  const ready = confirm.trim().toUpperCase() === "YES";
  return (
    <div className="overlay" onClick={onCancel}>
      <form className="dialog consent" role="dialog" aria-modal="true" aria-labelledby="consent-title"
            onClick={(e) => e.stopPropagation()}
            onSubmit={(e) => { e.preventDefault(); if (ready) onAccept(allowCode); }}>
        <h3 id="consent-title">Switch to Online mode: Gemini {model}</h3>
        <p className="warning">{disclosure.text}</p>
        <label className="row gap consent-option">
          <input type="checkbox" checked={allowCode} onChange={(e) => setAllowCode(e.target.checked)} />
          <span>{disclosure.source_code_text}</span>
        </label>
        <label className="consent-confirm">
          <span>Type <b>YES</b> to agree (privacy notice version <span className="mono">{disclosure.version}</span>)</span>
          <input value={confirm} onChange={(e) => setConfirm(e.target.value)} autoComplete="off" spellCheck={false}
                 aria-label="Type YES to agree" autoFocus />
        </label>
        <div className="row gap">
          <button type="submit" className="primary" disabled={!ready}>Agree and go online</button>
          <button type="button" onClick={onCancel}>Stay offline</button>
        </div>
      </form>
    </div>
  );
}
