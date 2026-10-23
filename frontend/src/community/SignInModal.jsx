import React from "react";
import { isMock, signIn, signUp } from "./api.js";

// Sign in / sign up. onDone(user) runs after success; onClose closes without signing in.
export default function SignInModal({ onDone, onClose }) {
  const [mode, setMode] = React.useState("signin");
  const [name, setName] = React.useState("");
  const [password, setPassword] = React.useState("");
  const [error, setError] = React.useState("");
  const [busy, setBusy] = React.useState(false);
  const first = React.useRef(null);

  React.useEffect(() => {
    first.current?.focus();
    const onKey = (e) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  async function submit(e) {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      onDone(await (mode === "signin" ? signIn(name, password) : signUp(name, password)));
    } catch (err) {
      setError(err.message || "Something went wrong.");
      setBusy(false);
    }
  }

  const up = mode === "signup";
  return (
    <div className="overlay" onClick={onClose}>
      <form className="dialog cm-dialog" role="dialog" aria-modal="true" aria-label={up ? "Create account" : "Sign in"} onClick={(e) => e.stopPropagation()} onSubmit={submit}>
        <h3 className="cm-dialog-title">{up ? "Create an account" : "Sign in"}</h3>
        <label className="cm-field">
          Name
          <input ref={first} value={name} onChange={(e) => setName(e.target.value)} autoComplete="username" autoCapitalize="none" spellCheck="false" required />
          {up && <span className="muted small">3-24 characters: a-z, 0-9 and _</span>}
        </label>
        <label className="cm-field">
          Password
          <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete={up ? "new-password" : "current-password"} required />
          {up && <span className="muted small">At least 8 characters</span>}
        </label>
        {error && <div className="cm-error" role="alert">{error}</div>}
        <div className="row gap cm-dialog-actions">
          <button className="primary" type="submit" disabled={busy}>{busy ? "…" : up ? "Create account" : "Sign in"}</button>
          <button type="button" className="link" onClick={() => { setMode(up ? "signin" : "signup"); setError(""); }}>
            {up ? "I have an account" : "Create an account"}
          </button>
          <span className="grow" />
          <button type="button" onClick={onClose}>Cancel</button>
        </div>
        {isMock && <p className="muted small cm-hint">Demo accounts: demo_ana, demo_ben, demo_cara, demo_dev, demo_eli, demo_mod — password <span className="mono">demo-password</span>. Accounts you create stay in this browser.</p>}
      </form>
    </div>
  );
}
