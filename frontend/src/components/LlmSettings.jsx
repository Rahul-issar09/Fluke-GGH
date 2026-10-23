// AI model settings (LLM_PROVIDER_PHASES LP8): Offline (Ollama on this machine) or Online (Gemini).
// The Gemini key is typed here for every run of AEGIS and lives only in this component's state until
// the server has validated it; the server keeps it in memory for this run and never saves it.
import React from "react";
import { api } from "../api.js";
import {
  badgeFor, chatModels, consentBody, errorText, initialSettings, keyLooksValid, keyTransportProblem, settingsReducer,
} from "../llm/state.js";
import CloudConsent from "./CloudConsent.jsx";
import { Badge, Loading, useLoad } from "./ui.jsx";

// `compact`: the same controls inside New scan, under a smaller heading. `onModeChange(mode)` tells the
// page which mode is selected, so it can hold the scan until that mode is really in effect.
export default function LlmSettings({ onChanged, onModeChange, compact = false }) {
  const config = useLoad(() => api.llmConfig(), []);
  const providers = useLoad(() => api.llmProviders(), []);
  const [state, dispatch] = React.useReducer(settingsReducer, initialSettings);
  const [consentFor, setConsentFor] = React.useState(null);   // the validation awaiting the user's agreement

  const cfg = config.data;
  const gemini = (providers.data || []).find((p) => p.id === "gemini");

  const [started, setStarted] = React.useState(false);   // the mode below has been set from the server
  React.useEffect(() => {   // start on the mode that is in effect (or chosen and waiting for its key)
    if (!cfg) return;
    dispatch({ type: "mode", mode: cfg.location === "cloud" || cfg.awaiting_key ? "online" : "offline" });
    setStarted(true);
  }, [cfg?.generation]); // eslint-disable-line react-hooks/exhaustive-deps

  // not before: the reducer's initial "offline" is a placeholder, not the user's choice
  React.useEffect(() => { if (started) onModeChange?.(state.mode); }, [state.mode, started]); // eslint-disable-line react-hooks/exhaustive-deps

  const refresh = async (next) => {
    const fresh = next || (await api.llmConfig());
    config.reload();
    onChanged?.(fresh);
  };

  async function run(what, fn) {
    dispatch({ type: "busy", what });
    try {
      return await fn();
    } catch (error) {
      dispatch({ type: "error", error });
      return undefined;
    }
  }

  // ---- online: key → models → validate → (consent) → activate
  const loadModels = () => run("loading", async () => {
    const { models } = await api.llmDiscover(state.apiKey.trim());
    dispatch({ type: "models", models: chatModels(models), prefer: cfg.online_model });
  });

  const validate = () => run("validating", async () => {
    const out = await api.llmValidate("gemini", state.model, state.apiKey.trim());
    const validation = { id: out.validation_id, consentOnRecord: out.consent_on_record, disclosure: out.disclosure,
                         warnings: out.warnings };
    dispatch({ type: "validated", validation });                        // the key leaves this page's state here
    if (validation.consentOnRecord) await activate(validation, null);  // the same key as before: consent stands
    else setConsentFor(validation);
  });

  const activate = (validation, allowCode) => run("activating", async () => {
    const body = { provider: "gemini", model: state.model, validation_id: validation.id };
    if (allowCode !== null) body.consent = consentBody(validation.disclosure, allowCode);
    const next = await api.llmActivate(body);
    dispatch({ type: "done" });
    setConsentFor(null);
    await refresh(next);
  });

  const goOffline = (model) => run("activating", async () => {
    const next = await api.llmOffline(model);
    dispatch({ type: "done" });
    await refresh(next);
  });

  const forgetKey = () => run("activating", async () => {
    const next = await api.llmForgetKey();
    dispatch({ type: "done" });
    await refresh(next);
  });

  const transportProblem = keyTransportProblem(window.location);
  if (config.loading && !cfg) return <Loading what="Loading the AI model settings" />;
  if (config.error) return <div className="error">{errorText(config.error)}</div>;
  const badge = badgeFor(cfg);
  const keyFromServer = cfg.key?.configured && cfg.key.source !== "session";

  return (
    <section className={compact ? "llm-settings llm-compact" : "llm-settings"}>
      <div className="row between">
        {compact ? <h3>AI for this scan</h3> : <h2>AI model</h2>}
        <div className="row gap">
          <Badge kind={badge.kind}>{badge.text}</Badge>
          {(cfg.location === "cloud" || cfg.awaiting_key) && (
            <button onClick={() => goOffline()} disabled={Boolean(state.busy)}>Go offline now</button>
          )}
        </div>
      </div>
      <p className="muted small">{badge.title} Embeddings and the search index always stay on this machine
        ({cfg.embeddings.model}).{compact && " The choice also applies to questions in Ask; each scan records the model it used."}</p>

      {cfg.awaiting_key && (
        <p className="warning">Online mode{cfg.online_model ? ` (Gemini ${cfg.online_model})` : ""} is chosen, but the
          Gemini API key has not been entered since AEGIS started — AEGIS asks for it on every run and never saves it.
          Until then it runs offline. Enter the key below; the same key as before needs no new agreement.</p>
      )}
      {cfg.config_error && !cfg.awaiting_key && <p className="warning small">{cfg.config_error}</p>}
      {state.error && <div className="error" role="alert">{errorText(state.error)}</div>}

      <div className="row gap mode-choice" role="radiogroup" aria-label="AI mode">
        <label className="row gap"><input type="radio" name="mode" checked={state.mode === "offline"}
          onChange={() => dispatch({ type: "mode", mode: "offline" })} /> Offline — Ollama on this machine</label>
        <label className="row gap"><input type="radio" name="mode" checked={state.mode === "online"} disabled={!gemini?.allowed}
          onChange={() => dispatch({ type: "mode", mode: "online" })} /> Online — Google Gemini</label>
      </div>
      {gemini && !gemini.allowed && <p className="muted small">Online mode: {gemini.reason}</p>}

      {state.mode === "offline" ? (
        <OfflinePanel cfg={cfg} busy={state.busy} onUse={goOffline} />
      ) : (
        <div className="panel-block">
          {cfg.key?.configured && (
            <p className="small">Key in use this run: <span className="mono">…{cfg.key.last4}</span>{" "}
              <span className="muted">({cfg.key.source === "session" ? "entered this run, memory only" : `from the server's ${cfg.key.source === "env" ? "environment" : "key file"}`})</span>
              {cfg.key.source === "session" && <> · <button className="link" onClick={forgetKey} disabled={Boolean(state.busy)}>Forget it</button></>}
            </p>
          )}
          <form className="form" onSubmit={(e) => { e.preventDefault(); loadModels(); }}>
            <label>
              Gemini API key {keyFromServer ? <span className="muted small">(optional: the server already has one)</span> : null}
              {transportProblem && <span className="warning small" role="alert">{transportProblem}</span>}
              <input type="password" value={state.apiKey} autoComplete="new-password" spellCheck={false}
                     disabled={Boolean(transportProblem)}
                     placeholder="asked every run · never saved" aria-describedby="key-help"
                     onChange={(e) => dispatch({ type: "key", value: e.target.value })} />
              <span id="key-help" className="muted small">Sent only to this AEGIS server, which keeps it in memory until it
                stops. It is not stored in this browser.</span>
            </label>
            <div className="row gap">
              <button type="submit" disabled={Boolean(state.busy) || (!keyFromServer && !keyLooksValid(state.apiKey))}>
                {state.busy === "loading" ? "Loading models…" : "Load models"}</button>
            </div>
          </form>

          {state.models.length > 0 && (
            <form className="form" onSubmit={(e) => { e.preventDefault(); validate(); }}>
              <label>
                Model
                <select value={state.model} onChange={(e) => dispatch({ type: "model", model: e.target.value })}>
                  {state.models.map((m) => (
                    <option key={m.id} value={m.id}>
                      {m.display_name} ({m.id}){m.stage !== "stable" ? ` · ${m.stage}` : ""}{m.thinking ? " · thinking" : ""}
                    </option>
                  ))}
                </select>
              </label>
              <div className="row gap">
                <button type="submit" className="primary" disabled={Boolean(state.busy) || !state.model}>
                  {state.busy === "validating" ? "Checking the model…" : state.busy === "activating" ? "Switching…" : "Validate and switch"}
                </button>
                <span className="muted small">A tiny test request proves the key and model work before anything else is sent.</span>
              </div>
            </form>
          )}
        </div>
      )}

      {consentFor && (
        <CloudConsent disclosure={consentFor.disclosure} model={state.model}
                      onAccept={(allowCode) => activate(consentFor, allowCode)}
                      onCancel={() => { setConsentFor(null); dispatch({ type: "reset" }); }} />
      )}
    </section>
  );
}

function OfflinePanel({ cfg, busy, onUse }) {
  const models = useLoad(() => api.llmModels("ollama"), []);
  const [model, setModel] = React.useState("");
  const options = chatModels(models.data?.models);
  const current = cfg.provider === "ollama" ? cfg.model : "";
  return (
    <div className="panel-block">
      {models.error && <div className="error">{errorText(models.error)}</div>}
      {models.loading && !models.data && <Loading what="Asking Ollama for its models" />}
      {models.data && (
        <form className="form" onSubmit={(e) => { e.preventDefault(); onUse(model || current || undefined); }}>
          <label>
            Local model
            <select value={model || current} onChange={(e) => setModel(e.target.value)}>
              {!options.some((m) => m.id === current) && current && <option value={current}>{current} (not pulled)</option>}
              {options.map((m) => <option key={m.id} value={m.id}>{m.id}</option>)}
            </select>
          </label>
          <div className="row gap">
            <button type="submit" className="primary" disabled={Boolean(busy)}>
              {cfg.location === "cloud" || cfg.awaiting_key ? "Go offline with this model" : "Use this model"}</button>
            <span className="muted small">Nothing leaves this machine in Offline mode.</span>
          </div>
        </form>
      )}
    </div>
  );
}
