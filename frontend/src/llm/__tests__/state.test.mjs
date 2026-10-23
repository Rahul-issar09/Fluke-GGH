// AI-model settings checks. Run: node --test src/llm/__tests__/   (no extra packages)
// The key is held only until the server has validated it, never shown, and dropped on every reset.
import assert from "node:assert/strict";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import {
  askRoute, badgeFor, scanStart, chatModels, consentBody, errorText, initialSettings, keyLooksValid, keyTransportProblem, onlineNotice,
  settingsReducer, visibleSettings,
} from "../state.js";

const KEY = "AIzaSyUI-test-key-never-shown-000000001";
const run = (actions, state = initialSettings) => actions.reduce(settingsReducer, state);

test("the key is dropped as soon as the server has validated it", () => {
  const s = run([{ type: "mode", mode: "online" }, { type: "key", value: KEY },
                 { type: "models", models: [{ id: "gemini-2.5-flash" }] },
                 { type: "validated", validation: { id: "v1", consentOnRecord: false } }]);
  assert.equal(s.apiKey, "");
  assert.equal(s.validation.id, "v1");
  assert.equal(s.model, "gemini-2.5-flash");
});

test("switching mode, resetting and finishing all drop the key", () => {
  for (const action of [{ type: "mode", mode: "offline" }, { type: "reset" }, { type: "done" }]) {
    const s = run([{ type: "mode", mode: "online" }, { type: "key", value: KEY }, action]);
    assert.equal(s.apiKey, "");
  }
});

test("what may be shown never contains the key", () => {
  const s = run([{ type: "mode", mode: "online" }, { type: "key", value: KEY }]);
  const shown = JSON.stringify(visibleSettings(s));
  assert.ok(!shown.includes(KEY));
  assert.equal(visibleSettings(s).keyEntered, true);
});

test("a new key clears an earlier validation and model list", () => {
  const s = run([{ type: "key", value: KEY }, { type: "models", models: [{ id: "m" }] },
                 { type: "validated", validation: { id: "v1" } }, { type: "key", value: KEY + "x" }]);
  assert.equal(s.validation, null);
  assert.deepEqual(s.models, []);
});

test("key shape check before any request", () => {
  assert.ok(keyLooksValid(KEY));
  for (const bad of ["", "short", "has spaces in the middle of it", "x".repeat(300)]) assert.ok(!keyLooksValid(bad));
});

test("embedding models are not offered as chat models", () => {
  const models = [{ id: "qwen2.5:7b", capabilities: ["generate"] }, { id: "bge-m3:latest", capabilities: ["embedding"] },
                  { id: "llama2:latest", capabilities: [] }];
  assert.deepEqual(chatModels(models).map((m) => m.id), ["qwen2.5:7b", "llama2:latest"]);
});

test("the badge says offline, online or key needed", () => {
  assert.deepEqual(badgeFor({ model: "qwen2.5:7b", location: "local" }).text, "qwen2.5:7b · offline");
  assert.equal(badgeFor({ model: "gemini-2.5-flash", location: "cloud" }).kind, "warn");
  assert.equal(badgeFor({ model: "qwen2.5:7b", location: "local", awaiting_key: true }).text, "online · key needed");
});

test("the online notice mentions source code only when allowed", () => {
  assert.equal(onlineNotice({ location: "local" }), null);
  assert.ok(!onlineNotice({ location: "cloud", model: "g", allow_source_code: false }).includes("source code"));
  assert.ok(onlineNotice({ location: "cloud", model: "g", allow_source_code: true }).includes("source code"));
});

test("New scan never starts on a mode other than the one selected", () => {
  const offline = { location: "local", model: "qwen2.5:7b" };
  const online = { location: "cloud", model: "gemini-2.5-flash" };
  const waiting = { location: "local", model: "qwen2.5:7b", awaiting_key: true, online_model: "gemini-2.5-flash" };
  assert.equal(scanStart("offline", null).ok, false);                           // settings not loaded yet
  assert.deepEqual(scanStart("offline", offline), { ok: true, goOffline: false, reason: null });
  assert.deepEqual(scanStart("offline", online), { ok: true, goOffline: true, reason: null });   // switch first
  assert.equal(scanStart("offline", waiting).goOffline, true);                 // drop the pending online choice
  assert.deepEqual(scanStart("online", online), { ok: true, goOffline: false, reason: null });
  for (const cfg of [offline, waiting]) {                                       // online, but not in effect
    const s = scanStart("online", cfg);
    assert.equal(s.ok, false);
    assert.match(s.reason, /Gemini key/);
  }
  assert.equal(scanStart(null, offline).ok, false);                             // no mode reported yet
});

test("the Ask box says where a question goes, and never claims the model answered", () => {
  assert.equal(askRoute(null), null);
  assert.match(askRoute({ location: "local", model: "qwen2.5:7b" }), /on this machine by qwen2\.5:7b \(offline\)/);
  assert.match(askRoute({ location: "cloud", model: "gemini-2.5-flash" }), /sent to Gemini gemini-2\.5-flash \(online\)/);
  for (const cfg of [{ location: "local", model: "m" }, { location: "cloud", model: "m" }]) {
    assert.match(askRoute(cfg), /without AI/);
    assert.doesNotMatch(askRoute(cfg), /answered by/i);
  }
});

test("server errors become plain sentences", () => {
  assert.match(errorText({ status: 422, body: { error: "invalid_api_key", detail: "Gemini refused the API key (HTTP 400)" } }),
               /Check it in Google AI Studio/);
  assert.match(errorText({ status: 429, body: { error: "provider_quota_exhausted" } }), /daily Gemini quota/);
  assert.match(errorText({ status: 403, body: { error: "config_api_forbidden" } }), /machine AEGIS runs on/);
  assert.equal(errorText({ status: 500, body: { detail: "boom" } }), "boom");
});

test("a key is only typed where it does not cross the network unencrypted", () => {
  assert.equal(keyTransportProblem({ protocol: "http:", hostname: "127.0.0.1" }), null);
  assert.equal(keyTransportProblem({ protocol: "http:", hostname: "localhost" }), null);
  assert.equal(keyTransportProblem({ protocol: "https:", hostname: "aegis.example.com" }), null);
  assert.match(keyTransportProblem({ protocol: "http:", hostname: "aegis.lan" }), /unencrypted/);
});

test("the consent body carries the version that was shown", () => {
  assert.deepEqual(consentBody({ version: "2026-10-22.1" }, true),
                   { disclosure_version: "2026-10-22.1", accepted: true, allow_source_code: true });
});

test("no settings code stores anything in the browser or logs to the console", () => {
  const files = [];
  const walk = (dir) => readdirSync(dir).forEach((f) => {
    const p = join(dir, f);
    if (statSync(p).isDirectory()) { if (f !== "__tests__") walk(p); } else if (/\.(jsx?|mjs)$/.test(f)) files.push(p);
  });
  walk(fileURLToPath(new URL("..", import.meta.url)));
  for (const name of ["LlmSettings.jsx", "CloudConsent.jsx"]) {
    files.push(fileURLToPath(new URL(`../../components/${name}`, import.meta.url)));
  }
  for (const f of files) {
    const src = readFileSync(f, "utf8");
    assert.ok(!/localStorage|sessionStorage|indexedDB|console\./.test(src), `${f} must not store or log anything`);
  }
});
