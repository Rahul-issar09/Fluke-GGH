// Secure Prompt checks. Run: node --test src/secure/__tests__/   (no extra packages)
import assert from "node:assert/strict";
import { test } from "node:test";
import {
  EXAMPLES, MAX_PROMPT, bulletsAsText, coverageSummary, extensionFor, groupBullets, lockedText, onlineState, promptProblem,
  secureErrorText, sendNotice,
} from "../state.js";

const gemini = { provider: "gemini", model: "gemini-2.5-flash", location: "cloud", awaiting_key: false };
const ollama = { provider: "ollama", model: "qwen2.5:7b", location: "local", awaiting_key: false };

test("only Gemini Online mode with this run's key unlocks the page", () => {
  assert.deepEqual(onlineState(gemini), { ready: true, reason: null });
  assert.equal(onlineState(ollama).ready, false);
  assert.equal(onlineState(ollama).reason, "offline");
  assert.equal(onlineState({ ...gemini, awaiting_key: true }).reason, "key");
  assert.equal(onlineState(null).reason, "loading");
});

test("the locked text says what to do and never offers a local fallback", () => {
  assert.match(lockedText("offline"), /Gemini Online mode/);
  assert.match(lockedText("key"), /key/);
  assert.doesNotMatch(lockedText("offline"), /Ollama|local model/i);
});

test("the request text is checked before it is sent", () => {
  assert.ok(promptProblem("hi"));
  assert.ok(promptProblem("   "));
  assert.equal(promptProblem("make a login API"), null);
  assert.ok(promptProblem("x".repeat(MAX_PROMPT + 1)));
  assert.ok(EXAMPLES.every((e) => promptProblem(e) === null));
});

test("the privacy notice says only the request text is sent", () => {
  const text = sendNotice(gemini);
  assert.match(text, /Only the text of your request/);
  assert.match(text, /No code, scan results or files/);
  assert.match(text, /gemini-2\.5-flash/);
});

test("bullets are grouped by OWASP id in order, and coverage is counted", () => {
  const bullets = [
    { owasp: "A07", category: "Identification and Authentication Failures", action: "rate limit", why: "stops guessing" },
    { owasp: "A02", category: "Cryptographic Failures", action: "argon2id", why: "slow hash" },
    { owasp: "A02", category: "Cryptographic Failures", action: "salt", why: "unique hashes" },
  ];
  const groups = groupBullets(bullets);
  assert.deepEqual(groups.map((g) => [g.id, g.items.length]), [["A02", 2], ["A07", 1]]);
  assert.deepEqual(coverageSummary([{ status: "covered" }, { status: "covered" }, { status: "not_applicable" }, { status: "not_covered" }]),
                   { covered: 2, notApplicable: 1, notCovered: 1 });
  assert.match(bulletsAsText({ bullets }), /A02 Cryptographic Failures\n {2}- argon2id \(slow hash\)/);
});

test("errors are friendly and keep detail out of the way", () => {
  assert.match(secureErrorText({ body: { error: "online_required" } }), /Online mode/);
  assert.match(secureErrorText({ body: { error: "generation_failed" } }), /Try again/);
  assert.match(secureErrorText({ status: 422, body: {} }), /check the text/);
  assert.equal(secureErrorText(null), null);
});

test("file extensions follow the language, with a safe default", () => {
  assert.equal(extensionFor("flask"), "py");
  assert.equal(extensionFor("node"), "js");
  assert.equal(extensionFor("cobol"), "txt");
});
