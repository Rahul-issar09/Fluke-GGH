// Community safety checks. Run: node --test src/community/__tests__/   (no extra packages)
// Covers the Markdown reader (no markup, no script links), finding redaction, the secret guard,
// image checks, and the rules the data layer enforces (owners, votes, moderators, secrets).
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { scanForSecrets } from "../guard.js";
import { checkImageRef, sniffImage } from "../images.js";
import { parseInline, parseMarkdown, plainText, safeHref } from "../markdown.js";
import { redactFinding, redactText } from "../redact.js";

// ── the mock data layer runs in node with a fake localStorage and the real seed file ──
const store = new Map();
globalThis.localStorage = { getItem: (k) => store.get(k) ?? null, setItem: (k, v) => store.set(k, String(v)), removeItem: (k) => store.delete(k) };
const seed = readFileSync(new URL("../../../public/community/seed.json", import.meta.url), "utf8");
globalThis.fetch = async () => ({ json: async () => JSON.parse(seed) });
const { mockApi: api } = await import("../mockApi.js");
const PW = JSON.parse(seed).demoPassword;
const as = async (name) => { await api.signOut(); return api.signIn(name, PW); };
const rejects = async (p, code) => assert.equal((await p.then(() => ({ code: "NO_ERROR" }), (e) => e)).code, code);

const allText = (nodes) => nodes.map((n) => (n.v ?? "") + allText(n.c || [])).join("");

test("markdown keeps raw HTML as plain text", () => {
  const blocks = parseMarkdown('<script>alert(1)</script>\n\n<img src=x onerror="alert(1)">');
  assert.equal(blocks.length, 2);
  assert.ok(blocks.every((b) => b.t === "p"));
  assert.equal(allText(blocks[0].c), "<script>alert(1)</script>");
});

test("markdown links: only http(s) become links", () => {
  for (const bad of ["javascript:alert(1)", "data:text/html,<b>x</b>", "vbscript:x", "JaVaScRiPt:alert(1)"]) {
    const nodes = parseInline(`[click](${bad})`);
    assert.ok(nodes.every((n) => n.t !== "a"), bad);
    assert.equal(safeHref(bad), null);
  }
  const ok = parseInline("[docs](https://owasp.org/x) and https://example.org/a.");
  assert.deepEqual(ok.filter((n) => n.t === "a").map((n) => n.href), ["https://owasp.org/x", "https://example.org/a"]);
});

test("markdown blocks, inline styles and mentions", () => {
  const b = parseMarkdown("# Title\n\n- one\n- two\n\n1. a\n\n> quote\n\n```python\nx = '<b>'\n```\ntext **bold** *it* `code` @demo_ana");
  assert.deepEqual(b.map((x) => x.t), ["h", "ul", "ol", "quote", "code", "p"]);
  assert.equal(b[4].text, "x = '<b>'");
  assert.deepEqual(b[5].c.map((n) => n.t), ["text", "b", "text", "i", "text", "code", "text", "mention"]);
  assert.equal(plainText("**Hi** [x](https://a.org)\n\n- a\n- b", 100), "Hi x a; b");
});

test("finding redaction hides hosts and paths, drops evidence", () => {
  const f = {
    id: "F-1", type: "ssrf", owasp: "A10", state: "confirmed", file: "C:\\Users\\hp\\proj\\app\\routes\\fetch.py", line: 17,
    title: "SSRF via 'url' on http://10.0.0.5:8080/api/fetch from /home/bob/app/x.py and localhost:5000", evidence: { payload: "secret" },
  };
  const r = redactFinding(f, "S-1");
  assert.deepEqual(Object.keys(r).sort(), ["category", "id", "owasp", "scanId", "state", "summary"]);
  assert.ok(!/10\.0\.0\.5|localhost|Users|home\/bob|routes/.test(r.summary), r.summary);
  assert.match(r.summary, /<target>/);
  assert.match(r.summary, /\(in fetch\.py:17\)$/);
  assert.equal(redactText("GET /api/accounts/{id} in app/routes/accounts.py"), "GET /api/accounts/{id} in accounts.py");
});

test("secret guard finds tokens and masks them", () => {
  const hits = scanForSecrets("ok\nkey = AKIAABCDEFGHIJKLMNOP\ntoken ghp_" + "a".repeat(36));
  assert.deepEqual(hits.map((h) => [h.line, h.type]), [[2, "AWS access key"], [3, "GitHub token"]]);
  assert.ok(hits.every((h) => h.preview.length <= 8));
  assert.equal(scanForSecrets("password = os.environ['DB_PASSWORD']").length, 0);
});

test("images: real bytes decide, SVG refused", () => {
  assert.equal(sniffImage(Uint8Array.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])), "png");
  const svg = Buffer.from('<svg onload="alert(1)"/>').toString("base64");
  assert.throws(() => checkImageRef(`data:image/svg+xml;base64,${svg}`));
  assert.throws(() => checkImageRef(`data:image/png;base64,${svg}`)); // claims PNG, is not
});

test("data layer: reading needs no account; writing does", async () => {
  await api.signOut();
  assert.ok((await api.listQuestions({})).items.length > 0);
  assert.ok((await api.getQuestion("q-1")).answers.length > 0);
  await rejects(api.createPost({ type: "text", body: "hi", tags: [] }), "UNAUTHENTICATED");
});

test("data layer: secret posts are blocked", async () => {
  await as("demo_ben");
  await rejects(api.createPost({ type: "text", body: "my key AKIAABCDEFGHIJKLMNOP", tags: [] }), "SECRET_FOUND");
  await rejects(api.askQuestion({ title: "Why does my GitHub token leak?", body: "token ghp_" + "b".repeat(36), tags: ["git"] }), "SECRET_FOUND");
});

test("data layer: only owners edit or delete; no voting on your own", async () => {
  await as("demo_ben");
  const p = await api.createPost({ type: "text", body: "mine", tags: ["test"] });
  await as("demo_cara");
  await rejects(api.updatePost(p.id, { body: "hacked" }), "FORBIDDEN");
  await rejects(api.deletePost(p.id), "FORBIDDEN");
  const q = await api.askQuestion({ title: "How should I store session tokens?", body: "Cookie or localStorage?", tags: ["sessions"] });
  await rejects(api.voteQuestion(q.id, 1), "FORBIDDEN");
  await as("demo_ben");
  await rejects(api.acceptAnswer("q-1", "a-1"), "FORBIDDEN"); // only the asker accepts
  assert.equal((await api.deletePost(p.id)).ok, true);
});

test("moderation: reports reach moderators only; remove deletes the item", async () => {
  await as("demo_ana");
  await rejects(api.listReports(), "FORBIDDEN");
  const p = await api.createPost({ type: "text", body: "buy cheap followers", tags: [] });
  await as("demo_ben");
  await rejects(api.report("post", "p-nope", "spam"), "NOT_FOUND");
  await api.report("post", p.id, "spam");
  const mod = await as("demo_mod");
  assert.equal(mod.moderator, true);
  const queue = await api.listReports();
  const g = queue.find((x) => x.targetId === p.id);
  assert.ok(g && g.target.exists && g.reasons.includes("spam"));
  await api.resolveReport(g.id, "remove");
  await rejects(api.getPost(p.id), "NOT_FOUND");
  assert.ok(!(await api.listReports()).some((x) => x.targetId === p.id));
  const seeded = (await api.listReports()).find((x) => x.targetId === "p-12");
  await api.resolveReport(seeded.id, "dismiss");
  assert.ok(await api.getPost("p-12")); // dismiss keeps it
});
