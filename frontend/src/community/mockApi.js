// Mock of the Community API. State lives in this browser (localStorage "aegis.community.v1") and is seeded
// from public/community/seed.json. It enforces the same rules the real backend must: only owners edit or
// delete, nobody votes on their own item, images are checked by magic bytes, secrets are refused.
// It is NOT a security boundary: passwords are hashed here only so they are not stored as plain text.

import { ApiError } from "./errors.js";
import { scanForSecrets } from "./guard.js";
import { MAX_IMAGES, checkImageRef } from "./images.js";
import { CODE_LANGS, JOB_LEVELS, REPORT_REASONS, RESOURCE_KINDS } from "./types.js";

const KEY = "aegis.community.v1";
const LATENCY = 150;
const PAGE = 10;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const fail = (code, message, extra) => { throw new ApiError(code, message, extra); };

// ── storage ───────────────────────────────────────────────
let mem = null;
const save = () => { try { localStorage.setItem(KEY, JSON.stringify(mem)); } catch { /* private mode: kept in memory only */ } };

async function hash(password, salt) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: new TextEncoder().encode(salt), iterations: 10000 }, key, 256);
  return [...new Uint8Array(bits)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
const newSalt = () => [...crypto.getRandomValues(new Uint8Array(8))].map((b) => b.toString(16).padStart(2, "0")).join("");

async function buildState(seed) {
  const now = Date.now();
  const iso = (hoursAgo) => new Date(now - hoursAgo * 3600e3).toISOString();
  const users = [];
  for (const u of seed.users) {
    const salt = newSalt();
    users.push({ id: u.id, name: u.name, avatarColor: u.avatarColor, joinedAt: iso(u.joinedDaysAgo * 24), salt, hash: await hash(seed.demoPassword, salt) });
  }
  return {
    seq: 1000,
    session: null,
    users,
    posts: seed.posts.map((p) => ({ images: [], ...p, createdAt: iso(p.ageHours), likes: p.likes || [], baseLikes: p.baseLikes || 0 })),
    comments: seed.comments.map((c) => ({ ...c, createdAt: iso(c.ageHours) })),
    questions: seed.questions.map((q) => ({ ...q, createdAt: iso(q.ageHours), votes: q.votes || {}, acceptedAnswer: q.acceptedAnswer || null })),
    answers: seed.answers.map((a) => ({ ...a, createdAt: iso(a.ageHours), votes: a.votes || {} })),
    resources: seed.resources.map((r) => ({ ...r, createdAt: iso(r.ageHours), voters: r.voters || [] })),
    jobs: seed.jobs.map((j) => ({ ...j, postedAt: iso(j.ageHours), expiresAt: new Date(now + j.daysLeft * 86400e3).toISOString() })),
    notifications: seed.notifications.map((n) => ({ ...n, createdAt: iso(n.ageHours) })),
    reports: (seed.reports || []).map((r) => ({ status: "open", ...r, createdAt: iso(r.ageHours) })),
  };
}

let booting = null; // the first calls arrive together; they all wait for one load
async function boot() {
  try {
    const raw = localStorage.getItem(KEY);
    if (raw) { mem = JSON.parse(raw); return mem; }
  } catch { /* unreadable: start from the seed */ }
  const resp = await fetch("/community/seed.json");
  mem = await buildState(await resp.json());
  save();
  return mem;
}
const state = () => (mem ? Promise.resolve(mem) : (booting ??= boot()));

const call = (fn) => async (...args) => {
  await sleep(LATENCY);
  const s = await state();
  const out = await fn(s, ...args);
  save();
  return out;
};
const nextId = (s, prefix) => `${prefix}-${++s.seq}`;

// ── derived values ────────────────────────────────────────
const up = (item) => (item.baseUp || 0) + Object.values(item.votes || {}).filter((v) => v === 1).length;
const down = (item) => (item.baseDown || 0) + Object.values(item.votes || {}).filter((v) => v === -1).length;
const likeCount = (p) => (p.baseLikes || 0) + p.likes.length;

function reputation(s, uid) {
  let rep = 0;
  for (const p of s.posts) if (p.author === uid) rep += 2 * likeCount(p);
  for (const q of s.questions) if (q.author === uid) rep += 5 * up(q) - 2 * down(q);
  for (const a of s.answers) {
    if (a.author !== uid) continue;
    rep += 10 * up(a) - 2 * down(a);
    if (s.questions.some((q) => q.acceptedAnswer === a.id)) rep += 15;
  }
  return Math.max(0, rep);
}

function badgesOf(s, uid) {
  const accepted = s.answers.filter((a) => a.author === uid && s.questions.some((q) => q.acceptedAnswer === a.id)).length;
  const out = [];
  if (s.posts.some((p) => p.author === uid)) out.push("First post");
  if (s.answers.some((a) => a.author === uid)) out.push("First answer");
  if (accepted >= 5) out.push("Helper");
  if (s.posts.filter((p) => p.author === uid && p.type === "finding").length >= 3) out.push("Bug hunter");
  return out;
}

// Moderators are known by name, so browsers holding older demo data need no reset.
const MODERATORS = new Set(["demo_mod"]);
const isModerator = (s, uid) => MODERATORS.has(s.users.find((x) => x.id === uid)?.name);

const userView = (s, id) => {
  const u = s.users.find((x) => x.id === id);
  if (!u) return { id, name: "deleted_user", avatarColor: "#64748b", reputation: 0, badges: [], joinedAt: new Date(0).toISOString() };
  return { id: u.id, name: u.name, avatarColor: u.avatarColor, reputation: reputation(s, u.id), badges: badgesOf(s, u.id), joinedAt: u.joinedAt, ...(MODERATORS.has(u.name) ? { moderator: true } : {}) };
};

function postView(s, p, depth = 0) {
  const original = p.repostOf && depth === 0 ? s.posts.find((x) => x.id === p.repostOf) : null;
  const view = {
    id: p.id, author: userView(s, p.author), type: p.type, body: p.body || "", images: p.images || [], tags: p.tags || [],
    likeCount: likeCount(p), likedByMe: !!s.session && p.likes.includes(s.session),
    commentCount: s.comments.filter((c) => c.postId === p.id).length, createdAt: p.createdAt,
  };
  if (p.title) view.title = p.title;
  if (p.code) view.code = p.code;
  if (p.finding) view.finding = p.finding;
  if (p.editedAt) view.editedAt = p.editedAt;
  if (p.type === "repost") view.repostOf = original ? postView(s, original, 1) : null;
  return view;
}

function answerView(s, a) {
  return { id: a.id, questionId: a.questionId, author: userView(s, a.author), body: a.body, votes: up(a) - down(a), myVote: (s.session && a.votes[s.session]) || 0, accepted: s.questions.some((q) => q.acceptedAnswer === a.id), createdAt: a.createdAt };
}

function questionView(s, q) {
  const view = {
    id: q.id, author: userView(s, q.author), title: q.title, body: q.body, tags: q.tags, beginner: !!q.beginner,
    votes: up(q) - down(q), myVote: (s.session && q.votes[s.session]) || 0, answerCount: s.answers.filter((a) => a.questionId === q.id).length, createdAt: q.createdAt,
  };
  if (q.acceptedAnswer) view.acceptedAnswerId = q.acceptedAnswer;
  if (q.finding) view.finding = q.finding;
  return view;
}

const resourceView = (s, r) => ({ id: r.id, author: userView(s, r.author), title: r.title, url: r.url, kind: r.kind, tags: r.tags, votes: (r.baseUp || 0) + r.voters.length, votedByMe: !!s.session && r.voters.includes(s.session), createdAt: r.createdAt });
const jobView = (s, j) => ({ id: j.id, author: userView(s, j.author), role: j.role, company: j.company, location: j.location, remote: !!j.remote, level: j.level, url: j.url, postedAt: j.postedAt, expiresAt: j.expiresAt });

// ── guards and validation ─────────────────────────────────
function requireUser(s) {
  if (!s.session) fail("UNAUTHENTICATED", "Sign in to do that.");
  return s.session;
}
const ownOnly = (s, item, what) => {
  if (!item) fail("NOT_FOUND", `${what} not found.`);
  if (requireUser(s) !== item.author) fail("FORBIDDEN", `Only the author can change this ${what}.`);
};
const need = (item, what) => item || fail("NOT_FOUND", `${what} not found.`);

function cleanTags(tags, { min = 0, max = 5 } = {}) {
  const out = [...new Set((tags || []).map((t) => String(t).trim().toLowerCase().replace(/^#/, "")).filter(Boolean))];
  if (out.some((t) => !/^[a-z0-9-]{1,24}$/.test(t))) fail("INVALID", "Tags use a-z, 0-9 and '-', up to 24 characters.");
  if (out.length < min || out.length > max) fail("INVALID", min ? `Add ${min} to ${max} tags.` : `At most ${max} tags.`);
  return out;
}
const httpsUrl = (value) => {
  let u;
  try { u = new URL(value); } catch { fail("INVALID", "Enter a valid URL."); }
  if (u.protocol !== "https:") fail("INVALID", "Only https:// links are accepted.");
  return u.toString();
};
function guardSecrets(texts, acknowledged) {
  const hits = scanForSecrets(texts.filter(Boolean).join("\n"));
  if (hits.length && !acknowledged) fail("SECRET_FOUND", "Possible secret found.", { hits });
}
function cleanImages(images) {
  if ((images || []).length > MAX_IMAGES) fail("INVALID", `At most ${MAX_IMAGES} images per post.`);
  for (const ref of images || []) {
    try { checkImageRef(ref); } catch (err) { fail("INVALID_IMAGE", err.message); }
  }
  return images || [];
}
const text = (value, label, { min = 1, max }) => {
  const v = String(value ?? "").trim();
  if (v.length < min || v.length > max) fail("INVALID", `${label} must be ${min}-${max} characters.`);
  return v;
};

function notify(s, kind, to, targetId, targetType) {
  if (!to || to === s.session) return;
  s.notifications.push({ id: nextId(s, "n"), to, kind, actor: s.session, targetId, targetType, read: false, createdAt: new Date().toISOString() });
}
function notifyMentions(s, body, targetId, targetType) {
  for (const m of new Set(String(body).match(/@([a-z0-9_]{3,24})/g) || [])) {
    const u = s.users.find((x) => x.name === m.slice(1));
    if (u) notify(s, "mention", u.id, targetId, targetType);
  }
}

function page(items, cursor) {
  const start = Number(cursor) || 0;
  const slice = items.slice(start, start + PAGE);
  return { items: slice, nextCursor: start + PAGE < items.length ? String(start + PAGE) : null };
}
const matches = (q, ...fields) => !q || fields.join(" ").toLowerCase().includes(String(q).trim().toLowerCase());

// ── auth ──────────────────────────────────────────────────
const validName = (name) => /^[a-z0-9_]{3,24}$/.test(name) || fail("INVALID", "Name: 3-24 characters, a-z 0-9 and _.");

export const mockApi = {
  me: call((s) => (s.session ? userView(s, s.session) : null)),

  signIn: call(async (s, name, password) => {
    const u = s.users.find((x) => x.name === String(name).trim().toLowerCase());
    if (!u || (await hash(String(password), u.salt)) !== u.hash) fail("BAD_CREDENTIALS", "Wrong name or password.");
    s.session = u.id;
    return userView(s, u.id);
  }),

  signUp: call(async (s, name, password) => {
    const n = String(name).trim().toLowerCase();
    validName(n);
    if (String(password).length < 8) fail("INVALID", "Password: at least 8 characters.");
    if (s.users.some((x) => x.name === n)) fail("TAKEN", "That name is taken.");
    const salt = newSalt();
    const colors = ["#4f8cff", "#8b5cf6", "#22c55e", "#f59e0b", "#ec4899", "#14b8a6"];
    const u = { id: nextId(s, "u"), name: n, avatarColor: colors[s.users.length % colors.length], joinedAt: new Date().toISOString(), salt, hash: await hash(String(password), salt) };
    s.users.push(u);
    s.session = u.id;
    return userView(s, u.id);
  }),

  signOut: call((s) => { s.session = null; return { ok: true }; }),

  // ── posts ───────────────────────────────────────────────
  listPosts: call((s, { sort = "latest", tag, type, q, cursor } = {}) => {
    let list = s.posts.filter((p) => (!tag || (p.tags || []).includes(tag)) && (!type || p.type === type) && matches(q, p.title, p.body, (p.tags || []).join(" ")));
    if (sort === "top") {
      const week = Date.now() - 7 * 86400e3;
      list = list.filter((p) => Date.parse(p.createdAt) >= week).sort((a, b) => likeCount(b) - likeCount(a) || b.createdAt.localeCompare(a.createdAt));
    } else list = [...list].sort((a, b) => b.createdAt.localeCompare(a.createdAt));
    const out = page(list, cursor);
    return { ...out, items: out.items.map((p) => postView(s, p)) };
  }),

  getPost: call((s, id) => postView(s, need(s.posts.find((p) => p.id === id), "Post"))),

  createPost: call((s, input) => {
    const uid = requireUser(s);
    const type = input.type;
    if (type === "repost") fail("INVALID", "Use sharePost to repost.");
    const post = { id: nextId(s, "p"), author: uid, type, tags: cleanTags(input.tags), likes: [], baseLikes: 0, images: [], createdAt: new Date().toISOString() };
    applyPostFields(post, input);
    s.posts.push(post);
    notifyMentions(s, post.body, post.id, "post");
    return postView(s, post);
  }),

  updatePost: call((s, id, input) => {
    const post = s.posts.find((p) => p.id === id);
    ownOnly(s, post, "post");
    const draft = { ...post }; // edit a copy, so a rejected edit leaves the post untouched
    applyPostFields(draft, { ...input, type: post.type });
    if (input.tags) draft.tags = cleanTags(input.tags);
    draft.editedAt = new Date().toISOString();
    Object.assign(post, draft);
    return postView(s, post);
  }),

  deletePost: call((s, id) => {
    const post = s.posts.find((p) => p.id === id);
    ownOnly(s, post, "post");
    s.posts = s.posts.filter((p) => p.id !== id);
    s.comments = s.comments.filter((c) => c.postId !== id);
    return { ok: true };
  }),

  toggleLike: call((s, id) => {
    const uid = requireUser(s);
    const post = need(s.posts.find((p) => p.id === id), "Post");
    const liked = !post.likes.includes(uid);
    post.likes = liked ? [...post.likes, uid] : post.likes.filter((x) => x !== uid);
    if (liked) notify(s, "like", post.author, post.id, "post");
    return { liked, likeCount: likeCount(post) };
  }),

  sharePost: call((s, id, comment = "") => {
    const uid = requireUser(s);
    let original = need(s.posts.find((p) => p.id === id), "Post");
    if (original.type === "repost") original = need(s.posts.find((p) => p.id === original.repostOf), "Post");
    guardSecrets([comment]);
    const post = { id: nextId(s, "p"), author: uid, type: "repost", repostOf: original.id, body: text(comment || " ", "Comment", { min: 0, max: 2000 }), tags: [...(original.tags || [])].slice(0, 5), likes: [], baseLikes: 0, images: [], createdAt: new Date().toISOString() };
    s.posts.push(post);
    notify(s, "comment", original.author, original.id, "post");
    return postView(s, post);
  }),

  // ── comments ────────────────────────────────────────────
  listComments: call((s, postId) =>
    s.comments.filter((c) => c.postId === postId).sort((a, b) => a.createdAt.localeCompare(b.createdAt))
      .map((c) => ({ id: c.id, postId: c.postId, ...(c.parentId ? { parentId: c.parentId } : {}), author: userView(s, c.author), body: c.body, createdAt: c.createdAt }))),

  addComment: call((s, postId, body, parentId) => {
    const uid = requireUser(s);
    const post = need(s.posts.find((p) => p.id === postId), "Post");
    const clean = text(body, "Comment", { max: 2000 });
    guardSecrets([clean]);
    let parent = null;
    if (parentId) {
      parent = need(s.comments.find((c) => c.id === parentId && c.postId === postId), "Comment");
      if (parent.parentId) parent = s.comments.find((c) => c.id === parent.parentId) || parent; // one reply level
    }
    const comment = { id: nextId(s, "c"), postId, author: uid, body: clean, createdAt: new Date().toISOString(), ...(parent ? { parentId: parent.id } : {}) };
    s.comments.push(comment);
    notify(s, "comment", post.author, postId, "post");
    notifyMentions(s, clean, postId, "post");
    return { id: comment.id, postId, ...(comment.parentId ? { parentId: comment.parentId } : {}), author: userView(s, uid), body: clean, createdAt: comment.createdAt };
  }),

  deleteComment: call((s, id) => {
    const comment = s.comments.find((c) => c.id === id);
    ownOnly(s, comment, "comment");
    s.comments = s.comments.filter((c) => c.id !== id && c.parentId !== id);
    return { ok: true };
  }),

  // ── questions ───────────────────────────────────────────
  listQuestions: call((s, { tab = "newest", tag, q, cursor } = {}) => {
    let list = s.questions.filter((x) => (!tag || x.tags.includes(tag)) && matches(q, x.title, x.body, x.tags.join(" ")));
    if (tab === "unanswered") list = list.filter((x) => !s.answers.some((a) => a.questionId === x.id));
    if (tab === "top") list = [...list].sort((a, b) => up(b) - down(b) - (up(a) - down(a)) || b.createdAt.localeCompare(a.createdAt));
    else list = [...list].sort((a, b) => b.createdAt.localeCompare(a.createdAt));
    const out = page(list, cursor);
    return { ...out, items: out.items.map((x) => questionView(s, x)) };
  }),

  getQuestion: call((s, id) => {
    const q = need(s.questions.find((x) => x.id === id), "Question");
    const answers = s.answers.filter((a) => a.questionId === id).map((a) => answerView(s, a))
      .sort((a, b) => Number(b.accepted) - Number(a.accepted) || b.votes - a.votes || a.createdAt.localeCompare(b.createdAt));
    return { ...questionView(s, q), answers };
  }),

  askQuestion: call((s, input) => {
    const uid = requireUser(s);
    const title = text(input.title, "Title", { min: 15, max: 150 });
    const body = text(input.body, "Question", { min: 10, max: 10000 });
    const tags = cleanTags(input.tags, { min: 1, max: 5 });
    guardSecrets([title, body, input.finding?.summary], input.acknowledgedSecrets);
    const q = { id: nextId(s, "q"), author: uid, title, body, tags, beginner: !!input.beginner, votes: {}, baseUp: 0, baseDown: 0, acceptedAnswer: null, createdAt: new Date().toISOString(), ...(input.finding ? { finding: input.finding } : {}) };
    s.questions.push(q);
    notifyMentions(s, body, q.id, "question");
    return questionView(s, q);
  }),

  similarQuestions: call((s, title) => {
    const stop = new Set(["the", "a", "an", "is", "to", "do", "does", "how", "what", "why", "in", "of", "and", "for", "my", "i", "on", "with", "can", "it"]);
    const words = (t) => new Set(String(t).toLowerCase().match(/[a-z0-9]+/g)?.filter((w) => !stop.has(w) && w.length > 1) || []);
    const mine = words(title);
    if (!mine.size) return [];
    return s.questions
      .map((q) => { const theirs = words(q.title); const shared = [...mine].filter((w) => theirs.has(w)).length; return { q, score: shared / (mine.size + theirs.size - shared) }; })
      .filter((x) => x.score >= 0.2).sort((a, b) => b.score - a.score).slice(0, 5)
      .map(({ q }) => ({ id: q.id, title: q.title, answerCount: s.answers.filter((a) => a.questionId === q.id).length, votes: up(q) - down(q) }));
  }),

  voteQuestion: call((s, id, value) => castVote(s, need(s.questions.find((q) => q.id === id), "Question"), value)),

  // ── answers ─────────────────────────────────────────────
  addAnswer: call((s, questionId, body, opts = {}) => {
    const uid = requireUser(s);
    const q = need(s.questions.find((x) => x.id === questionId), "Question");
    const clean = text(body, "Answer", { min: 10, max: 10000 });
    guardSecrets([clean], opts.acknowledgedSecrets);
    const a = { id: nextId(s, "a"), questionId, author: uid, body: clean, votes: {}, baseUp: 0, baseDown: 0, createdAt: new Date().toISOString() };
    s.answers.push(a);
    notify(s, "answer", q.author, q.id, "question");
    notifyMentions(s, clean, q.id, "question");
    return answerView(s, a);
  }),

  voteAnswer: call((s, id, value) => castVote(s, need(s.answers.find((a) => a.id === id), "Answer"), value)),

  acceptAnswer: call((s, questionId, answerId) => {
    const q = need(s.questions.find((x) => x.id === questionId), "Question");
    ownOnly(s, q, "question");
    const a = need(s.answers.find((x) => x.id === answerId && x.questionId === questionId), "Answer");
    q.acceptedAnswer = a.id;
    notify(s, "accepted", a.author, q.id, "question");
    return questionView(s, q);
  }),

  // ── resources ───────────────────────────────────────────
  listResources: call((s, { kind, tag, q } = {}) =>
    s.resources.filter((r) => (!kind || r.kind === kind) && (!tag || r.tags.includes(tag)) && matches(q, r.title, r.tags.join(" ")))
      .map((r) => resourceView(s, r)).sort((a, b) => b.votes - a.votes || b.createdAt.localeCompare(a.createdAt))),

  addResource: call((s, input) => {
    const uid = requireUser(s);
    const kind = RESOURCE_KINDS.includes(input.kind) ? input.kind : fail("INVALID", "Pick a kind.");
    const r = { id: nextId(s, "r"), author: uid, title: text(input.title, "Title", { min: 3, max: 150 }), url: httpsUrl(input.url), kind, tags: cleanTags(input.tags), baseUp: 0, voters: [], createdAt: new Date().toISOString() };
    s.resources.push(r);
    return resourceView(s, r);
  }),

  voteResource: call((s, id) => {
    const uid = requireUser(s);
    const r = need(s.resources.find((x) => x.id === id), "Resource");
    if (r.author === uid) fail("FORBIDDEN", "You cannot vote for your own resource.");
    r.voters = r.voters.includes(uid) ? r.voters.filter((x) => x !== uid) : [...r.voters, uid];
    return { votes: (r.baseUp || 0) + r.voters.length, votedByMe: r.voters.includes(uid) };
  }),

  // ── jobs ────────────────────────────────────────────────
  listJobs: call((s, { level, remote, q } = {}) =>
    s.jobs.filter((j) => Date.parse(j.expiresAt) > Date.now() && (!level || j.level === level) && (remote === undefined || remote === null || remote === "" || !!j.remote === (remote === true || remote === "true")) && matches(q, j.role, j.company, j.location))
      .sort((a, b) => b.postedAt.localeCompare(a.postedAt)).map((j) => jobView(s, j))),

  addJob: call((s, input) => {
    const uid = requireUser(s);
    if (!JOB_LEVELS.includes(input.level)) fail("INVALID", "Pick a level.");
    const days = [7, 14, 30].includes(Number(input.expiryDays)) ? Number(input.expiryDays) : fail("INVALID", "Expiry: 7, 14 or 30 days.");
    const now = Date.now();
    const j = { id: nextId(s, "j"), author: uid, role: text(input.role, "Role", { min: 3, max: 100 }), company: text(input.company, "Company", { min: 2, max: 100 }), location: text(input.location, "Location", { min: 2, max: 100 }), remote: !!input.remote, level: input.level, url: httpsUrl(input.url), postedAt: new Date(now).toISOString(), expiresAt: new Date(now + days * 86400e3).toISOString() };
    s.jobs.push(j);
    return jobView(s, j);
  }),

  // ── profile, notifications, moderation ──────────────────
  getProfile: call((s, name) => {
    const u = need(s.users.find((x) => x.name === String(name).toLowerCase()), "User");
    const posts = s.posts.filter((p) => p.author === u.id).sort((a, b) => b.createdAt.localeCompare(a.createdAt)).map((p) => postView(s, p));
    const questions = s.questions.filter((q) => q.author === u.id).sort((a, b) => b.createdAt.localeCompare(a.createdAt)).map((q) => questionView(s, q));
    const answers = s.answers.filter((a) => a.author === u.id).sort((a, b) => b.createdAt.localeCompare(a.createdAt)).map((a) => ({ ...answerView(s, a), questionTitle: s.questions.find((q) => q.id === a.questionId)?.title || "" }));
    return { user: userView(s, u.id), stats: { posts: posts.length, questions: questions.length, answers: answers.length, acceptedAnswers: answers.filter((a) => a.accepted).length }, posts, questions, answers };
  }),

  listNotifications: call((s) => {
    if (!s.session) return [];
    return s.notifications.filter((n) => n.to === s.session).sort((a, b) => b.createdAt.localeCompare(a.createdAt))
      .map((n) => ({ id: n.id, kind: n.kind, actor: userView(s, n.actor), targetId: n.targetId, targetType: n.targetType, read: n.read, createdAt: n.createdAt }));
  }),

  markRead: call((s, ids) => {
    const set = new Set(ids);
    for (const n of s.notifications) if (n.to === s.session && set.has(n.id)) n.read = true;
    return { unread: s.notifications.filter((n) => n.to === s.session && !n.read).length };
  }),

  report: call((s, kind, id, reason) => {
    const uid = requireUser(s);
    if (!REPORT_REASONS.includes(reason)) fail("INVALID", "Pick a reason.");
    need(findTarget(s, kind, id), "Item");
    if (!s.reports.some((r) => r.by === uid && r.kind === kind && r.targetId === id && r.status === "open")) s.reports.push({ id: nextId(s, "rp"), by: uid, kind, targetId: id, reason, status: "open", createdAt: new Date().toISOString() });
    return { ok: true };
  }),

  // moderators only: open reports, one entry per reported item
  listReports: call((s) => {
    requireModerator(s);
    const groups = new Map();
    for (const r of s.reports.filter((x) => x.status === "open")) {
      const key = `${r.kind}:${r.targetId}`;
      const g = groups.get(key) || { id: r.id, kind: r.kind, targetId: r.targetId, reasons: [], reporters: [], count: 0, createdAt: r.createdAt };
      g.count += 1;
      if (!g.reasons.includes(r.reason)) g.reasons.push(r.reason);
      g.reporters.push(userView(s, r.by).name);
      if (r.createdAt > g.createdAt) g.createdAt = r.createdAt;
      groups.set(key, g);
    }
    return [...groups.values()].sort((a, b) => b.count - a.count || b.createdAt.localeCompare(a.createdAt))
      .map((g) => ({ ...g, target: targetView(s, g.kind, g.targetId) }));
  }),

  // moderators only: action "dismiss" keeps the item, "remove" deletes it; every open report on it is closed
  resolveReport: call((s, reportId, action) => {
    requireModerator(s);
    if (!["dismiss", "remove"].includes(action)) fail("INVALID", "Action: dismiss or remove.");
    const report = need(s.reports.find((r) => r.id === reportId), "Report");
    if (action === "remove") removeTarget(s, report.kind, report.targetId);
    for (const r of s.reports) {
      if (r.kind === report.kind && r.targetId === report.targetId && r.status === "open") {
        r.status = action === "remove" ? "removed" : "dismissed";
        r.resolvedBy = s.session;
      }
    }
    return { ok: true };
  }),

  // mock only: wipe the browser copy and start again from the seed
  resetDemoData: async () => {
    mem = null;
    booting = null;
    try { localStorage.removeItem(KEY); } catch { /* nothing to remove */ }
    await state();
    return { ok: true };
  },
};

// ── moderation helpers ────────────────────────────────────
function requireModerator(s) {
  if (!isModerator(s, requireUser(s))) fail("FORBIDDEN", "Moderators only.");
}

const REPORT_KINDS = { post: "posts", comment: "comments", question: "questions", answer: "answers", resource: "resources", job: "jobs" };
function findTarget(s, kind, id) {
  const list = s[REPORT_KINDS[kind]];
  if (!list) fail("INVALID", "Unknown item kind.");
  return list.find((x) => x.id === id) || null;
}

// what a moderator sees about a reported item; `link` says where it lives
function targetView(s, kind, id) {
  const t = findTarget(s, kind, id);
  if (!t) return { exists: false };
  const cut = (v) => { const x = String(v || "").replace(/\s+/g, " ").trim(); return x.length > 280 ? `${x.slice(0, 279)}…` : x; };
  const text = { post: [t.title, t.body, t.code?.source, t.finding?.summary], comment: [t.body], question: [t.title, t.body], answer: [t.body], resource: [t.title, t.url], job: [t.role, t.company, t.url] }[kind];
  const link = { post: `post/${id}`, comment: `post/${t.postId}`, question: `qa/${id}`, answer: `qa/${t.questionId}`, resource: "resources", job: "jobs" }[kind];
  return { exists: true, author: userView(s, t.author), excerpt: cut(text.filter(Boolean).join(" · ")), link };
}

function removeTarget(s, kind, id) {
  if (kind === "post") {
    s.posts = s.posts.filter((p) => p.id !== id);
    s.comments = s.comments.filter((c) => c.postId !== id);
  } else if (kind === "comment") s.comments = s.comments.filter((c) => c.id !== id && c.parentId !== id);
  else if (kind === "question") {
    s.questions = s.questions.filter((q) => q.id !== id);
    s.answers = s.answers.filter((a) => a.questionId !== id);
  } else if (kind === "answer") {
    s.answers = s.answers.filter((a) => a.id !== id);
    for (const q of s.questions) if (q.acceptedAnswer === id) q.acceptedAnswer = null;
  } else if (kind === "resource") s.resources = s.resources.filter((r) => r.id !== id);
  else if (kind === "job") s.jobs = s.jobs.filter((j) => j.id !== id);
}

function castVote(s, item, value) {
  const uid = requireUser(s);
  if (![1, -1, 0].includes(value)) fail("INVALID", "Vote must be +1, -1 or 0.");
  if (item.author === uid) fail("FORBIDDEN", "You cannot vote on your own post.");
  if (value === 0) delete item.votes[uid];
  else item.votes[uid] = value;
  return { votes: up(item) - down(item), myVote: value };
}

// copies the user-editable fields of a post, validating them for its type
function applyPostFields(post, input) {
  const type = post.type;
  if (!["text", "image", "article", "code", "finding", "repost"].includes(type)) fail("INVALID", "Unknown post type.");
  const maxBody = type === "article" ? 20000 : 2000;
  const body = String(input.body ?? post.body ?? "").trim();
  if (body.length > maxBody) fail("INVALID", `The text is limited to ${maxBody} characters.`);
  if (type === "text" && !body) fail("INVALID", "Write something first.");
  post.body = body;
  if (type === "article") post.title = text(input.title ?? post.title, "Title", { min: 3, max: 150 });
  if (type === "image" || type === "article") {
    post.images = cleanImages(input.images ?? post.images);
    if (type === "image" && !post.images.length) fail("INVALID", "Add at least one image.");
    if (type === "article") post.images = post.images.slice(0, 1); // one cover image
  }
  if (type === "code") {
    const code = input.code ?? post.code;
    if (!code || !CODE_LANGS.includes(code.lang) || !String(code.source || "").trim()) fail("INVALID", "Pick a language and add some code.");
    if (String(code.source).length > 10000) fail("INVALID", "Code is limited to 10000 characters.");
    post.code = { lang: code.lang, source: String(code.source) };
  }
  if (type === "finding") {
    const f = input.finding ?? post.finding;
    if (!f || !f.id || !f.category || !f.state || !f.summary) fail("INVALID", "Pick a finding to share.");
    post.finding = { id: String(f.id), scanId: f.scanId, category: String(f.category), owasp: String(f.owasp || ""), state: String(f.state), summary: text(f.summary, "Summary", { max: 300 }) };
  }
  guardSecrets([post.title, post.body, post.code?.source, post.finding?.summary], input.acknowledgedSecrets);
}
