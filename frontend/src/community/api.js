// The only door to Community data. Components import from here and never touch localStorage or fetch.
// With no configuration it talks to the in-browser mock (mockApi.js); with VITE_COMMUNITY_API set it calls a
// real server at that base URL, using the routes written above each function. Shapes are in types.js.

import { createHttpApi } from "./httpApi.js";
import { mockApi } from "./mockApi.js";

const BASE = import.meta.env.VITE_COMMUNITY_API;
const impl = BASE ? createHttpApi(BASE) : mockApi;

export const isMock = !BASE;
export { ApiError } from "./errors.js";
export { scanForSecrets } from "./guard.js"; // pure; the real backend repeats it server-side

// mock only: forget the browser copy and start again from the seed data
export const resetDemoData = async () => {
  if (!isMock) throw new Error("Reset applies to the demo data only.");
  return mockApi.resetDemoData();
};

// ── auth ──
// GET  /community/me                 -> User | null
export const me = () => impl.me();
// POST /community/auth/signin        { name, password } -> User
export const signIn = (name, password) => impl.signIn(name, password);
// POST /community/auth/signup        { name, password } -> User
export const signUp = (name, password) => impl.signUp(name, password);
// POST /community/auth/signout
export const signOut = () => impl.signOut();

// ── posts ──
// GET    /community/posts?sort=&tag=&type=&q=&cursor=   -> { items: Post[], nextCursor }
export const listPosts = (params) => impl.listPosts(params);
// GET    /community/posts/:id                           -> Post
export const getPost = (id) => impl.getPost(id);
// POST   /community/posts                               { type, title?, body, images[], code?, finding?, tags[], acknowledgedSecrets? } -> Post
export const createPost = (input) => impl.createPost(input);
// PATCH  /community/posts/:id                           owner only -> Post
export const updatePost = (id, input) => impl.updatePost(id, input);
// DELETE /community/posts/:id                           owner only
export const deletePost = (id) => impl.deletePost(id);
// POST   /community/posts/:id/like                      toggles -> { liked, likeCount }
export const toggleLike = (id) => impl.toggleLike(id);
// POST   /community/posts/:id/share                     { comment } -> Post (type "repost")
export const sharePost = (id, comment) => impl.sharePost(id, comment);

// ── comments ──
// GET    /community/posts/:id/comments                  -> Comment[]
export const listComments = (postId) => impl.listComments(postId);
// POST   /community/posts/:id/comments                  { body, parentId? } -> Comment
export const addComment = (postId, body, parentId) => impl.addComment(postId, body, parentId);
// DELETE /community/comments/:id                        author only
export const deleteComment = (id) => impl.deleteComment(id);

// ── questions ──
// GET    /community/questions?tab=newest|unanswered|top&tag=&q=&cursor=   -> { items: Question[], nextCursor }
export const listQuestions = (params) => impl.listQuestions(params);
// GET    /community/questions/:id                       -> Question with answers[]
export const getQuestion = (id) => impl.getQuestion(id);
// POST   /community/questions                           { title, body, tags[], beginner, finding?, acknowledgedSecrets? } -> Question
export const askQuestion = (input) => impl.askQuestion(input);
// GET    /community/questions/similar?title=            -> [{ id, title, answerCount, votes }] (up to 5)
export const similarQuestions = (title) => impl.similarQuestions(title);
// POST   /community/questions/:id/vote                  { value: 1|-1|0 } -> { votes, myVote }   (not on your own question)
export const voteQuestion = (id, value) => impl.voteQuestion(id, value);

// ── answers ──
// POST   /community/questions/:id/answers               { body, acknowledgedSecrets? } -> Answer
export const addAnswer = (questionId, body, opts) => impl.addAnswer(questionId, body, opts);
// POST   /community/answers/:id/vote                    { value: 1|-1|0 } -> { votes, myVote }   (not on your own answer)
export const voteAnswer = (id, value) => impl.voteAnswer(id, value);
// POST   /community/questions/:id/accept                { answerId } asker only -> Question
export const acceptAnswer = (questionId, answerId) => impl.acceptAnswer(questionId, answerId);

// ── resources ──
// GET    /community/resources?kind=&tag=&q=             -> Resource[]
export const listResources = (params) => impl.listResources(params);
// POST   /community/resources                           { title, url (https), kind, tags[] } -> Resource
export const addResource = (input) => impl.addResource(input);
// POST   /community/resources/:id/vote                  toggles -> { votes, votedByMe }
export const voteResource = (id) => impl.voteResource(id);

// ── jobs ──
// GET    /community/jobs?level=&remote=&q=              -> Job[] (expired ones are not listed)
export const listJobs = (params) => impl.listJobs(params);
// POST   /community/jobs                                { role, company, location, remote, level, url (https), expiryDays: 7|14|30 } -> Job
export const addJob = (input) => impl.addJob(input);

// ── profile ──
// GET    /community/users/:name                         -> { user, stats, posts, questions, answers }
export const getProfile = (name) => impl.getProfile(name);

// ── notifications ──
// GET    /community/notifications                       -> Notification[]
export const listNotifications = () => impl.listNotifications();
// POST   /community/notifications/read                  { ids[] } -> { unread }
export const markRead = (ids) => impl.markRead(ids);

// ── moderation ──
// POST   /community/reports                             { kind, id, reason } -> { ok }
export const report = (kind, id, reason) => impl.report(kind, id, reason);
// GET    /community/reports                             moderators only -> ReportGroup[]
export const listReports = () => impl.listReports();
// POST   /community/reports/:id/resolve                 { action: "dismiss"|"remove" } moderators only -> { ok }
export const resolveReport = (id, action) => impl.resolveReport(id, action);
