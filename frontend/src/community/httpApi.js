// The Community API over HTTP: the same functions as the mock, calling the routes listed in api.js.
// Used only when VITE_COMMUNITY_API is set (for example "https://api.example.org"). Cookies carry the session.
// The backend must answer errors as JSON { code, message, ... } with a 4xx/5xx status.

import { ApiError } from "./errors.js";

const qs = (params = {}) => {
  const s = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) if (v !== undefined && v !== null && v !== "") s.set(k, String(v));
  const out = s.toString();
  return out ? `?${out}` : "";
};

export function createHttpApi(base) {
  async function req(method, path, body) {
    let resp;
    try {
      resp = await fetch(base.replace(/\/$/, "") + path, {
        method,
        credentials: "include",
        headers: { Accept: "application/json", ...(body !== undefined ? { "Content-Type": "application/json" } : {}) },
        body: body === undefined ? undefined : JSON.stringify(body),
      });
    } catch {
      throw new ApiError("NETWORK", "Could not reach the community server.");
    }
    const data = resp.status === 204 ? null : await resp.json().catch(() => null);
    if (!resp.ok) throw new ApiError(data?.code || "ERROR", data?.message || `HTTP ${resp.status}`, data || {});
    return data;
  }
  const id = encodeURIComponent;

  return {
    me: () => req("GET", "/community/me"),
    signIn: (name, password) => req("POST", "/community/auth/signin", { name, password }),
    signUp: (name, password) => req("POST", "/community/auth/signup", { name, password }),
    signOut: () => req("POST", "/community/auth/signout"),

    listPosts: (p) => req("GET", `/community/posts${qs(p)}`),
    getPost: (i) => req("GET", `/community/posts/${id(i)}`),
    createPost: (input) => req("POST", "/community/posts", input),
    updatePost: (i, input) => req("PATCH", `/community/posts/${id(i)}`, input),
    deletePost: (i) => req("DELETE", `/community/posts/${id(i)}`),
    toggleLike: (i) => req("POST", `/community/posts/${id(i)}/like`),
    sharePost: (i, comment) => req("POST", `/community/posts/${id(i)}/share`, { comment }),

    listComments: (postId) => req("GET", `/community/posts/${id(postId)}/comments`),
    addComment: (postId, body, parentId) => req("POST", `/community/posts/${id(postId)}/comments`, { body, parentId }),
    deleteComment: (i) => req("DELETE", `/community/comments/${id(i)}`),

    listQuestions: (p) => req("GET", `/community/questions${qs(p)}`),
    getQuestion: (i) => req("GET", `/community/questions/${id(i)}`),
    askQuestion: (input) => req("POST", "/community/questions", input),
    similarQuestions: (title) => req("GET", `/community/questions/similar${qs({ title })}`),
    voteQuestion: (i, value) => req("POST", `/community/questions/${id(i)}/vote`, { value }),

    addAnswer: (qId, body, opts) => req("POST", `/community/questions/${id(qId)}/answers`, { body, ...opts }),
    voteAnswer: (i, value) => req("POST", `/community/answers/${id(i)}/vote`, { value }),
    acceptAnswer: (qId, answerId) => req("POST", `/community/questions/${id(qId)}/accept`, { answerId }),

    listResources: (p) => req("GET", `/community/resources${qs(p)}`),
    addResource: (input) => req("POST", "/community/resources", input),
    voteResource: (i) => req("POST", `/community/resources/${id(i)}/vote`),

    listJobs: (p) => req("GET", `/community/jobs${qs(p)}`),
    addJob: (input) => req("POST", "/community/jobs", input),

    getProfile: (name) => req("GET", `/community/users/${id(name)}`),

    listNotifications: () => req("GET", "/community/notifications"),
    markRead: (ids) => req("POST", "/community/notifications/read", { ids }),

    report: (kind, targetId, reason) => req("POST", "/community/reports", { kind, id: targetId, reason }),
    listReports: () => req("GET", "/community/reports"),
    resolveReport: (i, action) => req("POST", `/community/reports/${id(i)}/resolve`, { action }),
  };
}
