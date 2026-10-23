// INTENTIONALLY VULNERABLE demo frontend (test fixture for AEGIS; never deploy).
// It calls the demo API on the same origin so the deliberately planted weaknesses
// (IDOR on /api/accounts/{id}, SQL injection on /api/users/search, SSRF on /api/fetch)
// can be exercised from a browser. All requests are same-origin and cookie-based.
"use strict";

const api = {
  base: location.pathname.replace(/\/ui\/?.*$/, ""),
  async login(username, password) {
    const r = await fetch(this.base + "/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    });
    if (!r.ok) throw new Error("login failed (" + r.status + ")");
    return r.json();
  },
  async accounts() {
    return (await fetch(this.base + "/api/accounts")).json();
  },
  async account(id) {
    return (await fetch(this.base + "/api/accounts/" + encodeURIComponent(id))).json();
  },
  async searchUsers(name) {
    return (await fetch(this.base + "/api/users/search?name=" + encodeURIComponent(name))).json();
  },
  async preview(url) {
    return (await fetch(this.base + "/api/fetch?url=" + encodeURIComponent(url))).json();
  },
};

const $ = (id) => document.getElementById(id);
const show = (el, data) => { el.textContent = typeof data === "string" ? data : JSON.stringify(data, null, 2); };

$("login-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const msg = $("login-msg");
  try {
    await api.login($("username").value, $("password").value);
    msg.textContent = "Signed in.";
    msg.className = "msg ok";
    $("who").textContent = "signed in as " + $("username").value;
    $("app-card").hidden = false;
    loadAccounts();
  } catch (err) {
    msg.textContent = String(err.message || err);
    msg.className = "msg bad";
  }
});

async function loadAccounts() {
  const body = $("accounts").querySelector("tbody");
  body.textContent = "";
  try {
    const rows = await api.accounts();
    for (const a of rows) {
      const tr = document.createElement("tr");
      for (const key of ["id", "owner", "account_number", "balance"]) {
        const td = document.createElement("td");
        td.textContent = a[key];
        tr.appendChild(td);
      }
      body.appendChild(tr);
    }
  } catch (err) {
    show($("lookup-out"), String(err));
  }
}

$("load-accounts").addEventListener("click", loadAccounts);
$("lookup-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  show($("lookup-out"), await api.account($("account-id").value));
});
$("search-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  show($("search-out"), await api.searchUsers($("search-name").value));
});
$("fetch-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  show($("fetch-out"), await api.preview($("fetch-url").value));
});
