const axios = require("axios");
const http = require("http");
const app = require("express")();

app.get("/preview", async (req, res) => {
  const page = await axios.get(req.query.url);  // ruleid: js-ssrf
  res.send(page.data);
});

app.post("/webhook-test", async (req, res) => {
  const r = await fetch(req.body.callback, { method: "POST" });  // ruleid: js-ssrf
  res.sendStatus(r.status);
});

app.get("/image", (req, res) => {
  http.get(req.query.src, (up) => up.pipe(res));  // ruleid: js-ssrf
});
