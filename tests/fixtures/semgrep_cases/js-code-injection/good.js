const app = require("express")();

app.get("/calc", (req, res) => {
  const a = Number(req.query.a), b = Number(req.query.b);
  res.json({ result: a + b });
});

app.get("/config", (req, res) => {
  res.json(JSON.parse(req.query.json));
});

app.get("/later", (req, res) => {
  setTimeout(() => res.json({ done: req.query.id }), 10);
});
