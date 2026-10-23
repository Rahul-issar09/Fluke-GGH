const axios = require("axios");
const app = require("express")();
const ALLOWED = { docs: "https://docs.example.com/index.json" };

app.get("/preview", async (req, res) => {
  const page = await axios.get(ALLOWED[req.query.name] ? "https://docs.example.com/index.json" : "https://example.com");
  res.send(page.data);
});

app.get("/status", async (req, res) => {
  const r = await fetch("https://status.example.com/api", { headers: { "x-id": req.query.id } });
  res.sendStatus(r.status);
});
