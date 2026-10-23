const { execFile, spawn } = require("child_process");
const app = require("express")();

app.get("/ping", (req, res) => {
  execFile("ping", ["-c", "1", req.query.host], (err, out) => res.send(out));
});

app.get("/grep", (req, res) => {
  spawn("grep", [req.query.pattern, "log.txt"]);
  res.sendStatus(202);
});

app.get("/uptime", (req, res) => {
  require("child_process").exec("uptime", (err, out) => res.send(out));
});
