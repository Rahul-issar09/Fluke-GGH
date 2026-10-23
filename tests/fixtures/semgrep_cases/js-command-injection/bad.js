const { exec, spawn } = require("child_process");
const child_process = require("child_process");
const app = require("express")();

app.get("/ping", (req, res) => {
  exec("ping -c 1 " + req.query.host, (err, out) => res.send(out));  // ruleid: js-command-injection
});

app.post("/convert", (req, res) => {
  const file = req.body.file;
  child_process.execSync(`convert ${file} out.png`);  // ruleid: js-command-injection
  res.sendStatus(204);
});

app.get("/grep", (req, res) => {
  spawn(req.query.cmd, [], { shell: true });  // ruleid: js-command-injection
  res.sendStatus(202);
});
