const fs = require("fs");
const path = require("path");
const app = require("express")();

app.get("/download", (req, res) => {
  res.sendFile(path.join(__dirname, "files", req.query.name));  // ruleid: js-path-traversal
});

app.get("/logs/:file", (req, res) => {
  res.send(fs.readFileSync("/var/log/app/" + req.params.file, "utf8"));  // ruleid: js-path-traversal
});

app.get("/export", (req, res) => {
  fs.createReadStream(req.query.path).pipe(res);  // ruleid: js-path-traversal
});
