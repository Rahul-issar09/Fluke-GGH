const fs = require("fs");
const path = require("path");
const app = require("express")();

app.get("/download", (req, res) => {
  res.sendFile(path.join(__dirname, "files", path.basename(req.query.name)));
});

app.get("/readme", (req, res) => {
  res.send(fs.readFileSync(path.join(__dirname, "README.md"), "utf8"));
});
