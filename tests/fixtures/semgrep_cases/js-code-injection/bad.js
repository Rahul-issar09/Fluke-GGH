const vm = require("vm");
const app = require("express")();

app.get("/calc", (req, res) => {
  res.json({ result: eval(req.query.expr) });  // ruleid: js-code-injection
});

app.post("/rule", (req, res) => {
  const check = new Function("x", req.body.rule);  // ruleid: js-code-injection
  res.json({ ok: check(1) });
});

app.post("/sandbox", (req, res) => {
  res.json(vm.runInNewContext(req.body.code, {}));  // ruleid: js-code-injection
});
