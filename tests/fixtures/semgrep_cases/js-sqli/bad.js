const express = require("express");
const db = require("./db");
const router = express.Router();

router.get("/users", async (req, res) => {
  const rows = await db.query("SELECT * FROM users WHERE name = '" + req.query.name + "'");  // ruleid: js-sqli
  res.json(rows);
});

router.get("/orders/:id", async (req, res) => {
  const sql = `SELECT * FROM orders WHERE id = ${req.params.id}`;
  res.json(await pool.query(sql));  // ruleid: js-sqli
});

router.post("/search", (req, res) => {
  const { term } = req.body;
  connection.execute("SELECT * FROM items WHERE title LIKE '%" + term + "%'", (err, rows) => res.json(rows));  // ruleid: js-sqli
});

module.exports = router;
