const express = require("express");
const router = express.Router();

router.get("/users", async (req, res) => {
  res.json(await db.query("SELECT * FROM users WHERE name = $1", [req.query.name]));
});

router.get("/orders/:id", async (req, res) => {
  res.json(await pool.query("SELECT * FROM orders WHERE id = ?", [Number(req.params.id)]));
});

router.get("/count", async (req, res) => {
  res.json(await db.query("SELECT COUNT(*) FROM users"));
});

module.exports = router;
