// A small Express shop with planted weaknesses (test fixture, never deploy).
const express = require('express');
const { exec } = require('child_process');
const itemsRouter = require('./routes/items');
const db = require('./db');

const app = express();
app.use('/api/items', itemsRouter);

app.get('/api/users', async (req, res) => {
  res.json(await db.query("SELECT * FROM users WHERE name = '" + req.query.name + "'"));
});

app.get('/api/ping', (req, res) => {
  exec('ping -c 1 ' + req.query.host, (err, out) => res.send(out));
});

app.listen(3000);
