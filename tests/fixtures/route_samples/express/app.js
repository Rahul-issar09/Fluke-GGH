const express = require('express');
const ordersRouter = require('./routes/orders');
const db = require('./db');

const app = express();
app.use(express.json());
app.use('/api/orders', ordersRouter);

function health(req, res) {
  res.json({ ok: true });
}

app.get('/health', health);

app.post('/login', async (req, res) => {
  const user = await db.findUser(req.body.username);
  res.json({ ok: Boolean(user) });
});

app.listen(3000);
