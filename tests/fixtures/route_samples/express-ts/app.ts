import express, { Request, Response } from 'express';
import ordersRouter from './routes/orders';
import { db } from './db';

const app = express();
app.use(express.json());
app.use('/api/orders', ordersRouter);

function health(req: Request, res: Response): void {
  res.json({ ok: true });
}

app.get('/health', health);

app.post('/login', async (req: Request, res: Response) => {
  const user = await db.findUser(req.body.username as string);
  res.json({ ok: Boolean(user) });
});

export default app;
