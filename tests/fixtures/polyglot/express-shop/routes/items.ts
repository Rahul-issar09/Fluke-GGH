import { Router, Request, Response } from 'express';
import { pool } from '../db';

const router = Router();

router.get('/:id', async (req: Request, res: Response) => {
  const result = await pool.query(`SELECT * FROM items WHERE id = ${req.params.id}`);
  res.json(result.rows);
});

export default router;
