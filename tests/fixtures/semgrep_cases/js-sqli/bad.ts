import { Router, Request, Response } from "express";
import { pool } from "./db";

const router = Router();

router.get("/accounts/:id", async (req: Request, res: Response) => {
  const result = await pool.query(`SELECT * FROM accounts WHERE id = ${req.params.id}`);  // ruleid: js-sqli
  res.json(result.rows);
});

export default router;
