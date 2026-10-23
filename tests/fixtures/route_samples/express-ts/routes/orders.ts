import { Router, Request, Response, NextFunction } from 'express';
import { db } from '../db';

const router = Router();

const requireLogin = (req: Request, res: Response, next: NextFunction): void => next();

const getOrder = async (req: Request<{ id: string }>, res: Response): Promise<void> => {
  const order = await db.orders.findById(req.params.id); // no owner check
  res.json(order);
};

router.get('/:id', requireLogin, getOrder);

router
  .route('/:id/items')
  .get(async function listItems(req: Request, res: Response) {
    res.json(await db.items.forOrder(req.params.id));
  })
  .post(async (req: Request, res: Response) => {
    res.status(201).end();
  });

export default router;
