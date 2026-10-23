const express = require('express');
const db = require('../db');

const router = express.Router();

const requireLogin = (req, res, next) => next();

const getOrder = async (req, res) => {
  const order = await db.orders.findById(req.params.id); // no owner check
  res.json(order);
};

router.get('/:id', requireLogin, getOrder);

router
  .route('/:id/items')
  .get(async function listItems(req, res) {
    res.json(await db.items.forOrder(req.params.id));
  })
  .post(async (req, res) => {
    res.status(201).end();
  });

module.exports = router;
