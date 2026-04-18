import express from "express";
import Order from "../models/Order.js";

const router = express.Router();

// Get all orders
router.get("/", async (req, res) => {
  const orders = await Order.find().sort({ createdAt: -1 });
  res.json(orders);
});

// Get single order
router.get("/:id", async (req, res) => {
  const order = await Order.findById(req.params.id);
  if (!order) return res.status(404).json({ error: "Order not found" });
  res.json(order);
});

// Create order
router.post("/", async (req, res) => {
  const order = new Order(req.body);
  await order.save();
  res.status(201).json(order);
});

// Update order status
router.put("/:id", async (req, res) => {
  const order = await Order.findByIdAndUpdate(req.params.id, req.body, { new: true });
  res.json(order);
});

// Delete order
router.delete("/:id", async (req, res) => {
  await Order.findByIdAndDelete(req.params.id);
  res.json({ message: "Order deleted" });
});

export default router;
