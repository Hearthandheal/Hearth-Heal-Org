import express from "express";
import Order from "../models/Order.js";

const router = express.Router();

// Get all orders
router.get("/", async (req, res) => {
  try {
    const orders = await Order.find().sort({ createdAt: -1 });
    res.json(orders);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get single order
router.get("/:id", async (req, res) => {
  try {
    const order = await Order.findById(req.params.id);
    if (!order) return res.status(404).json({ error: "Order not found" });
    res.json(order);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Create order
router.post("/", async (req, res) => {
  try {
    const { products, amount, phone, name, address } = req.body;

    // Validation
    if (!products || !Array.isArray(products) || products.length === 0) {
      return res.status(400).json({ error: "Products are required" });
    }
    if (!amount || typeof amount !== 'number') {
      return res.status(400).json({ error: "Valid amount is required" });
    }
    if (!phone) {
      return res.status(400).json({ error: "Phone number is required" });
    }

    const order = await Order.create({
      products,
      amount,
      phone,
      name,
      address,
      status: "pending",
    });

    res.status(201).json(order);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Update order status
router.put("/:id", async (req, res) => {
  try {
    const order = await Order.findByIdAndUpdate(req.params.id, req.body, { new: true });
    if (!order) return res.status(404).json({ error: "Order not found" });
    res.json(order);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Delete order
router.delete("/:id", async (req, res) => {
  try {
    const order = await Order.findByIdAndDelete(req.params.id);
    if (!order) return res.status(404).json({ error: "Order not found" });
    res.json({ message: "Order deleted" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

export default router;
