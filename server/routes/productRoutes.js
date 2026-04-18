import express from "express";
import Product from "../models/Product.js";
import { verifyAdmin } from "../middleware/authMiddleware.js";

const router = express.Router();

// Get all products (public)
router.get("/", async (req, res) => {
  const products = await Product.find();
  res.json(products);
});

// Get single product (public)
router.get("/:id", async (req, res) => {
  const product = await Product.findById(req.params.id);
  if (!product) return res.status(404).json({ error: "Product not found" });
  res.json(product);
});

// Add product (admin only)
router.post("/", verifyAdmin, async (req, res) => {
  const product = new Product(req.body);
  await product.save();
  res.status(201).json(product);
});

// Update product (admin only)
router.put("/:id", verifyAdmin, async (req, res) => {
  const product = await Product.findByIdAndUpdate(req.params.id, req.body, { new: true });
  res.json(product);
});

// Delete product (admin only)
router.delete("/:id", verifyAdmin, async (req, res) => {
  await Product.findByIdAndDelete(req.params.id);
  res.json({ message: "Product deleted" });
});

export default router;
