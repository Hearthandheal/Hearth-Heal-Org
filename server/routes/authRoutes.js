import express from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import User from "../models/User.js";

const router = express.Router();

// Register
router.post("/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;
    
    // Check if user exists
    const existing = await User.findOne({ email });
    if (existing) {
      return res.status(400).json({ error: "User already exists" });
    }

    const hashed = await bcrypt.hash(password, 10);
    const user = await User.create({ name, email, password: hashed });

    res.json({ message: "User created", userId: user._id });
  } catch (err) {
    console.error("Register error:", err.message);
    res.status(500).json({ error: err.message });
  }
});

// One-time admin seed (remove after use)
router.get("/seed-admin", async (req, res) => {
  try {
    const adminEmail = "admin@hearthheal.com";
    const existing = await User.findOne({ email: adminEmail });
    if (existing) {
      return res.json({ message: "Admin already exists", email: adminEmail });
    }
    
    const hashed = await bcrypt.hash("Admin123!", 10);
    const admin = await User.create({
      name: "Admin",
      email: adminEmail,
      password: hashed,
      isAdmin: true,
    });
    
    res.json({ 
      message: "Admin created successfully!", 
      email: adminEmail,
      password: "Admin123!"
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Login
router.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ error: "User not found" });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ error: "Wrong password" });

    const token = jwt.sign(
      { id: user._id, isAdmin: user.isAdmin },
      process.env.JWT_SECRET
    );

    res.json({ token });
  } catch (err) {
    console.error("Login error:", err.message);
    res.status(500).json({ error: err.message });
  }
});

export default router;
