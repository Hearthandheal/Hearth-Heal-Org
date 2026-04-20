import mongoose from "mongoose";
import bcrypt from "bcryptjs";
import User from "./models/User.js";
import dotenv from "dotenv";

dotenv.config();

const seedAdmin = async () => {
  try {
    await mongoose.connect(process.env.MONGO_URI);
    console.log("Connected to MongoDB");

    const adminEmail = "admin@hearthheal.com";
    const adminPassword = "Admin123!";

    // Check if admin exists
    const existing = await User.findOne({ email: adminEmail });
    if (existing) {
      console.log("Admin user already exists:", adminEmail);
      process.exit(0);
    }

    // Create admin
    const hashed = await bcrypt.hash(adminPassword, 10);
    const admin = await User.create({
      name: "Admin",
      email: adminEmail,
      password: hashed,
      isAdmin: true,
    });

    console.log("Admin created successfully!");
    console.log("Email:", adminEmail);
    console.log("Password:", adminPassword);
    console.log("isAdmin:", admin.isAdmin);
    
    process.exit(0);
  } catch (err) {
    console.error("Error:", err.message);
    process.exit(1);
  }
};

seedAdmin();
