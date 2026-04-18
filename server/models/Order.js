import mongoose from "mongoose";

const orderSchema = new mongoose.Schema({
  products: Array,
  amount: Number,
  phone: String,
  status: { type: String, default: "pending" },
  mpesaReceipt: String,
  createdAt: { type: Date, default: Date.now },
});

export default mongoose.model("Order", orderSchema);
