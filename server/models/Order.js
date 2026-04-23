import mongoose from "mongoose";

const orderSchema = new mongoose.Schema({
  products: Array,
  amount: Number,
  phone: String,
  name: String,
  email: String,
  city: String,
  address: String,
  status: { type: String, default: "pending", enum: ["pending", "paid", "failed", "cancelled"] },
  mpesaReceipt: String,
  checkoutRequestID: String,
  transactionDate: Date,
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
});

orderSchema.pre('save', function(next) {
  this.updatedAt = new Date();
  next();
});

export default mongoose.model("Order", orderSchema);
