import mongoose from "mongoose";

const orderSchema = new mongoose.Schema({
  customerName: String,
  customerPhone: String,
  items: [{
    productId: mongoose.Schema.Types.ObjectId,
    name: String,
    price: Number,
    quantity: Number,
  }],
  totalAmount: Number,
  paymentStatus: { type: String, default: "pending" },
  mpesaReceipt: String,
  createdAt: { type: Date, default: Date.now },
});

export default mongoose.model("Order", orderSchema);
