import { useState, useEffect } from "react";
import axios from "axios";
import { motion } from "framer-motion";
import { useNavigate } from "react-router-dom";

// API URL - deployed backend (v2)
const API_URL = "https://hearth-heal-api.onrender.com/api";

interface CartItem {
  _id: string;
  name: string;
  price: number;
}

export default function Checkout() {
  const navigate = useNavigate();
  const [cart, setCart] = useState<CartItem[]>([]);
  const [loading, setLoading] = useState(false);
  const [status, setStatus] = useState<null | "pending" | "failed" | "success">(null);
  const [form, setForm] = useState({
    name: "",
    phone: "",
    address: "",
  });

  // 📱 Format Kenyan phone automatically
  const formatPhone = (value: string) => {
    let v = value.replace(/\D/g, "");
    if (v.startsWith("0")) v = "254" + v.slice(1);
    if (!v.startsWith("254")) v = "254" + v;
    return v.slice(0, 12);
  };

  useEffect(() => {
    const saved = localStorage.getItem('cart');
    if (saved) {
      setCart(JSON.parse(saved));
    }
  }, []);

  const total = cart.reduce((sum, item) => sum + item.price, 0);

  const handlePay = async () => {
    if (!form.phone || form.phone.length < 12) {
      return alert("Enter a valid Kenyan phone number (2547XXXXXXXX)");
    }
    if (cart.length === 0) return alert("Your cart is empty");

    setLoading(true);
    setStatus("pending");
    try {
      // Create order first
      const orderRes = await axios.post(`${API_URL}/orders`, {
        ...form,
        products: cart,
        amount: total,
      });

      // Initiate M-Pesa payment
      await axios.post(`${API_URL}/payments/stk`, {
        phone: form.phone,
        amount: total,
        orderId: orderRes.data._id,
      });

      // Clear cart
      localStorage.removeItem('cart');
      setCart([]);
      setStatus("success");
      
      // Redirect to success page
      navigate("/success");
    } catch (err: any) {
      setStatus("failed");
      alert("Error: " + (err.response?.data?.error || err.message));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="bg-black text-white min-h-screen px-6 md:px-20 py-16">

      {/* HEADER */}
      <motion.h1
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="text-3xl font-semibold mb-10"
      >
        Checkout
      </motion.h1>

      {/* STATUS UI */}
      {status === "pending" && (
        <div className="mb-8 text-green-400">
          Waiting for payment confirmation on your phone...
        </div>
      )}
      {status === "failed" && (
        <div className="mb-8 text-red-400">
          Payment failed. Try again.
        </div>
      )}
      {status === "success" && (
        <div className="mb-8 text-green-400">
          Payment initiated! Check your phone to complete.
        </div>
      )}

      <div className="grid md:grid-cols-2 gap-12">

        {/* LEFT - FORM */}
        <motion.div
          initial={{ opacity: 0, x: -20 }}
          animate={{ opacity: 1, x: 0 }}
          className="space-y-6"
        >

          <div>
            <label className="text-sm text-zinc-400">Full Name</label>
            <input
              placeholder="Full Name"
              className="w-full mt-2 p-4 bg-zinc-900 rounded-xl outline-none focus:ring-1 focus:ring-white"
              onChange={(e) => setForm({ ...form, name: e.target.value })}
            />
          </div>

          <div>
            <label className="text-sm text-zinc-400">Phone (M-Pesa)</label>
            <input
              placeholder="2547XXXXXXXX"
              value={form.phone}
              className="w-full mt-2 p-4 bg-zinc-900 rounded-xl outline-none focus:ring-1 focus:ring-white"
              onChange={(e) => setForm({ ...form, phone: formatPhone(e.target.value) })}
            />
          </div>

          <div>
            <label className="text-sm text-zinc-400">Delivery Address</label>
            <input
              placeholder="Delivery Address"
              className="w-full mt-2 p-4 bg-zinc-900 rounded-xl outline-none focus:ring-1 focus:ring-white"
              onChange={(e) => setForm({ ...form, address: e.target.value })}
            />
          </div>

        </motion.div>

        {/* RIGHT - ORDER SUMMARY */}
        <motion.div
          initial={{ opacity: 0, x: 20 }}
          animate={{ opacity: 1, x: 0 }}
          className="bg-zinc-900/40 p-6 rounded-3xl backdrop-blur-lg"
        >

          <h2 className="text-xl mb-6">Order Summary</h2>

          <div className="space-y-4">
            {cart.map((item, i) => (
              <div key={i} className="flex justify-between text-zinc-300">
                <span>{item.name}</span>
                <span>KES {item.price}</span>
              </div>
            ))}
          </div>

          <div className="border-t border-zinc-700 my-6"></div>

          <div className="flex justify-between text-lg font-medium">
            <span>Total</span>
            <span>KES {total}</span>
          </div>

          <button
            onClick={handlePay}
            disabled={loading}
            className="mt-8 w-full py-4 rounded-xl bg-green-500 text-black font-medium hover:bg-green-400 transition disabled:opacity-50 disabled:bg-zinc-600"
          >
            {loading ? "Processing..." : "Pay with M-Pesa"}
          </button>

        </motion.div>
      </div>

    </div>
  );
}
