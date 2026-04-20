import { useState, useEffect } from "react";
import axios from "axios";

const API_URL = "https://hearth-heal-api.onrender.com/api";

interface CartItem {
  _id: string;
  name: string;
  price: number;
}

export default function Checkout() {
  const [cart, setCart] = useState<CartItem[]>([]);
  const [form, setForm] = useState({
    name: "",
    phone: "",
    address: "",
  });

  useEffect(() => {
    const saved = localStorage.getItem('cart');
    if (saved) {
      setCart(JSON.parse(saved));
    }
  }, []);

  const total = cart.reduce((sum, item) => sum + item.price, 0);

  const handlePay = async () => {
    if (!form.phone) return alert("Enter phone number");

    try {
      // Create order first
      await axios.post(`${API_URL}/orders`, {
        products: cart,
        amount: total,
        phone: form.phone,
      });

      // Initiate M-Pesa payment
      await axios.post(`${API_URL}/payments/stk`, {
        phone: form.phone,
        amount: total,
      });

      // Clear cart
      localStorage.removeItem('cart');
      setCart([]);
      alert("Check your phone to complete payment. Your cart has been cleared.");
    } catch (err: any) {
      alert("Error: " + (err.response?.data?.error || err.message));
    }
  };

  return (
    <div className="bg-black text-white min-h-screen px-6 md:px-20 py-16">

      {/* HEADER */}
      <h1 className="text-3xl font-semibold mb-10">Checkout</h1>

      <div className="grid md:grid-cols-2 gap-12">

        {/* LEFT - FORM */}
        <div className="space-y-6">

          <div>
            <label className="text-sm text-zinc-400">Full Name</label>
            <input
              className="w-full mt-2 p-4 bg-zinc-900 rounded-xl outline-none focus:ring-1 focus:ring-white"
              onChange={(e) => setForm({ ...form, name: e.target.value })}
            />
          </div>

          <div>
            <label className="text-sm text-zinc-400">Phone (M-Pesa)</label>
            <input
              placeholder="2547XXXXXXXX"
              className="w-full mt-2 p-4 bg-zinc-900 rounded-xl outline-none focus:ring-1 focus:ring-white"
              onChange={(e) => setForm({ ...form, phone: e.target.value })}
            />
          </div>

          <div>
            <label className="text-sm text-zinc-400">Delivery Address</label>
            <input
              className="w-full mt-2 p-4 bg-zinc-900 rounded-xl outline-none focus:ring-1 focus:ring-white"
              onChange={(e) => setForm({ ...form, address: e.target.value })}
            />
          </div>

        </div>

        {/* RIGHT - ORDER SUMMARY */}
        <div className="bg-zinc-900/40 p-6 rounded-3xl backdrop-blur-lg">

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
            className="mt-8 w-full py-4 rounded-xl bg-white text-black font-medium hover:opacity-90 transition"
          >
            Pay with M-Pesa
          </button>

        </div>
      </div>

    </div>
  );
}
