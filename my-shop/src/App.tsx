import { useEffect, useState } from "react";
import axios from "axios";
import { motion } from "framer-motion";

const API_URL = "https://hearth-heal-api.onrender.com/api";

interface Product {
  _id: string;
  name: string;
  price: number;
  description?: string;
  image?: string;
}

export default function App() {
  const [products, setProducts] = useState<Product[]>([]);
  const [cart, setCart] = useState<Product[]>(() => {
    const saved = localStorage.getItem('cart');
    return saved ? JSON.parse(saved) : [];
  });
  const [phone, setPhone] = useState("2547XXXXXXXX");
  const [showCheckout, setShowCheckout] = useState(false);

  useEffect(() => {
    axios.get(`${API_URL}/products`)
      .then(res => setProducts(res.data));
  }, []);

  useEffect(() => {
    localStorage.setItem('cart', JSON.stringify(cart));
  }, [cart]);

  const addToCart = (p: Product) => setCart([...cart, p]);

  const removeFromCart = (i: number) => {
    const newCart = [...cart];
    newCart.splice(i, 1);
    setCart(newCart);
  };

  const total = cart.reduce((sum, item) => sum + item.price, 0);

  const checkout = async () => {
    try {
      // Create order first
      await axios.post(`${API_URL}/orders`, {
        products: cart,
        amount: total,
        phone,
      });

      // Initiate M-Pesa payment
      await axios.post(`${API_URL}/payments/stk`, {
        phone,
        amount: total,
      });

      alert("Check your phone to complete payment");
      setCart([]);
      localStorage.removeItem('cart');
      setShowCheckout(false);
    } catch (err: any) {
      alert("Error: " + (err.response?.data?.error || err.message));
    }
  };

  return (
    <div className="bg-black text-white min-h-screen font-sans">

      {/* NAVBAR */}
      <div className="flex justify-between items-center px-10 py-6 border-b border-zinc-800">
        <h1 className="text-2xl font-semibold tracking-wide">
          Hearth & Heal
        </h1>
        <div className="flex gap-6 text-sm text-zinc-400">
          <span className="hover:text-white cursor-pointer">Shop</span>
          <span className="hover:text-white cursor-pointer">About</span>
          <span 
            className="hover:text-white cursor-pointer"
            onClick={() => setShowCheckout(true)}
          >
            Cart ({cart.length})
          </span>
        </div>
      </div>

      {/* HERO */}
      <div className="text-center py-24 px-6">
        <h2 className="text-5xl md:text-6xl font-semibold leading-tight">
          Designed for Presence.
        </h2>
        <p className="text-zinc-400 mt-6 max-w-xl mx-auto">
          Minimal. Intentional. Timeless pieces crafted to elevate your everyday.
        </p>
      </div>

      {/* PRODUCTS */}
      <div className="grid md:grid-cols-3 gap-10 px-10 pb-20">
        {products.map((p, i) => (
          <motion.div
            key={p._id}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: i * 0.1 }}
            whileHover={{ scale: 1.03 }}
            className="group bg-zinc-900/40 backdrop-blur-lg p-6 rounded-3xl transition hover:bg-zinc-900/70"
          >
            <img
              src={p.image}
              className="h-64 w-full object-cover rounded-2xl mb-6"
            />

            <h3 className="text-lg font-medium">{p.name}</h3>
            <p className="text-zinc-400 mt-1">KES {p.price}</p>
            {p.description && (
              <p className="text-zinc-500 text-sm mt-2">{p.description}</p>
            )}

            <button
              onClick={() => addToCart(p)}
              className="mt-6 w-full py-3 rounded-xl border border-zinc-700 hover:border-white hover:bg-white hover:text-black transition duration-300"
            >
              Add to Cart
            </button>
          </motion.div>
        ))}
      </div>

      {/* CHECKOUT MODAL */}
      {showCheckout && (
        <motion.div 
          initial={{ opacity: 0 }} 
          animate={{ opacity: 1 }}
          className="fixed inset-0 bg-black/90 flex items-center justify-center z-50 p-4"
        >
          <motion.div 
            initial={{ y: 50, opacity: 0 }}
            animate={{ y: 0, opacity: 1 }}
            className="bg-zinc-950 border border-zinc-800 w-full max-w-4xl rounded-2xl overflow-hidden"
          >
            {/* Header */}
            <div className="bg-zinc-900 px-8 py-5 border-b border-zinc-800 flex justify-between items-center">
              <div>
                <h3 className="text-xl font-semibold text-white">Secure Checkout</h3>
                <p className="text-zinc-500 text-sm mt-1">Complete your purchase securely</p>
              </div>
              <button 
                onClick={() => setShowCheckout(false)}
                className="text-zinc-400 hover:text-white text-2xl"
              >
                ×
              </button>
            </div>

            {cart.length === 0 ? (
              <div className="p-8">
                <p className="text-zinc-400">Your cart is empty</p>
              </div>
            ) : (
              <div className="grid md:grid-cols-2">
                {/* Left: Order Summary */}
                <div className="p-8 border-r border-zinc-800">
                  <h4 className="text-sm font-medium text-zinc-400 uppercase tracking-wider mb-6">
                    Order Summary
                  </h4>
                  
                  <div className="space-y-4">
                    {cart.map((item, i) => (
                      <div key={i} className="flex justify-between items-start py-4 border-b border-zinc-800/50">
                        <div className="flex-1">
                          <p className="font-medium text-white">{item.name}</p>
                          {item.description && (
                            <p className="text-zinc-500 text-sm mt-1 line-clamp-1">{item.description}</p>
                          )}
                        </div>
                        <div className="text-right ml-4">
                          <p className="font-semibold text-white">KES {item.price}</p>
                          <button 
                            onClick={() => removeFromCart(i)}
                            className="text-red-400 hover:text-red-300 text-xs mt-1"
                          >
                            Remove
                          </button>
                        </div>
                      </div>
                    ))}
                  </div>

                  <div className="mt-6 pt-6 border-t border-zinc-800">
                    <div className="flex justify-between items-center">
                      <span className="text-zinc-400">Subtotal</span>
                      <span className="text-white">KES {total}</span>
                    </div>
                    <div className="flex justify-between items-center mt-2">
                      <span className="text-zinc-400">Shipping</span>
                      <span className="text-green-400">Free</span>
                    </div>
                    <div className="flex justify-between items-center mt-4 pt-4 border-t border-zinc-800">
                      <span className="text-lg font-semibold text-white">Total</span>
                      <span className="text-2xl font-bold text-white">KES {total}</span>
                    </div>
                  </div>
                </div>

                {/* Right: Payment */}
                <div className="p-8 bg-zinc-900/50">
                  <h4 className="text-sm font-medium text-zinc-400 uppercase tracking-wider mb-6">
                    Payment Method
                  </h4>

                  {/* Payment Options */}
                  <div className="space-y-3 mb-8">
                    <button className="w-full flex items-center gap-4 p-4 rounded-xl border-2 border-green-500 bg-green-500/10">
                      <div className="w-10 h-10 rounded-lg bg-green-500 flex items-center justify-center">
                        <span className="text-black font-bold text-sm">M</span>
                      </div>
                      <div className="flex-1 text-left">
                        <p className="font-semibold text-white">M-Pesa</p>
                        <p className="text-zinc-400 text-sm">Pay via M-Pesa</p>
                      </div>
                      <div className="w-4 h-4 rounded-full border-2 border-green-500 bg-green-500" />
                    </button>
                  </div>

                  {/* Phone Input */}
                  <div className="space-y-4">
                    <div>
                      <label className="block text-sm font-medium text-zinc-300 mb-2">
                        M-Pesa Phone Number
                      </label>
                      <input
                        type="tel"
                        value={phone}
                        onChange={(e) => setPhone(e.target.value)}
                        placeholder="2547XX XXX XXX"
                        className="w-full p-4 bg-zinc-800 border border-zinc-700 rounded-xl text-white placeholder-zinc-500 focus:border-green-500 focus:outline-none transition"
                      />
                      <p className="text-zinc-500 text-xs mt-2">
                        Enter the number to receive the STK push notification
                      </p>
                    </div>

                    <button
                      onClick={checkout}
                      className="w-full mt-6 bg-green-500 hover:bg-green-600 text-black font-semibold py-4 rounded-xl transition flex items-center justify-center gap-2"
                    >
                      <span>Complete Payment</span>
                      <span>KES {total}</span>
                    </button>

                    <p className="text-center text-zinc-500 text-xs mt-4">
                      You will receive an M-Pesa prompt on your phone to complete the payment
                    </p>
                  </div>
                </div>
              </div>
            )}
          </motion.div>
        </motion.div>
      )}

    </div>
  );
}
