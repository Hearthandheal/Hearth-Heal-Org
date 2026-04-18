import { useEffect, useState } from "react";
import axios from "axios";

const API_URL = "http://localhost:5000/api";

export default function App() {
  const [products, setProducts] = useState([]);
  const [cart, setCart] = useState([]);
  const [phone, setPhone] = useState("2547XXXXXXXX");
  const [showCheckout, setShowCheckout] = useState(false);

  useEffect(() => {
    axios.get(`${API_URL}/products`)
      .then(res => setProducts(res.data));
  }, []);

  const addToCart = (p) => setCart([...cart, p]);

  const removeFromCart = (i) => {
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
      setShowCheckout(false);
    } catch (err) {
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
        {products.map((p) => (
          <div
            key={p._id}
            className="group bg-zinc-900/40 backdrop-blur-lg p-6 rounded-3xl transition hover:bg-zinc-900/70"
          >
            <div className="h-64 bg-zinc-800 rounded-2xl mb-6 flex items-center justify-center text-zinc-500 overflow-hidden">
              {p.image ? (
                <img src={p.image} alt={p.name} className="w-full h-full object-cover" />
              ) : (
                "Image"
              )}
            </div>

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
          </div>
        ))}
      </div>

      {/* CHECKOUT MODAL */}
      {showCheckout && (
        <div className="fixed inset-0 bg-black/80 flex items-center justify-center z-50">
          <div className="bg-zinc-900 p-8 rounded-3xl w-full max-w-md">
            <div className="flex justify-between items-center mb-6">
              <h3 className="text-xl font-semibold">Your Cart</h3>
              <button 
                onClick={() => setShowCheckout(false)}
                className="text-zinc-400 hover:text-white"
              >
                ×
              </button>
            </div>

            {cart.length === 0 ? (
              <p className="text-zinc-400">Your cart is empty</p>
            ) : (
              <>
                {cart.map((item, i) => (
                  <div key={i} className="flex justify-between items-center py-3 border-b border-zinc-800">
                    <div>
                      <p className="font-medium">{item.name}</p>
                      <p className="text-zinc-400 text-sm">KES {item.price}</p>
                    </div>
                    <button 
                      onClick={() => removeFromCart(i)}
                      className="text-red-400 hover:text-red-300"
                    >
                      Remove
                    </button>
                  </div>
                ))}

                <div className="mt-6 pt-4 border-t border-zinc-800">
                  <p className="text-xl font-semibold">
                    Total: KES {total}
                  </p>

                  <input
                    type="text"
                    value={phone}
                    onChange={(e) => setPhone(e.target.value)}
                    placeholder="M-Pesa Phone (2547XXXXXXXX)"
                    className="w-full mt-4 p-3 bg-zinc-800 rounded-xl text-sm"
                  />

                  <button
                    onClick={checkout}
                    className="w-full mt-4 bg-white text-black py-3 rounded-xl font-semibold hover:bg-zinc-200 transition"
                  >
                    Pay with M-Pesa
                  </button>
                </div>
              </>
            )}
          </div>
        </div>
      )}

    </div>
  );
}
