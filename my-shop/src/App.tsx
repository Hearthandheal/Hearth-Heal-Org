import { useEffect, useState } from "react";
import axios from "axios";

const API_URL = "http://localhost:5000/api";

export default function App() {
  const [products, setProducts] = useState([]);
  const [cart, setCart] = useState([]);
  const [loading, setLoading] = useState(true);
  const [phone, setPhone] = useState("2547XXXXXXXX");

  useEffect(() => {
    fetchProducts();
  }, []);

  const fetchProducts = async () => {
    try {
      const res = await axios.get(`${API_URL}/products`);
      setProducts(res.data);
    } catch (err) {
      console.error("Failed to fetch products:", err);
    } finally {
      setLoading(false);
    }
  };

  const addToCart = (product) => {
    setCart([...cart, product]);
  };

  const removeFromCart = (index) => {
    const newCart = [...cart];
    newCart.splice(index, 1);
    setCart(newCart);
  };

  const total = cart.reduce((sum, item) => sum + item.price, 0);

  const checkout = async () => {
    if (cart.length === 0) {
      alert("Your cart is empty!");
      return;
    }
    try {
      await axios.post(`${API_URL}/payments/stk`, {
        phone: phone,
        amount: total,
      });
      alert("Check your phone to complete M-Pesa payment");
      setCart([]);
    } catch (err) {
      alert("Payment failed: " + (err.response?.data?.error || err.message));
    }
  };

  if (loading) {
    return (
      <div className="bg-black text-white min-h-screen flex items-center justify-center">
        <p className="text-xl">Loading products...</p>
      </div>
    );
  }

  return (
    <div className="bg-black text-white min-h-screen p-6">
      <h1 className="text-3xl font-bold mb-6">Hearth & Heal Store</h1>

      {/* Products */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 pr-72">
        {products.map((p) => (
          <div key={p._id} className="bg-zinc-900 p-4 rounded-2xl shadow-lg">
            {p.image && (
              <img
                src={p.image}
                alt={p.name}
                className="w-full h-48 object-cover rounded-xl mb-4"
              />
            )}
            <h2 className="text-xl font-semibold">{p.name}</h2>
            <p className="text-green-400 text-lg">KES {p.price}</p>
            <p className="text-gray-400 text-sm mt-2">{p.description}</p>
            <button
              onClick={() => addToCart(p)}
              className="mt-4 w-full bg-green-500 hover:bg-green-600 px-4 py-2 rounded-xl font-semibold transition"
            >
              Add to Cart
            </button>
          </div>
        ))}
      </div>

      {/* Cart Sidebar */}
      <div className="fixed right-4 top-4 bg-zinc-800 p-4 rounded-xl shadow-xl w-64 max-h-[80vh] overflow-y-auto">
        <h2 className="font-bold mb-4 text-xl">Cart ({cart.length})</h2>

        {cart.length === 0 ? (
          <p className="text-gray-400">Your cart is empty</p>
        ) : (
          <>
            {cart.map((item, i) => (
              <div
                key={i}
                className="flex justify-between items-center mb-2 pb-2 border-b border-zinc-700"
              >
                <div>
                  <p className="font-medium">{item.name}</p>
                  <p className="text-green-400 text-sm">KES {item.price}</p>
                </div>
                <button
                  onClick={() => removeFromCart(i)}
                  className="text-red-400 hover:text-red-300 text-sm"
                >
                  ×
                </button>
              </div>
            ))}

            <div className="mt-4 pt-4 border-t border-zinc-700">
              <p className="text-lg font-bold">
                Total: <span className="text-green-400">KES {total}</span>
              </p>

              <input
                type="text"
                value={phone}
                onChange={(e) => setPhone(e.target.value)}
                placeholder="M-Pesa Phone (2547XXXXXXXX)"
                className="w-full mt-3 p-2 bg-zinc-700 rounded-lg text-sm"
              />

              <button
                onClick={checkout}
                className="w-full mt-3 bg-green-500 hover:bg-green-600 px-4 py-2 rounded-xl font-semibold transition"
              >
                Pay with M-Pesa
              </button>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
