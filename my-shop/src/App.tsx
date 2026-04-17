import { useState } from "react";

const products = [
  { id: 1, name: "Luxury Hoodie", price: 45 },
  { id: 2, name: "Premium T-Shirt", price: 25 },
  { id: 3, name: "Classic Cap", price: 15 },
];

export default function App() {
  const [cart, setCart] = useState([]);

  const addToCart = (product) => {
    setCart([...cart, product]);
  };

  return (
    <div className="bg-black text-white min-h-screen p-6">
      <h1 className="text-3xl font-bold mb-6">Hearth & Heal Store</h1>

      {/* Products */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {products.map((p) => (
          <div key={p.id} className="bg-zinc-900 p-4 rounded-2xl shadow-lg">
            <h2 className="text-xl font-semibold">{p.name}</h2>
            <p className="text-green-400">${p.price}</p>
            <button
              onClick={() => addToCart(p)}
              className="mt-3 bg-green-500 hover:bg-green-600 px-4 py-2 rounded-xl"
            >
              Add to Cart
            </button>
          </div>
        ))}
      </div>

      {/* Cart */}
      <div className="fixed right-4 top-4 bg-zinc-800 p-4 rounded-xl shadow-xl w-64">
        <h2 className="font-bold mb-2">Cart ({cart.length})</h2>
        {cart.map((item, i) => (
          <p key={i}>{item.name}</p>
        ))}
      </div>
    </div>
  );
}
