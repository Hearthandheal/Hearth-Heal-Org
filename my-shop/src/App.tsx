import { useEffect, useState } from "react";
import axios from "axios";
import { motion } from "framer-motion";
import { Link } from "react-router-dom";

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
  const [profilePic, setProfilePic] = useState(() => {
    const saved = localStorage.getItem('profilePic');
    return saved || '/images/community/community (1).jpg';
  });
  const [showProfilePicker, setShowProfilePicker] = useState(false);

  const profileOptions = [
    '/images/community/community (1).jpg',
    '/images/community/community (2).jpg',
    '/images/community/community (3).jpg',
    '/images/community/community (4).jpg',
    '/images/community/community (5).jpg',
  ];

  const handleProfileChange = (pic: string) => {
    setProfilePic(pic);
    localStorage.setItem('profilePic', pic);
    setShowProfilePicker(false);
  };

  useEffect(() => {
    axios.get(`${API_URL}/products`)
      .then(res => setProducts(res.data));
  }, []);

  useEffect(() => {
    localStorage.setItem('cart', JSON.stringify(cart));
  }, [cart]);

  const addToCart = (p: Product) => {
    const newCart = [...cart, p];
    setCart(newCart);
    localStorage.setItem('cart', JSON.stringify(newCart));
  };

  return (
    <div className="bg-black text-white min-h-screen font-sans" style={{backgroundColor: '#000'}}>

      {/* NAVBAR */}
      <div className="flex justify-between items-center px-10 py-6 border-b border-zinc-800">
        <h1 className="text-2xl font-semibold tracking-wide">
          Hearth & Heal
        </h1>
        <div className="flex gap-6 text-sm text-zinc-400 items-center">
          <span className="hover:text-white cursor-pointer">Shop</span>
          <span className="hover:text-white cursor-pointer">About</span>
          <Link 
            to="/checkout"
            className="hover:text-white"
          >
            Cart ({cart.length})
          </Link>
          
          {/* Profile Picture */}
          <div className="relative">
            <img
              src={profilePic}
              alt="Profile"
              onClick={() => setShowProfilePicker(!showProfilePicker)}
              className="w-10 h-10 rounded-full object-cover cursor-pointer border-2 border-zinc-700 hover:border-green-500 transition"
            />
            
            {/* Profile Picker Dropdown */}
            {showProfilePicker && (
              <div className="absolute right-0 top-12 bg-zinc-900 border border-zinc-700 rounded-xl p-3 shadow-xl z-50">
                <p className="text-xs text-zinc-400 mb-2">Select Profile</p>
                <div className="grid grid-cols-3 gap-2">
                  {profileOptions.map((pic, idx) => (
                    <img
                      key={idx}
                      src={pic}
                      alt={`Profile ${idx}`}
                      onClick={() => handleProfileChange(pic)}
                      className={`w-12 h-12 rounded-full object-cover cursor-pointer border-2 transition hover:scale-110 ${
                        profilePic === pic ? 'border-green-500' : 'border-zinc-700'
                      }`}
                    />
                  ))}
                </div>
              </div>
            )}
          </div>
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
              className="mt-6 w-full py-3 rounded-xl border border-zinc-700 hover:border-green-500 hover:bg-green-500 hover:text-black transition duration-300"
            >
              Add to Cart
            </button>
          </motion.div>
        ))}
      </div>

    </div>
  );
}
