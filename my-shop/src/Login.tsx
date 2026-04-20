import axios from "axios";
import { useState, useEffect } from "react";

const API_URL = "https://hearth-heal-api.onrender.com/api";

// Background images for slideshow
const backgroundImages = [
  "https://images.unsplash.com/photo-1551836020-4b6587e3c123?w=1920",
  "https://images.unsplash.com/photo-1576091160550-2173dba999ef?w=1920",
  "https://images.unsplash.com/photo-1576091160399-112ba8d25d1d?w=1920",
];

export default function Login() {
  const [isRegister, setIsRegister] = useState(false);
  const [form, setForm] = useState({ name: "", email: "", password: "" });
  const [currentImage, setCurrentImage] = useState(0);

  // Auto-rotate background images every 5 seconds
  useEffect(() => {
    const timer = setInterval(() => {
      setCurrentImage((prev) => (prev + 1) % backgroundImages.length);
    }, 5000);
    return () => clearInterval(timer);
  }, []);

  const submit = async () => {
    try {
      const endpoint = isRegister ? "/auth/register" : "/auth/login";
      const res = await axios.post(`${API_URL}${endpoint}`, form);
      
      if (res.data.token) {
        localStorage.setItem("token", res.data.token);
        alert(isRegister ? "Registered! Please login." : "Logged in!");
        if (!isRegister) window.location.href = "/";
      }
    } catch (err: any) {
      const errorMsg = err.response?.data?.error || err.response?.data || err.message;
      alert("Error: " + errorMsg);
    }
  };

  return (
    <div className="relative text-white min-h-screen flex items-center justify-center p-6 overflow-hidden">
      {/* Background Images */}
      {backgroundImages.map((img, index) => (
        <div
          key={img}
          className={`absolute inset-0 transition-opacity duration-1000 ${
            index === currentImage ? "opacity-100" : "opacity-0"
          }`}
          style={{
            backgroundImage: `url(${img})`,
            backgroundSize: "cover",
            backgroundPosition: "center",
          }}
        />
      ))}
      {/* Dark overlay */}
      <div className="absolute inset-0 bg-black/60" />
      
      {/* Content */}
      <div className="relative z-10 bg-zinc-900/90 p-8 rounded-2xl w-full max-w-md backdrop-blur-sm">
        <h1 className="text-2xl font-bold mb-6 text-center">
          {isRegister ? "Register" : "Login"}
        </h1>

        {isRegister && (
          <input 
            className="w-full mb-4 p-3 bg-zinc-800 rounded-lg"
            placeholder="Name"
            value={form.name}
            onChange={e => setForm({...form, name: e.target.value})}
          />
        )}
        <input 
          className="w-full mb-4 p-3 bg-zinc-800 rounded-lg"
          placeholder="Email"
          type="email"
          value={form.email}
          onChange={e => setForm({...form, email: e.target.value})}
        />
        <input 
          className="w-full mb-4 p-3 bg-zinc-800 rounded-lg"
          placeholder="Password"
          type="password"
          value={form.password}
          onChange={e => setForm({...form, password: e.target.value})}
        />

        <button 
          onClick={submit}
          className="w-full bg-green-500 hover:bg-green-600 px-4 py-3 rounded-xl font-semibold mb-4"
        >
          {isRegister ? "Register" : "Login"}
        </button>

        <p className="text-center text-gray-400">
          {isRegister ? "Already have an account? " : "Don't have an account? "}
          <button 
            onClick={() => setIsRegister(!isRegister)}
            className="text-green-400 hover:underline"
          >
            {isRegister ? "Login" : "Register"}
          </button>
        </p>
      </div>
    </div>
  );
}
