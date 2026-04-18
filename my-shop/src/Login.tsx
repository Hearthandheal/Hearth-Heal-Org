import axios from "axios";
import { useState } from "react";

const API_URL = "http://localhost:5000/api";

export default function Login() {
  const [isRegister, setIsRegister] = useState(false);
  const [form, setForm] = useState({ name: "", email: "", password: "" });

  const submit = async () => {
    try {
      const endpoint = isRegister ? "/auth/register" : "/auth/login";
      const res = await axios.post(`${API_URL}${endpoint}`, form);
      
      if (res.data.token) {
        localStorage.setItem("token", res.data.token);
        alert(isRegister ? "Registered! Please login." : "Logged in!");
        if (!isRegister) window.location.href = "/";
      }
    } catch (err) {
      alert("Error: " + (err.response?.data || err.message));
    }
  };

  return (
    <div className="bg-black text-white min-h-screen flex items-center justify-center p-6">
      <div className="bg-zinc-900 p-8 rounded-2xl w-full max-w-md">
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
