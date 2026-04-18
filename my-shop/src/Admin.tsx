import axios from "axios";
import { useState } from "react";

const API_URL = "http://localhost:5000/api";

export default function Admin() {
  const [product, setProduct] = useState({ 
    name: "", 
    price: "",
    description: "",
    image: ""
  });

  const createProduct = async () => {
    try {
      const token = localStorage.getItem("token");
      if (!token) {
        alert("Please login first");
        return;
      }

      await axios.post(`${API_URL}/products`, {
        ...product,
        price: Number(product.price)
      }, {
        headers: { Authorization: token },
      });
      
      alert("Product added successfully!");
      setProduct({ name: "", price: "", description: "", image: "" });
    } catch (err) {
      alert("Error: " + (err.response?.data || err.message));
    }
  };

  return (
    <div className="bg-black text-white min-h-screen p-6">
      <h1 className="text-3xl font-bold mb-6">Admin - Add Product</h1>

      <div className="bg-zinc-900 p-6 rounded-2xl max-w-md">
        <input 
          className="w-full mb-4 p-3 bg-zinc-800 rounded-lg"
          placeholder="Product Name" 
          value={product.name}
          onChange={e => setProduct({...product, name: e.target.value})}
        />
        <input 
          className="w-full mb-4 p-3 bg-zinc-800 rounded-lg"
          placeholder="Price (KES)" 
          type="number"
          value={product.price}
          onChange={e => setProduct({...product, price: e.target.value})}
        />
        <input 
          className="w-full mb-4 p-3 bg-zinc-800 rounded-lg"
          placeholder="Description" 
          value={product.description}
          onChange={e => setProduct({...product, description: e.target.value})}
        />
        <input 
          className="w-full mb-4 p-3 bg-zinc-800 rounded-lg"
          placeholder="Image URL" 
          value={product.image}
          onChange={e => setProduct({...product, image: e.target.value})}
        />
        <button 
          onClick={createProduct}
          className="w-full bg-green-500 hover:bg-green-600 px-4 py-3 rounded-xl font-semibold"
        >
          Add Product
        </button>
      </div>
    </div>
  );
}
