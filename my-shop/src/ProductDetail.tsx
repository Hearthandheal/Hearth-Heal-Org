import { useState } from 'react';
import { motion } from 'framer-motion';

// Sample product data
const product = {
  name: "Premium Wellness Hoodie",
  price: 4500,
  rating: 4.8,
  reviews: 124,
  images: [
    "/images/community/community (1).jpg",
    "/images/community/community (2).jpg",
    "/images/community/community (3).jpg",
    "/images/community/community (4).jpg",
  ],
  sizes: ["S", "M", "L", "XL"],
  colors: ["#1a1a1a", "#f5f5f5", "#39ff14", "#8b4513"],
  description: [
    "Premium organic cotton blend",
    "Breathable, moisture-wicking fabric",
    "Modern athletic fit with room to move",
    "Reinforced stitching for durability",
    "Ethically sourced materials",
  ],
};

export default function ProductDetail() {
  const [selectedImage, setSelectedImage] = useState(0);
  const [selectedSize, setSelectedSize] = useState("M");
  const [selectedColor, setSelectedColor] = useState(product.colors[0]);
  const [quantity, setQuantity] = useState(1);
  const [activeTab, setActiveTab] = useState("description");

  const addToCart = () => {
    alert(`Added ${quantity} × ${product.name} (${selectedSize}) to cart!`);
  };

  return (
    <div className="min-h-screen bg-[#0a0a0a] text-white">
      {/* Subtle gradient background */}
      <div className="fixed inset-0 bg-gradient-to-b from-[#111] to-[#0a0a0a] pointer-events-none" />

      <div className="relative z-10 max-w-7xl mx-auto px-8 py-12">
        {/* Main Layout - 2 Columns */}
        <div className="grid grid-cols-12 gap-12">
          
          {/* LEFT: Product Images (60%) */}
          <div className="col-span-7 space-y-6">
            {/* Main Image */}
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              className="relative aspect-[4/3] rounded-2xl overflow-hidden bg-[#1a1a1a] shadow-2xl"
              style={{ boxShadow: '0 25px 50px -12px rgba(57, 255, 20, 0.15)' }}
            >
              <img
                src={product.images[selectedImage]}
                alt={product.name}
                className="w-full h-full object-cover"
              />
              {/* Glass overlay effect */}
              <div className="absolute inset-0 bg-white/5 backdrop-blur-[1px]" />
            </motion.div>

            {/* Thumbnails */}
            <div className="flex gap-4">
              {product.images.map((img, index) => (
                <button
                  key={index}
                  onClick={() => setSelectedImage(index)}
                  className={`relative w-24 h-24 rounded-xl overflow-hidden transition-all duration-300 ${
                    selectedImage === index
                      ? 'ring-2 ring-[#39ff14] ring-offset-2 ring-offset-[#0a0a0a]'
                      : 'opacity-60 hover:opacity-100'
                  }`}
                >
                  <img src={img} alt={`View ${index + 1}`} className="w-full h-full object-cover" />
                  {selectedImage === index && (
                    <div className="absolute inset-0 bg-[#39ff14]/10" />
                  )}
                </button>
              ))}
            </div>
          </div>

          {/* RIGHT: Product Info (40%) */}
          <div className="col-span-5 space-y-8">
            {/* Product Name */}
            <motion.h1
              initial={{ opacity: 0, x: 20 }}
              animate={{ opacity: 1, x: 0 }}
              className="text-5xl font-bold leading-tight"
              style={{ fontFamily: 'Poppins, Montserrat, sans-serif' }}
            >
              {product.name}
            </motion.h1>

            {/* Price */}
            <motion.div
              initial={{ opacity: 0, x: 20 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: 0.1 }}
              className="text-4xl font-bold"
              style={{ color: '#39ff14' }}
            >
              KES {product.price.toLocaleString()}
            </motion.div>

            {/* Rating */}
            <motion.div
              initial={{ opacity: 0, x: 20 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: 0.2 }}
              className="flex items-center gap-2"
            >
              <div className="flex text-yellow-400">
                {[...Array(5)].map((_, i) => (
                  <span key={i} className={i < Math.floor(product.rating) ? 'text-yellow-400' : 'text-gray-600'}>
                    ★
                  </span>
                ))}
              </div>
              <span className="text-gray-400 text-sm">
                ({product.reviews} reviews)
              </span>
            </motion.div>

            {/* Size Selection */}
            <motion.div
              initial={{ opacity: 0, x: 20 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: 0.3 }}
            >
              <label className="block text-sm text-gray-400 mb-3">Size</label>
              <div className="flex gap-3">
                {product.sizes.map((size) => (
                  <button
                    key={size}
                    onClick={() => setSelectedSize(size)}
                    className={`w-14 h-14 rounded-xl font-medium transition-all duration-300 ${
                      selectedSize === size
                        ? 'bg-[#39ff14] text-black shadow-lg'
                        : 'bg-transparent border-2 border-[#39ff14]/50 text-gray-300 hover:border-[#39ff14]'
                    }`}
                    style={
                      selectedSize === size
                        ? { boxShadow: '0 0 20px rgba(57, 255, 20, 0.4)' }
                        : {}
                    }
                  >
                    {size}
                  </button>
                ))}
              </div>
            </motion.div>

            {/* Color Selection */}
            <motion.div
              initial={{ opacity: 0, x: 20 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: 0.4 }}
            >
              <label className="block text-sm text-gray-400 mb-3">Color</label>
              <div className="flex gap-3">
                {product.colors.map((color) => (
                  <button
                    key={color}
                    onClick={() => setSelectedColor(color)}
                    className={`w-12 h-12 rounded-full transition-all duration-300 ${
                      selectedColor === color
                        ? 'ring-2 ring-offset-2 ring-offset-[#0a0a0a]'
                        : 'hover:scale-110'
                    }`}
                    style={{
                      backgroundColor: color,
                      boxShadow: selectedColor === color ? `0 0 20px ${color}80` : 'none',
                      border: color === '#f5f5f5' ? '1px solid rgba(255,255,255,0.2)' : 'none',
                    }}
                  />
                ))}
              </div>
            </motion.div>

            {/* Quantity & Add to Cart */}
            <motion.div
              initial={{ opacity: 0, x: 20 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: 0.5 }}
              className="flex items-center gap-6 pt-4"
            >
              {/* Quantity Selector */}
              <div className="flex items-center bg-[#1a1a1a] rounded-xl border border-gray-700">
                <button
                  onClick={() => setQuantity(Math.max(1, quantity - 1))}
                  className="w-12 h-12 text-xl text-gray-400 hover:text-white transition-colors"
                >
                  -
                </button>
                <span className="w-12 text-center font-medium">{quantity}</span>
                <button
                  onClick={() => setQuantity(quantity + 1)}
                  className="w-12 h-12 text-xl text-gray-400 hover:text-white transition-colors"
                >
                  +
                </button>
              </div>

              {/* Add to Cart Button */}
              <motion.button
                onClick={addToCart}
                whileHover={{ scale: 1.02 }}
                whileTap={{ scale: 0.98 }}
                className="flex-1 h-14 rounded-2xl font-bold text-lg tracking-wide transition-all duration-300"
                style={{
                  background: 'linear-gradient(180deg, #39ff14 0%, #2dd30a 100%)',
                  color: '#000',
                  boxShadow: '0 8px 32px rgba(57, 255, 20, 0.3), 0 0 0 1px rgba(57, 255, 20, 0.2)',
                }}
              >
                ADD TO CART
              </motion.button>
            </motion.div>
          </div>
        </div>

        {/* Lower Section: Details */}
        <motion.div
          initial={{ opacity: 0, y: 40 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.6 }}
          className="mt-20"
        >
          {/* Glass effect panel */}
          <div
            className="rounded-3xl p-8 border border-white/10"
            style={{
              background: 'rgba(255, 255, 255, 0.05)',
              backdropFilter: 'blur(10px)',
            }}
          >
            {/* Tabs */}
            <div className="flex gap-8 border-b border-white/10 pb-4 mb-6">
              {['description', 'details', 'reviews'].map((tab) => (
                <button
                  key={tab}
                  onClick={() => setActiveTab(tab)}
                  className={`text-lg font-medium capitalize transition-all duration-300 ${
                    activeTab === tab
                      ? 'text-[#39ff14] border-b-2 border-[#39ff14] pb-4 -mb-4.5'
                      : 'text-gray-400 hover:text-white'
                  }`}
                >
                  {tab}
                </button>
              ))}
            </div>

            {/* Tab Content */}
            <div className="text-gray-300 leading-relaxed">
              {activeTab === 'description' && (
                <ul className="space-y-3">
                  {product.description.map((item, index) => (
                    <li key={index} className="flex items-start gap-3">
                      <span className="text-[#39ff14] mt-1">•</span>
                      <span>{item}</span>
                    </li>
                  ))}
                </ul>
              )}
              {activeTab === 'details' && (
                <div className="grid grid-cols-2 gap-6">
                  <div>
                    <h4 className="text-white font-medium mb-2">Material</h4>
                    <p className="text-gray-400">80% Organic Cotton, 20% Polyester</p>
                  </div>
                  <div>
                    <h4 className="text-white font-medium mb-2">Care</h4>
                    <p className="text-gray-400">Machine wash cold, tumble dry low</p>
                  </div>
                  <div>
                    <h4 className="text-white font-medium mb-2">Origin</h4>
                    <p className="text-gray-400">Made in Kenya</p>
                  </div>
                  <div>
                    <h4 className="text-white font-medium mb-2">Shipping</h4>
                    <p className="text-gray-400">Free delivery within Nairobi</p>
                  </div>
                </div>
              )}
              {activeTab === 'reviews' && (
                <div className="space-y-4">
                  <p className="text-gray-400">Customer reviews coming soon...</p>
                </div>
              )}
            </div>
          </div>
        </motion.div>
      </div>
    </div>
  );
}
