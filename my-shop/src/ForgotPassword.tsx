import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Link } from 'react-router-dom';

const backgroundImages = [
  "/images/community/community (1).jpg",
  "/images/community/community (2).jpg",
  "/images/community/community (3).jpg",
];

export default function ForgotPassword() {
  const [email, setEmail] = useState('');
  const [submitted, setSubmitted] = useState(false);
  const [currentImage, setCurrentImage] = useState(0);

  // Auto-rotate background images every 5 seconds
  useEffect(() => {
    const timer = setInterval(() => {
      setCurrentImage((prev) => (prev + 1) % backgroundImages.length);
    }, 5000);
    return () => clearInterval(timer);
  }, []);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    // Mock submission
    setSubmitted(true);
  };

  return (
    <div className="min-h-screen flex items-center justify-center relative overflow-hidden" style={{ backgroundColor: '#0a0a0a' }}>
      {/* Background Images */}
      {backgroundImages.map((img, index) => (
        <div
          key={img}
          className={`absolute inset-0 transition-opacity duration-1000 ${
            index === currentImage ? 'opacity-100' : 'opacity-0'
          }`}
          style={{
            backgroundImage: `url(${img})`,
            backgroundSize: 'cover',
            backgroundPosition: 'center',
          }}
        />
      ))}
      
      {/* Dark overlay */}
      <div className="absolute inset-0 bg-black/30" />

      {/* Form Container */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="relative z-10 w-full max-w-md p-8"
      >
        <div 
          className="rounded-2xl p-8 border border-white/10"
          style={{
            background: 'rgba(20, 20, 20, 0.9)',
            backdropFilter: 'blur(10px)',
          }}
        >
          <h1 className="text-3xl font-bold text-white text-center mb-2">
            Reset Password
          </h1>
          <p className="text-gray-400 text-center mb-8">
            Enter your email to receive reset instructions
          </p>

          {!submitted ? (
            <form onSubmit={handleSubmit} className="space-y-6">
              <div>
                <label className="block text-sm text-gray-400 mb-2">Email</label>
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="w-full p-4 bg-zinc-800 rounded-xl text-white border border-zinc-700 focus:border-green-500 focus:outline-none transition-colors"
                  placeholder="your@email.com"
                  required
                />
              </div>

              <button
                type="submit"
                className="w-full py-4 rounded-xl font-semibold text-black transition-all duration-300 hover:scale-[1.02]"
                style={{
                  background: 'linear-gradient(180deg, #39ff14 0%, #2dd30a 100%)',
                  boxShadow: '0 8px 32px rgba(57, 255, 20, 0.3)',
                }}
              >
                Send Reset Link
              </button>
            </form>
          ) : (
            <div className="text-center py-4">
              <div className="w-16 h-16 rounded-full bg-green-500/20 flex items-center justify-center mx-auto mb-4">
                <span className="text-green-400 text-2xl">✓</span>
              </div>
              <p className="text-white mb-2">Check your email!</p>
              <p className="text-gray-400 text-sm">
                We&apos;ve sent reset instructions to {email}
              </p>
            </div>
          )}

          <div className="mt-8 text-center">
            <Link 
              to="/login" 
              className="text-gray-400 hover:text-green-400 transition-colors text-sm"
            >
              ← Back to Login
            </Link>
          </div>
        </div>
      </motion.div>
    </div>
  );
}
