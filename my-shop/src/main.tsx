import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter, Routes, Route, Link } from 'react-router-dom'
import './style.css'
import App from './App.tsx'
import Login from './Login.tsx'
import Admin from './Admin.tsx'
import Checkout from './Checkout.tsx'

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <BrowserRouter>
      <nav className="bg-zinc-900 p-4 flex gap-4">
        <Link to="/" className="text-white hover:text-green-400">Shop</Link>
        <Link to="/login" className="text-white hover:text-green-400">Login</Link>
        <Link to="/admin" className="text-white hover:text-green-400">Admin</Link>
        <Link to="/checkout" className="text-white hover:text-green-400 ml-auto">Checkout</Link>
      </nav>
      <Routes>
        <Route path="/" element={<App />} />
        <Route path="/login" element={<Login />} />
        <Route path="/admin" element={<Admin />} />
        <Route path="/checkout" element={<Checkout />} />
      </Routes>
    </BrowserRouter>
  </StrictMode>,
)
