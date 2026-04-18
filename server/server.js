import express from 'express';
import mongoose from 'mongoose';
import cors from 'cors';
import dotenv from 'dotenv';
import axios from 'axios';
import productRoutes from './routes/productRoutes.js';
import orderRoutes from './routes/orderRoutes.js';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(express.json());

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/hearth_heal_shop')
  .then(() => console.log('✅ MongoDB Connected'))
  .catch(err => console.error('❌ MongoDB Error:', err));

// Routes
app.use('/api/products', productRoutes);
app.use('/api/orders', orderRoutes);

// M-Pesa STK Push
app.post('/api/payments/mpesa', async (req, res) => {
  try {
    const { phone, amount, orderId } = req.body;
    
    // TODO: Implement M-Pesa STK Push
    // This is a placeholder - you'll need to integrate with Safaricom API
    
    res.json({ 
      message: 'M-Pesa STK Push initiated',
      phone,
      amount,
      orderId,
      status: 'pending'
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`📦 API ready at http://localhost:${PORT}/api`);
});
