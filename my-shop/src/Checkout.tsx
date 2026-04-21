import { useState, useEffect } from "react";
import axios from "axios";
import { useNavigate } from "react-router-dom";

const API_URL = "https://hearth-heal-api.onrender.com/api";

interface CartItem {
  _id: string;
  name: string;
  price: number;
}

export default function Checkout() {
  const navigate = useNavigate();
  const [cart, setCart] = useState<CartItem[]>([]);
  const [loading, setLoading] = useState(false);
  const [form, setForm] = useState({
    name: "",
    email: "",
    phone: "",
    city: "",
    address: "",
  });
  const [paymentMethod, setPaymentMethod] = useState("mpesa");

  useEffect(() => {
    const saved = localStorage.getItem('cart');
    if (saved) {
      setCart(JSON.parse(saved));
    }
  }, []);

  const total = cart.reduce((sum, item) => sum + item.price, 0);
  const shipping = 0;
  const grandTotal = total + shipping;

  const formatPhone = (value: string) => {
    let v = value.replace(/\D/g, "");
    if (v.startsWith("0")) v = "254" + v.slice(1);
    if (!v.startsWith("254")) v = "254" + v;
    return v.slice(0, 12);
  };

  const handlePay = async () => {
    if (!form.phone || form.phone.length < 12) {
      return alert("Enter a valid Kenyan phone number (2547XXXXXXXX)");
    }
    if (cart.length === 0) return alert("Your cart is empty");

    setLoading(true);
    try {
      const orderRes = await axios.post(`${API_URL}/orders`, {
        ...form,
        products: cart,
        amount: grandTotal,
      });

      await axios.post(`${API_URL}/payments/stk`, {
        phone: form.phone,
        amount: grandTotal,
        orderId: orderRes.data._id,
      });

      localStorage.removeItem('cart');
      setCart([]);
      navigate("/success");
    } catch (err: any) {
      alert("Error: " + (err.response?.data?.error || err.message));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ 
      fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto',
      background: '#0a0a0a', 
      minHeight: '100vh',
      padding: '40px 20px'
    }}>
      <div style={{ maxWidth: '1100px', margin: 'auto' }}>
        <h2 style={{ 
          color: 'white', 
          marginBottom: '20px',
          fontSize: '28px',
          fontWeight: 600
        }}>
          Checkout
        </h2>

        <div style={{ 
          display: 'grid', 
          gridTemplateColumns: '2fr 1fr', 
          gap: '30px'
        }}>
          {/* LEFT SIDE */}
          <div>
            {/* Shipping Details */}
            <div style={{
              background: 'rgba(20, 20, 20, 0.9)',
              padding: '25px',
              borderRadius: '16px',
              border: '1px solid rgba(255,255,255,0.1)',
              marginBottom: '20px'
            }}>
              <h3 style={{ color: 'white', margin: '0 0 20px 0' }}>Shipping Details</h3>

              <input
                type="text"
                placeholder="Full Name"
                value={form.name}
                onChange={(e) => setForm({ ...form, name: e.target.value })}
                style={{
                  width: '100%',
                  padding: '14px',
                  marginTop: '10px',
                  marginBottom: '20px',
                  borderRadius: '10px',
                  border: '1px solid #333',
                  background: '#1a1a1a',
                  color: 'white',
                  fontSize: '14px',
                  outline: 'none'
                }}
              />

              <input
                type="email"
                placeholder="Email Address"
                value={form.email}
                onChange={(e) => setForm({ ...form, email: e.target.value })}
                style={{
                  width: '100%',
                  padding: '14px',
                  marginTop: '10px',
                  marginBottom: '20px',
                  borderRadius: '10px',
                  border: '1px solid #333',
                  background: '#1a1a1a',
                  color: 'white',
                  fontSize: '14px',
                  outline: 'none'
                }}
              />

              <div style={{ display: 'flex', gap: '15px' }}>
                <input
                  type="text"
                  placeholder="Phone (2547XXXXXXXX)"
                  value={form.phone}
                  onChange={(e) => setForm({ ...form, phone: formatPhone(e.target.value) })}
                  style={{
                    flex: 1,
                    padding: '14px',
                    marginTop: '10px',
                    marginBottom: '20px',
                    borderRadius: '10px',
                    border: '1px solid #333',
                    background: '#1a1a1a',
                    color: 'white',
                    fontSize: '14px',
                    outline: 'none'
                  }}
                />
                <input
                  type="text"
                  placeholder="City"
                  value={form.city}
                  onChange={(e) => setForm({ ...form, city: e.target.value })}
                  style={{
                    flex: 1,
                    padding: '14px',
                    marginTop: '10px',
                    marginBottom: '20px',
                    borderRadius: '10px',
                    border: '1px solid #333',
                    background: '#1a1a1a',
                    color: 'white',
                    fontSize: '14px',
                    outline: 'none'
                  }}
                />
              </div>

              <input
                type="text"
                placeholder="Delivery Address"
                value={form.address}
                onChange={(e) => setForm({ ...form, address: e.target.value })}
                style={{
                  width: '100%',
                  padding: '14px',
                  marginTop: '10px',
                  marginBottom: '20px',
                  borderRadius: '10px',
                  border: '1px solid #333',
                  background: '#1a1a1a',
                  color: 'white',
                  fontSize: '14px',
                  outline: 'none'
                }}
              />
            </div>

            {/* Payment Method */}
            <div style={{
              background: 'rgba(20, 20, 20, 0.9)',
              padding: '25px',
              borderRadius: '16px',
              border: '1px solid rgba(255,255,255,0.1)'
            }}>
              <h3 style={{ color: 'white', margin: '0 0 20px 0' }}>Payment Method</h3>

              <label style={{
                display: 'flex',
                alignItems: 'center',
                gap: '10px',
                marginBottom: '15px',
                cursor: 'pointer',
                color: '#aaa'
              }}>
                <input
                  type="radio"
                  name="payment"
                  value="mpesa"
                  checked={paymentMethod === "mpesa"}
                  onChange={(e) => setPaymentMethod(e.target.value)}
                  style={{ width: 'auto' }}
                />
                M-Pesa
              </label>

              <label style={{
                display: 'flex',
                alignItems: 'center',
                gap: '10px',
                marginBottom: '15px',
                cursor: 'pointer',
                color: '#aaa'
              }}>
                <input
                  type="radio"
                  name="payment"
                  value="card"
                  checked={paymentMethod === "card"}
                  onChange={(e) => setPaymentMethod(e.target.value)}
                  style={{ width: 'auto' }}
                />
                Credit / Debit Card (Coming Soon)
              </label>

              <label style={{
                display: 'flex',
                alignItems: 'center',
                gap: '10px',
                marginBottom: '15px',
                cursor: 'pointer',
                color: '#aaa'
              }}>
                <input
                  type="radio"
                  name="payment"
                  value="paypal"
                  checked={paymentMethod === "paypal"}
                  onChange={(e) => setPaymentMethod(e.target.value)}
                  style={{ width: 'auto' }}
                />
                PayPal (Coming Soon)
              </label>
            </div>
          </div>

          {/* RIGHT SIDE - Order Summary */}
          <div style={{
            background: 'rgba(20, 20, 20, 0.9)',
            padding: '25px',
            borderRadius: '16px',
            border: '1px solid rgba(255,255,255,0.1)',
            height: 'fit-content'
          }}>
            <h3 style={{ color: 'white', margin: '0 0 20px 0' }}>Order Summary</h3>

            <div>
              {cart.map((item, i) => (
                <div key={i} style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  marginBottom: '15px',
                  color: '#aaa'
                }}>
                  <span>{item.name}</span>
                  <span>KES {item.price}</span>
                </div>
              ))}
            </div>

            <div style={{
              display: 'flex',
              justifyContent: 'space-between',
              marginBottom: '15px',
              color: '#aaa'
            }}>
              <span>Shipping</span>
              <span>{shipping === 0 ? 'Calculated at checkout' : `KES ${shipping}`}</span>
            </div>

            <hr style={{ border: 'none', borderTop: '1px solid #333', margin: '20px 0' }} />

            <div style={{
              display: 'flex',
              justifyContent: 'space-between',
              fontSize: '18px',
              fontWeight: 'bold',
              color: 'white'
            }}>
              <span>Total</span>
              <span>KES {grandTotal}</span>
            </div>

            <button
              onClick={handlePay}
              disabled={loading}
              style={{
                width: '100%',
                padding: '16px',
                border: 'none',
                borderRadius: '12px',
                background: loading ? '#333' : '#39ff14',
                color: loading ? '#666' : 'black',
                fontSize: '16px',
                fontWeight: 600,
                cursor: loading ? 'not-allowed' : 'pointer',
                transition: '0.3s',
                marginTop: '20px'
              }}
            >
              {loading ? "Processing..." : "Complete Purchase"}
            </button>
          </div>

        </div>
      </div>
    </div>
  );
}
