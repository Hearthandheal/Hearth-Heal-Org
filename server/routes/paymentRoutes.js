import express from "express";
import axios from "axios";
import Order from "../models/Order.js";

const router = express.Router();

// Generate timestamp in YYYYMMDDHHMMSS format
const getTimestamp = () => {
  const now = new Date();
  return now.getFullYear() +
    String(now.getMonth() + 1).padStart(2, '0') +
    String(now.getDate()).padStart(2, '0') +
    String(now.getHours()).padStart(2, '0') +
    String(now.getMinutes()).padStart(2, '0') +
    String(now.getSeconds()).padStart(2, '0');
};

// Generate M-Pesa password
const getPassword = (shortcode, passkey, timestamp) => {
  const str = shortcode + passkey + timestamp;
  return Buffer.from(str).toString('base64');
};

router.post("/stk", async (req, res) => {
  const { phone, amount, orderId } = req.body;

  // Validation
  if (!phone) {
    return res.status(400).json({ error: "Phone number is required" });
  }
  if (!amount || amount <= 0) {
    return res.status(400).json({ error: "Valid amount is required" });
  }

  // Validate phone format (must be 12 digits starting with 254)
  if (!phone.match(/^254\d{9}$/)) {
    return res.status(400).json({ error: "Phone must be in format 254XXXXXXXXX" });
  }

  try {
    // 1. Get Access Token
    if (!process.env.MPESA_CONSUMER_KEY || !process.env.MPESA_CONSUMER_SECRET) {
      return res.status(500).json({ error: "M-Pesa credentials not configured" });
    }

    const auth = Buffer.from(
      process.env.MPESA_CONSUMER_KEY + ":" + process.env.MPESA_CONSUMER_SECRET
    ).toString("base64");

    const tokenRes = await axios.get(
      "https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials",
      {
        headers: { Authorization: `Basic ${auth}` },
      }
    );

    const token = tokenRes.data.access_token;
    const timestamp = getTimestamp();
    const password = getPassword(process.env.MPESA_SHORTCODE, process.env.MPESA_PASSKEY, timestamp);

    // 2. STK Push
    const stkRes = await axios.post(
      "https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest",
      {
        BusinessShortCode: process.env.MPESA_SHORTCODE,
        Password: password,
        Timestamp: timestamp,
        TransactionType: "CustomerPayBillOnline",
        Amount: amount,
        PartyA: phone,
        PartyB: process.env.MPESA_SHORTCODE,
        PhoneNumber: phone,
        CallBackURL: process.env.MPESA_CALLBACK_URL,
        AccountReference: req.body.orderId || "Hearth&Heal",
        TransactionDesc: "Payment",
      },
      {
        headers: { Authorization: `Bearer ${token}` },
      }
    );

    res.json(stkRes.data);
  } catch (err) {
    console.error("M-Pesa Error:", err.response?.data || err.message);
    res.status(500).json({ error: err.response?.data || err.message });
  }
});

// M-Pesa Callback
router.post("/callback", async (req, res) => {
  try {
    console.log("M-Pesa callback received:", JSON.stringify(req.body, null, 2));

    const data = req.body;

    // Check if callback has the expected structure
    if (!data.Body || !data.Body.stkCallback) {
      console.error("Invalid callback structure");
      return res.json({ ResultCode: 0, ResultDesc: "Received" });
    }

    // Extract payment result
    const resultCode = data.Body.stkCallback.ResultCode;
    const checkoutRequestID = data.Body.stkCallback.CheckoutRequestID;
    const resultDesc = data.Body.stkCallback.ResultDesc;

    // Get orderId from AccountReference (passed during STK push)
    const callbackMetadata = data.Body.stkCallback.CallbackMetadata?.Item || [];
    const orderId = callbackMetadata.find(i => i.Name === "AccountReference")?.Value;
    const mpesaReceipt = callbackMetadata.find(i => i.Name === "MpesaReceiptNumber")?.Value;
    const transactionDate = callbackMetadata.find(i => i.Name === "TransactionDate")?.Value;
    const amount = callbackMetadata.find(i => i.Name === "Amount")?.Value;

    if (!orderId) {
      console.log("No orderId found in callback");
      return res.json({ ResultCode: 0, ResultDesc: "Received" });
    }

    if (resultCode === 0) {
      // SUCCESS
      console.log("✓ Payment successful:", {
        checkoutRequestID,
        orderId,
        mpesaReceipt,
        amount,
        transactionDate
      });

      await Order.findByIdAndUpdate(orderId, {
        status: "paid",
        mpesaReceipt: mpesaReceipt || null,
        checkoutRequestID: checkoutRequestID,
        transactionDate: transactionDate ? new Date(transactionDate) : null,
      });

      console.log("✓ Order marked as paid:", orderId);
    } else {
      // FAILED
      console.log("✗ Payment failed:", {
        resultCode,
        resultDesc,
        orderId
      });

      await Order.findByIdAndUpdate(orderId, {
        status: "failed",
        checkoutRequestID: checkoutRequestID,
      });

      console.log("✓ Order marked as failed:", orderId);
    }

    res.json({ ResultCode: 0, ResultDesc: "Success" });
  } catch (err) {
    console.error("Callback error:", err.message);
    res.json({ ResultCode: 0, ResultDesc: "Received" });
  }
});

export default router;
