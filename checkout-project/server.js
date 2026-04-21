const express = require("express");
const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY || "YOUR_STRIPE_SECRET_KEY");
const cors = require("cors");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// CREATE PAYMENT INTENT (Stripe)
app.post("/create-payment-intent", async (req, res) => {
    try {
        const { amount } = req.body;

        const paymentIntent = await stripe.paymentIntents.create({
            amount: amount * 100, // Convert to cents
            currency: "usd",
            payment_method_types: ["card"]
        });

        res.send({
            clientSecret: paymentIntent.client_secret
        });
    } catch (error) {
        res.status(500).send(error.message);
    }
});

// M-PESA STK PUSH
app.post("/mpesa-pay", async (req, res) => {
    const { phone, amount } = req.body;

    // TODO: Replace with real Daraja API logic
    console.log(`Initiating M-Pesa payment for ${phone} amount ${amount}`);

    res.send({ message: "M-Pesa STK Push sent (mock)" });
});

app.listen(PORT, () => {
  console.log(`Checkout server running on port ${PORT}`);
});
