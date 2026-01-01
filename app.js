require('dotenv').config();
const express = require("express");
const crypto = require("crypto");
const cors = require("cors");

const app = express();
app.use(cors());
app.use(express.json());

// In-memory demo store (replace with DB in production)
const store = { invoices: new Map(), payments: new Map() };

function newRef() {
    return "ECZ-" + Date.now() + "-" + Math.floor(Math.random() * 9999);
}

// --- Invoices ---

// Create invoice
app.post("/invoices", (req, res) => {
    const { customerId, amount, currency = "KES", items } = req.body; // Added items for context if needed
    const ref = newRef();
    const invoice = {
        id: crypto.randomUUID(),
        reference_number: ref,
        customer_id: customerId,
        amount,
        currency,
        items, // Store items
        status: "PENDING",
        created_at: Date.now(),
        expires_at: Date.now() + 24 * 60 * 60 * 1000
    };
    store.invoices.set(ref, invoice);
    res.json(invoice);
});

// Check invoice status
app.get("/invoices/:ref", (req, res) => {
    const invoice = store.invoices.get(req.params.ref);
    if (!invoice) return res.status(404).json({ error: "Not found" });
    res.json(invoice);
});


// --- Payments ---

// Helper: M-Pesa STK Push (Mock implementation)
async function mpesaStkPush({ phoneNumber, amount, reference_number }) {
    console.log(`[Mock STK Push] Sending ${amount} request to ${phoneNumber} for ref ${reference_number}`);
    // In real life:
    // 1) Obtain OAuth token
    // 2) Generate Password
    // 3) POST to /stkpush

    // Simulate Webhook callback after a delay
    setTimeout(() => {
        console.log(`[Mock STK Push] Simulating user payment for ${reference_number}`);
        const invoice = store.invoices.get(reference_number);
        if (invoice) {
            invoice.status = "PAID";
            invoice.paid_at = Date.now();
            invoice.receipt_serial = "R-" + Date.now();
        }
    }, 10000); // 10 seconds delay

    return { request_id: "stk-" + Date.now() };
}

// Start payment
app.post("/payments", async (req, res) => {
    const { reference_number, channel, phoneNumber } = req.body; // Added phoneNumber for M-Pesa
    const invoice = store.invoices.get(reference_number);
    if (!invoice) return res.status(404).json({ error: "Invoice not found" });

    // Create a payment attempt
    const paymentId = crypto.randomUUID();
    const payment = {
        id: paymentId,
        invoice_id: invoice.id,
        channel,
        status: "INITIATED",
        initiated_at: Date.now()
    };
    store.payments.set(paymentId, payment);

    let responseData = { payment_id: paymentId, status: "INITIATED" };

    if (channel === 'mpesa') {
        if (!phoneNumber) return res.status(400).json({ error: "Phone number required for M-Pesa" });
        const stk = await mpesaStkPush({
            phoneNumber,
            amount: invoice.amount,
            reference_number
        });
        responseData.message = "STK Push sent to phone.";
        responseData.provider_ref = stk.request_id;
    } else {
        // Generic Redirect
        responseData.redirect_url = `https://gateway.example/checkout?ref=${reference_number}&amount=${invoice.amount}`;
    }

    res.json(responseData);
});


// --- Webhooks ---

// Signature Verification
function verifySignature(req, secret) {
    // If no secret is set in env, skip verification (dev mode) or fail safely. 
    // For this demo, if secret is missing, we might match undefined or skip.
    if (!secret) {
        console.warn("No Webhook Secret configured. Skipping signature check.");
        return true;
    }
    const signature = req.headers["x-signature"];
    if (!signature) return false;

    const payload = JSON.stringify(req.body);
    const expected = crypto.createHmac("sha256", secret).update(payload).digest("hex");
    return signature === expected;
}

// M-Pesa Webhook
app.post("/webhooks/mpesa", (req, res) => {
    if (!verifySignature(req, process.env.MPESA_SECRET)) {
        console.error("Invalid M-Pesa signature");
        return res.status(401).send("Invalid signature");
    }

    const { Body } = req.body;
    const ref = Body?.stkCallback?.CallbackMetadata?.Item?.find(i => i.Name === "AccountReference")?.Value;
    const resultCode = Body?.stkCallback?.ResultCode;

    console.log(`[Webhook] M-Pesa callback for ${ref}, code: ${resultCode}`);

    const invoice = store.invoices.get(ref);
    if (invoice) {
        if (resultCode === 0) {
            invoice.status = "PAID";
            invoice.paid_at = Date.now();
            invoice.receipt_serial = "R-" + Date.now();
        } else {
            invoice.status = "FAILED";
        }
    }
    res.status(200).end();
});

// Card/Generic Webhook
app.post("/webhooks/card", (req, res) => {
    const { reference_number, status } = req.body;

    const invoice = store.invoices.get(reference_number);
    if (!invoice) return res.status(404).end();

    if (status === "SUCCESS" && invoice.status !== "PAID") {
        invoice.status = "PAID";
        invoice.paid_at = Date.now();
        invoice.receipt_serial = "R-" + Date.now();
    }
    if (status === "FAILED") {
        invoice.status = "FAILED";
    }

    res.status(200).end();
});


const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Payment server running on port ${PORT}`));
