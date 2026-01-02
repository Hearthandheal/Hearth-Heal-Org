/**
 * Bank-style payment system (Node.js, Express)
 * Features: Secure invoice creation, payment orchestration, webhooks, reconciliation, logging
 * Security: Helmet, rate limiting, input validation, webhook signature verification, idempotency
 * Storage: In-memory Maps for demo (replace with DB: Postgres/MySQL)
 */

require("dotenv").config();
const express = require("express");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const cors = require("cors");
const crypto = require("crypto");
const cron = require("node-cron");
const winston = require("winston");

const app = express();

/* ----------------------------- Logging setup ----------------------------- */
const logger = winston.createLogger({
    level: "info",
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
    ),
    transports: [new winston.transports.Console()]
});

/* ----------------------------- Security setup ---------------------------- */
app.use(helmet());
app.use(cors({ origin: true }));
app.use(express.json({ limit: "1mb" }));
app.disable("x-powered-by");

const limiter = rateLimit({
    windowMs: 10 * 60 * 1000,
    max: 300, // tune per needs
    standardHeaders: true,
    legacyHeaders: false
});
app.use(limiter);

/* ----------------------------- In-memory store --------------------------- */
// Replace with DB tables: invoices, payments, transactions, receipts, audit_logs
const store = {
    invoices: new Map(),     // key: reference_number -> invoice object
    payments: new Map(),     // key: payment_id -> payment attempt
    transactions: new Map(), // key: txn_id -> transaction detail
    receipts: new Map(),     // key: receipt_serial -> receipt detail
    audit: [],               // append-only audit events
    otps: new Map()          // key: identifier (email/phone) -> { code, expiresAt }
};

/* ----------------------------- Helpers ---------------------------------- */
const ENV = {
    PORT: process.env.PORT || 3000,
    BASE_URL: process.env.BASE_URL || "http://localhost:3000",
    STRIPE_PUBLISHABLE_KEY: process.env.STRIPE_PUBLISHABLE_KEY || "",
    STRIPE_SECRET_KEY: process.env.STRIPE_SECRET_KEY || "",
    STRIPE_WEBHOOK_SECRET: process.env.STRIPE_WEBHOOK_SECRET || "",
    MPESA_CONSUMER_KEY: process.env.MPESA_CONSUMER_KEY || "",
    MPESA_CONSUMER_SECRET: process.env.MPESA_CONSUMER_SECRET || "",
    MPESA_PASSKEY: process.env.MPESA_PASSKEY || "",
    MPESA_SHORTCODE: process.env.MPESA_SHORTCODE || "",
    MPESA_CALLBACK_URL: process.env.MPESA_CALLBACK_URL || "",
    WEBHOOK_SHARED_SECRET: process.env.WEBHOOK_SHARED_SECRET || "change_me",
    OTP_EXPIRY_MS: 5 * 60 * 1000 // 5 minutes
};

function newRef() {
    return "ECZ-" + Date.now() + "-" + Math.floor(Math.random() * 999999);
}
function now() { return new Date().toISOString(); }

function audit(action, payload = {}) {
    const event = { time: now(), action, payload };
    store.audit.push(event);
    logger.info({ audit: event });
}

function hmacSha256Hex(secret, payloadString) {
    return crypto.createHmac("sha256", secret).update(payloadString).digest("hex");
}

function isPositiveAmount(val) {
    return typeof val === "number" && isFinite(val) && val > 0;
}

function issueReceipt(invoice) {
    const serial = "R-" + Date.now() + "-" + Math.floor(Math.random() * 999999);
    const receipt = {
        serial,
        invoice_ref: invoice.reference_number,
        amount: invoice.amount,
        currency: invoice.currency,
        issued_at: now(),
        customer_id: invoice.customer_id
    };
    store.receipts.set(serial, receipt);
    return receipt;
}

/* ----------------------------- Auth/OTP API ----------------------------- */

// Request OTP
app.post("/auth/otp/request", (req, res) => {
    try {
        const { identifier, type } = req.body; // type: 'email' | 'phone'
        if (!identifier || !type) return res.status(400).json({ error: "Missing identifier or type" });

        // Generate 6-digit code
        const code = Math.floor(100000 + Math.random() * 900000).toString();
        const expiresAt = Date.now() + ENV.OTP_EXPIRY_MS;

        store.otps.set(identifier, { code, expiresAt });

        // In production, send via Email (e.g. SendGrid) or SMS (e.g. Twilio/Infobip)
        // For demo/dev, we log it to console.
        logger.info({ msg: "OTP GENERATED", identifier, code });
        console.log(`[MOCK OTP] Sent to ${identifier}: ${code}`);

        audit("OTP_REQUESTED", { identifier, type });
        res.json({ message: "OTP sent successfully" });
    } catch (err) {
        logger.error({ err });
        res.status(500).json({ error: "Server error" });
    }
});

// Verify OTP
app.post("/auth/otp/verify", (req, res) => {
    try {
        const { identifier, code } = req.body;
        if (!identifier || !code) return res.status(400).json({ error: "Missing identifier or code" });

        const record = store.otps.get(identifier);
        if (!record) return res.status(400).json({ error: "Invalid or expired OTP" });

        if (Date.now() > record.expiresAt) {
            store.otps.delete(identifier);
            return res.status(400).json({ error: "OTP expired" });
        }

        if (record.code !== code) {
            return res.status(400).json({ error: "Invalid code" });
        }

        // Success
        store.otps.delete(identifier); // consume OTP
        audit("OTP_VERIFIED", { identifier });

        // Return a session token or user object (Mock)
        res.json({ success: true, user: { identifier, name: identifier.split('@')[0] || identifier } });

    } catch (err) {
        logger.error({ err });
        res.status(500).json({ error: "Server error" });
    }
});

/* ----------------------------- Invoice API ------------------------------- */
// Create invoice
app.post("/invoices", (req, res) => {
    try {
        const { customerId, amount, currency = "KES", description = "" } = req.body;
        if (!customerId || !isPositiveAmount(amount)) {
            return res.status(400).json({ error: "Invalid customerId or amount" });
        }
        const ref = newRef();
        const invoice = {
            id: crypto.randomUUID(),
            reference_number: ref,
            customer_id: String(customerId),
            amount: Number(amount),
            currency: String(currency).toUpperCase(),
            description: String(description || ""),
            status: "PENDING",
            created_at: now(),
            expires_at: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString()
        };
        store.invoices.set(ref, invoice);
        audit("INVOICE_CREATED", { reference_number: ref, amount: amount, currency });
        res.json(invoice);
    } catch (err) {
        logger.error({ err });
        res.status(500).json({ error: "Server error" });
    }
});

// Get invoice status
app.get("/invoices/:ref", (req, res) => {
    const invoice = store.invoices.get(req.params.ref);
    if (!invoice) return res.status(404).json({ error: "Not found" });
    res.json(invoice);
});

/* ----------------------------- Payment Orchestration --------------------- */
// Start payment attempt (channel: "card" | "bank" | "mpesa")
app.post("/payments", (req, res) => {
    try {
        const { reference_number, channel } = req.body;
        const invoice = store.invoices.get(reference_number);
        if (!invoice) return res.status(404).json({ error: "Invoice not found" });
        if (invoice.status !== "PENDING") {
            return res.status(409).json({ error: "Invoice not payable" });
        }
        const paymentId = crypto.randomUUID();
        const payment = {
            id: paymentId,
            invoice_id: invoice.id,
            invoice_ref: reference_number,
            channel,
            status: "INITIATED",
            initiated_at: now()
        };
        store.payments.set(paymentId, payment);
        audit("PAYMENT_INITIATED", { payment_id: paymentId, channel, reference_number });

        // Simulate channel routing:
        if (channel === "card") {
            // Redirect to your card gateway checkout (replace with real URL)
            const checkoutUrl = `${ENV.BASE_URL}/demo/redirect?ref=${reference_number}&amount=${invoice.amount}`;
            return res.json({ payment_id: paymentId, redirect_url: checkoutUrl });
        } else if (channel === "mpesa") {
            // STK Push trigger (stub)
            // For this demo, we auto-mark as PAID after 10 seconds to simulate user completing payment
            setTimeout(() => {
                if (invoice.status === "PENDING") {
                    invoice.status = "PAID";
                    invoice.paid_at = now();
                    const receipt = issueReceipt(invoice);
                    audit("AUTO_PAID_SIMULATION", { reference_number, receipt_serial: receipt.serial });
                }
            }, 10000);

            return res.json({
                payment_id: paymentId,
                message: "M-Pesa STK Push initiated. Check your phone to approve.",
                invoice_ref: reference_number
            });
        } else if (channel === "bank") {
            // Bank/virtual account flow (stub)
            const virtualAccount = "VA-" + Math.floor(Math.random() * 999999);
            return res.json({
                payment_id: paymentId,
                message: "Use the virtual account/reference to pay via bank transfer.",
                virtual_account: virtualAccount,
                amount: invoice.amount,
                reference_number
            });
        } else {
            return res.status(400).json({ error: "Unsupported channel" });
        }
    } catch (err) {
        logger.error({ err });
        res.status(500).json({ error: "Server error" });
    }
});

/* ----------------------------- Webhooks --------------------------------- */
/**
 * Card/Bank-like webhook:
 * - Expects body: { reference_number, status: "SUCCESS"|"FAILED", provider_txn_id, amount }
 * - Validates HMAC signature in header: x-signature = HMAC_SHA256(secret, JSON.stringify(body))
 * - Idempotent: only mark paid once
 */
app.post("/webhooks/bank", (req, res) => {
    try {
        const sig = req.headers["x-signature"];
        const payloadStr = JSON.stringify(req.body);
        const expected = hmacSha256Hex(ENV.WEBHOOK_SHARED_SECRET, payloadStr);
        if (sig !== expected) {
            audit("WEBHOOK_REJECTED", { reason: "invalid_signature" });
            return res.status(401).json({ error: "Invalid signature" });
        }

        const { reference_number, status, provider_txn_id, amount } = req.body;
        const invoice = store.invoices.get(reference_number);
        if (!invoice) return res.status(404).end();

        audit("WEBHOOK_RECEIVED", { channel: "bank", reference_number, status });

        if (status === "SUCCESS" && invoice.status !== "PAID") {
            // Basic amount check
            if (Number(amount) !== Number(invoice.amount)) {
                audit("AMOUNT_MISMATCH", { reference_number, expected: invoice.amount, got: amount });
                // Depending on policy, mark as REVIEW or reject
            }
            invoice.status = "PAID";
            invoice.paid_at = now();
            const receipt = issueReceipt(invoice);
            audit("RECEIPT_ISSUED", { receipt_serial: receipt.serial, reference_number });
        } else if (status === "FAILED") {
            invoice.status = "FAILED";
        }

        res.status(200).end();
    } catch (err) {
        logger.error({ err });
        res.status(500).end();
    }
});

/**
 * M-Pesa webhook (Daraja STK callback format varies; this is a simplified handler)
 * In production: validate origin/signature per provider docs.
 */
app.post("/webhooks/mpesa", (req, res) => {
    try {
        // Assume payload: { Body: { stkCallback: { ResultCode, CallbackMetadata: { Item: [{Name, Value}...] } } } }
        const body = req.body?.Body?.stkCallback;
        audit("WEBHOOK_RECEIVED", { channel: "mpesa", raw: !!body });

        if (!body) return res.status(400).end();

        const resultCode = body.ResultCode;
        const items = body.CallbackMetadata?.Item || [];
        const refItem = items.find(i => i.Name === "AccountReference");
        const amountItem = items.find(i => i.Name === "Amount");
        const ref = refItem?.Value;
        const amount = amountItem?.Value;

        const invoice = store.invoices.get(ref);
        if (!invoice) return res.status(404).end();

        if (resultCode === 0 && invoice.status !== "PAID") {
            invoice.status = "PAID";
            invoice.paid_at = now();
            const receipt = issueReceipt(invoice);
            audit("RECEIPT_ISSUED", { receipt_serial: receipt.serial, reference_number: ref, amount });
        } else if (resultCode !== 0) {
            invoice.status = "FAILED";
        }

        res.status(200).end();
    } catch (err) {
        logger.error({ err });
        res.status(500).end();
    }
});

/* ----------------------------- Receipts & Status ------------------------- */
app.get("/receipts/:serial", (req, res) => {
    const receipt = store.receipts.get(req.params.serial);
    if (!receipt) return res.status(404).json({ error: "Not found" });
    res.json(receipt);
});

/* ----------------------------- Reconciliation Job ----------------------- */
/**
 * Nightly reconciliation:
 * - Pull settlement reports from providers (stubbed)
 * - Cross-check invoices marked PAID against settlement lines
 * - Flag mismatches for manual review
 */
cron.schedule("0 2 * * *", async () => {
    try {
        audit("RECONCILIATION_START", {});
        // Stub: simulate settlement data
        const settlementRefs = Array.from(store.invoices.values())
            .filter(inv => inv.status === "PAID")
            .map(inv => inv.reference_number);

        // Check each paid invoice is present in settlement
        for (const inv of store.invoices.values()) {
            if (inv.status === "PAID") {
                const found = settlementRefs.includes(inv.reference_number);
                if (!found) {
                    audit("RECON_FLAG_MISSING", { reference_number: inv.reference_number });
                }
            }
        }
        audit("RECONCILIATION_COMPLETE", {});
    } catch (err) {
        logger.error({ err });
        audit("RECONCILIATION_ERROR", { error: String(err) });
    }
});

/* ----------------------------- Demo endpoints ---------------------------- */
// Simple demo redirect landing
app.get("/demo/redirect", (req, res) => {
    res.send("Demo checkout landing. In production, redirect to your gateway UI.");
});

/* ----------------------------- Error handling ---------------------------- */
app.use((err, req, res, next) => {
    logger.error({ err });
    res.status(500).json({ error: "Unexpected error" });
});

/* ----------------------------- Start server ------------------------------ */
app.listen(ENV.PORT, () => {
    logger.info({ msg: `Server running on port ${ENV.PORT}` });
});
