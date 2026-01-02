/**
 * Hearth & Heal - Secure Backend
 * Logic: Email verification signup, 2FA OTP login, M-Pesa payments
 * Security: DB Persistence, Bcrypt Hashing, Rate Limiting, JWT Rotation, Helmet
 */

require("dotenv").config();
const express = require("express");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const cors = require("cors");
const crypto = require("crypto");
const cron = require("node-cron");
const winston = require("winston");
const nodemailer = require("nodemailer");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const db = require("./db");

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
    max: 300,
    standardHeaders: true,
    legacyHeaders: false
});
app.use(limiter);

/* ----------------------------- Database init --------------------------- */
db.initDb()
    .then(() => logger.info("Database initialized"))
    .catch(err => logger.error("DB Init failed", err));

/* ----------------------------- Helpers ---------------------------------- */
const ENV = {
    PORT: process.env.PORT || 3000,
    BASE_URL: process.env.BASE_URL || "http://localhost:3000",
    EMAIL_USER: process.env.EMAIL_USER,
    EMAIL_PASS: process.env.EMAIL_PASS,
    JWT_SECRETS: (process.env.JWT_SECRET || "default_h&h_secret").split(","),
    OTP_EXPIRY_MS: 5 * 60 * 1000,
    WEBHOOK_SHARED_SECRET: process.env.WEBHOOK_SHARED_SECRET || "change_me"
};

function now() { return new Date().toISOString(); }

function audit(action, payload = {}) {
    logger.info({ audit: { time: now(), action, payload } });
}

function hmacSha256Hex(secret, payloadString) {
    return crypto.createHmac("sha256", secret).update(payloadString).digest("hex");
}

function generateOtp() {
    return Math.floor(100000 + Math.random() * 900000).toString();
}

async function sendEmail(email, subject, text) {
    if (!ENV.EMAIL_USER || !ENV.EMAIL_PASS) {
        logger.warn("Email credentials missing, skipping email send.");
        return;
    }
    const transporter = nodemailer.createTransport({
        service: "gmail",
        auth: { user: ENV.EMAIL_USER, pass: ENV.EMAIL_PASS }
    });
    await transporter.sendMail({
        from: `Hearth & Heal <${ENV.EMAIL_USER}>`,
        to: email, subject, text
    });
}

function signJwt(payload) {
    return jwt.sign(payload, ENV.JWT_SECRETS[0], { expiresIn: "2h" });
}

function verifyJwt(token) {
    for (const secret of ENV.JWT_SECRETS) {
        try { return jwt.verify(token, secret); } catch (e) { continue; }
    }
    throw new Error("Invalid token");
}

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    message: { error: "Too many attempts. Please try again later." }
});

/* ----------------------------- Auth API ----------------------------- */

app.post("/request-verification", authLimiter, async (req, res) => {
    try {
        const { email } = req.body;
        if (!email) return res.status(400).json({ error: "Email required" });

        const code = generateOtp();
        const ref = crypto.randomUUID();
        const codeHash = bcrypt.hashSync(code, 8);

        await db.run(
            `INSERT INTO verifications (ref, code_hash, identifier, expires_at) VALUES (?, ?, ?, ?)`,
            [ref, codeHash, email, Date.now() + 10 * 60 * 1000]
        );

        await sendEmail(email, "Verify Your Email", `Your code is ${code}. It expires in 10 minutes.`);
        res.json({ ref, message: "Verification code sent" });
    } catch (err) {
        logger.error({ err });
        res.status(500).json({ error: "Server error" });
    }
});

app.post("/verify-email", authLimiter, async (req, res) => {
    try {
        const { ref, code, password } = req.body;
        const records = await db.query(`SELECT * FROM verifications WHERE ref = ?`, [ref]);
        const record = records[0];

        if (!record || Date.now() > record.expires_at) return res.status(400).json({ error: "Invalid or expired code" });
        if (!bcrypt.compareSync(code, record.code_hash)) return res.status(400).json({ error: "Invalid code" });

        const passwordHash = bcrypt.hashSync(password, 10);
        await db.run(
            `INSERT INTO users (identifier, password_hash, verified) VALUES (?, ?, TRUE) 
             ON CONFLICT(identifier) DO UPDATE SET password_hash = ?, verified = TRUE`,
            [record.identifier, passwordHash, passwordHash]
        );
        await db.run(`DELETE FROM verifications WHERE ref = ?`, [ref]);

        res.json({ success: true, message: "Account created" });
    } catch (err) {
        logger.error({ err });
        res.status(500).json({ error: "Server error" });
    }
});

app.post("/login", authLimiter, async (req, res) => {
    try {
        const { email, password } = req.body;
        const users = await db.query(`SELECT * FROM users WHERE identifier = ? AND verified = TRUE`, [email]);
        const user = users[0];

        if (!user || !bcrypt.compareSync(password, user.password_hash)) {
            return res.status(400).json({ error: "Invalid credentials" });
        }

        const otp = generateOtp();
        const ref = crypto.randomUUID();
        const otpHash = bcrypt.hashSync(otp, 8);

        await db.run(
            `INSERT INTO otps (ref, otp_hash, identifier, expires_at) VALUES (?, ?, ?, ?)`,
            [ref, otpHash, email, Date.now() + ENV.OTP_EXPIRY_MS]
        );

        await sendEmail(email, "Login OTP", `Your OTP is ${otp}. Expires in 5 minutes.`);
        res.json({ ref, message: "OTP sent" });
    } catch (err) {
        logger.error({ err });
        res.status(500).json({ error: "Server error" });
    }
});

app.post(["/auth/otp/verify", "/verify-otp"], authLimiter, async (req, res) => {
    try {
        const { ref, otp } = req.body;
        const records = await db.query(`SELECT * FROM otps WHERE ref = ?`, [ref]);
        const record = records[0];

        if (!record || Date.now() > record.expires_at) return res.status(400).json({ error: "Invalid or expired OTP" });
        if (!bcrypt.compareSync(otp, record.otp_hash)) return res.status(400).json({ error: "Invalid OTP" });

        await db.run(`DELETE FROM otps WHERE ref = ?`, [ref]);
        const token = signJwt({ email: record.identifier });
        res.json({ success: true, token, user: { email: record.identifier } });
    } catch (err) {
        logger.error({ err });
        res.status(500).json({ error: "Server error" });
    }
});

app.post(["/auth/otp/request", "/request-otp"], authLimiter, async (req, res) => {
    try {
        const { email } = req.body;
        const otp = generateOtp();
        const ref = crypto.randomUUID();
        const otpHash = bcrypt.hashSync(otp, 8);
        await db.run(`INSERT INTO otps (ref, otp_hash, identifier, expires_at) VALUES (?, ?, ?, ?)`, [ref, otpHash, email, Date.now() + ENV.OTP_EXPIRY_MS]);
        await sendEmail(email, "Your OTP", `Your OTP is ${otp}`);
        res.json({ ref, message: "OTP sent" });
    } catch (err) { res.status(500).json({ error: "Failed" }); }
});

/* ----------------------------- Invoice & Payments ----------------------- */

app.post("/invoices", async (req, res) => {
    try {
        const { customerId, amount, currency = "KES", description = "" } = req.body;
        const ref = "ECZ-" + Date.now() + "-" + Math.floor(Math.random() * 9999);
        const invoice = { reference_number: ref, id: crypto.randomUUID(), customer_id: customerId, amount, currency, status: "PENDING", created_at: now() };
        await db.run(`INSERT INTO invoices (reference_number, id, customer_id, amount, currency, description, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, [ref, invoice.id, customerId, amount, currency, description, "PENDING", invoice.created_at]);
        res.json(invoice);
    } catch (err) { res.status(500).json({ error: "Error" }); }
});

app.get("/invoices/:ref", async (req, res) => {
    const invs = await db.query(`SELECT * FROM invoices WHERE reference_number = ?`, [req.params.ref]);
    invs[0] ? res.json(invs[0]) : res.status(404).json({ error: "Not found" });
});

app.post("/payments", async (req, res) => {
    try {
        const { reference_number, channel } = req.body;
        const invs = await db.query(`SELECT * FROM invoices WHERE reference_number = ?`, [reference_number]);
        if (!invs[0] || invs[0].status !== "PENDING") return res.status(400).json({ error: "Invalid invoice" });

        if (channel === "mpesa") {
            setTimeout(async () => {
                await db.run(`UPDATE invoices SET status = 'PAID', paid_at = ? WHERE reference_number = ?`, [now(), reference_number]);
            }, 5000);
            return res.json({ message: "STK Push simulated" });
        }
        res.json({ message: "Initiated" });
    } catch (err) { res.status(500).json({ error: "Error" }); }
});

/* ----------------------------- Webhooks --------------------------------- */

app.post("/webhooks/bank", async (req, res) => {
    const sig = req.headers["x-signature"];
    const expected = hmacSha256Hex(ENV.WEBHOOK_SHARED_SECRET, JSON.stringify(req.body));
    if (sig !== expected) return res.status(401).end();

    const { reference_number, status } = req.body;
    if (status === "SUCCESS") {
        await db.run(`UPDATE invoices SET status = 'PAID', paid_at = ? WHERE reference_number = ?`, [now(), reference_number]);
    }
    res.end();
});

app.post("/webhooks/mpesa", async (req, res) => {
    const ref = req.body?.Body?.stkCallback?.CallbackMetadata?.Item?.find(i => i.Name === "AccountReference")?.Value;
    if (ref) await db.run(`UPDATE invoices SET status = 'PAID', paid_at = ? WHERE reference_number = ?`, [now(), ref]);
    res.end();
});

/* ----------------------------- Error & Init ------------------------------ */

app.use((err, req, res, next) => {
    logger.error({ err });
    res.status(500).json({ error: "Unexpected error" });
});

app.listen(ENV.PORT, () => logger.info({ msg: `Server running on port ${ENV.PORT}` }));
