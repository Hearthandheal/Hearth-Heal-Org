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

const path = require("path");

const app = express();

app.get("/health", (req, res) => res.json({ status: "ok", time: new Date().toISOString() }));
const logger = winston.createLogger({
    level: "info",
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
    ),
    transports: [new winston.transports.Console()]
});

/* ----------------------------- Security setup ---------------------------- */
// Configure Helmet to allow Google Fonts and scripts needed for the frontend
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            "default-src": ["'self'"],
            "script-src": ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net"],
            "style-src": ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
            "font-src": ["'self'", "https://fonts.gstatic.com"],
            "img-src": ["'self'", "data:", "https:*"],
            "connect-src": ["'self'", "https://hearth-heal-org.onrender.com", "http://localhost:3000"]
        },
    }
}));
app.use(cors({ origin: true }));
app.use(express.json({ limit: "1mb" }));
app.use(express.static(path.join(__dirname))); // Serve static frontend files
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
    EMAIL_FROM: process.env.EMAIL_FROM || process.env.EMAIL_USER,
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

const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
        user: ENV.EMAIL_USER,
        pass: ENV.EMAIL_PASS
    }
});

// Send email function
async function sendEmail(to, subject, text) {
    if (!ENV.EMAIL_USER || !ENV.EMAIL_PASS) {
        logger.warn("EMAIL_CREDENTIALS_MISSING: Simulation mode active.", { to });
        console.log(`\n--- [EMAIL SIMULATION] ---\nTo: ${to}\nSubject: ${subject}\nBody: ${text}\n--------------------------\n`);
        return;
    }

    try {
        await transporter.sendMail({
            from: ENV.EMAIL_FROM,
            to,
            subject,
            text,
            html: `<div style="font-family: sans-serif; padding: 20px; border: 1px solid #eee; border-radius: 5px;">
                    <h2 style="color: #00E676;">Hearth & Heal</h2>
                    <p>${text.replace(/\n/g, '<br>')}</p>
                    <hr style="border: none; border-top: 1px solid #eee;">
                    <p style="font-size: 12px; color: #888;">If you didn't request this, please ignore this email.</p>
                   </div>`
        });
        logger.info("EMAIL_SENT_SUCCESS", { to });
    } catch (err) {
        logger.error("EMAIL_SEND_FAILURE", { error: err.message, to });
        throw new Error("Email service temporarily unavailable. Please try again later.");
    }
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

function getUuid() {
    if (typeof crypto.randomUUID === "function") return crypto.randomUUID();
    return crypto.randomBytes(16).toString("hex");
}

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    message: { error: "Too many attempts. Please try again later." }
});

const resetLimiter = rateLimit({
    windowMs: 60 * 1000 * 60, // 1 hour
    max: 5,
    message: { error: "Too many reset requests. Please try again in an hour." }
});

/* ----------------------------- Auth API ----------------------------- */

app.post("/request-verification", authLimiter, async (req, res) => {
    try {
        const { email } = req.body;
        if (!email || typeof email !== "string") {
            return res.status(400).json({ error: "Valid email required" });
        }

        // Check 1-minute cooldown
        const duration = 10 * 60 * 1000;
        const recent = await db.query(`SELECT * FROM verifications WHERE identifier = ? AND expires_at > ? ORDER BY expires_at DESC LIMIT 1`, [email, Date.now() + duration - 60000]);
        if (recent[0]) return res.status(429).json({ error: "Please wait 1 minute before requesting another code." });

        const code = generateOtp();
        const ref = getUuid();
        const codeHash = bcrypt.hashSync(code, 8);

        await db.run(
            `INSERT INTO verifications (ref, code_hash, identifier, expires_at) VALUES (?, ?, ?, ?)`,
            [ref, codeHash, email, Date.now() + duration]
        );

        await sendEmail(email, "Verify Your Email", `Your code is ${code}. It expires in 10 minutes.`);
        res.json({ ref, message: "Verification code sent" });
    } catch (err) {
        logger.error("Signup request failed", { error: err.message });
        res.status(500).json({ error: err.message || "Server error" });
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
        logger.error("Verify email failed", { error: err.message });
        res.status(500).json({ error: err.message || "Server error" });
    }
});

app.post("/login", authLimiter, async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) {
            return res.status(400).json({ error: "Email and password required" });
        }

        const users = await db.query(`SELECT * FROM users WHERE identifier = ? AND verified = TRUE`, [email]);
        const user = users[0];

        if (!user || !user.password_hash || !bcrypt.compareSync(password, user.password_hash)) {
            return res.status(400).json({ error: "Invalid credentials" });
        }

        // Check 1-minute cooldown for OTP
        const recent = await db.query(`SELECT * FROM otps WHERE identifier = ? AND (expires_at - ?) > ? ORDER BY expires_at DESC LIMIT 1`, [email, ENV.OTP_EXPIRY_MS, Date.now() - 60000]);
        if (recent[0]) return res.status(429).json({ error: "OTP already sent. Please wait 1 minute before requesting another." });

        const otp = generateOtp();
        const ref = getUuid();
        const otpHash = bcrypt.hashSync(otp, 8);

        await db.run(
            `INSERT INTO otps (ref, otp_hash, identifier, expires_at) VALUES (?, ?, ?, ?)`,
            [ref, otpHash, email, Date.now() + ENV.OTP_EXPIRY_MS]
        );

        await sendEmail(email, "Login OTP", `Your OTP is ${otp}. Expires in 5 minutes.`);
        res.json({ ref, message: "OTP sent" });
    } catch (err) {
        logger.error("Login attempt failed", { error: err.message });
        res.status(500).json({ error: err.message || "Server error" });
    }
});

app.post(["/auth/otp/verify", "/verify-otp"], authLimiter, async (req, res) => {
    try {
        const { ref, otp } = req.body;
        if (!ref || !otp) return res.status(400).json({ error: "Reference and OTP required" });

        const records = await db.query(`SELECT * FROM otps WHERE ref = ?`, [ref]);
        const record = records[0];

        if (!record || Date.now() > record.expires_at) return res.status(400).json({ error: "Invalid or expired OTP" });
        if (!record.otp_hash || !bcrypt.compareSync(otp, record.otp_hash)) return res.status(400).json({ error: "Invalid OTP" });

        await db.run(`DELETE FROM otps WHERE ref = ?`, [ref]);
        const token = signJwt({ email: record.identifier });
        res.json({ success: true, token, user: { email: record.identifier } });
    } catch (err) {
        logger.error("OTP verification failed", { error: err.message, stack: err.stack });
        res.status(500).json({ error: "Server error" });
    }
});

app.post(["/auth/otp/request", "/request-otp"], authLimiter, async (req, res) => {
    try {
        const { email } = req.body;
        const recent = await db.query(`SELECT * FROM otps WHERE identifier = ? AND (expires_at - ?) > ? ORDER BY expires_at DESC LIMIT 1`, [email, ENV.OTP_EXPIRY_MS, Date.now() - 60000]);
        if (recent[0]) return res.status(429).json({ error: "OTP already sent. Please wait 1 minute." });

        const otp = generateOtp();
        const ref = getUuid();
        const otpHash = bcrypt.hashSync(otp, 8);
        await db.run(`INSERT INTO otps (ref, otp_hash, identifier, expires_at) VALUES (?, ?, ?, ?)`, [ref, otpHash, email, Date.now() + ENV.OTP_EXPIRY_MS]);
        await sendEmail(email, "Your OTP", `Your OTP is ${otp}`);
        res.json({ ref, message: "OTP sent" });
    } catch (err) { res.status(500).json({ error: "Failed" }); }
});

/* -------------------- Password Reset -------------------- */
app.post("/request-reset", resetLimiter, async (req, res) => {
    try {
        const { email } = req.body;
        if (!email) return res.status(400).json({ error: "Email required" });

        const users = await db.query(`SELECT * FROM users WHERE identifier = ? AND verified = TRUE`, [email]);
        if (users.length === 0) {
            // Audit failed attempt but return success to prevent user enumeration
            audit("PASSWORD_RESET_REQUEST_FAILED", { email, reason: "NOT_FOUND" });
            return res.json({ message: "If an account exists, a reset link was sent." });
        }

        // Check 1-minute cooldown for Reset
        const duration = 15 * 60 * 1000;
        const recent = await db.query(`SELECT * FROM password_resets WHERE identifier = ? AND (expires_at - ?) > ? ORDER BY expires_at DESC LIMIT 1`, [email, duration, Date.now() - 60000]);
        if (recent[0]) return res.status(429).json({ error: "Reset link already sent. Please wait 1 minute." });

        const token = crypto.randomBytes(20).toString("hex");
        const ref = getUuid();
        const tokenHash = crypto.createHash('sha256').update(token).digest('hex');

        await db.run(
            `INSERT INTO password_resets (ref, token_hash, identifier, expires_at) VALUES (?, ?, ?, ?)`,
            [ref, tokenHash, email, Date.now() + duration]
        );

        const resetLink = `${ENV.BASE_URL}/forgot-password.html?ref=${ref}&token=${token}`;
        const emailBody = `A password reset was requested for your account.\n\n` +
            `Click here to reset: ${resetLink}\n\n` +
            `Or use this code: ${token}\n\n` +
            `This link expires in 15 minutes. If you did not request this, please ignore this email.`;

        await sendEmail(email, "Password Reset Request", emailBody);
        audit("PASSWORD_RESET_REQUESTED", { email, ref });

        res.json({ ref, message: "Reset link sent to email" });
    } catch (err) {
        logger.error("Reset request failed", { error: err.message });
        res.status(500).json({ error: "Server error" });
    }
});

app.post("/verify-reset", authLimiter, async (req, res) => {
    try {
        const { ref, token, newPassword } = req.body;
        if (!ref || !token || !newPassword) return res.status(400).json({ error: "All fields required" });

        const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
        const records = await db.query(`SELECT * FROM password_resets WHERE ref = ?`, [ref]);
        const record = records[0];

        if (!record || Date.now() > record.expires_at) {
            audit("PASSWORD_RESET_FAILED", { ref, reason: "EXPIRED_OR_INVALID" });
            return res.status(400).json({ error: "Invalid or expired link" });
        }

        if (record.token_hash !== tokenHash) {
            audit("PASSWORD_RESET_FAILED", { ref, reason: "TOKEN_MISMATCH" });
            return res.status(400).json({ error: "Invalid reset token" });
        }

        if (newPassword.length < 6) return res.status(400).json({ error: "Password must be at least 6 characters" });

        const passwordHash = bcrypt.hashSync(newPassword, 10);
        await db.run(`UPDATE users SET password_hash = ? WHERE identifier = ?`, [passwordHash, record.identifier]);
        await db.run(`DELETE FROM password_resets WHERE ref = ?`, [ref]);

        audit("PASSWORD_RESET_SUCCESS", { email: record.identifier });
        res.json({ success: true, message: "Password reset successfully" });
    } catch (err) {
        logger.error("Password reset failed", { error: err.message });
        res.status(500).json({ error: "Server error" });
    }
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
