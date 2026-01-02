const { Pool } = require('pg');
const Database = require('better-sqlite3');
const path = require('path');

// Connection pooling for Postgres
let pool;
let sqlite;

const isProduction = process.env.NODE_ENV === 'production' || !!process.env.DATABASE_URL;

if (isProduction) {
    pool = new Pool({
        connectionString: process.env.DATABASE_URL,
        ssl: { rejectUnauthorized: false } // Required for many hosted DBs like Render/Neon
    });
    console.log("Using PostgreSQL Database");
} else {
    // Local development uses SQLite for ease of setup
    sqlite = new Database(path.join(__dirname, 'hearth.db'));
    console.log("Using SQLite Database");
}

// Helper to run queries across either DB
async function query(text, params) {
    if (isProduction) {
        return (await pool.query(text, params)).rows;
    } else {
        return sqlite.prepare(text).all(params || []);
    }
}

async function run(text, params) {
    if (isProduction) {
        await pool.query(text, params);
    } else {
        sqlite.prepare(text).run(params || []);
    }
}

// Initial Schema Setup
const initDb = async () => {
    const schemas = [
        `CREATE TABLE IF NOT EXISTS users (
            identifier TEXT PRIMARY KEY,
            password_hash TEXT,
            verified BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )`,
        `CREATE TABLE IF NOT EXISTS verifications (
            ref TEXT PRIMARY KEY,
            code_hash TEXT,
            identifier TEXT,
            expires_at BIGINT
        )`,
        `CREATE TABLE IF NOT EXISTS otps (
            ref TEXT PRIMARY KEY,
            otp_hash TEXT,
            identifier TEXT,
            expires_at BIGINT
        )`,
        `CREATE TABLE IF NOT EXISTS invoices (
            reference_number TEXT PRIMARY KEY,
            id TEXT,
            customer_id TEXT,
            amount DECIMAL,
            currency TEXT,
            description TEXT,
            status TEXT,
            created_at TEXT,
            expires_at TEXT,
            paid_at TEXT
        )`
    ];

    for (const schema of schemas) {
        await run(schema);
    }
};

module.exports = {
    query,
    run,
    initDb
};
