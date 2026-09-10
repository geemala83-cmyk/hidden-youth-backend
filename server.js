const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const { Pool } = require("pg");
const fs = require("fs");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json({ limit: "2mb" }));

/* =====================================================
   DATABASE
===================================================== */

if (!process.env.DATABASE_URL) {
    console.error("DATABASE_URL is not configured.");
    process.exit(1);
}

if (!process.env.ADMIN_USERNAME || !process.env.ADMIN_PASSWORD) {
    console.error(
        "ADMIN_USERNAME and ADMIN_PASSWORD are required."
    );
    process.exit(1);
}

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    connectionTimeoutMillis: 10000
});

/* =====================================================
   ADMIN AUTH
===================================================== */

const ADMIN_TOKEN_TTL_MS =
    24 * 60 * 60 * 1000;

function getAdminSecret() {
    return crypto
        .createHash("sha256")
        .update(
            `${process.env.ADMIN_USERNAME}:${process.env.ADMIN_PASSWORD}`
        )
        .digest("hex");
}

function createAdminToken() {

    const payload = {
        sub: "admin",
        exp: Date.now() + ADMIN_TOKEN_TTL_MS
    };

    const encoded = Buffer
        .from(JSON.stringify(payload))
        .toString("base64url");

    const signature = crypto
        .createHmac(
            "sha256",
            getAdminSecret()
        )
        .update(encoded)
        .digest("base64url");

    return `${encoded}.${signature}`;
}

function verifyAdminToken(token) {

    try {

        if (!token) return false;

        const parts =
            token.split(".");

        if (parts.length !== 2) {
            return false;
        }

        const encoded = parts[0];
        const signature = parts[1];

        const expected =
            crypto
                .createHmac(
                    "sha256",
                    getAdminSecret()
                )
                .update(encoded)
                .digest("base64url");

        const a = Buffer.from(signature);
        const b = Buffer.from(expected);

        if (
            a.length !== b.length ||
            !crypto.timingSafeEqual(a, b)
        ) {
            return false;
        }

        const payload =
            JSON.parse(
                Buffer
                    .from(
                        encoded,
                        "base64url"
                    )
                    .toString("utf8")
            );

        return (
            payload.sub === "admin" &&
            payload.exp > Date.now()
        );

    } catch {

        return false;
    }
}

function requireAdmin(req, res, next) {

    const header =
        req.headers.authorization || "";

    const token =
        header.startsWith("Bearer ")
            ? header.slice(7)
            : "";

    if (!verifyAdminToken(token)) {

        return res.status(401).json({

            success: false,

            message:
                "Unauthorized. Admin login required."

        });
    }

    next();
}



/* =====================================================
   CUSTOMER AUTHENTICATION
===================================================== */

const customerSessions = new Map();
const CUSTOMER_TOKEN_TTL_MS = 30 * 24 * 60 * 60 * 1000;

function normalizeCustomerEmail(value) {
    return String(value || "").trim().toLowerCase();
}

function hashCustomerPassword(password, salt) {
    return crypto
        .scryptSync(String(password), salt, 64)
        .toString("hex");
}

function createCustomerToken(customerId) {
    const token = crypto.randomBytes(32).toString("hex");
    customerSessions.set(token, {
        customerId: Number(customerId),
        expiresAt: Date.now() + CUSTOMER_TOKEN_TTL_MS
    });
    return token;
}

function getCustomerSession(req) {
    const auth = req.headers.authorization || "";
    if (!auth.startsWith("Bearer ")) return null;

    const token = auth.slice(7);
    const session = customerSessions.get(token);

    if (!session || session.expiresAt <= Date.now()) {
        if (session) customerSessions.delete(token);
        return null;
    }

    return { token, ...session };
}

function requireCustomer(req, res, next) {
    const session = getCustomerSession(req);

    if (!session) {
        return res.status(401).json({
            success: false,
            message: "Customer login required."
        });
    }

    req.customerSession = session;
    next();
}

app.post("/api/customer/register", async (req, res) => {
    try {
        const name = String(req.body?.name || "").trim();
        const email = normalizeCustomerEmail(req.body?.email);
        const password = String(req.body?.password || "");

        if (!name || !email || !password) {
            return res.status(400).json({
                success: false,
                message: "Name, email and password are required."
            });
        }

        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
            return res.status(400).json({
                success: false,
                message: "Please enter a valid email address."
            });
        }

        if (password.length < 8) {
            return res.status(400).json({
                success: false,
                message: "Password must be at least 8 characters."
            });
        }

        const existing = await pool.query(
            `SELECT id FROM customers WHERE LOWER(email) = LOWER($1) LIMIT 1`,
            [email]
        );

        if (existing.rows.length) {
            return res.status(409).json({
                success: false,
                message: "An account with this email already exists."
            });
        }

        const salt = crypto.randomBytes(16).toString("hex");
        const passwordHash = hashCustomerPassword(password, salt);

        const result = await pool.query(
            `
            INSERT INTO customers (name, email, password_hash, password_salt)
            VALUES ($1, $2, $3, $4)
            RETURNING id, name, email, created_at
            `,
            [name, email, passwordHash, salt]
        );

        const customer = result.rows[0];
        const token = createCustomerToken(customer.id);

        res.status(201).json({
            success: true,
            message: "Account created successfully.",
            token,
            customer: {
                id: customer.id,
                name: customer.name,
                email: customer.email,
                createdAt: customer.created_at
            }
        });
    } catch (error) {
        console.error("CUSTOMER REGISTER ERROR:", error);
        res.status(500).json({
            success: false,
            message: "Could not create customer account."
        });
    }
});

app.post("/api/customer/login", async (req, res) => {
    try {
        const email = normalizeCustomerEmail(req.body?.email);
        const password = String(req.body?.password || "");

        if (!email || !password) {
            return res.status(400).json({
                success: false,
                message: "Email and password are required."
            });
        }

        const result = await pool.query(
            `
            SELECT id, name, email, password_hash, password_salt, created_at
            FROM customers
            WHERE LOWER(email) = LOWER($1)
            LIMIT 1
            `,
            [email]
        );

        if (!result.rows.length) {
            return res.status(401).json({
                success: false,
                message: "Invalid email or password."
            });
        }

        const customer = result.rows[0];
        const suppliedHash = hashCustomerPassword(password, customer.password_salt);
        const a = Buffer.from(suppliedHash, "hex");
        const b = Buffer.from(customer.password_hash, "hex");

        if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
            return res.status(401).json({
                success: false,
                message: "Invalid email or password."
            });
        }

        await pool.query(
            `UPDATE customers SET last_login_at = NOW(), updated_at = NOW() WHERE id = $1`,
            [customer.id]
        );

        const token = createCustomerToken(customer.id);

        res.json({
            success: true,
            message: "Login successful.",
            token,
            customer: {
                id: customer.id,
                name: customer.name,
                email: customer.email,
                createdAt: customer.created_at
            }
        });
    } catch (error) {
        console.error("CUSTOMER LOGIN ERROR:", error);
        res.status(500).json({
            success: false,
            message: "Could not log in."
        });
    }
});

app.post("/api/customer/logout", requireCustomer, (req, res) => {
    customerSessions.delete(req.customerSession.token);
    res.json({ success: true, message: "Logged out successfully." });
});

app.get("/api/customer/me", requireCustomer, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT id, name, email, created_at FROM customers WHERE id = $1 LIMIT 1`,
            [req.customerSession.customerId]
        );

        if (!result.rows.length) {
            customerSessions.delete(req.customerSession.token);
            return res.status(401).json({
                success: false,
                message: "Customer account not found."
            });
        }

        const customer = result.rows[0];
        res.json({
            success: true,
            customer: {
                id: customer.id,
                name: customer.name,
                email: customer.email,
                createdAt: customer.created_at
            }
        });
    } catch (error) {
        console.error("CUSTOMER ME ERROR:", error);
        res.status(500).json({
            success: false,
            message: "Could not load account."
        });
    }
});

app.get("/api/customer/orders", requireCustomer, async (req, res) => {
    try {
        const customerResult = await pool.query(
            `SELECT email FROM customers WHERE id = $1 LIMIT 1`,
            [req.customerSession.customerId]
        );

        if (!customerResult.rows.length) {
            return res.status(401).json({ success: false, message: "Customer account not found." });
        }

        const email = customerResult.rows[0].email;
        const result = await pool.query(
            `
            SELECT id, customer, items, total, status, created_at
            FROM orders
            WHERE (
                    LOWER(COALESCE(customer->>'email', '')) = LOWER($1)
                    OR (
                        NULLIF(customer->>'customerId', '') IS NOT NULL
                        AND (customer->>'customerId')::INTEGER = $2
                    )
                )
            ORDER BY created_at DESC
            `,
            [email, req.customerSession.customerId]
        );

        res.json({
            success: true,
            count: result.rows.length,
            orders: result.rows.map(order => ({
                id: order.id,
                customer: order.customer,
                items: order.items,
                total: Number(order.total),
                status: order.status,
                createdAt: order.created_at
            }))
        });
    } catch (error) {
        console.error("CUSTOMER ORDERS ERROR:", error);
        res.status(500).json({ success: false, message: "Could not fetch your orders." });
    }
});


/* =====================================================
   DATABASE INITIALIZATION
===================================================== */

async function initializeDatabase() {

    try {

        /* ==============================
           CUSTOMERS
        ============================== */

        await pool.query(`
            CREATE TABLE IF NOT EXISTS customers (
                id SERIAL PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                email VARCHAR(320) NOT NULL,
                password_hash TEXT NOT NULL,
                password_salt TEXT NOT NULL,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );
        `);

        await pool.query(`
            CREATE UNIQUE INDEX IF NOT EXISTS customers_email_unique_idx
            ON customers (LOWER(email));
        `);

        await pool.query(`
            ALTER TABLE customers
            ADD COLUMN IF NOT EXISTS last_login_at TIMESTAMPTZ;
        `);

        /* ==============================
           ORDERS
        ============================== */

        await pool.query(`
            CREATE TABLE IF NOT EXISTS orders (

                id VARCHAR(100) PRIMARY KEY,

                customer JSONB NOT NULL,

                items JSONB NOT NULL,

                total NUMERIC(12,2)
                    NOT NULL DEFAULT 0,

                status VARCHAR(50)
                    NOT NULL DEFAULT 'PENDING',

                created_at TIMESTAMPTZ
                    NOT NULL DEFAULT NOW()
            );
        `);


        /* ==============================
           PRODUCTS
        ============================== */

        await pool.query(`
            CREATE TABLE IF NOT EXISTS products (

                id SERIAL PRIMARY KEY,

                name VARCHAR(255) NOT NULL,

                category VARCHAR(100),

                description TEXT,

                price NUMERIC(12,2)
                    NOT NULL DEFAULT 0,

                image TEXT,

                stock INTEGER
                    NOT NULL DEFAULT 0,

                available BOOLEAN
                    NOT NULL DEFAULT TRUE,

                created_at TIMESTAMPTZ
                    NOT NULL DEFAULT NOW(),

                updated_at TIMESTAMPTZ
                    NOT NULL DEFAULT NOW()
            );
        `);


        /* ==============================
           VISITORS
        ============================== */

        await pool.query(`
            CREATE TABLE IF NOT EXISTS visitors (

                visitor_id VARCHAR(150)
                    PRIMARY KEY,

                page TEXT,

                ip_hash VARCHAR(255),

                user_agent TEXT,

                last_seen TIMESTAMPTZ
                    NOT NULL DEFAULT NOW(),

                created_at TIMESTAMPTZ
                    NOT NULL DEFAULT NOW()
            );
        `);


        /* ==============================
           CART SESSIONS
        ============================== */

        await pool.query(`
            CREATE TABLE IF NOT EXISTS cart_sessions (

                visitor_id VARCHAR(150)
                    PRIMARY KEY,

                items JSONB
                    NOT NULL DEFAULT '[]'::jsonb,

                total NUMERIC(12,2)
                    NOT NULL DEFAULT 0,

                last_seen TIMESTAMPTZ
                    NOT NULL DEFAULT NOW(),

                created_at TIMESTAMPTZ
                    NOT NULL DEFAULT NOW()
            );
        `);


        /* ==============================
           INDEXES
        ============================== */

        await pool.query(`
            CREATE INDEX IF NOT EXISTS
            visitors_last_seen_idx
            ON visitors(last_seen);
        `);

        await pool.query(`
            CREATE INDEX IF NOT EXISTS
            cart_sessions_last_seen_idx
            ON cart_sessions(last_seen);
        `);


        /* ==============================
           SEED PRODUCTS
        ============================== */

        const productCount =
            await pool.query(
                `SELECT COUNT(*) FROM products`
            );

        if (
            Number(productCount.rows[0].count) === 0
        ) {

            await pool.query(`
                INSERT INTO products
                (
                    name,
                    category,
                    description,
                    price,
                    image,
                    stock,
                    available
                )
                VALUES

                (
                    'GYM FIT — 01',
                    'Gym Fit',
                    'Performance / Movement',
                    4990,
                    'gym.fit.jpg',
                    10,
                    TRUE
                ),

                (
                    'GYM FIT — 02',
                    'Gym Fit',
                    'Performance / Movement',
                    4990,
                    'gym.fit2.jpg',
                    10,
                    TRUE
                ),

                (
                    'GYM FIT — 03',
                    'Gym Fit',
                    'Performance / Movement',
                    4990,
                    'gym.fit3.jpg',
                    10,
                    TRUE
                ),

                (
                    'GYM FIT — 04',
                    'Gym Fit',
                    'Performance / Movement',
                    4990,
                    'gym.fit4.jpg',
                    10,
                    TRUE
                );
            `);

            console.log(
                "DEFAULT PRODUCTS INSERTED"
            );
        }


        /* ==============================
           FIX PRODUCTS WITH STOCK 0
        ============================== */

        await pool.query(`
            UPDATE products

            SET available = FALSE

            WHERE stock <= 0;
        `);


        console.log(
            "POSTGRESQL DATABASE READY"
        );

    } catch (error) {

        console.error(
            "DATABASE INITIALIZATION ERROR:",
            error.message
        );

        process.exit(1);
    }
}

/* =====================================================
   ADMIN LOGIN
===================================================== */

app.post(
    "/api/admin/login",
    (req, res) => {

        const username =
            String(
                req.body?.username || ""
            );

        const password =
            String(
                req.body?.password || ""
            );

        if (
            username !==
                process.env.ADMIN_USERNAME ||
            password !==
                process.env.ADMIN_PASSWORD
        ) {

            return res.status(401).json({

                success: false,

                message:
                    "Invalid username or password."

            });
        }

        res.json({

            success: true,

            message:
                "Admin login successful.",

            token:
                createAdminToken(),

            expiresIn:
                ADMIN_TOKEN_TTL_MS
        });
    }
);



/* =====================================================
   CUSTOMER MANAGEMENT — ADMIN — ADDED ONLY
===================================================== */

app.get(
    "/api/admin/customers",
    requireAdmin,
    async (req, res) => {

        try {

            await pool.query(`
                UPDATE orders o
                SET customer = jsonb_set(
                    o.customer,
                    '{customerId}',
                    to_jsonb(c.id),
                    true
                )
                FROM customers c
                WHERE LOWER(COALESCE(o.customer->>'email', '')) = LOWER(c.email)
                  AND COALESCE(o.customer->>'customerId', '') = ''
            `);

            const result = await pool.query(`
                SELECT
                    c.id,
                    c.name,
                    c.email,
                    c.created_at,
                    c.last_login_at,
                    COUNT(o.id)::INTEGER AS total_orders
                FROM customers c
                LEFT JOIN orders o
                    ON (
                        LOWER(COALESCE(o.customer->>'email', '')) = LOWER(c.email)
                        OR (
                            NULLIF(o.customer->>'customerId', '') IS NOT NULL
                            AND (o.customer->>'customerId')::INTEGER = c.id
                        )
                    )
                GROUP BY
                    c.id,
                    c.name,
                    c.email,
                    c.created_at,
                    c.last_login_at
                ORDER BY c.created_at DESC
            `);

            const now = Date.now();

            const activeCustomerIds = new Set(
                Array.from(customerSessions.values())
                    .filter(session => session.expiresAt > now)
                    .map(session => Number(session.customerId))
            );

            res.json({
                success: true,
                count: result.rows.length,
                customers: result.rows.map(customer => ({
                    id: customer.id,
                    name: customer.name,
                    email: customer.email,
                    createdAt: customer.created_at,
                    lastLoginAt: customer.last_login_at,
                    totalOrders: Number(customer.total_orders || 0),
                    loggedIn: activeCustomerIds.has(Number(customer.id))
                }))
            });

        } catch (error) {

            console.error(
                "ADMIN CUSTOMERS ERROR:",
                error.message
            );

            res.status(500).json({
                success: false,
                message: "Could not fetch customers."
            });

        }

    }
);


app.get(
    "/api/admin/customers/:id/orders",
    requireAdmin,
    async (req, res) => {

        try {

            const customerId = Number(req.params.id);

            if (!Number.isInteger(customerId) || customerId <= 0) {
                return res.status(400).json({
                    success: false,
                    message: "Invalid customer ID."
                });
            }

            const customerResult = await pool.query(
                `SELECT email FROM customers WHERE id = $1 LIMIT 1`,
                [customerId]
            );

            if (!customerResult.rows.length) {
                return res.status(404).json({
                    success: false,
                    message: "Customer not found."
                });
            }

            const email = customerResult.rows[0].email;

            const result = await pool.query(
                `
                SELECT id, customer, items, total, status, created_at
                FROM orders
                WHERE (
                    LOWER(COALESCE(customer->>'email', '')) = LOWER($1)
                    OR (
                        NULLIF(customer->>'customerId', '') IS NOT NULL
                        AND (customer->>'customerId')::INTEGER = $2
                    )
                )
                ORDER BY created_at DESC
                `,
                [email, customerId]
            );

            res.json({
                success: true,
                count: result.rows.length,
                orders: result.rows.map(order => ({
                    id: order.id,
                    customer: order.customer,
                    items: order.items,
                    total: Number(order.total),
                    status: order.status,
                    createdAt: order.created_at
                }))
            });

        } catch (error) {

            console.error(
                "ADMIN CUSTOMER ORDERS ERROR:",
                error.message
            );

            res.status(500).json({
                success: false,
                message: "Could not fetch customer orders."
            });

        }

    }
);


/* =====================================================
   LAHORE POSTAL CODE LOOKUP
   HIDDEN YOUTH
===================================================== */

const verifiedLahorePostalCodes = {
    "53100": "LAHORE KAHNA NAU",
    "53200": "BARKI",
    "53400": "LAHORE BATA PUR",
    "53480": "LAHORE BATA PUR",
    "53500": "JALLO",
    "53600": "WAGHA LAHORE",
    "53700": "THOKAR NIAZ BEG",
    "53710": "LAHORE E.M.E SOCIETY P.O",
    "53720": "LAHORE BAHRIA TOWN",
    "53800": "CHUHANG",
    "54000": "LAHORE GPO",
    "54010": "NAULAKHA",
    "54020": "LAHORE ALFLAH",
    "54030": "LAHORE AITCHESON COLLEGE",
    "54100": "SHAH ALAM MARKET",
    "54110": "SHAHI MOHALLAH",
    "54120": "TIMBER MARKET",
    "54500": "LAHORE MULTAN ROAD POST OFFICE",
    "54510": "REWAZ GARDEN",
    "54550": "LAHORE PT & T AUDIT",
    "54560": "LAHORE PMG PUNJAB POST OFFICE",
    "54570": "LAHORE ALLAMA IQBAL TOWN",
    "54590": "LAHORE NEW UNIVERSITY CAMPUS",
    "54600": "LAHORE FEROZEPUR ROAD",
    "54610": "LAHORE SHADMAN WOMEN MODEL P.O",
    "54650": "LAHORE SECONDARY BOARD",
    "54660": "LAHORE GULBERG COLONY",
    "54700": "LAHORE MODEL TOWN",
    "54760": "LAHORE ISMAIL NAGAR",
    "54762": "LAHORE NISHTAR TOWN",
    "54770": "LAHORE TOWNSHIP SECTOR A-1",
    "54780": "LAHORE AWAN COLONEY",
    "54782": "LAHORE JOHAR TOWN",
    "54786": "LAHORE GREEN TOWN",
    "54790": "MANSOORA",
    "54792": "LAHORE DEFENCE HOUSING SOCIETY",
    "54800": "LAHORE C.M.A. CANTT.",
    "54810": "LAHORE CANTT. GPO",
    "54820": "LAHORE POSTMALL / JALLO MORE",
    "54840": "MUGHALPURA",
    "54850": "LAHORE HARBANS PURA",
    "54870": "LAHORE TAJPURA",
    "54880": "LAHORE PUNJAB GOVERNOR HOUSE",
    "54890": "LAHORE ENGINEERING UNIVERSITY",
    "54900": "CHAH MIRAN",
    "54920": "LAHORE BAGHBANPURA",
    "54950": "SHAHDARA BAGH",
    "55150": "RAIWIND",
    "55160": "LAHORE KOHINOOR ENERGY",
    "55210": "BALLOKI",
    "55270": "MANGA MANDI",
    "05301": "SAMANABAD PO",
    "05302": "DSPS SOUTH DIVN LAHORE PO",
    "05303": "FAISAL TOWN PO",
    "05304": "M BLOCK MODEL TOWN PO",
    "05305": "FEROZPUR ROAD PO",
    "05306": "CHOWK ICHHRA",
    "05307": "GULAB DEVI HOSPITAL PO",
    "05308": "ICHHRA PO",
    "05309": "NEW GARDEN TOWN N. PO",
    "05310": "RASOOL PARK PO",
    "05311": "REHMAN PURA PO",
    "05312": "ROTARY CENTRE",
    "05313": "WAHDAT COLONY PO",
    "05401": "LAHORE GPO NPO",
    "05402": "CHOWK QURTABA PO",
    "05403": "GOR ESTATE PO",
    "05404": "HIGH COURT PO",
    "05405": "ISLAMPURA PO",
    "05406": "MADINA CHOK POST OFFICE",
    "05407": "RACE COURSE ROAD PO",
    "05408": "SESSION COURT PO",
    "05409": "SHADMAN COLONY PO",
    "05410": "SHADMAN COLONY NPO",
    "05411": "MOZANG PO",
    "05412": "BADAMI BAGH PO",
    "05413": "DATA GUNJ BUKSH PO",
    "05414": "DATA NAGAR PO",
    "05415": "FLATTIES HOTEL PO",
    "05416": "KAMYAB NPO",
    "05417": "KAMYAB PO",
    "05418": "LAHORE KUTCHERY PO",
    "05419": "LAKSHMI CHOWK PO",
    "05420": "MOCHI GATE PO",
    "05421": "PAKISTAN TIMES PO",
    "05422": "PUNJAB UNIVERSITY OLD CAMPUS PO",
    "05423": "TAJ COMPANY NPO",
    "05424": "TAJ COMPANY PO",
    "05425": "A.I TOWN NPO",
    "05426": "WAPDA TOWN PO",
    "05427": "MANSOORA NPO",
    "05428": "N.U CAMPUS NPO",
    "05429": "SHAHDRA TOWN PO",
    "05430": "AZAM PO",
    "05431": "V R INSTITUTE PO",
    "05432": "EP CENTRE SADAR BAZAR NPO",
    "05433": "FORTRESS STADIUM PO",
    "05434": "ORDINANCE DEPOT PO",
    "05435": "SADDAR BAZAR PO",
    "05436": "LAHORE AIRPORT LSG",
    "05437": "LAHORE AIRPORT NPO BATCH-I",
    "05438": "LAHORE AIRPORT NPO BATCH-II",
    "05439": "MASJID KHALID PO",
    "05440": "NISHAT COLONY PO",
    "05441": "NISHTAR COLONY PO",
    "05442": "R.A BAZAR PO",
    "05443": "SERVICES PO",
    "05444": "WALTON PO",
    "05445": "RANG MAHAL NPO",
    "05446": "RANG MAHAL PO",
    "05447": "SHAH ALAM MARKET NPO",
    "05449": "AMER SIDHU PO",
    "05450": "KOT LAKHPAT PO",
    "05452": "JAHANGIR TOWN PO",
    "05453": "SANDA PO",
    "05454": "L.C.C.H SOCIETY PO",
    "05455": "L.C.C.H SOCIETY NPO",
    "05456": "CG OFFICE PO",
    "05457": "GULBERG COLONY NPO",
    "05458": "GULBERG N. PO",
    "05459": "GULBERG PO",
    "05460": "BAGHBANPURA NPO",
    "05461": "BILAL GUNJ PO",
    "05462": "KPAR PO",
    "05463": "ADDA CHABEEL PO",
    "05464": "MEHBOOB BOOTI",
    "05465": "PAKISTAN MINT PO",
    "05466": "SHALIMAR TOWN PO",
    "05467": "AGRICULTURE HOUSE PO",
    "05468": "ALLAMA IQBAL ROAD PO",
    "05469": "NAULAKHA NPO",
    "05470": "RAILWAY HEADQUARTER HSG",
    "05471": "CHAH MIRAN NPO",
    "05472": "DAROGHAWALA PO",
    "05473": "FAIZ BAGH PO",
    "05474": "MISRI SHAH PO",
    "05475": "SHAD BAGH PO",
    "05476": "SULTAN PURA PO",
    "05477": "WASSANPURA PO",
    "05478": "DHARAMPURA PO",
    "05479": "GUNJ MOGHAL PURA PO",
    "05480": "NABI PURA PO",
    "05481": "KASURPURA PO",
    "05482": "SHAHDRA TOWN PO",
    "05483": "RUSTOM SOHRAB CYCLE FACTORY PO",
    "05484": "SHAHDRA BAGH NPO",
    "05485": "DHOLANWAL PO",
    "05486": "SHAH NOOR PO",
    "05487": "MARGAZAR COLONY PO",
    "05488": "CHUBURGI GARDEN ESTATE PO",
    "05489": "MULTAN ROAD NPO",
    "05490": "MULTAN ROAD PO",
    "05491": "SODIWAL PO",
    "05492": "S&S EP CENTRE PO",
    "05493": "PAKKI THATTI PO",
    "05494": "QARSHI DAWA KHANA PO",
    "05495": "SAMANABAD NPO",
    "05497": "REHMAN PURA PO",
    "05498": "NEW FRUIT MARKET PO",
    "05499": "SHER SHAH COLONY PO"
};

app.get(
    "/api/postal-codes/:code",
    async (req, res) => {

        try {

            const postalCode =
                String(req.params.code || "")
                    .replace(/\D/g, "")
                    .slice(0, 5);

            if (postalCode.length !== 5) {

                return res.status(400).json({
                    success: false,
                    message: "VALID 5 DIGIT POSTAL CODE REQUIRED.",
                    results: []
                });
            }

            const area =
                verifiedLahorePostalCodes[postalCode];

            if (!area) {

                return res.status(404).json({
                    success: false,
                    message: "LAHORE POSTAL CODE NOT FOUND.",
                    results: []
                });
            }

            return res.json({
                success: true,
                results: [
                    {
                        postalCode,
                        area_name: area,
                        city: "Lahore",
                        province: "Punjab"
                    }
                ]
            });

        } catch (error) {

            console.error(
                "POSTAL CODE LOOKUP ERROR:",
                error.message
            );

            return res.status(500).json({
                success: false,
                message: "COULD NOT VERIFY POSTAL CODE.",
                results: []
            });
        }
    }
);


/* =====================================================
   HOME
===================================================== */

app.get("/", async (req, res) => {

    try {

        await pool.query("SELECT 1");

        res.json({

            brand: "Hidden Youth",

            status: "ONLINE",

            database: "CONNECTED",

            message:
                "Welcome to the Hidden Youth world."

        });

    } catch {

        res.status(500).json({

            brand: "Hidden Youth",

            status: "ONLINE",

            database: "DISCONNECTED",

            message:
                "Backend is running but database is unavailable."

        });
    }
});

/* =====================================================
   PRODUCTS — PUBLIC
===================================================== */

app.get(
    "/api/products",
    async (req, res) => {

        try {

            const result =
                await pool.query(`

                    SELECT
                        id,
                        name,
                        category,
                        description,
                        price,
                        image,
                        stock,
                        available,
                        created_at,
                        updated_at

                    FROM products

                    ORDER BY id ASC

                `);

            const products =
                result.rows.map(product => ({

                    id:
                        product.id,

                    name:
                        product.name,

                    category:
                        product.category,

                    description:
                        product.description,

                    price:
                        Number(product.price),

                    image:
                        product.image,

                    stock:
                        Number(product.stock),

                    available:
                        Number(product.stock) > 0 &&
                        product.available === true,

                    createdAt:
                        product.created_at,

                    updatedAt:
                        product.updated_at

                }));

            res.json({

                success: true,

                count:
                    products.length,

                products

            });

        } catch (error) {

            console.error(
                "GET PRODUCTS ERROR:",
                error
            );

            res.status(500).json({

                success: false,

                message:
                    "Could not fetch products."

            });
        }
    }
);

/* =====================================================
   SINGLE PRODUCT
===================================================== */

app.get(
    "/api/products/:id",
    async (req, res) => {

        try {

            const result =
                await pool.query(
                    `
                    SELECT
                        id,
                        name,
                        category,
                        description,
                        price,
                        image,
                        stock,
                        available

                    FROM products

                    WHERE id = $1

                    LIMIT 1
                    `,
                    [
                        Number(req.params.id)
                    ]
                );

            if (
                result.rows.length === 0
            ) {

                return res.status(404).json({

                    success: false,

                    message:
                        "Product not found."

                });
            }

            const product =
                result.rows[0];

            res.json({

                success: true,

                product: {

                    ...product,

                    price:
                        Number(product.price),

                    stock:
                        Number(product.stock),

                    available:
                        Number(product.stock) > 0 &&
                        product.available === true

                }

            });

        } catch (error) {

            console.error(error);

            res.status(500).json({

                success: false,

                message:
                    "Could not fetch product."

            });
        }
    }
);

/* =====================================================
   CATEGORY
===================================================== */

app.get(
    "/api/category/:category",
    async (req, res) => {

        try {

            const result =
                await pool.query(
                    `
                    SELECT
                        id,
                        name,
                        category,
                        description,
                        price,
                        image,
                        stock,
                        available

                    FROM products

                    WHERE LOWER(category)
                    =
                    LOWER($1)

                    ORDER BY id ASC
                    `,
                    [
                        req.params.category
                    ]
                );

            const products =
                result.rows.map(product => ({

                    ...product,

                    price:
                        Number(product.price),

                    stock:
                        Number(product.stock),

                    available:
                        Number(product.stock) > 0 &&
                        product.available === true

                }));

            res.json({

                success: true,

                count:
                    products.length,

                products

            });

        } catch (error) {

            res.status(500).json({

                success: false,

                message:
                    "Could not fetch category."

            });
        }
    }
);

/* =====================================================
   ADMIN — ADD PRODUCT
===================================================== */

app.post(
    "/api/admin/products",
    requireAdmin,
    async (req, res) => {

        try {

            const {

                name,
                category,
                description,
                price,
                image,
                stock,
                available

            } = req.body;

            if (!name) {

                return res.status(400).json({

                    success: false,

                    message:
                        "Product name is required."

                });
            }

            const cleanPrice =
                Number(price) || 0;

            const cleanStock =
                Math.max(
                    0,
                    Number(stock) || 0
                );

            const cleanAvailable =
                cleanStock > 0 &&
                available !== false;

            const result =
                await pool.query(
                    `
                    INSERT INTO products
                    (
                        name,
                        category,
                        description,
                        price,
                        image,
                        stock,
                        available
                    )

                    VALUES
                    (
                        $1,
                        $2,
                        $3,
                        $4,
                        $5,
                        $6,
                        $7
                    )

                    RETURNING *
                    `,
                    [

                        String(name).trim(),

                        String(
                            category || ""
                        ).trim(),

                        String(
                            description || ""
                        ).trim(),

                        cleanPrice,

                        String(
                            image || ""
                        ).trim(),

                        cleanStock,

                        cleanAvailable

                    ]
                );

            const product =
                result.rows[0];

            res.status(201).json({

                success: true,

                message:
                    "Product added successfully.",

                product: {

                    ...product,

                    price:
                        Number(product.price),

                    stock:
                        Number(product.stock)

                }

            });

        } catch (error) {

            console.error(
                "ADD PRODUCT ERROR:",
                error
            );

            res.status(500).json({

                success: false,

                message:
                    "Could not add product."

            });
        }
    }
);

/* =====================================================
   ADMIN — UPDATE PRODUCT
===================================================== */

app.patch(
    "/api/admin/products/:id",
    requireAdmin,
    async (req, res) => {

        try {

            const id =
                Number(req.params.id);

            const current =
                await pool.query(
                    `
                    SELECT *
                    FROM products
                    WHERE id = $1
                    LIMIT 1
                    `,
                    [id]
                );

            if (
                current.rows.length === 0
            ) {

                return res.status(404).json({

                    success: false,

                    message:
                        "Product not found."

                });
            }

            const old =
                current.rows[0];

            const name =
                req.body.name !== undefined
                    ? String(req.body.name).trim()
                    : old.name;

            const category =
                req.body.category !== undefined
                    ? String(req.body.category).trim()
                    : old.category;

            const description =
                req.body.description !== undefined
                    ? String(req.body.description).trim()
                    : old.description;

            const price =
                req.body.price !== undefined
                    ? Number(req.body.price) || 0
                    : Number(old.price);

            const image =
                req.body.image !== undefined
                    ? String(req.body.image).trim()
                    : old.image;

            const stock =
                req.body.stock !== undefined
                    ? Math.max(
                        0,
                        Number(req.body.stock) || 0
                    )
                    : Number(old.stock);

            const available =
                stock > 0 &&
                (
                    req.body.available !== undefined
                        ? req.body.available === true
                        : old.available === true
                );

            const result =
                await pool.query(
                    `
                    UPDATE products

                    SET
                        name = $1,
                        category = $2,
                        description = $3,
                        price = $4,
                        image = $5,
                        stock = $6,
                        available = $7,
                        updated_at = NOW()

                    WHERE id = $8

                    RETURNING *
                    `,
                    [

                        name,

                        category,

                        description,

                        price,

                        image,

                        stock,

                        available,

                        id

                    ]
                );

            const product =
                result.rows[0];

            res.json({

                success: true,

                message:
                    "Product updated successfully.",

                product: {

                    ...product,

                    price:
                        Number(product.price),

                    stock:
                        Number(product.stock)

                }

            });

        } catch (error) {

            console.error(
                "UPDATE PRODUCT ERROR:",
                error
            );

            res.status(500).json({

                success: false,

                message:
                    "Could not update product."

            });
        }
    }
);

/* =====================================================
   ADMIN — DELETE PRODUCT
===================================================== */

app.delete(
    "/api/admin/products/:id",
    requireAdmin,
    async (req, res) => {

        try {

            const result =
                await pool.query(
                    `
                    DELETE FROM products

                    WHERE id = $1

                    RETURNING id
                    `,
                    [
                        Number(req.params.id)
                    ]
                );

            if (
                result.rows.length === 0
            ) {

                return res.status(404).json({

                    success: false,

                    message:
                        "Product not found."

                });
            }

            res.json({

                success: true,

                message:
                    "Product deleted successfully."

            });

        } catch (error) {

            console.error(
                "DELETE PRODUCT ERROR:",
                error
            );

            res.status(500).json({

                success: false,

                message:
                    "Could not delete product."

            });
        }
    }
);

/* =====================================================
   CREATE ORDER
   PUBLIC
===================================================== */

app.post(
    "/api/orders",
    async (req, res) => {

        const client =
            await pool.connect();

        try {

            const {
                customer,
                items
            } = req.body;

            if (
                !customer ||
                typeof customer !== "object" ||
                !Array.isArray(items) ||
                items.length === 0
            ) {

                return res.status(400).json({

                    success: false,

                    message:
                        "Customer and items are required."

                });
            }

            const name =
                String(
                    customer.name || ""
                ).trim();

            const phone =
                String(
                    customer.phone || ""
                ).trim();

            const address =
                String(
                    customer.address || ""
                ).trim();

            const city =
                String(
                    customer.city || ""
                ).trim();

            if (
                !name ||
                !phone ||
                !address ||
                !city
            ) {

                return res.status(400).json({

                    success: false,

                    message:
                        "Name, phone, address and city are required."

                });
            }

            await client.query("BEGIN");

            const cleanItems = [];

            let total = 0;

            /* ==============================
               CHECK REAL PRODUCTS + STOCK
            ============================== */

            for (const item of items) {

                const productId =
                    Number(item.id);

                const requestedQuantity =
                    Math.max(
                        1,
                        Number(item.quantity) || 1
                    );

                const result =
                    await client.query(
                        `
                        SELECT
                            id,
                            name,
                            price,
                            image,
                            stock,
                            available

                        FROM products

                        WHERE id = $1

                        FOR UPDATE
                        `,
                        [productId]
                    );

                if (
                    result.rows.length === 0
                ) {

                    throw new Error(
                        `Product ${productId} not found.`
                    );
                }

                const product =
                    result.rows[0];

                const stock =
                    Number(product.stock);

                if (
                    stock <= 0 ||
                    product.available !== true
                ) {

                    throw new Error(
                        `${product.name} is SOLD OUT.`
                    );
                }

                if (
                    requestedQuantity > stock
                ) {

                    throw new Error(
                        `Only ${stock} ${product.name} available.`
                    );
                }

                const itemTotal =
                    Number(product.price) *
                    requestedQuantity;

                total += itemTotal;

                cleanItems.push({

                    id:
                        product.id,

                    name:
                        product.name,

                    price:
                        Number(product.price),

                    quantity:
                        requestedQuantity,

                    image:
                        product.image || ""

                });


                /* ==============================
                   REDUCE STOCK
                ============================== */

                const newStock =
                    stock -
                    requestedQuantity;

                await client.query(
                    `
                    UPDATE products

                    SET
                        stock = $1,
                        available =
                            CASE
                                WHEN $1 <= 0
                                THEN FALSE
                                ELSE available
                            END,
                        updated_at = NOW()

                    WHERE id = $2
                    `,
                    [
                        newStock,
                        product.id
                    ]
                );
            }


            /* ==============================
               ORDER ID
            ============================== */

            const orderId =
                "HY-" +
                Date.now() +
                "-" +
                Math.floor(
                    Math.random() * 1000
                );


            const customerSession = getCustomerSession(req);

            let accountEmail = String(customer.email || "").trim().toLowerCase();
            let accountCustomerId = null;

            if (customerSession) {
                const accountResult = await client.query(
                    `SELECT id, email FROM customers WHERE id = $1 LIMIT 1`,
                    [customerSession.customerId]
                );
                if (accountResult.rows.length) {
                    accountCustomerId = Number(accountResult.rows[0].id);
                    accountEmail = accountResult.rows[0].email;
                }
            }

            /*
               If the customer's in-memory login session is no longer available
               (for example after a Railway restart), link the order by the
               customer email that the checkout already sends.
            */
            if (!accountCustomerId && accountEmail) {
                const emailCustomerResult = await client.query(
                    `SELECT id, email FROM customers WHERE LOWER(email) = LOWER($1) LIMIT 1`,
                    [accountEmail]
                );
                if (emailCustomerResult.rows.length) {
                    accountCustomerId = Number(emailCustomerResult.rows[0].id);
                    accountEmail = emailCustomerResult.rows[0].email;
                }
            }

            const cleanCustomer = {

                name,

                email: accountEmail,

                customerId: accountCustomerId,

                phone,

                address,

                city,

                postalCode: String(customer.postalCode || "").trim(),

                deliveryCharge: Number(customer.deliveryCharge || 0)

            };


            /* ==============================
               SAVE ORDER
            ============================== */

            const result =
                await client.query(
                    `
                    INSERT INTO orders
                    (
                        id,
                        customer,
                        items,
                        total,
                        status
                    )

                    VALUES
                    (
                        $1,
                        $2::jsonb,
                        $3::jsonb,
                        $4,
                        $5
                    )

                    RETURNING
                        id,
                        customer,
                        items,
                        total,
                        status,
                        created_at
                    `,
                    [

                        orderId,

                        JSON.stringify(
                            cleanCustomer
                        ),

                        JSON.stringify(
                            cleanItems
                        ),

                        total,

                        "PENDING"

                    ]
                );


            await client.query("COMMIT");


            const savedOrder =
                result.rows[0];


            res.status(201).json({

                success: true,

                message:
                    "Order created successfully.",

                order: {

                    id:
                        savedOrder.id,

                    customer:
                        savedOrder.customer,

                    items:
                        savedOrder.items,

                    total:
                        Number(
                            savedOrder.total
                        ),

                    status:
                        savedOrder.status,

                    createdAt:
                        savedOrder.created_at

                }

            });

        } catch (error) {

            try {
                await client.query("ROLLBACK");
            } catch {}

            console.error(
                "CREATE ORDER ERROR:",
                error
            );

            res.status(400).json({

                success: false,

                message:
                    error.message ||
                    "Could not create order."

            });

        } finally {

            client.release();
        }
    }
);

/* =====================================================
   ADMIN — GET ALL ORDERS
===================================================== */

app.get(
    "/api/orders",
    requireAdmin,
    async (req, res) => {

        try {

            const result =
                await pool.query(`
                    SELECT
                        id,
                        customer,
                        items,
                        total,
                        status,
                        created_at

                    FROM orders

                    ORDER BY
                        created_at DESC
                `);

            const orders =
                result.rows.map(order => ({

                    id:
                        order.id,

                    customer:
                        order.customer,

                    items:
                        order.items,

                    total:
                        Number(
                            order.total
                        ),

                    status:
                        order.status,

                    createdAt:
                        order.created_at

                }));

            res.json({

                success: true,

                count:
                    orders.length,

                orders

            });

        } catch (error) {

            console.error(
                "GET ORDERS ERROR:",
                error
            );

            res.status(500).json({

                success: false,

                message:
                    "Could not fetch orders."

            });
        }
    }
);

/* =====================================================
   ADMIN — SINGLE ORDER
===================================================== */

app.get(
    "/api/orders/:id",
    requireAdmin,
    async (req, res) => {

        try {

            const result =
                await pool.query(
                    `
                    SELECT
                        id,
                        customer,
                        items,
                        total,
                        status,
                        created_at

                    FROM orders

                    WHERE id = $1

                    LIMIT 1
                    `,
                    [
                        req.params.id
                    ]
                );

            if (
                result.rows.length === 0
            ) {

                return res.status(404).json({

                    success: false,

                    message:
                        "Order not found."

                });
            }

            const order =
                result.rows[0];

            res.json({

                success: true,

                order: {

                    id:
                        order.id,

                    customer:
                        order.customer,

                    items:
                        order.items,

                    total:
                        Number(
                            order.total
                        ),

                    status:
                        order.status,

                    createdAt:
                        order.created_at

                }

            });

        } catch (error) {

            console.error(error);

            res.status(500).json({

                success: false,

                message:
                    "Could not fetch order."

            });
        }
    }
);

/* =====================================================
   ADMIN — UPDATE ORDER STATUS
===================================================== */

app.patch(
    "/api/orders/:id/status",
    requireAdmin,
    async (req, res) => {

        try {

            const {
                status
            } = req.body;

            const allowedStatuses = [

                "PENDING",

                "CONFIRMED",

                "SHIPPED",

                "DELIVERED",

                "CANCELLED"

            ];

            if (
                !allowedStatuses.includes(
                    status
                )
            ) {

                return res.status(400).json({

                    success: false,

                    message:
                        "Invalid order status."

                });
            }

            const result =
                await pool.query(
                    `
                    UPDATE orders

                    SET status = $1

                    WHERE id = $2

                    RETURNING
                        id,
                        customer,
                        items,
                        total,
                        status,
                        created_at
                    `,
                    [
                        status,
                        req.params.id
                    ]
                );

            if (
                result.rows.length === 0
            ) {

                return res.status(404).json({

                    success: false,

                    message:
                        "Order not found."

                });
            }

            const order =
                result.rows[0];

            res.json({

                success: true,

                message:
                    "Order status updated successfully.",

                order: {

                    id:
                        order.id,

                    customer:
                        order.customer,

                    items:
                        order.items,

                    total:
                        Number(
                            order.total
                        ),

                    status:
                        order.status,

                    createdAt:
                        order.created_at

                }

            });

        } catch (error) {

            console.error(
                "UPDATE STATUS ERROR:",
                error
            );

            res.status(500).json({

                success: false,

                message:
                    "Could not update order status."

            });
        }
    }
);

/* =====================================================
   LIVE VISITOR TRACKING
===================================================== */

app.post(
    "/api/visitors/heartbeat",
    async (req, res) => {

        try {

            const visitorId =
                String(
                    req.body?.visitorId || ""
                ).trim();

            const page =
                String(
                    req.body?.page || "/"
                ).trim();

            if (!visitorId) {

                return res.status(400).json({

                    success: false,

                    message:
                        "visitorId is required."

                });
            }

            const userAgent =
                req.headers[
                    "user-agent"
                ] || "";

            const rawIp =
                req.headers[
                    "x-forwarded-for"
                ] ||
                req.socket.remoteAddress ||
                "";

            const ipHash =
                crypto
                    .createHash("sha256")
                    .update(
                        String(rawIp)
                    )
                    .digest("hex");

            await pool.query(
                `
                INSERT INTO visitors
                (
                    visitor_id,
                    page,
                    ip_hash,
                    user_agent,
                    last_seen
                )

                VALUES
                (
                    $1,
                    $2,
                    $3,
                    $4,
                    NOW()
                )

                ON CONFLICT
                (
                    visitor_id
                )

                DO UPDATE SET

                    page = EXCLUDED.page,

                    ip_hash = EXCLUDED.ip_hash,

                    user_agent =
                        EXCLUDED.user_agent,

                    last_seen = NOW()
                `,
                [

                    visitorId,

                    page,

                    ipHash,

                    userAgent

                ]
            );

            res.json({

                success: true

            });

        } catch (error) {

            console.error(
                "VISITOR HEARTBEAT ERROR:",
                error
            );

            res.status(500).json({

                success: false

            });
        }
    }
);

/* =====================================================
   CART TRACKING
===================================================== */

app.post(
    "/api/visitor/cart",
    async (req, res) => {

        try {

            const visitorId =
                String(
                    req.body?.visitorId || ""
                ).trim();

            const items =
                Array.isArray(
                    req.body?.items
                )
                    ? req.body.items
                    : [];

            if (!visitorId) {

                return res.status(400).json({

                    success: false,

                    message:
                        "visitorId is required."

                });
            }

            const cleanItems =
                items.map(item => ({

                    id:
                        Number(item.id),

                    name:
                        String(
                            item.name || ""
                        ),

                    price:
                        Number(
                            item.price
                        ) || 0,

                    quantity:
                        Math.max(
                            1,
                            Number(
                                item.quantity
                            ) || 1
                        ),

                    image:
                        String(
                            item.image || ""
                        )

                }));

            const total =
                cleanItems.reduce(
                    (sum, item) =>
                        sum +
                        item.price *
                        item.quantity,
                    0
                );

            await pool.query(
                `
                INSERT INTO cart_sessions
                (
                    visitor_id,
                    items,
                    total,
                    last_seen
                )

                VALUES
                (
                    $1,
                    $2::jsonb,
                    $3,
                    NOW()
                )

                ON CONFLICT
                (
                    visitor_id
                )

                DO UPDATE SET

                    items =
                        EXCLUDED.items,

                    total =
                        EXCLUDED.total,

                    last_seen =
                        NOW()
                `,
                [

                    visitorId,

                    JSON.stringify(
                        cleanItems
                    ),

                    total

                ]
            );

            res.json({

                success: true

            });

        } catch (error) {

            console.error(
                "CART TRACKING ERROR:",
                error
            );

            res.status(500).json({

                success: false

            });
        }
    }
);

/* =====================================================
   ADMIN DASHBOARD
===================================================== */

app.get(
    "/api/admin/dashboard",
    requireAdmin,
    async (req, res) => {

        try {

            const [
                productsResult,
                ordersResult,
                pendingResult,
                visitorsResult,
                cartsResult
            ] = await Promise.all([

                pool.query(`
                    SELECT COUNT(*) AS count
                    FROM products
                `),

                pool.query(`
                    SELECT COUNT(*) AS count
                    FROM orders
                `),

                pool.query(`
                    SELECT COUNT(*) AS count
                    FROM orders
                    WHERE status = 'PENDING'
                `),

                pool.query(`
                    SELECT COUNT(*) AS count
                    FROM visitors
                    WHERE last_seen >
                        NOW() - INTERVAL '60 seconds'
                `),

                pool.query(`
                    SELECT COUNT(*) AS count
                    FROM cart_sessions
                    WHERE jsonb_array_length(items) > 0
                    AND last_seen >
                        NOW() - INTERVAL '30 minutes'
                `)

            ]);

            res.json({

                success: true,

                dashboard: {

                    totalProducts:
                        Number(
                            productsResult
                                .rows[0]
                                .count
                        ),

                    totalOrders:
                        Number(
                            ordersResult
                                .rows[0]
                                .count
                        ),

                    pendingOrders:
                        Number(
                            pendingResult
                                .rows[0]
                                .count
                        ),

                    liveVisitors:
                        Number(
                            visitorsResult
                                .rows[0]
                                .count
                        ),

                    activeCarts:
                        Number(
                            cartsResult
                                .rows[0]
                                .count
                        )

                }

            });

        } catch (error) {

            console.error(
                "DASHBOARD ERROR:",
                error
            );

            res.status(500).json({

                success: false,

                message:
                    "Could not load dashboard."

            });
        }
    }
);

/* =====================================================
   ADMIN — LIVE VISITORS
===================================================== */

app.get(
    "/api/admin/visitors",
    requireAdmin,
    async (req, res) => {

        try {

            const result =
                await pool.query(`
                    SELECT
                        visitor_id,
                        page,
                        user_agent,
                        last_seen,
                        created_at

                    FROM visitors

                    WHERE last_seen >
                        NOW() - INTERVAL '60 seconds'

                    ORDER BY
                        last_seen DESC
                `);

            res.json({

                success: true,

                count:
                    result.rows.length,

                visitors:
                    result.rows

            });

        } catch (error) {

            console.error(error);

            res.status(500).json({

                success: false,

                message:
                    "Could not fetch visitors."

            });
        }
    }
);

/* =====================================================
   ADMIN — ACTIVE CARTS
===================================================== */

app.get(
    "/api/admin/carts",
    requireAdmin,
    async (req, res) => {

        try {

            const result =
                await pool.query(`
                    SELECT
                        visitor_id,
                        items,
                        total,
                        last_seen,
                        created_at

                    FROM cart_sessions

                    WHERE
                        jsonb_array_length(items) > 0

                    AND last_seen >
                        NOW() - INTERVAL '30 minutes'

                    ORDER BY
                        last_seen DESC
                `);

            const carts =
                result.rows.map(cart => ({

                    visitorId:
                        cart.visitor_id,

                    items:
                        cart.items,

                    total:
                        Number(
                            cart.total
                        ),

                    lastSeen:
                        cart.last_seen,

                    createdAt:
                        cart.created_at

                }));

            res.json({

                success: true,

                count:
                    carts.length,

                carts

            });

        } catch (error) {

            console.error(error);

            res.status(500).json({

                success: false,

                message:
                    "Could not fetch carts."

            });
        }
    }
);

/* =====================================================
   CLEAN OLD VISITORS / CARTS
===================================================== */

async function cleanupTracking() {

    try {

        await pool.query(`
            DELETE FROM visitors

            WHERE last_seen <
                NOW() - INTERVAL '24 hours'
        `);

        await pool.query(`
            DELETE FROM cart_sessions

            WHERE last_seen <
                NOW() - INTERVAL '7 days'
        `);

    } catch (error) {

        console.error(
            "TRACKING CLEANUP ERROR:",
            error.message
        );
    }
}

setInterval(
    cleanupTracking,
    60 * 60 * 1000
);


/* =====================================================
   START SERVER
===================================================== */

async function startServer() {

    await initializeDatabase();

    app.listen(
        PORT,
        "0.0.0.0",
        () => {

            console.log(
                `HIDDEN YOUTH BACKEND RUNNING → PORT ${PORT}`
            );

            console.log(
                "DATABASE: POSTGRESQL"
            );

            console.log(
                "PRODUCT MANAGEMENT: READY"
            );

            console.log(
                "STOCK SYSTEM: READY"
            );

            console.log(
                "LIVE VISITOR TRACKING: READY"
            );

            console.log(
                "CART TRACKING: READY"
            );
        }
    );
}

startServer();
