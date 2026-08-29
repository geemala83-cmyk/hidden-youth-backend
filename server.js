const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;

/* ==============================
   MIDDLEWARE
============================== */

app.use(cors());
app.use(express.json());


/* ==============================
   POSTGRESQL
============================== */

if (!process.env.DATABASE_URL) {
    console.error("DATABASE_URL is not configured.");
    process.exit(1);
}

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    connectionTimeoutMillis: 10000
});


/* ==============================
   ADMIN SECURITY
============================== */

const ADMIN_USERNAME =
    process.env.ADMIN_USERNAME;

const ADMIN_PASSWORD =
    process.env.ADMIN_PASSWORD;

if (!ADMIN_USERNAME || !ADMIN_PASSWORD) {

    console.error(
        "ADMIN_USERNAME or ADMIN_PASSWORD is not configured."
    );

    process.exit(1);
}


/*
   Temporary login sessions.

   Token is stored in server memory.
   When Railway restarts/redeploys,
   existing admin sessions expire.
*/

const adminSessions = new Map();


/* ==============================
   CREATE ADMIN TOKEN
============================== */

function createAdminToken() {

    return crypto.randomBytes(32).toString("hex");

}


/* ==============================
   ADMIN AUTH MIDDLEWARE
============================== */

function requireAdmin(req, res, next) {

    const authorization =
        req.headers.authorization || "";


    if (!authorization.startsWith("Bearer ")) {

        return res.status(401).json({

            success: false,

            message:
                "Admin authentication required."

        });

    }


    const token =
        authorization.substring(7).trim();


    if (!token || !adminSessions.has(token)) {

        return res.status(401).json({

            success: false,

            message:
                "Invalid or expired admin session."

        });

    }


    next();

}


/* ==============================
   CREATE ORDERS TABLE
============================== */

async function initializeDatabase() {

    try {

        await pool.query(`
            CREATE TABLE IF NOT EXISTS orders (
                id VARCHAR(100) PRIMARY KEY,
                customer JSONB NOT NULL,
                items JSONB NOT NULL,
                total NUMERIC(12, 2) NOT NULL DEFAULT 0,
                status VARCHAR(50) NOT NULL DEFAULT 'PENDING',
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );
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


/* ==============================
   HIDDEN YOUTH PRODUCTS
============================== */

const products = [

    {
        id: 1,
        name: "GYM FIT — 01",
        category: "Gym Fit",
        description: "Performance / Movement",
        price: 4990,
        image: "gym.fit.jpg"
    },

    {
        id: 2,
        name: "GYM FIT — 02",
        category: "Gym Fit",
        description: "Performance / Movement",
        price: 4990,
        image: "gym.fit2.jpg"
    },

    {
        id: 3,
        name: "GYM FIT — 03",
        category: "Gym Fit",
        description: "Performance / Movement",
        price: 4990,
        image: "gym.fit3.jpg"
    },

    {
        id: 4,
        name: "GYM FIT — 04",
        category: "Gym Fit",
        description: "Performance / Movement",
        price: 4990,
        image: "gym.fit4.jpg"
    }

];


/* ==============================
   HOME / API STATUS
============================== */

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

    } catch (error) {

        res.status(500).json({

            brand: "Hidden Youth",

            status: "ONLINE",

            database: "DISCONNECTED",

            message:
                "Backend is running but database is unavailable."

        });

    }

});


/* ==============================
   ADMIN LOGIN
============================== */

app.post("/api/admin/login", (req, res) => {

    try {

        const username =
            String(
                req.body.username || ""
            ).trim();

        const password =
            String(
                req.body.password || ""
            );


        if (
            username !== ADMIN_USERNAME ||
            password !== ADMIN_PASSWORD
        ) {

            return res.status(401).json({

                success: false,

                message:
                    "Invalid username or password."

            });

        }


        const token =
            createAdminToken();


        adminSessions.set(
            token,
            {
                username: ADMIN_USERNAME,
                createdAt: Date.now()
            }
        );


        res.json({

            success: true,

            message:
                "Admin login successful.",

            token: token

        });


    } catch (error) {

        console.error(
            "ADMIN LOGIN ERROR:",
            error
        );

        res.status(500).json({

            success: false,

            message:
                "Login failed."

        });

    }

});


/* ==============================
   ADMIN LOGOUT
============================== */

app.post(
    "/api/admin/logout",
    requireAdmin,
    (req, res) => {

        const authorization =
            req.headers.authorization || "";

        const token =
            authorization.substring(7).trim();


        adminSessions.delete(token);


        res.json({

            success: true,

            message:
                "Admin logged out successfully."

        });

    }
);


/* ==============================
   CHECK ADMIN SESSION
============================== */

app.get(
    "/api/admin/me",
    requireAdmin,
    (req, res) => {

        res.json({

            success: true,

            authenticated: true

        });

    }
);


/* ==============================
   GET ALL PRODUCTS
============================== */

app.get("/api/products", (req, res) => {

    res.json({

        success: true,

        count: products.length,

        products: products

    });

});


/* ==============================
   GET SINGLE PRODUCT
============================== */

app.get("/api/products/:id", (req, res) => {

    const id =
        Number(req.params.id);


    const product =
        products.find(
            item => item.id === id
        );


    if (!product) {

        return res.status(404).json({

            success: false,

            message:
                "Product not found."

        });

    }


    res.json({

        success: true,

        product: product

    });

});


/* ==============================
   GET PRODUCTS BY CATEGORY
============================== */

app.get(
    "/api/category/:category",
    (req, res) => {

        const category =
            req.params.category.toLowerCase();


        const result =
            products.filter(
                product =>
                    product.category.toLowerCase() ===
                    category
            );


        res.json({

            success: true,

            count: result.length,

            products: result

        });

    }
);


/* ==============================
   CREATE ORDER
   PUBLIC CUSTOMER API
============================== */

app.post(
    "/api/orders",
    async (req, res) => {

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


            /* CUSTOMER */

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


            /* ORDER ITEMS */

            const cleanItems =
                items.map(item => {

                    const price =
                        Number(item.price) || 0;


                    const quantity =
                        Math.max(
                            1,
                            Number(item.quantity) || 1
                        );


                    return {

                        id: item.id,

                        name:
                            String(
                                item.name || ""
                            ),

                        price: price,

                        quantity: quantity,

                        image:
                            String(
                                item.image || ""
                            )

                    };

                });


            /* TOTAL */

            const total =
                cleanItems.reduce(
                    (sum, item) => {

                        return sum +
                            (
                                item.price *
                                item.quantity
                            );

                    },
                    0
                );


            /* ORDER ID */

            const orderId =
                "HY-" +
                Date.now() +
                "-" +
                Math.floor(
                    Math.random() * 1000
                );


            const cleanCustomer = {

                name: name,

                phone: phone,

                address: address,

                city: city

            };


            /* SAVE */

            const result =
                await pool.query(

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


            const savedOrder =
                result.rows[0];


            const order = {

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

            };


            res.status(201).json({

                success: true,

                message:
                    "Order created successfully.",

                order: order

            });


        } catch (error) {

            console.error(
                "CREATE ORDER ERROR:",
                error
            );


            res.status(500).json({

                success: false,

                message:
                    "Could not create order."

            });

        }

    }
);


/* ==============================
   GET ALL ORDERS
   ADMIN ONLY
============================== */

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

                    ORDER BY created_at DESC

                `);


            const formattedOrders =
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
                    formattedOrders.length,

                orders:
                    formattedOrders

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


/* ==============================
   GET SINGLE ORDER
   ADMIN ONLY
============================== */

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

                    [req.params.id]

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

            console.error(
                "GET SINGLE ORDER ERROR:",
                error
            );


            res.status(500).json({

                success: false,

                message:
                    "Could not fetch order."

            });

        }

    }
);


/* ==============================
   UPDATE ORDER STATUS
   ADMIN ONLY
============================== */

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


/* ==============================
   START SERVER
============================== */

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
                "ADMIN SECURITY: ENABLED"
            );

        }
    );

}


startServer();
