const express = require("express");
const cors = require("cors");
const fs = require("fs");
const path = require("path");

const app = express();
const PORT = 3000;

app.use(cors());
app.use(express.json());

/* =====================================================
   HIDDEN YOUTH PRODUCTS
===================================================== */

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


/* =====================================================
   ORDERS FILE
===================================================== */

const ordersFile = path.join(__dirname, "orders.json");


/* =====================================================
   LOAD ORDERS
===================================================== */

function loadOrders() {

    try {

        if (!fs.existsSync(ordersFile)) {

            fs.writeFileSync(
                ordersFile,
                "[]",
                "utf8"
            );

            return [];
        }

        const data =
            fs.readFileSync(
                ordersFile,
                "utf8"
            );

        if (!data.trim()) {
            return [];
        }

        const parsed =
            JSON.parse(data);

        if (Array.isArray(parsed)) {
            return parsed;
        }

        return [];

    } catch (error) {

        console.error(
            "ORDERS LOAD ERROR:",
            error.message
        );

        return [];
    }
}


/* =====================================================
   SAVE ORDERS
===================================================== */

function saveOrders() {

    try {

        fs.writeFileSync(
            ordersFile,
            JSON.stringify(orders, null, 2),
            "utf8"
        );

        console.log(
            "ORDER SAVED TO:",
            ordersFile
        );

        return true;

    } catch (error) {

        console.error(
            "ORDERS SAVE ERROR:",
            error
        );

        return false;
    }
}


/* =====================================================
   ORDERS
===================================================== */

let orders = loadOrders();


/* =====================================================
   HOME
===================================================== */

app.get("/", (req, res) => {

    res.json({

        brand: "Hidden Youth",

        status: "ONLINE",

        message:
            "Welcome to the Hidden Youth world.",

        orders:
            orders.length,

        products:
            products.length

    });

});


/* =====================================================
   GET ALL PRODUCTS
===================================================== */

app.get("/api/products", (req, res) => {

    res.json({

        success: true,

        count:
            products.length,

        products:
            products

    });

});


/* =====================================================
   GET SINGLE PRODUCT
===================================================== */

app.get("/api/products/:id", (req, res) => {

    const id =
        Number(req.params.id);

    const product =
        products.find(
            item =>
                item.id === id
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

        product:
            product

    });

});


/* =====================================================
   GET PRODUCTS BY CATEGORY
===================================================== */

app.get(
    "/api/category/:category",
    (req, res) => {

        const category =
            req.params.category
                .toLowerCase();

        const result =
            products.filter(
                product =>
                    product.category
                        .toLowerCase() ===
                    category
            );

        res.json({

            success: true,

            count:
                result.length,

            products:
                result

        });

    }
);


/* =====================================================
   CREATE ORDER
===================================================== */

app.post("/api/orders", (req, res) => {

    try {

        const {
            customer,
            items
        } = req.body;


        /* ==============================
           CHECK CUSTOMER
        ============================== */

        if (!customer) {

            return res.status(400).json({

                success: false,

                message:
                    "Customer details are required."

            });

        }


        /* ==============================
           CHECK ITEMS
        ============================== */

        if (
            !Array.isArray(items) ||
            items.length === 0
        ) {

            return res.status(400).json({

                success: false,

                message:
                    "At least one product is required."

            });

        }


        /* ==============================
           CUSTOMER DATA
        ============================== */

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


        /* ==============================
           PREPARE PRODUCTS
        ============================== */

        const cleanItems =
            items.map(item => {

                const product =
                    products.find(
                        product =>
                            product.id ===
                            Number(item.id)
                    );

                if (!product) {

                    throw new Error(
                        "Invalid product ID: " +
                        item.id
                    );

                }


                const quantity =
                    Number(
                        item.quantity
                    );


                if (
                    !Number.isInteger(quantity) ||
                    quantity <= 0
                ) {

                    throw new Error(
                        "Invalid quantity for " +
                        product.name
                    );

                }


                return {

                    id:
                        product.id,

                    name:
                        product.name,

                    price:
                        Number(product.price),

                    quantity:
                        quantity,

                    image:
                        product.image

                };

            });


        /* ==============================
           TOTAL
        ============================== */

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


        /* ==============================
           ORDER ID
        ============================== */

        const order = {

            id:
                "HY-" +
                Date.now(),

            customer: {

                name:
                    name,

                phone:
                    phone,

                address:
                    address,

                city:
                    city

            },

            items:
                cleanItems,

            total:
                total,

            status:
                "PENDING",

            createdAt:
                new Date().toISOString()

        };


        /* ==============================
           ADD ORDER
        ============================== */

        orders.push(order);


        /* ==============================
           SAVE TO JSON
        ============================== */

        const saved =
            saveOrders();


        if (!saved) {

            orders.pop();

            return res.status(500).json({

                success: false,

                message:
                    "Order received but could not be saved."

            });

        }


        /* ==============================
           TERMINAL LOG
        ============================== */

        console.log("");

        console.log(
            "======================================"
        );

        console.log(
            "      NEW HIDDEN YOUTH ORDER"
        );

        console.log(
            "======================================"
        );

        console.log(
            "ORDER ID:",
            order.id
        );

        console.log(
            "CUSTOMER:",
            order.customer.name
        );

        console.log(
            "PHONE:",
            order.customer.phone
        );

        console.log(
            "CITY:",
            order.customer.city
        );

        console.log(
            "TOTAL: Rs.",
            order.total.toLocaleString()
        );

        console.log(
            "SAVED ORDERS:",
            orders.length
        );

        console.log(
            "FILE:",
            ordersFile
        );

        console.log(
            "======================================"
        );

        console.log("");


        /* ==============================
           RESPONSE
        ============================== */

        return res.status(201).json({

            success:
                true,

            message:
                "Order created successfully.",

            order:
                order

        });

    } catch (error) {

        console.error(
            "ORDER CREATION ERROR:",
            error
        );

        return res.status(400).json({

            success:
                false,

            message:
                error.message ||
                "Unable to create order."

        });

    }

});


/* =====================================================
   GET ALL ORDERS
===================================================== */

app.get("/api/orders", (req, res) => {

    res.json({

        success:
            true,

        count:
            orders.length,

        orders:
            orders

    });

});


/* =====================================================
   GET SINGLE ORDER
===================================================== */

app.get(
    "/api/orders/:id",
    (req, res) => {

        const order =
            orders.find(
                item =>
                    item.id ===
                    req.params.id
            );

        if (!order) {

            return res.status(404).json({

                success:
                    false,

                message:
                    "Order not found."

            });

        }

        res.json({

            success:
                true,

            order:
                order

        });

    }
);


/* =====================================================
   SERVER ERROR HANDLER
===================================================== */

app.use(
    (err, req, res, next) => {

        console.error(
            "SERVER ERROR:",
            err
        );

        res.status(500).json({

            success:
                false,

            message:
                "Internal server error."

        });

    }
);


/* =====================================================
   START SERVER
===================================================== */

app.listen(
    PORT,
    () => {

        console.log("");

        console.log(
            "======================================"
        );

        console.log(
            "      HIDDEN YOUTH BACKEND"
        );

        console.log(
            "======================================"
        );

        console.log(
            `Server: http://localhost:${PORT}`
        );

        console.log(
            `Products: ${products.length}`
        );

        console.log(
            `Saved Orders: ${orders.length}`
        );

        console.log(
            "Orders File:",
            ordersFile
        );

        console.log(
            "======================================"
        );

        console.log("");

    }
);