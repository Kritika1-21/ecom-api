const express = require('express');
const mysql = require('mysql');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const cors = require('cors');
const dotenv = require('dotenv');

dotenv.config();

const app = express();
const port = process.env.PORT || 3000;

// Middleware
app.use(bodyParser.json());
app.use(cors());

// MySQL Connection
const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DATABASE_NAME
});

db.connect(err => {
    if (err) throw err;
    console.log('MySQL connected...');
});

// Signup API
app.post('/signup', async (req, res) => {
    const { username, email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);

    const sql = 'INSERT INTO users (username, email, password) VALUES (?, ?, ?)';
    db.query(sql, [username, email, hashedPassword], (err, result) => {
        if (err) {
            return res.status(500).send({ message: 'User registration failed', error: err });
        }
        res.status(201).send({ message: 'User registered successfully' });
    });
});

// Login API
app.post('/login', (req, res) => {
    const { email, password } = req.body;

    const sql = 'SELECT * FROM users WHERE email = ?';
    db.query(sql, [email], async (err, result) => {
        if (err) throw err;

        if (result.length === 0) {
            return res.status(404).send({ message: 'User not found' });
        }

        const user = result[0];
        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
            return res.status(400).send({ message: 'Invalid credentials' });
        }

        const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.status(200).send({ message: 'Login successful', token });
    });
});

app.get('/products', (req, res) => {
    const sql = 'SELECT * FROM products';
    db.query(sql, (err, results) => {
        if (err) throw err;
        res.json(results);
    });
});

app.get('/products/:id', (req, res) => {
    const sql = 'SELECT * FROM products WHERE id = ?';
    db.query(sql, [req.params.id], (err, result) => {
        if (err) throw err;
        res.json(result[0]); // Return the first and only product
    });
});

app.post('/place-order', (req, res) => {
    const { userId, cartItems, total } = req.body;

    // Insert into orders table
    const orderQuery = 'INSERT INTO orders (user_id, total) VALUES (?, ?)';
    db.query(orderQuery, [userId, total], (err, result) => {
        if (err) {
            return res.status(500).json({ error: 'Failed to place order' });
        }

        const orderId = result.insertId;

        // Insert each cart item into order_items table
        const orderItemsQuery = 'INSERT INTO order_items (order_id, product_name, price, quantity) VALUES ?';
        const orderItemsData = cartItems.map(item => [orderId, item.name, item.price, item.quantity]);

        db.query(orderItemsQuery, [orderItemsData], (err, result) => {
            if (err) {
                return res.status(500).json({ error: 'Failed to save order items' });
            }
            res.status(200).json({ message: 'Order placed successfully', orderId });
        });
    });
});

// Start server
app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});
