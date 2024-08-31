// File: app.js

const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const cors = require('cors');
const config = require('./config');

require('dotenv').config();

const app = express();
const port = process.env.PORT || 3000;

// Middleware
app.use(bodyParser.json());
app.use(cors());

// MySQL Connection
const db = mysql.createPool(config);

// MySQL Connection
db.getConnection((err, connection) => {
    if (err) {
        console.error('Error connecting to MySQL:', err);
        return;
    }
    console.log('Connected to MySQL');
});

// Signup API
app.post('/signup', async (req, res) => {
    try {
        const { username, email, password } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);

        const sql = 'INSERT INTO users (username, email, password) VALUES (?, ?, ?)';
        db.query(sql, [username, email, hashedPassword], (err, result) => {
            if (err) {
                console.error('Error inserting user:', err);
                return res.status(500).send({ message: 'User registration failed', error: err.message });
            }
            res.status(201).send({ message: 'User registered successfully' });
        });
    } catch (err) {
        console.error('Signup error:', err);
        res.status(500).send({ message: 'Internal server error', error: err.message });
    }
});

// Login API
app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        const sql = 'SELECT * FROM users WHERE email = ?';
        db.query(sql, [email], async (err, result) => {
            if (err) {
                console.error('Error during login query:', err);
                return res.status(500).send({ message: 'Internal server error', error: err.message });
            }

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
    } catch (err) {
        console.error('Login error:', err);
        res.status(500).send({ message: 'Internal server error', error: err.message });
    }
});

// Products API
app.get('/products', (req, res) => {
    const sql = 'SELECT * FROM products';
    db.query(sql, (err, results) => {
        if (err) {
            console.error('Error fetching products:', err);
            return res.status(500).send({ message: 'Failed to retrieve products', error: err.message });
        }
        res.json(results);
    });
});

// Single Product API
app.get('/products/:id', (req, res) => {
    const sql = 'SELECT * FROM products WHERE id = ?';
    db.query(sql, [req.params.id], (err, result) => {
        if (err) {
            console.error('Error fetching product:', err);
            return res.status(500).send({ message: 'Failed to retrieve product', error: err.message });
        }
        if (result.length === 0) {
            return res.status(404).send({ message: 'Product not found' });
        }
        res.json(result[0]);
    });
});

// Place Order API
app.post('/place-order', (req, res) => {
    const { userId, cartItems, total } = req.body;

    const orderQuery = 'INSERT INTO orders (user_id, total) VALUES (?, ?)';
    db.query(orderQuery, [userId, total], (err, result) => {
        if (err) {
            console.error('Error placing order:', err);
            return res.status(500).json({ error: 'Failed to place order', message: err.message });
        }

        const orderId = result.insertId;
        const orderItemsQuery = 'INSERT INTO order_items (order_id, product_name, price, quantity) VALUES ?';
        const orderItemsData = cartItems.map(item => [orderId, item.name, item.price, item.quantity]);

        db.query(orderItemsQuery, [orderItemsData], (err, result) => {
            if (err) {
                console.error('Error saving order items:', err);
                return res.status(500).json({ error: 'Failed to save order items', message: err.message });
            }
            res.status(200).json({ message: 'Order placed successfully', orderId });
        });
    });
});

// Start server
app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});

