const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(bodyParser.json());
app.use('/uploads', express.static('uploads'));

// MySQL connection
const db = mysql.createConnection({
    host: 'localhost',
    user: process.env.user,
    password: process.env.password,
    database: 'social_media'
});

db.connect((err) => {
    if (err) throw err;
    console.log('MySQL connected');
});


const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir, { recursive: true });
    console.log('✅ Uploads directory created');
}
app.use('/uploads', express.static(uploadDir));

// Multer setup for image uploads
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, uploadDir);
    },
    filename: (req, file, cb) => {
        cb(null, Date.now() + path.extname(file.originalname));
    }
});
const upload = multer({ storage });

// JWT secret key
const JWT_SECRET = process.env.JWT_SECRET;

// Middleware to authenticate JWT
const authenticateJWT = (req, res, next) => {
    const token = req.header('Authorization');
    if (!token) return res.status(401).json({ error: 'Access denied' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Invalid token' });
        req.user = user;
        next();
    });
};

// User registration
app.post('/api/register', async (req, res) => {
    const { username, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);

    const query = 'INSERT INTO users (username, password) VALUES (?, ?)';
    db.query(query, [username, hashedPassword], (err, results) => {
        if (err) return res.status(400).json({ error: 'Username already exists' });
        res.json({ id: results.insertId });
    });
});

// User login
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;

    const query = 'SELECT * FROM users WHERE username = ?';
    db.query(query, [username], async (err, results) => {
        if (err || results.length === 0) return res.status(400).json({ error: 'Invalid credentials' });

        const user = results[0];
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) return res.status(400).json({ error: 'Invalid credentials' });

        const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET);
        res.json({ token, username: user.username }); // ✅ Return username as well
    });
});


// Create a new post (with image upload)
app.post('/api/posts', authenticateJWT, upload.single('image'), (req, res) => {
    const { content } = req.body;
    const image_url = req.file ? `/uploads/${req.file.filename}` : '';
    const user_id = req.user.id;

    const query = 'INSERT INTO posts (user_id, content, image_url) VALUES (?, ?, ?)';
    db.query(query, [user_id, content, image_url], (err, results) => {
        if (err) throw err;
        res.json({ id: results.insertId });
    });
});

app.get('/api/posts', authenticateJWT, (req, res) => {
    const userId = req.user ? req.user.id : null;

    const query = `
        SELECT posts.*, users.username, 
        COUNT(comments.id) AS comment_count, 
        (SELECT COUNT(*) FROM likes WHERE likes.post_id = posts.id AND likes.user_id = ?) AS likedByUser
        FROM posts
        INNER JOIN users ON posts.user_id = users.id
        LEFT JOIN comments ON posts.id = comments.post_id
        GROUP BY posts.id
        ORDER BY (posts.likes + comment_count) DESC
    `;

    db.query(query, [userId], (err, results) => {
        if (err) throw err;
        res.json(results.map(post => ({
            ...post,
            likedByUser: post.likedByUser > 0 // Convert to boolean
        })));
    });
});

// Like/unlike a post
app.put('/api/posts/:id/like', authenticateJWT, (req, res) => {
    const postId = req.params.id;
    const userId = req.user.id;

    // Check if the user is the author of the post
    const checkAuthorQuery = 'SELECT user_id FROM posts WHERE id = ?';
    db.query(checkAuthorQuery, [postId], (err, results) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        if (results.length === 0) return res.status(404).json({ error: 'Post not found' });

        const postAuthorId = results[0].user_id;
        if (postAuthorId === userId) {
            return res.status(400).json({ error: "You cannot like your own post" });
        }

        // If not the author, proceed with liking the post
        const likeQuery = 'UPDATE posts SET likes = likes + 1 WHERE id = ?';
        db.query(likeQuery, [postId], (err) => {
            if (err) return res.status(500).json({ error: 'Failed to like post' });
            res.json({ success: true });
        });
    });
});


// Add a comment
app.post('/api/posts/:id/comments', authenticateJWT, (req, res) => {
    const postId = req.params.id;
    const { comment } = req.body;
    const userId = req.user.id;

    const query = 'INSERT INTO comments (post_id, user_id, comment) VALUES (?, ?, ?)';
    db.query(query, [postId, userId, comment], (err, results) => {
        if (err) throw err;
        res.json({ id: results.insertId });
    });
});

// Fetch a user's own posts
app.get('/api/my-posts', authenticateJWT, (req, res) => {
    const userId = req.user.id;

    const query = 'SELECT * FROM posts WHERE user_id = ?';
    db.query(query, [userId], (err, results) => {
        if (err) throw err;
        res.json(results);
    });
});

// Start the server
const PORT = 5000;
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});