import express from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import db from '../db.js';
import { authenticate } from '../middleware/auth.js';
import dotenv from 'dotenv';
dotenv.config();

const router = express.Router();
const JWT_SECRET = process.env.JWT_SECRET;
const JWT_EXPIRE = process.env.JWT_EXPIRE || '7d';

// Register
router.post('/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    if (!username || !email || !password) {
      return res.status(400).json({ error: 'Please provide username, email and password' });
    }

    // Check existing user
    db.get('SELECT id FROM users WHERE email = ? OR username = ?', [email, username], async (err, row) => {
      if (err) return res.status(500).json({ error: err.message });
      if (row) return res.status(409).json({ error: 'Username or email already exists' });

      const hashedPassword = await bcrypt.hash(password, 10);
      db.run(
        'INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
        [username, email, hashedPassword],
        function (err) {
          if (err) return res.status(500).json({ error: err.message });

          const userId = this.lastID;
          // Create user_points entry
          db.run('INSERT INTO user_points (user_id) VALUES (?)', [userId]);

          const token = jwt.sign({ userId, email }, JWT_SECRET, { expiresIn: JWT_EXPIRE });
          res.status(201).json({
            success: true,
            token,
            user: { id: userId, username, email, preferred_language: 'en' }
          });
        }
      );
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Login
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'Please provide email and password' });
    }

    db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
      if (err) return res.status(500).json({ error: err.message });
      if (!user) return res.status(401).json({ error: 'Invalid credentials' });

      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) return res.status(401).json({ error: 'Invalid credentials' });

      const token = jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET, { expiresIn: JWT_EXPIRE });
      res.json({
        success: true,
        token,
        user: {
          id: user.id,
          username: user.username,
          email: user.email,
          preferred_language: user.preferred_language,
          alarm_enabled: user.alarm_enabled,
          created_at: user.created_at
        }
      });
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get current user
router.get('/me', authenticate, (req, res) => {
  db.get('SELECT id, username, email, preferred_language, alarm_enabled, created_at FROM users WHERE id = ?', [req.userId], (err, user) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json({ user });
  });
});

export default router;