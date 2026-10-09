import express from 'express';
import axios from 'axios';
import { authenticate } from '../middleware/auth.js';
import dotenv from 'dotenv';
dotenv.config();

const router = express.Router();
const AI_URL = process.env.AI_SERVICE_URL || 'http://localhost:5001';

router.post('/crawl', authenticate, async (req, res) => {
  try {
    const { url } = req.body;
    if (!url) return res.status(400).json({ error: 'URL required' });
    const aiRes = await axios.post(`${AI_URL}/analyze/website`, { url });
    res.json(aiRes.data);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Website analysis failed' });
  }
});

export default router;