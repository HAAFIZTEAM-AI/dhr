import express from 'express';
import multer from 'multer';
import axios from 'axios';
import { authenticate } from '../middleware/auth.js';
import dotenv from 'dotenv';
dotenv.config();

const router = express.Router();
const AI_URL = process.env.AI_SERVICE_URL || 'http://localhost:5001';
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 10 * 1024 * 1024 } });

router.post('/analyze', authenticate, upload.single('audio'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No audio file provided' });
    const audioBase64 = req.file.buffer.toString('base64');
    const language = req.body.language || 'en';
    const aiRes = await axios.post(`${AI_URL}/analyze/voice`, { audio_base64: audioBase64, language });
    res.json(aiRes.data);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Voice analysis failed' });
  }
});

export default router;