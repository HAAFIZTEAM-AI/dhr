import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import dotenv from 'dotenv';
import rateLimit from 'express-rate-limit';
import { initDB } from './db.js';
import authRoutes from './routes/auth.js';
import scanRoutes from './routes/scan.js';
import voiceRoutes from './routes/voice.js';
import phoneRoutes from './routes/phone.js';
import websiteRoutes from './routes/website.js';
import reportsRoutes from './routes/reports.js';
import historyRoutes from './routes/history.js';
import threatsRoutes from './routes/threats.js';
import familyRoutes from './routes/family.js';
import gamificationRoutes from './routes/gamification.js';
import mapRoutes from './routes/map.js';
import { errorHandler } from './middleware/errorHandler.js';

dotenv.config();
const app = express();
const PORT = process.env.PORT || 3001;

initDB();

app.use(helmet());
app.use(cors({ origin: process.env.FRONTEND_URL || '*' }));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Rate limiter for general API
const apiLimiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW) || 15 * 60 * 1000,
  max: parseInt(process.env.RATE_LIMIT_MAX) || 1000, // <-- Increased to 1000 for dev
  message: 'Too many requests, please try again later.'
});

// Stricter limiter for auth routes to protect against brute-force login/register attempts
const authLimiter = rateLimit({
  windowMs: parseInt(process.env.AUTH_RATE_LIMIT_WINDOW) || 15 * 60 * 1000,
  max: parseInt(process.env.AUTH_RATE_LIMIT_MAX) || 20,
  message: 'Too many authentication attempts, please try again later.'
});

// Apply the stricter limiter to /api/auth, and the general limiter to the rest of /api
app.use('/api', (req, res, next) => {
  if (req.path.startsWith('/auth')) {
    authLimiter(req, res, next);
  } else {
    apiLimiter(req, res, next);
  }
});

// Routes
app.use('/api/auth', authRoutes);
app.use('/api/scan', scanRoutes);
app.use('/api/voice', voiceRoutes);
app.use('/api/phone', phoneRoutes);
app.use('/api/website', websiteRoutes);
app.use('/api/reports', reportsRoutes);
app.use('/api/history', historyRoutes);
app.use('/api/threats', threatsRoutes);
app.use('/api/family', familyRoutes);
app.use('/api/gamification', gamificationRoutes);
app.use('/api/map', mapRoutes);

app.get('/health', (req, res) => res.json({ status: 'ok' }));

app.use(errorHandler);

app.listen(PORT, () => {
  console.log(`HAAFIZ backend running on port ${PORT}`);
});