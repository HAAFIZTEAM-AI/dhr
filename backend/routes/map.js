import express from 'express';
import db from '../db.js';

const router = express.Router();

// GET /api/map/hotspots
router.get('/hotspots', (req, res) => {
  db.all(`
    SELECT lr.city, lr.province, lr.latitude, lr.longitude, COUNT(*) as report_count,
           GROUP_CONCAT(DISTINCT t.type) as top_scam_types
    FROM location_reports lr
    JOIN threats t ON t.city = lr.city
    GROUP BY lr.city, lr.latitude, lr.longitude
  `, (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ hotspots: rows });
  });
});

// GET /api/map/city/:city
router.get('/city/:city', (req, res) => {
  const city = req.params.city;
  db.all('SELECT * FROM threats WHERE city = ? ORDER BY created_at DESC LIMIT 50', [city], (err, reports) => {
    if (err) return res.status(500).json({ error: err.message });
    db.get('SELECT COUNT(*) as total, COUNT(DISTINCT type) as types FROM threats WHERE city = ?', [city], (err, stats) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ city, reports, stats });
    });
  });
});

export default router;