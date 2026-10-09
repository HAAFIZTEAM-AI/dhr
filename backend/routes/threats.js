import express from 'express';
import db from '../db.js';
import { authenticate } from '../middleware/auth.js';

const router = express.Router();

// GET /api/threats - public feed
router.get('/', (req, res) => {
  const { severity, type, city, page = 1, limit = 20 } = req.query;
  const offset = (page - 1) * limit;
  let where = '1=1';
  const params = [];
  if (severity) { where += ' AND severity = ?'; params.push(severity); }
  if (type) { where += ' AND type = ?'; params.push(type); }
  if (city) { where += ' AND city = ?'; params.push(city); }
  db.all(`SELECT * FROM threats WHERE ${where} ORDER BY created_at DESC LIMIT ? OFFSET ?`, [...params, limit, offset], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    db.get(`SELECT COUNT(*) as total FROM threats WHERE ${where}`, params, (err, countRow) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ threats: rows, total: countRow.total, page: Number(page) });
    });
  });
});

// GET /api/threats/stats
router.get('/stats', (req, res) => {
  db.all(`SELECT severity, COUNT(*) as count FROM threats GROUP BY severity`, (err, bySeverity) => {
    if (err) return res.status(500).json({ error: err.message });
    db.get('SELECT COUNT(*) as total FROM threats', (err, totalRow) => {
      if (err) return res.status(500).json({ error: err.message });
      db.get('SELECT COUNT(*) as new_today FROM threats WHERE created_at >= date("now","start of day")', (err, todayRow) => {
        if (err) return res.status(500).json({ error: err.message });
        const by_severity = {};
        bySeverity.forEach(r => by_severity[r.severity] = r.count);
        res.json({
          total: totalRow.total,
          new_today: todayRow.new_today,
          by_severity
        });
      });
    });
  });
});

// POST /api/threats (optional auth)
router.post('/', authenticate, (req, res) => {
  const { title, description, type, severity = 'medium', city } = req.body;
  db.run(
    'INSERT INTO threats (title, description, type, severity, city, reported_by) VALUES (?, ?, ?, ?, ?, ?)',
    [title, description, type, severity, city, req.userId],
    function (err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ success: true, threat_id: this.lastID });
    }
  );
});

export default router;