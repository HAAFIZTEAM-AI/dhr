import express from 'express';
import db from '../db.js';
import { authenticate } from '../middleware/auth.js';

const router = express.Router();

// GET /api/reports - get user's reports or all public (with pagination)
router.get('/', authenticate, (req, res) => {
  const { page = 1, limit = 20, type } = req.query;
  const offset = (page - 1) * limit;
  const userId = req.userId;
  let where = 'user_id = ?';
  const params = [userId];
  if (type) {
    where += ' AND content_type = ?';
    params.push(type);
  }
  db.all(`SELECT * FROM reports WHERE ${where} ORDER BY created_at DESC LIMIT ? OFFSET ?`, [...params, limit, offset], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    db.get(`SELECT COUNT(*) as total FROM reports WHERE ${where}`, params, (err, countRow) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ reports: rows, total: countRow.total, page: Number(page) });
    });
  });
});

// POST /api/reports
router.post('/', authenticate, (req, res) => {
  const { content, content_type = 'text', result, confidence, is_scam, language = 'en', phone_number, city } = req.body;
  db.run(
    `INSERT INTO reports (user_id, content, content_type, result, confidence, is_scam, language, phone_number, city)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [req.userId, content, content_type, result, confidence, is_scam, language, phone_number, city],
    function (err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ success: true, report_id: this.lastID });
    }
  );
});

// PUT /api/reports/:id
router.put('/:id', authenticate, (req, res) => {
  const { content, result, confidence } = req.body;
  db.run(
    'UPDATE reports SET content = COALESCE(?, content), result = COALESCE(?, result), confidence = COALESCE(?, confidence) WHERE id = ? AND user_id = ?',
    [content, result, confidence, req.params.id, req.userId],
    function (err) {
      if (err) return res.status(500).json({ error: err.message });
      if (this.changes === 0) return res.status(404).json({ error: 'Report not found' });
      res.json({ success: true });
    }
  );
});

// DELETE /api/reports/:id
router.delete('/:id', authenticate, (req, res) => {
  db.run('DELETE FROM reports WHERE id = ? AND user_id = ?', [req.params.id, req.userId], function (err) {
    if (err) return res.status(500).json({ error: err.message });
    if (this.changes === 0) return res.status(404).json({ error: 'Report not found' });
    res.json({ success: true });
  });
});

export default router;