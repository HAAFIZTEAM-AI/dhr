import express from 'express';
import db from '../db.js';
import { authenticate } from '../middleware/auth.js';

const router = express.Router();

// GET /api/history
router.get('/', authenticate, (req, res) => {
  const { page = 1, limit = 20, search } = req.query;
  const offset = (page - 1) * limit;
  const userId = req.userId;
  let where = 'user_id = ?';
  const params = [userId];
  if (search) {
    where += ' AND (input LIKE ? OR result LIKE ?)';
    params.push(`%${search}%`, `%${search}%`);
  }
  db.all(`SELECT * FROM history WHERE ${where} ORDER BY created_at DESC LIMIT ? OFFSET ?`, [...params, limit, offset], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    db.get(`SELECT COUNT(*) as total FROM history WHERE ${where}`, params, (err, countRow) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ history: rows, total: countRow.total });
    });
  });
});

// DELETE /api/history/:id
router.delete('/:id', authenticate, (req, res) => {
  db.run('DELETE FROM history WHERE id = ? AND user_id = ?', [req.params.id, req.userId], function (err) {
    if (err) return res.status(500).json({ error: err.message });
    if (this.changes === 0) return res.status(404).json({ error: 'Entry not found' });
    res.json({ success: true });
  });
});

// DELETE /api/history - clear all
router.delete('/', authenticate, (req, res) => {
  db.run('DELETE FROM history WHERE user_id = ?', [req.userId], function (err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ success: true, deleted_count: this.changes });
  });
});

// GET /api/history/export - CSV
router.get('/export', authenticate, (req, res) => {
  db.all('SELECT * FROM history WHERE user_id = ? ORDER BY created_at DESC', [req.userId], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    const escapeCsv = (val) => String(val ?? '').replace(/"/g, '""');
    let csv = 'id,input,input_type,result,confidence,is_scam,risk_factors,language,created_at\n';
    rows.forEach(r => {
      csv += `${r.id},"${escapeCsv(r.input)}",${r.input_type},${r.result},${r.confidence},${r.is_scam},"${escapeCsv(r.risk_factors)}",${r.language},${r.created_at}\n`;
    });
    res.header('Content-Type', 'text/csv');
    res.attachment('haafiz_history.csv');
    res.send(csv);
  });
});

export default router;