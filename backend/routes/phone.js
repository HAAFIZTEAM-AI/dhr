import express from 'express';
import db from '../db.js';
import { authenticate } from '../middleware/auth.js';

const router = express.Router();

// Normalize Pakistani phone numbers to a consistent local format (0XXXXXXXXXX),
// matching ai-service/analyzers/phone_analyzer.py's normalize_phone, so the
// same number reported in different formats (+92..., 92..., 03...) maps to a
// single phone_reputation row instead of several inconsistent ones.
function normalizePhone(phone) {
  let normalized = String(phone).replace(/[\s\-()]/g, '');
  if (normalized.startsWith('+92')) {
    normalized = '0' + normalized.slice(3);
  } else if (normalized.startsWith('92')) {
    normalized = '0' + normalized.slice(2);
  }
  return normalized;
}

// GET /api/phone/:number - public phone lookup
router.get('/:number', (req, res) => {
  const number = normalizePhone(req.params.number);
  db.get('SELECT * FROM phone_reputation WHERE phone_number = ?', [number], (err, row) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!row) {
      return res.json({
        phone_number: number,
        reputation_score: 10,
        report_count: 0,
        scam_types: [],
        last_reported: null,
        risk_level: 'low'
      });
    }
    const riskLevel = row.risk_score >= 80 ? 'critical' : row.risk_score >= 60 ? 'high' : row.risk_score >= 30 ? 'medium' : 'low';
    res.json({
      phone_number: row.phone_number,
      reputation_score: row.risk_score,
      report_count: row.report_count,
      scam_types: row.scam_types ? row.scam_types.split(',') : [],
      last_reported: row.last_reported,
      risk_level: riskLevel
    });
  });
});

// POST /api/phone/report - report a number
router.post('/report', authenticate, (req, res) => {
  const { scam_type, notes } = req.body;
  if (!req.body.phone_number) return res.status(400).json({ error: 'Phone number required' });
  const phone_number = normalizePhone(req.body.phone_number);

  db.get('SELECT * FROM phone_reputation WHERE phone_number = ?', [phone_number], (err, row) => {
    if (err) return res.status(500).json({ error: err.message });
    if (row) {
      const newCount = row.report_count + 1;
      const newScore = Math.min(newCount * 2, 100);
      const types = row.scam_types ? row.scam_types.split(',') : [];
      if (scam_type && !types.includes(scam_type)) types.push(scam_type);
      db.run(
        'UPDATE phone_reputation SET report_count = ?, risk_score = ?, scam_types = ?, last_reported = CURRENT_TIMESTAMP WHERE id = ?',
        [newCount, newScore, types.join(','), row.id],
        function (err) {
          if (err) return res.status(500).json({ error: err.message });
          res.json({ success: true, new_report_count: newCount });
        }
      );
    } else {
      db.run(
        'INSERT INTO phone_reputation (phone_number, report_count, risk_score, scam_types) VALUES (?, 1, 20, ?)',
        [phone_number, scam_type || 'unknown'],
        function (err) {
          if (err) return res.status(500).json({ error: err.message });
          res.json({ success: true, new_report_count: 1 });
        }
      );
    }
  });
});

export default router;