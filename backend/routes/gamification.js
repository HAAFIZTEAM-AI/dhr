import express from 'express';
import db from '../db.js';
import { authenticate } from '../middleware/auth.js';

const router = express.Router();

// GET /api/gamification/points
router.get('/points', authenticate, (req, res) => {
  db.get('SELECT * FROM user_points WHERE user_id = ?', [req.userId], (err, row) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!row) {
      db.run('INSERT INTO user_points (user_id) VALUES (?)', [req.userId]);
      return res.json({ total_points: 0, current_level: 1, next_level_points: 100, badges: [], login_streak: 0 });
    }
    const nextLevelPoints = row.current_level * 100;
    res.json({
      total_points: row.total_points,
      current_level: row.current_level,
      next_level_points: nextLevelPoints,
      badges: JSON.parse(row.badges || '[]'),
      login_streak: row.login_streak
    });
  });
});

// POST /api/gamification/award
router.post('/award', authenticate, (req, res) => {
  const { points = 0, badge, reason } = req.body;
  db.get('SELECT * FROM user_points WHERE user_id = ?', [req.userId], (err, row) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!row) {
      db.run('INSERT INTO user_points (user_id) VALUES (?)', [req.userId]);
      row = { total_points: 0, current_level: 1, badges: '[]' };
    }
    const newTotal = row.total_points + points;
    const newLevel = Math.floor(newTotal / 100) + 1;
    let badges = JSON.parse(row.badges || '[]');
    if (badge && !badges.includes(badge)) badges.push(badge);
    db.run(
      'UPDATE user_points SET total_points = ?, current_level = ?, badges = ? WHERE user_id = ?',
      [newTotal, newLevel, JSON.stringify(badges), req.userId],
      function (err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true, new_total: newTotal, level_up: newLevel > row.current_level });
      }
    );
  });
});

// POST /api/gamification/streak
router.post('/streak', authenticate, (req, res) => {
  db.get('SELECT * FROM user_points WHERE user_id = ?', [req.userId], (err, row) => {
    if (err) return res.status(500).json({ error: err.message });
    const today = new Date().toISOString().slice(0,10);
    if (!row) {
      db.run('INSERT INTO user_points (user_id, login_streak, last_login) VALUES (?, 1, ?)', [req.userId, today]);
      return res.json({ streak: 1, last_login: today, points_earned: 5 });
    }
    const yesterday = new Date(Date.now() - 86400000).toISOString().slice(0,10);
    let newStreak = row.login_streak;
    if (row.last_login === today) {
      // already logged in today
      return res.json({ streak: row.login_streak, last_login: today, points_earned: 0 });
    } else if (row.last_login === yesterday) {
      newStreak += 1;
    } else {
      newStreak = 1;
    }
    const pointsEarned = newStreak >= 7 ? 10 : 5;
    db.run(
      'UPDATE user_points SET login_streak = ?, last_login = ?, total_points = total_points + ? WHERE user_id = ?',
      [newStreak, today, pointsEarned, req.userId],
      function (err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ streak: newStreak, last_login: today, points_earned: pointsEarned });
      }
    );
  });
});

export default router;