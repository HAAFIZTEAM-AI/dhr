import express from 'express';
import crypto from 'crypto';
import db from '../db.js';
import { authenticate } from '../middleware/auth.js';

const router = express.Router();

// POST /api/family/create
router.post('/create', authenticate, (req, res) => {
  const { name } = req.body;
  if (!name) return res.status(400).json({ error: 'Group name required' });
  const inviteCode = crypto.randomBytes(4).toString('hex').toUpperCase();
  db.run(
    'INSERT INTO family_groups (name, created_by, invite_code) VALUES (?, ?, ?)',
    [name, req.userId, inviteCode],
    function (err) {
      if (err) return res.status(500).json({ error: err.message });
      const groupId = this.lastID;
      db.run('INSERT INTO family_members (group_id, user_id, role) VALUES (?, ?, ?)', [groupId, req.userId, 'admin']);
      res.json({ success: true, group: { id: groupId, name, invite_code: inviteCode } });
    }
  );
});

// POST /api/family/join
router.post('/join', authenticate, (req, res) => {
  const { invite_code } = req.body;
  db.get('SELECT * FROM family_groups WHERE invite_code = ?', [invite_code], (err, group) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!group) return res.status(404).json({ error: 'Invalid invite code' });
    db.run(
      'INSERT OR IGNORE INTO family_members (group_id, user_id, role) VALUES (?, ?, ?)',
      [group.id, req.userId, 'member'],
      function (err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true, group: { id: group.id, name: group.name } });
      }
    );
  });
});

// GET /api/family/mine
router.get('/mine', authenticate, (req, res) => {
  db.get(
    `SELECT fg.* FROM family_groups fg
     JOIN family_members fm ON fm.group_id = fg.id
     WHERE fm.user_id = ?`,
    [req.userId],
    (err, group) => {
      if (err) return res.status(500).json({ error: err.message });
      if (!group) return res.json({ group: null });

      db.all('SELECT u.id, u.username, u.email, fm.role FROM family_members fm JOIN users u ON u.id = fm.user_id WHERE fm.group_id = ?', [group.id], (err, members) => {
        if (err) return res.status(500).json({ error: err.message });
        db.all('SELECT * FROM family_alerts WHERE group_id = ? ORDER BY created_at DESC LIMIT 20', [group.id], (err, alerts) => {
          if (err) return res.status(500).json({ error: err.message });
          const isAdmin = members.find(m => m.id === req.userId)?.role === 'admin';
          res.json({ group: { ...group, members, alerts }, is_admin: isAdmin });
        });
      });
    }
  );
});

// GET /api/family/alerts
router.get('/alerts', authenticate, (req, res) => {
  db.get('SELECT group_id FROM family_members WHERE user_id = ?', [req.userId], (err, row) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!row) return res.json({ alerts: [], unread_count: 0 });
    db.all('SELECT * FROM family_alerts WHERE group_id = ? ORDER BY created_at DESC', [row.group_id], (err, alerts) => {
      if (err) return res.status(500).json({ error: err.message });
      const unread = alerts.filter(a => !a.is_read).length;
      res.json({ alerts, unread_count: unread });
    });
  });
});

// POST /api/family/send-alert - manually send alert to family group
router.post('/send-alert', authenticate, (req, res) => {
  const { message } = req.body;
  if (!message) return res.status(400).json({ error: 'Message required' });

  db.get(
    'SELECT group_id FROM family_members WHERE user_id = ?',
    [req.userId],
    (err, member) => {
      if (err) return res.status(500).json({ error: err.message });
      if (!member) return res.status(404).json({ error: 'You are not part of any family group' });

      db.run(
        'INSERT INTO family_alerts (group_id, triggered_by, message) VALUES (?, ?, ?)',
        [member.group_id, req.userId, message],
        function (insErr) {
          if (insErr) return res.status(500).json({ error: insErr.message });
          res.json({ success: true, alert_id: this.lastID });
        }
      );
    }
  );
});

// DELETE /api/family/:id (admin only)
router.delete('/:id', authenticate, (req, res) => {
  db.get('SELECT role FROM family_members WHERE group_id = ? AND user_id = ?', [req.params.id, req.userId], (err, member) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!member || member.role !== 'admin') return res.status(403).json({ error: 'Only admin can delete group' });
    db.run('DELETE FROM family_groups WHERE id = ?', [req.params.id], function (err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ success: true });
    });
  });
});

export default router;