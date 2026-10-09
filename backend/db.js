import sqlite3 from 'sqlite3';
import path from 'path';
import fs from 'fs';
import dotenv from 'dotenv';
import { fileURLToPath } from 'url';

dotenv.config();
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const dbPath = process.env.DB_PATH || path.join(__dirname, 'haafiz.db');

if (!fs.existsSync(path.dirname(dbPath))) {
  fs.mkdirSync(path.dirname(dbPath), { recursive: true });
}

const db = new sqlite3.Database(dbPath);
db.run('PRAGMA foreign_keys = ON');

export function initDB() {
  const schema = `
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      preferred_language TEXT DEFAULT 'en',
      alarm_enabled BOOLEAN DEFAULT 1,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS reports (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      content TEXT NOT NULL,
      content_type TEXT DEFAULT 'text',
      result TEXT,
      confidence INTEGER,
      is_scam BOOLEAN,
      language TEXT DEFAULT 'en',
      phone_number TEXT,
      city TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS history (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      input TEXT NOT NULL,
      input_type TEXT DEFAULT 'text',
      result TEXT NOT NULL,
      confidence INTEGER,
      is_scam BOOLEAN,
      risk_factors TEXT,
      language TEXT DEFAULT 'en',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS threats (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL,
      description TEXT NOT NULL,
      type TEXT NOT NULL,
      severity TEXT DEFAULT 'medium' CHECK(severity IN ('low', 'medium', 'high', 'critical')),
      source TEXT,
      city TEXT,
      reported_by INTEGER,
      validated BOOLEAN DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (reported_by) REFERENCES users(id) ON DELETE SET NULL
    );
    CREATE TABLE IF NOT EXISTS blacklist (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      domain TEXT UNIQUE NOT NULL,
      reason TEXT,
      added_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS phone_reputation (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      phone_number TEXT UNIQUE NOT NULL,
      report_count INTEGER DEFAULT 1,
      risk_score INTEGER CHECK(risk_score BETWEEN 0 AND 100),
      scam_types TEXT,
      last_reported DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS family_groups (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      created_by INTEGER NOT NULL,
      invite_code TEXT UNIQUE NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS family_members (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      group_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      role TEXT DEFAULT 'member' CHECK(role IN ('admin', 'member')),
      joined_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (group_id) REFERENCES family_groups(id) ON DELETE CASCADE,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
      UNIQUE(group_id, user_id)
    );
    CREATE TABLE IF NOT EXISTS family_alerts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      group_id INTEGER NOT NULL,
      triggered_by INTEGER NOT NULL,
      scan_id INTEGER,
      message TEXT NOT NULL,
      is_read BOOLEAN DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (group_id) REFERENCES family_groups(id) ON DELETE CASCADE,
      FOREIGN KEY (triggered_by) REFERENCES users(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS user_points (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER UNIQUE NOT NULL,
      total_points INTEGER DEFAULT 0,
      current_level INTEGER DEFAULT 1,
      badges TEXT DEFAULT '[]',
      login_streak INTEGER DEFAULT 0,
      last_login DATE,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS location_reports (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      report_id INTEGER,
      city TEXT NOT NULL,
      province TEXT,
      latitude REAL,
      longitude REAL,
      is_approximate BOOLEAN DEFAULT 1,
      FOREIGN KEY (report_id) REFERENCES reports(id) ON DELETE SET NULL
    );
    CREATE INDEX IF NOT EXISTS idx_history_user ON history(user_id);
    CREATE INDEX IF NOT EXISTS idx_reports_user ON reports(user_id);
    CREATE INDEX IF NOT EXISTS idx_threats_city ON threats(city);
    CREATE INDEX IF NOT EXISTS idx_phone_number ON phone_reputation(phone_number);
    CREATE INDEX IF NOT EXISTS idx_family_group ON family_members(group_id);
  `;
  db.exec(schema, (err) => {
    if (err) console.error('DB init error:', err.message);
    else console.log('Database ready');
  });
}

export default db;