const path = require('path');
const fs = require('fs');
const sqlite3 = require('sqlite3').verbose();

const DATA_DIR = path.join(__dirname, 'data');
const DB_PATH = path.join(DATA_DIR, 'logs.sqlite');

function createDb() {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  const db = new sqlite3.Database(DB_PATH);

  db.serialize(() => {
    db.run(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'user',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `);

    db.run(`
      CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts DATETIME NOT NULL,
        source TEXT NOT NULL,
        player_name TEXT,
        command TEXT,
        result TEXT,
        success INTEGER,
        ip TEXT,
        raw_json TEXT
      )
    `);

    db.run(`
      CREATE TABLE IF NOT EXISTS players (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nickname TEXT UNIQUE NOT NULL,
        first_seen DATETIME NOT NULL,
        last_seen DATETIME NOT NULL,
        last_ip TEXT
      )
    `);

    db.run(`
      CREATE INDEX IF NOT EXISTS idx_logs_ts ON logs (ts DESC)
    `);

    db.run(`
      CREATE INDEX IF NOT EXISTS idx_logs_player ON logs (player_name)
    `);
  });

  return db;
}

const db = createDb();

module.exports = { db };

