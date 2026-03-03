const express = require('express');
const path = require('path');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const { db } = require('./db');

const app = express();
const PORT = process.env.PORT || 4000;
const API_KEY = process.env.MC_LOGS_API_KEY || 'change-me-api-key';
const SESSION_SECRET = process.env.SESSION_SECRET || 'change-me-session-secret';

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(
  session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false
  })
);

app.use('/static', express.static(path.join(__dirname, 'public')));

function requireAuth(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'auth_required' });
  }
  next();
}

function requireRole(role) {
  return (req, res, next) => {
    if (!req.session.userId) return res.status(401).json({ error: 'auth_required' });
    db.get('SELECT role FROM users WHERE id = ?', [req.session.userId], (err, row) => {
      if (err) return res.status(500).json({ error: 'db_error' });
      if (!row) return res.status(401).json({ error: 'auth_required' });
      const allowed = row.role === role || row.role === 'owner';
      if (!allowed) return res.status(403).json({ error: 'forbidden' });
      next();
    });
  };
}

// список пользователей (logs — просмотр, owner — ещё и редактирование/удаление)
app.get('/api/admin/users', requireRole('logs'), (req, res) => {
  db.all('SELECT id, username, email, role, created_at FROM users ORDER BY id ASC', [], (err, rows) => {
    if (err) return res.status(500).json({ error: 'db_error' });
    res.json(rows);
  });
});

function ensureFirstUserOwner(username, cb) {
  db.get('SELECT COUNT(*) as cnt FROM users', (err, row) => {
    if (err) return cb(err);
    const isFirst = row.cnt === 0;
    cb(null, isFirst ? 'owner' : 'user');
  });
}

app.post('/api/auth/register', (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'username_and_password_required' });
  }
  ensureFirstUserOwner(username, (err, role) => {
    if (err) return res.status(500).json({ error: 'db_error' });
    const hash = bcrypt.hashSync(password, 10);
    db.run(
      'INSERT INTO users (username, email, password_hash, role) VALUES (?,?,?,?)',
      [username, email || null, hash, role],
      function (insertErr) {
        if (insertErr) {
          if (insertErr.message.includes('UNIQUE')) {
            return res.status(409).json({ error: 'user_or_email_exists' });
          }
          return res.status(500).json({ error: 'db_error' });
        }
        req.session.userId = this.lastID;
        res.json({ id: this.lastID, username, role });
      }
    );
  });
});

app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'username_and_password_required' });
  db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
    if (err) return res.status(500).json({ error: 'db_error' });
    if (!user) return res.status(401).json({ error: 'invalid_credentials' });
    const ok = bcrypt.compareSync(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: 'invalid_credentials' });
    req.session.userId = user.id;
    res.json({ id: user.id, username: user.username, role: user.role });
  });
});

app.post('/api/auth/logout', (req, res) => {
  req.session.destroy(() => {
    res.json({ ok: true });
  });
});

app.get('/api/me', requireAuth, (req, res) => {
  db.get('SELECT id, username, role, created_at FROM users WHERE id = ?', [req.session.userId], (err, user) => {
    if (err) return res.status(500).json({ error: 'db_error' });
    if (!user) return res.status(404).json({ error: 'not_found' });
    res.json(user);
  });
});

function validateApiKey(req, res, next) {
  const key = req.headers['x-api-key'];
  if (!key || key !== API_KEY) {
    return res.status(401).json({ error: 'invalid_api_key' });
  }
  next();
}

app.post('/api/logs/ingest', validateApiKey, (req, res) => {
  const { ts, source, playerName, command, result, success, ip, raw } = req.body;

  const when = ts || new Date().toISOString();
  const src = source || 'unknown';

  db.run(
    `
    INSERT INTO logs (ts, source, player_name, command, result, success, ip, raw_json)
    VALUES (?,?,?,?,?,?,?,?)
  `,
    [
      when,
      src,
      playerName || null,
      command || null,
      result || null,
      typeof success === 'boolean' ? (success ? 1 : 0) : null,
      ip || null,
      raw ? JSON.stringify(raw) : null
    ],
    function (err) {
      if (err) {
        console.error('Failed to insert log', err);
        return res.status(500).json({ error: 'db_error' });
      }

      if (playerName) {
        const now = when;
        db.run(
          `
          INSERT INTO players (nickname, first_seen, last_seen, last_ip)
          VALUES (?,?,?,?)
          ON CONFLICT(nickname) DO UPDATE SET
            last_seen = excluded.last_seen,
            last_ip = COALESCE(excluded.last_ip, players.last_ip)
        `,
          [playerName, now, now, ip || null],
          (pErr) => {
            if (pErr) console.error('Failed to upsert player', pErr);
          }
        );
      }

      res.json({ id: this.lastID });
    }
  );
});

app.put('/api/admin/users/:id', requireRole('owner'), (req, res) => {
  const { id } = req.params;
  const { role, password } = req.body;
  const updates = [];
  const params = [];

  if (role) {
    updates.push('role = ?');
    params.push(role);
  }
  if (password) {
    const hash = bcrypt.hashSync(password, 10);
    updates.push('password_hash = ?');
    params.push(hash);
  }

  if (!updates.length) return res.status(400).json({ error: 'no_updates' });

  params.push(id);
  db.run(`UPDATE users SET ${updates.join(', ')} WHERE id = ?`, params, function (err) {
    if (err) return res.status(500).json({ error: 'db_error' });
    // Даже если изменений нет (роль та же, пароль не задан) — считаем операцию успешной
    res.json({ ok: true, changed: this.changes });
  });
});

app.delete('/api/admin/users/:id', requireRole('owner'), (req, res) => {
  const { id } = req.params;

  db.get('SELECT id, role FROM users WHERE id = ?', [id], (err, user) => {
    if (err) return res.status(500).json({ error: 'db_error' });
    if (!user) return res.status(404).json({ error: 'not_found' });
    if (user.role === 'owner') {
      return res.status(400).json({ error: 'cannot_delete_owner' });
    }
    if (user.id === req.session.userId) {
      return res.status(400).json({ error: 'cannot_delete_self' });
    }

    db.run('DELETE FROM users WHERE id = ?', [id], function (delErr) {
      if (delErr) return res.status(500).json({ error: 'db_error' });
      res.json({ ok: true });
    });
  });
});

app.get('/api/logs', requireRole('logs'), (req, res) => {
  const { limit = 100, player, source, from, to, q } = req.query;
  const params = [];
  const where = [];

  if (player) {
    where.push('player_name = ?');
    params.push(player);
  }
  if (source) {
    where.push('source = ?');
    params.push(source);
  }
  if (from) {
    where.push('ts >= ?');
    params.push(from);
  }
  if (to) {
    where.push('ts <= ?');
    params.push(to);
  }
  if (q) {
    const like = `%${q}%`;
    where.push('(command LIKE ? OR result LIKE ? OR player_name LIKE ? OR ip LIKE ? OR ts LIKE ?)');
    params.push(like, like, like, like, like);
  }

  let sql = 'SELECT * FROM logs';
  if (where.length) sql += ' WHERE ' + where.join(' AND ');
  sql += ' ORDER BY ts DESC LIMIT ?';
  params.push(Number(limit));

  db.all(sql, params, (err, rows) => {
    if (err) return res.status(500).json({ error: 'db_error' });
    res.json(rows);
  });
});

app.get('/api/players', requireRole('logs'), (req, res) => {
  db.all(
    `
    SELECT id, nickname, first_seen, last_seen, last_ip
    FROM players
    ORDER BY last_seen DESC
  `,
    [],
    (err, rows) => {
      if (err) return res.status(500).json({ error: 'db_error' });
      res.json(rows);
    }
  );
});

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`Logs backend listening on http://localhost:${PORT}`);
  console.log('Remember to set MC_LOGS_API_KEY and SESSION_SECRET in production.');
});

