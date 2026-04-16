const express = require('express');
const crypto = require('crypto');
const path = require('path');
const Database = require('better-sqlite3');

const app = express();
const PORT = process.env.PORT || 3000;

// Session tokens (in-memory, cleared on restart)
const sessions = new Map();

// Initialize SQLite database for visitor tracking
const db = new Database(process.env.DB_PATH || './visitors.db');
db.pragma('journal_mode = WAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS visits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT DEFAULT (datetime('now')),
    ip TEXT,
    user_agent TEXT,
    referrer TEXT,
    country TEXT,
    city TEXT,
    path TEXT DEFAULT '/'
  )
`);

db.exec(`
  CREATE TABLE IF NOT EXISTS chapter_reads (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT DEFAULT (datetime('now')),
    visitor_ip TEXT,
    chapter TEXT
  )
`);

const insertVisit = db.prepare(
  'INSERT INTO visits (ip, user_agent, referrer, country, city, path) VALUES (?, ?, ?, ?, ?, ?)'
);

const insertChapterRead = db.prepare(
  'INSERT INTO chapter_reads (visitor_ip, chapter) VALUES (?, ?)'
);

app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, 'public')));

// Parse session cookie
function getSession(req) {
  const cookie = req.headers.cookie || '';
  const match = cookie.match(/session=([a-f0-9]+)/);
  return match ? sessions.get(match[1]) : null;
}

// Admin login page
app.get('/admin', (req, res) => {
  if (getSession(req)) return res.redirect('/stats');
  const error = req.query.error ? '<p class="error">Invalid password. Try again.</p>' : '';
  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Admin Login</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: 'DM Sans', system-ui, sans-serif; background: #0a0a0a; color: #e0e0e0; display: flex; align-items: center; justify-content: center; min-height: 100vh; }
    .login { background: #111; border: 1px solid #222; border-radius: 16px; padding: 2.5rem; width: 100%; max-width: 380px; }
    .login h1 { font-size: 1.4rem; color: #fff; margin-bottom: 0.5rem; }
    .login .sub { font-size: 0.85rem; color: #666; margin-bottom: 2rem; }
    label { display: block; font-size: 0.8rem; color: #888; letter-spacing: 0.1em; text-transform: uppercase; margin-bottom: 0.5rem; }
    input[type="password"] { width: 100%; padding: 0.75rem 1rem; background: #0a0a0a; border: 1px solid #333; border-radius: 8px; color: #e0e0e0; font-size: 1rem; font-family: inherit; outline: none; transition: border-color 0.2s; }
    input[type="password"]:focus { border-color: #c9a96e; }
    button { width: 100%; margin-top: 1.5rem; padding: 0.75rem; background: #c9a96e; color: #0a0a0a; border: none; border-radius: 8px; font-size: 0.95rem; font-weight: 600; font-family: inherit; cursor: pointer; transition: opacity 0.2s; }
    button:hover { opacity: 0.85; }
    .error { color: #e74c3c; font-size: 0.85rem; margin-bottom: 1rem; }
    a { color: #c9a96e; text-decoration: none; display: block; text-align: center; margin-top: 1.5rem; font-size: 0.85rem; }
  </style>
  <link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;700&display=swap" rel="stylesheet">
</head>
<body>
  <form class="login" method="POST" action="/admin/login">
    <h1>Analytics</h1>
    <p class="sub">Enter your admin password to view stats.</p>
    ${error}
    <label for="pw">Password</label>
    <input type="password" id="pw" name="password" autofocus required>
    <button type="submit">Sign In</button>
    <a href="/">Back to site</a>
  </form>
</body>
</html>`);
});

// Handle login
app.post('/admin/login', (req, res) => {
  const statsKey = process.env.STATS_KEY;
  if (!statsKey) return res.status(500).send('STATS_KEY not configured.');
  const { password } = req.body;
  if (password !== statsKey) {
    return res.redirect('/admin?error=1');
  }
  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, { created: Date.now() });
  res.setHeader('Set-Cookie', `session=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=86400`);
  res.redirect('/stats');
});

// Handle logout
app.get('/admin/logout', (req, res) => {
  const cookie = (req.headers.cookie || '').match(/session=([a-f0-9]+)/);
  if (cookie) sessions.delete(cookie[1]);
  res.setHeader('Set-Cookie', 'session=; Path=/; HttpOnly; Max-Age=0');
  res.redirect('/admin');
});

// Track page visit
app.post('/api/track', (req, res) => {
  const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip;
  const userAgent = req.headers['user-agent'] || '';
  const referrer = req.headers['referer'] || req.body.referrer || '';
  const country = req.headers['cf-ipcountry'] || req.headers['x-vercel-ip-country'] || '';
  const city = req.headers['x-vercel-ip-city'] || '';
  const pagePath = req.body.path || '/';

  try {
    insertVisit.run(ip, userAgent, referrer, country, city, pagePath);
    res.json({ ok: true });
  } catch (err) {
    console.error('Track error:', err);
    res.status(500).json({ error: 'tracking failed' });
  }
});

// Track chapter scroll-into-view
app.post('/api/track-chapter', (req, res) => {
  const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip;
  const { chapter } = req.body;
  if (!chapter) return res.status(400).json({ error: 'chapter required' });

  try {
    insertChapterRead.run(ip, chapter);
    res.json({ ok: true });
  } catch (err) {
    console.error('Chapter track error:', err);
    res.status(500).json({ error: 'tracking failed' });
  }
});

// HTML escape to prevent stored XSS
const esc = s => String(s).replace(/[&<>"']/g, c =>
  ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

// Stats dashboard (cookie-session protected)
app.get('/stats', (req, res) => {
  if (!getSession(req)) return res.redirect('/admin');

  const totalVisits = db.prepare('SELECT COUNT(*) as count FROM visits').get().count;
  const todayVisits = db.prepare(
    "SELECT COUNT(*) as count FROM visits WHERE date(timestamp) = date('now')"
  ).get().count;
  const uniqueIPs = db.prepare('SELECT COUNT(DISTINCT ip) as count FROM visits').get().count;
  const recentVisits = db.prepare(
    'SELECT timestamp, ip, referrer, country, city, user_agent FROM visits ORDER BY id DESC LIMIT 50'
  ).all();
  const topReferrers = db.prepare(
    "SELECT referrer, COUNT(*) as count FROM visits WHERE referrer != '' GROUP BY referrer ORDER BY count DESC LIMIT 10"
  ).all();
  const dailyVisits = db.prepare(
    "SELECT date(timestamp) as day, COUNT(*) as count FROM visits GROUP BY date(timestamp) ORDER BY day DESC LIMIT 30"
  ).all();
  const chapterStats = db.prepare(
    'SELECT chapter, COUNT(*) as reads, COUNT(DISTINCT visitor_ip) as unique_readers FROM chapter_reads GROUP BY chapter ORDER BY reads DESC'
  ).all();

  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Visitor Stats — Christian Saladin Bio</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: 'DM Sans', system-ui, sans-serif; background: #0a0a0a; color: #e0e0e0; padding: 2rem; }
    h1 { font-size: 1.8rem; margin-bottom: 1.5rem; color: #fff; }
    h2 { font-size: 1.2rem; margin: 2rem 0 1rem; color: #c9a96e; }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 1rem; margin-bottom: 2rem; }
    .card { background: #161616; border: 1px solid #222; border-radius: 12px; padding: 1.5rem; }
    .card .num { font-size: 2rem; font-weight: 700; color: #c9a96e; }
    .card .label { font-size: 0.85rem; color: #888; margin-top: 0.25rem; }
    table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
    th, td { text-align: left; padding: 0.6rem 0.8rem; border-bottom: 1px solid #1a1a1a; }
    th { color: #888; font-weight: 500; }
    td { color: #ccc; }
    .ua { max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    a { color: #c9a96e; }
    .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.5rem; }
    .header h1 { margin-bottom: 0; }
    .logout { font-size: 0.85rem; color: #888; text-decoration: none; padding: 0.4rem 1rem; border: 1px solid #333; border-radius: 6px; transition: all 0.2s; }
    .logout:hover { color: #fff; border-color: #c9a96e; }
  </style>
  <link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;700&display=swap" rel="stylesheet">
</head>
<body>
  <div class="header">
    <h1>Visitor Stats</h1>
    <a href="/admin/logout" class="logout">Sign Out</a>
  </div>
  <div class="grid">
    <div class="card"><div class="num">${totalVisits}</div><div class="label">Total Visits</div></div>
    <div class="card"><div class="num">${todayVisits}</div><div class="label">Today</div></div>
    <div class="card"><div class="num">${uniqueIPs}</div><div class="label">Unique Visitors</div></div>
  </div>

  <h2>Chapter Engagement</h2>
  <table>
    <tr><th>Chapter</th><th>Total Reads</th><th>Unique Readers</th></tr>
    ${chapterStats.map(c => `<tr><td>${esc(c.chapter)}</td><td>${c.reads}</td><td>${c.unique_readers}</td></tr>`).join('')}
  </table>

  <h2>Daily Visits (Last 30 Days)</h2>
  <table>
    <tr><th>Date</th><th>Visits</th></tr>
    ${dailyVisits.map(d => `<tr><td>${d.day}</td><td>${d.count}</td></tr>`).join('')}
  </table>

  <h2>Top Referrers</h2>
  <table>
    <tr><th>Referrer</th><th>Count</th></tr>
    ${topReferrers.map(r => `<tr><td>${esc(r.referrer)}</td><td>${r.count}</td></tr>`).join('')}
  </table>

  <h2>Recent Visits</h2>
  <table>
    <tr><th>Time</th><th>IP</th><th>Country</th><th>Referrer</th><th>User Agent</th></tr>
    ${recentVisits.map(v => `<tr>
      <td>${esc(v.timestamp)}</td>
      <td>${esc(v.ip)}</td>
      <td>${esc(v.country || '—')} ${esc(v.city || '')}</td>
      <td>${esc(v.referrer || '—')}</td>
      <td class="ua">${esc(v.user_agent)}</td>
    </tr>`).join('')}
  </table>
</body>
</html>`);
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`Christian Saladin Bio running on port ${PORT}`);
});
