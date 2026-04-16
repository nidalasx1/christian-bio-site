const express = require('express');
const path = require('path');
const Database = require('better-sqlite3');

const app = express();
const PORT = process.env.PORT || 3000;

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
app.use(express.static(path.join(__dirname, 'public')));

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

// Stats dashboard (password-protected via HTTP Basic Auth)
app.get('/stats', (req, res) => {
  const statsKey = process.env.STATS_KEY;
  if (!statsKey) {
    return res.status(500).send('STATS_KEY environment variable not set.');
  }
  const auth = req.headers.authorization || '';
  const [scheme, cred] = auth.split(' ');
  const expected = Buffer.from(`admin:${statsKey}`).toString('base64');
  if (scheme !== 'Basic' || cred !== expected) {
    return res.status(401).set('WWW-Authenticate', 'Basic realm="Stats"').send('Unauthorized');
  }

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
  </style>
  <link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;700&display=swap" rel="stylesheet">
</head>
<body>
  <h1>Visitor Stats</h1>
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
