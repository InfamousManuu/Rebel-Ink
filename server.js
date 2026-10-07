const express = require('express');
const path = require('path');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = Number(process.env.PORT || 3000);

let JWT_SECRET = process.env.JWT_SECRET;
let ADMIN_SETUP_TOKEN = process.env.ADMIN_SETUP_TOKEN || '';

if (!JWT_SECRET || JWT_SECRET.length < 32) {
  JWT_SECRET = crypto.randomBytes(48).toString('hex');
  console.warn('JWT_SECRET not set — generated a temporary one. Set it in Render Environment to keep logins stable across restarts.');
}
if (!ADMIN_SETUP_TOKEN || ADMIN_SETUP_TOKEN.length < 24) {
  ADMIN_SETUP_TOKEN = crypto.randomBytes(24).toString('hex');
  console.warn('ADMIN_SETUP_TOKEN not set — generated a temporary one. Set it in Render Environment so the setup URL stays the same.');
}

// ---------- In-memory store (lost when the free service sleeps/restarts) ----------
const users = [];       // { id, name, phone, country, state, email, password_hash, role, status, admin_notes, created_at, updated_at, last_login_at }
const bookings = [];    // { id, user_id, service, date, problem, photos, status, admin_note, approved_at, rejected_at, created_at, updated_at }

app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '20mb' }));
app.use(express.urlencoded({ extended: false, limit: '20mb' }));

const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 30, standardHeaders: true, legacyHeaders: false, message: { error: 'Too many authentication attempts. Please try again later.' } });
const adminLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 120, standardHeaders: true, legacyHeaders: false });
const setupLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10, standardHeaders: true, legacyHeaders: false });

function uid() { return crypto.randomUUID(); }
function now() { return new Date().toISOString(); }

function safeUser(u) {
  if (!u) return null;
  return {
    _id: u.id,
    name: u.name,
    phone: u.phone,
    country: u.country,
    state: u.state || '',
    email: u.email,
    role: u.role,
    status: u.status,
    adminNotes: u.admin_notes || '',
    createdAt: u.created_at,
    updatedAt: u.updated_at,
    lastLoginAt: u.last_login_at || null
  };
}
function tokenFor(user) {
  return jwt.sign({ sub: user.id, role: user.role, email: user.email }, JWT_SECRET, { expiresIn: '7d', issuer: 'rebel-ink' });
}
function cleanText(value, max) { return String(value ?? '').trim().slice(0, max); }
function normalizeEmail(email) { return String(email || '').trim().toLowerCase(); }
function validPassword(pw) {
  return typeof pw === 'string' && pw.length >= 8 && pw.length <= 128 &&
    /[a-zA-Z]/.test(pw) && /[0-9]/.test(pw) && /[^a-zA-Z0-9]/.test(pw);
}
function validPhotos(photos) {
  if (!Array.isArray(photos) || photos.length > 5) return false;
  return photos.every(p => p && typeof p.name === 'string' && typeof p.dataUrl === 'string' &&
    /^data:image\/(jpeg|jpg|png|webp|gif);base64,/i.test(p.dataUrl) && p.dataUrl.length <= 3_500_000);
}
function csvEscape(v) {
  const s = String(v ?? '');
  return /[",\n\r]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
}
function sameSecret(a, b) {
  const aa = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  return aa.length === bb.length && crypto.timingSafeEqual(aa, bb);
}

function hasAdmin() {
  return users.some(u => u.role === 'admin');
}
function findUserById(id) {
  return users.find(u => u.id === id) || null;
}
function findUserByEmail(email) {
  return users.find(u => u.email === email) || null;
}

function auth(req, res, next) {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : '';
  if (!token) return res.status(401).json({ error: 'Authentication required.' });
  try {
    const payload = jwt.verify(token, JWT_SECRET, { issuer: 'rebel-ink' });
    const user = findUserById(payload.sub);
    if (!user || user.status === 'suspended') return res.status(401).json({ error: 'Account is unavailable.' });
    req.user = user;
    next();
  } catch (_) {
    return res.status(401).json({ error: 'Invalid or expired session.' });
  }
}
function adminOnly(req, res, next) {
  if (!req.user || req.user.role !== 'admin') return res.status(403).json({ error: 'Admin access required.' });
  next();
}

function setupPage() {
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Rebel Ink — First Admin Setup</title><style>body{font-family:Arial,sans-serif;background:#f5f7fb;margin:0;padding:30px;color:#172033}.card{max-width:520px;margin:40px auto;background:#fff;padding:30px;border-radius:16px;box-shadow:0 10px 35px #0001}h1{margin-top:0}.field{margin:15px 0}label{display:block;font-weight:700;margin-bottom:7px}input{width:100%;box-sizing:border-box;padding:12px;border:1px solid #ccd4df;border-radius:8px;font-size:16px}.btn{width:100%;padding:13px;border:0;border-radius:8px;background:#1e3a5f;color:#fff;font-weight:700;font-size:16px;cursor:pointer}.msg{margin:14px 0;padding:12px;border-radius:8px;display:none;white-space:pre-wrap}.ok{background:#ecfdf5;color:#065f46}.err{background:#fef2f2;color:#991b1b}.small{font-size:13px;color:#64748b;line-height:1.5}</style></head><body><div class="card"><h1>Rebel Ink — Admin Setup</h1><p class="small">This page is only for the first administrator. Once an admin account exists, this setup route permanently closes.</p><div id="msg" class="msg"></div><form id="f"><div class="field"><label>Setup token</label><input id="token" required></div><div class="field"><label>Admin name</label><input id="name" required value="Rebel Ink Administrator"></div><div class="field"><label>Admin email</label><input id="email" type="email" required></div><div class="field"><label>Choose admin password</label><input id="password" type="password" required minlength="8"></div><div class="field"><label>Confirm password</label><input id="confirm" type="password" required minlength="8"></div><button class="btn">Create Administrator</button></form></div><script>const q=new URLSearchParams(location.search);document.getElementById('token').value=q.get('token')||'';const msg=document.getElementById('msg');document.getElementById('f').onsubmit=async e=>{e.preventDefault();msg.style.display='none';const p=document.getElementById('password').value,c=document.getElementById('confirm').value;if(p!==c){msg.className='msg err';msg.textContent='Passwords do not match.';msg.style.display='block';return}try{const r=await fetch('/api/admin/setup',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token:document.getElementById('token').value,name:document.getElementById('name').value,email:document.getElementById('email').value,password:p})});const d=await r.json();if(!r.ok)throw new Error(d.error||'Setup failed');msg.className='msg ok';msg.textContent='Admin created! You can now log in from the main site.';msg.style.display='block';setTimeout(()=>location.href='/',1500)}catch(err){msg.className='msg err';msg.textContent=err.message;msg.style.display='block'}}; </script></body></html>`;
}

function start() {
  console.log('Rebel Ink running in MEMORY mode (no database).');
  console.log('WARNING: All data is lost when the free Web Service sleeps or restarts.');
  if (!hasAdmin()) {
    console.log('FIRST ADMIN SETUP REQUIRED. Open /admin-setup?token=' + ADMIN_SETUP_TOKEN);
    console.log('Choose the admin email and password yourself. The setup route closes after the first admin is created.');
  }

  app.get('/api/health', (_req, res) =>
    res.json({ ok: true, service: 'rebel-ink', storage: 'memory', time: new Date().toISOString() })
  );

  app.get('/admin-setup', (_req, res) => {
    if (hasAdmin()) return res.status(404).send('Admin setup is already completed.');
    res.type('html').send(setupPage());
  });

  app.post('/api/admin/setup', setupLimiter, async (req, res) => {
    try {
      if (hasAdmin()) return res.status(409).json({ error: 'Admin setup has already been completed.' });
      if (!sameSecret(req.body.token || '', ADMIN_SETUP_TOKEN)) return res.status(403).json({ error: 'Invalid setup token.' });
      const name = cleanText(req.body.name, 120) || 'Rebel Ink Administrator';
      const email = normalizeEmail(req.body.email);
      const password = req.body.password || '';
      if (!/^\S+@\S+\.\S+$/.test(email)) return res.status(400).json({ error: 'Enter a valid email address.' });
      if (!validPassword(password)) return res.status(400).json({ error: 'Password must be at least 8 characters and include letters, numbers and a special character.' });
      if (findUserByEmail(email)) return res.status(409).json({ error: 'That email is already registered.' });
      const passwordHash = await bcrypt.hash(password, 12);
      const t = now();
      const user = {
        id: uid(), name, phone: '', country: 'United States', state: '',
        email, password_hash: passwordHash, role: 'admin', status: 'approved',
        admin_notes: '', created_at: t, updated_at: t, last_login_at: null
      };
      users.push(user);
      res.status(201).json({ message: 'Administrator created successfully.', user: safeUser(user) });
    } catch (e) {
      console.error(e);
      res.status(500).json({ error: 'Admin setup failed.' });
    }
  });

  app.post('/api/register', authLimiter, async (req, res) => {
    try {
      const name = cleanText(req.body.name, 120);
      const phone = cleanText(req.body.phone, 40);
      const country = cleanText(req.body.country, 80);
      const state = cleanText(req.body.state, 80);
      const email = normalizeEmail(req.body.email);
      const password = req.body.password;
      if (!name || !phone || !country || !email || !validPassword(password)) {
        return res.status(400).json({ error: 'Name, phone, country, email and a strong password are required.' });
      }
      if (!/^\S+@\S+\.\S+$/.test(email)) return res.status(400).json({ error: 'Enter a valid email address.' });
      if (findUserByEmail(email)) return res.status(409).json({ error: 'That email is already registered.' });
      const passwordHash = await bcrypt.hash(password, 12);
      const t = now();
      const user = {
        id: uid(), name, phone, country, state, email,
        password_hash: passwordHash, role: 'member', status: 'pending',
        admin_notes: '', created_at: t, updated_at: t, last_login_at: null
      };
      users.push(user);
      res.status(201).json({ message: 'Registration submitted. Wait for admin approval.', user: safeUser(user) });
    } catch (e) {
      console.error(e);
      res.status(500).json({ error: 'Registration failed.' });
    }
  });

  app.post('/api/login', authLimiter, async (req, res) => {
    const email = normalizeEmail(req.body.email);
    const password = req.body.password || '';
    const user = findUserByEmail(email);
    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(401).json({ error: 'Invalid email or password.' });
    }
    if (user.status === 'suspended') {
      return res.status(403).json({ error: 'This account is suspended. Contact the administrator.' });
    }
    user.last_login_at = now();
    user.updated_at = now();
    res.json({ token: tokenFor(user), user: safeUser(user) });
  });

  app.post('/api/admin/login', authLimiter, async (req, res) => {
    const email = normalizeEmail(req.body.email);
    const password = req.body.password || '';
    const user = findUserByEmail(email);
    if (!user || user.role !== 'admin' || !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(401).json({ error: 'Invalid admin credentials.' });
    }
    user.last_login_at = now();
    user.updated_at = now();
    res.json({ token: tokenFor(user), user: safeUser(user) });
  });

  app.post('/api/reset-password', authLimiter, (_req, res) =>
    res.status(503).json({ error: 'Password reset is disabled until secure email verification is configured. Contact the administrator.' })
  );

  app.get('/api/me', auth, (req, res) => {
    const bs = bookings
      .filter(b => b.user_id === req.user.id)
      .sort((a, b) => (b.created_at > a.created_at ? 1 : -1))
      .map(b => ({
        _id: b.id, service: b.service,
        date: b.date ? String(b.date).slice(0, 10) : '',
        problem: b.problem, photos: b.photos || [], status: b.status,
        adminNote: b.admin_note || '', createdAt: b.created_at, updatedAt: b.updated_at
      }));
    res.json({ user: { ...safeUser(req.user), bookings: bs } });
  });

  app.post('/api/bookings', auth, (req, res) => {
    if (req.user.status !== 'approved') {
      return res.status(403).json({ error: 'Your account must be approved before booking.' });
    }
    const service = cleanText(req.body.service, 120);
    const date = cleanText(req.body.date, 20);
    const problem = cleanText(req.body.problem, 5000);
    const photos = Array.isArray(req.body.photos) ? req.body.photos : [];
    if (!service || !problem) return res.status(400).json({ error: 'Service and problem description are required.' });
    if (!validPhotos(photos)) return res.status(400).json({ error: 'Invalid photo data (max 5 images, each under ~2.5MB).' });
    const t = now();
    const booking = {
      id: uid(), user_id: req.user.id, service, date: date || null, problem,
      photos, status: 'Pending', admin_note: '', approved_at: null, rejected_at: null,
      created_at: t, updated_at: t
    };
    bookings.push(booking);
    res.status(201).json({
      message: 'Appointment request submitted.',
      booking: {
        _id: booking.id, service: booking.service, date: booking.date || '',
        problem: booking.problem, photos: booking.photos, status: booking.status,
        adminNote: '', createdAt: booking.created_at, updatedAt: booking.updated_at
      }
    });
  });

  // Admin list members
  app.get('/api/admin/members', auth, adminOnly, adminLimiter, (_req, res) => {
    const list = users
      .filter(u => u.role === 'member')
      .sort((a, b) => (b.created_at > a.created_at ? 1 : -1))
      .map(u => {
        const mine = bookings.filter(b => b.user_id === u.id);
        return { ...safeUser(u), bookings: mine.map(b => ({
          _id: b.id, service: b.service, date: b.date || '', problem: b.problem,
          photos: b.photos || [], status: b.status, adminNote: b.admin_note || '',
          createdAt: b.created_at, updatedAt: b.updated_at
        })) };
      });
    res.json({ members: list });
  });

  app.patch('/api/admin/members/:id/status', auth, adminOnly, (req, res) => {
    const status = req.body.status;
    if (!['pending', 'approved', 'suspended'].includes(status)) {
      return res.status(400).json({ error: 'Invalid status.' });
    }
    const user = users.find(u => u.id === req.params.id && u.role === 'member');
    if (!user) return res.status(404).json({ error: 'Member not found.' });
    user.status = status;
    user.updated_at = now();
    res.json({ message: `Member ${status}.`, user: safeUser(user) });
  });

  app.patch('/api/admin/members/:id/notes', auth, adminOnly, (req, res) => {
    const user = users.find(u => u.id === req.params.id && u.role === 'member');
    if (!user) return res.status(404).json({ error: 'Member not found.' });
    user.admin_notes = cleanText(req.body.notes, 5000);
    user.updated_at = now();
    res.json({ message: 'Notes saved.' });
  });

  app.patch('/api/admin/bookings/:userId/:bookingId/status', auth, adminOnly, (req, res) => {
    const status = req.body.status;
    if (!['Pending', 'Approved', 'Rejected', 'Done', 'Cancelled'].includes(status)) {
      return res.status(400).json({ error: 'Invalid appointment status.' });
    }
    const booking = bookings.find(b => b.id === req.params.bookingId && b.user_id === req.params.userId);
    if (!booking) return res.status(404).json({ error: 'Appointment not found.' });
    booking.status = status;
    booking.admin_note = cleanText(req.body.adminNote, 3000);
    booking.updated_at = now();
    if (status === 'Approved') booking.approved_at = now();
    if (status === 'Rejected') booking.rejected_at = now();
    res.json({ message: `Appointment ${status.toLowerCase()}.` });
  });

  app.get('/api/admin/export', auth, adminOnly, adminLimiter, (_req, res) => {
    const members = users.filter(u => u.role === 'member').sort((a, b) => (b.created_at > a.created_at ? 1 : -1));
    const rows = [['Member ID', 'Name', 'Email', 'Phone', 'Country', 'State', 'Account Status', 'Member Since', 'Appointment ID', 'Service', 'Preferred Date', 'Appointment Status', 'Problem', 'Admin Note', 'Appointment Created']];
    for (const m of members) {
      const mine = bookings.filter(b => b.user_id === m.id);
      if (!mine.length) {
        rows.push([m.id, m.name, m.email, m.phone, m.country, m.state, m.status, m.created_at, '', '', '', '', '', m.admin_notes || '', '']);
      }
      for (const b of mine) {
        rows.push([m.id, m.name, m.email, m.phone, m.country, m.state, m.status, m.created_at, b.id, b.service, b.date, b.status, b.problem, b.admin_note, b.created_at]);
      }
    }
    const csv = rows.map(r => r.map(csvEscape).join(',')).join('\r\n');
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="rebel-ink-members.csv"');
    res.send('\ufeff' + csv);
  });

  app.get(/.*/, (_req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
  app.use((err, _req, res, _next) => {
    console.error(err);
    if (err.type === 'entity.too.large') return res.status(413).json({ error: 'Request too large.' });
    res.status(500).json({ error: 'Server error.' });
  });

  app.listen(PORT, () => console.log(`Rebel Ink server listening on port ${PORT}`));
}

start();
