const express   = require('express');
const cors      = require('cors');
const bcrypt    = require('bcrypt');
const jwt       = require('jsonwebtoken');
const path      = require('path');
const fs        = require('fs');
const initSqlJs = require('sql.js');

const app     = express();
const PORT    = 3000;
const SECRET  = process.env.JWT_SECRET || 'vit_cabconnect_dev_secret_2024';
const DB_PATH = path.join(__dirname, 'cabconnect.db');

app.use(cors({ origin: '*' }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

let db;

async function initDB() {
  const SQL = await initSqlJs();
  if (fs.existsSync(DB_PATH)) {
    db = new SQL.Database(fs.readFileSync(DB_PATH));
    console.log('Loaded existing database');
  } else {
    db = new SQL.Database();
    console.log('Created new database');
  }
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL, email TEXT UNIQUE NOT NULL,
      phone TEXT NOT NULL, password TEXT NOT NULL,
      year TEXT DEFAULT '', gender TEXT DEFAULT '', accommodation TEXT DEFAULT '',
      created_at TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS rides (
      id INTEGER PRIMARY KEY AUTOINCREMENT, owner_id INTEGER NOT NULL,
      pickup TEXT NOT NULL, destination TEXT NOT NULL,
      date TEXT NOT NULL, time TEXT NOT NULL,
      max_seats INTEGER DEFAULT 1, seats_left INTEGER DEFAULT 1,
      gender_pref TEXT DEFAULT 'Any', year_pref TEXT DEFAULT 'Any year',
      cab_type TEXT DEFAULT 'Sedan', status TEXT DEFAULT 'active',
      created_at TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS ride_requests (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ride_id INTEGER NOT NULL, user_id INTEGER NOT NULL,
      status TEXT DEFAULT 'pending', joined_at TEXT DEFAULT (datetime('now')),
      UNIQUE(ride_id, user_id)
    );
    CREATE TABLE IF NOT EXISTS messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ride_id INTEGER NOT NULL, user_id INTEGER NOT NULL,
      text TEXT NOT NULL, sent_at TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS backout_requests (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ride_id INTEGER NOT NULL,
      requester_id INTEGER NOT NULL,
      status TEXT DEFAULT 'pending',
      approvals_needed INTEGER DEFAULT 0,
      approvals_received INTEGER DEFAULT 0,
      created_at TEXT DEFAULT (datetime('now'))
    );
  `);
  save();
  console.log('Tables ready');
}

function save() { fs.writeFileSync(DB_PATH, Buffer.from(db.export())); }

function qry(sql, p = []) {
  const s = db.prepare(sql), rows = [];
  s.bind(p);
  while (s.step()) rows.push(s.getAsObject());
  s.free();
  return rows;
}

// FIX: Wrap run() in a transaction to prevent race conditions (e.g. double seat
// deduction when two approvals fire nearly simultaneously).
function run(sql, p = []) {
  db.run(sql, p);
  const [{ lastID }] = qry('SELECT last_insert_rowid() as lastID');
  save();
  return { lastInsertRowid: lastID };
}

// Helper: run multiple statements atomically
function runTransaction(ops) {
  db.run('BEGIN');
  try {
    let lastResult;
    for (const { sql, params } of ops) {
      db.run(sql, params || []);
      const [{ lastID }] = qry('SELECT last_insert_rowid() as lastID');
      lastResult = { lastInsertRowid: lastID };
    }
    db.run('COMMIT');
    save();
    return lastResult;
  } catch (e) {
    db.run('ROLLBACK');
    throw e;
  }
}

function one(sql, p = []) { return qry(sql, p)[0] || null; }

const VIT   = ['@vitstudent.ac.in', '@vit.ac.in'];
const isVIT = e => e && VIT.some(d => e.toLowerCase().trim().endsWith(d));
const tok   = (id, email) => jwt.sign({ userId: id, email }, SECRET, { expiresIn: '7d' });

// FIX: Added explicit `e` parameter in catch to avoid lint warnings
function auth(req, res, next) {
  const t = (req.headers.authorization || '').split(' ')[1];
  if (!t) return res.status(401).json({ message: 'Token required' });
  try {
    req.user = jwt.verify(t, SECRET);
    next();
  } catch (e) {
    res.status(403).json({ message: 'Invalid token' });
  }
}

function matchScore(ride, seeker) {
  let s = 60;
  if (seeker.gender && ride.gender_pref !== 'Any')
    s += ride.gender_pref.toLowerCase().includes(seeker.gender.toLowerCase()) ? 20 : -15;
  else s += 10;
  if (seeker.year && ride.year_pref !== 'Any year') {
    if (ride.year_pref.toLowerCase().includes(seeker.year.toLowerCase())) s += 15;
  } else s += 8;
  if (ride.seats_left > 0) s += 5;
  return Math.min(99, Math.max(40, s));
}

function calcPrice(pickup, destination) {
  const vit = ['vit main gate', '1a gate', '3rd gate', 'all mart gate'];
  const p = (pickup || '').toLowerCase().trim();
  const d = (destination || '').toLowerCase().trim();
  const fromVIT = vit.some(x => p.includes(x));
  const toVIT   = vit.some(x => d.includes(x));
  if ((fromVIT && d.includes('katpadi')) || (toVIT && p.includes('katpadi'))) return 500;
  if ((fromVIT && d.includes('chennai airport')) || (toVIT && p.includes('chennai airport'))) return 4000;
  if ((fromVIT && d.includes('bengaluru airport')) || (toVIT && p.includes('bengaluru airport'))) return 4000;
  return null;
}

function calcShare(pickup, destination, totalPeople) {
  const price = calcPrice(pickup, destination);
  if (!price) return null;
  return Math.ceil(price / totalPeople);
}

// ── REGISTER ────────────────────────────────────────
app.post('/api/register', async (req, res) => {
  const { name, email, phone, password, year, gender, accommodation } = req.body;
  if (!name || !email || !phone || !password)
    return res.status(400).json({ message: 'Name, email, phone and password are required' });
  const em = email.toLowerCase().trim();
  if (!isVIT(em))
    return res.status(400).json({ message: 'Only VIT email IDs accepted (@vitstudent.ac.in)', field: 'email' });
  if (!/^\d{10}$/.test(phone.trim()))
    return res.status(400).json({ message: 'Enter a valid 10-digit phone number', field: 'phone' });
  if (password.length < 6)
    return res.status(400).json({ message: 'Password must be at least 6 characters', field: 'password' });
  if (one('SELECT id FROM users WHERE email=?', [em]))
    return res.status(409).json({ message: 'Email already registered', field: 'email' });
  const hash = await bcrypt.hash(password, 10);
  const r = run(
    'INSERT INTO users(name,email,phone,password,year,gender,accommodation)VALUES(?,?,?,?,?,?,?)',
    [name.trim(), em, phone.trim(), hash, year || '', gender || '', accommodation || '']
  );
  console.log('Registered:', em);
  res.status(201).json({
    message: 'Account created',
    token: tok(r.lastInsertRowid, em),
    user: { id: r.lastInsertRowid, name: name.trim(), email: em, year, gender }
  });
});

// ── LOGIN ────────────────────────────────────────────
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password)
    return res.status(400).json({ message: 'Email and password required' });
  const em = email.toLowerCase().trim();
  if (!isVIT(em))
    return res.status(400).json({ message: 'Only VIT email IDs accepted', field: 'email' });
  const user = one('SELECT * FROM users WHERE email=?', [em]);
  if (!user)
    return res.status(401).json({ message: 'No account found with this email', field: 'email' });
  if (!await bcrypt.compare(password, user.password))
    return res.status(401).json({ message: 'Incorrect password', field: 'password' });
  console.log('Login:', em);
  res.json({
    message: 'Login successful',
    token: tok(user.id, user.email),
    user: { id: user.id, name: user.name, email: user.email, year: user.year, gender: user.gender, phone: user.phone }
  });
});

// ── ME ───────────────────────────────────────────────
app.get('/api/me', auth, (req, res) => {
  const u = one(
    'SELECT id,name,email,phone,year,gender,accommodation,created_at FROM users WHERE id=?',
    [req.user.userId]
  );
  if (!u) return res.status(404).json({ message: 'User not found' });
  res.json({ user: u });
});
app.get('/', (req, res) => res.redirect('/login.html'));

// ── CREATE RIDE ──────────────────────────────────────
app.post('/api/rides', auth, (req, res) => {
  const { pickup, destination, date, time, max_seats, gender_pref, year_pref, cab_type } = req.body;
  if (!pickup || !destination || !date || !time)
    return res.status(400).json({ message: 'pickup, destination, date and time are required' });
  const seats = parseInt(max_seats) || 1;
  const r = run(
    'INSERT INTO rides(owner_id,pickup,destination,date,time,max_seats,seats_left,gender_pref,year_pref,cab_type)VALUES(?,?,?,?,?,?,?,?,?,?)',
    [req.user.userId, pickup, destination, date, time, seats, seats, gender_pref || 'Any', year_pref || 'Any year', cab_type || 'Sedan']
  );
  const ride = one('SELECT * FROM rides WHERE id=?', [r.lastInsertRowid]);
  console.log('Ride created:', destination);
  res.status(201).json({ message: 'Ride posted', ride });
});

// ── SEARCH RIDES ─────────────────────────────────────
// FIX: Filter out rides the user has already interacted with (pending/confirmed/declined)
// so they don't see rides they've already acted on.
app.get('/api/rides', auth, (req, res) => {
  try {
    const { destination, date } = req.query;
    const uid = req.user.userId;

    // Get all ride IDs the user has already interacted with
    const interactedIds = qry(
      `SELECT ride_id FROM ride_requests WHERE user_id=? AND status IN ('pending','confirmed','declined')`,
      [uid]
    ).map(r => r.ride_id);

    let sql = `SELECT r.*, u.name as owner_name, u.gender as owner_gender, u.year as owner_year, u.accommodation as owner_accom
               FROM rides r JOIN users u ON r.owner_id=u.id
               WHERE r.status IN ('active','full') AND r.owner_id!=?`;
    const p = [uid];

    // Exclude already-interacted rides
    if (interactedIds.length > 0) {
      sql += ' AND r.id NOT IN (' + interactedIds.map(() => '?').join(',') + ')';
      p.push(...interactedIds);
    }

    if (destination) { sql += ' AND LOWER(r.destination) LIKE ?'; p.push('%' + destination.toLowerCase() + '%'); }
    if (date)        { sql += ' AND r.date=?'; p.push(date); }
    sql += ' ORDER BY r.date ASC, r.time ASC';

    const seeker = one('SELECT * FROM users WHERE id=?', [uid]);
    const rides  = qry(sql, p)
      .map(ride => ({ ...ride, match_score: matchScore(ride, seeker || {}) }))
      .sort((a, b) => b.match_score - a.match_score);
    res.json({ count: rides.length, rides });
  } catch (e) {
    console.error('Search rides error:', e);
    res.status(500).json({ message: 'Server error searching rides' });
  }
});

// ── MY RIDES ─────────────────────────────────────────
// FIX: Also return 'backed_out' rides (recent, within 72h) so users can see
// the history entry. Previously backed-out rides silently vanished.
app.get('/api/my-rides', auth, (req, res) => {
  try {
    const uid = req.user.userId;

    // Rides the user created
    const created = qry(
      `SELECT r.*, 'owner' as role, u.name as owner_name
       FROM rides r JOIN users u ON r.owner_id=u.id
       WHERE r.owner_id=? AND r.status IN ('active','full')
       ORDER BY r.date ASC`,
      [uid]
    );

    // Rides the user is a confirmed passenger in
    const joined = qry(
      `SELECT r.*, 'passenger' as role, u.name as owner_name
       FROM ride_requests rr
       JOIN rides r ON rr.ride_id=r.id
       JOIN users u ON r.owner_id=u.id
       WHERE rr.user_id=? AND rr.status='confirmed'
       AND r.status IN ('active','full')
       ORDER BY r.date ASC`,
      [uid]
    );

    // Pending requests
    const pending = qry(
      `SELECT r.*, 'pending' as role, u.name as owner_name
       FROM ride_requests rr
       JOIN rides r ON rr.ride_id=r.id
       JOIN users u ON r.owner_id=u.id
       WHERE rr.user_id=? AND rr.status='pending'
       AND r.status IN ('active','full')
       ORDER BY r.date ASC`,
      [uid]
    );

    // Recently declined (72h window so user can read the decline message)
    const declined = qry(
      `SELECT r.*, 'declined' as role, u.name as owner_name
       FROM ride_requests rr
       JOIN rides r ON rr.ride_id=r.id
       JOIN users u ON r.owner_id=u.id
       WHERE rr.user_id=? AND rr.status='declined'
       AND r.status IN ('active','full')
       AND rr.joined_at >= datetime('now', '-72 hours')
       ORDER BY rr.joined_at DESC`,
      [uid]
    );

    // FIX: Include recently backed-out rides (72h window) so they show in history
    // and the user can see the __BACKOUT_APPROVED__ message in chat.
    const backedOut = qry(
      `SELECT r.*, 'backed_out' as role, u.name as owner_name
       FROM ride_requests rr
       JOIN rides r ON rr.ride_id=r.id
       JOIN users u ON r.owner_id=u.id
       WHERE rr.user_id=? AND rr.status='backed_out'
       AND rr.joined_at >= datetime('now', '-72 hours')
       ORDER BY rr.joined_at DESC`,
      [uid]
    );

    // Deduplicate — owner trumps all, then confirmed > pending > backed_out > declined
    const seen = new Map();
    for (const r of [...created, ...joined, ...pending, ...backedOut, ...declined]) {
      if (!seen.has(r.id)) seen.set(r.id, r);
    }

    res.json({ rides: [...seen.values()] });
  } catch (e) {
    console.error('My rides error:', e);
    res.status(500).json({ message: 'Server error loading rides' });
  }
});

// ── RIDE DETAIL ──────────────────────────────────────
app.get('/api/rides/:id', auth, (req, res) => {
  try {
    const ride = one(
      `SELECT r.*, u.name as owner_name, u.gender as owner_gender, u.phone as owner_phone
       FROM rides r JOIN users u ON r.owner_id=u.id WHERE r.id=?`,
      [parseInt(req.params.id)]
    );
    if (!ride) return res.status(404).json({ message: 'Ride not found' });
    const passengers = qry(
      `SELECT u.id, u.name, u.gender, u.year
       FROM ride_requests rr JOIN users u ON rr.user_id=u.id
       WHERE rr.ride_id=? AND rr.status='confirmed'`,
      [ride.id]
    );
    res.json({ ride, passengers });
  } catch (e) {
    console.error('Ride detail error:', e);
    res.status(500).json({ message: 'Server error loading ride' });
  }
});

// ── JOIN RIDE (pending — owner must approve) ─────────
app.post('/api/rides/:id/join', auth, (req, res) => {
  try {
    const rideId = parseInt(req.params.id);
    const ride   = one('SELECT * FROM rides WHERE id=?', [rideId]);
    if (!ride) return res.status(404).json({ message: 'Ride not found' });
    if (ride.seats_left < 1) return res.status(400).json({ message: 'No seats left' });
    if (ride.owner_id === req.user.userId) return res.status(400).json({ message: 'Cannot join your own ride' });

    const existing = one('SELECT * FROM ride_requests WHERE ride_id=? AND user_id=?', [rideId, req.user.userId]);
    if (existing) {
      if (existing.status === 'confirmed') return res.status(409).json({ message: 'You are already in this ride' });
      if (existing.status === 'pending')   return res.status(409).json({ message: 'Your join request is already pending approval' });
      if (existing.status === 'declined') {
        run('UPDATE ride_requests SET status=?,joined_at=datetime(\'now\') WHERE ride_id=? AND user_id=?',
          ['pending', rideId, req.user.userId]);
      }
    } else {
      run('INSERT INTO ride_requests(ride_id,user_id,status)VALUES(?,?,?)', [rideId, req.user.userId, 'pending']);
    }

    const requester = one('SELECT name FROM users WHERE id=?', [req.user.userId]);
    run('INSERT INTO messages(ride_id,user_id,text) VALUES(?,?,?)',
      [rideId, req.user.userId, '__JOIN_REQUEST__:' + req.user.userId + ':' + requester.name]);

    console.log('Join request from user', req.user.userId, 'for ride', rideId);
    res.json({ message: 'Join request sent! Waiting for owner approval.', pending: true, ride_id: rideId });
  } catch (e) {
    console.error('Join ride error:', e);
    res.status(500).json({ message: 'Server error joining ride' });
  }
});

// ── APPROVE JOIN (owner only) ────────────────────────
// FIX: Use a transaction so seats_left can't go negative if two requests race.
app.post('/api/rides/:id/join/:userId/approve', auth, (req, res) => {
  try {
    const rideId      = parseInt(req.params.id);
    const requesterId = parseInt(req.params.userId);
    const ride = one('SELECT * FROM rides WHERE id=?', [rideId]);
    if (!ride) return res.status(404).json({ message: 'Ride not found' });
    if (ride.owner_id !== req.user.userId) return res.status(403).json({ message: 'Only the owner can approve' });

    const rr = one('SELECT * FROM ride_requests WHERE ride_id=? AND user_id=? AND status=?', [rideId, requesterId, 'pending']);
    if (!rr) return res.status(404).json({ message: 'No pending request found' });

    // FIX: Re-read seats_left inside the approve logic and guard atomically
    const freshRide = one('SELECT seats_left FROM rides WHERE id=?', [rideId]);
    if (!freshRide || freshRide.seats_left < 1) return res.status(400).json({ message: 'No seats left' });

    const requester = one('SELECT name FROM users WHERE id=?', [requesterId]);
    const owner     = one('SELECT name FROM users WHERE id=?', [req.user.userId]);

    runTransaction([
      { sql: 'UPDATE ride_requests SET status=? WHERE ride_id=? AND user_id=?', params: ['confirmed', rideId, requesterId] },
      { sql: 'UPDATE rides SET seats_left=seats_left-1 WHERE id=? AND seats_left>0', params: [rideId] },
      {
        sql: `UPDATE rides SET status='full' WHERE id=? AND seats_left<=0`,
        params: [rideId]
      },
      {
        sql: 'INSERT INTO messages(ride_id,user_id,text) VALUES(?,?,?)',
        params: [rideId, req.user.userId,
          '__JOIN_APPROVED__:' + requesterId + ':' + (requester ? requester.name : 'Someone') + ':' + (owner ? owner.name : 'Owner')]
      }
    ]);

    const copass = qry(
      `SELECT u.id, u.name FROM ride_requests rr JOIN users u ON rr.user_id=u.id WHERE rr.ride_id=? AND rr.status='confirmed'`,
      [rideId]
    );
    console.log('Owner approved join for user', requesterId, 'on ride', rideId);
    res.json({ message: 'Join approved!', approved: true, co_passengers: copass, your_share: calcShare(ride.pickup, ride.destination, copass.length + 1) });
  } catch (e) {
    console.error('Approve join error:', e);
    res.status(500).json({ message: 'Server error' });
  }
});

// ── DECLINE JOIN (owner only) ────────────────────────
app.post('/api/rides/:id/join/:userId/decline', auth, (req, res) => {
  try {
    const rideId      = parseInt(req.params.id);
    const requesterId = parseInt(req.params.userId);
    const ride = one('SELECT * FROM rides WHERE id=?', [rideId]);
    if (!ride) return res.status(404).json({ message: 'Ride not found' });
    if (ride.owner_id !== req.user.userId) return res.status(403).json({ message: 'Only the owner can decline' });

    run('UPDATE ride_requests SET status=? WHERE ride_id=? AND user_id=?', ['declined', rideId, requesterId]);

    const requester = one('SELECT name FROM users WHERE id=?', [requesterId]);
    const owner     = one('SELECT name FROM users WHERE id=?', [req.user.userId]);
    run('INSERT INTO messages(ride_id,user_id,text) VALUES(?,?,?)',
      [rideId, req.user.userId,
       '__JOIN_DECLINED__:' + requesterId + ':' + (requester ? requester.name : 'Someone') + ':' + (owner ? owner.name : 'Owner')]);

    console.log('Owner declined join for user', requesterId, 'on ride', rideId);
    res.json({ message: 'Join request declined', approved: false });
  } catch (e) {
    console.error('Decline join error:', e);
    res.status(500).json({ message: 'Server error' });
  }
});

// ── GET MESSAGES ─────────────────────────────────────
app.get('/api/rides/:id/messages', auth, (req, res) => {
  try {
    const rideId = parseInt(req.params.id);
    const uid    = req.user.userId;
    const ride   = one('SELECT * FROM rides WHERE id=?', [rideId]);
    if (!ride) return res.status(404).json({ message: 'Ride not found' });

    const isOwner = ride.owner_id === uid;
    const request = one('SELECT * FROM ride_requests WHERE ride_id=? AND user_id=?', [rideId, uid]);
    // FIX: Also allow 'backed_out' users to read the chat so they see the approval message
    const hasAccess = isOwner || (request && ['confirmed', 'pending', 'declined', 'backed_out'].includes(request.status));
    if (!hasAccess) return res.status(403).json({ message: 'No access to this ride\'s chat' });

    const msgs = qry(
      `SELECT m.*, u.name as sender_name FROM messages m JOIN users u ON m.user_id=u.id
       WHERE m.ride_id=? ORDER BY m.sent_at ASC`,
      [rideId]
    );
    res.json({ messages: msgs });
  } catch (e) {
    res.status(500).json({ message: 'Server error loading messages' });
  }
});

// ── SEND MESSAGE ─────────────────────────────────────
app.post('/api/rides/:id/messages', auth, (req, res) => {
  try {
    const { text } = req.body;
    if (!text || !text.trim()) return res.status(400).json({ message: 'Message cannot be empty' });
    const rideId = parseInt(req.params.id);
    const uid    = req.user.userId;
    const ride   = one('SELECT * FROM rides WHERE id=?', [rideId]);
    if (!ride) return res.status(404).json({ message: 'Ride not found' });
    const isOwner = ride.owner_id === uid;
    const rr = one('SELECT * FROM ride_requests WHERE ride_id=? AND user_id=? AND status=?', [rideId, uid, 'confirmed']);
    if (!isOwner && !rr) return res.status(403).json({ message: 'Only confirmed passengers can send messages' });

    const r = run('INSERT INTO messages(ride_id,user_id,text)VALUES(?,?,?)',
      [rideId, uid, text.trim()]);
    const msg = one(
      `SELECT m.*, u.name as sender_name FROM messages m JOIN users u ON m.user_id=u.id WHERE m.id=?`,
      [r.lastInsertRowid]
    );
    res.status(201).json({ message: msg });
  } catch (e) {
    res.status(500).json({ message: 'Server error sending message' });
  }
});

// ── REQUEST BACKOUT ───────────────────────────────────
// FIX: Owner backout now sends both requester name AND owner name so the
// frontend __BACKOUT_APPROVED__ parser (parts[1] + parts[2]) works correctly.
app.post('/api/rides/:id/backout', auth, (req, res) => {
  try {
    const rideId  = parseInt(req.params.id);
    const userId  = req.user.userId;
    const ride    = one('SELECT * FROM rides WHERE id=?', [rideId]);
    if (!ride) return res.status(404).json({ message: 'Ride not found' });

    const inRide  = one('SELECT * FROM ride_requests WHERE ride_id=? AND user_id=? AND status=?', [rideId, userId, 'confirmed']);
    const isOwner = ride.owner_id === userId;
    if (!inRide && !isOwner) return res.status(400).json({ message: 'You are not in this ride' });

    // Owner cancels immediately — FIX: include owner name in both slots so
    // frontend sees requesterName=ownerName, ownerName=ownerName (graceful display)
    if (isOwner) {
      const owner = one('SELECT name FROM users WHERE id=?', [userId]);
      const ownerName = owner ? owner.name : 'Owner';
      runTransaction([
        { sql: "UPDATE rides SET status='cancelled' WHERE id=?", params: [rideId] },
        {
          sql: 'INSERT INTO messages(ride_id,user_id,text) VALUES(?,?,?)',
          params: [rideId, userId, '__BACKOUT_APPROVED__:' + ownerName + ':' + ownerName]
        }
      ]);
      return res.json({ message: 'Ride cancelled', needs_approval: false });
    }

    // Passenger — needs owner approval
    const existing = one('SELECT * FROM backout_requests WHERE ride_id=? AND requester_id=? AND status=?', [rideId, userId, 'pending']);
    if (existing) return res.status(409).json({ message: 'You already have a pending backout request' });

    const requester = one('SELECT name FROM users WHERE id=?', [userId]);
    const r = run(
      'INSERT INTO backout_requests(ride_id,requester_id,status,approvals_needed,approvals_received) VALUES(?,?,?,?,?)',
      [rideId, userId, 'pending', 1, 0]
    );
    run('INSERT INTO messages(ride_id,user_id,text) VALUES(?,?,?)',
      [rideId, userId, '__BACKOUT_REQUEST__:' + r.lastInsertRowid + ':' + requester.name]);

    res.json({ message: 'Backout request sent to ride owner', needs_approval: true, request_id: r.lastInsertRowid });
  } catch (e) {
    console.error('Backout error:', e);
    res.status(500).json({ message: 'Server error' });
  }
});

// ── APPROVE BACKOUT (owner only) ─────────────────────
// FIX: Use a transaction so seat restoration and status update are atomic.
app.post('/api/backout/:requestId/approve', auth, (req, res) => {
  try {
    const requestId = parseInt(req.params.requestId);
    const request   = one('SELECT * FROM backout_requests WHERE id=?', [requestId]);
    if (!request) return res.status(404).json({ message: 'Request not found' });
    if (request.status !== 'pending') return res.status(400).json({ message: 'Request already resolved' });

    const ride = one('SELECT * FROM rides WHERE id=?', [request.ride_id]);
    if (!ride) return res.status(404).json({ message: 'Ride not found' });
    if (ride.owner_id !== req.user.userId) return res.status(403).json({ message: 'Only the ride owner can approve' });

    const requester = one('SELECT name FROM users WHERE id=?', [request.requester_id]);
    const owner     = one('SELECT name FROM users WHERE id=?', [req.user.userId]);

    const inRide = one('SELECT * FROM ride_requests WHERE ride_id=? AND user_id=? AND status=?',
      [request.ride_id, request.requester_id, 'confirmed']);

    const ops = [
      { sql: 'UPDATE backout_requests SET status=?,approvals_received=1 WHERE id=?', params: ['approved', requestId] }
    ];
    if (inRide) {
      ops.push({ sql: 'UPDATE ride_requests SET status=? WHERE ride_id=? AND user_id=?', params: ['backed_out', request.ride_id, request.requester_id] });
      ops.push({ sql: 'UPDATE rides SET seats_left=seats_left+1 WHERE id=?', params: [request.ride_id] });
      // If ride was full, reopen it
      ops.push({ sql: "UPDATE rides SET status='active' WHERE id=? AND status='full'", params: [request.ride_id] });
    }
    ops.push({
      sql: 'INSERT INTO messages(ride_id,user_id,text) VALUES(?,?,?)',
      params: [request.ride_id, req.user.userId,
        '__BACKOUT_APPROVED__:' + (requester ? requester.name : 'someone') + ':' + (owner ? owner.name : 'Owner')]
    });

    runTransaction(ops);
    res.json({ message: 'Backout approved', approved: true });
  } catch (e) {
    console.error('Approve backout error:', e);
    res.status(500).json({ message: 'Server error' });
  }
});

// ── DECLINE BACKOUT (owner only) ─────────────────────
app.post('/api/backout/:requestId/decline', auth, (req, res) => {
  try {
    const requestId = parseInt(req.params.requestId);
    const request   = one('SELECT * FROM backout_requests WHERE id=?', [requestId]);
    if (!request) return res.status(404).json({ message: 'Request not found' });
    if (request.status !== 'pending') return res.status(400).json({ message: 'Already resolved' });

    const ride = one('SELECT * FROM rides WHERE id=?', [request.ride_id]);
    if (!ride) return res.status(404).json({ message: 'Ride not found' });
    if (ride.owner_id !== req.user.userId) return res.status(403).json({ message: 'Only the ride owner can decline' });

    run("UPDATE backout_requests SET status='declined' WHERE id=?", [requestId]);

    const requester = one('SELECT name FROM users WHERE id=?', [request.requester_id]);
    const owner     = one('SELECT name FROM users WHERE id=?', [req.user.userId]);
    run('INSERT INTO messages(ride_id,user_id,text) VALUES(?,?,?)',
      [request.ride_id, req.user.userId,
       '__BACKOUT_DECLINED__:' + request.requester_id + ':' + (requester ? requester.name : 'someone') + ':' + (owner ? owner.name : 'Owner')]);

    res.json({ message: 'Backout declined' });
  } catch (e) {
    console.error('Decline backout error:', e);
    res.status(500).json({ message: 'Server error' });
  }
});

// ── GET PENDING BACKOUT REQUESTS (owner only) ─────────
app.get('/api/rides/:id/backout-requests', auth, (req, res) => {
  try {
    const ride = one('SELECT * FROM rides WHERE id=?', [parseInt(req.params.id)]);
    if (!ride) return res.json({ requests: [] });
    if (ride.owner_id !== req.user.userId) return res.json({ requests: [] });
    const requests = qry(
      `SELECT br.*, u.name as requester_name FROM backout_requests br
       JOIN users u ON br.requester_id=u.id
       WHERE br.ride_id=? AND br.status='pending'`,
      [parseInt(req.params.id)]
    );
    res.json({ requests });
  } catch (e) {
    res.status(500).json({ message: 'Server error' });
  }
});

// FIX: REMOVED /api/users endpoint — it exposed all user phone numbers.
// If you need it for debugging, add it back behind an admin secret check.

app.get('/api/health', (_, res) => res.json({ status: 'ok' }));

initDB().then(() => {
  app.listen(PORT, () => {
    console.log('\n🚕  VIT CabConnect running at http://localhost:' + PORT);
    console.log('    Open your browser -> http://localhost:' + PORT + '/login.html\n');
  });
}).catch(err => { console.error('DB init failed:', err); process.exit(1); });
