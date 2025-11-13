/*
Triabo License Server - Final
Includes: license signing, activation, verify, revoke, WebAuthn register/auth endpoints,
Telegram notifications (if TELEGRAM_BOT_TOKEN + TELEGRAM_CHAT_ID in env), admin auth via ADMIN_TOKEN env.
Also serves a simple admin HTML UI at /admin protected by ADMIN_TOKEN header.
Requires: private.pem, public.pem in project root.
*/
const express = require('express');
const bodyParser = require('body-parser');
const fs = require('fs');
const path = require('path');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const sqlite3 = require('sqlite3').verbose();
const fetch = require('node-fetch');
const cors = require('cors');
const { generateRegistrationOptions, verifyRegistrationResponse, generateAuthenticationOptions, verifyAuthenticationResponse } = require('@simplewebauthn/server');

const PRIVATE_KEY_PATH = path.join(__dirname, 'private.pem');
const PUBLIC_KEY_PATH = path.join(__dirname, 'public.pem');
if(!fs.existsSync(PRIVATE_KEY_PATH) || !fs.existsSync(PUBLIC_KEY_PATH)){
  console.error('Missing private.pem/public.pem - see README to generate keys.');
  // continue, server will fail later if keys missing
}
const PRIVATE_KEY = fs.existsSync(PRIVATE_KEY_PATH) ? fs.readFileSync(PRIVATE_KEY_PATH) : null;
const PUBLIC_KEY = fs.existsSync(PUBLIC_KEY_PATH) ? fs.readFileSync(PUBLIC_KEY_PATH) : null;

const DB_PATH = path.join(__dirname, 'licenses.db');
const db = new sqlite3.Database(DB_PATH);

// init tables
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS licenses (
    license_key TEXT PRIMARY KEY,
    type TEXT,
    max_activations INTEGER DEFAULT 1,
    hwid_hash TEXT,
    owner_email TEXT,
    created_at INTEGER,
    expires_at INTEGER,
    revoked INTEGER DEFAULT 0,
    trial_used INTEGER DEFAULT 0
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS activations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    license_key TEXT,
    hwid_hash TEXT,
    ip TEXT,
    country TEXT,
    asn TEXT,
    user_agent TEXT,
    created_at INTEGER
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS webauthn_credentials (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT,
    credential_id TEXT,
    public_key TEXT,
    sign_count INTEGER DEFAULT 0,
    created_at INTEGER
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS webauthn_challenges (
    email TEXT PRIMARY KEY,
    challenge TEXT,
    created_at INTEGER
  )`);
});

const app = express();
app.use(helmet());
app.use(cors());
app.use(bodyParser.json({limit: '200kb'}));
app.use(express.static(path.join(__dirname, 'public')));

// Rate limiter (general)
const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: 120,
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(limiter);

function adminAuth(req,res,next){
  const token = req.headers['x-admin-token'] || req.query.admin_token;
  if(!process.env.ADMIN_TOKEN){
    return res.status(403).json({ error: 'admin_protection_not_configured' });
  }
  if(token !== process.env.ADMIN_TOKEN) return res.status(401).json({ error: 'unauthorized' });
  next();
}

// helper: hash hwid
function hashHWID(hwid){
  return crypto.createHmac('sha256', process.env.HWID_SALT || 'triabo_server_secret_salt_v1').update(hwid).digest('hex');
}

// helper: geo lookup via ip-api or ipinfo
async function geoLookup(ip){
  try {
    const API = process.env.IPINFO_TOKEN;
    if(API){
      const res = await fetch(`https://ipinfo.io/${ip}/json?token=${API}`);
      if(res.ok) return await res.json();
    } else {
      const res = await fetch(`http://ip-api.com/json/${ip}`);
      if(res.ok) return await res.json();
    }
  } catch(e){
    return null;
  }
  return null;
}

// telegram notifier
async function notifyAdmin(text){
  try {
    const BOT = process.env.TELEGRAM_BOT_TOKEN;
    const CHAT = process.env.TELEGRAM_CHAT_ID;
    if(!BOT || !CHAT) return;
    await fetch(`https://api.telegram.org/bot${BOT}/sendMessage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ chat_id: CHAT, text })
    });
  } catch(e){
    console.error('notifyAdmin error', e.message);
  }
}

// sign license payload -> JWT RS256
function signLicense(payload){
  if(!PRIVATE_KEY) throw new Error('private.pem missing');
  return jwt.sign(payload, PRIVATE_KEY, { algorithm: 'RS256' });
}

// verify token
function verifyToken(token){
  if(!PUBLIC_KEY) return null;
  try {
    return jwt.verify(token, PUBLIC_KEY, { algorithms: ['RS256'] });
  } catch(e){
    return null;
  }
}

// create license entry (admin tool) - protected
app.post('/api/sign', adminAuth, async (req,res) => {
  const { license_key, type='full', max_activations=1, owner_email=null, expires_at=null } = req.body || {};
  if(!license_key) return res.status(400).json({ error: 'license_key required' });
  const created_at = Date.now();
  db.run(`INSERT OR REPLACE INTO licenses(license_key,type,max_activations,owner_email,created_at,expires_at,revoked,trial_used) VALUES(?,?,?,?,?,?,0,0)`,
    [license_key,type,max_activations,owner_email,created_at, expires_at], function(err){
      if(err) return res.status(500).json({ error: err.message });
      const payload = { license_key, type, max_activations, owner_email, created_at, expires_at };
      const token = signLicense(payload);
      notifyAdmin && notifyAdmin(`License created: ${license_key} owner=${owner_email||'N/A'}`);
      return res.json({ ok:true, token });
    });
});

// activation
app.post('/api/activate', async (req,res) => {
  const { license_key, hwid, client_info } = req.body || {};
  if(!license_key || !hwid) return res.status(400).json({ error: 'license_key and hwid required' });
  const hwid_hash = hashHWID(hwid);
  const ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress || req.socket.remoteAddress;
  const ua = (req.headers['user-agent']||'').slice(0,500);
  const geo = await geoLookup(ip).catch(()=>null);
  const country = geo && (geo.country || geo.countryCode) ? (geo.country || geo.countryCode) : null;
  const asn = geo && geo.org ? geo.org : null;

  db.get(`SELECT * FROM licenses WHERE license_key = ?`, [license_key], (err,row) => {
    if(err) return res.status(500).json({ error: err.message });
    if(!row) return res.status(404).json({ error: 'invalid_license' });
    if(row.revoked) return res.status(403).json({ error: 'revoked' });

    if(!row.hwid_hash){
      if(row.trial_used && row.type==='trial') return res.status(403).json({ error:'trial_already_used' });
      db.run(`UPDATE licenses SET hwid_hash = ?, trial_used = CASE WHEN type='trial' THEN 1 ELSE trial_used END WHERE license_key = ?`, [hwid_hash, license_key]);
      db.run(`INSERT INTO activations(license_key, hwid_hash, ip, country, asn, user_agent, created_at) VALUES(?,?,?,?,?,?,?)`,
        [license_key, hwid_hash, ip, country, asn, ua, Date.now()]);
      const payload = { license_key, type: row.type || 'full', hwid_hash, issued_at: Date.now() };
      const token = signLicense(payload);
      notifyAdmin && notifyAdmin(`Activation: ${license_key} ip=${ip} country=${country||'N/A'} asn=${asn||'N/A'}`);
      return res.json({ ok:true, token });
    } else {
      if(hwid_hash === row.hwid_hash){
        db.run(`INSERT INTO activations(license_key, hwid_hash, ip, country, asn, user_agent, created_at) VALUES(?,?,?,?,?,?,?)`,
          [license_key, hwid_hash, ip, country, asn, ua, Date.now()]);
        const payload = { license_key, type: row.type || 'full', hwid_hash, issued_at: Date.now() };
        const token = signLicense(payload);
        notifyAdmin && notifyAdmin(`Activation: ${license_key} (re-activation) ip=${ip}`);
        return res.json({ ok:true, token });
      } else {
        db.all(`SELECT * FROM activations WHERE license_key = ? ORDER BY created_at DESC LIMIT 5`, [license_key], (err, rows) => {
          if(err) return res.status(500).json({ error: err.message });
          const recent = rows || [];
          const recentCountries = new Set(recent.map(r => r.country).filter(Boolean));
          const recentASNs = new Set(recent.map(r => r.asn).filter(Boolean));
          if(country && recentCountries.size>0 && !recentCountries.has(country)){
            return res.status(403).json({ error:'hwid_mismatch_location_change' });
          }
          if(asn && recentASNs.size>0 && !recentASNs.has(asn)){
            return res.status(403).json({ error:'hwid_mismatch_network_change' });
          }
          // fallback deny
          notifyAdmin && notifyAdmin(`Suspicious activation attempt for ${license_key} from ip=${ip} country=${country} asn=${asn}`);
          return res.status(403).json({ error:'hwid_mismatch' });
        });
      }
    }
  });
});

// verify token
app.post('/api/verify', (req,res) => {
  const { token } = req.body || {};
  if(!token) return res.status(400).json({ error:'token required' });
  const valid = verifyToken(token);
  if(!valid) return res.status(403).json({ error:'invalid_token' });
  return res.json({ ok:true, data: valid });
});

// revoke license - protected
app.post('/api/revoke', adminAuth, (req,res) => {
  const { license_key } = req.body || {};
  if(!license_key) return res.status(400).json({ error: 'license_key required' });
  db.run(`UPDATE licenses SET revoked = 1 WHERE license_key = ?`, [license_key], function(err){
    if(err) return res.status(500).json({ error: err.message });
    notifyAdmin && notifyAdmin(`License revoked: ${license_key}`);
    return res.json({ ok:true });
  });
});

// admin list (protected)
app.get('/api/licenses', adminAuth, (req,res) => {
  db.all(`SELECT * FROM licenses ORDER BY created_at DESC LIMIT 500`, [], (err,rows) => {
    if(err) return res.status(500).json({ error: err.message });
    return res.json({ ok:true, licenses: rows });
  });
});

/* WebAuthn endpoints using @simplewebauthn/server
   - /webauthn/register/request  -> returns options (challenge) for navigator.credentials.create
   - /webauthn/register/complete -> verifies attestation, stores credential
   - /webauthn/auth/request      -> returns options for navigator.credentials.get
   - /webauthn/auth/complete     -> verifies assertion
*/
const rpName = process.env.RP_NAME || 'Triabo';
const rpID = process.env.RP_ID || 'localhost';
const origin = process.env.ORIGIN || 'https://localhost:3000';

app.post('/webauthn/register/request', async (req,res) => {
  const { email } = req.body || {};
  if(!email) return res.status(400).json({ error:'email required' });
  // create options
  const opts = generateRegistrationOptions({
    rpName,
    rpID,
    userID: Buffer.from(email).toString('base64'),
    userName: email,
    timeout: 60000,
    attestationType: 'none',
    authenticatorSelection: { userVerification: 'preferred' }
  });
  // store challenge
  db.run(`INSERT OR REPLACE INTO webauthn_challenges(email,challenge,created_at) VALUES(?,?,?)`, [email, opts.challenge, Date.now()]);
  return res.json(opts);
});

app.post('/webauthn/register/complete', async (req,res) => {
  const { email, attestation } = req.body || {};
  if(!email || !attestation) return res.status(400).json({ error:'email+attestation required' });
  // fetch challenge
  db.get(`SELECT challenge FROM webauthn_challenges WHERE email = ?`, [email], async (err,row) => {
    if(err) return res.status(500).json({ error: err.message });
    if(!row) return res.status(400).json({ error:'no_challenge' });
    const expectedChallenge = row.challenge;
    try {
      const verification = await verifyRegistrationResponse({
        response: attestation,
        expectedChallenge,
        expectedOrigin: origin,
        expectedRPID: rpID
      });
      const { verified, registrationInfo } = verification;
      if(!verified) return res.status(400).json({ error:'registration_not_verified' });
      const { credentialPublicKey, credentialID, counter } = registrationInfo;
      // store credential
      db.run(`INSERT INTO webauthn_credentials(email,credential_id,public_key,sign_count,created_at) VALUES(?,?,?,?,?)`,
        [email, Buffer.from(credentialID).toString('base64'), credentialPublicKey.toString('base64'), counter || 0, Date.now()]);
      return res.json({ ok:true });
    } catch(e){
      return res.status(400).json({ error: e.message || 'verification_failed' });
    }
  });
});

app.post('/webauthn/auth/request', (req,res) => {
  const { email } = req.body || {};
  if(!email) return res.status(400).json({ error:'email required' });
  db.all(`SELECT credential_id FROM webauthn_credentials WHERE email = ?`, [email], (err, rows) => {
    if(err) return res.status(500).json({ error: err.message });
    const allowCredentials = (rows || []).map(r => ({ id: r.credential_id, type: 'public-key', transports: ['usb','ble','nfc','internal'] }));
    const opts = generateAuthenticationOptions({ timeout:60000, allowCredentials, userVerification: 'preferred' });
    db.run(`INSERT OR REPLACE INTO webauthn_challenges(email,challenge,created_at) VALUES(?,?,?)`, [email, opts.challenge, Date.now()]);
    return res.json(opts);
  });
});

app.post('/webauthn/auth/complete', async (req,res) => {
  const { email, assertion } = req.body || {};
  if(!email || !assertion) return res.status(400).json({ error:'email+assertion required' });
  db.get(`SELECT challenge FROM webauthn_challenges WHERE email = ?`, [email], async (err,row) => {
    if(err) return res.status(500).json({ error: err.message });
    if(!row) return res.status(400).json({ error:'no_challenge' });
    const expectedChallenge = row.challenge;
    db.get(`SELECT credential_id, public_key, sign_count FROM webauthn_credentials WHERE email = ?`, [email], async (err, cred) => {
      if(err) return res.status(500).json({ error: err.message });
      if(!cred) return res.status(400).json({ error:'no_credential' });
      try {
        const verification = await verifyAuthenticationResponse({
          response: assertion,
          expectedChallenge,
          expectedOrigin: origin,
          expectedRPID: rpID,
          authenticator: {
            credentialPublicKey: Buffer.from(cred.public_key, 'base64'),
            credentialID: Buffer.from(cred.credential_id, 'base64'),
            counter: cred.sign_count || 0
          }
        });
        const { verified, authenticationInfo } = verification;
        if(!verified) return res.status(400).json({ error:'auth_not_verified' });
        db.run(`UPDATE webauthn_credentials SET sign_count = ? WHERE email = ?`, [authenticationInfo.newCounter || 0, email]);
        return res.json({ ok:true });
      } catch(e){
        return res.status(400).json({ error: e.message || 'auth_verification_failed' });
      }
    });
  });
});

// Serve admin UI (protected)
app.get('/admin', adminAuth, (req,res) => {
  res.sendFile(path.join(__dirname,'public','admin.html'));
});

// Simple admin API to fetch activations and licenses (protected)
app.get('/api/admin/overview', adminAuth, (req,res) => {
  db.serialize(() => {
    db.all(`SELECT license_key,type,owner_email,created_at,expires_at,revoked FROM licenses ORDER BY created_at DESC LIMIT 200`, [], (err,licenses) => {
      if(err) return res.status(500).json({ error: err.message });
      db.all(`SELECT license_key,ip,country,asn,user_agent,created_at FROM activations ORDER BY created_at DESC LIMIT 200`, [], (err2,activations) => {
        if(err2) return res.status(500).json({ error: err2.message });
        return res.json({ ok:true, licenses, activations });
      });
    });
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, ()=>{
  console.log('License server listening on', PORT);
  // send server started notification
  if(typeof notifyAdmin === 'function'){
    notifyAdmin(`Triabo license server started on port ${PORT}`);
  }
});
