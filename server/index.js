// Static Visual — единый сервер: статика (site) + API + гейт скачивания.
// Хранилище: Upstash Redis (env UPSTASH_REDIS_REST_URL / _TOKEN). Без env — in-memory (для локального теста).
// Node-нативный scrypt → старые пароли с Netlify подходят как есть.
'use strict';

const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const PORT = Number(process.env.PORT || 8000);
const SITE_DIR = path.join(__dirname, '..', 'public');
const GITHUB_LATEST =
  'https://github.com/s3rroz/static-visual/releases/latest/download/StaticVisual.exe';

const SESSION_TTL = 30 * 24 * 60 * 60; // сек
const DAY = 24 * 60 * 60 * 1000;
const DEFAULT_AMOUNT = 5.99;

// ─────────────────────────────  storage (Upstash Redis или in-memory)

const REDIS_URL = process.env.UPSTASH_REDIS_REST_URL || '';
const REDIS_TOKEN = process.env.UPSTASH_REDIS_REST_TOKEN || '';
const mem = REDIS_URL ? null : new Map();

async function cmd(args) {
  const res = await fetch(REDIS_URL, {
    method: 'POST',
    headers: { authorization: 'Bearer ' + REDIS_TOKEN, 'content-type': 'application/json' },
    body: JSON.stringify(args),
  });
  if (!res.ok) throw new Error('redis ' + res.status);
  return res.json();
}

async function kvGet(key) {
  if (mem) { const v = mem.get(key); return v == null ? null : JSON.parse(v); }
  const v = await cmd(['GET', key]);
  return v == null ? null : JSON.parse(v);
}
async function kvSet(key, val, ttlSec) {
  if (mem) { mem.set(key, JSON.stringify(val)); return; }
  if (ttlSec) await cmd(['SET', key, JSON.stringify(val), 'EX', String(ttlSec)]);
  else await cmd(['SET', key, JSON.stringify(val)]);
}
async function kvDel(key) {
  if (mem) { mem.delete(key); return; }
  await cmd(['DEL', key]);
}
async function kvKeys(prefix) {
  if (mem) return [...mem.keys()].filter((k) => k.startsWith(prefix));
  return (await cmd(['KEYS', prefix + '*'])) || [];
}
async function refEmail(code) {
  code = String(code || '').trim().toUpperCase();
  if (!code) return '';
  if (mem) return mem.get('ref:' + code) || '';
  return (await cmd(['GET', 'ref:' + code])) || '';
}
async function setRef(code, email) {
  if (mem) mem.set('ref:' + code, email);
  else await cmd(['SET', 'ref:' + code, email]);
}

// ─────────────────────────────  data helpers

const normalizeEmail = (v) => String(v || '').trim().toLowerCase();
const validEmail = (v) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v);
const round2 = (n) => Math.round((Number(n) + Number.EPSILON) * 100) / 100;
function envList(name) { return (process.env[name] || '').split(',').map((s) => s.trim().toLowerCase()).filter(Boolean); }
const isAdminEmail = (e) => envList('ADMIN_EMAILS').includes(normalizeEmail(e));
const isAffiliateEmail = (e) => envList('AFFILIATE_EMAILS').includes(normalizeEmail(e));
function affiliateRate() { const r = parseFloat(process.env.AFFILIATE_RATE); return Number.isFinite(r) && r > 0 && r < 1 ? r : 0.2; }
function maskEmail(e) { const at = e.indexOf('@'); if (at <= 1) return e; const n = e.slice(0, at); return n.slice(0, 2) + '•'.repeat(Math.max(1, n.length - 2)) + e.slice(at); }

const getUser = (email) => kvGet('user:' + email);
const saveUser = (u) => kvSet('user:' + u.email, u);
const delUser = (email) => kvDel('user:' + email);
async function listUsers() {
  const keys = await kvKeys('user:');
  const out = [];
  for (const k of keys) { const u = await kvGet(k); if (u) out.push(u); }
  out.sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));
  return out;
}
const getSale = (id) => kvGet('sale:' + id);
const saveSale = (s) => kvSet('sale:' + s.id, s);
async function listSales() {
  const keys = await kvKeys('sale:');
  const out = [];
  for (const k of keys) { const s = await kvGet(k); if (s) out.push(s); }
  out.sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));
  return out;
}

async function createSession(email) {
  const token = crypto.randomBytes(32).toString('hex');
  await kvSet('sess:' + token, { email, created: Date.now(), exp: Date.now() + SESSION_TTL * 1000 }, SESSION_TTL);
  return token;
}
const getSession = (token) => (token ? kvGet('sess:' + token) : null);
const destroySession = (token) => (token ? kvDel('sess:' + token) : Promise.resolve());

async function ensureRefCode(u) {
  if (u && !u.refCode) {
    u.refCode = await uniqueRefCode();
    await saveUser(u);
    await setRef(u.refCode, u.email);
  }
  return u;
}
async function uniqueRefCode() {
  let c;
  do { c = makeRefCode(); } while (await refEmail(c));
  return c;
}

// ─────────────────────────────  crypto (scrypt) / ключи

function hashPassword(password, salt) {
  const s = salt || crypto.randomBytes(16).toString('hex');
  return { salt: s, hash: crypto.scryptSync(password, s, 64).toString('hex') };
}
function verifyPassword(password, salt, hash) {
  try {
    const test = crypto.scryptSync(password, salt, 64).toString('hex');
    return test.length === hash.length && crypto.timingSafeEqual(Buffer.from(test, 'hex'), Buffer.from(hash, 'hex'));
  } catch { return false; }
}
function randomKey() {
  const a = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const bytes = crypto.randomBytes(20);
  let chars = '';
  for (let i = 0; i < 20; i++) chars += a[bytes[i] % a.length];
  const groups = [];
  for (let i = 0; i < 20; i += 4) groups.push(chars.slice(i, i + 4));
  return 'SV-' + groups.join('-');
}
function makeRefCode() {
  const a = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';
  const bytes = crypto.randomBytes(8);
  let s = '';
  for (let i = 0; i < 8; i++) s += a[bytes[i] % a.length];
  return s;
}
const randomId = () => crypto.randomBytes(8).toString('hex');

function createUser(email, salt, hash, discord, refCode, referredBy) {
  return {
    email, salt, hash,
    discord: String(discord || '').slice(0, 60),
    plan: 'none', licenseKey: '', hwid: '', revoked: false,
    refCode: refCode || '', referredBy: referredBy || '', refManual: false, saleCreated: false,
    createdAt: Date.now(), activatedAt: 0, lastSeen: 0,
  };
}
function publicUser(u) {
  return {
    email: u.email, plan: u.plan,
    licenseKey: u.licenseKey || '', hasKey: !!u.licenseKey,
    hwidBound: !!u.hwid, hwidPreview: u.hwid ? u.hwid.slice(0, 12) : '',
    revoked: !!u.revoked, discord: u.discord || '',
    refCode: u.refCode || '', referredBy: u.referredBy || '',
    isAffiliate: isAffiliateEmail(u.email), isAdmin: isAdminEmail(u.email),
    createdAt: u.createdAt || 0, activatedAt: u.activatedAt || 0, lastSeen: u.lastSeen || 0,
  };
}
function enrich(users) {
  const refCount = new Map(), refConv = new Map();
  for (const u of users) if (u.referredBy) {
    refCount.set(u.referredBy, (refCount.get(u.referredBy) || 0) + 1);
    if (u.licenseKey) refConv.set(u.referredBy, (refConv.get(u.referredBy) || 0) + 1);
  }
  return users.map((u) => ({
    ...publicUser(u), hwid: u.hwid || '',
    refCount: refCount.get(u.email) || 0, refConverted: refConv.get(u.email) || 0,
  }));
}
function summarize(sales) {
  const byAff = new Map(); let gross = 0, commissionTotal = 0, paid = 0, pending = 0, saleCount = 0;
  const bucket = (e) => { if (!byAff.has(e)) byAff.set(e, { email: e, sales: 0, revenue: 0, commission: 0, paid: 0, pending: 0 }); return byAff.get(e); };
  for (const s of sales) { if (s.voided) continue;
    const b = bucket(s.affiliateEmail || '');
    b.sales++; b.revenue = round2(b.revenue + (s.amount || 0)); b.commission = round2(b.commission + (s.commission || 0));
    if (s.paid) b.paid = round2(b.paid + (s.commission || 0)); else b.pending = round2(b.pending + (s.commission || 0));
    gross = round2(gross + (s.amount || 0)); commissionTotal = round2(commissionTotal + (s.commission || 0));
    if (s.paid) paid = round2(paid + (s.commission || 0)); else pending = round2(pending + (s.commission || 0));
    saleCount++;
  }
  return { totals: { gross, commissionTotal, paid, pending, saleCount }, byAffiliate: [...byAff.values()].filter((x) => x.email).sort((a, b) => b.commission - a.commission) };
}

// ─────────────────────────────  HTTP utils

const CORS = {
  'access-control-allow-origin': '*',
  'access-control-allow-methods': 'GET,POST,DELETE,OPTIONS',
  'access-control-allow-headers': 'authorization,content-type',
};
function sendJson(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...CORS });
  res.end(body);
}
async function readBody(req) {
  let raw = '';
  for await (const c of req) raw += c;
  try { return JSON.parse(raw || '{}'); } catch { return {}; }
}
const bearer = (req) => (req.headers.authorization || '').replace(/^Bearer\s+/i, '').trim();
async function authUser(req) { const s = await getSession(bearer(req)); return s ? await getUser(s.email) : null; }

// ─────────────────────────────  handlers

async function hRegister(req, res) {
  const b = await readBody(req);
  const email = normalizeEmail(b.email), password = String(b.password || ''), discord = String(b.discord || '').trim();
  const refInput = String(b.ref || '').trim().toUpperCase();
  if (!validEmail(email)) return sendJson(res, 400, { ok: false, error: 'bad_email' });
  if (password.length < 6) return sendJson(res, 400, { ok: false, error: 'weak_password' });
  if (await getUser(email)) return sendJson(res, 409, { ok: false, error: 'email_taken' });
  let referredBy = '';
  if (refInput) { const r = await refEmail(refInput); if (r && r !== email) referredBy = r; }
  const { salt, hash } = hashPassword(password);
  const refCode = await uniqueRefCode();
  const user = createUser(email, salt, hash, discord, refCode, referredBy);
  await saveUser(user); await setRef(refCode, email);
  const token = await createSession(email);
  sendJson(res, 200, { ok: true, token, user: publicUser(user) });
}
async function hLogin(req, res) {
  const b = await readBody(req);
  const email = normalizeEmail(b.email), password = String(b.password || '');
  const user = await getUser(email);
  if (!user || !verifyPassword(password, user.salt, user.hash)) {
    await new Promise((r) => setTimeout(r, 400));
    return sendJson(res, 401, { ok: false, error: 'bad_credentials' });
  }
  await ensureRefCode(user);
  const token = await createSession(email);
  sendJson(res, 200, { ok: true, token, user: publicUser(user) });
}
async function hLogout(req, res) { await destroySession(bearer(req)); sendJson(res, 200, { ok: true }); }
async function hMe(req, res) {
  const user = await authUser(req);
  if (!user) return sendJson(res, 401, { ok: false, error: 'unauthorized' });
  await ensureRefCode(user);
  sendJson(res, 200, { ok: true, user: publicUser(user) });
}
async function hActivate(req, res) {
  const user = await authUser(req);
  if (!user) return sendJson(res, 401, { ok: false, error: 'unauthorized' });
  const b = await readBody(req);
  const key = String(b.key || '').trim().toUpperCase(), hwid = String(b.hwid || '').trim();
  if (!key || !hwid) return sendJson(res, 400, { ok: false, error: 'missing_params' });
  if (user.revoked) return sendJson(res, 403, { ok: false, error: 'revoked' });
  if (!user.licenseKey) return sendJson(res, 404, { ok: false, error: 'no_license' });
  if (key !== user.licenseKey) return sendJson(res, 400, { ok: false, error: 'wrong_key' });
  if (!user.hwid) {
    user.hwid = hwid; user.activatedAt = Date.now(); user.lastSeen = Date.now();
    await saveUser(user);
    return sendJson(res, 200, { ok: true, status: 'activated', user: publicUser(user) });
  }
  if (user.hwid !== hwid) return sendJson(res, 409, { ok: false, error: 'hwid_mismatch' });
  user.lastSeen = Date.now(); await saveUser(user);
  sendJson(res, 200, { ok: true, status: 'ok', user: publicUser(user) });
}
async function hSession(req, res) {
  const user = await authUser(req);
  if (!user) return sendJson(res, 401, { ok: false, error: 'unauthorized' });
  const b = await readBody(req); const hwid = String(b.hwid || '').trim();
  if (user.revoked) return sendJson(res, 403, { ok: false, error: 'revoked' });
  if (!user.licenseKey) return sendJson(res, 404, { ok: false, error: 'no_license' });
  if (!user.hwid) return sendJson(res, 409, { ok: false, error: 'not_activated' });
  if (!hwid || user.hwid !== hwid) return sendJson(res, 409, { ok: false, error: 'hwid_mismatch' });
  user.lastSeen = Date.now(); await saveUser(user);
  sendJson(res, 200, { ok: true, status: 'ok' });
}
async function hReferrals(req, res) {
  const user = await authUser(req);
  if (!user) return sendJson(res, 401, { ok: false, error: 'unauthorized' });
  await ensureRefCode(user);
  const all = await listUsers();
  const invited = all.filter((u) => u.referredBy === user.email)
    .map((u) => ({ email: u.email, hasKey: !!u.licenseKey, createdAt: u.createdAt || 0 }))
    .sort((a, b) => b.createdAt - a.createdAt);
  sendJson(res, 200, { ok: true, refCode: user.refCode, invited, count: invited.length, converted: invited.filter((u) => u.hasKey).length });
}
async function hAffiliate(req, res) {
  const user = await authUser(req);
  if (!user) return sendJson(res, 401, { ok: false, error: 'unauthorized' });
  await ensureRefCode(user);
  const rate = affiliateRate();
  const [sales, users] = await Promise.all([listSales(), listUsers()]);
  const mine = sales.filter((s) => s.affiliateEmail === user.email && !s.voided);
  let revenue = 0, earned = 0, paid = 0;
  for (const s of mine) { revenue = round2(revenue + (s.amount || 0)); earned = round2(earned + (s.commission || 0)); if (s.paid) paid = round2(paid + (s.commission || 0)); }
  sendJson(res, 200, {
    ok: true, isAffiliate: isAffiliateEmail(user.email), rate, refCode: user.refCode || '',
    stats: { registrations: users.filter((u) => u.referredBy === user.email).length, sales: mine.length, revenue, earned, paid, pending: round2(earned - paid) },
    sales: mine.slice(0, 50).map((s) => ({ id: s.id, buyer: maskEmail(s.buyerEmail), amount: s.amount, commission: s.commission, paid: !!s.paid, date: s.createdAt })),
  });
}
async function hAdmin(req, res) {
  const b = await readBody(req); const action = String(b.action || '');
  if (action === 'import') {
    const mt = process.env.MIGRATE_TOKEN || '';
    const admin = await authUser(req); const byAdmin = admin && isAdminEmail(admin.email);
    const byToken = mt && String(b.token || '') === mt;
    if (!byAdmin && !byToken) return sendJson(res, 401, { ok: false, error: 'unauthorized' });
    let nu = 0, ns = 0;
    for (const raw of (Array.isArray(b.users) ? b.users : [])) {
      const email = normalizeEmail(raw.email); if (!email) continue;
      const u = { ...raw, email }; if (!u.refCode) u.refCode = await uniqueRefCode();
      await saveUser(u); await setRef(u.refCode, email); nu++;
    }
    for (const raw of (Array.isArray(b.sales) ? b.sales : [])) { const s = { ...raw }; if (!s.id) s.id = randomId(); await saveSale(s); ns++; }
    return sendJson(res, 200, { ok: true, users: nu, sales: ns });
  }
  const admin = await authUser(req);
  if (!admin || !isAdminEmail(admin.email)) return sendJson(res, 401, { ok: false, error: 'unauthorized' });

  if (action === 'users') return sendJson(res, 200, { ok: true, users: enrich(await listUsers()) });
  if (action === 'stats') {
    const users = await listUsers(); const sales = await listSales(); const rows = enrich(users);
    const { totals, byAffiliate } = summarize(sales); const now = Date.now();
    return sendJson(res, 200, { ok: true, stats: {
      total: rows.length, withKey: rows.filter((u) => u.hasKey).length, active: rows.filter((u) => u.hwidBound).length,
      banned: rows.filter((u) => u.revoked).length, referred: rows.filter((u) => u.referredBy).length, referrers: rows.filter((u) => u.refCount > 0).length,
      new7: rows.filter((u) => now - (u.createdAt || 0) < 7 * DAY).length, new30: rows.filter((u) => now - (u.createdAt || 0) < 30 * DAY).length, ...totals },
      topAffiliates: byAffiliate.slice(0, 10).map((a) => { const u = users.find((x) => x.email === a.email); return { email: a.email, refCode: u?.refCode || '', sales: a.sales, commission: a.commission, paid: a.paid, pending: a.pending }; }) });
  }
  if (action === 'issue') {
    const email = normalizeEmail(b.email); const user = await getUser(email);
    if (!user) return sendJson(res, 404, { ok: false, error: 'user_not_found' });
    const key = user.licenseKey || randomKey(); user.licenseKey = key; user.plan = 'lifetime'; user.revoked = false;
    if (!user.saleCreated) {
      user.saleCreated = true; await saveUser(user);
      const amt = Number(b.amount); const amount = Number.isFinite(amt) && amt >= 0 ? amt : DEFAULT_AMOUNT;
      const affiliateEmail = user.referredBy || ''; let refCode = '';
      if (affiliateEmail) { const au = await getUser(affiliateEmail); refCode = au?.refCode || ''; }
      const commission = affiliateEmail ? round2(amount * affiliateRate()) : 0;
      const sale = { id: randomId(), buyerEmail: email, affiliateEmail, refCode, amount: round2(amount), rate: affiliateRate(), commission, voided: false, paid: false, paidAt: 0, createdAt: Date.now() };
      await saveSale(sale);
      return sendJson(res, 200, { ok: true, key, saleId: sale.id, affiliateEmail, commission, user: publicUser(user) });
    }
    await saveUser(user); return sendJson(res, 200, { ok: true, key, user: publicUser(user) });
  }
  if (action === 'sales') { const sales = await listSales(); return sendJson(res, 200, { ok: true, sales, ...summarize(sales) }); }
  if (action === 'markpaid') {
    if (b.saleId) { const s = await getSale(String(b.saleId)); if (!s) return sendJson(res, 404, { ok: false, error: 'sale_not_found' }); s.paid = true; s.paidAt = Date.now(); await saveSale(s); return sendJson(res, 200, { ok: true }); }
    if (b.affiliateEmail) { const t = normalizeEmail(b.affiliateEmail); const sales = await listSales(); let n = 0; for (const s of sales) if (s.affiliateEmail === t && !s.paid && !s.voided) { s.paid = true; s.paidAt = Date.now(); await saveSale(s); n++; } return sendJson(res, 200, { ok: true, marked: n }); }
    return sendJson(res, 400, { ok: false, error: 'missing_params' });
  }
  if (action === 'void') { const s = await getSale(String(b.saleId)); if (!s) return sendJson(res, 404, { ok: false, error: 'sale_not_found' }); s.voided = b.voided !== false; await saveSale(s); return sendJson(res, 200, { ok: true, voided: s.voided }); }
  if (action === 'setref') {
    const email = normalizeEmail(b.email); const buyer = await getUser(email); if (!buyer) return sendJson(res, 404, { ok: false, error: 'user_not_found' });
    const ref = normalizeEmail(b.referrer); const sales = await listSales(); const sale = sales.find((x) => x.buyerEmail === email && !x.voided);
    if (!ref) { if (sale && sale.paid) return sendJson(res, 400, { ok: false, error: 'sale_paid' }); buyer.referredBy = ''; buyer.refManual = false; await saveUser(buyer); if (sale) { sale.affiliateEmail = ''; sale.refCode = ''; sale.commission = 0; await saveSale(sale); } return sendJson(res, 200, { ok: true, referredBy: '', cleared: true, reassigned: !!sale }); }
    if (ref === email) return sendJson(res, 400, { ok: false, error: 'self_referral' });
    const refUser = await getUser(ref); if (!refUser) return sendJson(res, 404, { ok: false, error: 'referrer_not_found' });
    await ensureRefCode(refUser); if (sale && sale.paid) return sendJson(res, 400, { ok: false, error: 'sale_paid' });
    buyer.referredBy = ref; buyer.refManual = true; await saveUser(buyer);
    if (sale) { sale.affiliateEmail = ref; sale.refCode = refUser.refCode || ''; sale.commission = round2((sale.amount || 0) * affiliateRate()); await saveSale(sale); }
    return sendJson(res, 200, { ok: true, referredBy: ref, refCode: refUser.refCode || '', reassigned: !!sale });
  }
  if (action === 'reset') { const email = normalizeEmail(b.email); const user = await getUser(email); if (!user) return sendJson(res, 404, { ok: false, error: 'user_not_found' }); user.hwid = ''; user.activatedAt = 0; await saveUser(user); return sendJson(res, 200, { ok: true }); }
  if (action === 'revoke') { const email = normalizeEmail(b.email); const user = await getUser(email); if (!user) return sendJson(res, 404, { ok: false, error: 'user_not_found' }); user.revoked = b.revoked === true; await saveUser(user); return sendJson(res, 200, { ok: true }); }
  if (action === 'delete') { const email = normalizeEmail(b.email); const user = await getUser(email); if (user && user.refCode) await kvDel('ref:' + user.refCode); await delUser(email); return sendJson(res, 200, { ok: true }); }
  return sendJson(res, 400, { ok: false, error: 'unknown_action' });
}
async function hDownload(req, res, url) {
  const token = url.searchParams.get('token') || bearer(req);
  const sess = await getSession(token);
  if (!sess) return sendJson(res, 401, { ok: false, error: 'unauthorized' });
  const user = await getUser(sess.email);
  if (!user || !user.licenseKey || user.revoked) return sendJson(res, 403, { ok: false, error: 'no_license' });
  user.lastSeen = Date.now(); await saveUser(user);
  res.writeHead(302, { location: GITHUB_LATEST, 'cache-control': 'no-store', ...CORS });
  res.end();
}

// ─────────────────────────────  static

const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css', '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.ico': 'image/x-icon', '.svg': 'image/svg+xml', '.txt': 'text/plain', '.json': 'application/json', '.woff2': 'font/woff2' };
function serveStatic(url, res) {
  let p = decodeURIComponent(url.pathname);
  if (p === '/') p = '/index.html';
  const file = path.normalize(path.join(SITE_DIR, p));
  if (!file.startsWith(SITE_DIR)) { res.writeHead(403); return res.end('forbidden'); }
  fs.readFile(file, (err, buf) => {
    if (err) { res.writeHead(404, { 'content-type': 'text/plain' }); return res.end('not found'); }
    const ext = path.extname(file).toLowerCase();
    res.writeHead(200, { 'content-type': MIME[ext] || 'application/octet-stream', 'cache-control': ext === '.html' ? 'no-cache' : 'public, max-age=3600' });
    res.end(buf);
  });
}

// ─────────────────────────────  router

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://localhost');
  const p = url.pathname, m = req.method;
  try {
    if (m === 'OPTIONS') { res.writeHead(204, CORS); return res.end(); }
    if (p === '/health' || (p === '/' && m === 'GET' && false)) return sendJson(res, 200, { ok: true, service: 'staticvisual' });
    if (m === 'POST' && p === '/api/register') return await hRegister(req, res);
    if (m === 'POST' && p === '/api/login') return await hLogin(req, res);
    if (m === 'POST' && p === '/api/logout') return await hLogout(req, res);
    if ((m === 'GET' || m === 'POST') && p === '/api/me') return await hMe(req, res);
    if (m === 'POST' && p === '/api/activate') return await hActivate(req, res);
    if (m === 'POST' && p === '/api/session') return await hSession(req, res);
    if ((m === 'GET' || m === 'POST') && p === '/api/referrals') return await hReferrals(req, res);
    if ((m === 'GET' || m === 'POST') && p === '/api/affiliate') return await hAffiliate(req, res);
    if (m === 'POST' && p === '/api/admin') return await hAdmin(req, res);
    if (p === '/download/app') return await hDownload(req, res, url);
    if (m === 'GET') return serveStatic(url, res);
    res.writeHead(404); res.end('not found');
  } catch (e) {
    sendJson(res, 500, { ok: false, error: 'server_error', detail: String(e && e.message || e) });
  }
});
server.listen(PORT, '0.0.0.0', () => console.log('staticvisual on :' + PORT + (REDIS_URL ? ' (upstash)' : ' (in-memory)')));
