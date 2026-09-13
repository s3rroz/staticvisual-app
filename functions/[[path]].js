// Static Visual — Cloudflare Pages Functions (единый роутер: API + гейт скачивания + падс Through).
// Данные: Cloudflare KV с переменной `STORE` (создать KV namespace и примянуть его к Pages).
// Хостинг статики — этот же проект Pages (build = нет, publish = site/).
// Хендлеры Request→Response — как в Netlify/Deno версии. Пароли: scrypt (@noble/hashes) → подходят хэши с Netlify.
import { scrypt } from "@noble/hashes/scrypt";
import { hex } from "./_util.js";
const _te = new TextEncoder();

const GITHUB_LATEST = "https://github.com/s3rroz/static-visual/releases/latest/download/StaticVisual.exe";
const SESSION_TTL = 30 * 24 * 60 * 60; // сек
const DAY = 24 * 60 * 60 * 1000;
const DEFAULT_AMOUNT = 5.99;

// ---------- env ----------
const envList = (env, n) => (env[n] || "").split(",").map((s) => s.trim().toLowerCase()).filter(Boolean);
const normalizeEmail = (v) => String(v || "").trim().toLowerCase();
const validEmail = (v) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v);
const round2 = (n) => Math.round((Number(n) + Number.EPSILON) * 100) / 100;
function isAdminEmail(env, e) { return envList(env, "ADMIN_EMAILS").includes(normalizeEmail(e)); }
function isAffiliateEmail(env, e) { return envList(env, "AFFILIATE_EMAILS").includes(normalizeEmail(e)); }
function affiliateRate(env) { const r = parseFloat(env.AFFILIATE_RATE); return Number.isFinite(r) && r > 0 && r < 1 ? r : 0.2; }
function maskEmail(e) { const at = e.indexOf("@"); if (at <= 1) return e; const n = e.slice(0, at); return n.slice(0, 2) + "•".repeat(Math.max(1, n.length - 2)) + e.slice(at); }

// ---------- KV helpers ----------
const store = (env) => env.STORE;
const getUser = (env, email) => store(env).get("user:" + email, "json");
const saveUser = (env, u) => store(env).put("user:" + u.email, JSON.stringify(u));
const delUser = (env, email) => store(env).delete("user:" + email);
async function listUsers(env) {
  const out = []; let cursor;
  do { const res = await store(env).list({ prefix: "user:", cursor }); for (const k of res.keys) { const u = await store(env).get(k.name, "json"); if (u) out.push(u); } cursor = res.list_complete ? null : res.cursor; } while (cursor);
  out.sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0)); return out;
}
const getRefEmail = (env, code) => store(env).get("ref:" + String(code || "").toUpperCase(), "text");
const setRef = (env, code, email) => store(env).put("ref:" + code, email);
const getSale = (env, id) => store(env).get("sale:" + id, "json");
const saveSale = (env, s) => store(env).put("sale:" + s.id, JSON.stringify(s));
async function listSales(env) {
  const out = []; let cursor;
  do { const res = await store(env).list({ prefix: "sale:", cursor }); for (const k of res.keys) { const s = await store(env).get(k.name, "json"); if (s) out.push(s); } cursor = res.list_complete ? null : res.cursor; } while (cursor);
  out.sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0)); return out;
}
const getSession = (env, t) => (t ? store(env).get("sess:" + t, "json") : null);
const destroySession = (env, t) => (t ? store(env).delete("sess:" + t) : Promise.resolve());
async function createSession(env, email) {
  const token = await randomHex(32);
  await store(env).put("sess:" + token, JSON.stringify({ email, created: Date.now(), exp: Date.now() + SESSION_TTL * 1000 }), { expirationTtl: SESSION_TTL });
  return token;
}
function makeRefCode() { const a = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"; let s = ""; const b = new Uint8Array(8); crypto.getRandomValues(b); for (const x of b) s += a[x % a.length]; return s; }
async function uniqueRefCode(env) { let c; do { c = makeRefCode(); } while (await getRefEmail(env, c)); return c; }
async function ensureRefCode(env, u) { if (u && !u.refCode) { u.refCode = await uniqueRefCode(env); await saveUser(env, u); await setRef(env, u.refCode, u.email); } return u; }

// ---------- crypto (scrypt) ----------
function randomHex(n) { const a = new Uint8Array(n); crypto.getRandomValues(a); return hex(a); }
function scryptHex(password, saltHex) { return hex(scrypt(_te.encode(password), _te.encode(saltHex), { N: 16384, r: 8, p: 1, dkLen: 64 })); }
function hashPassword(pw) { const s = hex(crypto.getRandomValues(new Uint8Array(16))); return { salt: s, hash: scryptHex(pw, s) }; }
function verifyPassword(pw, salt, hash) { try { const t = scryptHex(pw, salt); return t === hash; } catch { return false; } }
function randomKey() { const a = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; let c = ""; const b = new Uint8Array(20); crypto.getRandomValues(b); for (const x of b) c += a[x % a.length]; return "SV-" + c.slice(0,4)+"-"+c.slice(4,8)+"-"+c.slice(8,12)+"-"+c.slice(12,16)+"-"+c.slice(16,20); }
const randomId = (n = 8) => randomHex(n);

// ---------- model ----------
function createUser(email, salt, hash, discord, refCode, referredBy) {
  return { email, salt, hash, discord: String(discord || "").slice(0, 60), plan: "none", licenseKey: "", hwid: "", revoked: false, refCode: refCode || "", referredBy: referredBy || "", refManual: false, saleCreated: false, createdAt: Date.now(), activatedAt: 0, lastSeen: 0 };
}
function publicUser(env, u) {
  return { email: u.email, plan: u.plan, licenseKey: u.licenseKey || "", hasKey: !!u.licenseKey, hwidBound: !!u.hwid, hwidPreview: u.hwid ? u.hwid.slice(0, 12) : "", revoked: !!u.revoked, discord: u.discord || "", refCode: u.refCode || "", referredBy: u.referredBy || "", isAffiliate: isAffiliateEmail(env, u.email), isAdmin: isAdminEmail(env, u.email), createdAt: u.createdAt || 0, activatedAt: u.activatedAt || 0, lastSeen: u.lastSeen || 0 };
}
function enrich(env, users) {
  const rc = new Map(), rv = new Map();
  for (const u of users) if (u.referredBy) { rc.set(u.referredBy, (rc.get(u.referredBy) || 0) + 1); if (u.licenseKey) rv.set(u.referredBy, (rv.get(u.referredBy) || 0) + 1); }
  return users.map((u) => ({ ...publicUser(env, u), hwid: u.hwid || "", refCount: rc.get(u.email) || 0, refConverted: rv.get(u.email) || 0 }));
}
function summarize(sales) {
  const byAff = new Map(); let gross = 0, commissionTotal = 0, paid = 0, pending = 0, saleCount = 0;
  const bucket = (e) => { if (!byAff.has(e)) byAff.set(e, { email: e, sales: 0, revenue: 0, commission: 0, paid: 0, pending: 0 }); return byAff.get(e); };
  for (const s of sales) { if (s.voided) continue; const b = bucket(s.affiliateEmail || ""); b.sales++; b.revenue = round2(b.revenue + (s.amount || 0)); b.commission = round2(b.commission + (s.commission || 0)); if (s.paid) b.paid = round2(b.paid + (s.commission || 0)); else b.pending = round2(b.pending + (s.commission || 0)); gross = round2(gross + (s.amount || 0)); commissionTotal = round2(commissionTotal + (s.commission || 0)); if (s.paid) paid = round2(paid + (s.commission || 0)); else pending = round2(pending + (s.commission || 0)); saleCount++; }
  return { totals: { gross, commissionTotal, paid, pending, saleCount }, byAffiliate: [...byAff.values()].filter((x) => x.email).sort((a, b) => b.commission - a.commission) };
}

// ---------- http ----------
const CORS = { "access-control-allow-origin": "*", "access-control-allow-methods": "GET,POST,DELETE,OPTIONS", "access-control-allow-headers": "authorization,content-type" };
const json = (status, obj) => new Response(JSON.stringify(obj), { status, headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", ...CORS } });
async function readJson(req) { try { return await req.json(); } catch { return {}; } }
const bearer = (req) => (req.headers.get("authorization") || "").replace(/^Bearer\s+/i, "").trim();
async function authUser(env, req) { const s = await getSession(env, bearer(req)); return s ? await getUser(env, s.email) : null; }

// ---------- handlers ----------
async function hRegister(env, req) { const b = await readJson(req); const email = normalizeEmail(b.email), pw = String(b.password || ""), discord = String(b.discord || "").trim(), refInput = String(b.ref || "").toUpperCase().trim(); if (!validEmail(email)) return json(400, { ok: false, error: "bad_email" }); if (pw.length < 6) return json(400, { ok: false, error: "weak_password" }); if (await getUser(env, email)) return json(409, { ok: false, error: "email_taken" }); let referredBy = ""; if (refInput) { const r = await getRefEmail(env, refInput); if (r && r !== email) referredBy = r; } const { salt, hash } = hashPassword(pw); const refCode = await uniqueRefCode(env); const user = createUser(email, salt, hash, discord, refCode, referredBy); await saveUser(env, user); await setRef(env, refCode, email); const token = await createSession(env, email); return json(200, { ok: true, token, user: publicUser(env, user) }); }
async function hLogin(env, req) { const b = await readJson(req); const email = normalizeEmail(b.email), pw = String(b.password || ""); const user = await getUser(env, email); if (!user || !verifyPassword(pw, user.salt, user.hash)) { await new Promise((r) => setTimeout(r, 300)); return json(401, { ok: false, error: "bad_credentials" }); } await ensureRefCode(env, user); const token = await createSession(env, email); return json(200, { ok: true, token, user: publicUser(env, user) }); }
async function hLogout(env, req) { await destroySession(env, bearer(req)); return json(200, { ok: true }); }
async function hMe(env, req) { const u = await authUser(env, req); if (!u) return json(401, { ok: false, error: "unauthorized" }); await ensureRefCode(env, u); return json(200, { ok: true, user: publicUser(env, u) }); }
async function hActivate(env, req) { const u = await authUser(env, req); if (!u) return json(401, { ok: false, error: "unauthorized" }); const b = await readJson(req); const key = String(b.key || "").toUpperCase().trim(), hwid = String(b.hwid || "").trim(); if (!key || !hwid) return json(400, { ok: false, error: "missing_params" }); if (u.revoked) return json(403, { ok: false, error: "revoked" }); if (!u.licenseKey) return json(404, { ok: false, error: "no_license" }); if (key !== u.licenseKey) return json(400, { ok: false, error: "wrong_key" }); if (!u.hwid) { u.hwid = hwid; u.activatedAt = Date.now(); u.lastSeen = Date.now(); await saveUser(env, u); return json(200, { ok: true, status: "activated", user: publicUser(env, u) }); } if (u.hwid !== hwid) return json(409, { ok: false, error: "hwid_mismatch" }); u.lastSeen = Date.now(); await saveUser(env, u); return json(200, { ok: true, status: "ok", user: publicUser(env, u) }); }
async function hSession(env, req) { const u = await authUser(env, req); if (!u) return json(401, { ok: false, error: "unauthorized" }); const b = await readJson(req); const hwid = String(b.hwid || "").trim(); if (u.revoked) return json(403, { ok: false, error: "revoked" }); if (!u.licenseKey) return json(404, { ok: false, error: "no_license" }); if (!u.hwid) return json(409, { ok: false, error: "not_activated" }); if (!hwid || u.hwid !== hwid) return json(409, { ok: false, error: "hwid_mismatch" }); u.lastSeen = Date.now(); await saveUser(env, u); return json(200, { ok: true, status: "ok" }); }
async function hReferrals(env, req) { const u = await authUser(env, req); if (!u) return json(401, { ok: false, error: "unauthorized" }); await ensureRefCode(env, u); const all = await listUsers(env); const invited = all.filter((x) => x.referredBy === u.email).map((x) => ({ email: x.email, hasKey: !!x.licenseKey, createdAt: x.createdAt || 0 })).sort((a, b) => b.createdAt - a.createdAt); return json(200, { ok: true, refCode: u.refCode, invited, count: invited.length, converted: invited.filter((x) => x.hasKey).length }); }
async function hAffiliate(env, req) { const u = await authUser(env, req); if (!u) return json(401, { ok: false, error: "unauthorized" }); await ensureRefCode(env, u); const rate = affiliateRate(env); const [sales, users] = await Promise.all([listSales(env), listUsers(env)]); const mine = sales.filter((s) => s.affiliateEmail === u.email && !s.voided); let revenue = 0, earned = 0, paid = 0; for (const s of mine) { revenue = round2(revenue + (s.amount || 0)); earned = round2(earned + (s.commission || 0)); if (s.paid) paid = round2(paid + (s.commission || 0)); } return json(200, { ok: true, isAffiliate: isAffiliateEmail(env, u.email), rate, refCode: u.refCode || "", stats: { registrations: users.filter((x) => x.referredBy === u.email).length, sales: mine.length, revenue, earned, paid, pending: round2(earned - paid) }, sales: mine.slice(0, 50).map((s) => ({ id: s.id, buyer: maskEmail(s.buyerEmail), amount: s.amount, commission: s.commission, paid: !!s.paid, date: s.createdAt })) }); }
async function hAdmin(env, req) {
  const b = await readJson(req); const action = String(b.action || "");
  if (action === "import") {
    const mt = env.MIGRATE_TOKEN || ""; const admin = await authUser(env, req); const byAdmin = admin && isAdminEmail(env, admin.email); const byToken = mt && String(b.token || "") === mt;
    if (!byAdmin && !byToken) return json(401, { ok: false, error: "unauthorized" });
    let nu = 0, ns = 0;
    for (const raw of (Array.isArray(b.users) ? b.users : [])) { const email = normalizeEmail(raw.email); if (!email) continue; const u = { ...raw, email }; if (!u.refCode) u.refCode = await uniqueRefCode(env); await saveUser(env, u); await setRef(env, u.refCode, email); nu++; }
    for (const raw of (Array.isArray(b.sales) ? b.sales : [])) { const s = { ...raw }; if (!s.id) s.id = randomId(); await saveSale(env, s); ns++; }
    return json(200, { ok: true, users: nu, sales: ns });
  }
  const admin = await authUser(env, req); if (!admin || !isAdminEmail(env, admin.email)) return json(401, { ok: false, error: "unauthorized" });
  if (action === "users") return json(200, { ok: true, users: enrich(env, await listUsers(env)) });
  if (action === "stats") { const users = await listUsers(env); const sales = await listSales(env); const rows = enrich(env, users); const { totals, byAffiliate } = summarize(sales); const now = Date.now(); return json(200, { ok: true, stats: { total: rows.length, withKey: rows.filter((u) => u.hasKey).length, active: rows.filter((u) => u.hwidBound).length, banned: rows.filter((u) => u.revoked).length, referred: rows.filter((u) => u.referredBy).length, referrers: rows.filter((u) => u.refCount > 0).length, new7: rows.filter((u) => now - (u.createdAt || 0) < 7 * DAY).length, new30: rows.filter((u) => now - (u.createdAt || 0) < 30 * DAY).length, ...totals }, topAffiliates: byAffiliate.slice(0, 10).map((a) => { const u = users.find((x) => x.email === a.email); return { email: a.email, refCode: (u && u.refCode) || "", sales: a.sales, commission: a.commission, paid: a.paid, pending: a.pending }; }) }); }
  if (action === "issue") { const email = normalizeEmail(b.email); const user = await getUser(env, email); if (!user) return json(404, { ok: false, error: "user_not_found" }); const key = user.licenseKey || randomKey(); user.licenseKey = key; user.plan = "lifetime"; user.revoked = false; if (!user.saleCreated) { user.saleCreated = true; await saveUser(env, user); const amt = Number(b.amount); const amount = Number.isFinite(amt) && amt >= 0 ? amt : DEFAULT_AMOUNT; const affiliateEmail = user.referredBy || ""; let refCode = ""; if (affiliateEmail) { const au = await getUser(env, affiliateEmail); refCode = (au && au.refCode) || ""; } const commission = affiliateEmail ? round2(amount * affiliateRate(env)) : 0; const sale = { id: randomId(), buyerEmail: email, affiliateEmail, refCode, amount: round2(amount), rate: affiliateRate(env), commission, voided: false, paid: false, paidAt: 0, createdAt: Date.now() }; await saveSale(env, sale); return json(200, { ok: true, key, saleId: sale.id, affiliateEmail, commission, user: publicUser(env, user) }); } await saveUser(env, user); return json(200, { ok: true, key, user: publicUser(env, user) }); }
  if (action === "sales") { const sales = await listSales(env); return json(200, { ok: true, sales, ...summarize(sales) }); }
  if (action === "markpaid") { if (b.saleId) { const s = await getSale(env, String(b.saleId)); if (!s) return json(404, { ok: false, error: "sale_not_found" }); s.paid = true; s.paidAt = Date.now(); await saveSale(env, s); return json(200, { ok: true }); } if (b.affiliateEmail) { const t = normalizeEmail(b.affiliateEmail); const sales = await listSales(env); let n = 0; for (const s of sales) if (s.affiliateEmail === t && !s.paid && !s.voided) { s.paid = true; s.paidAt = Date.now(); await saveSale(env, s); n++; } return json(200, { ok: true, marked: n }); } return json(400, { ok: false, error: "missing_params" }); }
  if (action === "void") { const s = await getSale(env, String(b.saleId)); if (!s) return json(404, { ok: false, error: "sale_not_found" }); s.voided = b.voided !== false; await saveSale(env, s); return json(200, { ok: true, voided: s.voided }); }
  if (action === "setref") { const email = normalizeEmail(b.email); const buyer = await getUser(env, email); if (!buyer) return json(404, { ok: false, error: "user_not_found" }); const ref = normalizeEmail(b.referrer); const sales = await listSales(env); const sale = sales.find((x) => x.buyerEmail === email && !x.voided); if (!ref) { if (sale && sale.paid) return json(400, { ok: false, error: "sale_paid" }); buyer.referredBy = ""; buyer.refManual = false; await saveUser(env, buyer); if (sale) { sale.affiliateEmail = ""; sale.refCode = ""; sale.commission = 0; await saveSale(env, sale); } return json(200, { ok: true, referredBy: "", cleared: true, reassigned: !!sale }); } if (ref === email) return json(400, { ok: false, error: "self_referral" }); const refUser = await getUser(env, ref); if (!refUser) return json(404, { ok: false, error: "referrer_not_found" }); await ensureRefCode(env, refUser); if (sale && sale.paid) return json(400, { ok: false, error: "sale_paid" }); buyer.referredBy = ref; buyer.refManual = true; await saveUser(env, buyer); if (sale) { sale.affiliateEmail = ref; sale.refCode = refUser.refCode || ""; sale.commission = round2((sale.amount || 0) * affiliateRate(env)); await saveSale(env, sale); } return json(200, { ok: true, referredBy: ref, refCode: refUser.refCode || "", reassigned: !!sale }); }
  if (action === "reset") { const email = normalizeEmail(b.email); const user = await getUser(env, email); if (!user) return json(404, { ok: false, error: "user_not_found" }); user.hwid = ""; user.activatedAt = 0; await saveUser(env, user); return json(200, { ok: true }); }
  if (action === "revoke") { const email = normalizeEmail(b.email); const user = await getUser(env, email); if (!user) return json(404, { ok: false, error: "user_not_found" }); user.revoked = b.revoked === true; await saveUser(env, user); return json(200, { ok: true }); }
  if (action === "delete") { const email = normalizeEmail(b.email); const user = await getUser(env, email); if (user && user.refCode) await store(env).delete("ref:" + user.refCode); await delUser(env, email); return json(200, { ok: true }); }
  return json(400, { ok: false, error: "unknown_action" });
}
async function hDownload(env, req) { const url = new URL(req.url); const token = url.searchParams.get("token") || bearer(req); const sess = await getSession(env, token); if (!sess) return json(401, { ok: false, error: "unauthorized" }); const u = await getUser(env, sess.email); if (!u || !u.licenseKey || u.revoked) return json(403, { ok: false, error: "no_license" }); u.lastSeen = Date.now(); await saveUser(env, u); return new Response(null, { status: 302, headers: { location: GITHUB_LATEST, "cache-control": "no-store", ...CORS } }); }

// ---------- router (catch-all; всё не /api и не /download отдаём статике через next()) ----------
async function route(ctx) {
  const { request, env, next } = ctx; const url = new URL(request.url); const p = url.pathname; const m = request.method;
  if (m === "OPTIONS") return new Response(null, { status: 204, headers: CORS });
  if (p === "/health") return json(200, { ok: true, service: "staticvisual" });
  let r;
  if (m === "POST" && p === "/api/register") r = await hRegister(env, request);
  else if (m === "POST" && p === "/api/login") r = await hLogin(env, request);
  else if (m === "POST" && p === "/api/logout") r = await hLogout(env, request);
  else if ((m === "GET" || m === "POST") && p === "/api/me") r = await hMe(env, request);
  else if (m === "POST" && p === "/api/activate") r = await hActivate(env, request);
  else if (m === "POST" && p === "/api/session") r = await hSession(env, request);
  else if ((m === "GET" || m === "POST") && p === "/api/referrals") r = await hReferrals(env, request);
  else if ((m === "GET" || m === "POST") && p === "/api/affiliate") r = await hAffiliate(env, request);
  else if (m === "POST" && p === "/api/admin") r = await hAdmin(env, request);
  else if (p === "/download/app") r = await hDownload(env, request);
  if (r) return r;
  return next ? next() : new Response("not found", { status: 404 });
}
export const onRequest = route;
export { route as __handle };
