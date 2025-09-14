import express from 'express';
import session from 'express-session';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';
import Datastore from 'nedb-promises';
import compression from 'compression';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = Number(process.env.PORT || 3000);
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
// Provide a safe default so the admin endpoint works even if env var is missing (can be overridden in Environment)
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || 'admin-123';
// Telegram bot integration (optional)
const TG_BOT_TOKEN = process.env.TG_BOT_TOKEN || '';
const TG_ADMIN_ID = Number(process.env.TG_ADMIN_ID || 0); // numeric Telegram user id
const TG_WEBHOOK_SECRET = process.env.TG_WEBHOOK_SECRET || 'tg-secret';
// Render API (optional, for /deploy via bot)
const RENDER_API_TOKEN = process.env.RENDER_API_TOKEN || '';
const RENDER_SERVICE_ID = process.env.RENDER_SERVICE_ID || '';

// Ensure data directories; if DATA_DIR differs from repo data path, try one-time migrate
fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(path.join(DATA_DIR, 'sessions'), { recursive: true });
const REPO_DATA_DIR = path.join(__dirname, 'data');
try {
  if (path.resolve(DATA_DIR) !== path.resolve(REPO_DATA_DIR)) {
    const usersPath = path.join(DATA_DIR, 'users.db');
    const invitesPath = path.join(DATA_DIR, 'invites.db');
    const oldUsers = path.join(REPO_DATA_DIR, 'users.db');
    const oldInvites = path.join(REPO_DATA_DIR, 'invites.db');
    if (!fs.existsSync(usersPath) && fs.existsSync(oldUsers)) fs.copyFileSync(oldUsers, usersPath);
    if (!fs.existsSync(invitesPath) && fs.existsSync(oldInvites)) fs.copyFileSync(oldInvites, invitesPath);
  }
} catch {}

// DB (Postgres adapter if DATABASE_URL provided, otherwise NeDB)
const DATABASE_URL = process.env.DATABASE_URL || '';
let usersDb, invitesDb;
if (DATABASE_URL) {
  const pgMod = await import('pg');
  const { Pool } = pgMod;
  const pool = new Pool({ connectionString: DATABASE_URL, ssl: { rejectUnauthorized: false } });
  // init tables
  await pool.query(`CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username TEXT UNIQUE,
    usernameLower TEXT UNIQUE,
    key_hash TEXT,
    hwid TEXT,
    hwid_status TEXT,
    hwid_approved_at TEXT,
    hwid_updated_at TEXT,
    hwid_activation_used BOOLEAN,
    hwid_reset_done_at TEXT,
    game_activation_used BOOLEAN,
    game_activated_at TEXT,
    created_at TIMESTAMP DEFAULT NOW()
  )`);
  await pool.query(`CREATE TABLE IF NOT EXISTS invites (
    id SERIAL PRIMARY KEY,
    key TEXT UNIQUE,
    raw TEXT,
    used BOOLEAN DEFAULT FALSE,
    used_by TEXT,
    used_byLower TEXT,
    used_at TEXT,
    created_at TIMESTAMP DEFAULT NOW()
  )`);

  usersDb = {
    async findOne(query){
      if (query?.$or) {
        const a = query.$or[0];
        const b = query.$or[1];
        const nameL = a.usernameLower || b.usernameLower || null;
        const name = a.username || b?.username || null;
        const res = await pool.query('SELECT * FROM users WHERE usernameLower=$1 OR username=$2 LIMIT 1', [nameL, name]);
        return res.rows[0] || null;
      }
      if (query?.username) {
        const res = await pool.query('SELECT * FROM users WHERE username=$1 LIMIT 1', [query.username]);
        return res.rows[0] || null;
      }
      if (query?.usernameLower) {
        const res = await pool.query('SELECT * FROM users WHERE usernameLower=$1 LIMIT 1', [query.usernameLower]);
        return res.rows[0] || null;
      }
      return null;
    },
    async update(filter, updateObj, options={}){
      // supports patterns used in code
      let row = await this.findOne(filter);
      if (!row && options.upsert) {
        const set = updateObj.$set || {};
        const username = set.username || filter.username || null;
        const usernameLower = set.usernameLower || filter.usernameLower || (username? username.toLowerCase(): null);
        await pool.query('INSERT INTO users (username, usernameLower, key_hash, hwid, hwid_status, hwid_approved_at, hwid_updated_at, hwid_activation_used, hwid_reset_done_at, game_activation_used, game_activated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) ON CONFLICT (usernameLower) DO UPDATE SET username=EXCLUDED.username, key_hash=EXCLUDED.key_hash, hwid=EXCLUDED.hwid, hwid_status=EXCLUDED.hwid_status, hwid_approved_at=EXCLUDED.hwid_approved_at, hwid_updated_at=EXCLUDED.hwid_updated_at, hwid_activation_used=EXCLUDED.hwid_activation_used, hwid_reset_done_at=EXCLUDED.hwid_reset_done_at, game_activation_used=EXCLUDED.game_activation_used, game_activated_at=EXCLUDED.game_activated_at', [
          username,
          usernameLower,
          set.key_hash||null,
          set.hwid||null,
          set.hwid_status||null,
          set.hwid_approved_at||null,
          set.hwid_updated_at||null,
          set.hwid_activation_used??null,
          set.hwid_reset_done_at||null,
          set.game_activation_used??null,
          set.game_activated_at||null
        ]);
        return;
      }
      if (!row) return;
      const set = updateObj.$set || {};
      const unset = (updateObj.$unset||{});
      const merged = { ...row, ...set };
      for (const k of Object.keys(unset)) delete merged[k];
      const usernameLowerFinal = (merged.usernameLower || merged.usernamelower || (merged.username? merged.username.toLowerCase(): null));
      await pool.query('UPDATE users SET username=$1, usernameLower=$2, key_hash=$3, hwid=$4, hwid_status=$5, hwid_approved_at=$6, hwid_updated_at=$7, hwid_activation_used=$8, hwid_reset_done_at=$9, game_activation_used=$10, game_activated_at=$11 WHERE id=$12', [
        merged.username||null,
        usernameLowerFinal||null,
        merged.key_hash||null,
        merged.hwid||null,
        merged.hwid_status||null,
        merged.hwid_approved_at||null,
        merged.hwid_updated_at||null,
        merged.hwid_activation_used??null,
        merged.hwid_reset_done_at||null,
        merged.game_activation_used??null,
        merged.game_activated_at||null,
        row.id
      ]);
    },
    async insert(doc){
      await this.update({ usernameLower: doc.usernameLower }, { $set: doc }, { upsert: true });
    },
    find(){
      return {
        sort(){ return this; },
        async limit(n){ const r = await pool.query('SELECT * FROM users ORDER BY id DESC LIMIT $1', [n]); return r.rows; }
      };
    },
    async ensureIndex(){ /* noop */ }
  };

  invitesDb = {
    async findOne(query){
      if (query?.$or) {
        const res = await pool.query('SELECT * FROM invites WHERE used_by=$1 OR used_byLower=$2 LIMIT 1', [query.$or[0].used_by||null, query.$or[1].used_byLower||null]);
        return res.rows[0] || null;
      }
      if (query?.key && query?.used && query.used.$ne === true) {
        const res = await pool.query('SELECT * FROM invites WHERE key=$1 AND (used IS DISTINCT FROM TRUE) LIMIT 1', [query.key]);
        return res.rows[0] || null;
      }
      if (query?.key) {
        const res = await pool.query('SELECT * FROM invites WHERE key=$1 LIMIT 1', [query.key]);
        return res.rows[0] || null;
      }
      if (query?.raw) {
        const res = await pool.query('SELECT * FROM invites WHERE raw=$1 LIMIT 1', [query.raw]);
        return res.rows[0] || null;
      }
      return null;
    },
    async insert(doc){
      await pool.query('INSERT INTO invites (key, raw, used, used_by, used_byLower, used_at) VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (key) DO NOTHING', [doc.key||null, doc.raw||null, !!doc.used, doc.used_by||null, doc.used_byLower||null, doc.used_at||null]);
    },
    async update(filter, updateObj){
      let row = await this.findOne(filter);
      if (!row) return;
      const set = updateObj.$set || {};
      const merged = { ...row, ...set };
      await pool.query('UPDATE invites SET key=$1, raw=$2, used=$3, used_by=$4, used_byLower=$5, used_at=$6 WHERE id=$7', [
        merged.key||null, merged.raw||null, merged.used??null, merged.used_by||null, merged.used_byLower||null, merged.used_at||null, row.id
      ]);
    },
    async ensureIndex(){ /* noop; enforced by schema */ }
  };
} else {
  // NeDB fallback (current behavior)
  usersDb = Datastore.create({ filename: path.join(DATA_DIR, 'users.db'), autoload: true, timestampData: true });
  invitesDb = Datastore.create({ filename: path.join(DATA_DIR, 'invites.db'), autoload: true, timestampData: true });
  await usersDb.ensureIndex({ fieldName: 'username', unique: false });
  await usersDb.ensureIndex({ fieldName: 'usernameLower', unique: true });
  await invitesDb.ensureIndex({ fieldName: 'key', unique: true });
}

// Views & static
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
// Enable gzip/deflate compression for faster responses
app.use(compression());
// Cache static files for 1 day
app.use('/static', express.static(path.join(__dirname, 'public'), { maxAge: '1d', etag: true }));
app.use(express.urlencoded({ extended: false }));

// Sessions (no CSRF for simplicity)
app.use(session({
  secret: process.env.SESSION_SECRET || 'change-me',
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', secure: false, maxAge: 1000*60*60*24*7 }
}));

// Template locals
app.use((req, res, next) => {
  res.locals.user = req.session.user || null;
  res.locals.flash = req.session.flash || null;
  delete req.session.flash;
  next();
});

// Helpers
function normKey(s = '') {
  return String(s).toUpperCase().replace(/[^A-Z0-9]/g, ''); // remove spaces and dashes
}

// ===== Telegram helpers =====
import https from 'https';
function tgSend(chatId, text) {
  if (!TG_BOT_TOKEN) return;
  const payload = JSON.stringify({ chat_id: chatId, text, parse_mode: 'HTML', disable_web_page_preview: true });
  const url = new URL(`https://api.telegram.org/bot${TG_BOT_TOKEN}/sendMessage`);
  const opts = { method: 'POST', headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) } };
  const req = https.request(url, opts, res => { res.resume(); });
  req.on('error', ()=>{});
  req.write(payload); req.end();
}
async function renderDeploy() {
  if (!RENDER_API_TOKEN || !RENDER_SERVICE_ID) return { ok:false, error:'RENDER_API not configured' };
  try {
    const payload = JSON.stringify({ clearCache: true });
    const url = new URL(`https://api.render.com/v1/services/${RENDER_SERVICE_ID}/deploys`);
    const opts = { method: 'POST', headers: { 'Authorization': `Bearer ${RENDER_API_TOKEN}`, 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) } };
    await new Promise((resolve, reject) => {
      const r = https.request(url, opts, res => { res.on('data', ()=>{}); res.on('end', resolve); });
      r.on('error', reject); r.write(payload); r.end();
    });
    return { ok:true };
  } catch (e) { return { ok:false, error:String(e) }; }
}

// ===== Simple Admin panel (token required) =====
app.get('/admin', (req, res) => {
  const token = (req.query.token||'').toString();
  if (!ADMIN_TOKEN) return res.status(503).send('ADMIN_TOKEN not set');
  if (token !== ADMIN_TOKEN) return res.status(403).send('forbidden');
  res.render('admin', { title: 'Админ', adminToken: ADMIN_TOKEN });
});

// Health
app.get('/health', (req, res) => res.send('OK'));

// Admin backup endpoints (token required)
app.get('/admin/export', async (req, res) => {
  const token = (req.query.token||'').toString();
  if (token !== ADMIN_TOKEN) return res.status(403).json({ error:'forbidden' });
  const users = await usersDb.find({});
  const invites = await invitesDb.find({});
  res.setHeader('Content-Disposition', 'attachment; filename="backup.json"');
  res.json({ users, invites, exported_at: new Date().toISOString() });
});

// Telegram Webhook (POST /tg/:secret)
app.post('/tg/:secret', express.json({ limit: '256kb' }), async (req, res) => {
  try {
    if (!TG_BOT_TOKEN) return res.status(503).send('tg disabled');
    if (req.params.secret !== TG_WEBHOOK_SECRET) return res.status(403).send('forbidden');
    const u = req.body?.message?.from;
    const chatId = req.body?.message?.chat?.id;
    const text = (req.body?.message?.text||'').trim();
    if (!u || !chatId || !text) return res.json({ ok:true });
    if (TG_ADMIN_ID && u.id !== TG_ADMIN_ID) { tgSend(chatId, 'no access'); return res.json({ ok:true }); }

    const [cmdRaw, ...rest] = text.split(/\s+/);
    const cmd = cmdRaw.toLowerCase();
    if (cmd === '/start') {
      tgSend(chatId, 'Команды:\n/invites 1 — создать 1 ключ\n/invites 10 — создать 10 ключей\n/users 10 — показать 10 пользователей\n/deploy — запустить деплой (если настроен Render API)');
    } else if (cmd === '/invites') {
      // поддержка форматов: "/invites 10" или "/invites10"
      let nStr = rest[0] || (cmdRaw.replace(/[^0-9]/g,'') || '1');
      let n = parseInt(nStr, 10); if (isNaN(n)) n = 1; n = Math.max(1, Math.min(100, n));
      const created = [];
      for (let i=0;i<n;i++){
        let key; while (true){ key = 'INV-' + randomKey(20); const ex = await invitesDb.findOne({ key: normKey(key) }); if (!ex) break; }
        await invitesDb.insert({ key: normKey(key), raw: key, used: false });
        created.push(key);
      }
      // если сообщение слишком длинное — отправим частями
      const header = `Создано ${created.length}:`;
      let chunk = header + "\n";
      for (const k of created){
        if ((chunk + k + "\n").length > 3500){ tgSend(chatId, chunk.trimEnd()); chunk = ''; }
        chunk += k + "\n";
      }
      if (chunk.trim()) tgSend(chatId, chunk.trim());
    } else if (cmd === '/users') {
      const limit = Math.max(1, Math.min(50, Number(rest[0]||10)));
      const all = await usersDb.find({}).sort({ _id: -1 }).limit(limit);
      const lines = all.map(u=>`${u.username} — ${u.hwid_status||'no_hwid'}`);
      tgSend(chatId, lines.length? lines.join('\n') : 'Нет пользователей');
    } else if (cmd === '/deploy') {
      if (!RENDER_API_TOKEN || !RENDER_SERVICE_ID){
        tgSend(chatId, 'Не настроено: добавь переменные RENDER_API_TOKEN и RENDER_SERVICE_ID в Render → Environment');
      } else {
        const r = await renderDeploy();
        tgSend(chatId, r.ok? 'Запустил деплой (clear cache)' : `Не удалось: ${r.error}`);
      }
    } else {
      tgSend(chatId, 'Неизвестная команда');
    }
    return res.json({ ok:true });
  } catch (e) {
    try { const chatId = req.body?.message?.chat?.id; if (chatId) tgSend(chatId, 'Ошибка: ' + e); } catch {}
    return res.json({ ok:true });
  }
});

// Admin: generate invite keys
function randomKey(len = 20) {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let out = '';
  for (let i = 0; i < len; i++) out += chars[Math.floor(Math.random() * chars.length)];
  return out.match(/.{1,4}/g).join('-');
}

app.get('/admin/invites', async (req, res) => {
  if (!ADMIN_TOKEN) return res.status(503).json({ error: 'ADMIN_TOKEN not set' });
  const token = (req.query.token||'').toString();
  if (token !== ADMIN_TOKEN) return res.status(403).json({ error: 'forbidden' });
  const count = Math.max(1, Math.min(100, Number(req.query.count||1)));
  const created = [];
  for (let i = 0; i < count; i++) {
    let key;
    // ensure uniqueness
    // eslint-disable-next-line no-constant-condition
    while (true) {
      key = 'INV-' + randomKey(20);
      const exists = await invitesDb.findOne({ key: normKey(key) });
      if (!exists) break;
    }
    await invitesDb.insert({ key: normKey(key), raw: key, used: false });
    created.push(key);
  }
  return res.json({ created });
});

// API: HWID check for game client
app.get('/api/hwid/check', async (req, res) => {
  try {
    const usernameRaw = (req.query.u||'').toString().trim();
    const usernameLower = usernameRaw.toLowerCase();
    const hwid = (req.query.hwid||'').toString().trim();
    if (!usernameLower || !hwid) return res.status(400).json({ status: 'bad_request' });
    const u = await usersDb.findOne({ $or: [ { usernameLower }, { username: usernameRaw } ] });
    if (!u) return res.json({ status: 'no_user' });
    if (!u.hwid) return res.json({ status: 'no_hwid' });
    if (u.hwid !== hwid) return res.json({ status: 'mismatch' });
    if (u.hwid_status === 'approved') {
      if (u.game_activation_used) return res.json({ status: 'approved' });
      return res.json({ status: 'game_pending' });
    }
    return res.json({ status: u.hwid_status || 'pending' });
  } catch (e) {
    console.error('hwid/check error', e);
    return res.status(500).json({ status: 'error' });
  }
});

// API: one-time game activation from Minecraft client
app.post('/api/hwid/activate', async (req, res) => {
  try {
    const usernameRaw = (req.body.u||'').toString().trim();
    const usernameLower = usernameRaw.toLowerCase();
    const hwid = (req.body.hwid||'').toString().trim();
    if (!usernameLower || !hwid) return res.status(400).json({ ok:false, error:'bad_request' });
    const u = await usersDb.findOne({ $or: [ { usernameLower }, { username: usernameRaw } ] });
    if (!u) return res.status(404).json({ ok:false, error:'no_user' });
    if (!u.hwid || u.hwid !== hwid) return res.status(400).json({ ok:false, error:'mismatch' });
    if (u.hwid_status !== 'approved') return res.status(400).json({ ok:false, error:'not_approved' });
    if (u.game_activation_used) return res.json({ ok:true, already:true });
    await usersDb.update({ _id: u._id }, { $set: { game_activation_used: true, game_activated_at: new Date().toISOString() } });
    return res.json({ ok:true });
  } catch (e) {
    console.error('hwid/activate error', e);
    return res.status(500).json({ ok:false, error:'error' });
  }
});

// Pages
app.get('/', async (req, res) => {
  try {
    const sessUser = req.session.user;
    let hwidStatus = null;
    if (sessUser && sessUser.username) {
      const u = await usersDb.findOne({ $or: [ { username: sessUser.username }, { usernameLower: (sessUser.username||'').toLowerCase() } ] });
      hwidStatus = u?.hwid_status || null;
    }
    return res.render('index', { title: 'BABER client', hwidStatus });
  } catch (e) {
    return res.render('index', { title: 'BABER client' });
  }
});
app.get('/register', (req, res) => res.render('register', { title: 'Регистрация' }));
app.post('/register', async (req, res) => {
  const username = (req.body.username||'').trim();
  const usernameLower = username.toLowerCase();
  const keyRaw = (req.body.key||'').trim();
  const key = normKey(keyRaw);
  if (!username || !key) { req.session.flash={type:'error',message:'Укажи ник и ключ'}; return res.redirect('/register'); }
  // Ник уже существует? Разрешим вход, а не новую регистрацию
  const existing = await usersDb.findOne({ usernameLower });
  if (existing) {
    if (normKey(existing.key_hash||'') !== key) {
      req.session.flash = { type:'error', message:'Ник уже занят. Введите правильный ключ на странице Вход.' };
      return res.redirect('/login');
    }
    // Ключ совпал — считаем, что пользователь просто пытается войти через форму регистрации
    req.session.user = { username: existing.username };
    req.session.flash = { type:'success', message:'Добро пожаловать!' };
    return res.redirect('/download');
  }
  // Accept invite keys with or without dashes/spaces (tolerant lookup)
  // 1) Попробуем найти любой инвайт по key/raw без фильтра used, чтобы различить «неверный» и «уже использован»
  let invAny = await invitesDb.findOne({ $or: [ { key: key }, { raw: keyRaw }, { key: normKey(keyRaw) } ] });
  if (!invAny) {
    req.session.flash={type:'error',message:'Неверный ключ: проверь, что скопирован полностью без лишних символов'};
    return res.redirect('/register');
  }
  if (invAny.used === true) {
    req.session.flash={type:'error',message:'Ключ уже использован. Сгенерируйте новый'};
    return res.redirect('/register');
  }
  const inv = invAny;
  await usersDb.update({ usernameLower }, { $set: { username, usernameLower, key_hash: key } }, { upsert: true });
  await invitesDb.update({ _id: inv._id }, { $set: { used: true, used_by: username, used_at: new Date().toISOString() } });
  await invitesDb.update({ _id: inv._id }, { $set: { used_byLower: usernameLower } });
  req.session.user = { username };
  req.session.flash = { type:'success', message:'Добро пожаловать!' };
  return res.redirect('/');
});
app.get('/login', (req, res) => res.render('login', { title: 'Вход' }));
app.post('/login', async (req, res) => {
  const usernameInput = (req.body.username||'').trim();
  const usernameLower = usernameInput.toLowerCase();
  const keyInput = normKey((req.body.key||'').trim());
  let u = await usersDb.findOne({ $or: [ { usernameLower }, { username: usernameInput } ] });
  let ok = false;
  // 1) Основная проверка по user.key_hash
  if (u && normKey(u.key_hash||'') === keyInput) {
    ok = true;
  }
  // 2) Фоллбек по инвайту пользователя (case-insensitive)
  if (!ok) {
    const invByUser = await invitesDb.findOne({ $or: [ { used_by: (u?.username)||usernameInput }, { used_byLower: usernameLower } ] });
    const invKeyNorm = invByUser ? normKey(invByUser.key||invByUser.raw||'') : '';
    if (invByUser && invKeyNorm === keyInput) {
      ok = true;
      // если пользователя нет — создадим
      if (!u) {
        await usersDb.update({ usernameLower }, { $set: { username: usernameInput, usernameLower, key_hash: keyInput } }, { upsert: true });
        u = await usersDb.findOne({ usernameLower });
      } else if (normKey(u.key_hash||'') !== keyInput) {
        // обновим ключ, если отличается
        await usersDb.update({ _id: u._id }, { $set: { key_hash: keyInput } });
      }
    }
  }
  // 3) Фоллбек по инвайту с ключом (если в used_by записан ник в другом регистре)
  if (!ok) {
    const invByKey = await invitesDb.findOne({ key: keyInput });
    if (invByKey && ((invByKey.used_byLower||'') === usernameLower || (invByKey.used_by||'') === usernameInput)) {
      ok = true;
      if (!u) {
        await usersDb.update({ usernameLower }, { $set: { username: usernameInput, usernameLower, key_hash: keyInput } }, { upsert: true });
        u = await usersDb.findOne({ usernameLower });
      } else if (normKey(u.key_hash||'') !== keyInput) {
        await usersDb.update({ _id: u._id }, { $set: { key_hash: keyInput } });
      }
    }
  }
  // 4) Если инвайт существует и ещё не использован — привяжем к этому пользователю прямо при входе
  if (!ok) {
    const invFree = await invitesDb.findOne({ key: keyInput, used: { $ne: true } });
    if (invFree) {
      await invitesDb.update({ _id: invFree._id }, { $set: { used: true, used_by: usernameInput, used_byLower: usernameLower, used_at: new Date().toISOString() } });
      await usersDb.update({ usernameLower }, { $set: { username: usernameInput, usernameLower, key_hash: keyInput } }, { upsert: true });
      u = await usersDb.findOne({ usernameLower });
      ok = !!u;
    }
  }
  if (!ok || !u) { req.session.flash={type:'error',message:'Неверные данные'}; return res.redirect('/login'); }
  req.session.user = { username: u.username };
  return res.redirect('/');
});
app.post('/logout', (req, res)=>{ req.session.destroy(()=>res.redirect('/')); });

function requireAuth(req, res, next){ if(!req.session.user){ req.session.flash={type:'error',message:'Войдите'}; return res.redirect('/login'); } next(); }

// Require HWID approved to access protected resources (download/mod)
async function requireHwidApproved(req, res, next){
  try {
    const username = req.session.user?.username;
    if (!username) { req.session.flash={type:'error',message:'Войдите'}; return res.redirect('/login'); }
    const u = await usersDb.findOne({ username });
    if (!u || !u.hwid || u.hwid_status !== 'approved') {
      req.session.flash = { type: 'error', message: 'Привяжите HWID и дождитесь подтверждения. Сброс HWID — 30 RUB (FunPay)'};
      return res.redirect('/hwid');
    }
    return next();
  } catch(err){
    console.error('requireHwidApproved error', err);
    req.session.flash = { type: 'error', message: 'Ошибка проверки HWID' };
    return res.redirect('/hwid');
  }
}

// HWID management pages
app.get('/hwid', requireAuth, async (req,res)=>{
  const username = req.session.user.username;
  const u = await usersDb.findOne({ username });
  // Auto-approve if there is a pending hwid already stored (to avoid stuck "pending")
  if (u && u.hwid && u.hwid_status && u.hwid_status !== 'approved') {
    await usersDb.update(
      { username },
      { $set: { hwid_status: 'approved', hwid_approved_at: new Date().toISOString(), hwid_activation_used: true } }
    );
    req.session.flash = { type:'success', message:'HWID подтверждён. Скачивание доступно.' };
  }
  const u2 = await usersDb.findOne({ username });
  return res.render('hwid', { title: 'HWID привязка', u: u2, funpay1: 'https://funpay.com/users/13579417/', funpay2: 'https://funpay.com/users/10104456/', price: 30 });
});

app.post('/hwid', requireAuth, async (req,res)=>{
  const username = req.session.user.username;
  const hwid = (req.body.hwid||'').trim();
  if (!hwid || hwid.length < 6 || hwid.length > 128){
    req.session.flash = { type:'error', message:'Укажи корректный HWID' };
    return res.redirect('/hwid');
  }
  const u = await usersDb.findOne({ username });
  if (!u) { req.session.flash={type:'error',message:'Пользователь не найден'}; return res.redirect('/hwid'); }
  // If there is already a pending HWID for this user, auto-approve it now
  if (u.hwid && u.hwid_status !== 'approved') {
    await usersDb.update(
      { username },
      { $set: {
          hwid: u.hwid, // keep existing
          hwid_status: 'approved',
          hwid_approved_at: new Date().toISOString(),
          hwid_activation_used: true
        } }
    );
    req.session.flash = { type:'success', message:'HWID подтверждён. Скачивание доступно.' };
    return res.redirect('/hwid');
  }
  // One-time activation without extra key (auto-approve on first bind)
  if (u.hwid_activation_used) {
    req.session.flash = { type:'error', message:'HWID уже был привязан. Для смены HWID обратитесь к администратору (30 ₽).' };
    return res.redirect('/hwid');
  }
  await usersDb.update(
    { username },
    { $set: {
        hwid,
        hwid_status: 'approved',
        hwid_updated_at: new Date().toISOString(),
        hwid_approved_at: new Date().toISOString(),
        hwid_activation_used: true
      } },
    { upsert: true }
  );
  req.session.flash = { type:'success', message:'HWID привязан и автоматически подтверждён. Скачивание доступно.' };
  return res.redirect('/hwid');
});

// Admin endpoints for HWID operations (manual FunPay confirmation)
app.get('/admin/hwid/approve', async (req,res)=>{
  const token = (req.query.token||'').toString();
  if (token !== ADMIN_TOKEN) return res.status(403).json({ error:'forbidden' });
  const username = (req.query.user||'').toString();
  if (!username) return res.status(400).json({ error:'user required' });
  await usersDb.update({ username }, { $set: { hwid_status: 'approved', hwid_approved_at: new Date().toISOString() }, $unset: { hwid_reset_requested: true } });
  return res.json({ ok:true });
});

app.get('/admin/hwid/reset', async (req,res)=>{
  const token = (req.query.token||'').toString();
  if (token !== ADMIN_TOKEN) return res.status(403).json({ error:'forbidden' });
  const username = (req.query.user||'').toString();
  if (!username) return res.status(400).json({ error:'user required' });
  await usersDb.update({ username }, { $unset: { hwid: true, hwid_status: true, hwid_approved_at: true }, $set: { hwid_reset_done_at: new Date().toISOString() } });
  return res.json({ ok:true });
});

app.get('/admin/hwid/set', async (req,res)=>{
  const token = (req.query.token||'').toString();
  if (token !== ADMIN_TOKEN) return res.status(403).json({ error:'forbidden' });
  const username = (req.query.user||'').toString();
  const hwid = (req.query.hwid||'').toString();
  if (!username || !hwid) return res.status(400).json({ error:'user & hwid required' });
  await usersDb.update({ username }, { $set: { hwid, hwid_status: 'approved', hwid_approved_at: new Date().toISOString() } }, { upsert: true });
  return res.json({ ok:true });
});

// Protected content requires HWID approved
app.get('/download', requireAuth, requireHwidApproved, (req,res)=> res.render('download', { title:'Скачать мод' }));
app.get('/mod', requireAuth, requireHwidApproved, (req,res)=>{
  // Serve from public/ so the file is in the repo and deployed reliably
  const p = path.join(__dirname, 'public', 'client-mod.jar');
  if (!fs.existsSync(p)) {
    req.session.flash={type:'error',message:'Файл не найден. Положите client-mod.jar в web3/public/ и задеплойте.'};
    return res.redirect('/download');
  }
  return res.download(p, 'BABERClientMod.jar');
});

app.listen(PORT, ()=> console.log(`web3 ready: http://localhost:${PORT}`));
