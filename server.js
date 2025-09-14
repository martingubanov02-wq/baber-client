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

fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(path.join(DATA_DIR, 'sessions'), { recursive: true });

// DB
const usersDb = Datastore.create({ filename: path.join(DATA_DIR, 'users.db'), autoload: true, timestampData: true });
const invitesDb = Datastore.create({ filename: path.join(DATA_DIR, 'invites.db'), autoload: true, timestampData: true });
await usersDb.ensureIndex({ fieldName: 'username', unique: true });
await invitesDb.ensureIndex({ fieldName: 'key', unique: true });

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

// Health
app.get('/health', (req, res) => res.send('OK'));

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
      const exists = await invitesDb.findOne({ key });
      if (!exists) break;
    }
    await invitesDb.insert({ key, used: false });
    created.push(key);
  }
  return res.json({ created });
});

// API: HWID check for game client
app.get('/api/hwid/check', async (req, res) => {
  try {
    const username = (req.query.u||'').toString().trim();
    const hwid = (req.query.hwid||'').toString().trim();
    if (!username || !hwid) return res.status(400).json({ status: 'bad_request' });
    const u = await usersDb.findOne({ username });
    if (!u) return res.json({ status: 'no_user' });
    if (!u.hwid) return res.json({ status: 'no_hwid' });
    if (u.hwid !== hwid) return res.json({ status: 'mismatch' });
    if (u.hwid_status === 'approved') return res.json({ status: 'approved' });
    return res.json({ status: u.hwid_status || 'pending' });
  } catch (e) {
    console.error('hwid/check error', e);
    return res.status(500).json({ status: 'error' });
  }
});

// Pages
app.get('/', (req, res) => res.render('index', { title: 'BABER client' }));
app.get('/register', (req, res) => res.render('register', { title: 'Регистрация' }));
app.post('/register', async (req, res) => {
  const username = (req.body.username||'').trim();
  const key = (req.body.key||'').trim();
  if (!username || !key) { req.session.flash={type:'error',message:'Укажи ник и ключ'}; return res.redirect('/register'); }
  const inv = await invitesDb.findOne({ key, used: { $ne: true } });
  if (!inv) { req.session.flash={type:'error',message:'Неверный или уже использованный ключ'}; return res.redirect('/register'); }
  await usersDb.update({ username }, { $set: { username, key_hash: key } }, { upsert: true });
  await invitesDb.update({ _id: inv._id }, { $set: { used: true, used_by: username, used_at: new Date().toISOString() } });
  req.session.user = { username };
  req.session.flash = { type:'success', message:'Добро пожаловать!' };
  return res.redirect('/download');
});
app.get('/login', (req, res) => res.render('login', { title: 'Вход' }));
app.post('/login', async (req, res) => {
  const username = (req.body.username||'').trim();
  const key = (req.body.key||'').trim();
  const u = await usersDb.findOne({ username });
  if (!u || u.key_hash !== key) { req.session.flash={type:'error',message:'Неверные данные'}; return res.redirect('/login'); }
  req.session.user = { username };
  return res.redirect('/download');
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
  const p = path.join(__dirname, 'downloads', 'client-mod.jar');
  if (!fs.existsSync(p)) { req.session.flash={type:'error',message:'Файл не найден'}; return res.redirect('/download'); }
  return res.download(p, 'BABERClientMod.jar');
});

app.listen(PORT, ()=> console.log(`web3 ready: http://localhost:${PORT}`));
