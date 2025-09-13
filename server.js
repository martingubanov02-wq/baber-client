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

app.get('/download', requireAuth, (req,res)=> res.render('download', { title:'Скачать мод' }));
app.get('/mod', requireAuth, (req,res)=>{
  const p = path.join(__dirname, 'downloads', 'client-mod.jar');
  if (!fs.existsSync(p)) { req.session.flash={type:'error',message:'Файл не найден'}; return res.redirect('/download'); }
  return res.download(p, 'BABERClientMod.jar');
});

app.listen(PORT, ()=> console.log(`web3 ready: http://localhost:${PORT}`));
