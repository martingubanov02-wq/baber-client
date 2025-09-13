import path from 'path';
import { fileURLToPath } from 'url';
import Datastore from 'nedb-promises';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

function randomKey(len = 20) {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let out = '';
  for (let i = 0; i < len; i++) out += chars[Math.floor(Math.random() * chars.length)];
  return out.match(/.{1,4}/g).join('-');
}

async function main() {
  const count = Number(process.argv[2] || 5);
  const dataDir = process.env.DATA_DIR || path.join(__dirname, '..', 'data');
  const invitesDb = Datastore.create({ filename: path.join(dataDir, 'invites.db'), autoload: true, timestampData: true });
  await invitesDb.ensureIndex({ fieldName: 'key', unique: true });

  const created = [];
  for (let i = 0; i < count; i++) {
    let key;
    while (true) {
      key = 'INV-' + randomKey(20);
      const exists = await invitesDb.findOne({ key });
      if (!exists) break;
    }
    await invitesDb.insert({ key, used: false });
    created.push(key);
  }
  console.log(JSON.stringify({ created }, null, 2));
}

main().catch(err => { console.error(err); process.exit(1); });
