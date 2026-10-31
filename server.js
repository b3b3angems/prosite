const crypto = require('crypto');
const path = require('path');
const express = require('express');
const { neon } = require('@neondatabase/serverless');

const { DATABASE_URL, GOOGLE_CLIENT_ID: GID, GOOGLE_CLIENT_SECRET: GSEC, JWT_SECRET: SEC, ENC_KEY } = process.env;
const ADMIN = (process.env.ADMIN_EMAIL || 'sfaa28272834@gmail.com').toLowerCase();
const BASE = (process.env.BASE_URL || process.env.RENDER_EXTERNAL_URL || '').replace(/\/$/, '');
const sql = neon(DATABASE_URL || 'postgresql://x:x@localhost/x');
const EK = crypto.createHash('sha256').update(ENC_KEY || '').digest();
const SRC = ['تيك توك', 'إنستقرام', 'سناب شات', 'واتساب'], ST = ['new', 'working', 'done', 'cancelled'], HEX = /^#[0-9a-f]{6}$/i;

const b64 = b => Buffer.from(b).toString('base64url');
const hmac = s => crypto.createHmac('sha256', SEC || '').update(s).digest('base64url');
const sign = p => { const h = b64('{"a":"HS256"}'), b = b64(JSON.stringify(p)); return `${h}.${b}.${hmac(h + '.' + b)}`; };
const verify = t => {
  const [h, b, s] = String(t || '').split('.'); if (!s) return null;
  const x = hmac(h + '.' + b); if (x.length !== s.length || !crypto.timingSafeEqual(Buffer.from(x), Buffer.from(s))) return null;
  const p = JSON.parse(Buffer.from(b, 'base64url')); return p.exp > Date.now() / 1000 ? p : null;
};
// AES-256-GCM: أي تعديل على الكود يُبطله
const seal = o => {
  const iv = crypto.randomBytes(12), c = crypto.createCipheriv('aes-256-gcm', EK, iv);
  const ct = Buffer.concat([c.update(JSON.stringify(o), 'utf8'), c.final()]);
  return 'PR2-' + b64(Buffer.concat([iv, c.getAuthTag(), ct]));
};
const unseal = code => {
  const m = String(code).match(/PR2-[A-Za-z0-9_-]+/); if (!m) throw new Error('bad');
  const b = Buffer.from(m[0].slice(4), 'base64url'), d = crypto.createDecipheriv('aes-256-gcm', EK, b.subarray(0, 12));
  d.setAuthTag(b.subarray(12, 28));
  return JSON.parse(Buffer.concat([d.update(b.subarray(28)), d.final()]).toString('utf8'));
};
const str = (v, max) => typeof v === 'string' ? v.trim().slice(0, max) : '';

async function init() {
  await sql`create table if not exists users(id serial primary key, name text not null, email text unique not null,
    role text not null default 'customer' check (role in ('customer','staff','admin')), active boolean not null default true,
    google_id text, picture text, created_at timestamptz not null default now())`;
  await sql`alter table users add column if not exists google_id text`;
  await sql`alter table users add column if not exists picture text`;
  await sql`do $$ begin alter table users alter column pass drop not null; exception when undefined_column then null; end $$`;
  await sql`create table if not exists orders(id serial primary key, user_id int not null references users(id) on delete cascade,
    pkg int not null check (pkg between 1 and 3), tpl int not null check (tpl between 1 and 5), code text not null,
    status text not null default 'new' check (status in ('new','working','done','cancelled')),
    assigned_to int references users(id) on delete set null, created_at timestamptz not null default now(), updated_at timestamptz not null default now())`;
  await sql`create index if not exists orders_user on orders(user_id)`;
  await sql`create index if not exists orders_assignee on orders(assigned_to, status)`;
}

const donePage = pop => `<!doctype html><meta charset="utf-8"><body style="background:#0a0a0a;color:#f5f5f0;font-family:sans-serif;text-align:center;padding:60px">تم تسجيل الدخول…<script>try{new BroadcastChannel('pr').postMessage('ok')}catch(e){}${pop ? 'setTimeout(function(){window.close()},200);setTimeout(function(){location.href="/"},1500)' : 'location.href="/"'}</script>`;

async function api(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  const J = (c, o) => res.status(c).json(o), E = (c, m) => J(c, { error: m });
  try {
    const [r0, r1, r2] = req.path.replace(/^\/api\/?/, '').split('/').filter(Boolean), M = req.method, B = req.body && typeof req.body === 'object' ? req.body : {};
    if (!SEC || SEC.length < 24 || !ENC_KEY || !DATABASE_URL) return E(500, 'إعدادات الخادم ناقصة');
    if (M !== 'GET') { const o = req.headers.origin; if (o && new URL(o).host !== req.headers.host) return E(403, 'مرفوض'); }
    const ck = Object.fromEntries((req.headers.cookie || '').split(';').map(x => x.trim().split('=')).filter(x => x[0]));
    const cookie = (n, v, age, lax) => res.append('Set-Cookie', `${n}=${v}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${age}`);

    /* ---- Google OAuth ---- */
    if (r0 === 'auth' && r1 === 'google' && M === 'GET') {
      if (!GID || !GSEC || !BASE) return E(500, 'إعدادات Google ناقصة');
      const RU = BASE + '/api/auth/google/callback';
      if (!r2) {
        const state = crypto.randomBytes(16).toString('hex');
        cookie('pg', `${state}.${req.query.popup ? 1 : 0}`, 600);
        const q = new URLSearchParams({ client_id: GID, redirect_uri: RU, response_type: 'code', scope: 'openid email profile', state, prompt: 'select_account' });
        return res.redirect('https://accounts.google.com/o/oauth2/v2/auth?' + q);
      }
      if (r2 === 'callback') {
        const [st, pop] = (ck.pg || '').split('.'), { code, state } = req.query;
        if (!code || !state || state !== st) return res.status(400).send('طلب غير صالح، أعد المحاولة.');
        const tr = await fetch('https://oauth2.googleapis.com/token', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({ code, client_id: GID, client_secret: GSEC, redirect_uri: RU, grant_type: 'authorization_code' }) });
        const t = await tr.json();
        if (!t.id_token) return res.status(400).send('فشل تسجيل الدخول عبر Google.');
        const g = JSON.parse(Buffer.from(t.id_token.split('.')[1], 'base64url')); // وصلنا مباشرة من Google عبر TLS
        if (g.aud !== GID || !['accounts.google.com', 'https://accounts.google.com'].includes(g.iss) || !g.email_verified) return res.status(400).send('حساب غير صالح.');
        const email = String(g.email).toLowerCase(), name = str(g.name || email.split('@')[0], 60);
        let [u] = await sql`insert into users(name,email,google_id,picture) values(${name},${email},${g.sub},${str(g.picture, 300)})
          on conflict (email) do update set google_id=excluded.google_id, name=excluded.name, picture=excluded.picture
          returning id,name,email,role,active`;
        if (email === ADMIN && u.role !== 'admin') [u] = await sql`update users set role='admin' where id=${u.id} returning id,name,email,role,active`;
        if (!u.active) return res.status(403).send('الحساب موقوف.');
        cookie('pr', sign({ id: u.id, exp: Math.floor(Date.now() / 1000) + 604800 }), 604800);
        cookie('pg', '', 0);
        return res.type('html').send(donePage(pop === '1'));
      }
    }
    if (r0 === 'logout' && M === 'POST') { cookie('pr', '', 0); return J(200, { ok: 1 }); }

    const p = verify(ck.pr); let me = null;
    if (p) [me] = await sql`select id,name,email,role,picture from users where id=${p.id} and active`;
    if (r0 === 'me') return me ? J(200, me) : E(401, 'غير مسجّل');
    if (!me) return E(401, 'سجّل الدخول أولاً');
    const isStaff = me.role === 'staff' || me.role === 'admin', isAdmin = me.role === 'admin';

    if (r0 === 'orders' && !r1 && M === 'POST') {
      const pkg = +B.pkg, tpl = +B.tpl, u = B.u || {};
      const cu = { n: str(u.n, 80), d: str(u.d, 10), r: str(u.r, 600), s: str(u.s, 20) };
      if (!(pkg >= 1 && pkg <= 3 && tpl >= 1 && tpl <= 5)) return E(400, 'قالب غير صالح');
      if (!cu.n || !cu.r || !SRC.includes(cu.s) || !(new Date(cu.d) <= new Date())) return E(400, 'أكمل البيانات الإجبارية بشكل صحيح');
      const t = {}, c = {};
      Object.entries(B.t || {}).slice(0, 60).forEach(([k, v]) => { if (/^\d{1,2}$/.test(k) && typeof v === 'string') t[k] = v.slice(0, 1000); });
      Object.entries(B.c || {}).slice(0, 12).forEach(([k, v]) => { if (HEX.test(k) && HEX.test(v)) c[k.toLowerCase()] = v.toLowerCase(); });
      const [{ n }] = await sql`select count(*)::int as n from orders where user_id=${me.id} and created_at>now()-interval '1 hour'`;
      if (n >= 10) return E(429, 'تجاوزت الحد المسموح، حاول لاحقاً');
      const [{ id }] = await sql`select nextval(pg_get_serial_sequence('orders','id'))::int as id`;
      // توزيع الطلب: الموظف الأقل طلبات مفتوحة، وإن لم يوجد موظفون يذهب للمدير
      const [a] = await sql`select u.id from users u left join orders o on o.assigned_to=u.id and o.status in ('new','working')
        where u.active and u.role='staff' group by u.id order by count(o.id), u.id limit 1`;
      const [ad] = a ? [a] : await sql`select id from users where active and role='admin' order by id limit 1`;
      const code = seal({ no: 'PR-' + (1000 + id), pkg, tpl, t, c, imgs: Math.min(+B.imgs || 0, 20), u: cu, at: Date.now() });
      await sql`insert into orders(id,user_id,pkg,tpl,code,assigned_to) values(${id},${me.id},${pkg},${tpl},${code},${ad ? ad.id : null})`;
      return J(200, { no: 'PR-' + (1000 + id), code });
    }
    if (r0 === 'orders' && !r1 && M === 'GET') {
      if (!isStaff) return J(200, await sql`select id,pkg,tpl,status,created_at from orders where user_id=${me.id} order by id desc limit 100`);
      return J(200, await sql`select o.id,o.pkg,o.tpl,o.status,o.created_at,o.assigned_to,c.name as cname,s.name as sname
        from orders o join users c on c.id=o.user_id left join users s on s.id=o.assigned_to
        where ${!!isAdmin} or o.assigned_to=${me.id} order by o.id desc limit 200`);
    }
    if (r0 === 'orders' && r1 && /^\d+$/.test(r1)) {
      if (!isStaff) return E(403, 'غير مصرح');
      const id = +r1, [o] = await sql`select id,code,assigned_to from orders where id=${id}`;
      if (!o || (!isAdmin && o.assigned_to !== me.id)) return E(404, 'الطلب غير موجود');
      if (M === 'GET') return J(200, { data: unseal(o.code) });
      if (M === 'PATCH') {
        if (B.status !== undefined) { if (!ST.includes(B.status)) return E(400, 'حالة غير صالحة'); await sql`update orders set status=${B.status}, updated_at=now() where id=${id}`; }
        if (B.assigned_to !== undefined) {
          if (!isAdmin) return E(403, 'للمدير فقط');
          const [s] = await sql`select id from users where id=${+B.assigned_to} and active and role in ('staff','admin')`;
          if (!s) return E(400, 'موظف غير صالح'); await sql`update orders set assigned_to=${s.id}, updated_at=now() where id=${id}`;
        }
        return J(200, { ok: 1 });
      }
    }
    if (r0 === 'staff' && M === 'GET') return isAdmin ? J(200, await sql`select id,name from users where active and role in ('staff','admin') order by name`) : E(403, 'للمدير فقط');
    if (r0 === 'decode' && M === 'POST') {
      if (!isStaff) return E(403, 'غير مصرح');
      try { return J(200, { data: unseal(B.code) }); } catch (e) { return E(400, 'الكود غير صالح أو تم العبث به'); }
    }
    return E(404, 'غير موجود');
  } catch (e) { console.error(e); return E(500, 'خطأ في الخادم'); }
}

const app = express();
app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use((q, r, n) => { r.setHeader('X-Content-Type-Options', 'nosniff'); r.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin'); n(); });
app.use(express.json({ limit: '100kb' }));
app.all('/api/*', api);
app.use(express.static(path.join(__dirname, 'public')));
app.listen(process.env.PORT || 3000, async () => {
  console.log('listening on', process.env.PORT || 3000);
  try { await init(); console.log('db ready'); } catch (e) { console.error('db init failed:', e.message); }
});
