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

const CAP = [{ t: 3, i: 1, h: 0 }, { t: 10, i: 2, h: 0 }, { t: 7, i: 1, h: 8 }, { t: 32, i: 4, h: 4 }], IMG = /^data:image\/jpeg;base64,[A-Za-z0-9+\/=]+$/, URL_ = /^https?:\/\/[^\s]{3,300}$/i;
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

const RET_DAYS = 30; // سياسة الاحتفاظ: صور الطلبات ونسخ الاسترجاع المرتبطة بها تُحذف نهائياً بعد 30 يوماً
const buckets = new Map();
const allow = (k, max, ms) => { const n = Date.now(), a = (buckets.get(k) || []).filter(x => n - x < ms); if (a.length >= max) { buckets.set(k, a); return false; } a.push(n); buckets.set(k, a); return true; };
const existingOrder = async (uid, idem) => {
  const [o] = await sql`select o.id,o.code,(select token from drafts d where d.order_id=o.id limit 1) as token from orders o where o.user_id=${uid} and o.idem=${idem}`;
  return o ? { no: 'PR-' + (1000 + o.id), code: o.code, restore: o.token ? BASE + '/?restore=' + o.token : '', duplicate: true } : null;
};
const hits = new Map();
const limited = ip => { const n = Date.now(), a = (hits.get(ip) || []).filter(x => n - x < 60000); a.push(n); hits.set(ip, a); return a.length > 30; };
const clean = (st, pkg) => {
  const cap = CAP[(pkg || 3) - 1], t = {}, c = {}, h = {}, i = {};
  Object.entries(st.t || {}).slice(0, cap.t).forEach(([k, x]) => { if (/^\d{1,2}$/.test(k) && typeof x === 'string') t[k] = x.slice(0, 1000); });
  Object.entries(st.c || {}).slice(0, 12).forEach(([k, x]) => { if (HEX.test(k) && HEX.test(x)) c[k.toLowerCase()] = x.toLowerCase(); });
  Object.entries(st.h || {}).slice(0, cap.h).forEach(([k, x]) => { if (/^\d{1,2}$/.test(k) && typeof x === 'string' && URL_.test(x.trim())) h[k] = x.trim(); });
  Object.entries(st.i && typeof st.i === 'object' ? st.i : {}).slice(0, cap.i).forEach(([k, x]) => { if (/^\d$/.test(k) && typeof x === 'string' && x.length < 160000 && IMG.test(x)) i[k] = x; });
  return { t, c, h, i };
};
// نسخة سحابية للتصميم: رابط استرجاع فريد (7 أيام للمسودة، 30 يوماً إذا ارتبطت بطلب)
const saveDraft = async (uid, pkg, tpl, state, oid) => {
  const tok = crypto.randomBytes(18).toString('base64url'), days = (oid ? 30 : 7) + ' days';
  const [d] = await sql`insert into drafts(user_id,pkg,tpl,state,token,order_id,expires_at)
    values(${uid},${pkg},${tpl},${state},${tok},${oid || null},now()+${days}::interval)
    on conflict (user_id,pkg,tpl) where order_id is null
    do update set state=excluded.state, updated_at=now(), expires_at=excluded.expires_at
    returning token, expires_at`;
  return d;
};
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
  await sql`alter table orders add column if not exists idem text`;
  await sql`create unique index if not exists orders_idem on orders(user_id,idem) where idem is not null`;
  await sql`create index if not exists orders_user on orders(user_id)`;
  await sql`create table if not exists drafts(id serial primary key, user_id int not null references users(id) on delete cascade, pkg int not null, tpl int not null,
    state text not null, token text unique not null, order_id int references orders(id) on delete set null,
    updated_at timestamptz not null default now(), expires_at timestamptz not null)`;
  await sql`create unique index if not exists drafts_active on drafts(user_id,pkg,tpl) where order_id is null`;
  await sql`create table if not exists order_images(order_id int not null references orders(id) on delete cascade, idx int not null, data text not null, primary key(order_id, idx))`;
  await sql`create index if not exists orders_assignee on orders(assigned_to, status)`;
  await sql`do $$ begin if not exists (select 1 from pg_constraint where conname='orders_pkg_chk2') then alter table orders drop constraint if exists orders_pkg_check; alter table orders add constraint orders_pkg_chk2 check (pkg between 1 and 4); end if; end $$`;
  await sql`do $$ begin if not exists (select 1 from pg_constraint where conname='orders_tpl_chk2') then alter table orders drop constraint if exists orders_tpl_check; alter table orders add constraint orders_tpl_chk2 check (tpl between 1 and 8); end if; end $$`;
}

// سياسة الاحتفاظ: حذف صور الطلبات بعد 30 يوماً ونسخ الاسترجاع المنتهية
async function purge() {
  await sql`delete from order_images where order_id in (select id from orders where created_at < now() - ${RET_DAYS + ' days'}::interval)`;
  await sql`delete from drafts where expires_at < now()`;
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

    if (r0 === 'drafts' && r1 === 't' && r2 && M === 'GET') {
      if (limited(req.ip)) return E(429, 'محاولات كثيرة، انتظر قليلاً');
      const [d] = await sql`select pkg,tpl,state,expires_at,order_id from drafts where token=${r2}`;
      if (!d) return E(404, 'رابط الاسترجاع غير صحيح');
      if (new Date(d.expires_at) < new Date()) return E(410, 'انتهت صلاحية رابط الاسترجاع');
      const stt = JSON.parse(d.state);
      if (d.order_id) { const rows = await sql`select idx,data from order_images where order_id=${d.order_id}`; stt.i = Object.fromEntries(rows.map(r => [r.idx, r.data])); }
      return J(200, { pkg: d.pkg, tpl: d.tpl, state: stt });
    }
    const p = verify(ck.pr); let me = null;
    if (p) [me] = await sql`select id,name,email,role,picture from users where id=${p.id} and active`;
    if (r0 === 'me') return me ? J(200, me) : E(401, 'غير مسجّل');
    if (!me) return E(401, 'سجّل الدخول أولاً');
    const isStaff = me.role === 'staff' || me.role === 'admin', isAdmin = me.role === 'admin';

    if (r0 === 'drafts' && !r1 && M === 'DELETE') { await sql`delete from drafts where user_id=${me.id} and order_id is null`; return J(200, { ok: 1 }); }
    if (r0 === 'drafts' && !r1 && M === 'PUT') {
      const pkg = +B.pkg, tpl = +B.tpl;
      if (!(pkg >= 1 && pkg <= 4 && tpl >= 1 && tpl <= (pkg === 4 ? 8 : 5))) return E(400, 'قالب غير صالح');
      if (!allow('dw1:' + me.id, 1, 1000) || !allow('dw:' + me.id, 40, 600000)) return E(429, 'سرعة الحفظ عالية، سيُعاد الحفظ تلقائياً');
      const stt = JSON.stringify(clean(B.state || {}, pkg));
      if (stt.length > 520000) return E(413, 'حجم المسودة كبير، صغّر الصور');
      const [{ n }] = await sql`select coalesce(sum(length(state)),0)::int as n from drafts where user_id=${me.id} and order_id is null and not (pkg=${pkg} and tpl=${tpl})`;
      if (n + stt.length > 2000000) return E(413, 'تجاوزت حصة التخزين السحابي، احذف مسوداتك القديمة');
      const d = await saveDraft(me.id, pkg, tpl, stt, null);
      return J(200, { link: BASE + '/?restore=' + d.token, expires: d.expires_at });
    }
    if (r0 === 'drafts' && r1 === 'latest' && M === 'GET') {
      const [d] = await sql`select pkg,tpl,state,updated_at,token from drafts where user_id=${me.id} and order_id is null and expires_at>now() order by updated_at desc limit 1`;
      return J(200, d ? { pkg: d.pkg, tpl: d.tpl, state: JSON.parse(d.state), at: d.updated_at, link: BASE + '/?restore=' + d.token } : {});
    }
    if (r0 === 'orders' && !r1 && M === 'POST') {
      const pkg = +B.pkg, tpl = +B.tpl, u = B.u || {};
      const idem = typeof B.idem === 'string' && /^[A-Za-z0-9]{10,40}$/.test(B.idem) ? B.idem : null;
      if (idem) { const ex = await existingOrder(me.id, idem); if (ex) return J(200, ex); }
      const cu = { n: str(u.n, 80), d: str(u.d, 10), r: str(u.r, 600), s: str(u.s, 20), p: str(u.p, 20).replace(/[^\d+]/g, '') };
      if (!(pkg >= 1 && pkg <= 4 && tpl >= 1 && tpl <= (pkg === 4 ? 8 : 5))) return E(400, 'قالب غير صالح');
      if (!cu.n || !cu.r || !SRC.includes(cu.s) || !/^\+?\d{9,15}$/.test(cu.p) || !(new Date(cu.d) <= new Date())) return E(400, 'أكمل البيانات الإجبارية بشكل صحيح');
      const t = {}, c = {};
      Object.entries(B.t || {}).slice(0, 60).forEach(([k, v]) => { if (/^\d{1,2}$/.test(k) && typeof v === 'string') t[k] = v.slice(0, 1000); });
      Object.entries(B.c || {}).slice(0, 12).forEach(([k, v]) => { if (HEX.test(k) && HEX.test(v)) c[k.toLowerCase()] = v.toLowerCase(); });
      const h = {}, im = {}, cap = CAP[pkg - 1];
      Object.entries(B.h || {}).slice(0, 12).forEach(([k, x]) => { if (/^\d{1,2}$/.test(k) && typeof x === 'string' && URL_.test(x.trim())) h[k] = x.trim(); });
      Object.entries(B.imgs && typeof B.imgs === 'object' ? B.imgs : {}).slice(0, 6).forEach(([k, x]) => { if (/^\d$/.test(k) && typeof x === 'string' && x.length < 160000 && IMG.test(x)) im[k] = x; });
      if (Object.keys(t).length > cap.t || Object.keys(h).length > cap.h || Object.keys(im).length > cap.i) return E(400, 'تجاوزت حدود الباقة المختارة');
      const [{ n }] = await sql`select count(*)::int as n from orders where user_id=${me.id} and created_at>now()-interval '1 hour'`;
      if (n >= 10) return E(429, 'تجاوزت الحد المسموح، حاول لاحقاً');
      const [{ id }] = await sql`select nextval(pg_get_serial_sequence('orders','id'))::int as id`;
      // توزيع الطلب: الموظف الأقل طلبات مفتوحة، وإن لم يوجد موظفون يذهب للمدير
      const [a] = await sql`select u.id from users u left join orders o on o.assigned_to=u.id and o.status in ('new','working')
        where u.active and u.role='staff' group by u.id order by count(o.id), u.id limit 1`;
      const [ad] = a ? [a] : await sql`select id from users where active and role='admin' order by id limit 1`;
      const no = 'PR-' + (1000 + id), tok = crypto.randomBytes(18).toString('base64url');
      const code = seal({ no, pkg, tpl, t, c, h, imgs: Object.keys(im).length, u: cu, em: me.email, at: Date.now() });
      // تنفيذ ذري: الطلب + الصور + نسخة الاسترجاع + حذف المسودة، إما كلها أو لا شيء
      const ops = [
        sql`insert into orders(id,user_id,pkg,tpl,code,assigned_to,idem) values(${id},${me.id},${pkg},${tpl},${code},${ad ? ad.id : null},${idem})`,
        ...Object.entries(im).map(([k, x]) => sql`insert into order_images(order_id,idx,data) values(${id},${+k},${x})`),
        sql`insert into drafts(user_id,pkg,tpl,state,token,order_id,expires_at) values(${me.id},${pkg},${tpl},${JSON.stringify({ t, c, h, i: {} })},${tok},${id},now()+${RET_DAYS + ' days'}::interval)`,
        sql`delete from drafts where user_id=${me.id} and pkg=${pkg} and tpl=${tpl} and order_id is null`
      ];
      try { await sql.transaction(ops); }
      catch (e) { const ex = idem && await existingOrder(me.id, idem); if (ex) return J(200, ex); throw e; }
      return J(200, { no, code, restore: BASE + '/?restore=' + tok });
    }
    if (r0 === 'orders' && !r1 && M === 'GET') {
      if (!isStaff) return J(200, await sql`select o.id,o.pkg,o.tpl,o.status,o.created_at,(select token from drafts d where d.order_id=o.id limit 1) as token from orders o where o.user_id=${me.id} order by o.id desc limit 100`);
      const rows = await sql`select o.id,o.code,o.pkg,o.tpl,o.status,o.created_at,o.assigned_to,c.name as cname,c.email as cemail,s.name as sname
        from orders o join users c on c.id=o.user_id left join users s on s.id=o.assigned_to
        where ${!!isAdmin} or o.assigned_to=${me.id} order by o.id desc limit 200`;
      return J(200, rows.map(({ code, ...r }) => { try { r.cphone = unseal(code).u.p; } catch (e) { /* ignore */ } return r; }));
    }
    if (r0 === 'orders' && r1 && /^\d+$/.test(r1)) {
      if (!isStaff) return E(403, 'غير مصرح');
      const id = +r1, [o] = await sql`select id,code,assigned_to from orders where id=${id}`;
      if (!o || (!isAdmin && o.assigned_to !== me.id)) return E(404, 'الطلب غير موجود');
      if (M === 'GET') { const rows = await sql`select idx,data from order_images where order_id=${id}`; return J(200, { data: unseal(o.code), images: Object.fromEntries(rows.map(r => [r.idx, r.data])) }); }
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
    if (r0 === 'users') {
      if (!isAdmin) return E(403, 'للمدير فقط');
      if (M === 'GET' && !r1) return J(200, await sql`select id,name,email,role,active from users order by id desc limit 300`);
      if (M === 'PATCH' && r1 && /^\d+$/.test(r1)) {
        const uid = +r1, [tu] = await sql`select id,email from users where id=${uid}`;
        if (!tu) return E(404, 'غير موجود');
        if (uid === me.id || tu.email === ADMIN) return E(400, 'لا يمكن تعديل هذا الحساب');
        if (!['customer', 'staff', 'admin'].includes(B.role)) return E(400, 'دور غير صالح');
        await sql`update users set role=${B.role} where id=${uid}`; return J(200, { ok: 1 });
      }
    }
    if (r0 === 'staff' && M === 'GET') return isAdmin ? J(200, await sql`select id,name from users where active and role in ('staff','admin') order by name`) : E(403, 'للمدير فقط');
    if (r0 === 'decode' && M === 'POST') {
      if (!isStaff) return E(403, 'غير مصرح');
      try { const d = unseal(B.code), oid = parseInt(String(d.no).replace('PR-', ''), 10) - 1000; const rows = oid > 0 ? await sql`select idx,data from order_images where order_id=${oid}` : []; return J(200, { data: d, images: Object.fromEntries(rows.map(r => [r.idx, r.data])) }); } catch (e) { return E(400, 'الكود غير صالح أو تم العبث به'); }
    }
    return E(404, 'غير موجود');
  } catch (e) { console.error(e); return E(500, 'خطأ في الخادم'); }
}

const app = express();
app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use((q, r, n) => { r.setHeader('X-Content-Type-Options', 'nosniff'); r.setHeader('X-Frame-Options', 'SAMEORIGIN'); r.setHeader('Strict-Transport-Security', 'max-age=15552000'); r.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin'); n(); });
app.use(express.json({ limit: '2mb' }));
app.all('/api/*', api);
// يدعم الشكل المسطّح (index.html بجانب server.js) أو مجلد public
const ROOT = require('fs').existsSync(path.join(__dirname, 'public', 'index.html')) ? path.join(__dirname, 'public') : __dirname;
app.get('/', (q, r) => r.sendFile(path.join(ROOT, 'index.html')));
app.use((q, r, n) => /\.(png|jpe?g|webp|gif|svg|ico|woff2?)$/i.test(q.path) ? n() : r.status(404).send('Not found'));
app.use(express.static(ROOT, { index: false }));
app.listen(process.env.PORT || 3000, async () => {
  console.log('listening on', process.env.PORT || 3000);
  setInterval(() => { hits.clear(); buckets.clear(); purge().catch(e => console.error('purge failed:', e.message)); }, 3600000);
  try { await init(); await purge(); console.log('db ready'); } catch (e) { console.error('db init failed:', e.message); }
});
