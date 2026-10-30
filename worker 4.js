// =====================================================================
//  مكتبة الكتب - Cloudflare Worker
//  يحتوي على: الموقع + واجهة API + بوت الاستلام (Webhook) + قاعدة D1 (SQLite)
//
//  المتغيرات المطلوبة (Variables / Secrets):
//    BOT_TOKEN       (Secret)  توكن بوت الاستلام
//    WEBHOOK_SECRET  (Secret)  كلمة سرية من أحرف وأرقام فقط (للحماية وللتفعيل)
//    BOT_USERNAME    (Var)     يوزر البوت بدون @
//    GROUP_ID        (Var)     معرف المجموعة (يبدأ بـ -100)
//    USERBOT_ID      (Var)     ايدي الحساب (الجلسة) الذي يشغّله ملف بايثون
//    SITE_URL        (اختياري) رابط الموقع إذا استخدمت دومين خاص
//  الربط المطلوب: قاعدة D1 باسم  DB
// =====================================================================

// ------------------------- إعدادات تتحكم بها -------------------------
const CONFIG = {
  MAX_BOOKS_SHOWN: 100,      // أقصى عدد كتب يعرضها الموقع من نتيجة البحث
  BOOK_COOLDOWN_MIN: 15,     // المدة (بالدقائق) قبل أن يستلم الشخص نفس الكتاب مرة أخرى
  SEARCH_WAIT_SEC: 90,       // أقصى انتظار لرد الحساب على البحث
  DELIVERY_WAIT_SEC: 90,     // أقصى انتظار لوصول الكتاب من الحساب
  SEARCHES_PER_MINUTE: 5,    // أقصى عدد عمليات بحث للشخص في الدقيقة
  SESSION_DAYS: 30,          // مدة بقاء تسجيل الدخول في الموقع
  LOGIN_MAX_FAILS: 8,        // محاولات كود خاطئة مسموحة لكل IP خلال 10 دقائق
  MAX_QUERY_LEN: 80,         // أقصى طول لكلمة البحث
  KEY_NAME_CHARS: 20,        // عدد أحرف الاسم المستخدمة لبصمة الكتاب (لا تغيّره بعد التشغيل)
};

// ----------------------------- أدوات عامة -----------------------------
const now = () => Date.now();
const esc = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' },
  });
}

function randomHex(bytes) {
  const a = new Uint8Array(bytes);
  crypto.getRandomValues(a);
  return [...a].map((b) => b.toString(16).padStart(2, '0')).join('');
}

const CODE_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
function makeCode() {
  const a = new Uint8Array(10);
  crypto.getRandomValues(a);
  return [...a].map((b) => CODE_ALPHABET[b % CODE_ALPHABET.length]).join('');
}
const prettyCode = (c) => c.slice(0, 5) + '-' + c.slice(5);

async function bookKey(name, size) {
  const base = String(name).trim().toLowerCase().slice(0, CONFIG.KEY_NAME_CHARS) + '|' + String(size).trim();
  const buf = await crypto.subtle.digest('SHA-1', new TextEncoder().encode(base));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

async function tg(env, method, body) {
  try {
    const r = await fetch(`https://api.telegram.org/bot${env.BOT_TOKEN}/${method}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body || {}),
    });
    return await r.json();
  } catch (e) {
    return { ok: false, description: String(e) };
  }
}

// ----------------------------- قاعدة البيانات -----------------------------
const SCHEMA = [
  'CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, first_name TEXT, code TEXT UNIQUE NOT NULL, created_at INTEGER NOT NULL)',
  'CREATE TABLE IF NOT EXISTS sessions (token TEXT PRIMARY KEY, user_id INTEGER NOT NULL, expires_at INTEGER NOT NULL)',
  'CREATE TABLE IF NOT EXISTS attempts (ip TEXT NOT NULL, ts INTEGER NOT NULL)',
  'CREATE INDEX IF NOT EXISTS idx_attempts ON attempts(ip, ts)',
  'CREATE TABLE IF NOT EXISTS searches (id TEXT PRIMARY KEY, user_id INTEGER NOT NULL, query TEXT NOT NULL, req_msg_id INTEGER, created_at INTEGER NOT NULL)',
  'CREATE INDEX IF NOT EXISTS idx_searches_req ON searches(req_msg_id)',
  'CREATE TABLE IF NOT EXISTS search_parts (search_id TEXT NOT NULL, part INTEGER NOT NULL, total INTEGER NOT NULL, msg_id INTEGER NOT NULL, items TEXT NOT NULL, PRIMARY KEY (search_id, part))',
  'CREATE TABLE IF NOT EXISTS books (key TEXT PRIMARY KEY, file_id TEXT NOT NULL, name TEXT, size TEXT, created_at INTEGER NOT NULL)',
  'CREATE TABLE IF NOT EXISTS pending (id TEXT PRIMARY KEY, get_msg_id INTEGER, user_id INTEGER NOT NULL, book_key TEXT NOT NULL, name TEXT, size TEXT, status TEXT NOT NULL, created_at INTEGER NOT NULL)',
  'CREATE INDEX IF NOT EXISTS idx_pending_msg ON pending(get_msg_id)',
  'CREATE TABLE IF NOT EXISTS sends (user_id INTEGER NOT NULL, book_key TEXT NOT NULL, sent_at INTEGER NOT NULL)',
  'CREATE INDEX IF NOT EXISTS idx_sends ON sends(user_id, book_key, sent_at)',
];
let schemaReady = false;
async function ensureSchema(env) {
  if (schemaReady) return;
  await env.DB.batch(SCHEMA.map((s) => env.DB.prepare(s)));
  schemaReady = true;
}

async function cleanup(env) {
  const t = now();
  await env.DB.batch([
    env.DB.prepare('DELETE FROM sessions WHERE expires_at < ?').bind(t),
    env.DB.prepare('DELETE FROM attempts WHERE ts < ?').bind(t - 600000),
    env.DB.prepare('DELETE FROM search_parts WHERE search_id IN (SELECT id FROM searches WHERE created_at < ?)').bind(t - 3 * 86400000),
    env.DB.prepare('DELETE FROM searches WHERE created_at < ?').bind(t - 3 * 86400000),
    env.DB.prepare('DELETE FROM pending WHERE created_at < ?').bind(t - 86400000),
    env.DB.prepare('DELETE FROM sends WHERE sent_at < ?').bind(t - 86400000),
  ]);
}

const getUser = (env, id) => env.DB.prepare('SELECT * FROM users WHERE id = ?').bind(id).first();
const publicUser = (u) => ({ id: u.id, username: u.username, first_name: u.first_name });

// ------------------------------ المسارات ------------------------------
export default {
  async fetch(request, env, ctx) {
    try {
      return await route(request, env, ctx);
    } catch (e) {
      console.error(e);
      return json({ error: 'خطأ في الخادم' }, 500);
    }
  },
};

async function route(request, env, ctx) {
  if (!env.DB) {
    return new Response('قاعدة D1 غير مربوطة. اربطها باسم DB ثم أعد المحاولة.', {
      status: 500,
      headers: { 'content-type': 'text/plain; charset=utf-8' },
    });
  }
  await ensureSchema(env);
  if (Math.random() < 0.03) ctx.waitUntil(cleanup(env).catch(() => {}));

  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method;

  if (path === '/telegram' && method === 'POST') return handleWebhook(request, env, url.origin);
  if (path === '/setup') return handleSetup(url, env);
  if (path === '/' && method === 'GET') return page(env);
  if (path === '/api/login' && method === 'POST') return apiLogin(request, env);

  if (path.startsWith('/api/')) {
    const user = await authUser(request, env);
    if (!user) return json({ error: 'غير مسجل' }, 401);

    if (path === '/api/me') return json({ user: publicUser(user) });
    if (path === '/api/logout' && method === 'POST') {
      const token = (request.headers.get('authorization') || '').slice(7);
      await env.DB.prepare('DELETE FROM sessions WHERE token = ?').bind(token).run();
      return json({ ok: true });
    }
    if (path === '/api/avatar') return apiAvatar(env, user);
    if (path === '/api/search' && method === 'POST') return apiSearchStart(request, env, user);
    if (path.startsWith('/api/search/')) return apiSearchStatus(env, user, path.slice(12));
    if (path === '/api/book' && method === 'POST') return apiBook(request, env, user);
    if (path.startsWith('/api/delivery/')) return apiDelivery(env, user, path.slice(14));
  }
  return new Response('Not found', { status: 404 });
}

// ------------------------------ المصادقة ------------------------------
async function authUser(request, env) {
  const h = request.headers.get('authorization') || '';
  const token = h.startsWith('Bearer ') ? h.slice(7).trim() : '';
  if (!token) return null;
  return env.DB.prepare(
    'SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token = ? AND s.expires_at > ?'
  ).bind(token, now()).first();
}

async function apiLogin(request, env) {
  const ip = request.headers.get('cf-connecting-ip') || 'unknown';
  const fails = await env.DB.prepare('SELECT COUNT(*) AS c FROM attempts WHERE ip = ? AND ts > ?')
    .bind(ip, now() - 600000).first();
  if (fails && fails.c >= CONFIG.LOGIN_MAX_FAILS) {
    return json({ error: 'محاولات كثيرة، انتظر عشر دقائق ثم حاول' }, 429);
  }
  const body = await request.json().catch(() => ({}));
  const code = String(body.code || '').toUpperCase().replace(/[^A-Z0-9]/g, '');
  const user = code.length >= 8
    ? await env.DB.prepare('SELECT * FROM users WHERE code = ?').bind(code).first()
    : null;
  if (!user) {
    await env.DB.prepare('INSERT INTO attempts(ip, ts) VALUES(?, ?)').bind(ip, now()).run();
    return json({ error: 'الكود غير صحيح' }, 401);
  }
  const token = randomHex(32);
  await env.DB.prepare('INSERT INTO sessions(token, user_id, expires_at) VALUES(?, ?, ?)')
    .bind(token, user.id, now() + CONFIG.SESSION_DAYS * 86400000).run();
  return json({ token, user: publicUser(user) });
}

async function apiAvatar(env, user) {
  const p = await tg(env, 'getUserProfilePhotos', { user_id: user.id, limit: 1 });
  const sizes = p.ok && p.result.photos && p.result.photos[0];
  if (!sizes || !sizes.length) return new Response('', { status: 404 });
  const best = sizes[Math.min(1, sizes.length - 1)];
  const f = await tg(env, 'getFile', { file_id: best.file_id });
  if (!f.ok) return new Response('', { status: 404 });
  const img = await fetch(`https://api.telegram.org/file/bot${env.BOT_TOKEN}/${f.result.file_path}`);
  if (!img.ok) return new Response('', { status: 404 });
  return new Response(img.body, {
    headers: { 'content-type': 'image/jpeg', 'cache-control': 'private, max-age=3600' },
  });
}

// -------------------------------- البحث --------------------------------
async function apiSearchStart(request, env, user) {
  const body = await request.json().catch(() => ({}));
  const q = String(body.q || '').replace(/\s+/g, ' ').trim().slice(0, CONFIG.MAX_QUERY_LEN);
  if (q.length < 2) return json({ error: 'اكتب اسم الكتاب' }, 400);

  const recent = await env.DB.prepare('SELECT COUNT(*) AS c FROM searches WHERE user_id = ? AND created_at > ?')
    .bind(user.id, now() - 60000).first();
  if (recent && recent.c >= CONFIG.SEARCHES_PER_MINUTE) {
    return json({ error: 'عمليات بحث كثيرة، انتظر قليلا' }, 429);
  }

  const id = randomHex(5);
  await env.DB.prepare('INSERT INTO searches(id, user_id, query, created_at) VALUES(?, ?, ?, ?)')
    .bind(id, user.id, q, now()).run();

  const text = `⌯ طلب بحث جديد\n⌯ الكلمة: ${q}\n⌯ الرمز: ${id}`;
  const r = await tg(env, 'sendMessage', { chat_id: env.GROUP_ID, text, disable_notification: true });
  if (!r.ok) {
    await env.DB.prepare('DELETE FROM searches WHERE id = ?').bind(id).run();
    console.error('sendMessage to group failed', r);
    return json({ error: 'تعذر إرسال طلب البحث، حاول لاحقا' }, 502);
  }
  await env.DB.prepare('UPDATE searches SET req_msg_id = ? WHERE id = ?').bind(r.result.message_id, id).run();
  return json({ id });
}

async function loadSearch(env, id, userId) {
  const s = await env.DB.prepare('SELECT * FROM searches WHERE id = ? AND user_id = ?').bind(id, userId).first();
  if (!s) return null;
  const { results: rows } = await env.DB.prepare(
    'SELECT part, total, msg_id, items FROM search_parts WHERE search_id = ? ORDER BY part'
  ).bind(id).all();
  let items = [];
  let total = 0;
  for (const r of rows) {
    total = Math.max(total, r.total);
    try { items = items.concat(JSON.parse(r.items)); } catch (e) { /* تجاهل */ }
  }
  items = items.filter((i) => i.n <= CONFIG.MAX_BOOKS_SHOWN).sort((a, b) => a.n - b.n);
  const anchorRow = rows.find((r) => r.part === 1) || rows[0];
  return {
    s,
    items,
    complete: rows.length > 0 && rows.length >= total,
    partsCount: rows.length,
    anchor: anchorRow ? anchorRow.msg_id : null,
  };
}

async function apiSearchStatus(env, user, id) {
  const ls = await loadSearch(env, id, user.id);
  if (!ls) return json({ error: 'البحث غير موجود' }, 404);
  const expired = now() - ls.s.created_at > CONFIG.SEARCH_WAIT_SEC * 1000;
  if (ls.complete || (ls.partsCount > 0 && expired)) {
    return json({
      status: 'done',
      query: ls.s.query,
      results: ls.items.map((i) => ({ n: i.n, name: i.name, size: i.size })),
    });
  }
  if (expired) return json({ status: 'timeout' });
  return json({ status: 'pending' });
}

// ------------------------------ طلب كتاب ------------------------------
async function apiBook(request, env, user) {
  const body = await request.json().catch(() => ({}));
  const ls = await loadSearch(env, String(body.id || ''), user.id);
  if (!ls) return json({ error: 'انتهت صلاحية البحث، ابحث من جديد' }, 404);
  const n = parseInt(body.n, 10);
  const item = ls.items.find((i) => i.n === n);
  if (!item || !ls.anchor) return json({ error: 'الكتاب غير موجود' }, 404);

  const key = await bookKey(item.name, item.size);
  const t = now();

  // منع تكرار الكتاب قبل انتهاء المدة
  const cd = CONFIG.BOOK_COOLDOWN_MIN * 60000;
  const last = await env.DB.prepare('SELECT MAX(sent_at) AS t FROM sends WHERE user_id = ? AND book_key = ?')
    .bind(user.id, key).first();
  if (last && last.t && t - last.t < cd) {
    return json({ status: 'cooldown', wait: Math.ceil((cd - (t - last.t)) / 1000) });
  }

  // طلب سابق ما زال قيد الانتظار
  const pend = await env.DB.prepare(
    "SELECT id FROM pending WHERE user_id = ? AND book_key = ? AND status = 'pending' AND created_at > ?"
  ).bind(user.id, key, t - CONFIG.DELIVERY_WAIT_SEC * 1000).first();
  if (pend) return json({ status: 'requested', pid: pend.id });

  // إن كان الكتاب محفوظا في الكاش نرسله مباشرة بدون إزعاج الحساب
  const cached = await env.DB.prepare('SELECT file_id FROM books WHERE key = ?').bind(key).first();
  if (cached) {
    const r = await tg(env, 'sendDocument', { chat_id: user.id, document: cached.file_id });
    if (r.ok) {
      await env.DB.prepare('INSERT INTO sends(user_id, book_key, sent_at) VALUES(?, ?, ?)').bind(user.id, key, now()).run();
      return json({ status: 'sent' });
    }
    if (r.error_code === 403) {
      return json({ error: 'لا يمكن الإرسال إليك، افتح البوت واضغط ابدأ' }, 409);
    }
    // الملف المحفوظ لم يعد صالحا، نحذفه ونطلبه من الحساب
    await env.DB.prepare('DELETE FROM books WHERE key = ?').bind(key).run();
  }

  // طلب الكتاب من الحساب عبر الرد برقمه
  const pid = randomHex(6);
  await env.DB.prepare(
    "INSERT INTO pending(id, user_id, book_key, name, size, status, created_at) VALUES(?, ?, ?, ?, ?, 'pending', ?)"
  ).bind(pid, user.id, key, item.name, item.size, t).run();

  const r = await tg(env, 'sendMessage', {
    chat_id: env.GROUP_ID,
    text: String(n),
    reply_parameters: { message_id: ls.anchor, allow_sending_without_reply: false },
    disable_notification: true,
  });
  if (!r.ok) {
    await env.DB.prepare('DELETE FROM pending WHERE id = ?').bind(pid).run();
    console.error('book request failed', r);
    return json({ error: 'تعذر طلب الكتاب، حاول لاحقا' }, 502);
  }
  await env.DB.prepare('UPDATE pending SET get_msg_id = ? WHERE id = ?').bind(r.result.message_id, pid).run();
  return json({ status: 'requested', pid });
}

async function apiDelivery(env, user, pid) {
  const p = await env.DB.prepare('SELECT status, created_at FROM pending WHERE id = ? AND user_id = ?')
    .bind(pid, user.id).first();
  if (!p) return json({ error: 'الطلب غير موجود' }, 404);
  if (p.status === 'pending' && now() - p.created_at > CONFIG.DELIVERY_WAIT_SEC * 1000) {
    return json({ status: 'failed', message: 'تأخر وصول الكتاب، حاول مرة أخرى' });
  }
  if (p.status === 'failed') return json({ status: 'failed', message: 'تعذر إرسال الكتاب، تأكد أن البوت غير محظور وحاول مرة أخرى' });
  return json({ status: p.status });
}

// --------------------------- بوت الاستلام (Webhook) ---------------------------
async function handleWebhook(request, env, origin) {
  if (!env.WEBHOOK_SECRET || request.headers.get('x-telegram-bot-api-secret-token') !== env.WEBHOOK_SECRET) {
    return new Response('forbidden', { status: 403 });
  }
  let upd;
  try { upd = await request.json(); } catch (e) { return new Response('ok'); }
  const site = env.SITE_URL || origin;
  try {
    if (upd.callback_query) {
      await onCallback(upd.callback_query, env, site);
    } else if (upd.message) {
      const m = upd.message;
      if (m.chat && m.chat.type === 'private') await onPrivate(m, env, site);
      else if (m.chat && String(m.chat.id) === String(env.GROUP_ID)) await onGroup(m, env);
    }
  } catch (e) {
    console.error('webhook error', e);
  }
  return new Response('ok');
}

// ---- الخاص: /start وإنشاء الحساب ----
const siteButton = (site) => ({ text: 'ادخل للموقع للبحث عن ملايين الكتب', url: site });

function codeText(user) {
  return (
    '⌯ كود الدخول إلى الموقع:\n\n' +
    `<code>${prettyCode(user.code)}</code>\n\n` +
    '⌯ اضغط على الكود لنسخه ثم ضعه في الموقع'
  );
}

async function onPrivate(m, env, site) {
  const from = m.from;
  if (!from || from.is_bot) return;
  let user = await getUser(env, from.id);
  if (user && ((user.username || null) !== (from.username || null) || (user.first_name || '') !== (from.first_name || ''))) {
    await env.DB.prepare('UPDATE users SET username = ?, first_name = ? WHERE id = ?')
      .bind(from.username || null, from.first_name || '', from.id).run();
  }

  if (!user) {
    await tg(env, 'sendMessage', {
      chat_id: m.chat.id,
      text:
        '⌯ مرحبا بك في بوت مكتبة الكتب\n\n' +
        '⌯ مكتبة تضم ملايين الكتب\n' +
        '⌯ أنشئ حسابك للحصول على كود الدخول إلى الموقع\n' +
        '⌯ وبعدها تصلك الكتب هنا مباشرة',
      reply_markup: { inline_keyboard: [[{ text: 'إنشاء الحساب', callback_data: 'create', style: 'success' }]] },
    });
    return;
  }

  await tg(env, 'sendMessage', {
    chat_id: m.chat.id,
    text:
      '⌯ مرحبا بك في بوت مكتبة الكتب\n\n' +
      '⌯ ابحث عن أي كتاب من الموقع وسيصلك هنا مباشرة\n' +
      '⌯ مكتبة تضم ملايين الكتب',
    reply_markup: {
      inline_keyboard: [[siteButton(site)], [{ text: 'كود الدخول الخاص بي', callback_data: 'mycode' }]],
    },
  });
}

async function createUser(env, from) {
  for (let i = 0; i < 5; i++) {
    try {
      await env.DB.prepare('INSERT INTO users(id, username, first_name, code, created_at) VALUES(?, ?, ?, ?, ?)')
        .bind(from.id, from.username || null, from.first_name || '', makeCode(), now()).run();
      return await getUser(env, from.id);
    } catch (e) {
      const existing = await getUser(env, from.id);
      if (existing) return existing;
    }
  }
  throw new Error('code generation failed');
}

async function onCallback(cq, env, site) {
  const chat = cq.message && cq.message.chat;
  if (!chat || chat.type !== 'private') {
    await tg(env, 'answerCallbackQuery', { callback_query_id: cq.id });
    return;
  }
  const from = cq.from;

  if (cq.data === 'create') {
    let user = await getUser(env, from.id);
    if (!user) user = await createUser(env, from);
    await tg(env, 'answerCallbackQuery', { callback_query_id: cq.id });
    // نستبدل الرسالة بالكود ونحذف زر الإنشاء نهائيا
    await tg(env, 'editMessageText', {
      chat_id: chat.id,
      message_id: cq.message.message_id,
      text: '⌯ تم إنشاء حسابك بنجاح\n\n' + codeText(user),
      parse_mode: 'HTML',
      reply_markup: { inline_keyboard: [[siteButton(site)]] },
    });
    return;
  }

  if (cq.data === 'mycode') {
    const user = await getUser(env, from.id);
    await tg(env, 'answerCallbackQuery', { callback_query_id: cq.id });
    if (!user) return;
    await tg(env, 'sendMessage', {
      chat_id: chat.id,
      text: codeText(user),
      parse_mode: 'HTML',
      reply_markup: { inline_keyboard: [[siteButton(site)]] },
    });
    return;
  }

  await tg(env, 'answerCallbackQuery', { callback_query_id: cq.id });
}

// ---- المجموعة: ردود الحساب (نتائج + كتب) ----
function parsePart(text) {
  const pm = text.match(/الجزء:\s*(\d+)\s*\/\s*(\d+)/);
  if (!pm) return null;
  const items = [];
  for (const line of text.split('\n')) {
    const m = line.match(/^\s*(\d{1,4})\.\s+(.+?)\s+‹([^‹›]+)›\s*$/);
    if (m) items.push({ n: parseInt(m[1], 10), name: m[2].trim(), size: m[3].trim() });
  }
  return { part: parseInt(pm[1], 10), total: parseInt(pm[2], 10), items };
}

async function onGroup(m, env) {
  // لا نقبل إلا ردود حساب الجلسة المحدد
  if (!m.from || String(m.from.id) !== String(env.USERBOT_ID)) return;
  const rep = m.reply_to_message;
  if (!rep) return;

  // 1) وصل ملف: هو الكتاب المطلوب
  if (m.document) {
    const p = await env.DB.prepare("SELECT * FROM pending WHERE get_msg_id = ? AND status = 'pending'")
      .bind(rep.message_id).first();
    if (!p) return;
    await env.DB.prepare('INSERT OR REPLACE INTO books(key, file_id, name, size, created_at) VALUES(?, ?, ?, ?, ?)')
      .bind(p.book_key, m.document.file_id, p.name, p.size, now()).run();
    // sendDocument بالمعرّف: يصل بدون حقوق وبدون وسم إعادة توجيه وبدون وصف
    const r = await tg(env, 'sendDocument', { chat_id: p.user_id, document: m.document.file_id });
    if (r.ok) {
      await env.DB.prepare("UPDATE pending SET status = 'sent' WHERE id = ?").bind(p.id).run();
      await env.DB.prepare('INSERT INTO sends(user_id, book_key, sent_at) VALUES(?, ?, ?)').bind(p.user_id, p.book_key, now()).run();
    } else {
      console.error('deliver failed', r);
      await env.DB.prepare("UPDATE pending SET status = 'failed' WHERE id = ?").bind(p.id).run();
    }
    return;
  }

  const text = m.text || '';
  if (!text) return;

  // 2) نتائج بحث (رد على رسالة طلب البحث)
  const s = await env.DB.prepare('SELECT id FROM searches WHERE req_msg_id = ?').bind(rep.message_id).first();
  if (s) {
    const parsed = parsePart(text);
    if (!parsed) return;
    await env.DB.prepare(
      'INSERT OR REPLACE INTO search_parts(search_id, part, total, msg_id, items) VALUES(?, ?, ?, ?, ?)'
    ).bind(s.id, parsed.part, parsed.total, m.message_id, JSON.stringify(parsed.items)).run();
    return;
  }

  // 3) رد نصي على طلب كتاب = فشل (انتهت الجلسة أو تعذر الجلب)
  await env.DB.prepare("UPDATE pending SET status = 'failed' WHERE get_msg_id = ? AND status = 'pending'")
    .bind(rep.message_id).run();
}

// ------------------------- تفعيل البوت (مرة واحدة) -------------------------
async function handleSetup(url, env) {
  if (!env.WEBHOOK_SECRET || url.searchParams.get('key') !== env.WEBHOOK_SECRET) {
    return json({ error: 'forbidden' }, 403);
  }
  const missing = ['BOT_TOKEN', 'BOT_USERNAME', 'GROUP_ID', 'USERBOT_ID', 'WEBHOOK_SECRET'].filter((k) => !env[k]);
  if (missing.length) return json({ ok: false, missing_variables: missing });

  const webhook = await tg(env, 'setWebhook', {
    url: (env.SITE_URL || url.origin).replace(/\/$/, '') + '/telegram',
    secret_token: env.WEBHOOK_SECRET,
    allowed_updates: ['message', 'callback_query'],
    drop_pending_updates: true,
  });
  await tg(env, 'setMyCommands', { commands: [{ command: 'start', description: 'ابدأ' }] });
  const me = await tg(env, 'getMe');
  const botInGroup = await tg(env, 'getChatMember', { chat_id: env.GROUP_ID, user_id: me.ok ? me.result.id : 0 });
  const userbotInGroup = await tg(env, 'getChatMember', { chat_id: env.GROUP_ID, user_id: Number(env.USERBOT_ID) });

  return new Response(
    JSON.stringify(
      {
        webhook: webhook.ok ? 'تم تفعيل الويب هوك' : webhook,
        bot: me.ok ? '@' + me.result.username : me,
        bot_username_matches: me.ok ? me.result.username.toLowerCase() === String(env.BOT_USERNAME).replace(/^@/, '').toLowerCase() : false,
        bot_in_group: botInGroup.ok ? botInGroup.result.status : botInGroup.description,
        userbot_in_group: userbotInGroup.ok ? userbotInGroup.result.status : userbotInGroup.description,
      },
      null,
      2
    ),
    { headers: { 'content-type': 'application/json; charset=utf-8' } }
  );
}

// ------------------------------- الموقع -------------------------------
function page(env) {
  const bot = String(env.BOT_USERNAME || '').replace(/^@/, '');
  return new Response(PAGE.replaceAll('__BOT__', bot), {
    headers: {
      'content-type': 'text/html; charset=utf-8',
      'cache-control': 'no-cache',
      'x-content-type-options': 'nosniff',
      'referrer-policy': 'no-referrer',
    },
  });
}

const PAGE = String.raw`<!doctype html>
<html lang="ar" dir="rtl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="theme-color" content="#f8faf9" media="(prefers-color-scheme: light)">
<meta name="theme-color" content="#101312" media="(prefers-color-scheme: dark)">
<title>مكتبة الكتب</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Cairo:wght@400;600;700;800&display=swap" rel="stylesheet">
<link href="https://fonts.googleapis.com/css2?family=Material+Symbols+Rounded:opsz,wght,FILL,GRAD@24,400,0,0&display=swap" rel="stylesheet">
<style>
:root{
  --bg:#f8faf9;--surface:#ffffff;--surface-2:#f0f4f2;--outline:#dbe2de;
  --text:#191c1b;--text-2:#5b635f;
  --primary:#1a73e8;--on-primary:#ffffff;--primary-c:#d9e7fd;--on-primary-c:#0b3a82;
  --green:#188038;--green-c:#ddf1e2;--red:#d93025;--red-c:#fde4e1;--amber:#b06000;
  --shadow:0 1px 2px rgba(0,0,0,.06),0 4px 14px rgba(0,0,0,.05);
}
@media (prefers-color-scheme:dark){:root{
  --bg:#101312;--surface:#181c1b;--surface-2:#202523;--outline:#35403b;
  --text:#e3e8e5;--text-2:#9aa6a0;
  --primary:#8ab4f8;--on-primary:#062e6f;--primary-c:#1d3a68;--on-primary-c:#d3e3fd;
  --green:#81c995;--green-c:#1b3a26;--red:#f28b82;--red-c:#4a1f1b;--amber:#fdd663;
  --shadow:0 1px 2px rgba(0,0,0,.4),0 4px 14px rgba(0,0,0,.3);
}}
*{box-sizing:border-box;-webkit-tap-highlight-color:transparent}
[hidden]{display:none!important}
body{margin:0;background:var(--bg);color:var(--text);font-family:'Cairo',system-ui,-apple-system,sans-serif;line-height:1.6;min-height:100vh}
.ms{font-family:'Material Symbols Rounded';font-weight:400;font-style:normal;font-size:24px;line-height:1;letter-spacing:normal;text-transform:none;display:inline-block;white-space:nowrap;direction:ltr;-webkit-font-feature-settings:'liga';font-feature-settings:'liga';-webkit-font-smoothing:antialiased;user-select:none}
h1,h2,p{margin:0}
.muted{color:var(--text-2)}

.top{position:sticky;top:0;z-index:20;display:flex;align-items:center;justify-content:space-between;gap:12px;padding:10px 16px;padding-top:max(10px,env(safe-area-inset-top));background:var(--bg);background:color-mix(in srgb,var(--bg) 88%,transparent);-webkit-backdrop-filter:blur(14px);backdrop-filter:blur(14px);border-bottom:1px solid var(--outline)}
.brand{display:flex;align-items:center;gap:10px;font-weight:800;font-size:18px}
.brand .logo{width:38px;height:38px;border-radius:12px;display:grid;place-items:center;background:var(--primary-c);color:var(--on-primary-c)}
.chip{display:flex;align-items:center;gap:8px;border:1px solid var(--outline);background:var(--surface);color:var(--text);border-radius:999px;padding:4px 14px 4px 6px;font:700 14px 'Cairo',sans-serif;cursor:pointer;max-width:55vw}
.chip span:last-child{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.avatar{width:32px;height:32px;border-radius:50%;flex:none;display:grid;place-items:center;background:var(--primary);color:var(--on-primary);font-weight:800;font-size:15px;background-size:cover;background-position:center}
.avatar.big{width:84px;height:84px;font-size:34px}

main{max-width:720px;margin:0 auto;padding:20px 16px 64px}
.card{background:var(--surface);border:1px solid var(--outline);border-radius:28px;padding:28px 22px;box-shadow:var(--shadow)}
.login{display:flex;flex-direction:column;gap:18px;margin-top:8px}
.hero-icon{width:68px;height:68px;border-radius:22px;display:grid;place-items:center;background:var(--primary-c);color:var(--on-primary-c);margin:0 auto}
.hero-icon .ms{font-size:36px}
.login h1{text-align:center;font-size:22px;font-weight:800}
.login>p{text-align:center;font-size:14px}
.steps{list-style:none;margin:0;padding:0;display:flex;flex-direction:column;gap:10px}
.steps li{display:flex;align-items:center;gap:12px;background:var(--surface-2);border-radius:16px;padding:10px 14px;font-size:14px;font-weight:600}
.steps .n{width:26px;height:26px;border-radius:50%;flex:none;display:grid;place-items:center;background:var(--primary);color:var(--on-primary);font-size:13px;font-weight:800}

.btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;height:48px;padding:0 24px;border:0;border-radius:999px;font:700 15px 'Cairo',sans-serif;cursor:pointer;text-decoration:none;transition:filter .15s,transform .1s}
.btn:active{transform:scale(.98)}
.btn:disabled{opacity:.55;cursor:default}
.btn.filled{background:var(--primary);color:var(--on-primary)}
.btn.tonal{background:var(--primary-c);color:var(--on-primary-c)}
.btn.out{background:transparent;color:var(--red);border:1px solid var(--outline)}
.btn.block{width:100%}
.btn.sm{height:40px;padding:0 18px}

.field{display:flex;flex-direction:column;gap:6px;font-size:13px;font-weight:700;color:var(--text-2)}
.field input{height:54px;border-radius:16px;border:1.5px solid var(--outline);background:var(--surface);color:var(--text);padding:0 16px;font:700 20px/1 ui-monospace,Menlo,monospace;letter-spacing:3px;text-align:center;text-transform:uppercase;outline:none;transition:border-color .15s,box-shadow .15s}
.field input:focus{border-color:var(--primary);box-shadow:0 0 0 3px var(--primary-c)}
.err{color:var(--red);font-size:14px;font-weight:700;text-align:center}

.hero{text-align:center;padding:26px 4px 18px}
.hero h1{font-size:26px;font-weight:800}
.hero p{margin-top:4px;font-size:14px}
.searchbar{display:flex;align-items:center;gap:8px;background:var(--surface);border:1.5px solid var(--outline);border-radius:999px;padding:6px 8px 6px 8px;box-shadow:var(--shadow);transition:border-color .15s,box-shadow .15s}
.searchbar:focus-within{border-color:var(--primary);box-shadow:0 0 0 3px var(--primary-c)}
.searchbar>.ms{color:var(--text-2);margin-inline-start:10px}
.searchbar input{flex:1;min-width:0;border:0;background:transparent;color:var(--text);font:600 16px 'Cairo',sans-serif;height:40px;outline:none}

.status{margin-top:22px;background:var(--surface);border:1px solid var(--outline);border-radius:20px;padding:16px 18px;display:flex;flex-direction:column;gap:12px}
.status b{font-size:15px}
.lp{height:4px;border-radius:4px;background:var(--primary-c);overflow:hidden;position:relative}
.lp::after{content:'';position:absolute;top:0;bottom:0;width:40%;background:var(--primary);border-radius:4px;animation:lp 1.2s ease-in-out infinite}
@keyframes lp{0%{inset-inline-start:-40%}100%{inset-inline-start:100%}}
.dots::after{content:'';animation:dots 1.4s steps(4,end) infinite}
@keyframes dots{0%{content:''}25%{content:'.'}50%{content:'..'}75%,100%{content:'...'}}

.rhead{display:flex;align-items:center;justify-content:space-between;gap:10px;margin:26px 4px 12px}
.rhead h2{font-size:16px;font-weight:800;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.count{flex:none;background:var(--primary-c);color:var(--on-primary-c);border-radius:999px;padding:2px 12px;font-size:13px;font-weight:800}
.list{display:flex;flex-direction:column;gap:10px}
.item{display:flex;align-items:center;gap:12px;width:100%;text-align:start;background:var(--surface);color:var(--text);border:1px solid var(--outline);border-radius:20px;padding:12px 14px;cursor:pointer;font-family:inherit;box-shadow:var(--shadow);transition:transform .1s,border-color .15s}
.item:hover{border-color:var(--primary)}
.item:active{transform:scale(.99)}
.num{flex:none;width:38px;height:38px;border-radius:12px;display:grid;place-items:center;background:var(--red-c);color:var(--red);font-weight:800;font-size:14px}
.meta{flex:1;min-width:0;display:flex;flex-direction:column;gap:2px}
.title{font-weight:700;font-size:15px;line-height:1.5;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden;word-break:break-word}
.size{font-size:12px;font-weight:700;color:var(--text-2);direction:ltr;text-align:start}
.act{flex:none;width:40px;height:40px;border-radius:50%;display:grid;place-items:center;background:var(--primary-c);color:var(--on-primary-c)}
.act.ms{font-size:22px}
.act.done{background:var(--green-c);color:var(--green)}
.act.bad{background:var(--red-c);color:var(--red)}
.act.wait{background:var(--surface-2);color:var(--amber)}
.spin{position:relative}
.spin::after{content:'';width:20px;height:20px;border:3px solid var(--primary-c);border-top-color:var(--primary);border-radius:50%;animation:rot .8s linear infinite;background:transparent}
@keyframes rot{to{transform:rotate(360deg)}}

.empty{margin-top:26px;text-align:center;padding:30px 16px;border:1px dashed var(--outline);border-radius:24px;color:var(--text-2)}
.empty .ms{font-size:42px;color:var(--text-2)}
.empty b{display:block;color:var(--text);margin-top:6px}

.snack{position:fixed;inset-inline:16px;bottom:max(20px,env(safe-area-inset-bottom));max-width:480px;margin:0 auto;z-index:50;display:flex;align-items:center;justify-content:space-between;gap:14px;background:#2b3230;color:#f1f4f2;border-radius:16px;padding:12px 18px;font-size:14px;font-weight:600;box-shadow:0 8px 24px rgba(0,0,0,.3)}
.snack a{color:#8ab4f8;font-weight:800;text-decoration:none;white-space:nowrap}

.modal{position:fixed;inset:0;z-index:40;background:rgba(0,0,0,.45);display:flex;align-items:flex-end;justify-content:center}
.sheet{width:100%;max-width:480px;background:var(--surface);border-radius:28px 28px 0 0;padding:26px 22px max(26px,env(safe-area-inset-bottom));display:flex;flex-direction:column;align-items:center;gap:14px}
.sheet h2{font-size:20px;font-weight:800}
.rows{width:100%;display:flex;flex-direction:column;gap:8px}
.row{display:flex;align-items:center;justify-content:space-between;gap:10px;background:var(--surface-2);border-radius:14px;padding:10px 14px;font-size:14px;font-weight:700}
.row span:first-child{color:var(--text-2)}
.row span:last-child{direction:ltr;font-family:ui-monospace,Menlo,monospace}
@media(min-width:600px){.modal{align-items:center}.sheet{border-radius:28px}}
</style>
</head>
<body>
<header class="top">
  <div class="brand"><span class="logo"><span class="ms">auto_stories</span></span><span>مكتبة الكتب</span></div>
  <button id="profileBtn" class="chip" hidden><span class="avatar"></span><span id="nameSmall"></span></button>
</header>

<main>
  <section id="vLogin" class="card login" hidden>
    <div class="hero-icon"><span class="ms">lock_open</span></div>
    <h1>أهلا بك في مكتبة الكتب</h1>
    <p class="muted">لاستلام الكتب في تيليجرام تحتاج إلى حساب مرتبط بالبوت</p>
    <ol class="steps">
      <li><span class="n">1</span><div>افتح البوت واضغط ابدأ</div></li>
      <li><span class="n">2</span><div>اضغط زر إنشاء الحساب لتحصل على الكود</div></li>
      <li><span class="n">3</span><div>انسخ الكود وضعه في الخانة أدناه</div></li>
    </ol>
    <a class="btn tonal block" href="https://t.me/__BOT__" target="_blank" rel="noopener"><span class="ms">smart_toy</span>فتح البوت @__BOT__</a>
    <label class="field"><span>ادخل الكود الخاص بإنشاء الحساب لإرسال الكتب لك في البوت</span>
      <input id="code" dir="ltr" autocomplete="off" autocapitalize="characters" spellcheck="false" placeholder="XXXXX-XXXXX" maxlength="14">
    </label>
    <button id="loginBtn" class="btn filled block">دخول</button>
    <p id="loginErr" class="err" hidden></p>
  </section>

  <section id="vApp" hidden>
    <div class="hero">
      <h1>ابحث بين ملايين الكتب</h1>
      <p class="muted">اكتب اسم الكتاب أو جزءا واضحا من عنوانه</p>
    </div>
    <form id="sform" class="searchbar">
      <span class="ms">search</span>
      <input id="q" type="search" enterkeyhint="search" placeholder="اسم الكتاب" autocomplete="off" maxlength="80">
      <button id="sbtn" class="btn filled sm" type="submit">بحث</button>
    </form>
    <div id="status" class="status" hidden>
      <b>يتم البحث عن <span id="sq"></span><span class="dots"></span></b>
      <div class="lp"></div>
    </div>
    <div id="results"></div>
  </section>
</main>

<div id="modal" class="modal" hidden>
  <div class="sheet">
    <span class="avatar big"></span>
    <h2 id="mName"></h2>
    <div class="rows">
      <div class="row"><span>المعرف</span><span id="mUser"></span></div>
      <div class="row"><span>الايدي</span><span id="mId"></span></div>
    </div>
    <a class="btn tonal block" href="https://t.me/__BOT__" target="_blank" rel="noopener"><span class="ms">smart_toy</span>فتح البوت</a>
    <button id="logoutBtn" class="btn out block"><span class="ms">logout</span>تسجيل الخروج</button>
    <button id="closeBtn" class="btn block" style="background:transparent;color:var(--text-2)">إغلاق</button>
  </div>
</div>

<div id="snack" class="snack" hidden><span id="snackText"></span><a id="snackAct" hidden target="_blank" rel="noopener"></a></div>

<script>
(function(){
'use strict';
var BOT_URL='https://t.me/__BOT__';
var $=function(s){return document.querySelector(s)};
var token='';try{token=localStorage.getItem('tok')||''}catch(e){}
var me=null,curId='',seq=0;
var sleep=function(ms){return new Promise(function(r){setTimeout(r,ms)})};
function el(tag,cls,txt){var e=document.createElement(tag);if(cls)e.className=cls;if(txt!==undefined)e.textContent=txt;return e}
function saveTok(t){token=t;try{if(t)localStorage.setItem('tok',t);else localStorage.removeItem('tok')}catch(e){}}

async function api(path,body){
  var o={method:body?'POST':'GET',headers:{'content-type':'application/json'}};
  if(token)o.headers.authorization='Bearer '+token;
  if(body)o.body=JSON.stringify(body);
  var d={};
  try{
    var r=await fetch(path,o);
    try{d=await r.json()}catch(e){}
    d.http=r.status;
    if(r.status===401&&path!=='/api/login')toLogin();
  }catch(e){d={error:'تعذر الاتصال بالإنترنت',http:0}}
  return d;
}

var tt;
function toast(t,href,label){
  var s=$('#snack');$('#snackText').textContent=t;
  var a=$('#snackAct');
  if(href){a.href=href;a.textContent=label||'فتح';a.hidden=false}else{a.hidden=true}
  s.hidden=false;clearTimeout(tt);
  tt=setTimeout(function(){s.hidden=true},5000);
}

function show(v){
  $('#vLogin').hidden=v!=='login';
  $('#vApp').hidden=v!=='app';
  $('#profileBtn').hidden=v!=='app';
}
function toLogin(){saveTok('');me=null;seq++;show('login')}

function initial(n){return (n||'?').trim().charAt(0).toUpperCase()}
function renderMe(){
  var n=me.first_name||me.username||'مستخدم';
  $('#nameSmall').textContent=n;
  $('#mName').textContent=n;
  $('#mUser').textContent=me.username?'@'+me.username:'-';
  $('#mId').textContent=String(me.id);
  document.querySelectorAll('.avatar').forEach(function(a){a.textContent=initial(n);a.style.backgroundImage=''});
  loadAvatar();
}
async function loadAvatar(){
  try{
    var r=await fetch('/api/avatar',{headers:{authorization:'Bearer '+token}});
    if(!r.ok)return;
    var u=URL.createObjectURL(await r.blob());
    document.querySelectorAll('.avatar').forEach(function(a){a.style.backgroundImage='url('+u+')';a.textContent=''});
  }catch(e){}
}
function enterApp(){show('app');renderMe()}

/* ---------- تسجيل الدخول ---------- */
function loginErr(t){var e=$('#loginErr');e.textContent=t;e.hidden=!t}
async function login(){
  var code=$('#code').value.trim();
  if(code.replace(/[^A-Za-z0-9]/g,'').length<8){loginErr('اكتب الكود كاملا');return}
  loginErr('');$('#loginBtn').disabled=true;
  var r=await api('/api/login',{code:code});
  $('#loginBtn').disabled=false;
  if(r.error){loginErr(r.error);return}
  saveTok(r.token);me=r.user;$('#code').value='';enterApp();
}
$('#loginBtn').onclick=login;
$('#code').addEventListener('keydown',function(e){if(e.key==='Enter')login()});
$('#code').addEventListener('input',function(){this.value=this.value.toUpperCase()});

/* ---------- الملف الشخصي ---------- */
$('#profileBtn').onclick=function(){$('#modal').hidden=false};
$('#closeBtn').onclick=function(){$('#modal').hidden=true};
$('#modal').addEventListener('click',function(e){if(e.target===this)this.hidden=true});
$('#logoutBtn').onclick=async function(){
  $('#modal').hidden=true;
  await api('/api/logout',{});
  $('#results').textContent='';
  toLogin();
};

/* ---------- البحث ---------- */
function startStatus(q){$('#sq').textContent='«'+q+'»';$('#status').hidden=false}
function stopStatus(){$('#status').hidden=true}
function emptyBox(icon,title,sub){
  var b=el('div','empty');
  b.append(el('span','ms',icon),el('b','',title),el('span','',sub));
  return b;
}

$('#sform').addEventListener('submit',function(e){e.preventDefault();doSearch()});

async function doSearch(){
  var q=$('#q').value.replace(/\s+/g,' ').trim();
  if(q.length<2){toast('اكتب اسم الكتاب أولا');return}
  $('#q').blur();
  var my=++seq;
  $('#results').textContent='';startStatus(q);$('#sbtn').disabled=true;
  var r=await api('/api/search',{q:q});
  if(r.error){stopStatus();$('#sbtn').disabled=false;toast(r.error);return}
  for(var i=0;i<100;i++){
    await sleep(i<2?1500:2000);
    if(my!==seq)return;
    var d=await api('/api/search/'+r.id);
    if(my!==seq)return;
    if(d.status==='done'){$('#sbtn').disabled=false;showResults(r.id,q,d.results||[]);return}
    if(d.status!=='pending')break;
  }
  if(my!==seq)return;
  stopStatus();$('#sbtn').disabled=false;
  $('#results').append(emptyBox('error','تعذر الحصول على النتائج','حاول البحث مرة أخرى بعد قليل'));
}

function showResults(id,q,list){
  curId=id;stopStatus();
  var box=$('#results');box.textContent='';
  var h=el('div','rhead');
  h.append(el('h2','','نتائج: '+q),el('span','count',list.length+' كتاب'));
  box.append(h);
  if(!list.length){box.append(emptyBox('search_off','لم يتم العثور على نتائج','جرّب كلمات أخرى أو اسما أوضح للكتاب'));return}
  var ul=el('div','list');
  list.forEach(function(b){
    var it=el('button','item');it.type='button';
    var meta=el('span','meta');
    meta.append(el('span','title',b.name),el('span','size',b.size));
    var act=el('span','act ms','send');
    it.append(el('span','num',String(b.n)),meta,act);
    it.onclick=function(){pickBook(b,act)};
    ul.append(it);
  });
  box.append(ul);
  box.scrollIntoView({behavior:'smooth',block:'start'});
}

/* ---------- طلب كتاب ---------- */
var busy={};
function setAct(a,kind){
  if(kind==='spin'){a.className='act spin';a.textContent='';return}
  var map={ok:['act ms done','check_circle'],bad:['act ms bad','error'],wait:['act ms wait','schedule'],idle:['act ms','send']};
  a.className=map[kind][0];a.textContent=map[kind][1];
}
function mins(s){return Math.max(1,Math.ceil(s/60))+' دقيقة'}

async function pickBook(b,act){
  if(busy[b.n])return;
  busy[b.n]=1;setAct(act,'spin');
  try{
    var r=await api('/api/book',{id:curId,n:b.n});
    if(r.status==='sent'){setAct(act,'ok');toast('تم إرسال الكتاب إلى البوت',BOT_URL,'فتح البوت');return}
    if(r.status==='cooldown'){setAct(act,'wait');toast('يمكنك استلام هذا الكتاب مرة أخرى بعد '+mins(r.wait));return}
    if(r.status==='requested'){
      for(var i=0;i<70;i++){
        await sleep(1500);
        var d=await api('/api/delivery/'+r.pid);
        if(d.status==='sent'){setAct(act,'ok');toast('تم إرسال الكتاب إلى البوت',BOT_URL,'فتح البوت');return}
        if(d.status==='failed'||d.error){setAct(act,'bad');toast(d.message||d.error||'تعذر إرسال الكتاب');return}
      }
      setAct(act,'bad');toast('تأخر وصول الكتاب، حاول مرة أخرى');return;
    }
    setAct(act,'bad');toast(r.error||'حدث خطأ، حاول مرة أخرى');
  }finally{busy[b.n]=0}
}

/* ---------- البداية ---------- */
(async function(){
  if(!token){show('login');return}
  var r=await api('/api/me');
  if(r.user){me=r.user;enterApp()}else{show('login')}
})();
})();
</script>
</body>
</html>`;
