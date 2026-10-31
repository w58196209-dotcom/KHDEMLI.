"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const http = require("node:http");
const express = require("express");
const { DatabaseSync } = require("node:sqlite");
const { Server } = require("socket.io");

const PORT = Number(process.env.PORT) || 3000;
const HOST = process.env.HOST || (process.env.NODE_ENV === "production" ? "0.0.0.0" : "127.0.0.1");
const SESSION_COOKIE = "khdemli_session";
const ADMIN_COOKIE = "khdemli_admin";
const SESSION_DAYS = 14;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "";
const ALLOW_WEAK_ADMIN_PASSWORD = process.env.ADMIN_ALLOW_WEAK_PASSWORD === "1" &&
  process.env.NODE_ENV !== "production" &&
  ["127.0.0.1", "localhost", "::1"].includes(HOST);
const ADMIN_PASSWORD_SALT = crypto.randomBytes(16);
const ADMIN_PASSWORD_HASH = ((ADMIN_PASSWORD.length >= 16 && ADMIN_PASSWORD.length <= 128) ||
  (ALLOW_WEAK_ADMIN_PASSWORD && ADMIN_PASSWORD.length >= 2 && ADMIN_PASSWORD.length <= 128))
  ? crypto.scryptSync(ADMIN_PASSWORD, ADMIN_PASSWORD_SALT, 64)
  : null;
const ROOT = __dirname;
const DATA_DIR = path.join(ROOT, "data");
fs.mkdirSync(DATA_DIR, { recursive: true });

const db = new DatabaseSync(path.join(DATA_DIR, "khdemli.sqlite"));
db.exec("PRAGMA foreign_keys = ON;");
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    first_name TEXT NOT NULL,
    last_name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE COLLATE NOCASE,
    account_type TEXT NOT NULL CHECK (account_type IN ('customer', 'client')),
    phone TEXT NOT NULL DEFAULT '',
    wilaya TEXT NOT NULL,
    password_salt TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS sessions_expiry_idx ON sessions(expires_at);
  CREATE TABLE IF NOT EXISTS services (
    id TEXT PRIMARY KEY,
    owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    category TEXT NOT NULL,
    area TEXT NOT NULL,
    price INTEGER NOT NULL,
    description TEXT NOT NULL,
    created_at TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS conversations (
    id TEXT PRIMARY KEY,
    service_id TEXT NOT NULL REFERENCES services(id) ON DELETE CASCADE,
    requester_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    updated_at TEXT NOT NULL,
    UNIQUE (service_id, requester_id)
  );
  CREATE TABLE IF NOT EXISTS conversation_participants (
    conversation_id TEXT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    PRIMARY KEY (conversation_id, user_id)
  );
  CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY,
    conversation_id TEXT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    sender_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    text TEXT NOT NULL,
    created_at TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS provider_reviews (
    id INTEGER PRIMARY KEY,
    provider_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    reviewer_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    rating INTEGER NOT NULL CHECK (rating BETWEEN 1 AND 5),
    comment TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE (provider_id, reviewer_id),
    CHECK (provider_id != reviewer_id)
  );
  CREATE TABLE IF NOT EXISTS admin_sessions (
    token_hash TEXT PRIMARY KEY,
    expires_at INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS admin_audit_log (
    id INTEGER PRIMARY KEY,
    action TEXT NOT NULL,
    resource_id TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
  );
  CREATE INDEX IF NOT EXISTS messages_conversation_idx ON messages(conversation_id, id);
  CREATE INDEX IF NOT EXISTS services_created_idx ON services(created_at);
  CREATE INDEX IF NOT EXISTS provider_reviews_provider_idx ON provider_reviews(provider_id, created_at DESC);
`);

const conversationColumns = db.prepare("PRAGMA table_info(conversations)").all().map((column) => column.name);
if (conversationColumns.includes("project_id")) {
  const copyServiceConversations = conversationColumns.includes("service_id")
    ? `INSERT INTO conversations_new (id, service_id, requester_id, updated_at)
       SELECT id, service_id, requester_id, updated_at FROM conversations WHERE service_id IS NOT NULL;`
    : "";
  db.exec("PRAGMA foreign_keys = OFF;");
  try {
    db.exec(`
      BEGIN IMMEDIATE;
      DELETE FROM messages
        WHERE conversation_id IN (SELECT id FROM conversations WHERE project_id IS NOT NULL);
      DELETE FROM conversation_participants
        WHERE conversation_id IN (SELECT id FROM conversations WHERE project_id IS NOT NULL);
      DELETE FROM conversations WHERE project_id IS NOT NULL;
      CREATE TABLE conversations_new (
        id TEXT PRIMARY KEY,
        service_id TEXT NOT NULL REFERENCES services(id) ON DELETE CASCADE,
        requester_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        updated_at TEXT NOT NULL,
        UNIQUE (service_id, requester_id)
      );
      ${copyServiceConversations}
      DROP TABLE conversations;
      ALTER TABLE conversations_new RENAME TO conversations;
      DROP TABLE IF EXISTS projects;
      COMMIT;
    `);
  } catch (error) {
    db.exec("ROLLBACK;");
    throw error;
  } finally {
    db.exec("PRAGMA foreign_keys = ON;");
  }
}
db.exec("DROP TABLE IF EXISTS projects;");
db.prepare("DELETE FROM admin_sessions").run();

const app = express();
const server = http.createServer(app);
const io = new Server(server);
app.disable("x-powered-by");
app.set("trust proxy", process.env.TRUST_PROXY === "1" ? 1 : false);
app.use(express.json({ limit: "32kb" }));

const getUserById = db.prepare(`
  SELECT id, first_name AS firstName, last_name AS lastName,
         first_name || ' ' || last_name AS name, email,
         'all' AS accountType, phone, wilaya
  FROM users WHERE id = ?
`);
const sessionLookup = db.prepare(`
  SELECT user_id AS userId FROM sessions
  WHERE token_hash = ? AND expires_at > ?
`);
const sessionInsert = db.prepare("INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)");
const deleteSession = db.prepare("DELETE FROM sessions WHERE token_hash = ?");
const userByEmail = db.prepare("SELECT * FROM users WHERE email = ? COLLATE NOCASE");
const userInsert = db.prepare(`
  INSERT INTO users (first_name, last_name, email, account_type, phone, wilaya, password_salt, password_hash, created_at)
  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
`);
const getParticipants = db.prepare("SELECT user_id AS id FROM conversation_participants WHERE conversation_id = ?");
const getConversation = db.prepare("SELECT * FROM conversations WHERE id = ?");
const addParticipant = db.prepare("INSERT INTO conversation_participants (conversation_id, user_id) VALUES (?, ?)");
const insertMessage = db.prepare("INSERT INTO messages (conversation_id, sender_id, text, created_at) VALUES (?, ?, ?, ?)");
const hasTwoWayConversation = db.prepare(`
  SELECT 1
  FROM conversations c
  JOIN services s ON s.id = c.service_id
  WHERE c.requester_id = ? AND s.owner_id = ?
    AND EXISTS (SELECT 1 FROM messages m WHERE m.conversation_id = c.id AND m.sender_id = c.requester_id)
    AND EXISTS (
      SELECT 1 FROM messages m
      WHERE m.conversation_id = c.id AND m.sender_id = s.owner_id
    )
  LIMIT 1
`);
function hashToken(token) {
  return crypto.createHash("sha256").update(token).digest("hex");
}

function parseCookies(header = "") {
  return Object.fromEntries(header.split(";").map((part) => {
    const separator = part.indexOf("=");
    if (separator < 0) return ["", ""];
    const key = part.slice(0, separator).trim();
    try {
      return [key, decodeURIComponent(part.slice(separator + 1).trim())];
    } catch {
      return [key, ""];
    }
  }).filter(([key]) => key));
}

function withTransaction(operation) {
  db.exec("BEGIN IMMEDIATE");
  try {
    const result = operation();
    db.exec("COMMIT");
    return result;
  } catch (error) {
    db.exec("ROLLBACK");
    throw error;
  }
}

function getRequestUser(req) {
  const token = parseCookies(req.headers.cookie)[SESSION_COOKIE];
  if (!token || token.length > 256) return null;
  const session = sessionLookup.get(hashToken(token), Date.now());
  return session ? getUserById.get(session.userId) : null;
}

function requireUser(req, res, next) {
  const user = getRequestUser(req);
  if (!user) return res.status(401).json({ error: "يلزم تسجيل الدخول للمتابعة." });
  req.user = user;
  next();
}

function getAdminToken(req) {
  const token = parseCookies(req.headers.cookie)[ADMIN_COOKIE];
  return token && token.length <= 256 ? token : null;
}

function getAdminSession(req) {
  const token = getAdminToken(req);
  return token
    ? db.prepare("SELECT token_hash AS tokenHash FROM admin_sessions WHERE token_hash = ? AND expires_at > ?").get(hashToken(token), Date.now())
    : null;
}

function requireAdmin(req, res, next) {
  const session = getAdminSession(req);
  if (!session) return res.status(401).json({ error: "سجّل دخول المشرف للمتابعة." });
  req.adminSession = session;
  next();
}

function recordAdminAction(action, resourceId = "") {
  db.prepare("INSERT INTO admin_audit_log (action, resource_id, created_at) VALUES (?, ?, ?)")
    .run(action, String(resourceId), new Date().toISOString());
}

function requireSameOrigin(req, res, next) {
  const origin = req.get("origin");
  if (origin) {
    let parsedOrigin;
    try {
      parsedOrigin = new URL(origin);
    } catch {
      return res.status(403).json({ error: "مصدر الطلب غير صالح." });
    }
    if (parsedOrigin.host !== req.get("host") || parsedOrigin.protocol !== `${req.protocol}:`) {
      return res.status(403).json({ error: "مصدر الطلب غير مسموح." });
    }
  }
  next();
}

app.use("/api", requireSameOrigin);
app.use("/api", (req, res, next) => {
  res.set("Cache-Control", "no-store");
  next();
});

function setSessionCookie(res, userId) {
  const token = crypto.randomBytes(32).toString("base64url");
  const expiry = Date.now() + SESSION_DAYS * 24 * 60 * 60 * 1000;
  sessionInsert.run(hashToken(token), userId, expiry);
  res.cookie(SESSION_COOKIE, token, {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    maxAge: SESSION_DAYS * 24 * 60 * 60 * 1000,
    path: "/"
  });
}

const loginAttempts = new Map();
const adminLoginAttempts = new Map();
function loginIsLimited(ip) {
  return isLimitedByAttempts(loginAttempts, ip);
}
function isLimitedByAttempts(attempts, ip) {
  const now = Date.now();
  const attempt = attempts.get(ip);
  if (!attempt || now - attempt.startedAt >= 15 * 60 * 1000) {
    attempts.set(ip, { startedAt: now, count: 1 });
    return false;
  }
  attempt.count += 1;
  return attempt.count > 10;
}

app.post("/api/auth/signup", (req, res) => {
  const body = req.body || {};
  const firstName = typeof body.firstName === "string" ? body.firstName.trim() : "";
  const lastName = typeof body.lastName === "string" ? body.lastName.trim() : "";
  const email = typeof body.email === "string" ? body.email.trim().toLowerCase() : "";
  const password = typeof body.password === "string" ? body.password : "";
  const wilaya = typeof body.wilaya === "string" ? body.wilaya.trim() : "";
  if (firstName.length < 1 || firstName.length > 40 || lastName.length < 1 || lastName.length > 40 ||
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254 ||
      wilaya.length < 1 || wilaya.length > 60 ||
      password.length < 8 || password.length > 128 || !/[A-Za-z\u0600-\u06FF]/.test(password) || !/[0-9]/.test(password)) {
    return res.status(400).json({ error: "تحقق من البيانات المدخلة، ويجب أن تحتوي كلمة المرور على حرف ورقم." });
  }
  if (userByEmail.get(email)) return res.status(409).json({ error: "يوجد حساب بهذا البريد. سجّل الدخول بدلًا من ذلك." });
  const salt = crypto.randomBytes(16);
  const passwordHash = crypto.scryptSync(password, salt, 64).toString("hex");
  let result;
  try {
    result = userInsert.run(firstName, lastName, email, "customer", "", wilaya, salt.toString("hex"), passwordHash, new Date().toISOString());
  } catch (error) {
    if (error.code === "SQLITE_CONSTRAINT_UNIQUE") return res.status(409).json({ error: "يوجد حساب بهذا البريد. سجّل الدخول بدلًا من ذلك." });
    throw error;
  }
  setSessionCookie(res, Number(result.lastInsertRowid));
  res.status(201).json({ user: getUserById.get(Number(result.lastInsertRowid)) });
});

app.post("/api/auth/login", (req, res) => {
  const ip = req.ip || req.socket.remoteAddress || "unknown";
  if (loginIsLimited(ip)) return res.status(429).json({ error: "محاولات كثيرة. انتظر 15 دقيقة ثم حاول مجددًا." });
  const email = typeof req.body?.email === "string" ? req.body.email.trim().toLowerCase() : "";
  const password = typeof req.body?.password === "string" ? req.body.password : "";
  const account = userByEmail.get(email);
  const salt = account ? Buffer.from(account.password_salt, "hex") : Buffer.alloc(16);
  const expected = account ? Buffer.from(account.password_hash, "hex") : Buffer.alloc(64);
  const candidate = crypto.scryptSync(password.slice(0, 128), salt, 64);
  if (!account || !crypto.timingSafeEqual(candidate, expected)) {
    return res.status(401).json({ error: "البريد الإلكتروني أو كلمة المرور غير صحيحة." });
  }
  loginAttempts.delete(ip);
  setSessionCookie(res, account.id);
  res.json({ user: getUserById.get(account.id) });
});

app.get("/api/auth/me", (req, res) => {
  res.json({ user: getRequestUser(req) });
});

app.post("/api/auth/logout", (req, res) => {
  const token = parseCookies(req.headers.cookie)[SESSION_COOKIE];
  if (token) {
    const tokenHash = hashToken(token);
    deleteSession.run(tokenHash);
    for (const socket of io.sockets.sockets.values()) {
      if (socket.data.tokenHash === tokenHash) socket.disconnect(true);
    }
  }
  res.clearCookie(SESSION_COOKIE, { httpOnly: true, sameSite: "lax", secure: process.env.NODE_ENV === "production", path: "/" });
  res.status(204).end();
});

app.get("/api/admin/auth/me", (req, res) => {
  res.set("Cache-Control", "no-store");
  res.json({ enabled: Boolean(ADMIN_PASSWORD_HASH), authenticated: Boolean(getAdminSession(req)) });
});

app.post("/api/admin/auth/login", (req, res) => {
  if (!ADMIN_PASSWORD_HASH) {
    return res.status(503).json({ error: "دخول الإدارة غير مفعّل. اضبط ADMIN_PASSWORD قوية بطول 16 حرفاً على الأقل ثم أعد تشغيل الخادم." });
  }
  const ip = req.ip || req.socket.remoteAddress || "unknown";
  if (isLimitedByAttempts(adminLoginAttempts, ip)) {
    return res.status(429).json({ error: "محاولات دخول كثيرة. انتظر 15 دقيقة ثم حاول مجدداً." });
  }
  const password = typeof req.body?.password === "string" ? req.body.password : "";
  const candidate = crypto.scryptSync(password.slice(0, 128), ADMIN_PASSWORD_SALT, 64);
  if (password.length > 128 || !crypto.timingSafeEqual(candidate, ADMIN_PASSWORD_HASH)) {
    return res.status(401).json({ error: "كلمة مرور الإدارة غير صحيحة." });
  }
  adminLoginAttempts.delete(ip);
  const token = crypto.randomBytes(32).toString("base64url");
  const tokenHash = hashToken(token);
  db.prepare("INSERT INTO admin_sessions (token_hash, expires_at) VALUES (?, ?)")
    .run(tokenHash, Date.now() + SESSION_DAYS * 24 * 60 * 60 * 1000);
  res.cookie(ADMIN_COOKIE, token, {
    httpOnly: true,
    sameSite: "strict",
    secure: process.env.NODE_ENV === "production",
    maxAge: SESSION_DAYS * 24 * 60 * 60 * 1000,
    path: "/"
  });
  recordAdminAction("login");
  res.json({ authenticated: true });
});

app.post("/api/admin/auth/logout", requireAdmin, (req, res) => {
  recordAdminAction("logout");
  db.prepare("DELETE FROM admin_sessions WHERE token_hash = ?").run(req.adminSession.tokenHash);
  res.clearCookie(ADMIN_COOKIE, {
    httpOnly: true,
    sameSite: "strict",
    secure: process.env.NODE_ENV === "production",
    path: "/"
  });
  res.status(204).end();
});

app.get("/api/admin/services", requireAdmin, (req, res) => {
  recordAdminAction("list_services");
  const services = db.prepare(`
    SELECT s.id, s.title, s.category, s.area, s.price, s.created_at AS createdAt,
           s.owner_id AS ownerId, u.first_name || ' ' || u.last_name AS ownerName
    FROM services s JOIN users u ON u.id = s.owner_id
    ORDER BY s.created_at DESC
  `).all();
  res.json({ services });
});

app.delete("/api/admin/services/:id", requireAdmin, (req, res) => {
  const service = db.prepare("SELECT id FROM services WHERE id = ?").get(req.params.id);
  if (!service) return res.status(404).json({ error: "الخدمة غير موجودة." });
  withTransaction(() => {
    recordAdminAction("delete_service", service.id);
    db.prepare("DELETE FROM services WHERE id = ?").run(service.id);
  });
  res.status(204).end();
});

app.get("/api/admin/conversations", requireAdmin, (req, res) => {
  recordAdminAction("list_conversations");
  const conversations = db.prepare(`
    SELECT c.id, c.updated_at AS updatedAt, s.id AS serviceId, s.title AS serviceTitle,
           c.requester_id AS requesterId,
           requester.first_name || ' ' || requester.last_name AS requesterName,
           s.owner_id AS providerId,
           provider.first_name || ' ' || provider.last_name AS providerName,
           (SELECT COUNT(*) FROM messages m WHERE m.conversation_id = c.id) AS messageCount
    FROM conversations c
    JOIN services s ON s.id = c.service_id
    JOIN users requester ON requester.id = c.requester_id
    JOIN users provider ON provider.id = s.owner_id
    ORDER BY c.updated_at DESC
  `).all();
  res.json({ conversations });
});

app.get("/api/admin/conversations/:id", requireAdmin, (req, res) => {
  const conversation = db.prepare(`
    SELECT c.id, c.updated_at AS updatedAt, s.title AS serviceTitle,
           requester.first_name || ' ' || requester.last_name AS requesterName,
           provider.first_name || ' ' || provider.last_name AS providerName
    FROM conversations c
    JOIN services s ON s.id = c.service_id
    JOIN users requester ON requester.id = c.requester_id
    JOIN users provider ON provider.id = s.owner_id
    WHERE c.id = ?
  `).get(req.params.id);
  if (!conversation) return res.status(404).json({ error: "المحادثة غير موجودة." });
  recordAdminAction("view_conversation", conversation.id);
  const messages = db.prepare(`
    SELECT u.first_name || ' ' || u.last_name AS senderName,
           m.text, m.created_at AS createdAt
    FROM messages m JOIN users u ON u.id = m.sender_id
    WHERE m.conversation_id = ? ORDER BY m.id
  `).all(conversation.id);
  res.json({ conversation, messages });
});

app.get("/api/bootstrap", (req, res) => {
  const user = getRequestUser(req);
  const services = db.prepare(`
    SELECT s.id, s.owner_id AS owner, u.first_name || ' ' || u.last_name AS ownerName,
           s.title, s.category, s.area, s.price, s.description, s.created_at AS createdAt
    FROM services s JOIN users u ON u.id = s.owner_id ORDER BY s.created_at DESC
  `).all();
  const accounts = user
    ? db.prepare(`
      SELECT DISTINCT u.id, u.first_name || ' ' || u.last_name AS name
      FROM users u
      WHERE u.id = ? OR u.id IN (SELECT owner_id FROM services)
         OR u.id IN (
           SELECT cp2.user_id FROM conversation_participants cp1
           JOIN conversation_participants cp2 ON cp1.conversation_id = cp2.conversation_id
           WHERE cp1.user_id = ?
         )
    `).all(user.id, user.id)
    : db.prepare(`
      SELECT DISTINCT u.id, u.first_name || ' ' || u.last_name AS name
      FROM users u JOIN services s ON s.owner_id = u.id
    `).all();
  const conversations = user ? db.prepare(`
    SELECT c.id, c.service_id AS serviceId, c.updated_at AS updatedAt
    FROM conversations c
    JOIN conversation_participants cp ON cp.conversation_id = c.id
    WHERE cp.user_id = ? ORDER BY c.updated_at DESC
  `).all(user.id).map((conversation) => ({
    ...conversation,
    participants: getParticipants.all(conversation.id).map((participant) => participant.id),
    messages: db.prepare(`
      SELECT u.id AS sender, m.text, m.created_at AS createdAt
      FROM messages m JOIN users u ON u.id = m.sender_id
      WHERE m.conversation_id = ? ORDER BY m.id
    `).all(conversation.id)
  })) : [];
  res.json({ user, services, accounts, conversations });
});

app.get("/api/accounts/:id/profile", (req, res) => {
  const accountId = Number(req.params.id);
  if (!Number.isSafeInteger(accountId) || accountId < 1) {
    return res.status(400).json({ error: "معرّف الحساب غير صالح." });
  }
  const account = db.prepare(`
    SELECT id, first_name || ' ' || last_name AS name, wilaya
    FROM users WHERE id = ?
  `).get(accountId);
  if (!account) return res.status(404).json({ error: "لم نعثر على ملف مقدم الخدمة." });
  const summary = db.prepare(`
    SELECT COUNT(*) AS count, AVG(rating) AS average
    FROM provider_reviews WHERE provider_id = ?
  `).get(accountId);
  const reviews = db.prepare(`
    SELECT r.id, r.reviewer_id AS reviewerId,
           u.first_name || ' ' || u.last_name AS reviewerName,
           r.rating, r.comment, r.created_at AS createdAt, r.updated_at AS updatedAt
    FROM provider_reviews r
    JOIN users u ON u.id = r.reviewer_id
    WHERE r.provider_id = ? ORDER BY r.created_at DESC
  `).all(accountId);
  const user = getRequestUser(req);
  const ownReview = user
    ? db.prepare(`
      SELECT id, rating, comment, created_at AS createdAt, updated_at AS updatedAt
      FROM provider_reviews WHERE provider_id = ? AND reviewer_id = ?
    `).get(accountId, user.id) || null
    : null;
  const canReview = Boolean(user && (
    ownReview || hasTwoWayConversation.get(user.id, accountId)
  ));
  res.json({
    account,
    rating: { average: summary.average === null ? null : Number(summary.average), count: summary.count },
    reviews,
    canReview,
    ownReview
  });
});

app.post("/api/accounts/:id/reviews", requireUser, (req, res) => {
  const providerId = Number(req.params.id);
  const rating = Number(req.body?.rating);
  const comment = typeof req.body?.comment === "string" ? req.body.comment.trim() : "";
  if (!Number.isSafeInteger(providerId) || providerId < 1 || !Number.isInteger(rating) || rating < 1 || rating > 5) {
    return res.status(400).json({ error: "اختر تقييماً صحيحاً من نجمة إلى خمس نجوم." });
  }
  if (comment.length < 5 || comment.length > 1000) {
    return res.status(400).json({ error: "اكتب مراجعة من 5 إلى 1000 حرف." });
  }
  if (providerId === req.user.id) return res.status(400).json({ error: "لا يمكنك تقييم نفسك." });
  const provider = db.prepare("SELECT id FROM users WHERE id = ?").get(providerId);
  if (!provider) return res.status(404).json({ error: "لم نعثر على مقدم الخدمة." });
  const existingReview = db.prepare("SELECT id FROM provider_reviews WHERE provider_id = ? AND reviewer_id = ?").get(providerId, req.user.id);
  const eligible = hasTwoWayConversation.get(req.user.id, providerId);
  if (!existingReview && !eligible) {
    return res.status(403).json({ error: "يتاح تقييم مقدم الخدمة بعد تبادل الرسائل معه عبر المنصة." });
  }
  const now = new Date().toISOString();
  db.prepare(`
    INSERT INTO provider_reviews (provider_id, reviewer_id, rating, comment, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?)
    ON CONFLICT (provider_id, reviewer_id) DO UPDATE SET
      rating = excluded.rating, comment = excluded.comment, updated_at = excluded.updated_at
  `).run(providerId, req.user.id, rating, comment, now, now);
  const savedReview = db.prepare(`
    SELECT id, rating, comment, created_at AS createdAt, updated_at AS updatedAt
    FROM provider_reviews WHERE provider_id = ? AND reviewer_id = ?
  `).get(providerId, req.user.id);
  res.status(existingReview ? 200 : 201).json({ ...savedReview });
});

function validService(body) {
  const title = typeof body.title === "string" ? body.title.trim() : "";
  const description = typeof body.description === "string" ? body.description.trim() : "";
  const category = typeof body.category === "string" ? body.category : "";
  const area = typeof body.area === "string" ? body.area.trim() : "";
  const amount = Number(body.price);
  if (title.length < 1 || title.length > 100 || description.length < 20 || description.length > 3000 ||
      !["design", "programming", "writing", "marketing", "video", "business"].includes(category) ||
      area.length < 1 || area.length > 60 || !Number.isSafeInteger(amount) || amount < 1 || amount > 100000000) return null;
  return { title, description, category, area, amount };
}

app.post("/api/services", requireUser, (req, res) => {
  const input = validService(req.body || {});
  if (!input) return res.status(400).json({ error: "تحقق من عنوان الخدمة وتصنيفها وولايتها وسعرها ووصفها." });
  const { amount, ...fields } = input;
  const service = { id: crypto.randomUUID(), owner: req.user.id, ...fields, price: amount, createdAt: new Date().toISOString() };
  db.prepare("INSERT INTO services (id, owner_id, title, category, area, price, description, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
    .run(service.id, service.owner, service.title, service.category, service.area, service.price, service.description, service.createdAt);
  res.status(201).json({ service });
});

app.delete("/api/services/:id", requireUser, (req, res) => {
  const result = db.prepare("DELETE FROM services WHERE id = ? AND owner_id = ?").run(req.params.id, req.user.id);
  if (!result.changes) return res.status(404).json({ error: "الخدمة غير موجودة أو لا تملك صلاحية حذفها." });
  res.status(204).end();
});

app.post("/api/conversations", requireUser, (req, res) => {
  const serviceId = typeof req.body?.serviceId === "string" ? req.body.serviceId : "";
  if (!serviceId) return res.status(400).json({ error: "حدد خدمة لبدء المحادثة." });
  const service = db.prepare("SELECT id, owner_id AS owner FROM services WHERE id = ?").get(serviceId);
  if (!service) return res.status(404).json({ error: "لم نعثر على هذه الخدمة." });
  if (service.owner === req.user.id) return res.status(400).json({ error: "لا يمكنك مراسلة نفسك." });
  let conversation = db.prepare("SELECT id FROM conversations WHERE service_id = ? AND requester_id = ?").get(service.id, req.user.id);
  if (conversation) return res.json({ conversation });
  const id = crypto.randomUUID();
  const createdAt = new Date().toISOString();
  withTransaction(() => {
    const result = db.prepare("INSERT OR IGNORE INTO conversations (id, service_id, requester_id, updated_at) VALUES (?, ?, ?, ?)")
      .run(id, service.id, req.user.id, createdAt);
    if (result.changes) {
      addParticipant.run(id, service.owner);
      addParticipant.run(id, req.user.id);
    }
  });
  conversation = db.prepare("SELECT id FROM conversations WHERE service_id = ? AND requester_id = ?").get(service.id, req.user.id);
  res.status(201).json({
    conversation: { ...conversation, serviceId: service.id, updatedAt: createdAt }
  });
});

app.post("/api/messages", requireUser, (req, res) => {
  const conversationId = typeof req.body?.conversationId === "string" ? req.body.conversationId : "";
  const text = typeof req.body?.text === "string" ? req.body.text.trim() : "";
  const conversation = getConversation.get(conversationId);
  const participants = conversation ? getParticipants.all(conversationId).map((participant) => participant.id) : [];
  if (!conversation || !participants.includes(req.user.id)) return res.status(404).json({ error: "لا يمكن العثور على محادثة تخص حسابك." });
  if (!text || text.length > 1000) return res.status(400).json({ error: "يجب أن تكون الرسالة بين حرف واحد و1000 حرف." });
  const createdAt = new Date().toISOString();
  withTransaction(() => {
    insertMessage.run(conversationId, req.user.id, text, createdAt);
    db.prepare("UPDATE conversations SET updated_at = ? WHERE id = ?").run(createdAt, conversationId);
  });
  const message = { sender: req.user.id, text, createdAt };
  for (const participantId of participants) {
    io.to(`user:${participantId}`).emit("chat:message", { conversationId, message });
  }
  res.status(201).json({ message });
});

io.use((socket, next) => {
  const token = parseCookies(socket.handshake.headers.cookie)[SESSION_COOKIE];
  const session = token && token.length <= 256 ? sessionLookup.get(hashToken(token), Date.now()) : null;
  const user = session ? getUserById.get(session.userId) : null;
  if (!user) return next(new Error("يلزم تسجيل الدخول."));
  socket.data.user = user;
  socket.data.tokenHash = hashToken(token);
  next();
});
io.on("connection", (socket) => {
  socket.join(`user:${socket.data.user.id}`);
});

app.get("/", (req, res) => res.sendFile(path.join(ROOT, "index.html")));
app.get(/\/aa\/?$/, (req, res) => res.redirect(302, "/#/aa"));
app.use("/api", (req, res) => res.status(404).json({ error: "واجهة API غير موجودة." }));
app.use((error, req, res, next) => {
  console.error("Request failed:", error);
  if (res.headersSent) return next(error);
  res.status(500).json({ error: "حدث خطأ داخلي. تحقق من سجل الخادم." });
});

const cleanupTimer = setInterval(() => {
  db.prepare("DELETE FROM sessions WHERE expires_at <= ?").run(Date.now());
  db.prepare("DELETE FROM admin_sessions WHERE expires_at <= ?").run(Date.now());
}, 60 * 60 * 1000);
cleanupTimer.unref();

server.listen(PORT, HOST, () => {
  console.log(`KHDEMLI server listening on http://${HOST}:${PORT}`);
  console.log(`SQLite database: ${path.join(DATA_DIR, "khdemli.sqlite")}`);
  if (!ADMIN_PASSWORD_HASH) console.warn("Admin access is disabled. Set ADMIN_PASSWORD (16-128 characters) before starting the server. Weak passwords require an explicit local-only development opt-in.");
});

function shutdown() {
  server.close(() => {
    db.close();
    process.exit(0);
  });
}
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
