import express from "express";
import Database from "better-sqlite3";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import crypto from "crypto";
import path from "path";
import fs from "fs";

const app = express();
const PORT = Number(process.env.PORT || 3000);
const DB_FILE = process.env.DB_FILE || "./data/rbx.sqlite";
const ADMIN_USER = process.env.ADMIN_USER || "admin";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "CHANGE_ME";
const JWT_SECRET = process.env.JWT_SECRET || "CHANGE_ME";

fs.mkdirSync(path.dirname(DB_FILE), { recursive: true });
const db = new Database(DB_FILE);
db.pragma("journal_mode = WAL");

db.exec(`
CREATE TABLE IF NOT EXISTS keys (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  key TEXT NOT NULL UNIQUE,
  duration_days INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT,
  status TEXT NOT NULL DEFAULT 'active',
  hwid TEXT,
  last_used_at TEXT
);
`);

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json());
app.use(express.static("public"));

const apiLimiter = rateLimit({ windowMs: 60_000, limit: 120 });
app.use("/api/", apiLimiter);

function makeKey() {
  const chars = "0123456789ABCDEF";
  const randomPart = (length) =>
    Array.from({ length }, () => chars[crypto.randomInt(0, chars.length)]).join("");

  return `RBX-${randomPart(4)}-${randomPart(3)}`;
}

function adminAuth(req, res, next) {
  const token = (req.headers.authorization || "").replace(/^Bearer\s+/i, "");
  try {
    req.admin = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: "Não autorizado" });
  }
}

app.post("/api/admin/login", async (req, res) => {
  const { username, password } = req.body || {};
  if (username !== ADMIN_USER || !(await bcrypt.compare(password || "", await bcrypt.hash(ADMIN_PASSWORD, 10)))) {
    return res.status(401).json({ error: "Usuário ou senha inválidos" });
  }
  const token = jwt.sign({ sub: ADMIN_USER }, JWT_SECRET, { expiresIn: "8h" });
  res.json({ token });
});

app.post("/api/admin/keys", adminAuth, (req, res) => {
  const days = Number(req.body?.duration_days);
  if (![1, 7, 30, 90, 365, 0].includes(days)) {
    return res.status(400).json({ error: "duration_days deve ser 1, 7, 30, 90, 365 ou 0 (vitalícia)" });
  }

  let key;
  do { key = makeKey(); } while (db.prepare("SELECT 1 FROM keys WHERE key=?").get(key));

  const now = new Date();
  const expires = days === 0 ? null : new Date(now.getTime() + days * 86400000).toISOString();

  db.prepare(`
    INSERT INTO keys (key, duration_days, created_at, expires_at, status)
    VALUES (?, ?, ?, ?, 'active')
  `).run(key, days, now.toISOString(), expires);

  res.json({ key, duration_days: days, expires_at: expires, status: "active" });
});

app.get("/api/admin/keys", adminAuth, (req, res) => {
  const rows = db.prepare("SELECT id,key,duration_days,created_at,expires_at,status,hwid,last_used_at FROM keys ORDER BY id DESC").all();
  res.json(rows);
});

app.post("/api/admin/keys/:id/revoke", adminAuth, (req, res) => {
  const result = db.prepare("UPDATE keys SET status='revoked' WHERE id=?").run(req.params.id);
  if (!result.changes) return res.status(404).json({ error: "Key não encontrada" });
  res.json({ ok: true });
});

app.post("/api/validate", (req, res) => {
  const rawKey = String(req.body?.key || "").trim().toUpperCase();
  const hwid = String(req.body?.hwid || "").trim();

  if (!rawKey || !hwid) return res.status(400).json({ valid: false, error: "key e hwid são obrigatórios" });

  const row = db.prepare("SELECT * FROM keys WHERE key=?").get(rawKey);
  if (!row) return res.status(401).json({ valid: false, error: "Key inválida" });
  if (row.status === "revoked") return res.status(403).json({ valid: false, error: "Key revogada" });

  if (row.expires_at && new Date(row.expires_at) <= new Date()) {
    db.prepare("UPDATE keys SET status='expired' WHERE id=?").run(row.id);
    return res.status(403).json({ valid: false, error: "Key expirada" });
  }

  if (row.hwid && row.hwid !== hwid) {
    return res.status(403).json({ valid: false, error: "Key vinculada a outro dispositivo" });
  }

  if (!row.hwid) {
    db.prepare("UPDATE keys SET hwid=?, last_used_at=? WHERE id=?").run(hwid, new Date().toISOString(), row.id);
  } else {
    db.prepare("UPDATE keys SET last_used_at=? WHERE id=?").run(new Date().toISOString(), row.id);
  }

  res.json({
    valid: true,
    key: row.key,
    expires_at: row.expires_at,
    hwid_bound: true
  });
});

app.get(/.*/, (req, res) => res.sendFile(path.resolve("public/index.html")));
app.listen(PORT, () => console.log(`RBX Imperio Key Server em http://localhost:${PORT}`));