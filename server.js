import express from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import crypto from "crypto";
import path from "path";
import pg from "pg";

const { Pool } = pg;

const app = express();
const PORT = Number(process.env.PORT || 3000);

const ADMIN_USER = process.env.ADMIN_USER || "admin";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "CHANGE_ME";
const JWT_SECRET = process.env.JWT_SECRET || "CHANGE_ME";
const DATABASE_URL = process.env.DATABASE_URL;

if (!DATABASE_URL) {
  console.error("ERRO: DATABASE_URL não configurado.");
  process.exit(1);
}

const db = new Pool({
  connectionString: DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

async function iniciarBanco() {
  await db.query(`
    CREATE TABLE IF NOT EXISTS keys (
      id BIGSERIAL PRIMARY KEY,
      key TEXT NOT NULL UNIQUE,
      duration_days INTEGER NOT NULL,
      created_at TIMESTAMPTZ NOT NULL,
      expires_at TIMESTAMPTZ,
      status TEXT NOT NULL DEFAULT 'active',
      hwid TEXT,
      last_used_at TIMESTAMPTZ
    );
  `);

  console.log("Banco PostgreSQL conectado.");
}

app.set("trust proxy", 1);

app.use(helmet({ contentSecurityPolicy: false }));

app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader(
    "Access-Control-Allow-Headers",
    "Content-Type, Authorization"
  );
  res.setHeader(
    "Access-Control-Allow-Methods",
    "GET, POST, OPTIONS"
  );

  if (req.method === "OPTIONS") {
    return res.sendStatus(204);
  }

  next();
});

app.use(express.json());
app.use(express.static("public"));

const apiLimiter = rateLimit({
  windowMs: 60_000,
  limit: 120
});

app.use("/api/", apiLimiter);

function makeKey() {
  const chars = "0123456789ABCDEF";

  const randomPart = (length) =>
    Array.from(
      { length },
      () => chars[crypto.randomInt(0, chars.length)]
    ).join("");

  return `RBX-${randomPart(4)}-${randomPart(3)}`;
}

function adminAuth(req, res, next) {
  const token = (req.headers.authorization || "")
    .replace(/^Bearer\s+/i, "");

  try {
    req.admin = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({
      error: "Não autorizado"
    });
  }
}

app.post("/api/admin/login", async (req, res) => {
  const { username, password } = req.body || {};

  if (
    username !== ADMIN_USER ||
    password !== ADMIN_PASSWORD
  ) {
    return res.status(401).json({
      error: "Usuário ou senha inválidos"
    });
  }

  const token = jwt.sign(
    { sub: ADMIN_USER },
    JWT_SECRET,
    { expiresIn: "8h" }
  );

  res.json({ token });
});

app.post("/api/admin/keys", adminAuth, async (req, res) => {
  try {
    const days = Number(req.body?.duration_days);

    if (![1, 7, 30, 90, 365, 0].includes(days)) {
      return res.status(400).json({
        error:
          "duration_days deve ser 1, 7, 30, 90, 365 ou 0 (vitalícia)"
      });
    }

    let key;

    while (true) {
      key = makeKey();

      const existe = await db.query(
        "SELECT 1 FROM keys WHERE key = $1",
        [key]
      );

      if (existe.rowCount === 0) break;
    }

    const now = new Date();

    const expires =
      days === 0
        ? null
        : new Date(
            now.getTime() + days * 86400000
          );

    await db.query(
      `
      INSERT INTO keys
      (key, duration_days, created_at, expires_at, status)
      VALUES ($1, $2, $3, $4, 'active')
      `,
      [key, days, now, expires]
    );

    res.json({
      key,
      duration_days: days,
      expires_at: expires
        ? expires.toISOString()
        : null,
      status: "active"
    });
  } catch (error) {
    console.error("Erro criando key:", error);

    res.status(500).json({
      error: "Erro ao criar key"
    });
  }
});

app.get("/api/admin/keys", adminAuth, async (req, res) => {
  try {
    const result = await db.query(`
      SELECT
        id,
        key,
        duration_days,
        created_at,
        expires_at,
        status,
        hwid,
        last_used_at
      FROM keys
      ORDER BY id DESC
    `);

    res.json(result.rows);
  } catch (error) {
    console.error("Erro listando keys:", error);

    res.status(500).json({
      error: "Erro ao listar keys"
    });
  }
});

app.post(
  "/api/admin/keys/:id/revoke",
  adminAuth,
  async (req, res) => {
    try {
      const result = await db.query(
        `
        UPDATE keys
        SET status = 'revoked'
        WHERE id = $1
        RETURNING id
        `,
        [req.params.id]
      );

      if (result.rowCount === 0) {
        return res.status(404).json({
          error: "Key não encontrada"
        });
      }

      res.json({ ok: true });
    } catch (error) {
      console.error("Erro revogando key:", error);

      res.status(500).json({
        error: "Erro ao revogar key"
      });
    }
  }
);

app.post("/api/validate", async (req, res) => {
  try {
    const rawKey = String(
      req.body?.key || ""
    )
      .trim()
      .toUpperCase();

    const hwid = String(
      req.body?.hwid || ""
    ).trim();

    if (!rawKey || !hwid) {
      return res.status(400).json({
        valid: false,
        error: "key e hwid são obrigatórios"
      });
    }

    const result = await db.query(
      "SELECT * FROM keys WHERE key = $1",
      [rawKey]
    );

    if (result.rowCount === 0) {
      return res.status(401).json({
        valid: false,
        error: "Key inválida"
      });
    }

    const row = result.rows[0];

    if (row.status === "revoked") {
      return res.status(403).json({
        valid: false,
        error: "Key revogada"
      });
    }

    if (
      row.expires_at &&
      new Date(row.expires_at) <= new Date()
    ) {
      await db.query(
        `
        UPDATE keys
        SET status = 'expired'
        WHERE id = $1
        `,
        [row.id]
      );

      return res.status(403).json({
        valid: false,
        error: "Key expirada"
      });
    }

    if (row.hwid && row.hwid !== hwid) {
      return res.status(403).json({
        valid: false,
        error:
          "Key vinculada a outro dispositivo"
      });
    }

    const now = new Date();

    if (!row.hwid) {
      await db.query(
        `
        UPDATE keys
        SET hwid = $1,
            last_used_at = $2
        WHERE id = $3
        `,
        [hwid, now, row.id]
      );
    } else {
      await db.query(
        `
        UPDATE keys
        SET last_used_at = $1
        WHERE id = $2
        `,
        [now, row.id]
      );
    }

    res.json({
      valid: true,
      key: row.key,
      expires_at: row.expires_at,
      hwid_bound: true
    });
  } catch (error) {
    console.error("Erro validando key:", error);

    res.status(500).json({
      valid: false,
      error: "Erro interno do servidor"
    });
  }
});

app.get(/.*/, (req, res) => {
  res.sendFile(
    path.resolve("public/index.html")
  );
});

async function iniciarServidor() {
  try {
    await iniciarBanco();

    app.listen(PORT, () => {
      console.log(
        `RBX Imperio Key Server em http://localhost:${PORT}`
      );
    });
  } catch (error) {
    console.error(
      "ERRO AO CONECTAR NO BANCO:",
      error
    );

    process.exit(1);
  }
}

iniciarServidor();
