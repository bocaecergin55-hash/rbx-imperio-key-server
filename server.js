import express from "express";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
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
const PUBLIC_KEY_DURATION_DAYS = Number(
  process.env.PUBLIC_KEY_DURATION_DAYS ?? 0
);

// Mercado Pago
const MP_ACCESS_TOKEN = process.env.MP_ACCESS_TOKEN;

if (!DATABASE_URL) {
  console.error("ERRO: DATABASE_URL não configurado.");
  process.exit(1);
}

if (![0, 1, 7, 30, 90, 365].includes(PUBLIC_KEY_DURATION_DAYS)) {
  console.error("ERRO: PUBLIC_KEY_DURATION_DAYS inválido.");
  process.exit(1);
}

const db = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// =====================================================
// BANCO
// =====================================================

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

  await db.query(`
    CREATE TABLE IF NOT EXISTS users (
      id BIGSERIAL PRIMARY KEY,
      username TEXT NOT NULL UNIQUE,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      signup_ip TEXT NOT NULL UNIQUE,
      key_id BIGINT NOT NULL UNIQUE REFERENCES keys(id),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  // Guarda os pedidos Pix criados pelo checkout
  await db.query(`
    CREATE TABLE IF NOT EXISTS pix_orders (
      id BIGSERIAL PRIMARY KEY,
      external_reference TEXT NOT NULL UNIQUE,
      mp_order_id TEXT,
      plano TEXT NOT NULL,
      valor NUMERIC(10,2) NOT NULL,
      nome TEXT,
      sobrenome TEXT,
      email TEXT NOT NULL,
      telefone TEXT,
      status TEXT NOT NULL DEFAULT 'pending',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  console.log("Banco PostgreSQL conectado.");
}

// =====================================================
// MIDDLEWARES
// =====================================================

app.set("trust proxy", 1);

app.use(
  helmet({
    contentSecurityPolicy: false
  })
);

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

app.use(
  "/api/",
  rateLimit({
    windowMs: 60_000,
    limit: 120
  })
);

const generateLimiter = rateLimit({
  windowMs: 60_000,
  limit: 10
});

const pixLimiter = rateLimit({
  windowMs: 60_000,
  limit: 8
});

// =====================================================
// PLANOS DO CHECKOUT
// =====================================================

// O navegador envia apenas o código do plano.
// O valor verdadeiro é definido aqui no servidor.
const PLANOS = {
  start: {
    nome: "RBX Império Start",
    valor: "12.90"
  },

  pro: {
    nome: "RBX Império Pro",
    valor: "19.99"
  },

  imperio: {
    nome: "RBX Império",
    valor: "39.90"
  }
};

// =====================================================
// FUNÇÕES
// =====================================================

function makeKey() {
  const chars = "0123456789ABCDEF";

  const part = n =>
    Array.from(
      { length: n },
      () => chars[crypto.randomInt(0, chars.length)]
    ).join("");

  return `RBX-${part(4)}-${part(3)}`;
}

function adminAuth(req, res, next) {
  const token = (req.headers.authorization || "").replace(
    /^Bearer\s+/i,
    ""
  );

  try {
    req.admin = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({
      error: "Não autorizado"
    });
  }
}

function clientIp(req) {
  return String(
    req.ip || req.socket?.remoteAddress || ""
  ).replace(/^::ffff:/, "");
}

// =====================================================
// ADMIN LOGIN
// =====================================================

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

  res.json({
    token: jwt.sign(
      { sub: ADMIN_USER },
      JWT_SECRET,
      { expiresIn: "8h" }
    )
  });
});

// =====================================================
// ADMIN KEYS
// =====================================================

app.post(
  "/api/admin/keys",
  adminAuth,
  async (req, res) => {
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

        const x = await db.query(
          "SELECT 1 FROM keys WHERE key=$1",
          [key]
        );

        if (!x.rowCount) break;
      }

      const now = new Date();

      const expires =
        days === 0
          ? null
          : new Date(
              now.getTime() +
                days * 86400000
            );

      await db.query(
        `
        INSERT INTO keys
        (
          key,
          duration_days,
          created_at,
          expires_at,
          status
        )
        VALUES ($1,$2,$3,$4,'active')
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
    } catch (e) {
      console.error(
        "Erro criando key:",
        e
      );

      res.status(500).json({
        error: "Erro ao criar key"
      });
    }
  }
);

app.get(
  "/api/admin/keys",
  adminAuth,
  async (req, res) => {
    try {
      const r = await db.query(`
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

      res.json(r.rows);
    } catch (e) {
      console.error(
        "Erro listando keys:",
        e
      );

      res.status(500).json({
        error: "Erro ao listar keys"
      });
    }
  }
);

app.post(
  "/api/admin/keys/:id/revoke",
  adminAuth,
  async (req, res) => {
    try {
      const r = await db.query(
        `
        UPDATE keys
        SET status='revoked'
        WHERE id=$1
        RETURNING id
        `,
        [req.params.id]
      );

      if (!r.rowCount) {
        return res.status(404).json({
          error: "Key não encontrada"
        });
      }

      res.json({ ok: true });
    } catch (e) {
      console.error(
        "Erro revogando key:",
        e
      );

      res.status(500).json({
        error: "Erro ao revogar key"
      });
    }
  }
);

// =====================================================
// CADASTRO CLIENTE
// =====================================================

app.post(
  "/api/register",
  generateLimiter,
  async (req, res) => {
    const username = String(
      req.body?.username || ""
    ).trim();

    const email = String(
      req.body?.email || ""
    )
      .trim()
      .toLowerCase();

    const password = String(
      req.body?.password || ""
    );

    const ip = clientIp(req);

    if (
      !/^[A-Za-z0-9_.-]{3,24}$/.test(
        username
      )
    ) {
      return res.status(400).json({
        ok: false,
        error:
          "Usuário deve ter de 3 a 24 caracteres."
      });
    }

    if (
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(
        email
      )
    ) {
      return res.status(400).json({
        ok: false,
        error: "E-mail inválido."
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        ok: false,
        error:
          "A senha deve ter pelo menos 6 caracteres."
      });
    }

    const client = await db.connect();

    try {
      const blocked =
        await client.query(
          `
          SELECT 1
          FROM users
          WHERE signup_ip=$1
          `,
          [ip]
        );

      if (blocked.rowCount) {
        return res.status(409).json({
          ok: false,
          error:
            "Este acesso já possui uma conta. Entre na conta existente."
        });
      }

      const dup =
        await client.query(
          `
          SELECT 1
          FROM users
          WHERE
            lower(username)=lower($1)
            OR email=$2
          `,
          [username, email]
        );

      if (dup.rowCount) {
        return res.status(409).json({
          ok: false,
          error:
            "Usuário ou e-mail já cadastrado."
        });
      }

      let key;

      while (true) {
        key = makeKey();

        const x =
          await client.query(
            `
            SELECT 1
            FROM keys
            WHERE key=$1
            `,
            [key]
          );

        if (!x.rowCount) break;
      }

      const now = new Date();
      const days =
        PUBLIC_KEY_DURATION_DAYS;

      const expires =
        days === 0
          ? null
          : new Date(
              now.getTime() +
                days * 86400000
            );

      const hash =
        await bcrypt.hash(
          password,
          12
        );

      await client.query("BEGIN");

      const kr =
        await client.query(
          `
          INSERT INTO keys
          (
            key,
            duration_days,
            created_at,
            expires_at,
            status
          )
          VALUES
          ($1,$2,$3,$4,'active')
          RETURNING id
          `,
          [
            key,
            days,
            now,
            expires
          ]
        );

      await client.query(
        `
        INSERT INTO users
        (
          username,
          email,
          password_hash,
          signup_ip,
          key_id,
          created_at
        )
        VALUES
        ($1,$2,$3,$4,$5,$6)
        `,
        [
          username,
          email,
          hash,
          ip,
          kr.rows[0].id,
          now
        ]
      );

      await client.query(
        "COMMIT"
      );

      res.json({
        ok: true,
        key,
        username
      });
    } catch (e) {
      try {
        await client.query(
          "ROLLBACK"
        );
      } catch {}

      if (e.code === "23505") {
        return res.status(409).json({
          ok: false,
          error:
            "Já existe uma conta para estes dados ou acesso."
        });
      }

      console.error(
        "Erro cadastro:",
        e
      );

      res.status(500).json({
        ok: false,
        error:
          "Não foi possível criar a conta."
      });
    } finally {
      client.release();
    }
  }
);

// =====================================================
// LOGIN CLIENTE
// =====================================================

app.post(
  "/api/client/login",
  generateLimiter,
  async (req, res) => {
    const login = String(
      req.body?.login || ""
    ).trim();

    const password = String(
      req.body?.password || ""
    );

    try {
      const r = await db.query(
        `
        SELECT
          u.username,
          u.password_hash,
          k.key,
          k.status,
          k.expires_at
        FROM users u
        JOIN keys k
          ON k.id=u.key_id
        WHERE
          lower(u.username)=lower($1)
          OR lower(u.email)=lower($1)
        LIMIT 1
        `,
        [login]
      );

      if (
        !r.rowCount ||
        !(await bcrypt.compare(
          password,
          r.rows[0].password_hash
        ))
      ) {
        return res.status(401).json({
          ok: false,
          error:
            "Usuário/e-mail ou senha inválidos."
        });
      }

      const row = r.rows[0];

      if (
        row.status === "revoked"
      ) {
        return res.status(403).json({
          ok: false,
          error:
            "Sua key foi revogada."
        });
      }

      res.json({
        ok: true,
        username: row.username,
        key: row.key,
        expires_at:
          row.expires_at
      });
    } catch (e) {
      console.error(
        "Erro login cliente:",
        e
      );

      res.status(500).json({
        ok: false,
        error:
          "Não foi possível entrar."
      });
    }
  }
);

// =====================================================
// VALIDAR KEY
// =====================================================

app.post(
  "/api/validate",
  async (req, res) => {
    try {
      const rawKey = String(
        req.body?.key || ""
      )
        .trim()
        .toUpperCase();

      const hwid = String(
        req.body?.hwid || ""
      )
        .trim()
        .toUpperCase();

      if (!rawKey || !hwid) {
        return res.status(400).json({
          valid: false,
          error:
            "key e hwid são obrigatórios"
        });
      }

      const result =
        await db.query(
          `
          SELECT *
          FROM keys
          WHERE key=$1
          `,
          [rawKey]
        );

      if (!result.rowCount) {
        return res.status(401).json({
          valid: false,
          error: "Key inválida"
        });
      }

      const row =
        result.rows[0];

      if (
        row.status === "revoked"
      ) {
        return res.status(403).json({
          valid: false,
          error: "Key revogada"
        });
      }

      if (
        row.expires_at &&
        new Date(row.expires_at) <=
          new Date()
      ) {
        await db.query(
          `
          UPDATE keys
          SET status='expired'
          WHERE id=$1
          `,
          [row.id]
        );

        return res.status(403).json({
          valid: false,
          error: "Key expirada"
        });
      }

      if (
        row.hwid &&
        row.hwid !== hwid
      ) {
        return res.status(403).json({
          valid: false,
          error:
            "Key vinculada a outro dispositivo"
        });
      }

      const now = new Date();

      if (!row.hwid) {
        try {
          await db.query(
            `
            UPDATE keys
            SET
              hwid=$1,
              last_used_at=$2
            WHERE id=$3
            `,
            [
              hwid,
              now,
              row.id
            ]
          );
        } catch (e) {
          if (e.code === "23505") {
            return res.status(403).json({
              valid: false,
              error:
                "Este computador já possui outra key"
            });
          }

          throw e;
        }
      } else {
        await db.query(
          `
          UPDATE keys
          SET last_used_at=$1
          WHERE id=$2
          `,
          [now, row.id]
        );
      }

      res.json({
        valid: true,
        key: row.key,
        expires_at:
          row.expires_at,
        hwid_bound: true
      });
    } catch (e) {
      console.error(
        "Erro validando key:",
        e
      );

      res.status(500).json({
        valid: false,
        error:
          "Erro interno do servidor"
      });
    }
  }
);

// =====================================================
// CHECKOUT PIX - MERCADO PAGO
// =====================================================

app.post(
  "/api/pix/criar",
  pixLimiter,
  async (req, res) => {
    try {
      if (!MP_ACCESS_TOKEN) {
        console.error(
          "MP_ACCESS_TOKEN não configurado."
        );

        return res.status(500).json({
          ok: false,
          error:
            "Pagamento temporariamente indisponível."
        });
      }

      const planoCodigo = String(
        req.body?.plano || ""
      )
        .trim()
        .toLowerCase();

      const nome = String(
        req.body?.nome || ""
      ).trim();

      const sobrenome = String(
        req.body?.sobrenome || ""
      ).trim();

      const email = String(
        req.body?.email || ""
      )
        .trim()
        .toLowerCase();

      const telefone = String(
        req.body?.telefone || ""
      ).trim();

      const plano =
        PLANOS[planoCodigo];

      if (!plano) {
        return res.status(400).json({
          ok: false,
          error:
            "Plano inválido."
        });
      }

      if (
        nome.length < 2 ||
        nome.length > 80
      ) {
        return res.status(400).json({
          ok: false,
          error:
            "Informe seu nome."
        });
      }

      if (
        sobrenome.length < 2 ||
        sobrenome.length > 100
      ) {
        return res.status(400).json({
          ok: false,
          error:
            "Informe seu sobrenome."
        });
      }

      if (
        !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(
          email
        )
      ) {
        return res.status(400).json({
          ok: false,
          error:
            "Informe um e-mail válido."
        });
      }

      const externalReference =
        `RBX_${planoCodigo}_${Date.now()}_${crypto
          .randomBytes(4)
          .toString("hex")}`;

      const idempotencyKey =
        crypto.randomUUID();

      const body = {
        type: "online",

        total_amount:
          plano.valor,

        external_reference:
          externalReference,

        processing_mode:
          "automatic",

        transactions: {
          payments: [
            {
              amount:
                plano.valor,

              payment_method: {
                id: "pix",
                type: "bank_transfer"
              },

              // Pix válido por 30 minutos
              expiration_time: "PT30M"
            }
          ]
        },

        payer: {
          email
        }
      };

      const response =
        await fetch(
          "https://api.mercadopago.com/v1/orders",
          {
            method: "POST",

            headers: {
              Accept:
                "application/json",

              "Content-Type":
                "application/json",

              Authorization:
                `Bearer ${MP_ACCESS_TOKEN}`,

              "X-Idempotency-Key":
                idempotencyKey
            },

            body:
              JSON.stringify(body)
          }
        );

      const data =
        await response.json();

      if (!response.ok) {
        console.error(
          "Erro Mercado Pago:",
          response.status,
          JSON.stringify(data)
        );

        return res
          .status(502)
          .json({
            ok: false,
            error:
              "Não foi possível gerar o Pix agora.",
            details:
              data?.message ||
              data?.error ||
              null
          });
      }

      const mpOrderId =
        data?.id || null;

      const payment =
        data?.transactions
          ?.payments?.[0] ||
        null;

      /*
       * A resposta pode variar conforme
       * a versão/conta do Mercado Pago.
       * Procuramos os campos do QR
       * em alguns locais possíveis.
       */

      const qrCode =
        payment?.payment_method
          ?.qr_code ||
        payment?.qr_code ||
        payment?.point_of_interaction
          ?.transaction_data
          ?.qr_code ||
        data?.payment_method
          ?.qr_code ||
        data?.qr_code ||
        null;

      const qrCodeBase64 =
        payment?.payment_method
          ?.qr_code_base64 ||
        payment?.qr_code_base64 ||
        payment?.point_of_interaction
          ?.transaction_data
          ?.qr_code_base64 ||
        data?.payment_method
          ?.qr_code_base64 ||
        data?.qr_code_base64 ||
        null;

      const ticketUrl =
        payment?.payment_method
          ?.ticket_url ||
        payment?.ticket_url ||
        payment?.point_of_interaction
          ?.transaction_data
          ?.ticket_url ||
        data?.ticket_url ||
        null;

      await db.query(
        `
        INSERT INTO pix_orders
        (
          external_reference,
          mp_order_id,
          plano,
          valor,
          nome,
          sobrenome,
          email,
          telefone,
          status
        )
        VALUES
        (
          $1,$2,$3,$4,$5,$6,$7,$8,$9
        )
        `,
        [
          externalReference,
          mpOrderId,
          planoCodigo,
          plano.valor,
          nome,
          sobrenome,
          email,
          telefone,
          String(
            data?.status ||
              payment?.status ||
              "pending"
          )
        ]
      );

      res.json({
        ok: true,

        plano: {
          codigo:
            planoCodigo,
          nome:
            plano.nome,
          valor:
            plano.valor
        },

        order_id:
          mpOrderId,

        external_reference:
          externalReference,

        status:
          data?.status ||
          payment?.status ||
          "pending",

        qr_code:
          qrCode,

        qr_code_base64:
          qrCodeBase64,

        ticket_url:
          ticketUrl
      });
    } catch (e) {
      console.error(
        "Erro criando Pix:",
        e
      );

      res.status(500).json({
        ok: false,
        error:
          "Erro interno ao gerar o Pix."
      });
    }
  }
);

// =====================================================
// CONSULTAR STATUS DO PIX
// =====================================================

app.get(
  "/api/pix/status/:reference",
  async (req, res) => {
    try {
      const reference =
        String(
          req.params.reference ||
            ""
        ).trim();

      if (
        !/^[A-Za-z0-9_-]{1,100}$/.test(
          reference
        )
      ) {
        return res.status(400).json({
          ok: false,
          error:
            "Referência inválida."
        });
      }

      const local =
        await db.query(
          `
          SELECT
            external_reference,
            mp_order_id,
            plano,
            valor,
            status,
            created_at,
            updated_at
          FROM pix_orders
          WHERE external_reference=$1
          LIMIT 1
          `,
          [reference]
        );

      if (!local.rowCount) {
        return res.status(404).json({
          ok: false,
          error:
            "Pagamento não encontrado."
        });
      }

      const pedido =
        local.rows[0];

      if (
        !pedido.mp_order_id ||
        !MP_ACCESS_TOKEN
      ) {
        return res.json({
          ok: true,
          status:
            pedido.status,
          plano:
            pedido.plano,
          valor:
            pedido.valor
        });
      }

      const response =
        await fetch(
          `https://api.mercadopago.com/v1/orders/${encodeURIComponent(
            pedido.mp_order_id
          )}`,
          {
            headers: {
              Accept:
                "application/json",

              Authorization:
                `Bearer ${MP_ACCESS_TOKEN}`
            }
          }
        );

      const data =
        await response.json();

      if (!response.ok) {
        console.error(
          "Erro consultando order:",
          response.status,
          JSON.stringify(data)
        );

        return res.json({
          ok: true,
          status:
            pedido.status,
          plano:
            pedido.plano,
          valor:
            pedido.valor
        });
      }

      const novoStatus =
        String(
          data?.status ||
            data?.transactions
              ?.payments?.[0]
              ?.status ||
            pedido.status
        );

      await db.query(
        `
        UPDATE pix_orders
        SET
          status=$1,
          updated_at=NOW()
        WHERE external_reference=$2
        `,
        [
          novoStatus,
          reference
        ]
      );

      res.json({
        ok: true,
        status:
          novoStatus,
        plano:
          pedido.plano,
        valor:
          pedido.valor
      });
    } catch (e) {
      console.error(
        "Erro consultando Pix:",
        e
      );

      res.status(500).json({
        ok: false,
        error:
          "Erro ao consultar pagamento."
      });
    }
  }
);

// =====================================================
// SITE
// =====================================================

app.get(
  /.*/,
  (req, res) =>
    res.sendFile(
      path.resolve(
        "public/index.html"
      )
    )
);

// =====================================================
// INICIAR SERVIDOR
// =====================================================

async function iniciarServidor() {
  try {
    await iniciarBanco();

    app.listen(
      PORT,
      () =>
        console.log(
          `RBX Imperio Key Server em http://localhost:${PORT}`
        )
    );
  } catch (e) {
    console.error(
      "ERRO AO CONECTAR NO BANCO:",
      e
    );

    process.exit(1);
  }
}

iniciarServidor();
