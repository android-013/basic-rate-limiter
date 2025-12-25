const express = require("express");
const cors = require("cors");
const dotenv = require("dotenv");
const helmet = require("helmet");
const morgan = require("morgan");
const rateLimit = require("express-rate-limit");
const { slowDown } = require("express-slow-down");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const fs = require("fs/promises");
const path = require("path");
const crypto = require("crypto");

dotenv.config();

const app = express();

const PORT = Number(process.env.PORT || 4000);
const NODE_ENV = process.env.NODE_ENV || "development";

// If you are behind a reverse proxy (NGINX/Cloudflare/Heroku), uncomment:
// app.set("trust proxy", 1);

const JWT_SECRET = process.env.JWT_SECRET || "";
if (!JWT_SECRET || JWT_SECRET.length < 24) {
  console.warn("WARNING: JWT_SECRET is missing or too short. Please set a long random value in backend/.env");
}

// Sliding session
const ACCESS_TOKEN_TTL = process.env.ACCESS_TOKEN_TTL || "15m";
const REFRESH_TOKEN_TTL = process.env.REFRESH_TOKEN_TTL || "365d";

// Rate limiting / slowdown (env configurable)
const API_WINDOW_MS = Number(process.env.API_WINDOW_MS || 60_000);
const API_HARD_LIMIT = Number(process.env.API_HARD_LIMIT || 120);

const AUTH_WINDOW_MS = Number(process.env.AUTH_WINDOW_MS || 60_000);
const AUTH_SLOW_AFTER = Number(process.env.AUTH_SLOW_AFTER || 10);
const AUTH_SLOW_DELAY_MS = Number(process.env.AUTH_SLOW_DELAY_MS || 10_000);
const AUTH_HARD_LIMIT = Number(process.env.AUTH_HARD_LIMIT || 30);

// CORS allowlist
const allowedOrigins = (process.env.ALLOWED_ORIGINS || "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

// Storage
const usersFilePath = path.join(__dirname, "user.json");

// -------------------- Helpers: users file --------------------
async function ensureUsersFile() {
  try {
    await fs.access(usersFilePath);
  } catch {
    await fs.writeFile(usersFilePath, "[]", "utf8");
  }
}

async function readUsers() {
  await ensureUsersFile();
  const raw = await fs.readFile(usersFilePath, "utf8");
  try {
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

async function writeUsers(users) {
  const tmpPath = usersFilePath + ".tmp";
  await fs.writeFile(tmpPath, JSON.stringify(users, null, 2), "utf8");
  await fs.rename(tmpPath, usersFilePath);
}

// -------------------- Validation helpers --------------------
function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}
function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}
function isStrongEnoughPassword(pw) {
  return typeof pw === "string" && pw.length >= 8;
}

// -------------------- Token helpers --------------------
function signAccessToken(user) {
  return jwt.sign(
    { sub: user.id, email: user.email, name: user.name, type: "access" },
    JWT_SECRET,
    { expiresIn: ACCESS_TOKEN_TTL }
  );
}

function signRefreshToken(user) {
  return jwt.sign(
    { sub: user.id, type: "refresh", tid: crypto.randomUUID() },
    JWT_SECRET,
    { expiresIn: REFRESH_TOKEN_TTL }
  );
}

// -------------------- Middleware: basics --------------------
app.disable("x-powered-by");
app.use(helmet());
app.use(express.json({ limit: "50kb" }));
app.use(morgan(NODE_ENV === "production" ? "combined" : "dev"));

// -------------------- CORS (must run BEFORE limiters) --------------------
app.use(
  cors({
    origin: function (origin, cb) {
      if (!origin) {
        return cb(new Error("CORS blocked: missing Origin. Serve frontend via http:// (not file://)."));
      }
      if (!allowedOrigins.length) {
        return cb(new Error("CORS blocked: server allowlist is empty. Set ALLOWED_ORIGINS in backend/.env"));
      }
      if (allowedOrigins.includes(origin)) return cb(null, true);
      return cb(new Error(`CORS blocked: Origin not allowed: ${origin}`));
    },
    methods: ["GET", "POST", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
    maxAge: 86400
  })
);
app.options("*", cors());

// -------------------- Rate limiting + slowdown --------------------
const skipOptions = (req) => req.method === "OPTIONS";

// General API hard limiter
const apiLimiter = rateLimit({
  windowMs: API_WINDOW_MS,
  limit: API_HARD_LIMIT, // 'limit' renamed from 'max' in v7.x :contentReference[oaicite:1]{index=1}
  standardHeaders: "draft-7",
  legacyHeaders: false,
  skip: skipOptions, // do not count preflight
  message: { ok: false, error: "Too many requests. Please try again shortly." }
});

// Auth slowdown (start delaying after N requests)
const authSpeedLimiter = slowDown({
  windowMs: AUTH_WINDOW_MS,
  delayAfter: AUTH_SLOW_AFTER,
  delayMs: AUTH_SLOW_DELAY_MS, // fixed delay (ms) :contentReference[oaicite:2]{index=2}
  maxDelayMs: AUTH_SLOW_DELAY_MS, // keep it capped to the same fixed delay :contentReference[oaicite:3]{index=3}
  skip: skipOptions
});

// Auth hard limiter (absolute cap)
const authHardLimiter = rateLimit({
  windowMs: AUTH_WINDOW_MS,
  limit: AUTH_HARD_LIMIT,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  skip: skipOptions,
  message: { ok: false, error: "Too many authentication attempts. Please wait and retry." }
});

app.use("/api", apiLimiter);
app.use("/api/auth", authSpeedLimiter, authHardLimiter);

// -------------------- Routes --------------------
app.get("/api/health", (req, res) => {
  res.json({
    ok: true,
    message: "API healthy",
    env: NODE_ENV,
    allowedOrigins,
    rate: {
      api: { windowMs: API_WINDOW_MS, hardLimit: API_HARD_LIMIT },
      auth: { windowMs: AUTH_WINDOW_MS, slowAfter: AUTH_SLOW_AFTER, slowDelayMs: AUTH_SLOW_DELAY_MS, hardLimit: AUTH_HARD_LIMIT }
    }
  });
});

app.post("/api/auth/signup", async (req, res, next) => {
  try {
    const name = String(req.body?.name || "").trim();
    const email = normalizeEmail(req.body?.email);
    const password = req.body?.password;

    if (!name || name.length < 2) return res.status(400).json({ ok: false, error: "Name is required (minimum 2 characters)." });
    if (!email || !isValidEmail(email)) return res.status(400).json({ ok: false, error: "A valid email address is required." });
    if (!isStrongEnoughPassword(password)) return res.status(400).json({ ok: false, error: "Password must be at least 8 characters." });

    const users = await readUsers();
    if (users.some((u) => normalizeEmail(u.email) === email)) {
      return res.status(409).json({ ok: false, error: "User already exists. Please sign in." });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const newUser = {
      id: crypto.randomUUID(),
      name,
      email,
      passwordHash,
      refreshTokenHash: null,
      refreshIssuedAt: null,
      createdAt: new Date().toISOString()
    };

    users.push(newUser);
    await writeUsers(users);

    return res.status(201).json({ ok: true, user: { id: newUser.id, name: newUser.name, email: newUser.email } });
  } catch (err) {
    next(err);
  }
});

app.post("/api/auth/signin", async (req, res, next) => {
  try {
    const email = normalizeEmail(req.body?.email);
    const password = req.body?.password;

    if (!email || !isValidEmail(email)) return res.status(400).json({ ok: false, error: "A valid email address is required." });
    if (typeof password !== "string") return res.status(400).json({ ok: false, error: "Password is required." });

    const users = await readUsers();
    const user = users.find((u) => normalizeEmail(u.email) === email);
    if (!user) return res.status(401).json({ ok: false, error: "Invalid credentials." });

    const match = await bcrypt.compare(password, user.passwordHash);
    if (!match) return res.status(401).json({ ok: false, error: "Invalid credentials." });

    const accessToken = signAccessToken(user);
    const refreshToken = signRefreshToken(user);

    user.refreshTokenHash = await bcrypt.hash(refreshToken, 10);
    user.refreshIssuedAt = new Date().toISOString();
    await writeUsers(users);

    return res.json({
      ok: true,
      accessToken,
      refreshToken,
      user: { id: user.id, name: user.name, email: user.email }
    });
  } catch (err) {
    next(err);
  }
});

app.post("/api/auth/refresh", async (req, res, next) => {
  try {
    const refreshToken = String(req.body?.refreshToken || "");
    if (!refreshToken) return res.status(400).json({ ok: false, error: "Refresh token is required." });

    let payload;
    try {
      payload = jwt.verify(refreshToken, JWT_SECRET);
    } catch {
      return res.status(401).json({ ok: false, error: "Invalid or expired refresh token." });
    }

    if (payload?.type !== "refresh" || !payload?.sub) {
      return res.status(401).json({ ok: false, error: "Invalid refresh token." });
    }

    const users = await readUsers();
    const user = users.find((u) => u.id === payload.sub);
    if (!user || !user.refreshTokenHash) return res.status(401).json({ ok: false, error: "Refresh session not found." });

    const match = await bcrypt.compare(refreshToken, user.refreshTokenHash);
    if (!match) return res.status(401).json({ ok: false, error: "Refresh token was revoked or replaced." });

    const newAccessToken = signAccessToken(user);
    const newRefreshToken = signRefreshToken(user);

    user.refreshTokenHash = await bcrypt.hash(newRefreshToken, 10);
    user.refreshIssuedAt = new Date().toISOString();
    await writeUsers(users);

    return res.json({ ok: true, accessToken: newAccessToken, refreshToken: newRefreshToken });
  } catch (err) {
    next(err);
  }
});

app.post("/api/auth/logout", async (req, res, next) => {
  try {
    const refreshToken = String(req.body?.refreshToken || "");
    if (!refreshToken) return res.json({ ok: true });

    let payload;
    try {
      payload = jwt.verify(refreshToken, JWT_SECRET);
    } catch {
      return res.json({ ok: true });
    }

    if (payload?.type !== "refresh" || !payload?.sub) return res.json({ ok: true });

    const users = await readUsers();
    const user = users.find((u) => u.id === payload.sub);
    if (user) {
      user.refreshTokenHash = null;
      user.refreshIssuedAt = null;
      await writeUsers(users);
    }
    return res.json({ ok: true });
  } catch (err) {
    next(err);
  }
});

function requireAccessAuth(req, res, next) {
  const header = String(req.headers.authorization || "");
  const [type, token] = header.split(" ");

  if (type !== "Bearer" || !token) {
    return res.status(401).json({ ok: false, error: "Missing Bearer token." });
  }

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    if (payload?.type !== "access") return res.status(401).json({ ok: false, error: "Invalid access token." });
    req.user = payload;
    return next();
  } catch {
    return res.status(401).json({ ok: false, error: "Invalid or expired token." });
  }
}

app.get("/api/me", requireAccessAuth, (req, res) => {
  res.json({ ok: true, user: req.user });
});

// Error handler (also returns JSON for CORS blocks)
app.use((err, req, res, next) => {
  const msg = err?.message || "Server error";
  const isCors = msg.toLowerCase().includes("cors blocked");
  res.status(isCors ? 403 : 500).json({ ok: false, error: msg });
});

app.listen(PORT, () => {
  console.log(`Backend running on http://localhost:${PORT}`);
  console.log(`Allowed origins: ${allowedOrigins.length ? allowedOrigins.join(", ") : "(none)"}`);
  console.log(`API limit: ${API_HARD_LIMIT}/${Math.round(API_WINDOW_MS / 1000)}s`);
  console.log(`Auth: slow after ${AUTH_SLOW_AFTER}/${Math.round(AUTH_WINDOW_MS / 1000)}s with ${AUTH_SLOW_DELAY_MS}ms delay; hard cap ${AUTH_HARD_LIMIT}`);
});
