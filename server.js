console.log("SERVER FILE LOADED:", __filename);
const express = require("express");
const path = require("path");
require("dotenv").config({ path: path.join(__dirname, ".env.local") });

const multer = require("multer");
const pool = require("./db"); // mysql2/promise pool
const fs = require("fs");
const bcrypt = require("bcryptjs");
const rateLimit = require("express-rate-limit");
const crypto = require("crypto");
const { sendVerificationEmail, verifyTransporter } = require("./mailer");

// Sessions (ADMIN)
const session = require("express-session");
const mysql2 = require("mysql2"); // callback-based for session store
const MySQLStore = require("express-mysql-session")(session);

const app = express();
const PORT = process.env.PORT || 3000;

// ✅ fetch support (Node 18+ has global fetch; otherwise install node-fetch)
const fetchFn = global.fetch
  ? global.fetch
  : (...args) => import("node-fetch").then(({ default: fetch }) => fetch(...args));

// parse form fields
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

// serve static files (public/css, public/uploads, etc.)
app.use("/public", express.static(path.join(__dirname, "public")));

app.use((req, res, next) => {
  res.setHeader("Cache-Control", "no-store");
  next();
});

// ========================================
// SESSION STORE (MySQL) for ADMIN
// IMPORTANT: express-mysql-session needs callback-based connection
// ========================================
const DB_HOST = process.env.DB_HOST || "localhost";
const DB_USER = process.env.DB_USER || "samgyup_user";
// ✅ support both DB_PASSWORD and DB_PASS to avoid env mismatch
const DB_PASSWORD = process.env.DB_PASSWORD || process.env.DB_PASS || "";
const DB_NAME = process.env.DB_NAME || "samgyup_db";
const DB_CONNECTION_LIMIT = Number(process.env.DB_CONNECTION_LIMIT || 10);

const sessionDbPool = mysql2.createPool({
  host: DB_HOST,
  user: DB_USER,
  password: DB_PASSWORD,
  database: DB_NAME,
  connectionLimit: DB_CONNECTION_LIMIT,
});

const sessionStore = new MySQLStore(
  {
    clearExpired: true,
    checkExpirationInterval: 15 * 60 * 1000,
    expiration: 2 * 60 * 60 * 1000, // 2 hours
  },
  sessionDbPool
);

app.use(
  session({
    name: "sg_admin_sid",
    secret: process.env.SESSION_SECRET || "change-this-in-env",
    store: sessionStore,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: false, // set true if HTTPS
      maxAge: 2 * 60 * 60 * 1000,
    },
  })
);

// ========================================
// FILE UPLOAD SETUP (REGISTER)
// ========================================
const uploadsDir = path.join(__dirname, "public", "uploads");
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
  console.log("✅ Created uploads directory at:", uploadsDir);
} else {
  console.log("✅ Uploads directory exists at:", uploadsDir);
}

// Multer upload setup
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadsDir),
  filename: (req, file, cb) => {
    const safeName = file.originalname.replace(/[^a-zA-Z0-9._-]/g, "_");
    cb(null, Date.now() + "_" + safeName);
  },
});
const upload = multer({ storage });

// ========================================
// RATE LIMITING (LOGIN ONLY) - BY IP
// ========================================

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 500,
  message: { error: "Too many login attempts. Please try again in 15 minutes." },
  standardHeaders: true,
  legacyHeaders: false,
});

// ========================================
// VALIDATION FUNCTIONS
// ========================================
function isValidEmail(email) {
  const emailRegex = /^[^@\.][^@]*@[^@]+\.[^@]+$/;
  return emailRegex.test(email) && email.length <= 254;
}


// Password policy: 8+ chars, upper, lower, number, special
function isStrongPassword(pw) {
  if (!pw || pw.length < 8) return false;
  if (!/[A-Z]/.test(pw)) return false;
  if (!/[a-z]/.test(pw)) return false;
  if (!/[0-9]/.test(pw)) return false;
  if (!/[^A-Za-z0-9]/.test(pw)) return false;
  return true;
}

// Create a verification token (raw + hashed)
function makeVerificationToken() {
  const rawToken = crypto.randomBytes(32).toString("hex");
  const tokenHash = crypto.createHash("sha256").update(rawToken).digest("hex");
  return { rawToken, tokenHash };
}

// ✅ Google reCAPTCHA v2 verification (server-side)
async function verifyRecaptchaV2(token, ip) {
  const secret = process.env.RECAPTCHA_SECRET_KEY;

  if (!secret) {
    console.warn("[reCAPTCHA] Missing RECAPTCHA_SECRET_KEY in env");
    return false;
  }
  if (!token) return false;

  const params = new URLSearchParams();
  params.append("secret", secret);
  params.append("response", token);
  if (ip) params.append("remoteip", ip);

  const resp = await fetchFn("https://www.google.com/recaptcha/api/siteverify", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: params.toString(),
  });

  const data = await resp.json();
  return data && data.success === true;
}

// ========================================
// ACCOUNT LOCKING (BY EMAIL) - MySQL table: login_attempts
// ========================================
const LOCK_WINDOW_MIN = 15;
const LOCK_THRESHOLD = 10;
const LOCK_DURATION_MIN = 30;

async function getAttemptRow(email) {
  const [rows] = await pool.execute(
    `SELECT email, failed_count, first_failed_at, last_failed_at, lock_until
     FROM login_attempts
     WHERE email = ?
     LIMIT 1`,
    [email]
  );
  return rows[0] || null;
}

async function isEmailLocked(email) {
  const row = await getAttemptRow(email);
  if (!row || !row.lock_until) return false;
  return new Date(row.lock_until) > new Date();
}

async function recordFailedAttempt(email) {
  const now = new Date();
  const row = await getAttemptRow(email);

  // Create row if missing
  if (!row) {
    await pool.execute(
      `INSERT INTO login_attempts (email, failed_count, first_failed_at, last_failed_at, lock_until)
       VALUES (?, 1, ?, ?, NULL)`,
      [email, now, now]
    );
    return;
  }

  // If already locked, keep it locked (do not extend)
  if (row.lock_until && new Date(row.lock_until) > now) return;

  const firstFailedAt = row.first_failed_at ? new Date(row.first_failed_at) : null;
  const withinWindow =
    firstFailedAt && (now - firstFailedAt) <= (LOCK_WINDOW_MIN * 60 * 1000);

  const nextCount = withinWindow ? (row.failed_count + 1) : 1;
  const nextFirstFailedAt = withinWindow ? firstFailedAt : now;

  let lockUntil = null;
  if (nextCount >= LOCK_THRESHOLD) {
    lockUntil = new Date(now.getTime() + LOCK_DURATION_MIN * 60 * 1000);
  }

  await pool.execute(
    `UPDATE login_attempts
     SET failed_count = ?,
         first_failed_at = ?,
         last_failed_at = ?,
         lock_until = ?
     WHERE email = ?`,
    [nextCount, nextFirstFailedAt, now, lockUntil, email]
  );
}

async function clearLoginAttempts(email) {
  await pool.execute(`DELETE FROM login_attempts WHERE email = ?`, [email]);
}

// ========================================
// CLEANUP JOB (email attempts table)
// Uses last_failed_at so you don't need an updated_at column
// ========================================
const CLEANUP_EVERY_HOURS = 6;
const RETENTION_DAYS = 7;

async function cleanupLoginAttempts() {
  try {
    const [result] = await pool.execute(
      `DELETE FROM login_attempts
       WHERE last_failed_at < (NOW() - INTERVAL ? DAY)`,
      [RETENTION_DAYS]
    );

    console.log(`[CLEANUP] login_attempts: removed ${result.affectedRows || 0} old rows`);
  } catch (err) {
    console.error("[CLEANUP] login_attempts cleanup error:", err.message);
  }
}


// ========================================
// ADMIN SECURITY (timeout + CSRF + logging)
// ========================================

const ADMIN_IDLE_TIMEOUT_SEC = Number(process.env.ADMIN_IDLE_TIMEOUT_SEC || 30 * 60); // 30 minutes

function ensureLogDir() {
  const logDir = path.join(__dirname, "logs");
  if (!fs.existsSync(logDir)) fs.mkdirSync(logDir, { recursive: true });
  return logDir;
}

function adminLog(level, message, context = {}) {
  try {
    const logDir = ensureLogDir();
    const ts = new Date().toISOString();
    const file = path.join(logDir, `admin_${ts.slice(0, 10)}.log`);
    const line = `[${ts}] [${level}] ${message} ${JSON.stringify(context)}\n`;
    fs.appendFileSync(file, line);
  } catch (_) {}
}

// Admin idle timeout middleware
function adminSessionTimeout(req, res, next) {
  const p = req.path || "";
  const isAdminPath = p.startsWith("/admin") || p.startsWith("/api/admin");
  if (!isAdminPath) return next();

  if (!req.session || !req.session.admin) return next();

  const now = Date.now();
  const last = req.session.admin_last_activity || now;
  const elapsedSec = Math.floor((now - last) / 1000);

  if (elapsedSec > ADMIN_IDLE_TIMEOUT_SEC) {
    adminLog("INFO", "Admin session timed out", {
      ip: req.ip,
      adminEmail: req.session?.admin?.email,
      idleSeconds: elapsedSec,
    });

    req.session.destroy(() => {
      res.clearCookie("sg_admin_sid");
      return res.redirect("/login");
    });
    return;
  }

  req.session.admin_last_activity = now;
  next();
}

app.use(adminSessionTimeout);

// CSRF helpers
function ensureCsrfToken(req) {
  if (!req.session) return "";
  if (!req.session.csrf_token) {
    req.session.csrf_token = crypto.randomBytes(32).toString("hex");
  }
  return req.session.csrf_token;
}

// Admin CSRF endpoint
app.get("/api/admin/csrf", requireAdmin, (req, res) => {
  const token = ensureCsrfToken(req);
  return res.json({ csrfToken: token });
});

// CSRF validation middleware (admin POST only)
function requireCsrf(req, res, next) {
  if (!["POST", "PUT", "PATCH", "DELETE"].includes(req.method)) return next();
  if (!(req.path || "").startsWith("/api/admin")) return next();

  const token = req.headers["x-csrf-token"] || req.body.csrf_token;
  const sessionToken = req.session?.csrf_token;

  if (!token || !sessionToken) {
    return res.status(403).json({ error: "CSRF validation failed" });
  }

  const a = String(token);
  const b = String(sessionToken);

  const ok =
    a.length === b.length &&
    crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));

  if (!ok) return res.status(403).json({ error: "CSRF validation failed" });

  next();
}

app.use(requireCsrf);

// ========================================
// ADMIN-ONLY ACTIONS (MySQL-backed)
// ========================================

function toIntOrNull(v) {
  if (v === undefined || v === null || v === "") return null;
  const n = Number(v);
  if (!Number.isFinite(n)) return null;
  return Math.trunc(n);
}

// ---- Announcements ----
app.get("/api/admin/announcements", requireAdmin, async (req, res) => {
  try {
    const [rows] = await pool.execute(
      `SELECT id, message, created_at
       FROM admin_announcements
       ORDER BY id DESC
       LIMIT 25`
    );
    return res.json({ announcements: rows });
  } catch (err) {
    console.error("[ADMIN] announcements list error:", err);
    return res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/admin/announcements", requireAdmin, async (req, res) => {
  try {
    if (typeof req.body.message !== "string") {
      return res.status(400).json({ error: "Message required" });
    }

    const message = req.body.message.trim();
    if (!message || message.length > 2000) {
      return res.status(400).json({ error: "Message required (max 2000 chars)" });
    }

    await pool.execute(
      `INSERT INTO admin_announcements (message) VALUES (?)`,
      [message]
    );

    adminLog("INFO", "Announcement created", {
      ip: req.ip,
      adminEmail: req.session?.admin?.email,
      length: message.length,
    });

    return res.json({ message: "Announcement saved" });
  } catch (err) {
    console.error("[ADMIN] announcements create error:", err);
    return res.status(500).json({ error: "Server error" });
  }
});

// ---- Notes ----
app.get("/api/admin/notes", requireAdmin, async (req, res) => {
  try {
    const [rows] = await pool.execute(
      `SELECT id, note, created_at
       FROM admin_notes
       ORDER BY id DESC
       LIMIT 25`
    );
    return res.json({ notes: rows });
  } catch (err) {
    console.error("[ADMIN] notes list error:", err);
    return res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/admin/notes", requireAdmin, async (req, res) => {
  try {
    if (typeof req.body.note !== "string") {
      return res.status(400).json({ error: "Note required" });
    }

    const note = req.body.note.trim();
    if (!note || note.length > 2000) {
      return res.status(400).json({ error: "Note required (max 2000 chars)" });
    }

    await pool.execute(
      `INSERT INTO admin_notes (note) VALUES (?)`,
      [note]
    );

    adminLog("INFO", "Kitchen note created", {
      ip: req.ip,
      adminEmail: req.session?.admin?.email,
      length: note.length,
    });

    return res.json({ message: "Note saved" });
  } catch (err) {
    console.error("[ADMIN] notes create error:", err);
    return res.status(500).json({ error: "Server error" });
  }
});

// ---- Settings ----
app.get("/api/admin/settings", requireAdmin, async (req, res) => {
  try {
    const [rows] = await pool.execute(
      `SELECT id, max_reservations_per_slot, preparation_time_minutes, updated_at
       FROM admin_settings
       WHERE id = 1
       LIMIT 1`
    );

    if (rows.length === 0) {
      await pool.execute(
        `INSERT INTO admin_settings (id, max_reservations_per_slot, preparation_time_minutes)
         VALUES (1, 20, 15)`
      );
      return res.json({
        settings: { id: 1, max_reservations_per_slot: 20, preparation_time_minutes: 15 },
      });
    }

    return res.json({ settings: rows[0] });
  } catch (err) {
    console.error("[ADMIN] settings get error:", err);
    return res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/admin/settings", requireAdmin, async (req, res) => {
  try {
    const maxRes = toIntOrNull(req.body.max_reservations_per_slot);
    const prepMin = toIntOrNull(req.body.preparation_time_minutes);

    if (maxRes === null || prepMin === null) {
      return res.status(400).json({ error: "Both numeric fields are required" });
    }
    if (maxRes < 1 || maxRes > 500) {
      return res.status(400).json({ error: "max_reservations_per_slot must be 1..500" });
    }
    if (prepMin < 1 || prepMin > 480) {
      return res.status(400).json({ error: "preparation_time_minutes must be 1..480" });
    }

    await pool.execute(
      `UPDATE admin_settings
       SET max_reservations_per_slot = ?,
           preparation_time_minutes = ?
       WHERE id = 1`,
      [maxRes, prepMin]
    );

    adminLog("INFO", "Admin settings updated", {
      ip: req.ip,
      adminEmail: req.session?.admin?.email,
      max_reservations_per_slot: maxRes,
      preparation_time_minutes: prepMin,
    });

    return res.json({ message: "Settings updated" });
  } catch (err) {
    console.error("[ADMIN] settings update error:", err);
    return res.status(500).json({ error: "Server error" });
  }
});

// ========================================
// ADMIN GUARD (session-based)
// ========================================
function requireAdmin(req, res, next) {
  if (!req.session || !req.session.admin) {
    return res.redirect("/login"); // unified login
  }
  next();
}

/// ========================================
// ADMIN-ONLY ACTIONS (MySQL-backed)
// 1) Announcements (TEXT save + display)
// 2) Kitchen Notes (TEXT save + display)
// 3) Settings (NUMERIC inputs: max reservations + prep time)
// ========================================

console.log("✅ Registering admin-only action routes...");

function toIntOrNull(v) {
  if (v === undefined || v === null || v === "") return null;
  const n = Number(v);
  if (!Number.isFinite(n)) return null;
  return Math.trunc(n);
}

// ---- Announcements (TEXT) ----
app.get("/api/admin/announcements", requireAdmin, async (req, res) => {
  try {
    const [rows] = await pool.execute(
      `SELECT id, message, created_at
       FROM admin_announcements
       ORDER BY id DESC
       LIMIT 25`
    );
    return res.json({ announcements: rows });
  } catch (err) {
    console.error("[ADMIN] announcements list error:", err);
    return res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/admin/announcements", requireAdmin, async (req, res) => {
  try {
    const message = String(req.body.message || "").trim();
    if (!message || message.length > 2000) {
      return res.status(400).json({ error: "Message required (max 2000 chars)" });
    }

    await pool.execute(
      `INSERT INTO admin_announcements (message) VALUES (?)`,
      [message]
    );

    return res.json({ message: "Announcement saved" });
  } catch (err) {
    console.error("[ADMIN] announcements create error:", err);
    return res.status(500).json({ error: "Server error" });
  }
});

// ---- Notes (TEXT) ----
app.get("/api/admin/notes", requireAdmin, async (req, res) => {
  try {
    const [rows] = await pool.execute(
      `SELECT id, note, created_at
       FROM admin_notes
       ORDER BY id DESC
       LIMIT 25`
    );
    return res.json({ notes: rows });
  } catch (err) {
    console.error("[ADMIN] notes list error:", err);
    return res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/admin/notes", requireAdmin, async (req, res) => {
  try {
    const note = String(req.body.note || "").trim();
    if (!note || note.length > 2000) {
      return res.status(400).json({ error: "Note required (max 2000 chars)" });
    }

    await pool.execute(
      `INSERT INTO admin_notes (note) VALUES (?)`,
      [note]
    );

    return res.json({ message: "Note saved" });
  } catch (err) {
    console.error("[ADMIN] notes create error:", err);
    return res.status(500).json({ error: "Server error" });
  }
});

// ---- Settings (NUMERIC) ----
app.get("/api/admin/settings", requireAdmin, async (req, res) => {
  try {
    const [rows] = await pool.execute(
      `SELECT id, max_reservations_per_slot, preparation_time_minutes, updated_at
       FROM admin_settings
       WHERE id = 1
       LIMIT 1`
    );

    // Defensive: create row if missing
    if (rows.length === 0) {
      await pool.execute(
        `INSERT INTO admin_settings (id, max_reservations_per_slot, preparation_time_minutes)
         VALUES (1, 20, 15)`
      );
      return res.json({
        settings: {
          id: 1,
          max_reservations_per_slot: 20,
          preparation_time_minutes: 15,
        },
      });
    }

    return res.json({ settings: rows[0] });
  } catch (err) {
    console.error("[ADMIN] settings get error:", err);
    return res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/admin/settings", requireAdmin, async (req, res) => {
  try {
    const maxRes = toIntOrNull(req.body.max_reservations_per_slot);
    const prepMin = toIntOrNull(req.body.preparation_time_minutes);

    if (maxRes === null || prepMin === null) {
      return res.status(400).json({ error: "Both numeric fields are required" });
    }
    if (maxRes < 1 || maxRes > 500) {
      return res.status(400).json({ error: "max_reservations_per_slot must be 1..500" });
    }
    if (prepMin < 1 || prepMin > 480) {
      return res.status(400).json({ error: "preparation_time_minutes must be 1..480" });
    }

    await pool.execute(
      `UPDATE admin_settings
       SET max_reservations_per_slot = ?,
           preparation_time_minutes = ?
       WHERE id = 1`,
      [maxRes, prepMin]
    );

    return res.json({ message: "Settings updated" });
  } catch (err) {
    console.error("[ADMIN] settings update error:", err);
    return res.status(500).json({ error: "Server error" });
  }
});

/* ------------------ PAGES ------------------ */
app.get("/", (req, res) => res.sendFile(path.join(__dirname, "views", "home.html")));
app.get("/register", (req, res) => res.sendFile(path.join(__dirname, "views", "register.html")));
app.get("/login", (req, res) => res.sendFile(path.join(__dirname, "views", "login.html")));
app.get("/home", (req, res) => res.sendFile(path.join(__dirname, "views", "home.html")));
app.get("/welcome", (req, res) => res.sendFile(path.join(__dirname, "views", "welcome.html")));

// Admin dashboard (protected)
app.get("/admin/dashboard", requireAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, "views", "admin-dashboard.html"));
});

// Optional admin helpers
app.get("/api/admin/me", (req, res) => {
  if (!req.session || !req.session.admin) return res.status(401).json({ error: "Not logged in" });
  return res.json({ admin: req.session.admin });
});

app.post("/api/admin/logout", (req, res) => {
  req.session.destroy(() => {
    res.clearCookie("sg_admin_sid");
    return res.json({ message: "Logged out" });
  });
});

app.get("/branches", (req, res) => res.send("Branches page UI next"));
app.get("/menu", (req, res) => res.send("Menu/Order UI next"));
app.get("/reserve", (req, res) => res.send("Reserve UI next"));
app.get("/track", (req, res) => res.send("Track UI next"));

/* ------------------ EMAIL VERIFICATION ------------------ */
app.get("/test-email", async (req, res) => {
  try {
    await verifyTransporter();
    res.send("✅ SMTP OK (transporter verified).");
  } catch (e) {
    console.error("SMTP test failed:", e);
    res.status(500).send("❌ SMTP test failed: " + e.message);
  }
});

app.get("/verify-email", async (req, res) => {
  try {
    const email = (req.query.email || "").toString().trim().toLowerCase();
    const token = (req.query.token || "").toString().trim();

    if (!email || !token) {
      return res.status(400).send("Invalid verification link.");
    }

    const tokenHash = crypto.createHash("sha256").update(token).digest("hex");

    const [rows] = await pool.execute(
      `SELECT id, is_verified, verify_token_expires
       FROM users
       WHERE email = ? AND verify_token_hash = ?
       LIMIT 1`,
      [email, tokenHash]
    );

    if (rows.length === 0) {
      return res.status(400).send("Invalid or expired verification link.");
    }

    const user = rows[0];

    // Already verified
    if (user.is_verified === 1) {
      return res.redirect("/login?verified=1");
    }

    // Expired?
    if (user.verify_token_expires && new Date(user.verify_token_expires) < new Date()) {
      return res.status(400).send("Verification link expired. Please register again.");
    }

    // Verify user
    await pool.execute(
      `UPDATE users
       SET is_verified = 1, verify_token_hash = NULL, verify_token_expires = NULL
       WHERE id = ?`,
      [user.id]
    );

    return res.redirect("/login?verified=1");
  } catch (err) {
    console.error("Verify email error:", err.message);
    return res.status(500).send("Server error");
  }
});

/* ------------------ REGISTER ------------------ */
app.post("/register", upload.single("photo"), async (req, res) => {
  try {
    const { full_name, email, phone, password, confirm_password } = req.body;

    // ✅ CAPTCHA token from Google
    const captchaToken = req.body["g-recaptcha-response"];

    // ✅ Verify CAPTCHA server-side (IMPORTANT)
    const captchaOk = await verifyRecaptchaV2(captchaToken, req.ip);
    if (!captchaOk) {
      console.warn("[REGISTER] CAPTCHA failed for IP:", req.ip);
      return res.redirect("/register?error=1");
    }

    // required fields
    if (!full_name || !email || !phone || !password || !confirm_password) {
      return res.redirect("/register?error=1");
    }

    if (!isValidEmail(email)) return res.redirect("/register?error=1");
    if (password !== confirm_password) return res.redirect("/register?error=1");
    if (!isStrongPassword(password)) return res.redirect("/register?error=1");
    if (!req.file) return res.redirect("/register?error=1");

    const cleanName = full_name.trim();
    const cleanEmail = email.toLowerCase().trim();
    const cleanPhone = phone.trim();

    const photo_path = "/public/uploads/" + req.file.filename;

    // hash password
    const password_hash = await bcrypt.hash(password, 12);

    // verification token
    const { rawToken, tokenHash } = makeVerificationToken();
    const expires = new Date(Date.now() + 30 * 60 * 1000);

    // Insert user as NOT verified
    await pool.execute(
      `INSERT INTO users
        (full_name, email, phone, password_hash, photo_path, is_verified, verify_token_hash, verify_token_expires)
       VALUES
        (?, ?, ?, ?, ?, 0, ?, ?)`,
      [cleanName, cleanEmail, cleanPhone, password_hash, photo_path, tokenHash, expires]
    );

    // Send verification email (don’t crash registration if SMTP fails)
    const baseUrl = (process.env.APP_BASE_URL || `http://localhost:${PORT}`).replace(/\/$/, "");
    const verifyUrl = `${baseUrl}/verify-email?email=${encodeURIComponent(cleanEmail)}&token=${rawToken}`;

    try {
      await sendVerificationEmail({ toEmail: cleanEmail, fullName: cleanName, verifyUrl });
      return res.redirect("/login?verify=1");
    } catch (mailErr) {
      console.error("Email send failed:", mailErr?.message || mailErr);
      // Account exists but email couldn’t be sent
      return res.redirect("/login?verify=0");
    }

  } catch (err) {
    // 🔐 SECURITY: log real error server-side only
    if (err.code === "ER_DUP_ENTRY") {
      console.warn(`[REGISTER] Duplicate email attempt: ${req.body.email}`);
    } else {
      console.error("[REGISTER] Unexpected error:", err);
    }

    // 🔐 USER SEES ONLY GENERIC ERROR
    return res.redirect("/register?error=1");
  }
});

/* ------------------ LOGIN API (UNIFIED) ------------------ */
app.post("/api/login", loginLimiter, async (req, res) => {
  try {
    let { email, password, captchaToken } = req.body;

    // INPUT VALIDATION
    if (!email || !password) {
      return res.status(400).json({ error: "Invalid input" });
    }

    email = email.trim().toLowerCase();
    password = password.trim();

    if (!isValidEmail(email)) return res.status(400).json({ error: "Invalid input" });
    if (password.length < 8 || password.length > 128) return res.status(400).json({ error: "Invalid input" });

    // ✅ CAPTCHA REQUIRED EVERY LOGIN
    const captchaOk = await verifyRecaptchaV2(captchaToken, req.ip);
    if (!captchaOk) {
      return res.status(400).json({ error: "CAPTCHA verification failed" });
    }

    // ✅ EMAIL LOCK CHECK
    if (await isEmailLocked(email)) {
      return res.status(423).json({
        error: "Account temporarily locked due to too many failed attempts. Please try again later.",
      });
    }

    // ✅ include role
    const [rows] = await pool.execute(
      `SELECT
         id AS user_id,
         full_name,
         email,
         phone,
         photo_path,
         password_hash,
         is_verified,
         role
       FROM users
       WHERE email = ?
       LIMIT 1`,
      [email]
    );

    // Generic response (but still record failure)
    if (rows.length === 0) {
      await recordFailedAttempt(email);
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const user = rows[0];

    // Block login if not verified
    if (user.is_verified !== 1) {
      // counts as a failure too
      await recordFailedAttempt(email);
      return res.status(403).json({ error: "Please verify your email before logging in." });
    }

    const passwordMatch = await bcrypt.compare(password, user.password_hash);

    if (!passwordMatch) {
      await recordFailedAttempt(email);
      return res.status(401).json({ error: "Invalid credentials" });
    }

    // ✅ SUCCESS: clear attempts
    await clearLoginAttempts(email);

    // ✅ ADMIN: create session and redirect to admin dashboard
    if (user.role === "admin") {
      req.session.admin = {
        user_id: user.user_id,
        full_name: user.full_name,
        email: user.email,
        role: user.role,
      };

      return res.json({
        message: "Admin login successful",
        redirectTo: "/admin/dashboard",
      });
    }

    // ✅ NORMAL USER
    return res.json({
      message: "Login successful",
      user: {
        user_id: user.user_id,
        full_name: user.full_name,
        email: user.email,
        phone: user.phone,
        photo_path: user.photo_path,
      },
    });
  } catch (err) {
    console.error("Login error:", err.message);
    return res.status(500).json({ error: "Server error" });
  }
});

// Optional: stricter rate limit just for admin login
const adminLoginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { error: "Too many admin login attempts. Please try again later." },
  standardHeaders: true,
  legacyHeaders: false,
});

app.post("/api/admin/login", adminLoginLimiter, async (req, res) => {
  try {
    let { email, password, captchaToken } = req.body;

    if (!email || !password) return res.status(400).json({ error: "Invalid input" });

    email = email.trim().toLowerCase();
    password = password.trim();

    if (!isValidEmail(email)) return res.status(400).json({ error: "Invalid input" });
    if (password.length < 8 || password.length > 128) return res.status(400).json({ error: "Invalid input" });

    // ✅ CAPTCHA REQUIRED (since you chose every login)
    const captchaOk = await verifyRecaptchaV2(captchaToken, req.ip);
    if (!captchaOk) {
      return res.status(400).json({ error: "CAPTCHA verification failed" });
    }

    // ✅ Email lock still applies
    if (await isEmailLocked(email)) {
      return res.status(423).json({ error: "Account temporarily locked. Please try again later." });
    }

    const [rows] = await pool.execute(
      `SELECT id, full_name, email, password_hash, is_verified, role
       FROM users
       WHERE email = ?
       LIMIT 1`,
      [email]
    );

    // Generic failure
    if (rows.length === 0) {
      await recordFailedAttempt(email);
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const user = rows[0];

    // Must be admin
    if (user.role !== "admin") {
      await recordFailedAttempt(email);
      return res.status(403).json({ error: "Access denied" });
    }

    if (user.is_verified !== 1) {
      await recordFailedAttempt(email);
      return res.status(403).json({ error: "Please verify your email before logging in." });
    }

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) {
      await recordFailedAttempt(email);
      return res.status(401).json({ error: "Invalid credentials" });
    }

    await clearLoginAttempts(email);

    // ✅ Create admin session
    req.session.admin = {
      user_id: user.id,
      full_name: user.full_name,
      email: user.email,
      role: user.role,
    };

    return res.json({ message: "Admin login successful" });
  } catch (err) {
    console.error("Admin login error:", err.message);
    return res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/admin/logout", (req, res) => {
  req.session.destroy(() => {
    res.clearCookie("sg_admin_sid");
    return res.json({ message: "Logged out" });
  });
});

app.get("/api/admin/me", (req, res) => {
  if (!req.session || !req.session.admin) return res.status(401).json({ error: "Not logged in" });
  return res.json({ admin: req.session.admin });
});

/* ------------------ START ------------------ */
app.listen(PORT, () => {
  console.log(`✅ Server running at http://localhost:${PORT}`);
  console.log(`📝 Register: http://localhost:${PORT}/register`);
  console.log(`🔐 Login: http://localhost:${PORT}/login`);
  console.log(`🛡 Admin dashboard: http://localhost:${PORT}/admin/dashboard`);

  // cleanup at startup + every few hours
  cleanupLoginAttempts();
  setInterval(cleanupLoginAttempts, CLEANUP_EVERY_HOURS * 60 * 60 * 1000);
});
