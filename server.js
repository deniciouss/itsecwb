console.log("SERVER FILE LOADED:", __filename);
// server.js

const express = require("express");
const path = require("path");
require("dotenv").config({ path: path.join(__dirname, ".env.local") });

const multer = require("multer");
const pool = require("./db"); // mysql2/promise pool
const fs = require("fs");
const bcrypt = require("bcryptjs");
const rateLimit = require("express-rate-limit");
const crypto = require("crypto");
const https = require("https");
const { sendVerificationEmail, verifyTransporter } = require("./mailer");

// Sessions (ADMIN / USER)
const session = require("express-session");
const mysql2 = require("mysql2");
const MySQLStore = require("express-mysql-session")(session);

const app = express();
const PORT = process.env.PORT || 3000;
const DEBUG_ERRORS = process.env.DEBUG_ERRORS === "true";
const USE_HTTPS = process.env.USE_HTTPS === "true";
const SESSION_IDLE_MINUTES = Number(process.env.SESSION_IDLE_MINUTES || 30);

const HTTPS_KEY_PATH =
  process.env.HTTPS_KEY_PATH || path.join(__dirname, "certs", "localhost-key.pem");

const HTTPS_CERT_PATH =
  process.env.HTTPS_CERT_PATH || path.join(__dirname, "certs", "localhost.pem");

const HTTPS_PFX_PATH =
  process.env.HTTPS_PFX_PATH || path.join(__dirname, "certs", "localhost.pfx");

const HTTPS_PFX_PASSWORD = process.env.HTTPS_PFX_PASSWORD || "";

// fetch support
const fetchFn = global.fetch
  ? global.fetch
  : (...args) => import("node-fetch").then(({ default: fetch }) => fetch(...args));

app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use("/public", express.static(path.join(__dirname, "public")));

app.disable("x-powered-by");
app.set("trust proxy", 1);

// Basic security headers
app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  next();
});

// Block logs folder
app.use("/logs", (req, res) => {
  return res.status(403).send("Forbidden");
});

// Prevent cache on protected/auth pages
app.use((req, res, next) => {
  const noStorePaths = new Set([
    "/login",
    "/register",
    "/welcome",
    "/reserve",
    "/track",
    "/order"
  ]);

  if (
    noStorePaths.has(req.path) ||
    req.path.startsWith("/admin/") ||
    req.path.startsWith("/order/")
  ) {
    res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, private");
    res.setHeader("Pragma", "no-cache");
    res.setHeader("Expires", "0");
  }
  next();
});

// ========================================
// LOGGING
// ========================================
const logsDir = path.join(__dirname, "logs");
if (!fs.existsSync(logsDir)) {
  fs.mkdirSync(logsDir, { recursive: true });
}

// --- Syslog setup ---
const syslog = require("syslog-client");
let syslogClient = null;
if (process.env.SYSLOG_HOST) {
  syslogClient = syslog.createClient(process.env.SYSLOG_HOST, {
    port: Number(process.env.SYSLOG_PORT) || 514,
    transport:
      (process.env.SYSLOG_PROTOCOL || "udp").toLowerCase() === "tcp"
        ? syslog.Transport.Tcp
        : syslog.Transport.Udp,
    facility: Number(process.env.SYSLOG_FACILITY) || syslog.Facility.Local0,
    appName: process.env.SYSLOG_APP_NAME || "itsecwb",
  });
  console.log(`[SYSLOG] Forwarding to ${process.env.SYSLOG_HOST}:${process.env.SYSLOG_PORT || 514}`);
}

function sendSyslog(severity, message) {
  if (!syslogClient) return;
  syslogClient.log(message, { severity }, (err) => {
    if (err) console.error("[SYSLOG] forward failed:", err.message);
  });
}

function sendLoggly(message) {
  if (!process.env.LOGGLY_URL || !process.env.LOGGLY_TOKEN) return;
  fetchFn(process.env.LOGGLY_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/octet-stream",
      "Authorization": `Bearer ${process.env.LOGGLY_TOKEN}`,
    },
    body: message,
  }).catch((err) => console.error("[LOGGLY] forward failed:", err.message));
}

function audit(event, details = {}) {
  const safe = { ...details };

  delete safe.password;
  delete safe.confirm_password;
  delete safe.rawToken;
  delete safe.token;
  delete safe.password_hash;
  delete safe.verify_token_hash;

  const ts = new Date().toISOString();

  // 1. File
  const filename = path.join(logsDir, `app-${ts.slice(0, 10)}.log`);
  const line = JSON.stringify({ ts, event, ...safe }) + "\n";
  fs.appendFile(filename, line, (err) => {
    if (err) console.error("[AUDIT] write failed:", err.message);
  });

  // 2. DB
  pool.execute(
    "INSERT INTO audit_logs (ts, event, user_id, email, ip, details) VALUES (?, ?, ?, ?, ?, ?)",
    [
      new Date(),
      event,
      safe.userId ?? safe.user_id ?? null,
      safe.email ?? null,
      safe.ip ?? null,
      JSON.stringify(safe),
    ]
  ).catch((err) => console.error("[AUDIT] db insert failed:", err.message));

  // 3. Syslog + Loggly
  const auditMsg = `AUDIT ${event} ${JSON.stringify(safe)}`;
  sendSyslog(syslog.Severity.Informational, auditMsg);
  sendLoggly(auditMsg);
}

function ensureLogDir() {
  const logDir = path.join(__dirname, "logs");
  if (!fs.existsSync(logDir)) fs.mkdirSync(logDir, { recursive: true });
  return logDir;
}

function adminLog(level, message, context = {}) {
  const ts = new Date().toISOString();

  // 1. File
  try {
    const logDir = ensureLogDir();
    const file = path.join(logDir, `admin_${ts.slice(0, 10)}.log`);
    const line = `[${ts}] [${level}] ${message} ${JSON.stringify(context)}\n`;
    fs.appendFileSync(file, line);
  } catch (_) {}

  // 2. DB
  pool.execute(
    "INSERT INTO audit_logs (ts, event, user_id, email, ip, details) VALUES (?, ?, ?, ?, ?, ?)",
    [
      new Date(),
      `admin.${level.toLowerCase()}`,
      context.userId ?? context.user_id ?? null,
      context.email ?? context.adminEmail ?? null,
      context.ip ?? null,
      JSON.stringify({ message, ...context }),
    ]
  ).catch((err) => console.error("[ADMIN_LOG] db insert failed:", err.message));

  // 3. Syslog + Loggly
  const severity =
    level === "ERROR" ? syslog.Severity.Error
    : level === "WARN"  ? syslog.Severity.Warning
    : syslog.Severity.Informational;
  const adminMsg = `ADMIN [${level}] ${message} ${JSON.stringify(context)}`;
  sendSyslog(severity, adminMsg);
  sendLoggly(adminMsg);
}

function sendDebugOrGenericError(res, err, genericMessage = "Server error", status = 500) {
  if (DEBUG_ERRORS) {
    return res
      .status(status)
      .type("text/plain")
      .send(err && err.stack ? err.stack : String(err || genericMessage));
  }
  return res.status(status).send(genericMessage);
}

function sendApiDebugOrGenericError(res, err, genericMessage = "Server error", status = 500) {
  if (DEBUG_ERRORS) {
    return res.status(status).json({
      error: err.message || genericMessage,
      stack: err.stack || String(err),
    });
  }
  return res.status(status).json({ error: genericMessage });
}

function sendAdminApiError(res, err, genericMessage = "Server error", status = 500) {
  if (DEBUG_ERRORS) {
    return res.status(status).json({
      error: err && err.message ? err.message : genericMessage,
      stack: err && err.stack ? err.stack : String(err || genericMessage),
    });
  }

  return res.status(status).json({ error: genericMessage });
}

// ========================================
// SESSION STORE
// ========================================
const DB_HOST = process.env.DB_HOST || "localhost";
const DB_USER = process.env.DB_USER || "samgyup_user";
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

const SESSION_IDLE_MS = SESSION_IDLE_MINUTES * 60 * 1000;

const sessionStore = new MySQLStore(
  {
    clearExpired: true,
    checkExpirationInterval: 15 * 60 * 1000,
    expiration: SESSION_IDLE_MS,
  },
  sessionDbPool
);

app.use(
  session({
    name: "id",
    secret: process.env.SESSION_SECRET || "change-this-in-env",
    store: sessionStore,
    resave: false,
    saveUninitialized: false,
    rolling: true,
    unset: "destroy",
    proxy: true,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: USE_HTTPS,
      maxAge: SESSION_IDLE_MS,
      path: "/",
    },
  })
);

// ========================================
// REGISTER FILE UPLOAD
// ========================================
const uploadsDir = path.join(__dirname, "public", "uploads");
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
  console.log("✅ Created uploads directory at:", uploadsDir);
} else {
  console.log("✅ Uploads directory exists at:", uploadsDir);
}

const ALLOWED_IMAGE_MIME = new Set(["image/jpeg", "image/png", "image/webp"]);
const MAX_PROFILE_PHOTO_BYTES = 2 * 1024 * 1024;

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadsDir),
  filename: (req, file, cb) => {
    const randomName = `${Date.now()}_${crypto.randomBytes(16).toString("hex")}`;
    cb(null, randomName);
  },
});

const rawRegisterUpload = multer({
  storage,
  limits: {
    fileSize: MAX_PROFILE_PHOTO_BYTES,
    files: 1,
  },
  fileFilter: (req, file, cb) => {
    if (!ALLOWED_IMAGE_MIME.has(file.mimetype)) {
      return cb(new Error("INVALID_UPLOAD_TYPE"));
    }
    cb(null, true);
  },
});

const registerUpload = (req, res, next) => {
  rawRegisterUpload.single("photo")(req, res, (err) => {
    if (!err) return next();

    if (err instanceof multer.MulterError) {
      console.warn("[REGISTER] Multer error:", err.code, err.message);
    } else {
      console.warn("[REGISTER] Upload rejected:", err.message);
    }

    return res.redirect("/register?error=1");
  });
};

// ========================================
// RATE LIMITING
// ========================================
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 500,
  message: { error: "Too many login attempts. Please try again in 15 minutes." },
  standardHeaders: true,
  legacyHeaders: false,
});

const registerLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    return res.redirect("/register?error=1");
  },
});

const adminLoginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { error: "Too many admin login attempts. Please try again later." },
  standardHeaders: true,
  legacyHeaders: false,
});

// ========================================
// VALIDATION HELPERS
// ========================================
function splitEmailParts(email) {
  const cleanEmail = (email || "").trim();

  if (!cleanEmail || cleanEmail.length > 254) return null;

  const firstAt = cleanEmail.indexOf("@");
  const lastAt = cleanEmail.lastIndexOf("@");

  if (firstAt <= 0 || firstAt !== lastAt) return null;

  const localPart = cleanEmail.slice(0, firstAt);
  const domainPart = cleanEmail.slice(firstAt + 1);

  if (!localPart || !domainPart) return null;
  if (localPart.length > 64) return null;
  if (domainPart.length > 255) return null;

  return { cleanEmail, localPart, domainPart };
}

function isValidEmail(email) {
  const parts = splitEmailParts(email);
  if (!parts) return false;

  const { localPart, domainPart } = parts;

  const localRegex = /^(?!.*\.\.)[A-Za-z0-9](?:[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{0,62}[A-Za-z0-9])?$/;
  const domainRegex = /^(?=.{1,255}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])$/;

  return localRegex.test(localPart) && domainRegex.test(domainPart);
}

function isValidPHPhone(phone) {
  return /^09\d{9}$/.test((phone || "").trim());
}

function isStrongPassword(pw) {
  if (!pw || pw.length < 8) return false;
  if (Buffer.byteLength(pw, "utf8") > 72) return false;
  if (!/[A-Z]/.test(pw)) return false;
  if (!/[a-z]/.test(pw)) return false;
  if (!/[0-9]/.test(pw)) return false;
  if (!/[^A-Za-z0-9]/.test(pw)) return false;
  return true;
}

function safeUnlink(filePath) {
  try {
    if (filePath && fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
    }
  } catch (err) {
    console.warn("[REGISTER] Failed to delete file:", err.message);
  }
}

function detectImageMimeFromMagic(filePath) {
  const fd = fs.openSync(filePath, "r");
  const buffer = Buffer.alloc(12);

  try {
    fs.readSync(fd, buffer, 0, 12, 0);
  } finally {
    fs.closeSync(fd);
  }

  if (buffer[0] === 0xff && buffer[1] === 0xd8 && buffer[2] === 0xff) {
    return "image/jpeg";
  }

  if (
    buffer[0] === 0x89 &&
    buffer[1] === 0x50 &&
    buffer[2] === 0x4e &&
    buffer[3] === 0x47 &&
    buffer[4] === 0x0d &&
    buffer[5] === 0x0a &&
    buffer[6] === 0x1a &&
    buffer[7] === 0x0a
  ) {
    return "image/png";
  }

  if (
    buffer.toString("ascii", 0, 4) === "RIFF" &&
    buffer.toString("ascii", 8, 12) === "WEBP"
  ) {
    return "image/webp";
  }

  return null;
}

function mimeToSafeExtension(mime) {
  switch (mime) {
    case "image/jpeg":
      return ".jpg";
    case "image/png":
      return ".png";
    case "image/webp":
      return ".webp";
    default:
      return null;
  }
}

function makeVerificationToken() {
  const rawToken = crypto.randomBytes(32).toString("hex");
  const tokenHash = crypto.createHash("sha256").update(rawToken).digest("hex");
  return { rawToken, tokenHash };
}

function toIntOrNull(v) {
  if (v === undefined || v === null || v === "") return null;
  const n = Number(v);
  if (!Number.isFinite(n)) return null;
  return Math.trunc(n);
}

function isValidOrderText(value) {
  if (typeof value !== "string") return false;
  const clean = value.trim();
  return clean.length >= 1 && clean.length <= 255;
}

// ========================================
// CUSTOMER RESERVATION HELPERS
// ========================================
const TABLES_PER_BRANCH = 20;
const SEATS_PER_TABLE = 4;
const RESERVATION_DURATION_HOURS = 2;
const OPENING_HOUR = 11;
const CLOSING_HOUR = 20;

function normalizeTimeHHMM(value) {
  const match = String(value || "").match(/^(\d{2}):(\d{2})/);
  if (!match) return null;
  return `${match[1]}:${match[2]}`;
}

function isValidReservationText(value, maxLen = 300) {
  if (value == null) return true;
  if (typeof value !== "string") return false;
  return value.trim().length <= maxLen;
}

function isValidReservationDate(value) {
  return /^\d{4}-\d{2}-\d{2}$/.test(String(value || ""));
}

function isValidReservationTime(value) {
  const hhmm = normalizeTimeHHMM(value);
  return !!hhmm && /^([01]\d|2[0-3]):[0-5]\d$/.test(hhmm);
}

function timeToMinutes(value) {
  const hhmm = normalizeTimeHHMM(value);
  if (!hhmm) return null;
  const [h, m] = hhmm.split(":").map(Number);
  return h * 60 + m;
}

function minutesToHHMM(totalMinutes) {
  const h = Math.floor(totalMinutes / 60);
  const m = totalMinutes % 60;
  return `${String(h).padStart(2, "0")}:${String(m).padStart(2, "0")}`;
}

function addHoursToTime(value, hours) {
  const mins = timeToMinutes(value);
  if (mins === null) return null;
  return minutesToHHMM(mins + hours * 60);
}

function isAllowedReservationStartTime(value) {
  const mins = timeToMinutes(value);
  if (mins === null) return false;

  const hour = Math.floor(mins / 60);
  const minute = mins % 60;
  const latestStartHour = CLOSING_HOUR - RESERVATION_DURATION_HOURS;

  return minute === 0 && hour >= OPENING_HOUR && hour <= latestStartHour;
}

function calculateTablesNeeded(pax) {
  return Math.ceil(Number(pax) / SEATS_PER_TABLE);
}

function parseAssignedTables(value) {
  if (!value) return [];
  return String(value)
    .split(",")
    .map((v) => Number(v.trim()))
    .filter((n) => Number.isInteger(n) && n >= 1 && n <= TABLES_PER_BRANCH);
}

function formatAssignedTables(tables) {
  return tables.join(",");
}

function pickAvailableTables(usedTables, tablesNeeded) {
  const used = new Set(usedTables);
  const available = [];

  for (let i = 1; i <= TABLES_PER_BRANCH; i++) {
    if (!used.has(i)) available.push(i);
  }

  if (available.length < tablesNeeded) return null;
  return available.slice(0, tablesNeeded);
}

function reservationTimesOverlap(existingStart, requestedStart) {
  const aStart = timeToMinutes(existingStart);
  const bStart = timeToMinutes(requestedStart);

  if (aStart === null || bStart === null) return false;

  const aEnd = aStart + RESERVATION_DURATION_HOURS * 60;
  const bEnd = bStart + RESERVATION_DURATION_HOURS * 60;

  return aStart < bEnd && bStart < aEnd;
}

async function getCurrentCustomerProfile(userId) {
  const [rows] = await pool.execute(
    `SELECT id, full_name, email, phone
     FROM users
     WHERE id = ?
     LIMIT 1`,
    [userId]
  );
  return rows[0] || null;
}

async function findActiveBranchById(branchId) {
  const [rows] = await pool.execute(
    `SELECT id, name, is_active
     FROM branches
     WHERE id = ?
     LIMIT 1`,
    [branchId]
  );

  if (rows.length === 0) return null;
  const branch = rows[0];
  if (Number(branch.is_active) !== 1) return null;
  return branch;
}

async function getUsedTablesForSlot(branchId, reservationDate, requestedTime, excludeReservationId = null) {
  let sql = `
    SELECT assigned_tables, reservation_time
    FROM reservations
    WHERE branch_id = ?
      AND reservation_date = ?
      AND LOWER(COALESCE(status, 'pending')) IN ('pending', 'approved')
  `;
  const params = [branchId, reservationDate];

  if (excludeReservationId) {
    sql += ` AND id <> ?`;
    params.push(excludeReservationId);
  }

  const [rows] = await pool.execute(sql, params);

  const used = [];
  for (const row of rows) {
    if (!reservationTimesOverlap(row.reservation_time, requestedTime)) continue;
    used.push(...parseAssignedTables(row.assigned_tables));
  }

  return used;
}

async function hasDuplicateActiveReservation(userId, branchId, reservationDate, requestedTime, excludeReservationId = null) {
  let sql = `
    SELECT id, reservation_time
    FROM reservations
    WHERE user_id = ?
      AND branch_id = ?
      AND reservation_date = ?
      AND LOWER(COALESCE(status, 'pending')) IN ('pending', 'approved')
  `;
  const params = [userId, branchId, reservationDate];

  if (excludeReservationId) {
    sql += ` AND id <> ?`;
    params.push(excludeReservationId);
  }

  const [rows] = await pool.execute(sql, params);
  return rows.some((row) => reservationTimesOverlap(row.reservation_time, requestedTime));
}

// ========================================
// GOOGLE reCAPTCHA v2 verification
// ========================================
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
// ACCOUNT LOCKING (BY EMAIL)
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

  if (!row) {
    await pool.execute(
      `INSERT INTO login_attempts (email, failed_count, first_failed_at, last_failed_at, lock_until)
       VALUES (?, 1, ?, ?, NULL)`,
      [email, now, now]
    );
    return;
  }

  if (row.lock_until && new Date(row.lock_until) > now) return;

  const firstFailedAt = row.first_failed_at ? new Date(row.first_failed_at) : null;
  const withinWindow =
    firstFailedAt && (now - firstFailedAt) <= LOCK_WINDOW_MIN * 60 * 1000;

  const nextCount = withinWindow ? row.failed_count + 1 : 1;
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
// CLEANUP JOB
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
// ADMIN SECURITY
// ========================================
const ADMIN_IDLE_TIMEOUT_SEC = Number(process.env.ADMIN_IDLE_TIMEOUT_SEC || 30 * 60);

function requireAdmin(req, res, next) {
  if (!req.session || !req.session.admin) {
    if ((req.path || "").startsWith("/api/")) {
      return res.status(401).json({ error: "Not logged in" });
    }
    return res.redirect("/login");
  }
  next();
}

function requireUserPage(req, res, next) {
  if (!req.session || !req.session.user) {
    return res.redirect("/login");
  }
  next();
}

function requireUserApi(req, res, next) {
  if (!req.session || !req.session.user) {
    return res.status(401).json({ error: "Session expired or not logged in" });
  }
  next();
}

function adminSessionTimeout(req, res, next) {
  const p = req.path || "";
  const isAdminPath = p.startsWith("/admin") || p.startsWith("/api/admin");
  if (!isAdminPath) return next();
  if (p === "/api/admin/login") return next();

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
      res.clearCookie("id");
      if ((req.path || "").startsWith("/api/")) {
        return res.status(401).json({ error: "Session expired" });
      }
      return res.redirect("/login");
    });
    return;
  }

  req.session.admin_last_activity = now;
  next();
}

app.use(adminSessionTimeout);

function ensureCsrfToken(req) {
  if (!req.session) return "";
  if (!req.session.csrf_token) {
    req.session.csrf_token = crypto.randomBytes(32).toString("hex");
  }
  return req.session.csrf_token;
}

app.get("/api/admin/csrf", requireAdmin, (req, res) => {
  const token = ensureCsrfToken(req);
  return res.json({ csrfToken: token });
});

function requireCsrf(req, res, next) {
  if (!["POST", "PUT", "PATCH", "DELETE"].includes(req.method)) return next();
  if (!(req.path || "").startsWith("/api/admin")) return next();
  if (req.path === "/api/admin/login") return next();

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
// ADMIN-ONLY ACTIONS
// ========================================
console.log("✅ Registering admin-only action routes...");

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
    return sendAdminApiError(res, err, "Server error", 500);
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
      preview: message.slice(0, 80),
    });

    return res.json({ message: "Announcement saved" });
  } catch (err) {
    console.error("[ADMIN] announcements create error:", err);
    return sendAdminApiError(res, err, "Server error", 500);
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
    return sendAdminApiError(res, err, "Server error", 500);
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
      preview: note.slice(0, 80),
    });

    return res.json({ message: "Note saved" });
  } catch (err) {
    console.error("[ADMIN] notes create error:", err);
    return sendAdminApiError(res, err, "Server error", 500);
  }
});

// ---- Settings ----
app.get("/api/admin/settings", requireAdmin, async (req, res) => {
  try {
    const [rows] = await pool.execute(
      `SELECT
         id,
         max_reservations_per_slot,
         preparation_time_minutes,
         dine_in_time_limit_minutes,
         grace_period_minutes,
         updated_at
       FROM admin_settings
       WHERE id = 1
       LIMIT 1`
    );

    if (rows.length === 0) {
      await pool.execute(
        `INSERT INTO admin_settings (
          id,
          max_reservations_per_slot,
          preparation_time_minutes,
          dine_in_time_limit_minutes,
          grace_period_minutes
        )
        VALUES (1, 20, 15, 90, 10)`
      );

      return res.json({
        settings: {
          id: 1,
          max_reservations_per_slot: 20,
          preparation_time_minutes: 15,
          dine_in_time_limit_minutes: 90,
          grace_period_minutes: 10,
        },
      });
    }

    return res.json({ settings: rows[0] });
  } catch (err) {
    console.error("[ADMIN] settings get error:", err);
    return sendAdminApiError(res, err, "Server error", 500);
  }
});

app.post("/api/admin/settings", requireAdmin, async (req, res) => {
  try {
    const maxRes = toIntOrNull(req.body.max_reservations_per_slot);
    const prepMin = toIntOrNull(req.body.preparation_time_minutes);
    const dineLimit = toIntOrNull(req.body.dine_in_time_limit_minutes);
    const graceMin = toIntOrNull(req.body.grace_period_minutes);

    if (maxRes === null || prepMin === null || dineLimit === null || graceMin === null) {
      return res.status(400).json({ error: "All numeric fields are required" });
    }

    if (maxRes < 1 || maxRes > 500) {
      return res.status(400).json({ error: "max_reservations_per_slot must be 1..500" });
    }

    if (prepMin < 1 || prepMin > 480) {
      return res.status(400).json({ error: "preparation_time_minutes must be 1..480" });
    }

    if (dineLimit < 30 || dineLimit > 300) {
      return res.status(400).json({ error: "dine_in_time_limit_minutes must be 30..300" });
    }

    if (graceMin < 1 || graceMin > 120) {
      return res.status(400).json({ error: "grace_period_minutes must be 1..120" });
    }

    await pool.execute(
      `INSERT INTO admin_settings (
        id,
        max_reservations_per_slot,
        preparation_time_minutes,
        dine_in_time_limit_minutes,
        grace_period_minutes
      )
      VALUES (1, ?, ?, ?, ?)
      ON DUPLICATE KEY UPDATE
        max_reservations_per_slot = VALUES(max_reservations_per_slot),
        preparation_time_minutes = VALUES(preparation_time_minutes),
        dine_in_time_limit_minutes = VALUES(dine_in_time_limit_minutes),
        grace_period_minutes = VALUES(grace_period_minutes)`,
      [maxRes, prepMin, dineLimit, graceMin]
    );

    adminLog("INFO", "Admin settings updated", {
      ip: req.ip,
      adminEmail: req.session?.admin?.email,
      max_reservations_per_slot: maxRes,
      preparation_time_minutes: prepMin,
      dine_in_time_limit_minutes: dineLimit,
      grace_period_minutes: graceMin,
    });

    return res.json({ message: "Settings updated" });
  } catch (err) {
    console.error("[ADMIN] settings update error:", err);
    return sendAdminApiError(res, err, "Server error", 500);
  }
});

// ---- Branches ----
app.get("/api/admin/branches", requireAdmin, async (req, res) => {
  try {
    const [rows] = await pool.execute(
      `SELECT id, name, location, contact_number, operating_hours, is_active, created_at
       FROM branches
       ORDER BY id DESC`
    );

    return res.json({ branches: rows });
  } catch (err) {
    console.error("[ADMIN] branches list error:", err);
    return sendAdminApiError(res, err, "Server error", 500);
  }
});

app.post("/api/admin/branches", requireAdmin, async (req, res) => {
  try {
    const name = String(req.body.name || "").trim();
    const location = String(req.body.location || "").trim();
    const contact_number = String(req.body.contact_number || "").trim();
    const operating_hours = String(req.body.operating_hours || "").trim();

    if (!name || !location || !contact_number || !operating_hours) {
      return res.status(400).json({ error: "All branch fields are required" });
    }

    if (name.length > 100) {
      return res.status(400).json({ error: "Branch name is too long" });
    }

    if (location.length > 255) {
      return res.status(400).json({ error: "Location is too long" });
    }

    if (contact_number.length > 20) {
      return res.status(400).json({ error: "Contact number is too long" });
    }

    if (operating_hours.length > 100) {
      return res.status(400).json({ error: "Operating hours is too long" });
    }

    await pool.execute(
      `INSERT INTO branches (name, location, contact_number, operating_hours, is_active)
       VALUES (?, ?, ?, ?, 1)`,
      [name, location, contact_number, operating_hours]
    );

    adminLog("INFO", "Branch created", {
      ip: req.ip,
      adminEmail: req.session?.admin?.email,
      branch_name: name,
      location,
    });

    return res.json({ message: "Branch added successfully" });
  } catch (err) {
    console.error("[ADMIN] branch create error:", err);
    return sendAdminApiError(res, err, "Server error", 500);
  }
});

app.post("/api/admin/branches/:id/toggle", requireAdmin, async (req, res) => {
  try {
    const branchId = Number(req.params.id);

    if (!Number.isInteger(branchId) || branchId <= 0) {
      return res.status(400).json({ error: "Invalid branch ID" });
    }

    const [rows] = await pool.execute(
      `SELECT id, name, is_active
       FROM branches
       WHERE id = ?
       LIMIT 1`,
      [branchId]
    );

    if (rows.length === 0) {
      return res.status(404).json({ error: "Branch not found" });
    }

    const branch = rows[0];
    const newStatus = branch.is_active ? 0 : 1;

    await pool.execute(
      `UPDATE branches
       SET is_active = ?
       WHERE id = ?`,
      [newStatus, branchId]
    );

    adminLog("INFO", "Branch status toggled", {
      ip: req.ip,
      adminEmail: req.session?.admin?.email,
      branch_id: branchId,
      branch_name: branch.name,
      is_active: newStatus,
    });

    return res.json({
      message: newStatus ? "Branch enabled" : "Branch disabled"
    });
  } catch (err) {
    console.error("[ADMIN] branch toggle error:", err);
    return sendAdminApiError(res, err, "Server error", 500);
  }
});

// public active branches for customer reserve page
app.get("/api/branches-active", async (req, res) => {
  try {
    const [rows] = await pool.execute(
      `SELECT id, name, location, operating_hours
       FROM branches
       WHERE is_active = 1
       ORDER BY name ASC`
    );

    return res.json({ branches: rows });
  } catch (err) {
    console.error("[PUBLIC] active branches list error:", err);
    return sendAdminApiError(res, err, "Server error", 500);
  }
});

app.get("/api/menu-items/available", async (req, res) => {
  try {
    const [rows] = await pool.execute(
      `SELECT id, name, category, price, description
       FROM menu_items
       WHERE is_available = 1
       ORDER BY category ASC, name ASC`
    );

    return res.json({ menuItems: rows });
  } catch (err) {
    console.error("[PUBLIC] available menu items error:", err);
    return sendAdminApiError(res, err, "Server error", 500);
  }
});

// ---- Menu Items ----
app.get("/api/admin/menu-items", requireAdmin, async (req, res) => {
  try {
    const [rows] = await pool.execute(
      `SELECT id, name, category, price, description, is_available, created_at
       FROM menu_items
       ORDER BY id DESC`
    );

    return res.json({ menuItems: rows });
  } catch (err) {
    console.error("[ADMIN] menu items list error:", err);
    return sendAdminApiError(res, err, "Server error", 500);
  }
});

app.post("/api/admin/menu-items", requireAdmin, async (req, res) => {
  try {
    const name = String(req.body.name || "").trim();
    const category = String(req.body.category || "").trim();
    const description = String(req.body.description || "").trim();
    const price = Number(req.body.price);

    if (!name || !category || !description || req.body.price === undefined || req.body.price === null || req.body.price === "") {
      return res.status(400).json({ error: "All menu item fields are required" });
    }

    if (name.length > 150) {
      return res.status(400).json({ error: "Item name is too long" });
    }

    if (category.length > 100) {
      return res.status(400).json({ error: "Category is too long" });
    }

    if (description.length > 2000) {
      return res.status(400).json({ error: "Description is too long" });
    }

    if (!Number.isFinite(price) || price <= 0 || price > 99999.99) {
      return res.status(400).json({ error: "Price must be a valid positive amount" });
    }

    await pool.execute(
      `INSERT INTO menu_items (name, category, price, description, is_available)
       VALUES (?, ?, ?, ?, 1)`,
      [name, category, price.toFixed(2), description]
    );

    adminLog("INFO", "Menu item created", {
      ip: req.ip,
      adminEmail: req.session?.admin?.email,
      item_name: name,
      category,
      price: Number(price.toFixed(2)),
    });

    return res.json({ message: "Menu item added successfully" });
  } catch (err) {
    console.error("[ADMIN] menu item create error:", err);
    return sendAdminApiError(res, err, "Server error", 500);
  }
});

app.post("/api/admin/menu-items/:id/toggle", requireAdmin, async (req, res) => {
  try {
    const itemId = Number(req.params.id);

    if (!Number.isInteger(itemId) || itemId <= 0) {
      return res.status(400).json({ error: "Invalid menu item ID" });
    }

    const [rows] = await pool.execute(
      `SELECT id, name, is_available
       FROM menu_items
       WHERE id = ?
       LIMIT 1`,
      [itemId]
    );

    if (rows.length === 0) {
      return res.status(404).json({ error: "Menu item not found" });
    }

    const item = rows[0];
    const newStatus = item.is_available ? 0 : 1;

    await pool.execute(
      `UPDATE menu_items
       SET is_available = ?
       WHERE id = ?`,
      [newStatus, itemId]
    );

    adminLog("INFO", "Menu item availability toggled", {
      ip: req.ip,
      adminEmail: req.session?.admin?.email,
      item_id: itemId,
      item_name: item.name,
      is_available: newStatus,
    });

    return res.json({
      message: newStatus ? "Menu item enabled" : "Menu item disabled"
    });
  } catch (err) {
    console.error("[ADMIN] menu item toggle error:", err);
    return sendAdminApiError(res, err, "Server error", 500);
  }
});

// ---- Admin Reservations ----
app.get("/api/admin/reservations", requireAdmin, async (req, res) => {
  try {
    const filterDate = String(req.query.date || "").trim();
    const filterBranch = String(req.query.branch_id || "").trim();
    const filterStatus = String(req.query.status || "").trim().toLowerCase();

    let sql = `
      SELECT
        r.id,
        r.user_id,
        r.full_name,
        r.email,
        r.phone,
        r.reservation_date,
        r.reservation_time,
        r.guests_count,
        r.branch_id,
        r.status,
        r.admin_notes,
        r.reservation_note,
        r.tables_needed,
        r.assigned_tables,
        r.created_at,
        r.admin_updated_at,
        b.name AS branch_name
      FROM reservations r
      LEFT JOIN branches b ON r.branch_id = b.id
      WHERE 1=1
    `;

    const params = [];

    if (filterDate) {
      sql += ` AND r.reservation_date = ?`;
      params.push(filterDate);
    }

    if (filterBranch && Number.isInteger(Number(filterBranch)) && Number(filterBranch) > 0) {
      sql += ` AND r.branch_id = ?`;
      params.push(Number(filterBranch));
    }

    if (filterStatus) {
      sql += ` AND LOWER(COALESCE(r.status, 'pending')) = ?`;
      params.push(filterStatus);
    }

    sql += ` ORDER BY r.reservation_date DESC, r.reservation_time DESC, r.created_at DESC LIMIT 200`;

    const [rows] = await pool.execute(sql, params);

    return res.json({ reservations: rows });
  } catch (err) {
    console.error("[ADMIN] reservations list error:", err);
    return sendAdminApiError(res, err, "Server error", 500);
  }
});

app.post("/api/admin/reservations/:id/status", requireAdmin, async (req, res) => {
  try {
    const reservationId = Number(req.params.id);
    const status = String(req.body.status || "").trim().toLowerCase();
    const adminNotes = String(req.body.admin_notes || "").trim();

    const allowedStatuses = new Set([
      "approved",
      "rejected",
      "completed",
      "no_show",
      "cancelled",
      "pending"
    ]);

    if (!Number.isInteger(reservationId) || reservationId <= 0) {
      return res.status(400).json({ error: "Invalid reservation ID" });
    }

    if (!allowedStatuses.has(status)) {
      return res.status(400).json({ error: "Invalid reservation status" });
    }

    if (adminNotes.length > 255) {
      return res.status(400).json({ error: "Admin notes is too long" });
    }

    const [rows] = await pool.execute(
      `SELECT id, full_name, email, status
       FROM reservations
       WHERE id = ?
       LIMIT 1`,
      [reservationId]
    );

    if (rows.length === 0) {
      return res.status(404).json({ error: "Reservation not found" });
    }

    await pool.execute(
      `UPDATE reservations
       SET status = ?,
           admin_notes = ?,
           admin_updated_at = NOW()
       WHERE id = ?`,
      [status, adminNotes || null, reservationId]
    );

    adminLog("INFO", "Reservation status updated", {
      ip: req.ip,
      adminEmail: req.session?.admin?.email,
      reservation_id: reservationId,
      customer_name: rows[0].full_name,
      customer_email: rows[0].email,
      new_status: status,
    });

    return res.json({ message: "Reservation updated successfully" });
  } catch (err) {
    console.error("[ADMIN] reservation update error:", err);
    return sendAdminApiError(res, err, "Server error", 500);
  }
});

// ========================================
// CLEANUP START
// ========================================
cleanupLoginAttempts();
setInterval(cleanupLoginAttempts, CLEANUP_EVERY_HOURS * 60 * 60 * 1000);

/* ------------------ PAGES ------------------ */
app.get("/", (req, res) => res.sendFile(path.join(__dirname, "views", "home.html")));
app.get("/register", (req, res) => res.sendFile(path.join(__dirname, "views", "register.html")));
app.get("/login", (req, res) => res.sendFile(path.join(__dirname, "views", "login.html")));
app.get("/home", (req, res) => res.sendFile(path.join(__dirname, "views", "home.html")));
app.get("/welcome", (req, res) => res.sendFile(path.join(__dirname, "views", "welcome.html")));

app.get("/admin/dashboard", requireAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, "views", "admin-dashboard.html"));
});

app.get("/api/admin/me", (req, res) => {
  if (!req.session || !req.session.admin) {
    return res.status(401).json({ error: "Not logged in" });
  }
  return res.json({ admin: req.session.admin });
});

app.post("/api/admin/logout", (req, res) => {
  const adminEmail = req.session?.admin?.email || null;
  req.session.destroy(() => {
    res.clearCookie("id", { path: "/" });
    audit("auth.admin_logout", {
      email: adminEmail,
      ip: req.ip,
    });
    adminLog("INFO", "Admin logged out", {
      ip: req.ip,
      adminEmail,
    });
    return res.json({ message: "Logged out" });
  });
});

app.get("/branches", (req, res) => res.sendFile(path.join(__dirname, "views", "branches.html")));
app.get("/menu", (req, res) => res.sendFile(path.join(__dirname, "views", "menu.html")));

app.get("/reserve", requireUserPage, (req, res) => {
  res.sendFile(path.join(__dirname, "views", "reserve.html"));
});

app.get("/track", requireUserPage, (req, res) => {
  res.sendFile(path.join(__dirname, "views", "track.html"));
});

app.get("/order/:id", requireUserPage, (req, res) => {
  res.sendFile(path.join(__dirname, "views", "order.html"));
});

app.get("/api/me", (req, res) => {
  if (req.session?.admin) {
    return res.json({ role: "admin", user: req.session.admin });
  }
  if (req.session?.user) {
    return res.json({ role: "customer", user: req.session.user });
  }
  return res.status(401).json({ error: "Not logged in" });
});

app.post("/api/logout", (req, res) => {
  const userEmail = req.session?.user?.email || null;
  req.session.destroy(() => {
    res.clearCookie("id", { path: "/" });
    audit("auth.logout", {
      email: userEmail,
      ip: req.ip,
    });
    return res.json({ message: "Logged out" });
  });
});

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
      audit("verify_email.failed", {
        ip: req.ip,
        reason: "MISSING_EMAIL_OR_TOKEN",
      });
      return res.status(400).send("Invalid or expired verification link.");
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
      audit("verify_email.failed", {
        email,
        ip: req.ip,
        reason: "TOKEN_NOT_FOUND",
      });
      return res.status(400).send("Invalid or expired verification link.");
    }

    const user = rows[0];

    if (user.is_verified === 1) {
      audit("verify_email.already_verified", {
        email,
        ip: req.ip,
        user_id: user.id,
      });
      return res.redirect("/login?verified=1");
    }

    if (user.verify_token_expires && new Date(user.verify_token_expires) < new Date()) {
      audit("verify_email.failed", {
        email,
        ip: req.ip,
        user_id: user.id,
        reason: "TOKEN_EXPIRED",
      });
      return res.status(400).send("Invalid or expired verification link.");
    }

    await pool.execute(
      `UPDATE users
       SET is_verified = 1,
           verify_token_hash = NULL,
           verify_token_expires = NULL
       WHERE id = ?`,
      [user.id]
    );

    audit("verify_email.success", {
      email,
      ip: req.ip,
      user_id: user.id,
    });

    return res.redirect("/login?verified=1");
  } catch (err) {
    audit("verify_email.error", {
      ip: req.ip,
      path: req.originalUrl,
      message: err.message,
    });
    return sendDebugOrGenericError(res, err, "Server error", 500);
  }
});

/* ------------------ REGISTER ------------------ */
app.post("/register", registerLimiter, registerUpload, async (req, res) => {
  let uploadedFilePath = req.file?.path || null;

  try {
    const { full_name, email, phone, password, confirm_password } = req.body;
    const captchaToken = req.body["g-recaptcha-response"];

    const cleanName = (full_name || "").trim().replace(/\s+/g, " ");
    const emailParts = splitEmailParts(email);
    const cleanEmail = emailParts ? emailParts.cleanEmail.toLowerCase() : "";
    const cleanPhone = (phone || "").trim();

    const captchaOk = await verifyRecaptchaV2(captchaToken, req.ip);
    if (!captchaOk) {
      safeUnlink(uploadedFilePath);
      audit("register.failed", {
        email: cleanEmail || undefined,
        ip: req.ip,
        reason: "CAPTCHA_FAILED",
      });
      return res.redirect("/register?error=1");
    }

    if (!cleanName || !cleanEmail || !cleanPhone || !password || !confirm_password) {
      safeUnlink(uploadedFilePath);
      audit("register.failed", {
        email: cleanEmail || undefined,
        ip: req.ip,
        reason: "MISSING_REQUIRED_FIELDS",
      });
      return res.redirect("/register?error=1");
    }

    if (cleanName.length < 2 || cleanName.length > 160) {
      safeUnlink(uploadedFilePath);
      audit("register.failed", {
        email: cleanEmail,
        ip: req.ip,
        reason: "INVALID_FULL_NAME",
      });
      return res.redirect("/register?error=1");
    }

    if (!isValidEmail(cleanEmail)) {
      safeUnlink(uploadedFilePath);
      audit("register.failed", {
        email: cleanEmail,
        ip: req.ip,
        reason: "INVALID_EMAIL",
      });
      return res.redirect("/register?error=1");
    }

    if (!isValidPHPhone(cleanPhone)) {
      safeUnlink(uploadedFilePath);
      audit("register.failed", {
        email: cleanEmail,
        ip: req.ip,
        reason: "INVALID_PHONE",
      });
      return res.redirect("/register?error=1");
    }

    if (password !== confirm_password) {
      safeUnlink(uploadedFilePath);
      audit("register.failed", {
        email: cleanEmail,
        ip: req.ip,
        reason: "PASSWORD_MISMATCH",
      });
      return res.redirect("/register?error=1");
    }

    if (!isStrongPassword(password)) {
      safeUnlink(uploadedFilePath);
      audit("register.failed", {
        email: cleanEmail,
        ip: req.ip,
        reason: "WEAK_PASSWORD",
      });
      return res.redirect("/register?error=1");
    }

    if (!req.file || !uploadedFilePath) {
      audit("register.failed", {
        email: cleanEmail,
        ip: req.ip,
        reason: "MISSING_PHOTO",
      });
      return res.redirect("/register?error=1");
    }

    const detectedMime = detectImageMimeFromMagic(uploadedFilePath);
    const safeExt = mimeToSafeExtension(detectedMime);

    if (!detectedMime || !safeExt) {
      safeUnlink(uploadedFilePath);
      audit("register.failed", {
        email: cleanEmail,
        ip: req.ip,
        reason: "INVALID_IMAGE_SIGNATURE",
      });
      return res.redirect("/register?error=1");
    }

    const finalFilename = `${req.file.filename}${safeExt}`;
    const finalPath = path.join(uploadsDir, finalFilename);
    fs.renameSync(uploadedFilePath, finalPath);
    uploadedFilePath = finalPath;

    const photo_path = `/public/uploads/${finalFilename}`;

    const password_hash = await bcrypt.hash(password, 13);

    const { rawToken, tokenHash } = makeVerificationToken();
    const expires = new Date(Date.now() + 30 * 60 * 1000);

    await pool.execute(
      `INSERT INTO users
        (full_name, email, phone, password_hash, photo_path, is_verified, verify_token_hash, verify_token_expires)
       VALUES
        (?, ?, ?, ?, ?, 0, ?, ?)`,
      [cleanName, cleanEmail, cleanPhone, password_hash, photo_path, tokenHash, expires]
    );

    audit("register.success", {
      email: cleanEmail,
      ip: req.ip,
      photo_path,
    });

    const baseUrl = (process.env.APP_BASE_URL || `http://localhost:${PORT}`).replace(/\/$/, "");
    const verifyUrl =
      `${baseUrl}/verify-email?email=${encodeURIComponent(cleanEmail)}&token=${rawToken}`;

    try {
      await sendVerificationEmail({
        toEmail: cleanEmail,
        fullName: cleanName,
        verifyUrl,
      });

      audit("register.email_sent", {
        email: cleanEmail,
        ip: req.ip,
      });

      return res.redirect("/login?verify=1");
    } catch (mailErr) {
      audit("register.email_send_failed", {
        email: cleanEmail,
        ip: req.ip,
        message: mailErr.message,
      });

      return res.redirect("/login?verify=0");
    }
  } catch (err) {
    safeUnlink(uploadedFilePath);

    audit("register.error", {
      email: req.body?.email ? String(req.body.email).trim().toLowerCase() : undefined,
      ip: req.ip,
      code: err.code || "UNEXPECTED_ERROR",
      message: err.message,
    });

    if (DEBUG_ERRORS) {
      return sendDebugOrGenericError(res, err, "Registration failed", 500);
    }

    return res.redirect("/register?error=1");
  }
});

/* ------------------ LOGIN API (UNIFIED) ------------------ */
app.post("/api/login", loginLimiter, async (req, res) => {
  try {
    let { email, password, captchaToken } = req.body;

    if (!email || !password) {
      audit("auth.login.failed", {
        ip: req.ip,
        reason: "MISSING_INPUT",
      });
      return res.status(400).json({ error: "Invalid input" });
    }

    const emailParts = splitEmailParts(email);
    email = emailParts ? emailParts.cleanEmail.toLowerCase() : "";
    password = String(password);

    if (!isValidEmail(email)) {
      audit("auth.login.failed", {
        ip: req.ip,
        email,
        reason: "INVALID_EMAIL_FORMAT",
      });
      return res.status(400).json({ error: "Invalid input" });
    }

    if (password.length < 8 || password.length > 128) {
      audit("auth.login.failed", {
        ip: req.ip,
        email,
        reason: "INVALID_PASSWORD_LENGTH",
      });
      return res.status(400).json({ error: "Invalid input" });
    }

    const captchaOk = await verifyRecaptchaV2(captchaToken, req.ip);
    if (!captchaOk) {
      audit("auth.login.failed", {
        ip: req.ip,
        email,
        reason: "CAPTCHA_FAILED",
      });
      return res.status(400).json({ error: "CAPTCHA verification failed" });
    }

    if (await isEmailLocked(email)) {
      audit("auth.login.locked", {
        ip: req.ip,
        email,
      });
      return res.status(423).json({
        error: "Account temporarily locked due to too many failed attempts. Please try again later.",
      });
    }

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

    if (rows.length === 0) {
      await recordFailedAttempt(email);

      audit("auth.login.failed", {
        ip: req.ip,
        email,
        reason: "EMAIL_NOT_FOUND",
      });

      return res.status(401).json({ error: "Invalid credentials" });
    }

    const user = rows[0];

    if (user.is_verified !== 1) {
      await recordFailedAttempt(email);

      audit("auth.login.failed", {
        ip: req.ip,
        email,
        user_id: user.user_id,
        reason: "EMAIL_NOT_VERIFIED",
      });

      return res.status(403).json({ error: "Please verify your email before logging in." });
    }

    const passwordMatch = await bcrypt.compare(password, user.password_hash);

    if (!passwordMatch) {
      await recordFailedAttempt(email);

      audit("auth.login.failed", {
        ip: req.ip,
        email,
        user_id: user.user_id,
        reason: "WRONG_PASSWORD",
      });

      return res.status(401).json({ error: "Invalid credentials" });
    }

    await clearLoginAttempts(email);

    if (user.role === "admin") {
      delete req.session.user;
      req.session.admin = {
        user_id: user.user_id,
        full_name: user.full_name,
        email: user.email,
        role: user.role,
      };
      req.session.admin_last_activity = Date.now();
      ensureCsrfToken(req);

      audit("auth.admin_login.success", {
        ip: req.ip,
        email: user.email,
        user_id: user.user_id,
        role: user.role,
      });

      adminLog("INFO", "Admin login successful", {
        ip: req.ip,
        adminEmail: user.email,
        user_id: user.user_id,
      });

      return res.json({
        message: "Admin login successful",
        redirectTo: "/admin/dashboard",
      });
    }

    delete req.session.admin;
    req.session.user = {
      user_id: user.user_id,
      full_name: user.full_name,
      email: user.email,
      role: user.role || "customer",
    };

    audit("auth.login.success", {
      ip: req.ip,
      email: user.email,
      user_id: user.user_id,
      role: user.role || "customer",
    });

    return req.session.save(() => {
      return res.json({
        message: "Login successful",
        redirectTo: "/reserve",
        user: {
          user_id: user.user_id,
          full_name: user.full_name,
          email: user.email,
          phone: user.phone,
          photo_path: user.photo_path,
        },
      });
    });
  } catch (err) {
    console.error("Login error:", err.message);
    audit("auth.login.error", {
      ip: req.ip,
      email: req.body?.email ? String(req.body.email).trim().toLowerCase() : undefined,
      message: err.message,
    });
    return sendApiDebugOrGenericError(res, err, "Server error", 500);
  }
});

app.post("/api/admin/login", adminLoginLimiter, async (req, res) => {
  try {
    let { email, password, captchaToken } = req.body;

    if (!email || !password) {
      audit("auth.admin_login.failed", {
        ip: req.ip,
        reason: "MISSING_INPUT",
      });
      return res.status(400).json({ error: "Invalid input" });
    }

    const emailParts = splitEmailParts(email);
    email = emailParts ? emailParts.cleanEmail.toLowerCase() : "";
    password = String(password);

    if (!isValidEmail(email)) {
      audit("auth.admin_login.failed", {
        ip: req.ip,
        email,
        reason: "INVALID_EMAIL_FORMAT",
      });
      return res.status(400).json({ error: "Invalid input" });
    }

    if (password.length < 8 || password.length > 128) {
      audit("auth.admin_login.failed", {
        ip: req.ip,
        email,
        reason: "INVALID_PASSWORD_LENGTH",
      });
      return res.status(400).json({ error: "Invalid input" });
    }

    const captchaOk = await verifyRecaptchaV2(captchaToken, req.ip);
    if (!captchaOk) {
      audit("auth.admin_login.failed", {
        ip: req.ip,
        email,
        reason: "CAPTCHA_FAILED",
      });
      return res.status(400).json({ error: "CAPTCHA verification failed" });
    }

    if (await isEmailLocked(email)) {
      audit("auth.admin_login.locked", {
        ip: req.ip,
        email,
      });
      return res.status(423).json({ error: "Account temporarily locked. Please try again later." });
    }

    const [rows] = await pool.execute(
      `SELECT id, full_name, email, password_hash, is_verified, role
       FROM users
       WHERE email = ?
       LIMIT 1`,
      [email]
    );

    if (rows.length === 0) {
      await recordFailedAttempt(email);

      audit("auth.admin_login.failed", {
        ip: req.ip,
        email,
        reason: "EMAIL_NOT_FOUND",
      });

      return res.status(401).json({ error: "Invalid credentials" });
    }

    const user = rows[0];

    if (user.role !== "admin") {
      await recordFailedAttempt(email);

      audit("auth.admin_login.failed", {
        ip: req.ip,
        email,
        user_id: user.id,
        reason: "ACCESS_DENIED_NOT_ADMIN",
      });

      return res.status(403).json({ error: "Access denied" });
    }

    if (user.is_verified !== 1) {
      await recordFailedAttempt(email);

      audit("auth.admin_login.failed", {
        ip: req.ip,
        email,
        user_id: user.id,
        reason: "EMAIL_NOT_VERIFIED",
      });

      return res.status(403).json({ error: "Please verify your email before logging in." });
    }

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) {
      await recordFailedAttempt(email);

      audit("auth.admin_login.failed", {
        ip: req.ip,
        email,
        user_id: user.id,
        reason: "WRONG_PASSWORD",
      });

      return res.status(401).json({ error: "Invalid credentials" });
    }

    await clearLoginAttempts(email);

    delete req.session.user;
    req.session.admin = {
      user_id: user.id,
      full_name: user.full_name,
      email: user.email,
      role: user.role,
    };
    req.session.admin_last_activity = Date.now();
    ensureCsrfToken(req);

    audit("auth.admin_login.success", {
      ip: req.ip,
      email: user.email,
      user_id: user.id,
      role: user.role,
    });

    adminLog("INFO", "Admin login successful", {
      ip: req.ip,
      adminEmail: user.email,
      user_id: user.id,
    });

    return res.json({ message: "Admin login successful", redirectTo: "/admin/dashboard" });
  } catch (err) {
    console.error("Admin login error:", err.message);
    audit("auth.admin_login.error", {
      ip: req.ip,
      email: req.body?.email ? String(req.body.email).trim().toLowerCase() : undefined,
      message: err.message,
    });
    return sendApiDebugOrGenericError(res, err, "Server error", 500);
  }
});

// ========================================
// CUSTOMER RESERVATION ACTIONS
// ========================================
app.get("/api/reservations", requireUserApi, async (req, res) => {
  try {
    const [rows] = await pool.execute(
      `SELECT
         r.id,
         r.branch_id,
         b.name AS branch,
         r.reservation_note,
         r.guests_count AS pax,
         r.tables_needed,
         r.assigned_tables,
         r.reservation_date,
         r.reservation_time,
         r.status,
         r.created_at,
         r.admin_updated_at AS updated_at
       FROM reservations r
       LEFT JOIN branches b ON r.branch_id = b.id
       WHERE r.user_id = ?
       ORDER BY r.created_at DESC`,
      [req.session.user.user_id]
    );

    const reservations = rows.map((row) => ({
      ...row,
      reservation_time: normalizeTimeHHMM(row.reservation_time) || row.reservation_time,
      reservation_end_time: addHoursToTime(row.reservation_time, RESERVATION_DURATION_HOURS),
    }));

    return res.json({ reservations });
  } catch (err) {
    audit("reservation.list.error", {
      ip: req.ip,
      user_id: req.session.user.user_id,
      message: err.message,
    });
    return res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/reservations", requireUserApi, async (req, res) => {
  try {
    const { branch_id, reservation_note, pax, reservation_date, reservation_time } = req.body;

    const branchId = Number(branch_id);
    const cleanNote = String(reservation_note || "").trim();
    const paxValue = Number(pax);
    const cleanTime = normalizeTimeHHMM(reservation_time);

    if (!Number.isInteger(branchId) || branchId <= 0) {
      return res.status(400).json({ error: "Branch is required" });
    }

    if (!isValidReservationText(cleanNote, 300)) {
      return res.status(400).json({ error: "Invalid reservation note" });
    }

    if (!Number.isInteger(paxValue) || paxValue < 1 || paxValue > 80) {
      return res.status(400).json({ error: "Invalid pax" });
    }

    if (!isValidReservationDate(reservation_date)) {
      return res.status(400).json({ error: "Invalid reservation date" });
    }

    if (!cleanTime || !isAllowedReservationStartTime(cleanTime)) {
      return res.status(400).json({ error: "Reservation must start hourly between 11:00 and 18:00" });
    }

    const customer = await getCurrentCustomerProfile(req.session.user.user_id);
    if (!customer) {
      return res.status(404).json({ error: "Customer profile not found" });
    }

    const branchRow = await findActiveBranchById(branchId);
    if (!branchRow) {
      return res.status(400).json({ error: "Selected branch is unavailable" });
    }

    const tablesNeeded = calculateTablesNeeded(paxValue);
    if (tablesNeeded > TABLES_PER_BRANCH) {
      return res.status(400).json({ error: "Pax exceeds branch capacity" });
    }

    const duplicate = await hasDuplicateActiveReservation(
      req.session.user.user_id,
      branchId,
      reservation_date,
      cleanTime
    );

    if (duplicate) {
      return res.status(409).json({
        error: "You already have an overlapping reservation for this branch"
      });
    }

    const usedTables = await getUsedTablesForSlot(branchId, reservation_date, cleanTime);
    const assignedTables = pickAvailableTables(usedTables, tablesNeeded);

    if (!assignedTables) {
      return res.status(409).json({
        error: "No available tables for this branch and time slot"
      });
    }

    const assignedTablesText = formatAssignedTables(assignedTables);

    const [result] = await pool.execute(
      `INSERT INTO reservations
        (user_id, full_name, email, phone, reservation_date, reservation_time, guests_count, branch_id, status, reservation_note, tables_needed, assigned_tables)
       VALUES
        (?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?)`,
      [
        customer.id,
        customer.full_name,
        customer.email,
        customer.phone,
        reservation_date,
        cleanTime,
        paxValue,
        branchId,
        cleanNote,
        tablesNeeded,
        assignedTablesText,
      ]
    );

    audit("reservation.create", {
      ip: req.ip,
      user_id: req.session.user.user_id,
      email: req.session.user.email,
      reservation_id: result.insertId,
      branch_id: branchRow.id,
      branch_name: branchRow.name,
      assigned_tables: assignedTablesText,
      reservation_time: cleanTime,
      reservation_end_time: addHoursToTime(cleanTime, RESERVATION_DURATION_HOURS),
    });

    return res.json({
      message: "Reservation created successfully",
      assigned_tables: assignedTablesText,
      reservation_end_time: addHoursToTime(cleanTime, RESERVATION_DURATION_HOURS),
    });
  } catch (err) {
    audit("reservation.create.error", {
      ip: req.ip,
      user_id: req.session.user.user_id,
      message: err.message,
    });
    return res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/reservations/:id/edit", requireUserApi, async (req, res) => {
  try {
    const reservationId = Number(req.params.id);
    const { branch_id, reservation_note, pax, reservation_date, reservation_time } = req.body;

    if (!Number.isInteger(reservationId) || reservationId <= 0) {
      return res.status(400).json({ error: "Invalid reservation id" });
    }

    const branchId = Number(branch_id);
    const cleanNote = String(reservation_note || "").trim();
    const paxValue = Number(pax);
    const cleanTime = normalizeTimeHHMM(reservation_time);

    if (!Number.isInteger(branchId) || branchId <= 0) {
      return res.status(400).json({ error: "Branch is required" });
    }

    if (!isValidReservationText(cleanNote, 300)) {
      return res.status(400).json({ error: "Invalid reservation note" });
    }

    if (!Number.isInteger(paxValue) || paxValue < 1 || paxValue > 80) {
      return res.status(400).json({ error: "Invalid pax" });
    }

    if (!isValidReservationDate(reservation_date)) {
      return res.status(400).json({ error: "Invalid reservation date" });
    }

    if (!cleanTime || !isAllowedReservationStartTime(cleanTime)) {
      return res.status(400).json({ error: "Reservation must start hourly between 11:00 and 18:00" });
    }

    const customer = await getCurrentCustomerProfile(req.session.user.user_id);
    if (!customer) {
      return res.status(404).json({ error: "Customer profile not found" });
    }

    const branchRow = await findActiveBranchById(branchId);
    if (!branchRow) {
      return res.status(400).json({ error: "Selected branch is unavailable" });
    }

    const tablesNeeded = calculateTablesNeeded(paxValue);
    if (tablesNeeded > TABLES_PER_BRANCH) {
      return res.status(400).json({ error: "Pax exceeds branch capacity" });
    }

    const duplicate = await hasDuplicateActiveReservation(
      req.session.user.user_id,
      branchId,
      reservation_date,
      cleanTime,
      reservationId
    );

    if (duplicate) {
      return res.status(409).json({
        error: "You already have an overlapping reservation for this branch"
      });
    }

    const usedTables = await getUsedTablesForSlot(branchId, reservation_date, cleanTime, reservationId);
    const assignedTables = pickAvailableTables(usedTables, tablesNeeded);

    if (!assignedTables) {
      return res.status(409).json({
        error: "No available tables for this branch and time slot"
      });
    }

    const assignedTablesText = formatAssignedTables(assignedTables);

    const [result] = await pool.execute(
      `UPDATE reservations
       SET full_name = ?,
           email = ?,
           phone = ?,
           reservation_date = ?,
           reservation_time = ?,
           guests_count = ?,
           branch_id = ?,
           reservation_note = ?,
           tables_needed = ?,
           assigned_tables = ?
       WHERE id = ?
         AND user_id = ?
         AND LOWER(COALESCE(status, 'pending')) <> 'cancelled'`,
      [
        customer.full_name,
        customer.email,
        customer.phone,
        reservation_date,
        cleanTime,
        paxValue,
        branchId,
        cleanNote,
        tablesNeeded,
        assignedTablesText,
        reservationId,
        req.session.user.user_id,
      ]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: "Reservation not found or cannot be edited" });
    }

    audit("reservation.edit", {
      ip: req.ip,
      user_id: req.session.user.user_id,
      email: req.session.user.email,
      reservation_id: reservationId,
      branch_id: branchRow.id,
      branch_name: branchRow.name,
      assigned_tables: assignedTablesText,
      reservation_time: cleanTime,
      reservation_end_time: addHoursToTime(cleanTime, RESERVATION_DURATION_HOURS),
    });

    return res.json({
      message: "Reservation updated successfully",
      assigned_tables: assignedTablesText,
      reservation_end_time: addHoursToTime(cleanTime, RESERVATION_DURATION_HOURS),
    });
  } catch (err) {
    audit("reservation.edit.error", {
      ip: req.ip,
      user_id: req.session.user.user_id,
      message: err.message,
    });
    return res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/reservations/:id/cancel", requireUserApi, async (req, res) => {
  try {
    const reservationId = Number(req.params.id);

    if (!Number.isInteger(reservationId) || reservationId <= 0) {
      return res.status(400).json({ error: "Invalid reservation id" });
    }

    const [result] = await pool.execute(
      `UPDATE reservations
       SET status = 'cancelled',
           admin_updated_at = NOW()
       WHERE id = ?
         AND user_id = ?`,
      [reservationId, req.session.user.user_id]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: "Reservation not found" });
    }

    audit("reservation.cancel", {
      ip: req.ip,
      user_id: req.session.user.user_id,
      email: req.session.user.email,
      reservation_id: reservationId,
    });

    return res.json({ message: "Reservation cancelled successfully" });
  } catch (err) {
    audit("reservation.cancel.error", {
      ip: req.ip,
      user_id: req.session.user.user_id,
      message: err.message,
    });
    return res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/reservations/:id/delete", requireUserApi, async (req, res) => {
  try {
    const reservationId = Number(req.params.id);

    if (!Number.isInteger(reservationId) || reservationId <= 0) {
      return res.status(400).json({ error: "Invalid reservation id" });
    }

    const [result] = await pool.execute(
      `DELETE FROM reservations
       WHERE id = ?
         AND user_id = ?`,
      [reservationId, req.session.user.user_id]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: "Reservation not found" });
    }

    audit("reservation.delete", {
      ip: req.ip,
      user_id: req.session.user.user_id,
      email: req.session.user.email,
      reservation_id: reservationId,
    });

    return res.json({ message: "Reservation deleted successfully" });
  } catch (err) {
    audit("reservation.delete.error", {
      ip: req.ip,
      user_id: req.session.user.user_id,
      message: err.message,
    });
    return res.status(500).json({ error: "Server error" });
  }
});

// ========================================
// CUSTOMER ORDER ACTIONS
// ========================================
app.get("/api/reservations/:id/orders", requireUserApi, async (req, res) => {
  try {
    const reservationId = Number(req.params.id);

    if (!Number.isInteger(reservationId) || reservationId <= 0) {
      return res.status(400).json({ error: "Invalid reservation id" });
    }

    const [reservationRows] = await pool.execute(
      `SELECT
         r.id,
         r.user_id,
         r.reservation_date,
         r.reservation_time,
         r.status,
         b.name AS branch
       FROM reservations r
       LEFT JOIN branches b ON r.branch_id = b.id
       WHERE r.id = ?
         AND r.user_id = ?
       LIMIT 1`,
      [reservationId, req.session.user.user_id]
    );

    if (reservationRows.length === 0) {
      return res.status(404).json({ error: "Reservation not found" });
    }

    const reservation = reservationRows[0];

    const [orderRows] = await pool.execute(
  `SELECT id, order_text, quantity, created_at
   FROM reservation_orders
   WHERE reservation_id = ?
     AND user_id = ?
   ORDER BY created_at DESC, id DESC`,
  [reservationId, req.session.user.user_id]
);

    return res.json({
      reservation,
      orders: orderRows
    });
  } catch (err) {
    audit("reservation.orders.list.error", {
      ip: req.ip,
      user_id: req.session.user.user_id,
      reservation_id: req.params.id,
      message: err.message,
    });
    return res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/reservations/:id/orders", requireUserApi, async (req, res) => {
  try {
    const reservationId = Number(req.params.id);
    const menuItemId = Number(req.body.menu_item_id);
    const quantity = Number(req.body.quantity);

    if (!Number.isInteger(reservationId) || reservationId <= 0) {
      return res.status(400).json({ error: "Invalid reservation id" });
    }

    if (!Number.isInteger(menuItemId) || menuItemId <= 0) {
      return res.status(400).json({ error: "Please select a menu item" });
    }

    if (!Number.isInteger(quantity) || quantity < 1 || quantity > 10) {
      return res.status(400).json({ error: "Quantity must be from 1 to 10 only" });
    }

    const [reservationRows] = await pool.execute(
      `SELECT id, user_id, status
       FROM reservations
       WHERE id = ?
         AND user_id = ?
       LIMIT 1`,
      [reservationId, req.session.user.user_id]
    );

    if (reservationRows.length === 0) {
      return res.status(404).json({ error: "Reservation not found" });
    }

    const reservation = reservationRows[0];

    if (String(reservation.status || "").toLowerCase() === "cancelled") {
      return res.status(400).json({ error: "Cannot add order to a cancelled reservation" });
    }

    const [menuRows] = await pool.execute(
      `SELECT id, name, is_available
       FROM menu_items
       WHERE id = ?
       LIMIT 1`,
      [menuItemId]
    );

    if (menuRows.length === 0) {
      return res.status(404).json({ error: "Selected menu item not found" });
    }

    const menuItem = menuRows[0];

    if (Number(menuItem.is_available) !== 1) {
      return res.status(400).json({ error: "Selected menu item is unavailable" });
    }

    await pool.execute(
      `INSERT INTO reservation_orders
        (reservation_id, user_id, order_text, quantity)
       VALUES (?, ?, ?, ?)`,
      [reservationId, req.session.user.user_id, menuItem.name, quantity]
    );

    audit("reservation.order.create", {
      ip: req.ip,
      user_id: req.session.user.user_id,
      email: req.session.user.email,
      reservation_id: reservationId,
      menu_item_id: menuItemId,
      order_text: menuItem.name,
      quantity,
    });

    return res.json({ message: "Order saved successfully" });
  } catch (err) {
    audit("reservation.order.create.error", {
      ip: req.ip,
      user_id: req.session.user.user_id,
      reservation_id: req.params.id,
      message: err.message,
    });
    return res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/orders/:orderId/edit", requireUserApi, async (req, res) => {
  try {
    const orderId = Number(req.params.orderId);
    const menuItemId = Number(req.body.menu_item_id);
    const quantity = Number(req.body.quantity);

    if (!Number.isInteger(orderId) || orderId <= 0) {
      return res.status(400).json({ error: "Invalid order id" });
    }

    if (!Number.isInteger(menuItemId) || menuItemId <= 0) {
      return res.status(400).json({ error: "Please select a menu item" });
    }

    if (!Number.isInteger(quantity) || quantity < 1 || quantity > 10) {
      return res.status(400).json({ error: "Quantity must be from 1 to 10 only" });
    }

    const [orderRows] = await pool.execute(
      `SELECT ro.id, ro.user_id, ro.reservation_id, r.status
       FROM reservation_orders ro
       INNER JOIN reservations r ON ro.reservation_id = r.id
       WHERE ro.id = ?
         AND ro.user_id = ?
       LIMIT 1`,
      [orderId, req.session.user.user_id]
    );

    if (orderRows.length === 0) {
      return res.status(404).json({ error: "Order not found" });
    }

    const existingOrder = orderRows[0];

    if (String(existingOrder.status || "").toLowerCase() === "cancelled") {
      return res.status(400).json({ error: "Cannot edit order from a cancelled reservation" });
    }

    const [menuRows] = await pool.execute(
      `SELECT id, name, is_available
       FROM menu_items
       WHERE id = ?
       LIMIT 1`,
      [menuItemId]
    );

    if (menuRows.length === 0) {
      return res.status(404).json({ error: "Selected menu item not found" });
    }

    const menuItem = menuRows[0];

    if (Number(menuItem.is_available) !== 1) {
      return res.status(400).json({ error: "Selected menu item is unavailable" });
    }

    await pool.execute(
      `UPDATE reservation_orders
       SET order_text = ?, quantity = ?
       WHERE id = ?
         AND user_id = ?`,
      [menuItem.name, quantity, orderId, req.session.user.user_id]
    );

    audit("reservation.order.edit", {
      ip: req.ip,
      user_id: req.session.user.user_id,
      email: req.session.user.email,
      order_id: orderId,
      reservation_id: existingOrder.reservation_id,
      menu_item_id: menuItemId,
      order_text: menuItem.name,
      quantity,
    });

    return res.json({ message: "Order updated successfully" });
  } catch (err) {
    audit("reservation.order.edit.error", {
      ip: req.ip,
      user_id: req.session.user.user_id,
      order_id: req.params.orderId,
      message: err.message,
    });
    return res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/orders/:orderId/delete", requireUserApi, async (req, res) => {
  try {
    const orderId = Number(req.params.orderId);

    if (!Number.isInteger(orderId) || orderId <= 0) {
      return res.status(400).json({ error: "Invalid order id" });
    }

    const [rows] = await pool.execute(
      `SELECT id, reservation_id, order_text, quantity
       FROM reservation_orders
       WHERE id = ?
         AND user_id = ?
       LIMIT 1`,
      [orderId, req.session.user.user_id]
    );

    if (rows.length === 0) {
      return res.status(404).json({ error: "Order not found" });
    }

    const order = rows[0];

    await pool.execute(
      `DELETE FROM reservation_orders
       WHERE id = ?
         AND user_id = ?`,
      [orderId, req.session.user.user_id]
    );

    audit("reservation.order.delete", {
      ip: req.ip,
      user_id: req.session.user.user_id,
      email: req.session.user.email,
      order_id: orderId,
      reservation_id: order.reservation_id,
      order_text: order.order_text,
      quantity: order.quantity,
    });

    return res.json({ message: "Order deleted successfully" });
  } catch (err) {
    audit("reservation.order.delete.error", {
      ip: req.ip,
      user_id: req.session.user.user_id,
      order_id: req.params.orderId,
      message: err.message,
    });
    return res.status(500).json({ error: "Server error" });
  }
});
// ========================================
// GLOBAL ERROR HANDLER
// ========================================
app.use((err, req, res, next) => {
  console.error("[UNHANDLED]", err);

  audit("app.error", {
    ip: req.ip,
    method: req.method,
    path: req.originalUrl,
    message: err.message,
  });

  if (res.headersSent) {
    return next(err);
  }

  if (req.originalUrl.startsWith("/api/")) {
    if (DEBUG_ERRORS) {
      return res.status(500).json({
        error: err.message,
        stack: err.stack,
      });
    }

    return res.status(500).json({ error: "Server error" });
  }

  return sendDebugOrGenericError(res, err, "Server error", 500);
});

/* ------------------ START ------------------ */
function startServer() {
  if (USE_HTTPS) {
    try {
      if (fs.existsSync(HTTPS_PFX_PATH)) {
        const pfx = fs.readFileSync(HTTPS_PFX_PATH);

        https.createServer(
          {
            pfx,
            passphrase: HTTPS_PFX_PASSWORD,
          },
          app
        ).listen(PORT, () => {
          console.log(`✅ HTTPS server running at https://localhost:${PORT}`);
          console.log(`📝 Register: https://localhost:${PORT}/register`);
          console.log(`🔐 Login: https://localhost:${PORT}/login`);
        });

        return;
      }

      const key = fs.readFileSync(HTTPS_KEY_PATH);
      const cert = fs.readFileSync(HTTPS_CERT_PATH);

      https.createServer({ key, cert }, app).listen(PORT, () => {
        console.log(`✅ HTTPS server running at https://localhost:${PORT}`);
        console.log(`📝 Register: https://localhost:${PORT}/register`);
        console.log(`🔐 Login: https://localhost:${PORT}/login`);
      });
    } catch (err) {
      console.error("❌ HTTPS startup failed:", err.message);
      process.exit(1);
    }
    return;
  }

  app.listen(PORT, () => {
    console.log(`✅ HTTP server running at http://localhost:${PORT}`);
    console.log(`📝 Register: http://localhost:${PORT}/register`);
    console.log(`🔐 Login: http://localhost:${PORT}/login`);
  });
}

startServer();