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

const ALLOWED_IMAGE_MIME = new Set([
  "image/jpeg",
  "image/png",
  "image/webp",
]);

const MAX_PROFILE_PHOTO_BYTES = 2 * 1024 * 1024; // 2 MB

// Generate random filenames so we do not trust the original filename
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadsDir),
  filename: (req, file, cb) => {
    const randomName = `${Date.now()}_${crypto.randomBytes(16).toString("hex")}`;
    cb(null, randomName); // extension added later after backend signature check
  },
});

const rawRegisterUpload = multer({
  storage,
  limits: {
    fileSize: MAX_PROFILE_PHOTO_BYTES,
    files: 1,
  },
  fileFilter: (req, file, cb) => {
    // First layer only: reject obviously wrong MIME types early
    if (!ALLOWED_IMAGE_MIME.has(file.mimetype)) {
      return cb(new Error("INVALID_UPLOAD_TYPE"));
    }
    cb(null, true);
  },
});

// Wrapper so Multer errors become the same generic registration failure
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
// RATE LIMITING (LOGIN ONLY) - BY IP
// ========================================

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
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

function isValidPHPhone(phone) {
  return /^09\d{9}$/.test((phone || "").trim());
}

// Password policy:
// - min 8 chars
// - uppercase
// - lowercase
// - number
// - special character
// - max 72 bytes because bcrypt only uses first 72 bytes
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


// Detect real file type from magic bytes, not extension or frontend input
function detectImageMimeFromMagic(filePath) {
  const fd = fs.openSync(filePath, "r");
  const buffer = Buffer.alloc(12);

  try {
    fs.readSync(fd, buffer, 0, 12, 0);
  } finally {
    fs.closeSync(fd);
  }

  // JPEG: FF D8 FF
  if (buffer[0] === 0xff && buffer[1] === 0xd8 && buffer[2] === 0xff) {
    return "image/jpeg";
  }

  // PNG: 89 50 4E 47 0D 0A 1A 0A
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

  // WEBP: "RIFF" .... "WEBP"
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
// ADMIN GUARD (session-based)
// ========================================
function requireAdmin(req, res, next) {
  if (!req.session || !req.session.admin) {
    return res.redirect("/login"); // unified login
  }
  next();
}

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

const registerLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // max 5 registration attempts per IP
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    return res.redirect("/register?error=1");
  },
});
/* ------------------ REGISTER ------------------ */
app.post("/register", registerLimiter, registerUpload, async (req, res) => {
  let uploadedFilePath = req.file?.path || null;

  try {
    const { full_name, email, phone, password, confirm_password } = req.body;

    // CAPTCHA token from Google
    const captchaToken = req.body["g-recaptcha-response"];

    // Verify CAPTCHA server-side
    const captchaOk = await verifyRecaptchaV2(captchaToken, req.ip);
    if (!captchaOk) {
      console.warn("[REGISTER] CAPTCHA failed for IP:", req.ip);
      safeUnlink(uploadedFilePath);
      return res.redirect("/register?error=1");
    }

    // Required fields
    if (!full_name || !email || !phone || !password || !confirm_password) {
      safeUnlink(uploadedFilePath);
      return res.redirect("/register?error=1");
    }

    const cleanName = full_name.trim().replace(/\s+/g, " ");
    const cleanEmail = email.toLowerCase().trim();
    const cleanPhone = phone.trim();

    if (!cleanName || cleanName.length > 160) {
      safeUnlink(uploadedFilePath);
      return res.redirect("/register?error=1");
    }

    // Keep your current email validation because it is already acceptable and simple
    if (!isValidEmail(cleanEmail)) {
      safeUnlink(uploadedFilePath);
      return res.redirect("/register?error=1");
    }

    // Add backend phone validation
    if (!isValidPHPhone(cleanPhone)) {
      safeUnlink(uploadedFilePath);
      return res.redirect("/register?error=1");
    }

    // Do not trim passwords; compare exactly what user typed
    if (password !== confirm_password) {
      safeUnlink(uploadedFilePath);
      return res.redirect("/register?error=1");
    }

    if (!isStrongPassword(password)) {
      safeUnlink(uploadedFilePath);
      return res.redirect("/register?error=1");
    }

    if (!req.file || !uploadedFilePath) {
      return res.redirect("/register?error=1");
    }

    // BACKEND file signature check
    const detectedMime = detectImageMimeFromMagic(uploadedFilePath);
    const safeExt = mimeToSafeExtension(detectedMime);

    if (!detectedMime || !safeExt) {
      console.warn("[REGISTER] Invalid image signature");
      safeUnlink(uploadedFilePath);
      return res.redirect("/register?error=1");
    }

    // Rename saved file to correct safe extension
    const finalFilename = `${req.file.filename}${safeExt}`;
    const finalPath = path.join(uploadsDir, finalFilename);
    fs.renameSync(uploadedFilePath, finalPath);
    uploadedFilePath = finalPath;

    const photo_path = `/public/uploads/${finalFilename}`;

    // Hash password with cost factor above 12
    const password_hash = await bcrypt.hash(password, 13);

    // Email verification token
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

    // Send verification email
    const baseUrl = (process.env.APP_BASE_URL || `http://localhost:${PORT}`).replace(/\/$/, "");
    const verifyUrl = `${baseUrl}/verify-email?email=${encodeURIComponent(cleanEmail)}&token=${rawToken}`;

    try {
      await sendVerificationEmail({
        toEmail: cleanEmail,
        fullName: cleanName,
        verifyUrl,
      });
      return res.redirect("/login?verify=1");
    } catch (mailErr) {
      console.error("Email send failed:", mailErr?.message || mailErr);
      return res.redirect("/login?verify=0");
    }

  } catch (err) {
    safeUnlink(uploadedFilePath);

    if (err.code === "ER_DUP_ENTRY") {
      console.warn("[REGISTER] Duplicate email attempt");
    } else {
      console.error("[REGISTER] Unexpected error:", err);
    }

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
