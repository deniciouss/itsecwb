
const express = require("express");
const path = require("path");
require("dotenv").config({ path: path.join(__dirname, ".env.local") });


const multer = require("multer");
const pool = require("./db");
const fs = require("fs");
const bcrypt = require("bcryptjs");
const rateLimit = require("express-rate-limit");
const crypto = require("crypto");
const { sendVerificationEmail } = require("./mailer");
const { verifyTransporter } = require("./mailer");

const app = express();
const PORT = process.env.PORT || 3000;

// parse form fields
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

// serve static files (public/css, public/uploads, etc.)
app.use("/public", express.static(path.join(__dirname, "public")));

// CREATE UPLOADS DIRECTORY IF IT DOESN'T EXIST
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
// RATE LIMITING (LOGIN ONLY)
// ========================================

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Max 5 login attempts per 15 minutes
  message: { error: "Too many login attempts. Please try again in 15 minutes." },
  standardHeaders: true,
  legacyHeaders: false,
});

// ========================================
// VALIDATION FUNCTIONS
// ========================================

// Email validation
function isValidEmail(email) {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
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
  const rawToken = crypto.randomBytes(32).toString("hex"); // send to user
  const tokenHash = crypto.createHash("sha256").update(rawToken).digest("hex"); // store in DB
  return { rawToken, tokenHash };
}

/* ------------------ PAGES ------------------ */

app.get("/", (req, res) => res.sendFile(path.join(__dirname, "views", "home.html")));

app.get("/register", (req, res) => {
  res.sendFile(path.join(__dirname, "views", "register.html"));
});

app.get("/login", (req, res) => {
  res.sendFile(path.join(__dirname, "views", "login.html"));
});

app.get("/home", (req, res) => {
  res.sendFile(path.join(__dirname, "views", "home.html"));
});

app.get("/welcome", (req, res) => {
  res.sendFile(path.join(__dirname, "views", "welcome.html"));
});

app.get("/branches", (req, res) => res.send("Branches page UI next"));
app.get("/menu", (req, res) => res.send("Menu/Order UI next"));
app.get("/reserve", (req, res) => res.send("Reserve UI next"));
app.get("/track", (req, res) => res.send("Track UI next"));

/* ------------------ EMAIL VERIFICATION ------------------ */
/**
 * Link looks like:
 * /verify-email?email=someone@email.com&token=<rawToken>
 */

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
      return res.status(400).send("Verification link expired. Please register again (resend flow can be added).");
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

    // required fields
    if (!full_name || !email || !phone || !password || !confirm_password) {
      return res.redirect("/register?error=1");
    }

    // Email validation (you have isValidEmail earlier)
    if (!isValidEmail(email)) {
      return res.redirect("/register?error=1");
    }

    // confirm password
    if (password !== confirm_password) {
      return res.redirect("/register?error=1");
    }

    // strong password
    if (!isStrongPassword(password)) {
      return res.redirect("/register?error=1");
    }

    // photo required
    if (!req.file) {
      return res.redirect("/register?error=1");
    }

    const cleanName = full_name.trim();
    const cleanEmail = email.toLowerCase().trim();
    const cleanPhone = phone.trim();

    const photo_path = "/public/uploads/" + req.file.filename;

    // hash password
    const password_hash = await bcrypt.hash(password, 12);

    // verification token
    const { rawToken, tokenHash } = makeVerificationToken();
    const expires = new Date(Date.now() + 30 * 60 * 1000); // 30 mins

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
    const verifyUrl =
      `${baseUrl}/verify-email?email=${encodeURIComponent(cleanEmail)}&token=${rawToken}`;

    try {
      await sendVerificationEmail({
        toEmail: cleanEmail,
        fullName: cleanName,
        verifyUrl,
      });

      // Redirect to login with "check your email" notification
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


/* ------------------ LOGIN API ------------------ */

app.post("/api/login", loginLimiter, async (req, res) => {
  try {
    let { email, password } = req.body;

    // INPUT VALIDATION
    if (!email || !password) {
      return res.status(400).json({ error: "Invalid input" });
    }

    email = email.trim();
    password = password.trim();

    if (!isValidEmail(email)) {
      return res.status(400).json({ error: "Invalid input" });
    }

    if (password.length < 8 || password.length > 128) {
      return res.status(400).json({ error: "Invalid input" });
    }

    // Query user including verification status
    const [rows] = await pool.execute(
      `SELECT
         id AS user_id,
         full_name,
         email,
         phone,
         photo_path,
         password_hash,
         is_verified
       FROM users
       WHERE email = ?`,
      [email.toLowerCase()]
    );

    if (rows.length === 0) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const user = rows[0];

    // Block login if not verified
    if (user.is_verified !== 1) {
      return res.status(403).json({ error: "Please verify your email before logging in." });
    }

    const passwordMatch = await bcrypt.compare(password, user.password_hash);

    if (!passwordMatch) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

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
    res.status(500).json({ error: "Server error" });
  }
});

/* ------------------ START ------------------ */

app.listen(PORT, () => {
  console.log(`✅ Server running at http://localhost:${PORT}`);
  console.log(`📝 Register: http://localhost:${PORT}/register`);
  console.log(`🔐 Login: http://localhost:${PORT}/login`);
});
