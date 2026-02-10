const express = require("express");
const path = require("path");
const multer = require("multer");
const pool = require("./db");
const fs = require("fs");
const bcrypt = require("bcryptjs");
const rateLimit = require("express-rate-limit");

const app = express();
const PORT = 3000;

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

/* ------------------ REGISTER ------------------ */

app.post("/register", upload.single("photo"), async (req, res) => {
  try {
    const { full_name, email, phone, password, confirm_password } = req.body;

    // required fields
    if (!full_name || !email || !phone || !password || !confirm_password) {
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

    const photo_path = "/public/uploads/" + req.file.filename;
    const password_hash = await bcrypt.hash(password, 12);

    await pool.execute(
      `INSERT INTO users (full_name, email, phone, password_hash, photo_path)
       VALUES (?, ?, ?, ?, ?)`,
      [
        full_name.trim(),
        email.toLowerCase().trim(),
        phone.trim(),
        password_hash,
        photo_path
      ]
    );

    return res.redirect("/login?registered=1");

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

    // ========================================
    // INPUT VALIDATION
    // ========================================

    // Check if fields exist
    if (!email || !password) {
      return res.status(400).json({ error: "Invalid input" });
    }

    // Trim whitespace only (NO sanitization)
    email = email.trim();
    password = password.trim();

    // STRICT EMAIL VALIDATION
    if (!isValidEmail(email)) {
      return res.status(400).json({ error: "Invalid input" });
    }

    // Password length validation
    if (password.length < 8 || password.length > 128) {
      return res.status(400).json({ error: "Invalid input" });
    }

    // ========================================
    // DATABASE QUERY
    // Parameterized query prevents SQL injection
    // ========================================

    const [rows] = await pool.execute(
      `SELECT
         id AS user_id,
         full_name,
         email,
         phone,
         photo_path,
         password_hash
       FROM users
       WHERE email = ?`,
      [email.toLowerCase()]
    );

    // User not found - generic error
    if (rows.length === 0) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const user = rows[0];

    // ========================================
    // PASSWORD VERIFICATION
    // Password sent exactly as typed, compared with hash
    // ========================================

    const passwordMatch = await bcrypt.compare(password, user.password_hash);
    
    if (!passwordMatch) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    // ========================================
    // SUCCESS RESPONSE
    // ========================================

    return res.json({
      message: "Login successful",
      user: {
        user_id: user.user_id,
        full_name: user.full_name,
        email: user.email,
        phone: user.phone,
        photo_path: user.photo_path
      }
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