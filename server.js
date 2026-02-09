const express = require("express");
const path = require("path");
const multer = require("multer");
const pool = require("./db");
const fs = require("fs");

const app = express();
const PORT = 3000;

// parse form fields
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

// serve uploaded images (so you can open them in browser)
app.use("/public", express.static(path.join(__dirname, "public")));

// CREATE UPLOADS DIRECTORY IF IT DOESN'T EXIST
const uploadsDir = path.join(__dirname, "public", "uploads");
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
  console.log("✅ Created uploads directory at:", uploadsDir);
} else {
  console.log("✅ Uploads directory exists at:", uploadsDir);
}

// Multer upload setup (basic)
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadsDir);
  },
  filename: (req, file, cb) => {
    // basic filename: timestamp + original name
    const safeName = file.originalname.replace(/[^a-zA-Z0-9._-]/g, "_");
    cb(null, Date.now() + "_" + safeName);
  },
});

const upload = multer({ storage });

// Show login page
app.get("/login", (req, res) => {
  res.sendFile(path.join(__dirname, "views", "login.html"));
});

// Handle login API
app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: "Email and password are required" });
    }

    // Query user by email
    const [rows] = await pool.execute(
      `SELECT user_id, full_name, email, phone, photo_path, role_id 
       FROM users 
       WHERE email = ?`,
      [email.toLowerCase()]
    );

    if (rows.length === 0) {
      return res.status(401).json({ error: "Invalid email or password" });
    }

    const user = rows[0];

    res.json({
      message: "Login successful",
      user: {
        user_id: user.user_id,
        full_name: user.full_name,
        email: user.email,
        phone: user.phone,
        photo_path: user.photo_path,
        role_id: user.role_id || 1
      }
    });

  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// Show welcome page
app.get("/welcome", (req, res) => {
  res.sendFile(path.join(__dirname, "views", "welcome.html"));
});


// Show register page
app.get("/register", (req, res) => {
  res.sendFile(path.join(__dirname, "views", "register.html"));
});

// Handle registration
app.post("/register", upload.single("photo"), async (req, res) => {
  try {
    const { full_name, email, phone } = req.body;

    if (!req.file) {
      return res.status(400).send("Profile photo is required.");
    }

    // store a relative URL path
    const photo_path = "/public/uploads/" + req.file.filename;

    await pool.execute(
      `INSERT INTO users (full_name, email, phone, photo_path)
       VALUES (?, ?, ?, ?)`,
      [full_name, email.toLowerCase(), phone, photo_path]
    );

    res.send(`
      <h3>Registered successfully!</h3>
      <p>Name: ${full_name}</p>
      <p>Email: ${email}</p>
      <p>Phone: ${phone}</p>
      <p>Photo: <a href="${photo_path}" target="_blank">View Upload</a></p>
      <p><a href="/login">Go to Login</a></p>
    `);
  } catch (err) {
    console.error(err);

    // if duplicate email
    if (err.code === "ER_DUP_ENTRY") {
      return res.status(400).send("Email already exists. Try another.");
    }

    res.status(500).send("Server error");
  }
});

app.get("/", (req, res) => res.sendFile(path.join(__dirname, "views", "home.html")));
app.get("/branches", (req, res) => res.send("Branches page UI next"));
app.get("/menu", (req, res) => res.send("Menu/Order UI next"));
app.get("/reserve", (req, res) => res.send("Reserve UI next"));
app.get("/track", (req, res) => res.send("Track UI next"));

app.listen(PORT, () => {
  console.log(`✅ Server running at http://localhost:${PORT}`);
  console.log(`📝 Register: http://localhost:${PORT}/register`);
  console.log(`🔐 Login: http://localhost:${PORT}/login`);
});