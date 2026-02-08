const express = require("express");
const path = require("path");
const multer = require("multer");
const pool = require("./db");

const app = express();
const PORT = 3000;

// parse form fields
app.use(express.urlencoded({ extended: false }));

// serve uploaded images (so you can open them in browser)
app.use("/public", express.static(path.join(__dirname, "public")));

// Multer upload setup (basic)
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, path.join(__dirname, "public", "uploads"));
  },
  filename: (req, file, cb) => {
    // basic filename: timestamp + original name
    const safeName = file.originalname.replace(/[^a-zA-Z0-9._-]/g, "_");
    cb(null, Date.now() + "_" + safeName);
  },
});

const upload = multer({ storage });

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
      <p><a href="/register">Register another</a></p>
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
  console.log(`Server running at http://localhost:${PORT}/register`);
});
