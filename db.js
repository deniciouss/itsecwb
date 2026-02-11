const mysql = require("mysql2/promise");

const pool = mysql.createPool({
  host: process.env.DB_HOST || "localhost",
  user: process.env.DB_USER || "samgyup_user",
  password: process.env.DB_PASS || "",
  database: process.env.DB_NAME || "samgyup_db",
  waitForConnections: true,
  connectionLimit: Number(process.env.DB_CONNECTION_LIMIT || 10),
});

module.exports = pool;
