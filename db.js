// db.js

const mysql = require("mysql2/promise"); 
const pool = mysql.createPool({ 
  host: "localhost", 
  user: "samgyup_user", 
  password: "Samgyup123!", 
  database: "samgyup_db", 
  waitForConnections: true, 
  connectionLimit: 10 
}); 
  
  module.exports = pool;