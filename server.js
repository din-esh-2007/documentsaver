require("dotenv").config();
const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const path = require("path");
const multer = require("multer");
const fs = require("fs");
const mysql = require("mysql2/promise");

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "change_this_to_a_strong_secret";

// DB config via env (fallback to localhost for local dev)
const DB_HOST = process.env.DB_HOST || "127.0.0.1";
const DB_USER = process.env.DB_USER || "root";
const DB_PASS = process.env.DB_PASS || "";
const DB_NAME = process.env.DB_NAME || "regs_insight";

let pool = null; // will be set if DB connects

async function initDb() {
  try {
    const conn = await mysql.createConnection({
      host: DB_HOST,
      user: DB_USER,
      password: DB_PASS,
      multipleStatements: true,
      // If your DB provider requires SSL, uncomment below:
      // ssl: { rejectUnauthorized: true }
    });

    await conn.query(`CREATE DATABASE IF NOT EXISTS \`${DB_NAME}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;`);
    console.log("Database created or already exists:", DB_NAME);
    await conn.end();

    pool = mysql.createPool({
      host: DB_HOST,
      user: DB_USER,
      password: DB_PASS,
      database: DB_NAME,
      waitForConnections: true,
      connectionLimit: 10,
      queueLimit: 0,
      // ssl: { rejectUnauthorized: true } // uncomment if your DB requires SSL
    });

    const usersSql = `CREATE TABLE IF NOT EXISTS users (
      id INT AUTO_INCREMENT PRIMARY KEY,
      name VARCHAR(150),
      email VARCHAR(255) UNIQUE,
      password_hash VARCHAR(255),
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;`;

    const docsSql = `CREATE TABLE IF NOT EXISTS documents (
      id INT AUTO_INCREMENT PRIMARY KEY,
      user_id INT,
      document_name VARCHAR(500),
      document_type VARCHAR(200),
      document_date DATE,
      file_path VARCHAR(1000),
      original_filename VARCHAR(500),
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;`;

    const conn2 = await pool.getConnection();
    await conn2.query(usersSql);
    await conn2.query(docsSql);
    conn2.release();

    console.log("Tables ensured.");
  } catch (err) {
    console.error("DB init error:", err && err.message ? err.message : err);
    console.error("Server will keep running but DB is not connected. Set DB_HOST/DB_USER/DB_PASS/DB_NAME and re-deploy.");
    pool = null;
  }
}

// run DB init asynchronously
initDb();

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ensure uploads folder exists
const uploadsDir = path.join(__dirname, "uploads");
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });

const storage = multer.diskStorage({
  destination: function (req, file, cb) { cb(null, uploadsDir); },
  filename: function (req, file, cb) { cb(null, Date.now() + "-" + file.originalname.replace(/\s+/g, "_")); }
});
const upload = multer({ storage });

function authMiddleware(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ error: "Missing Authorization header" });
  const parts = header.split(" ");
  if (parts.length !== 2) return res.status(401).json({ error: "Bad Authorization header" });
  const token = parts[1];
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    next();
  } catch (e) {
    return res.status(401).json({ error: "Invalid token" });
  }
}

// Signup
app.post("/api/signup", async (req, res) => {
  const { name, email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: "email and password required" });
  if (!pool) return res.status(500).json({ error: "DB not initialized" });

  try {
    const hashed = await bcrypt.hash(password, 10);
    const [result] = await pool.query("INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)", [name || null, email, hashed]);
    const id = result.insertId;
    const token = jwt.sign({ id, email }, JWT_SECRET, { expiresIn: "12h" });
    res.json({ token, id, email });
  } catch (err) {
    if (err && err.code === "ER_DUP_ENTRY") return res.status(400).json({ error: "User already exists" });
    console.error("Signup error:", err);
    res.status(500).json({ error: "internal" });
  }
});

// Login
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;
  if (!pool) return res.status(500).json({ error: "DB not initialized" });
  const [rows] = await pool.query("SELECT * FROM users WHERE email = ?", [email]);
  if (!rows || rows.length === 0) return res.status(400).json({ error: "invalid" });
  const user = rows[0];
  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) return res.status(400).json({ error: "invalid" });
  const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: "12h" });
  res.json({ token, id: user.id, email: user.email, name: user.name });
});

// Upload endpoint (auth required)
app.post("/api/upload", authMiddleware, upload.single("file"), async (req, res) => {
  try {
    if (!pool) return res.status(500).json({ error: "DB not initialized" });
    const userId = req.user.id;
    const { document_name, document_type, document_date } = req.body;
    if (!req.file) return res.status(400).json({ error: "file required" });
    const filePath = path.relative(__dirname, req.file.path);
    await pool.query(
      "INSERT INTO documents (user_id, document_name, document_type, document_date, file_path, original_filename) VALUES (?, ?, ?, ?, ?, ?)",
      [userId, document_name || req.file.originalname, document_type || null, document_date || null, filePath, req.file.originalname]
    );
    res.json({ ok: true });
  } catch (err) {
    console.error("Upload error:", err);
    res.status(500).json({ error: "upload failed" });
  }
});

// list user's documents
app.get("/api/mydocs", authMiddleware, async (req, res) => {
  if (!pool) return res.status(500).json({ error: "DB not initialized" });
  const [rows] = await pool.query("SELECT * FROM documents WHERE user_id = ? ORDER BY created_at DESC", [req.user.id]);
  res.json(rows);
});

// search documents
app.get("/api/search", async (req, res) => {
  if (!pool) return res.status(500).json({ error: "DB not initialized" });
  const { q, type, date } = req.query;
  let sql = "SELECT d.*, u.email as uploaded_by FROM documents d LEFT JOIN users u ON u.id = d.user_id WHERE 1=1";
  const params = [];
  if (q) { sql += " AND (d.document_name LIKE ? OR d.original_filename LIKE ?)"; params.push("%"+q+"%","%"+q+"%"); }
  if (type) { sql += " AND d.document_type = ?"; params.push(type); }
  if (date) { sql += " AND d.document_date = ?"; params.push(date); }
  sql += " ORDER BY d.created_at DESC LIMIT 200";
  const [rows] = await pool.query(sql, params);
  res.json(rows);
});

// serve uploads and static UI
app.use("/uploads", express.static(path.join(__dirname, "uploads")));
app.use("/", express.static(path.join(__dirname, "public")));

// small healthcheck
app.get("/health", (req, res) => {
  res.json({ ok: true, db_connected: !!pool });
});

app.listen(PORT, () => {
  console.log("Server listening on port", PORT);
});
