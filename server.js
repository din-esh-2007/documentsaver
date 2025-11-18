/**
 * server.js
 * Robust server with DB pool, health route, auth, upload, search endpoints.
 * Generated to include DB_PORT support and health check.
 */
require("dotenv").config();
const express = require("express");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const mysql = require("mysql2/promise");
const cors = require("cors");

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors());

// static /uploads and public
const UPLOAD_DIR = path.join(__dirname, "uploads");
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });
app.use("/uploads", express.static(UPLOAD_DIR));
app.use("/", express.static(path.join(__dirname, "public")));

// JWT secret
const JWT_SECRET = process.env.JWT_SECRET || "change_this_secret_in_env";

// create mysql pool using port support
const DB_HOST = process.env.DB_HOST || "127.0.0.1";
const DB_PORT = process.env.DB_PORT ? Number(process.env.DB_PORT) : 3306;
const DB_USER = process.env.DB_USER || "root";
const DB_PASS = process.env.DB_PASS || "";
const DB_NAME = process.env.DB_NAME || "regs_insight";

let pool;
async function initPool() {
  try {
    pool = mysql.createPool({
      host: DB_HOST,
      port: DB_PORT,
      user: DB_USER,
      password: DB_PASS,
      database: DB_NAME,
      waitForConnections: true,
      connectionLimit: 10,
      connectTimeout: 10000,
    });
    // quick test
    const conn = await pool.getConnection();
    await conn.ping();
    conn.release();
    console.log("DB pool created and ping OK:", DB_HOST + ":" + DB_PORT, "db:", DB_NAME);
  } catch (e) {
    console.error("DB init error:", e && e.message ? e.message : e);
    // keep pool possibly undefined; app will still run but health will show db_connected:false
  }
}

// ensure database + tables if possible (safe when DB reachable)
async function ensureTables() {
  try {
    // If DB doesn't exist, try creating it (needs user permissions)
    const adminConn = await mysql.createConnection({ host: DB_HOST, port: DB_PORT, user: DB_USER, password: DB_PASS, multipleStatements: true });
    await adminConn.query(`CREATE DATABASE IF NOT EXISTS \`${DB_NAME}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;`);
    await adminConn.end();
    // create tables in DB
    const conn = await pool.getConnection();
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
    await conn.query(usersSql);
    await conn.query(docsSql);
    conn.release();
    console.log("Tables ensured.");
  } catch (e) {
    console.error("Failed to ensure tables:", e && e.message ? e.message : e);
  }
}

// Initialize DB pool and tables asynchronously
(async () => {
  await initPool();
  if (pool) await ensureTables();
})();

// multer for uploads
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, UPLOAD_DIR);
  },
  filename: function (req, file, cb) {
    const unique = Date.now() + "-" + Math.round(Math.random() * 1e9);
    cb(null, unique + path.extname(file.originalname));
  }
});
const upload = multer({ storage });

// auth middleware
function authMiddleware(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ error: "Missing auth" });
  const parts = header.split(" ");
  if (parts.length !== 2) return res.status(401).json({ error: "Bad auth" });
  const token = parts[1];
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    next();
  } catch (e) {
    return res.status(401).json({ error: "Invalid token" });
  }
}

// health endpoint
app.get("/api/health", async (req, res) => {
  try {
    if (pool) {
      try {
        const conn = await pool.getConnection();
        await conn.ping();
        conn.release();
        return res.json({ ok: true, db_connected: true });
      } catch (e) {
        return res.json({ ok: true, db_connected: false, error: String(e.message || e) });
      }
    } else {
      return res.json({ ok: true, db_connected: false, error: "no-db-pool" });
    }
  } catch (err) {
    return res.json({ ok: false, error: String(err.message || err) });
  }
});

// signup
app.post("/api/signup", async (req, res) => {
  const { name, email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: "email/password required" });
  try {
    const hashed = await bcrypt.hash(password, 10);
    const [result] = await pool.query("INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)", [name || null, email, hashed]);
    const id = result.insertId;
    const token = jwt.sign({ id, email }, JWT_SECRET, { expiresIn: "12h" });
    res.json({ token, id, email });
  } catch (err) {
    console.error("signup error:", err && err.message ? err.message : err);
    if (err && err.code === "ER_DUP_ENTRY") return res.status(400).json({ error: "User already exists" });
    res.status(500).json({ error: "internal" });
  }
});

// login
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const [rows] = await pool.query("SELECT * FROM users WHERE email = ?", [email]);
    if (!rows || rows.length === 0) return res.status(400).json({ error: "invalid" });
    const user = rows[0];
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(400).json({ error: "invalid" });
    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: "12h" });
    res.json({ token, id: user.id, email: user.email, name: user.name });
  } catch (err) {
    console.error("login error:", err && err.message ? err.message : err);
    res.status(500).json({ error: "internal" });
  }
});

// upload endpoint (auth required)
app.post("/api/upload", authMiddleware, upload.single("file"), async (req, res) => {
  try {
    const userId = req.user.id;
    const { document_name, document_type, document_date } = req.body;
    if (!req.file) return res.status(400).json({ error: "file required" });
    const filePath = path.relative(__dirname, req.file.path).replace(/\\\\/g, "/").replace(/\\/g, "/");
    await pool.query(
      "INSERT INTO documents (user_id, document_name, document_type, document_date, file_path, original_filename) VALUES (?, ?, ?, ?, ?, ?)",
      [userId, document_name || req.file.originalname, document_type || null, document_date || null, filePath, req.file.originalname]
    );
    res.json({ ok: true });
  } catch (err) {
    console.error("upload failed:", err && err.message ? err.message : err);
    res.status(500).json({ error: "upload failed" });
  }
});

// list user's documents
app.get("/api/mydocs", authMiddleware, async (req, res) => {
  try {
    const [rows] = await pool.query("SELECT * FROM documents WHERE user_id = ? ORDER BY created_at DESC", [req.user.id]);
    res.json(rows);
  } catch (err) {
    console.error("mydocs error:", err && err.message ? err.message : err);
    res.status(500).json({ error: "internal" });
  }
});

// delete document (auth required)
app.delete("/api/documents/:id", authMiddleware, async (req, res) => {
  try {
    const id = req.params.id;
    // fetch file path to delete file from disk
    const [rows] = await pool.query("SELECT * FROM documents WHERE id = ?", [id]);
    if (!rows || rows.length === 0) return res.status(404).json({ error: "not found" });
    const doc = rows[0];
    if (String(doc.user_id) !== String(req.user.id)) return res.status(403).json({ error: "forbidden" });
    // remove file
    if (doc.file_path) {
      try { fs.unlinkSync(path.join(__dirname, doc.file_path)); } catch (e) { /* ignore */ }
    }
    await pool.query("DELETE FROM documents WHERE id = ?", [id]);
    res.json({ ok: true });
  } catch (err) {
    console.error("delete error:", err && err.message ? err.message : err);
    res.status(500).json({ error: "internal" });
  }
});

// search documents (public)
app.get("/api/search", async (req, res) => {
  try {
    const { q, type, date } = req.query;
    let sql = "SELECT d.*, u.email as uploaded_by FROM documents d LEFT JOIN users u ON u.id = d.user_id WHERE 1=1";
    const params = [];
    if (q) { sql += " AND (d.document_name LIKE ? OR d.original_filename LIKE ?)"; params.push("%"+q+"%","%"+q+"%"); }
    if (type) { sql += " AND d.document_type = ?"; params.push(type); }
    if (date) { sql += " AND d.document_date = ?"; params.push(date); }
    sql += " ORDER BY d.created_at DESC LIMIT 200";
    const [rows] = await pool.query(sql, params);
    res.json(rows);
  } catch (err) {
    console.error("search error:", err && err.message ? err.message : err);
    res.status(500).json({ error: "internal" });
  }
});

// fallback: serve static UI
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// start server
const PORT = process.env.PORT ? Number(process.env.PORT) : 3000;
app.listen(PORT, () => {
  console.log("Server listening on port", PORT);
});
