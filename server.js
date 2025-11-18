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
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "change_this_to_a_strong_secret";

const UPLOAD_DIR = path.join(__dirname, "uploads");
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR);

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, UPLOAD_DIR);
  },
  filename: function (req, file, cb) {
    const unique = Date.now() + "-" + Math.round(Math.random()*1e6);
    cb(null, unique + "-" + file.originalname.replace(/\s+/g, "_"));
  }
});
const upload = multer({ storage });

let pool;
async function initDb() {
  pool = mysql.createPool({
    host: process.env.DB_HOST || "127.0.0.1",
    user: process.env.DB_USER || "root",
    password: process.env.DB_PASS || "",
    database: process.env.DB_NAME || "regs_insight",
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
  });
  // create tables if not exist
  const usersSql = `CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(150),
    email VARCHAR(255) UNIQUE,
    password_hash VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  )`;
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
  )`;
  const conn = await pool.getConnection();
  await conn.query(usersSql);
  await conn.query(docsSql);
  conn.release();
}
initDb().catch(err => { console.error("DB init error:", err); process.exit(1); });

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

// signup
app.post("/api/signup", async (req, res) => {
  const { name, email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: "email/password required" });
  const hashed = await bcrypt.hash(password, 10);
  try {
    const [result] = await pool.query("INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)", [name || null, email, hashed]);
    const id = result.insertId;
    const token = jwt.sign({ id, email }, JWT_SECRET, { expiresIn: "12h" });
    res.json({ token, id, email });
  } catch (err) {
    if (err && err.code === "ER_DUP_ENTRY") return res.status(400).json({ error: "User already exists" });
    console.error(err);
    res.status(500).json({ error: "internal" });
  }
});

// login
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;
  const [rows] = await pool.query("SELECT * FROM users WHERE email = ?", [email]);
  if (!rows || rows.length === 0) return res.status(400).json({ error: "invalid" });
  const user = rows[0];
  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) return res.status(400).json({ error: "invalid" });
  const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: "12h" });
  res.json({ token, id: user.id, email: user.email, name: user.name });
});

// upload endpoint (auth required)
app.post("/api/upload", authMiddleware, upload.single("file"), async (req, res) => {
  try {
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
    console.error(err);
    res.status(500).json({ error: "upload failed" });
  }
});

// list user's documents
app.get("/api/mydocs", authMiddleware, async (req, res) => {
  const [rows] = await pool.query("SELECT * FROM documents WHERE user_id = ? ORDER BY created_at DESC", [req.user.id]);
  res.json(rows);
});

// search documents by name/type/date (public for now, but can require auth)
app.get("/api/search", async (req, res) => {
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

// serve uploaded files
app.use("/uploads", express.static(path.join(__dirname, "uploads")));

// serve static UI
app.use("/", express.static(path.join(__dirname, "public")));

app.listen(PORT, () => {
  console.log("Server listening on port", PORT);
});

/*
  DELETE /api/documents/:id
  Auth required — deletes DB record and removes uploaded file from disk.
*/
app.delete("/api/documents/:id", authMiddleware, async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    if (!id) return res.status(400).json({ error: "invalid id" });
    const [rows] = await pool.query("SELECT file_path, user_id FROM documents WHERE id = ?", [id]);
    if (!rows || rows.length === 0) return res.status(404).json({ error: "not found" });
    const doc = rows[0];
    // Only allow owner or admin (for now allow owner)
    if (doc.user_id !== req.user.id) return res.status(403).json({ error: "forbidden" });
    // remove file if exists
    const fp = path.join(__dirname, doc.file_path || "");
    try { if (fp && fs.existsSync(fp)) fs.unlinkSync(fp); } catch(e) { console.error("unlink error", e); }
    await pool.query("DELETE FROM documents WHERE id = ?", [id]);
    return res.json({ ok: true });
  } catch (err) {
    console.error("delete error", err);
    return res.status(500).json({ error: "delete failed" });
  }
});

