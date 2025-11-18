require("dotenv").config();
const mysql = require("mysql2/promise");

async function main(){
  const host = process.env.DB_HOST || "127.0.0.1";
  const user = process.env.DB_USER || "root";
  const pass = process.env.DB_PASS || "";
  const dbName = process.env.DB_NAME || "regs_insight";
  try {
    const conn = await mysql.createConnection({ host, user, password: pass, multipleStatements: true });
    await conn.query(`CREATE DATABASE IF NOT EXISTS \`${dbName}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;`);
    console.log("Database created or already exists:", dbName);
    await conn.end();
  } catch (e) {
    console.error("Failed to create DB — is MySQL server running and are credentials correct? Error:");
    console.error(e.message || e);
    process.exit(1);
  }
}
main();
