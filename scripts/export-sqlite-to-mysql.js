"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { DatabaseSync } = require("node:sqlite");

const [databasePath, sqlPath, resetCodesPath] = process.argv.slice(2);
if (!databasePath || !sqlPath || !resetCodesPath) {
  console.error("Usage: node scripts/export-sqlite-to-mysql.js <sqlite-file> <mysql-dump.sql> <reset-codes.csv>");
  process.exit(2);
}

const outputs = [path.resolve(sqlPath), path.resolve(resetCodesPath)];
if (outputs[0] === outputs[1] || outputs.includes(path.resolve(databasePath))) {
  console.error("Choose different paths for the source database and both export files.");
  process.exit(2);
}

const database = new DatabaseSync(path.resolve(databasePath), { readOnly: true });
const tables = [
  ["users", ["id", "first_name", "last_name", "email", "account_type", "phone", "wilaya", "password_salt", "password_hash", "created_at"], "id"],
  ["services", ["id", "owner_id", "title", "category", "area", "price", "description", "created_at"], "created_at"],
  ["conversations", ["id", "service_id", "requester_id", "updated_at"], "updated_at"],
  ["conversation_participants", ["conversation_id", "user_id"], "conversation_id, user_id"],
  ["messages", ["id", "conversation_id", "sender_id", "text", "created_at"], "id"],
  ["provider_reviews", ["id", "provider_id", "reviewer_id", "rating", "comment", "created_at", "updated_at"], "id"],
  ["admin_audit_log", ["id", "action", "resource_id", "created_at"], "id"],
];
const createdOutputs = [];
let sqlFd;
let csvFd;

function sqlValue(value) {
  if (value === null) return "NULL";
  if (typeof value === "number" || typeof value === "bigint") return String(value);
  const hex = Buffer.from(String(value), "utf8").toString("hex");
  return `CONVERT(X'${hex}' USING utf8mb4)`;
}

function csvValue(value) {
  const text = String(value ?? "");
  return `"${text.replace(/"/g, '""')}"`;
}

try {
  const availableTables = new Set(database.prepare(
    "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
  ).all().map(({ name }) => name));
  for (const [table, columns] of tables) {
    if (!availableTables.has(table)) {
      throw new Error(`The SQLite database is missing required table "${table}".`);
    }
    const availableColumns = new Set(database.prepare(`PRAGMA table_info("${table}")`).all().map(({ name }) => name));
    const missing = columns.filter((column) => !availableColumns.has(column));
    if (missing.length) {
      throw new Error(`Table "${table}" is missing required columns: ${missing.join(", ")}.`);
    }
  }

  for (const output of outputs) {
    const fd = fs.openSync(output, "wx");
    createdOutputs.push(output);
    if (output === outputs[0]) sqlFd = fd;
    else csvFd = fd;
  }

  const writeSql = (text) => fs.writeSync(sqlFd, text);
  writeSql("-- Import this into a freshly created database after api/schema.sql.\n");
  writeSql("-- User sessions are intentionally not migrated. Existing users need one-time reset codes.\n");
  writeSql("SET FOREIGN_KEY_CHECKS = 0;\nSTART TRANSACTION;\n");

  const resetCodes = ['"email","reset_code","expires_at"'];
  const tokenExpiry = Date.now() + 30 * 24 * 60 * 60 * 1000;
  const userRows = database.prepare("SELECT id, email FROM users ORDER BY id").all();
  for (const user of userRows) {
    const token = crypto.randomBytes(32).toString("base64url");
    const tokenHash = crypto.createHash("sha256").update(token).digest("hex");
    writeSql(
      "INSERT INTO migration_reset_tokens (token_hash, user_id, expires_at) VALUES (" +
      [tokenHash, user.id, tokenExpiry].map(sqlValue).join(", ") +
      ");\n"
    );
    resetCodes.push([user.email, token, new Date(tokenExpiry).toISOString()].map(csvValue).join(","));
  }

  for (const [table, columns, orderBy] of tables) {
    const rows = database.prepare(`SELECT ${columns.map((column) => `"${column}"`).join(", ")} FROM "${table}" ORDER BY ${orderBy}`).all();
    for (const row of rows) {
      writeSql(
        `INSERT INTO \`${table}\` (${columns.map((column) => `\`${column}\``).join(", ")}) VALUES (` +
        columns.map((column) => sqlValue(row[column])).join(", ") +
        ");\n"
      );
    }
  }

  writeSql("COMMIT;\nSET FOREIGN_KEY_CHECKS = 1;\n");
  fs.writeSync(csvFd, resetCodes.join("\r\n") + "\r\n");
  console.log(`Exported ${userRows.length} account reset codes and data for ${tables.length} tables.`);
  console.log(`MySQL import: ${outputs[0]}`);
  console.log(`Keep this private and deliver each code to its account owner: ${outputs[1]}`);
} catch (error) {
  for (const fd of [sqlFd, csvFd]) {
    if (fd !== undefined) {
      try { fs.closeSync(fd); } catch {}
      if (fd === sqlFd) sqlFd = undefined;
      if (fd === csvFd) csvFd = undefined;
    }
  }
  for (const output of createdOutputs) {
    try { fs.unlinkSync(output); } catch {}
  }
  console.error(`Export failed: ${error.message}`);
  process.exitCode = 1;
} finally {
  database.close();
}

if (sqlFd !== undefined) fs.closeSync(sqlFd);
if (csvFd !== undefined) fs.closeSync(csvFd);
