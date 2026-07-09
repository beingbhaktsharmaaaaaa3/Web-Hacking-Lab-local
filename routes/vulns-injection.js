const express = require("express");
const router = express.Router();
const C = require("./vuln-common");
const initSqlJs = require("sql.js");

// ---------------------------------------------------------------------------
// Real SQLite database (sql.js — pure WASM, no native build tools required).
// Seeded once at startup with fake data. This is the ONE lab where the
// "vulnerability" is a genuinely real SQL engine parsing genuinely
// attacker-supplied SQL — perfectly safe because the DB is in-memory and
// contains only fake demo rows.
// ---------------------------------------------------------------------------
let dbReady;
function getDb() {
  if (!dbReady) {
    dbReady = initSqlJs().then((SQL) => {
      const db = new SQL.Database();
      db.run(`CREATE TABLE employees (id INTEGER, username TEXT, password TEXT, role TEXT, dept TEXT, salary TEXT);`);
      db.run(`INSERT INTO employees VALUES
        (1,'alice','Wonderland!1','employee','Engineering','62000'),
        (2,'bob','B0bPass!2','employee','Sales','58000'),
        (3,'carol','Car0lSecure!','employee','Engineering','64000'),
        (4,'admin','Adm1n_Sup3rSecret!','admin','Executive','140000');`);
      return db;
    });
  }
  return dbReady;
}
function escapeSql(str) {
  return String(str).replace(/'/g, "''");
}

router.get("/vuln/sql-injection", async (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  const u = req.query.username, p = req.query.password, dept = req.query.dept;
  let loginResult = "", searchResult = "", flag = null;

  if (u !== undefined || p !== undefined) {
    let query;
    if (difficulty === "easy") query = `SELECT username, role FROM employees WHERE username='${u || ""}' AND password='${p || ""}'`;
    else if (difficulty === "medium") query = `SELECT username, role FROM employees WHERE username='${u || ""}' AND password='${escapeSql(p || "")}'`;
    else query = `SELECT username, role FROM employees WHERE username='${escapeSql(u || "")}' AND password='${escapeSql(p || "")}'`;
    try {
      const db = await getDb();
      const res2 = db.exec(query);
      loginResult = `Query: ${query}\n\n` + (res2.length ? `✅ Logged in as: ${JSON.stringify(res2[0].values)}` : "❌ No matching credentials.");
      if (res2.length) {
        const gotAdmin = res2[0].values.some((row) => row[0] === "admin");
        if (gotAdmin && p !== "Adm1n_Sup3rSecret!") flag = C.getFlag(session, "sql-injection", difficulty);
      }
    } catch (e) {
      loginResult = `Query: ${query}\n\n⚠️ SQL error: ${e.message}`;
    }
  }
  if (dept !== undefined) {
    const query = `SELECT username, dept FROM employees WHERE dept='${dept}'`; // always unescaped — the "second way in"
    try {
      const db = await getDb();
      const res2 = db.exec(query);
      searchResult = `Query: ${query}\n\n` + (res2.length ? JSON.stringify(res2[0].values, null, 2) : "No results.");
      if (res2.length && res2[0].values.some((row) => row.includes("Adm1n_Sup3rSecret!"))) flag = C.getFlag(session, "sql-injection", difficulty);
    } catch (e) {
      searchResult = `Query: ${query}\n\n⚠️ SQL error: ${e.message}`;
    }
  }

  res.send(C.renderVulnPage({
    appName: "SecureCorp Employee Directory", difficulty,
    bodyHtml: `
      <h1>Employee Login</h1>
      <form method="GET">
        <input type="hidden" name="difficulty" value="${difficulty}" />
        <label>Username</label><input type="text" name="username" value="${(u || "").replace(/"/g, "&quot;")}" />
        <label>Password</label><input type="text" name="password" value="${(p || "").replace(/"/g, "&quot;")}" />
        <button type="submit">Log In</button>
      </form>
      ${loginResult ? `<div class="result">${loginResult}</div>` : ""}
      <hr style="margin:24px 0;border:none;border-top:1px solid #eee;" />
      <h1>Employee Directory Search</h1>
      <form method="GET">
        <input type="hidden" name="difficulty" value="${difficulty}" />
        <label>Department</label><input type="text" name="dept" value="${(dept || "").replace(/"/g, "&quot;")}" />
        <button type="submit">Search</button>
      </form>
      ${searchResult ? `<div class="result">${searchResult}</div>` : ""}
      ${flag ? `<div class="result" style="border-color:#4ade80;"><strong>🚩 Admin access obtained via injection.</strong>\nFLAG: ${flag}</div>` : ""}
    `
  }));
});

// ===================================================== COMMAND INJECTION ===
// SIMULATED — never actually executes anything on your machine. Detects
// shell metacharacters and returns realistic FAKE command output instead of
// calling child_process, so the technique is real but 100% harmless.
const FAKE_CMD_OUTPUTS = {
  whoami: "trainee",
  "cat /etc/passwd": C.VFS["/etc/passwd"],
  "uname -a": "Linux securecorp-demo 6.8.0-generic x86_64 GNU/Linux (simulated)",
  pwd: "/home/trainee",
  id: "uid=1000(trainee) gid=1000(trainee) groups=1000(trainee)",
  ls: "app  config.php  logs  uploads",
  dir: "app  config.php  logs  uploads"
};
function filterCmd(input, difficulty) {
  if (difficulty === "easy") return input;
  if (difficulty === "medium") return input.replace(/[;&]/g, "");
  return input.replace(/[;&|]/g, ""); // hard: still allows $(...) substitution
}
function simulateCommandInjection(filtered) {
  const hasMeta = /;|&&|\|\||\||`|\$\(/.test(filtered);
  if (!hasMeta) return null;
  const lower = filtered.toLowerCase();
  for (const key of Object.keys(FAKE_CMD_OUTPUTS)) {
    if (lower.includes(key)) return FAKE_CMD_OUTPUTS[key];
  }
  return "(no recognized command — try whoami, id, pwd, ls, \"cat /etc/passwd\", or \"uname -a\")";
}
router.get("/vuln/command-injection", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  const host = req.query.host;
  let output = "", flag = null;
  if (host !== undefined) {
    const filtered = filterCmd(host, difficulty);
    const injected = simulateCommandInjection(filtered);
    output = `PING ${filtered.split(/[;&|`]| \$\(/)[0].trim() || "target"} (10.0.0.5): 56 data bytes\n64 bytes from 10.0.0.5: icmp_seq=0 ttl=64 time=0.04${Math.floor(Math.random()*9)} ms (simulated)`;
    if (injected) {
      output += `\n${injected}`;
      flag = C.getFlag(session, "command-injection", difficulty);
    }
  }
  res.send(C.renderVulnPage({
    appName: "SecureCorp Network Diagnostics", difficulty,
    bodyHtml: `
      <h1>Ping a Host</h1>
      <p class="note">⚙️ Simulated tool — this never runs real shell commands on your machine, but the injection technique you use is the real one.</p>
      <form method="GET">
        <input type="hidden" name="difficulty" value="${difficulty}" />
        <label>Hostname</label><input type="text" name="host" value="${(host || "").replace(/"/g, "&quot;")}" placeholder="10.0.0.5" />
        <button type="submit">Ping</button>
      </form>
      ${output ? `<div class="result">${output}</div>` : ""}
      ${flag ? `<div class="result" style="border-color:#4ade80;"><strong>🚩 Command injection confirmed.</strong>\nFLAG: ${flag}</div>` : ""}
    `
  }));
});

// ==================================================================== SSTI ==
function filterSSTI(input, difficulty) {
  if (difficulty === "easy") return input;
  if (difficulty === "medium") return input.replace(/constructor/gi, "");
  return input.replace(/constructor/gi, "").replace(/process/gi, "");
}
function evaluateTemplate(input, difficulty) {
  return input.replace(/\{\{(.*?)\}\}/g, (m, expr) => {
    const filtered = filterSSTI(expr, difficulty);
    if (/constructor|process|global/i.test(filtered)) {
      return "[SIMULATED RCE PROOF] uid=1000(trainee) gid=1000(trainee) — SSTI confirmed";
    }
    if (/^[\d+\-*/(). ]+$/.test(filtered) && filtered.trim() !== "") {
      try { return String(Function('"use strict";return (' + filtered + ")")()); } catch (e) { return "[math error]"; }
    }
    return "[blocked or unrecognized expression]";
  });
}
router.get("/vuln/ssti", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  const message = req.query.message || "Hi {{7*7}}, thanks for signing up!";
  const rendered = evaluateTemplate(message, difficulty);
  const exploited = rendered.includes("SIMULATED RCE PROOF");
  const flag = exploited ? C.getFlag(session, "ssti", difficulty) : null;
  res.send(C.renderVulnPage({
    appName: "SecureCorp Greeting Card Generator", difficulty,
    bodyHtml: `
      <h1>Make a Greeting Card</h1>
      <form method="GET">
        <input type="hidden" name="difficulty" value="${difficulty}" />
        <label>Message (supports {{ }} template expressions)</label>
        <textarea name="message">${message.replace(/</g, "&lt;")}</textarea>
        <button type="submit">Render Card</button>
      </form>
      <div class="result">${rendered}</div>
      ${flag ? `<div class="result" style="border-color:#4ade80;"><strong>🚩 SSTI confirmed.</strong>\nFLAG: ${flag}</div>` : ""}
      <p class="note">Try: <code>{{7*7}}</code> or <code>{{constructor.constructor('x')()}}</code></p>
    `
  }));
});

// ===================================================================== XXE ==
function filterXXE(xml, difficulty) {
  if (difficulty === "easy") return xml;
  if (difficulty === "medium") return xml.replace(/system/gi, "");
  return xml.replace(/system/gi, "").replace(/public/gi, "");
}
function parseXXE(xml) {
  const entityMatch = xml.match(/<!ENTITY\s+(\w+)\s+(?:S\s*Y\s*S\s*T\s*E\s*M|P\s*U\s*B\s*L\s*I\s*C)\s+(?:"[^"]*"\s+)?"file:\/\/(\/[^"]+)"/i);
  let resolved = xml;
  let exploited = false;
  if (entityMatch) {
    const content = C.VFS[entityMatch[2]];
    if (content) exploited = true;
    resolved = resolved.split(`&${entityMatch[1]};`).join(content || `[file not found in sandbox: ${entityMatch[2]}]`);
  }
  const nameMatch = resolved.match(/<name>([\s\S]*?)<\/name>/i);
  const commentMatch = resolved.match(/<comment>([\s\S]*?)<\/comment>/i);
  return { name: nameMatch ? nameMatch[1] : "(none)", comment: commentMatch ? commentMatch[1] : "(none)", exploited };
}
router.get("/vuln/xxe", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  const defaultXml = `<?xml version="1.0"?>\n<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>\n<feedback><name>Jordan</name><comment>&xxe;</comment></feedback>`;
  const xml = req.query.xml !== undefined ? req.query.xml : defaultXml;
  let output = "", flag = null;
  if (req.query.xml !== undefined) {
    const filtered = filterXXE(xml, difficulty);
    const parsed = parseXXE(filtered);
    output = `Parsed feedback:\nname: ${parsed.name}\ncomment: ${parsed.comment}`;
    if (parsed.exploited) flag = C.getFlag(session, "xxe", difficulty);
  }
  res.send(C.renderVulnPage({
    appName: "SecureCorp Feedback Importer", difficulty,
    bodyHtml: `
      <h1>Import Feedback XML</h1>
      <form method="GET">
        <input type="hidden" name="difficulty" value="${difficulty}" />
        <label>XML</label>
        <textarea name="xml" style="min-height:160px;">${xml.replace(/</g, "&lt;")}</textarea>
        <button type="submit">Import</button>
      </form>
      ${output ? `<div class="result">${output}</div>` : ""}
      ${flag ? `<div class="result" style="border-color:#4ade80;"><strong>🚩 File disclosed via XXE.</strong>\nFLAG: ${flag}</div>` : ""}
    `
  }));
});

// ============================================================ CRLF INJECTION
function getPreviewValue(decodedOnce, difficulty) {
  if (difficulty === "easy") return decodedOnce;
  const stripped = decodedOnce.replace(/[\r\n]/g, "");
  if (difficulty === "medium") return stripped;
  try { return decodeURIComponent(stripped); } catch (e) { return stripped; }
}
router.get("/vuln/crlf-injection", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  const rawQs = req.originalUrl.split("?")[1] || "";
  const m = rawQs.match(/(?:^|&)email=([^&]*)/);
  let output = "", flag = null;
  if (m) {
    let decodedOnce;
    try { decodedOnce = decodeURIComponent(m[1]); } catch (e) { decodedOnce = m[1]; }
    const preview = getPreviewValue(decodedOnce, difficulty);
    const splitDetected = /[\r\n]/.test(preview);
    output = `HTTP/1.1 302 Found\nLocation: /vuln/crlf-injection/welcome\nX-Subscribed-Email: ${preview}\n\n<html>...</html>` +
      (splitDetected ? "\n\n🚩 Response splitting achieved — you injected extra header/body content." : "");
    if (splitDetected) flag = C.getFlag(session, "crlf-injection", difficulty);
  }
  res.send(C.renderVulnPage({
    appName: "SecureCorp Newsletter", difficulty,
    bodyHtml: `
      <h1>Subscribe to our Newsletter</h1>
      <p class="note">This simulates a raw HTTP response preview — no real headers are set, so nothing can crash; the splitting effect is shown as text.</p>
      <form method="GET">
        <input type="hidden" name="difficulty" value="${difficulty}" />
        <label>Email</label><input type="text" name="email" placeholder="you@example.com" />
        <button type="submit">Subscribe</button>
      </form>
      ${output ? `<div class="result">${output.replace(/</g, "&lt;")}</div>` : ""}
      ${flag ? `<div class="result" style="border-color:#4ade80;">FLAG: ${flag}</div>` : ""}
      <p class="note">Try appending to your email (URL-encode it): <code>%0d%0aSet-Cookie: admin=true</code></p>
    `
  }));
});

module.exports = { router };
