/**
 * routes/vuln-common.js
 *
 * Shared infrastructure for every lab: session store, a fully FAKE in-memory
 * "filesystem" and "internal services" map (so path traversal / LFI / XXE /
 * command injection / SSRF labs teach the real technique without ever
 * touching the real host filesystem or making real outbound network
 * requests), and the shared HTML shell used to render every standalone
 * vulnerable target page.
 */
const crypto = require("crypto");

function randomHex(bytes) {
  return crypto.randomBytes(bytes).toString("hex");
}

function difficultyOf(req) {
  const d = ((req.query && req.query.difficulty) || (req.body && req.body.difficulty) || (req.cookies && req.cookies.difficulty) || "easy").toLowerCase();
  return ["easy", "medium", "hard"].includes(d) ? d : "easy";
}

// ---------------------------------------------------------------------------
// Session store: sid -> { canonicalId, notes, lab: { [labId]: {...state} } }
// ---------------------------------------------------------------------------
const SESSIONS = new Map();

function getOrInitSession(req, res) {
  let sid = req.cookies.sid;
  if (!sid || !SESSIONS.has(sid)) {
    sid = randomHex(16);
    res.cookie("sid", sid, { httpOnly: false });
    SESSIONS.set(sid, { canonicalId: null, notes: [], lab: {} });
  }
  return { sid, session: SESSIONS.get(sid) };
}

function labState(session, labId, defaults) {
  if (!session.lab[labId]) session.lab[labId] = JSON.parse(JSON.stringify(defaults));
  return session.lab[labId];
}

function resetLabState(session, labId) {
  delete session.lab[labId];
  if (session.flags) {
    Object.keys(session.flags).forEach((k) => { if (k.indexOf(labId + ":") === 0) delete session.flags[k]; });
  }
}

// ---------------------------------------------------------------------------
// FLAG SYSTEM — real exploit verification. Each session gets a unique,
// unguessable flag per lab+difficulty, generated on first use. A lab's
// vulnerable route only reveals this flag in the response when the actual
// exploit condition is genuinely met (never on the "safe"/blocked path), so
// submitting the correct flag in the Report tab proves the exploit actually
// happened server-side — not just that the learner typed something
// payload-shaped into a textarea.
// ---------------------------------------------------------------------------
function getFlag(session, labId, difficulty) {
  if (!session.flags) session.flags = {};
  const key = labId + ":" + difficulty;
  if (!session.flags[key]) session.flags[key] = "FLAG{" + labId + "-" + difficulty + "-" + randomHex(4) + "}";
  return session.flags[key];
}
function checkFlag(session, labId, difficulty, submitted) {
  if (!session.flags) return false;
  const expected = session.flags[labId + ":" + difficulty];
  return !!expected && String(submitted || "").trim() === expected;
}

// ---------------------------------------------------------------------------
// A completely FAKE virtual filesystem. Traversal/inclusion bugs resolve
// against THIS object only — never Node's real `fs` module against the
// host disk. This keeps every "arbitrary file read" lab realistic in
// technique while being 100% harmless to run on your own laptop.
// ---------------------------------------------------------------------------
const VFS = {
  "/etc/passwd":
    "root:x:0:0:root:/root:/bin/bash\n" +
    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n" +
    "trainee:x:1000:1000:Trainee User:/home/trainee:/bin/bash\n",
  "/var/www/config.php":
    "<?php\ndefine('DB_HOST','127.0.0.1');\ndefine('DB_USER','securecorp_app');\ndefine('DB_PASS','Tr41n1ng_DB_2026!');\n?>",
  "/home/trainee/.ssh/id_rsa":
    "-----BEGIN OPENSSH PRIVATE KEY-----\n(fake training key — not a real credential)\nAAAAB3NzaC1yc2EAAAADAQABFAKEKEYDONOTUSE==\n-----END OPENSSH PRIVATE KEY-----",
  "/var/log/access.log": "127.0.0.1 - - [training] GET /index.html 200\n",
  "/app/templates/en.txt": "Welcome to SecureCorp Demo!",
  "/app/templates/fr.txt": "Bienvenue chez SecureCorp Demo !",
  "/app/templates/es.txt": "¡Bienvenido a SecureCorp Demo!",
  "/app/documents/report1.txt": "Q1 Report (fake demo data): revenue up 4% quarter over quarter.",
  "/app/documents/report2.txt": "Q2 Report (fake demo data): headcount grew by 3 engineers."
};

// A fake internal-services map used ONLY by the SSRF lab — no real outbound
// network requests are ever made by this app.
const FAKE_INTERNAL_SERVICES = {
  "169.254.169.254/latest/meta-data/iam/security-credentials/admin":
    '{"AccessKeyId":"AKIAFAKEDEMOTRAINING","SecretAccessKey":"fakeSecretDoNotUse1234567890","Token":"fake"}',
  "localhost:6379/info": "# Redis (simulated)\r\nredis_version:7.0.0\r\nrole:master\r\n",
  "internal-api.local/admin/users": '[{"id":1,"username":"admin","role":"superadmin"}]',
  "127.0.0.1/admin": "<h1>Internal Admin Panel (simulated)</h1><p>This should never be reachable from outside.</p>"
};

// ---------------------------------------------------------------------------
// Shared page chrome for every standalone "vulnerable target" page.
// Deliberately looks like a generic internal corporate app, NOT like the
// training platform shell — matches the "open in a new tab" pattern.
// ---------------------------------------------------------------------------
function renderVulnPage({ appName, difficulty, bodyHtml, extraHead }) {
  return `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8" />
<title>${appName} — SecureCorp Demo</title>
<style>
  *{box-sizing:border-box;}
  body{background:#f4f5f7;color:#1c2024;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;margin:0;}
  .topbar{background:#1c2024;color:#fff;padding:12px 24px;display:flex;justify-content:space-between;align-items:center;}
  .topbar .name{font-weight:700;letter-spacing:.02em;}
  .topbar .env{font-size:.72rem;color:#9aa1ab;font-family:ui-monospace,Menlo,monospace;}
  .wrap{max-width:720px;margin:32px auto;background:#fff;border:1px solid #e2e5e9;border-radius:10px;padding:32px;box-shadow:0 1px 3px rgba(0,0,0,.06);}
  h1{font-size:1.3rem;margin:0 0 18px;}
  label{display:block;font-size:.82rem;color:#5b6470;margin-bottom:4px;font-weight:600;}
  input[type=text],input[type=password],input[type=email],input[type=file],textarea,select{
    width:100%;padding:9px 11px;border:1px solid #d3d7dd;border-radius:6px;font-size:.92rem;margin-bottom:14px;font-family:inherit;
  }
  textarea{font-family:ui-monospace,Menlo,monospace;font-size:.82rem;min-height:100px;}
  button,.btn{background:#f5a524;color:#1c1200;border:none;padding:10px 18px;border-radius:6px;font-weight:700;cursor:pointer;font-size:.9rem;}
  button.secondary,.btn.secondary{background:#eceef1;color:#1c2024;}
  button.danger{background:#ef4444;color:#fff;}
  a.btn{display:inline-block;text-decoration:none;}
  .result{background:#f4f5f7;border:1px solid #e2e5e9;border-radius:8px;padding:14px 16px;margin-top:16px;font-family:ui-monospace,Menlo,monospace;font-size:.82rem;white-space:pre-wrap;word-break:break-word;}
  .note{font-size:.8rem;color:#7d838d;margin-top:10px;}
  .field-hidden-value{color:#a78bfa;font-weight:700;}
  table{width:100%;border-collapse:collapse;font-size:.85rem;}
  td,th{padding:7px 6px;border-bottom:1px solid #ececec;text-align:left;}
  .pill{display:inline-block;background:#eceef1;border-radius:999px;padding:2px 9px;font-size:.7rem;font-family:ui-monospace,Menlo,monospace;}
</style>
${extraHead || ""}
</head><body>
  <div class="topbar">
    <span class="name">${appName}</span>
    <span class="env">SecureCorp Demo · sandbox · difficulty: ${difficulty}</span>
  </div>
  <div class="wrap">${bodyHtml}</div>
</body></html>`;
}

// ---------------------------------------------------------------------------
// Shared fake user directory (used by IDOR, Access Control, Final Challenge)
// ---------------------------------------------------------------------------
const USERS = [
  { canonicalId: 1, username: "amoore", email: "a.moore@securecorp-demo.test", phone: "555-0101" },
  { canonicalId: 2, username: "bkline", email: "b.kline@securecorp-demo.test", phone: "555-0102" },
  { canonicalId: 3, username: "cwalsh", email: "c.walsh@securecorp-demo.test", phone: "555-0103" },
  { canonicalId: 4, username: "dpatel", email: "d.patel@securecorp-demo.test", phone: "555-0104" },
  { canonicalId: 5, username: "erivera", email: "e.rivera@securecorp-demo.test", phone: "555-0105" },
  { canonicalId: 6, username: "fchen", email: "f.chen@securecorp-demo.test", phone: "555-0106" },
  { canonicalId: 7, username: "gsingh", email: "g.singh@securecorp-demo.test", phone: "555-0107" },
  { canonicalId: 8, username: "hnguyen", email: "h.nguyen@securecorp-demo.test", phone: "555-0108" },
  { canonicalId: 9, username: "iolsen", email: "i.olsen@securecorp-demo.test", phone: "555-0109" },
  { canonicalId: 10, username: "jkumar", email: "j.kumar@securecorp-demo.test", phone: "555-0110" },
  { canonicalId: 11, username: "kbrooks", email: "k.brooks@securecorp-demo.test", phone: "555-0111" },
  { canonicalId: 12, username: "lferrer", email: "l.ferrer@securecorp-demo.test", phone: "555-0112" }
];
const ADMIN = {
  canonicalId: 100,
  username: "admin",
  email: "admin@securecorp-demo.test",
  phone: "555-0100",
  password: "CTBB_S3cr3t_2026!"
};
function findUserByCanonicalId(id) {
  if (id === 100) return ADMIN;
  return USERS.find((u) => u.canonicalId === id);
}
function encodeId(canonicalId, difficulty) {
  if (difficulty === "hard") return Buffer.from(String(canonicalId), "utf8").toString("base64");
  if (difficulty === "medium") return String(canonicalId * 37 + 4);
  return String(canonicalId);
}
function decodeId(raw, difficulty) {
  if (raw === undefined || raw === null || raw === "") return NaN;
  if (difficulty === "hard") {
    try { return parseInt(Buffer.from(String(raw), "base64").toString("utf8"), 10); } catch (e) { return NaN; }
  }
  if (difficulty === "medium") {
    const n = parseInt(raw, 10);
    if (Number.isNaN(n)) return NaN;
    return (n - 4) / 37;
  }
  return parseInt(raw, 10);
}

module.exports = {
  randomHex,
  difficultyOf,
  SESSIONS,
  getOrInitSession,
  labState,
  resetLabState,
  getFlag,
  checkFlag,
  VFS,
  FAKE_INTERNAL_SERVICES,
  renderVulnPage,
  USERS,
  ADMIN,
  findUserByCanonicalId,
  encodeId,
  decodeId
};
