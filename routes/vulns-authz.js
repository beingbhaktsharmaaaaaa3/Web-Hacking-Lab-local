const express = require("express");
const router = express.Router();
const C = require("./vuln-common");

const ADMIN_NOTE = {
  id: "n-admin-1",
  title: "Reminder to self",
  body: "Told IT (again) to stop leaving this discoverable. If support needs to double check user 100's account, /vuln/idor/profile still works the same as for everyone else. -A"
};

function ensureUser(session) {
  if (!session.canonicalId) {
    const pool = C.USERS[Math.floor(Math.random() * C.USERS.length)];
    session.canonicalId = pool.canonicalId;
    session.notes = [
      { id: "n1", title: "Welcome", body: "This is a demo note. Try editing me." },
      { id: "n2", title: "Groceries", body: "Milk, eggs, bread." }
    ];
  }
}

// ============================================================ IDOR =========
router.get("/vuln/idor", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  ensureUser(session);
  const myPublicId = C.encodeId(session.canonicalId, difficulty);
  res.send(C.renderVulnPage({
    appName: "SecureCorp Portal",
    difficulty,
    bodyHtml: `
      <h1>My Profile</h1>
      <p class="note">You're logged in. Your id is <span class="pill">${myPublicId}</span> — check the address bar.</p>
      <p class="note">Try visiting <code>/vuln/idor/profile?id=${myPublicId}&difficulty=${difficulty}</code> and changing the id.</p>
      <a class="btn" href="/vuln/idor/profile?id=${myPublicId}&difficulty=${difficulty}">View My Profile →</a>
    `
  }));
});

router.get("/vuln/idor/profile", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  ensureUser(session);
  const canonicalId = C.decodeId(req.query.id, difficulty);
  const user = C.findUserByCanonicalId(canonicalId);

  if (!user) {
    return res.send(C.renderVulnPage({
      appName: "SecureCorp Portal", difficulty,
      bodyHtml: `<h1>Profile not found</h1><p class="note">No user matches id "${req.query.id || ""}".</p><a class="btn secondary" href="/vuln/idor?difficulty=${difficulty}">← Back</a>`
    }));
  }
  // No ownership check — this endpoint returns ANY profile by id. That's the bug.
  const exploited = canonicalId !== session.canonicalId;
  const flag = exploited ? C.getFlag(session, "idor", difficulty) : null;
  res.send(C.renderVulnPage({
    appName: "SecureCorp Portal", difficulty,
    bodyHtml: `
      <h1>Profile: ${user.username}</h1>
      <table>
        <tr><th>Username</th><td>${user.username}</td></tr>
        <tr><th>Email</th><td>${user.email}</td></tr>
        <tr><th>id parameter</th><td>${req.query.id}</td></tr>
      </table>
      <p class="note">🔎 Open DevTools → view source / Network — the raw API response includes more than what's rendered here:</p>
      <div class="result">GET /api/viewUser?id=${req.query.id}&difficulty=${difficulty}
${JSON.stringify({ id: canonicalId, username: user.username, email: user.email, phone: user.phone, ...(user.password ? { password: user.password } : {}) }, null, 2)}</div>
      ${flag ? `<div class="result" style="border-color:#4ade80;"><strong>🚩 Exploit confirmed — you viewed a profile that isn't yours.</strong>\nFLAG: ${flag}</div>` : `<p class="note">(That's your own profile — try a different id to actually exploit this.)</p>`}
      <p style="margin-top:16px;"><a class="btn secondary" href="/vuln/idor?difficulty=${difficulty}">← Back to my profile</a></p>
    `
  }));
});

// JSON API (kept for the Network-tab / raw-request teaching moment)
router.get("/api/viewUser", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const canonicalId = C.decodeId(req.query.id, difficulty);
  if (Number.isNaN(canonicalId)) return res.status(400).json({ error: "Missing or malformed id parameter." });
  const user = C.findUserByCanonicalId(canonicalId);
  if (!user) return res.status(404).json({ error: "No such user." });
  res.json({
    id: canonicalId, username: user.username, email: user.email, phone: user.phone,
    ...(user.password ? { password: user.password } : {})
  });
});

// ================================================ BROKEN ACCESS CONTROL ====
function effectiveRole(req, difficulty) {
  if (difficulty === "easy") return "admin"; // no server check exists at all
  if (difficulty === "hard" && req.headers["x-debug-role"] === "admin") return "admin";
  const roleCookie = req.cookies.role;
  if (!roleCookie) return "viewer";
  if (difficulty === "hard") {
    try { return JSON.parse(Buffer.from(roleCookie, "base64").toString("utf8")).role || "viewer"; }
    catch (e) { return "viewer"; }
  }
  return roleCookie;
}

router.get("/vuln/access-control", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  ensureUser(session);
  if (difficulty === "hard") res.cookie("role", Buffer.from(JSON.stringify({ role: "viewer" })).toString("base64"));
  else res.cookie("role", "viewer");

  const notesHtml = session.notes.map((n) => `<div class="result">${n.title}\n${n.body}</div>`).join("");
  res.send(C.renderVulnPage({
    appName: "SecureCorp Notes", difficulty,
    bodyHtml: `
      <h1>My Notes <span class="pill">read-only viewer</span></h1>
      ${notesHtml}
      <button disabled>+ Add Note</button>
      <button disabled class="secondary">Edit</button>
      <button disabled class="danger">Delete</button>
      <p class="note">These buttons are disabled in the UI. Is the server actually enforcing that?</p>
      <hr style="margin:20px 0;border:none;border-top:1px solid #eee;" />
      <h1 style="font-size:1rem;">Raw request console</h1>
      <label>Title</label><input type="text" id="t" value="Hacked note" />
      <label>Body</label><input type="text" id="b" value="pwned via broken access control" />
      ${difficulty === "hard" ? `<label>X-Debug-Role header (optional)</label><input type="text" id="dr" placeholder="admin" />` : ""}
      <button onclick="sendNote()">POST /api/notes</button>
      <div class="result" id="out" style="display:none;"></div>
      <script>
        async function sendNote(){
          const headers = {'Content-Type':'application/json'};
          const dr = document.getElementById('dr');
          if (dr && dr.value) headers['X-Debug-Role'] = dr.value;
          const res = await fetch('/api/notes?difficulty=${difficulty}', { method:'POST', headers, body: JSON.stringify({title:document.getElementById('t').value, body:document.getElementById('b').value}) });
          const data = await res.json();
          const out = document.getElementById('out');
          out.style.display = 'block';
          out.textContent = 'HTTP ' + res.status + '\\n' + JSON.stringify(data, null, 2);
        }
      </script>
      <p class="note" style="margin-top:14px;">Console shortcut: <code>document.querySelectorAll('[disabled]').forEach(el =&gt; el.removeAttribute('disabled'))</code></p>
    `
  }));
});

router.get("/api/notes", (req, res) => {
  const { session } = C.getOrInitSession(req, res);
  ensureUser(session);
  if (req.query.scope === "admin") {
    const difficulty = C.difficultyOf(req);
    if (effectiveRole(req, difficulty) !== "admin") return res.status(403).json({ error: "Admin notes require an admin role." });
    return res.json({ notes: [ADMIN_NOTE] });
  }
  res.json({ notes: session.notes });
});
router.post("/api/notes", (req, res) => {
  const { session } = C.getOrInitSession(req, res);
  ensureUser(session);
  const difficulty = C.difficultyOf(req);
  if (difficulty !== "easy" && effectiveRole(req, difficulty) !== "admin") return res.status(403).json({ error: "Read-only accounts cannot create notes." });
  const note = { id: "n" + C.randomHex(4), title: req.body.title || "Untitled", body: req.body.body || "" };
  session.notes.push(note);
  const flag = C.getFlag(session, "access-control", difficulty);
  res.json({ message: "✅ Note created — access control bypassed. FLAG: " + flag, note, flag });
});

// ============================================================ FINAL ========
router.get("/vuln/final", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  ensureUser(session);
  res.send(C.renderVulnPage({
    appName: "SecureCorp — Classified", difficulty,
    bodyHtml: `
      <h1>[REDACTED]</h1>
      <p class="note">Somewhere in this application, an admin note points to something. Follow the trail. Find user 100's password.</p>
      <p class="note">Tools you already have: <code>/vuln/access-control</code> (to read admin notes) and <code>/vuln/idor/profile?id=</code> (to read a profile).</p>
      <a class="btn secondary" href="/vuln/access-control?difficulty=${difficulty}">Open SecureCorp Notes →</a>
    `
  }));
});

router.post("/api/final-challenge", (req, res) => {
  const answer = (req.body.password || "").trim();
  if (answer && answer === C.ADMIN.password) return res.json({ success: true, message: "Correct. Challenge complete." });
  res.json({ success: false, message: "Incorrect password." });
});

module.exports = { router, effectiveRole, ensureUser, ADMIN_NOTE };
