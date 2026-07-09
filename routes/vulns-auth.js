const express = require("express");
const router = express.Router();
const crypto = require("crypto");
const C = require("./vuln-common");

// ========================================================= 2FA BYPASS ======
router.get("/vuln/2fa-bypass", (req, res) => {
  const difficulty = C.difficultyOf(req);
  C.getOrInitSession(req, res);
  res.send(C.renderVulnPage({
    appName: "SecureCorp Login", difficulty,
    bodyHtml: `
      <h1>Log In</h1>
      <form method="GET" action="/vuln/2fa-bypass/login">
        <input type="hidden" name="difficulty" value="${difficulty}" />
        <label>Username</label><input type="text" name="username" placeholder="alice" />
        <label>Password</label><input type="text" name="password" placeholder="(anything — demo)" />
        <button type="submit">Log In</button>
      </form>
    `
  }));
});
router.get("/vuln/2fa-bypass/login", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  const st = C.labState(session, "2fa-bypass", { loggedIn: false, otpVerified: false, code: String(Math.floor(Math.random() * 100)).padStart(2, "0"), attempts: 0 });
  st.loggedIn = true;
  res.send(C.renderVulnPage({
    appName: "SecureCorp Login", difficulty,
    bodyHtml: `
      <h1>Enter your 2FA code</h1>
      <p class="note">A 2-digit code was "texted" to you.</p>
      <form method="GET" action="/vuln/2fa-bypass/verify">
        <input type="hidden" name="difficulty" value="${difficulty}" />
        <label>Code</label><input type="text" name="otp" maxlength="2" />
        <button type="submit">Verify</button>
      </form>
      ${difficulty === "easy" ? `<p class="note">Or just skip this — try going straight to <a href="/vuln/2fa-bypass/account?difficulty=${difficulty}">the account page</a>.</p>` : ""}
      ${difficulty === "hard" ? `<button class="secondary" onclick="bruteForce()">Try all 100 codes</button><div class="result" id="bf"></div>
        <script>
          async function bruteForce(){
            const out = document.getElementById('bf');
            for (let i=0;i<100;i++){
              const code = String(i).padStart(2,'0');
              const r = await fetch('/vuln/2fa-bypass/verify?difficulty=hard&otp='+code);
              const t = await r.text();
              if (t.includes('Verified')) { out.textContent = 'Found code: ' + code + ' after ' + (i+1) + ' attempts.'; return; }
            }
            out.textContent = 'No code worked (unexpected).';
          }
        </script>` : ""}
    `
  }));
});
router.get("/vuln/2fa-bypass/verify", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  const st = C.labState(session, "2fa-bypass", { loggedIn: true, otpVerified: false, code: "00", attempts: 0 });
  const otp = req.query.otp || "";
  let message;
  if (difficulty === "easy") {
    st.otpVerified = true;
    message = "Verified (this difficulty doesn't check the code at all).";
  } else if (difficulty === "medium") {
    st.otpVerified = true; // any value is accepted
    message = "Verified — any 2-digit value is accepted here.";
  } else {
    st.attempts++;
    if (otp === st.code) { st.otpVerified = true; message = "Verified! Correct code."; }
    else message = `Incorrect code. (attempt ${st.attempts}, no lockout in place)`;
  }
  res.send(C.renderVulnPage({
    appName: "SecureCorp Login", difficulty,
    bodyHtml: `<h1>${message}</h1><p style="margin-top:16px;"><a class="btn" href="/vuln/2fa-bypass/account?difficulty=${difficulty}">Continue to account →</a></p>`
  }));
});
router.get("/vuln/2fa-bypass/account", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  const st = C.labState(session, "2fa-bypass", { loggedIn: false, otpVerified: false, code: "00", attempts: 0 });
  if (!st.loggedIn) {
    return res.send(C.renderVulnPage({ appName: "SecureCorp Account", difficulty, bodyHtml: `<h1>Not logged in</h1><p class="note"><a href="/vuln/2fa-bypass?difficulty=${difficulty}">Log in first</a>.</p>` }));
  }
  if (difficulty !== "easy" && !st.otpVerified) {
    return res.send(C.renderVulnPage({ appName: "SecureCorp Account", difficulty, bodyHtml: `<h1>🔒 Blocked</h1><p class="note">2FA verification required before viewing this page.</p>` }));
  }
  const flag = C.getFlag(session, "2fa-bypass", difficulty);
  res.send(C.renderVulnPage({
    appName: "SecureCorp Account", difficulty,
    bodyHtml: `<h1>🎉 Full Account Access</h1><p class="note">Secret vault code: <span class="field-hidden-value">TR41N-9F2C</span></p>${difficulty === "easy" ? '<p class="note">Notice you never actually entered a correct 2FA code to get here.</p>' : ""}<div class="result" style="border-color:#4ade80;"><strong>🚩 2FA bypassed.</strong>\nFLAG: ${flag}</div>`
  }));
});

// ===================================================== WEAK PASSWORD =======
const ADMIN_PW = { easy: "admin123", medium: "Summer2024!", hard: "Tr41n1ng!2026" };
router.get("/vuln/weak-password", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  const st = C.labState(session, "weak-password", { attempts: 0, lockedOut: false });
  res.send(C.renderVulnPage({
    appName: "SecureCorp Login", difficulty,
    bodyHtml: `
      <h1>Register</h1>
      <p class="note">No complexity or length requirements are enforced — any password is accepted.</p>
      <form method="GET" action="/vuln/weak-password/register">
        <input type="hidden" name="difficulty" value="${difficulty}" />
        <label>New username</label><input type="text" name="username" />
        <label>New password</label><input type="text" name="password" />
        <button type="submit">Register</button>
      </form>
      <hr style="margin:24px 0;border:none;border-top:1px solid #eee;" />
      <h1>Log In (try to brute-force "admin")</h1>
      ${st.lockedOut ? '<p class="note">🔒 Locked out for this session (5 failed attempts). Try clearing cookies for a fresh session.</p>' : ""}
      <label>Password guess</label><input type="text" id="guess" />
      <button onclick="tryOne()">Try</button>
      <button class="secondary" onclick="tryList()">Run built-in wordlist</button>
      <div class="result" id="out"></div>
      <script>
        async function tryOne(){
          const p = document.getElementById('guess').value;
          const r = await fetch('/vuln/weak-password/login?difficulty=${difficulty}&username=admin&password=' + encodeURIComponent(p));
          document.getElementById('out').textContent = await r.text();
        }
        async function tryList(){
          const words = ['123456','password','admin123','qwerty','letmein','Summer2024!','Winter2024!','Tr41n1ng!2026','welcome1'];
          const out = document.getElementById('out');
          for (const w of words){
            const r = await fetch('/vuln/weak-password/login?difficulty=${difficulty}&username=admin&password=' + encodeURIComponent(w));
            const t = await r.text();
            out.textContent = 'Tried: ' + w + ' → ' + t;
            if (t.includes('Success')) return;
          }
        }
      </script>
    `
  }));
});
router.get("/vuln/weak-password/register", (req, res) => {
  const difficulty = C.difficultyOf(req);
  C.getOrInitSession(req, res);
  res.send(C.renderVulnPage({
    appName: "SecureCorp Login", difficulty,
    bodyHtml: `<h1>✅ Registered</h1><p class="note">Account "${(req.query.username || "").replace(/</g, "")}" created with password "${(req.query.password || "").replace(/</g, "")}" — no strength check was applied.</p>`
  }));
});
router.get("/vuln/weak-password/login", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  const st = C.labState(session, "weak-password", { attempts: 0, lockedOut: false });
  if (difficulty === "hard" && st.lockedOut) return res.send("Locked out for this session.");
  const ok = req.query.password === ADMIN_PW[difficulty];
  if (!ok) {
    st.attempts++;
    if (difficulty === "hard" && st.attempts >= 5) st.lockedOut = true;
    return res.send(`Failure. (attempt ${st.attempts}${difficulty === "hard" ? ", locks after 5" : ""})`);
  }
  res.send(`Success! admin password is "${ADMIN_PW[difficulty]}". FLAG: ${C.getFlag(session, "weak-password", difficulty)}`);
});

// ==================================================== PASSWORD RESET =======
const HARD_LEAKED_TOKEN = crypto.randomBytes(6).toString("hex");
const HARD_TOKEN_OWNER = { [HARD_LEAKED_TOKEN]: "admin" };
router.get("/vuln/password-reset", (req, res) => {
  const difficulty = C.difficultyOf(req);
  C.getOrInitSession(req, res);
  res.send(C.renderVulnPage({
    appName: "SecureCorp Password Reset", difficulty,
    bodyHtml: `
      <h1>Forgot your password?</h1>
      <form method="GET" action="/vuln/password-reset/request">
        <input type="hidden" name="difficulty" value="${difficulty}" />
        <label>Username</label><input type="text" name="username" placeholder="alice" />
        <button type="submit">Send reset link</button>
      </form>
      ${difficulty === "hard" ? `<div class="result">📧 Recently sent reset emails (debug log — shouldn't be exposed):\nadmin — token: ${HARD_LEAKED_TOKEN} (already used)</div>` : ""}
      <p class="note">Reset a password directly: <a href="/vuln/password-reset/reset-form?difficulty=${difficulty}">reset form →</a></p>
    `
  }));
});
router.get("/vuln/password-reset/request", (req, res) => {
  const difficulty = C.difficultyOf(req);
  C.getOrInitSession(req, res);
  const username = req.query.username || "";
  let token;
  if (difficulty === "easy") token = Buffer.from(username).toString("base64");
  else if (difficulty === "medium") token = username.split("").reverse().join("") + "-2024";
  else { token = crypto.randomBytes(6).toString("hex"); HARD_TOKEN_OWNER[token] = username; }
  res.send(C.renderVulnPage({
    appName: "SecureCorp Password Reset", difficulty,
    bodyHtml: `<h1>📧 Email sent (simulated)</h1><p class="note">Reset link: <code>/vuln/password-reset/reset?token=${token}</code></p>`
  }));
});
router.get("/vuln/password-reset/reset-form", (req, res) => {
  const difficulty = C.difficultyOf(req);
  res.send(C.renderVulnPage({
    appName: "SecureCorp Password Reset", difficulty,
    bodyHtml: `
      <h1>Reset Password</h1>
      <form method="GET" action="/vuln/password-reset/reset">
        <input type="hidden" name="difficulty" value="${difficulty}" />
        <label>Token</label><input type="text" name="token" />
        <label>New password</label><input type="text" name="newpassword" value="hacked123" />
        <button type="submit">Reset</button>
      </form>
    `
  }));
});
router.get("/vuln/password-reset/reset", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  const token = req.query.token || "";
  const newpassword = req.query.newpassword || "";
  let username = null;
  if (difficulty === "easy") { try { username = Buffer.from(token, "base64").toString("utf8"); } catch (e) {} }
  else if (difficulty === "medium") { if (token.endsWith("-2024")) username = token.slice(0, -5).split("").reverse().join(""); }
  else { username = HARD_TOKEN_OWNER[token] || null; }

  if (!username) {
    return res.send(C.renderVulnPage({ appName: "SecureCorp Password Reset", difficulty, bodyHtml: `<h1>❌ Invalid token</h1>` }));
  }
  const flag = username === "admin" ? C.getFlag(session, "password-reset", difficulty) : null;
  res.send(C.renderVulnPage({
    appName: "SecureCorp Password Reset", difficulty,
    bodyHtml: `<h1>✅ Password reset</h1><p class="note">The password for account "<strong>${username}</strong>" was changed to "${newpassword}" — without proving ownership of that account.</p>${flag ? `<div class="result" style="border-color:#4ade80;"><strong>🚩 Admin account compromised.</strong>\nFLAG: ${flag}</div>` : `<p class="note">(Try targeting the "admin" account specifically to fully solve this lab.)</p>`}`
  }));
});

// ==================================================== OAUTH MISCONFIG ======
router.get("/vuln/oauth-misconfig", (req, res) => {
  const difficulty = C.difficultyOf(req);
  C.getOrInitSession(req, res);
  res.send(C.renderVulnPage({
    appName: "SecureCorp ID — OAuth", difficulty,
    bodyHtml: `
      <h1>Authorize "ThirdPartyApp"</h1>
      <p class="note">ThirdPartyApp wants to log in using your SecureCorp ID. Where should we send the authorization code?</p>
      <form method="GET" action="/vuln/oauth-misconfig/authorize">
        <input type="hidden" name="difficulty" value="${difficulty}" />
        <label>redirect_uri</label>
        <input type="text" name="redirect_uri" value="https://securecorp-demo.test/callback" />
        <button type="submit">Authorize</button>
      </form>
    `
  }));
});
router.get("/vuln/oauth-misconfig/authorize", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  const redirectUri = req.query.redirect_uri || "";
  let blocked = false, reason = "";
  if (difficulty === "medium" && !redirectUri.includes("securecorp-demo.test")) { blocked = true; reason = "redirect_uri must reference securecorp-demo.test"; }
  if (difficulty === "hard" && !redirectUri.startsWith("https://securecorp-demo.test")) { blocked = true; reason = "redirect_uri must start with https://securecorp-demo.test"; }
  if (blocked) return res.send(C.renderVulnPage({ appName: "SecureCorp ID — OAuth", difficulty, bodyHtml: `<h1>Blocked</h1><p class="note">${reason}</p>` }));

  const fakeCode = "auth_code_" + C.randomHex(6);
  const finalUrl = redirectUri + (redirectUri.includes("?") ? "&" : "?") + "code=" + fakeCode;
  const looksOffDomain = !/^https:\/\/securecorp-demo\.test(\/|$|\?)/.test(redirectUri) || redirectUri.includes("/vuln/open-redirect");
  const flag = looksOffDomain ? C.getFlag(session, "oauth-misconfig", difficulty) : null;
  res.send(C.renderVulnPage({
    appName: "SecureCorp ID — OAuth", difficulty,
    bodyHtml: `<h1>Redirecting…</h1><div class="result">${finalUrl}</div>${looksOffDomain ? `<p class="note">🚩 That authorization code would be delivered off-domain.</p><div class="result" style="border-color:#4ade80;">FLAG: ${flag}</div>` : ""}`
  }));
});

// ======================================================== SAML =============
const SAMPLE_ASSERTION = Buffer.from(`<Assertion><Subject>guest</Subject><Attribute name="role">user</Attribute><Signature></Signature></Assertion>`).toString("base64");
router.get("/vuln/saml-vulns", (req, res) => {
  const difficulty = C.difficultyOf(req);
  C.getOrInitSession(req, res);
  res.send(C.renderVulnPage({
    appName: "SecureCorp SSO — SAML", difficulty,
    bodyHtml: `
      <h1>SAML Login</h1>
      <form method="GET" action="/vuln/saml-vulns/login">
        <input type="hidden" name="difficulty" value="${difficulty}" />
        <label>SAML Response (base64)</label>
        <textarea name="saml" style="min-height:120px;">${SAMPLE_ASSERTION}</textarea>
        <button type="submit">Log In</button>
      </form>
      <p class="note">Decoded sample: <code>&lt;Assertion&gt;&lt;Subject&gt;guest&lt;/Subject&gt;&lt;Attribute name="role"&gt;user&lt;/Attribute&gt;&lt;Signature&gt;&lt;/Signature&gt;&lt;/Assertion&gt;</code></p>
    `
  }));
});
router.get("/vuln/saml-vulns/login", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  let decoded = "";
  try { decoded = Buffer.from(req.query.saml || "", "base64").toString("utf8"); } catch (e) {}
  const subject = (decoded.match(/<Subject>(.*?)<\/Subject>/i) || [])[1];
  const role = (decoded.match(/<Attribute name="role">(.*?)<\/Attribute>/i) || [])[1];
  const signature = (decoded.match(/<Signature>([\s\S]*?)<\/Signature>/i) || [])[1];
  const notOnOrAfter = (decoded.match(/<NotOnOrAfter>(.*?)<\/NotOnOrAfter>/i) || [])[1];

  let blocked = false, reason = "";
  if (!subject) { blocked = true; reason = "Could not parse a Subject from the assertion."; }
  else if (difficulty !== "easy" && !signature) { blocked = true; reason = "Signature field missing."; }
  else if (difficulty === "hard") {
    if (!notOnOrAfter) { blocked = true; reason = "NotOnOrAfter missing."; }
    else if (new Date(notOnOrAfter).getTime() < Date.now()) { blocked = true; reason = "Assertion expired."; }
  }
  if (blocked) return res.send(C.renderVulnPage({ appName: "SecureCorp SSO — SAML", difficulty, bodyHtml: `<h1>❌ Rejected</h1><p class="note">${reason}</p>` }));
  const flag = subject === "admin" ? C.getFlag(session, "saml-vulns", difficulty) : null;
  res.send(C.renderVulnPage({
    appName: "SecureCorp SSO — SAML", difficulty,
    bodyHtml: `<h1>✅ Logged in as "${subject}"</h1><p class="note">Role: ${role || "user"}. Signature was ${difficulty === "easy" ? "never checked" : "checked for presence only — never cryptographically verified"}.</p>${flag ? `<div class="result" style="border-color:#4ade80;"><strong>🚩 Forged into the admin account.</strong>\nFLAG: ${flag}</div>` : `<p class="note">(Forge the Subject to "admin" specifically to fully solve this lab.)</p>`}`
  }));
});

// ======================================================= BRUTE FORCE =======
const BF_USERS = { jsmith: { password: "Winter2025!" } };
function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }
router.get("/vuln/brute-force", (req, res) => {
  const difficulty = C.difficultyOf(req);
  C.getOrInitSession(req, res);
  res.send(C.renderVulnPage({
    appName: "SecureCorp Staff Portal", difficulty,
    bodyHtml: `
      <h1>Staff Login</h1>
      <p class="note">Candidate usernames to investigate: admin, jsmith, test, svc_backup (only one is real).</p>
      <form method="GET" action="/vuln/brute-force/login">
        <input type="hidden" name="difficulty" value="${difficulty}" />
        <label>Username</label><input type="text" name="username" />
        <label>Password</label><input type="text" name="password" />
        <button type="submit">Log In</button>
      </form>
      ${difficulty === "easy" ? `<p class="note">The error message itself tells you whether the username exists.</p>` : ""}
      ${difficulty === "medium" ? `<p class="note">The error message is now identical either way — but check the "serverProcessingMs" field in the response for a timing difference between valid and invalid usernames.</p>` : ""}
      ${difficulty === "hard" ? `<p class="note">Message and timing are both identical now. Try several failed attempts against the SAME username — a lockout that only triggers for valid usernames is its own side-channel.</p>` : ""}
    `
  }));
});
router.get("/vuln/brute-force/login", async (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  const st = C.labState(session, "brute-force", { attempts: {} });
  const username = req.query.username || "";
  const password = req.query.password || "";
  const validUser = BF_USERS[username];

  if (difficulty === "easy") {
    if (!validUser) return res.json({ error: "No such user." });
    if (password !== validUser.password) return res.json({ error: "Incorrect password." });
  } else if (difficulty === "medium") {
    const delayMs = validUser ? 300 : 50;
    await sleep(delayMs);
    if (!validUser || password !== validUser.password) return res.json({ error: "Invalid username or password.", serverProcessingMs: delayMs });
  } else {
    st.attempts[username] = (st.attempts[username] || 0) + 1;
    await sleep(150);
    if (validUser && st.attempts[username] >= 5) {
      const flag = C.getFlag(session, "brute-force", difficulty);
      return res.json({ error: "Account temporarily locked due to repeated failed attempts.", enumerationFlag: flag, note: "Only valid usernames lock — this response itself confirms '" + username + "' is real." });
    }
    if (!validUser || password !== validUser.password) return res.json({ error: "Invalid username or password." });
  }
  const flag = C.getFlag(session, "brute-force", difficulty);
  res.json({ success: true, message: "Login successful.", flag });
});

module.exports = { router };
