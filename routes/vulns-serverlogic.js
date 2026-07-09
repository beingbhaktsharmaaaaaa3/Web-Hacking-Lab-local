const express = require("express");
const router = express.Router();
const path = require("path");
const fs = require("fs");
const multer = require("multer");
const C = require("./vuln-common");

// =============================================================== SSRF ======
function toIp(n) { return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join("."); }
function hostOf(url) { const m = url.match(/^https?:\/\/([^\/]+)/i); return m ? m[1].split(":")[0] : url; }
function isKnownInternalLiteral(s) { return /169\.254\.169\.254|127\.0\.0\.1|\blocalhost\b|internal-api\.local/i.test(s); }
function numericHostToInternalIp(hostToken) {
  if (/^\d+$/.test(hostToken)) { const ip = toIp(parseInt(hostToken, 10)); if (ip === "127.0.0.1" || ip === "169.254.169.254") return ip; }
  if (/^0x[0-9a-f]+$/i.test(hostToken)) { const ip = toIp(parseInt(hostToken, 16)); if (ip === "127.0.0.1" || ip === "169.254.169.254") return ip; }
  return null;
}
function lookupFakeService(effectiveUrl) {
  const lower = effectiveUrl.toLowerCase();
  const key = Object.keys(C.FAKE_INTERNAL_SERVICES).find((k) => lower.includes(k.split("/")[0]));
  return key ? C.FAKE_INTERNAL_SERVICES[key] : null;
}
router.get("/vuln/ssrf", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  const url = req.query.url;
  let output = "", flag = null;
  if (url !== undefined) {
    let effectiveUrl = url;
    let blocked = false;

    if (difficulty !== "easy" && isKnownInternalLiteral(url)) blocked = true;

    if (difficulty !== "easy") {
      const numericIp = numericHostToInternalIp(hostOf(url));
      if (numericIp) { blocked = false; effectiveUrl = url.replace(hostOf(url), numericIp); }
    }

    if (difficulty === "hard") {
      const redirMatch = url.match(/safe-redirector\.securecorp-demo\.test\/go\?to=([^&]+)/i);
      if (redirMatch) {
        const target = decodeURIComponent(redirMatch[1]);
        effectiveUrl = target;
        blocked = false;
      }
    }

    if (blocked) {
      output = `Request to ${url} was blocked — that host looked internal.`;
    } else {
      const fake = lookupFakeService(effectiveUrl);
      if (fake) {
        output = `Response from ${effectiveUrl}:\n${fake}`;
        flag = C.getFlag(session, "ssrf", difficulty);
      } else {
        output = `No internal service responded at that address. (This sandbox never makes real outbound requests — try 169.254.169.254, 127.0.0.1, localhost:6379, or internal-api.local.)`;
      }
    }
  }
  res.send(C.renderVulnPage({
    appName: "SecureCorp Health Check Tool", difficulty,
    bodyHtml: `
      <h1>Internal Health Check</h1>
      <p class="note">Paste a URL and we'll (simulate) checking it. No real outbound requests are ever made by this sandbox.</p>
      <form method="GET">
        <input type="hidden" name="difficulty" value="${difficulty}" />
        <label>URL</label><input type="text" name="url" value="${(url || "").replace(/"/g, "&quot;")}" placeholder="http://169.254.169.254/latest/meta-data/iam/security-credentials/admin" />
        <button type="submit">Check</button>
      </form>
      ${output ? `<div class="result">${output}</div>` : ""}
      ${flag ? `<div class="result" style="border-color:#4ade80;"><strong>🚩 Internal service reached via SSRF.</strong>\nFLAG: ${flag}</div>` : ""}
    `
  }));
});

// ======================================================== FILE UPLOAD ======
const UPLOAD_DIR = path.join(__dirname, "..", "uploads_sandbox");
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });
const upload = multer({ dest: UPLOAD_DIR, limits: { fileSize: 2 * 1024 * 1024 } });

router.get("/vuln/file-upload", (req, res) => {
  const difficulty = C.difficultyOf(req);
  C.getOrInitSession(req, res);
  res.send(C.renderVulnPage({
    appName: "SecureCorp Profile Picture Upload", difficulty,
    extraHead: `<meta charset="utf-8" />`,
    bodyHtml: `
      <h1>Upload Profile Picture</h1>
      <p class="note">Files are saved to a private sandbox folder on your own machine (never web-served or executed) — this teaches the validation-bypass technique with zero real risk.</p>
      <form method="POST" action="/vuln/file-upload?difficulty=${difficulty}" enctype="multipart/form-data">
        <input type="hidden" name="difficulty" value="${difficulty}" />
        <label>File</label><input type="file" name="file" />
        <button type="submit">Upload</button>
      </form>
    `
  }));
});
router.post("/vuln/file-upload", upload.single("file"), (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  const file = req.file;
  let message, flag = null;
  if (!file) {
    message = "No file received.";
  } else {
    const name = file.originalname || "";
    let blocked = false, reason = "";
    if (difficulty === "medium" && /\.php$/.test(name)) { blocked = true; reason = 'Blocked: ".php" extension not allowed.'; }
    if (difficulty === "hard" && /\.(php|phtml|php5|asp|jsp)$/i.test(name)) { blocked = true; reason = "Blocked: executable-looking extension not allowed."; }
    try { fs.unlinkSync(file.path); } catch (e) { /* ignore */ }
    if (blocked) {
      message = reason;
    } else {
      message = `✅ Accepted "${name}" (${file.mimetype}, ${file.size} bytes). In a real (misconfigured) deployment, this would be stored at a web-accessible path and, with an executable extension, would run as server-side code.`;
      flag = C.getFlag(session, "file-upload", difficulty);
    }
  }
  res.send(C.renderVulnPage({
    appName: "SecureCorp Profile Picture Upload", difficulty,
    bodyHtml: `<h1>Upload Result</h1><div class="result">${message}</div>${flag ? `<div class="result" style="border-color:#4ade80;"><strong>🚩 Upload validation bypassed.</strong>\nFLAG: ${flag}</div>` : ""}<p style="margin-top:16px;"><a class="btn secondary" href="/vuln/file-upload?difficulty=${difficulty}">← Try another file</a></p>`
  }));
});

// ============================================ PATH TRAVERSAL & LFI (shared) =
function traverse(baseParts, userInput, difficulty) {
  let p = userInput || "";
  if (difficulty === "medium") {
    p = p.split("../").join("");
  } else if (difficulty === "hard") {
    let prev;
    do { prev = p; p = p.split("../").join(""); } while (p !== prev);
    try { p = decodeURIComponent(p); } catch (e) { /* ignore */ }
  }
  const stack = baseParts.slice();
  for (const seg of p.split("/")) {
    if (seg === "..") stack.pop();
    else if (seg === "" || seg === ".") continue;
    else stack.push(seg);
  }
  return "/" + stack.join("/");
}

router.get("/vuln/path-traversal", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  const file = req.query.file;
  let output = "", flag = null;
  if (file !== undefined) {
    const resolved = traverse(["app", "documents"], file, difficulty);
    const escaped = resolved.indexOf("/app/documents") !== 0;
    const content = C.VFS[resolved];
    output = `Resolved path: ${resolved}\n\n` + (content || "[not found in sandbox]");
    if (escaped && content) flag = C.getFlag(session, "path-traversal", difficulty);
  }
  res.send(C.renderVulnPage({
    appName: "SecureCorp Document Viewer", difficulty,
    bodyHtml: `
      <h1>View a Document</h1>
      <form method="GET">
        <input type="hidden" name="difficulty" value="${difficulty}" />
        <label>File</label><input type="text" name="file" value="${(file || "").replace(/"/g, "&quot;")}" placeholder="report1.txt" />
        <button type="submit">View</button>
      </form>
      ${output ? `<div class="result">${output.replace(/</g, "&lt;")}</div>` : ""}
      ${flag ? `<div class="result" style="border-color:#4ade80;"><strong>🚩 Escaped the documents directory.</strong>\nFLAG: ${flag}</div>` : ""}
    `
  }));
});

router.get("/vuln/lfi", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  const lang = req.query.lang;
  let output = "", flag = null;
  if (lang !== undefined) {
    const resolved = traverse(["app", "templates"], lang, difficulty);
    const withExt = C.VFS[resolved] ? resolved : resolved + ".txt";
    const content = C.VFS[withExt] || C.VFS[resolved];
    const escaped = resolved.indexOf("/app/templates") !== 0;
    output = `Included: ${withExt}\n\n` + (content || "[not found in sandbox]");
    if (escaped && content) flag = C.getFlag(session, "lfi", difficulty);
  }
  res.send(C.renderVulnPage({
    appName: "SecureCorp Multilingual Loader", difficulty,
    bodyHtml: `
      <h1>Choose a Language</h1>
      <form method="GET">
        <input type="hidden" name="difficulty" value="${difficulty}" />
        <label>Language (lang) — try en, fr, es, or a traversal payload</label>
        <input type="text" name="lang" value="${(lang || "").replace(/"/g, "&quot;")}" placeholder="en" />
        <button type="submit">Load</button>
      </form>
      ${output ? `<div class="result">${output.replace(/</g, "&lt;")}</div>` : ""}
      ${flag ? `<div class="result" style="border-color:#4ade80;"><strong>🚩 Escaped the templates directory.</strong>\nFLAG: ${flag}</div>` : ""}
      <p class="note">Try: <code>../../../etc/passwd</code></p>
    `
  }));
});

// ===================================================== CACHE POISONING =====
const POISON_CACHE = new Map();
const POISON_PARAM = { easy: "utm_source", medium: "ref", hard: "lang" };
router.get("/vuln/cache-poisoning", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  const vulnParam = POISON_PARAM[difficulty];
  // Cache key includes every OTHER known tracking param (simulating "we fixed the last bug we found")
  // but always omits this tier's specific unkeyed param.
  const otherParams = Object.values(POISON_PARAM).filter((p) => p !== vulnParam);
  const keyParts = otherParams.map((p) => `${p}=${req.query[p] || ""}`).join("&");
  const cacheKey = req.path + "?" + keyParts;
  const now = Date.now();
  const cached = POISON_CACHE.get(cacheKey);
  if (cached && now - cached.time < 30000) {
    return res.send(cached.html + (difficulty === "easy" ? "\n<!-- served from shared cache -->" : ""));
  }
  const source = req.query[vulnParam] || "direct";
  const flag = source !== "direct" ? C.getFlag(session, "cache-poisoning", difficulty) : null;
  const html = C.renderVulnPage({
    appName: "SecureCorp Homepage", difficulty,
    bodyHtml: `<h1>Welcome!</h1><p class="note">Thanks for visiting from: <strong>${source}</strong> (via the "${vulnParam}" parameter)</p><p class="note">This whole page is cached for 30 seconds for every visitor. The cache key includes every OTHER known tracking parameter, but not "${vulnParam}".</p>${flag ? `<div class="result" style="border-color:#4ade80;"><strong>🚩 This flag was baked into a cached response — reload this exact URL with NO query string within 30s and it'll still appear.</strong>\nFLAG: ${flag}</div>` : ""}`
  });
  POISON_CACHE.set(cacheKey, { html, time: now });
  res.send(html);
});

// ===================================================== CACHE DECEPTION =====
const DECEPTION_CACHE = new Map();
router.get(/^\/vuln\/cache-deception\/account(\/.*)?$/, (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  const fullPath = req.path;
  const fullUrl = req.originalUrl;

  if (difficulty !== "easy" && fullPath !== "/vuln/cache-deception/account") {
    return res.status(404).send("Not found. (The trailing-path-segment trick from easier tiers is fixed here.)");
  }

  let cacheable, cacheKey;
  if (difficulty === "easy") {
    cacheable = /\.(js|css|jpg|png|json|ico)$/i.test(fullPath);
    cacheKey = fullPath;
  } else if (difficulty === "medium") {
    cacheable = /\.(js|css|jpg|png|json|ico)/i.test(fullUrl); // naive: matches anywhere in the full URL, including query
    cacheKey = fullUrl;
  } else {
    cacheable = /=[^&]*\.(js|css|jpg|png|json|ico)/i.test(fullUrl); // only matches a query VALUE specifically
    cacheKey = fullUrl;
  }

  if (cacheable) {
    const cached = DECEPTION_CACHE.get(cacheKey);
    if (cached) return res.send(cached);
  }
  const apiKey = "sk_live_FAKE_" + (session.canonicalId || Math.floor(Math.random() * 9000 + 1000)) + "_demo";
  const flag = cacheable ? C.getFlag(session, "cache-deception", difficulty) : null;
  const html = C.renderVulnPage({
    appName: "SecureCorp My Account", difficulty,
    bodyHtml: `<h1>My Account</h1><p class="note">Email: demo-user@securecorp-demo.test</p><p class="note">API Key: <span class="field-hidden-value">${apiKey}</span></p><p class="note">Requested: ${fullUrl}</p>${flag ? `<div class="result" style="border-color:#4ade80;"><strong>🚩 Private data cached under a deceptive URL.</strong>\nFLAG: ${flag}</div>` : ""}`
  });
  if (cacheable) DECEPTION_CACHE.set(cacheKey, html);
  res.send(html);
});
router.get("/vuln/cache-deception", (req, res) => res.redirect(`/vuln/cache-deception/account?difficulty=${C.difficultyOf(req)}`));

// =================================================== REQUEST SMUGGLING =====
// A textual analyzer (not a live two-server exploit) — parses a pasted raw
// request two different ways, mirroring how a front-end (Content-Length)
// and back-end (Transfer-Encoding) can disagree about where a request ends.
// The front-end here always trusts Content-Length only (never looks at TE —
// a realistic legacy-proxy simulation). What changes per difficulty is how
// strict the BACK-END is about recognizing a Transfer-Encoding header as
// chunked — each tier requires a genuinely different header construction.
function frontendView(raw) {
  const lines = raw.split("\n");
  const headerEnd = lines.findIndex((l) => l.trim() === "");
  const headers = lines.slice(0, headerEnd === -1 ? lines.length : headerEnd);
  const bodyLines = headerEnd === -1 ? [] : lines.slice(headerEnd + 1);
  const bodyText = bodyLines.join("\n");
  const clHeader = headers.find((h) => /^content-length:/i.test(h));
  const cl = clHeader ? parseInt(clHeader.split(":")[1].trim(), 10) : null;
  if (cl === null || Number.isNaN(cl)) return { request1: bodyText, leftover: "" };
  return { request1: bodyText.slice(0, cl), leftover: bodyText.slice(cl) };
}
function getTELines(headers) { return headers.filter((h) => /^transfer-encoding\s*:/i.test(h)); }
function backendRecognizesChunked(headers, difficulty) {
  const teLines = getTELines(headers);
  if (teLines.length === 0) return false;
  if (difficulty === "easy") return teLines.some((h) => /^transfer-encoding:\s*chunked\s*$/i.test(h));
  if (difficulty === "medium") return teLines.some((h) => /^transfer-encoding:\s*[\w-]+\s*,\s*chunked\s*$/i.test(h));
  if (teLines.length < 2) return false; // hard: requires two SEPARATE Transfer-Encoding lines
  return /^transfer-encoding:\s*chunked\s*$/i.test(teLines[teLines.length - 1]);
}
function backendView(raw, difficulty) {
  const lines = raw.split("\n");
  const headerEnd = lines.findIndex((l) => l.trim() === "");
  const headers = lines.slice(0, headerEnd === -1 ? lines.length : headerEnd);
  const bodyLines = headerEnd === -1 ? [] : lines.slice(headerEnd + 1);
  if (!backendRecognizesChunked(headers, difficulty)) return { request1: bodyLines.join("\n"), leftover: "" };
  let idx = 0, collected = [];
  while (idx < bodyLines.length) {
    const sizeLine = (bodyLines[idx] || "").trim();
    if (sizeLine === "0" || sizeLine === "") { idx++; break; }
    const size = parseInt(sizeLine, 16);
    idx++;
    if (Number.isNaN(size)) break;
    collected.push(bodyLines[idx]);
    idx++;
  }
  return { request1: collected.join("\n"), leftover: bodyLines.slice(idx).join("\n") };
}
const SMUGGLING_EXAMPLE = `POST /vuln/request-smuggling/target HTTP/1.1
Host: securecorp-demo.test
Content-Length: 4
Transfer-Encoding: chunked

0

SMUGGLED_REQUEST_HERE`;
router.get("/vuln/request-smuggling", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  const raw = req.query.raw !== undefined ? req.query.raw : SMUGGLING_EXAMPLE;
  let output = "", flag = null;
  if (req.query.raw !== undefined) {
    const front = frontendView(raw);
    const back = backendView(raw, difficulty);
    const desync = !!back.leftover.trim();
    output = `FRONT-END sees body as:\n"${front.request1}"\nleftover (front-end ignores this): "${front.leftover}"\n\nBACK-END sees body as:\n"${back.request1}"\nleftover (back-end treats this as the START of the NEXT request): "${back.leftover}"` +
      (desync ? "\n\n🚩 Desync: the back-end's leftover text would be smuggled into the next user's request." : "\n\nNo desync detected — the back-end doesn't recognize this Transfer-Encoding header as chunked at this difficulty.");
    if (desync) flag = C.getFlag(session, "request-smuggling", difficulty);
  }
  res.send(C.renderVulnPage({
    appName: "SecureCorp Protocol Analyzer", difficulty,
    bodyHtml: `
      <h1>Request Smuggling Analyzer</h1>
      <p class="note">This is a textual analyzer, not a live two-server exploit: paste a raw HTTP request and see how a Content-Length-based front-end and a Transfer-Encoding-based back-end disagree about where it ends.</p>
      ${difficulty === "easy" ? `<p class="note">The back-end recognizes a plain <code>Transfer-Encoding: chunked</code> header. The pre-filled example already triggers a desync.</p>` : ""}
      ${difficulty === "medium" ? `<p class="note">The back-end now only recognizes chunked encoding when it's part of a comma-separated list, e.g. <code>Transfer-Encoding: identity, chunked</code>. Edit the header below to that form.</p>` : ""}
      ${difficulty === "hard" ? `<p class="note">The back-end now requires TWO separate <code>Transfer-Encoding</code> header lines (it uses the last one). Try adding a line <code>Transfer-Encoding: identity</code> directly above the existing <code>Transfer-Encoding: chunked</code> line.</p>` : ""}
      <form method="GET">
        <input type="hidden" name="difficulty" value="${difficulty}" />
        <label>Raw request</label>
        <textarea name="raw" style="min-height:180px;">${raw.replace(/</g, "&lt;")}</textarea>
        <button type="submit">Analyze</button>
      </form>
      ${output ? `<div class="result">${output.replace(/</g, "&lt;")}</div>` : ""}
      ${flag ? `<div class="result" style="border-color:#4ade80;">FLAG: ${flag}</div>` : ""}
    `
  }));
});

// ===================================================== SECONDARY CONTEXT ===
const TICKETS = [];
function sanitizeShared(input, difficulty) {
  if (difficulty === "easy") return input;
  if (difficulty === "medium") return input.replace(/<script/gi, "");
  return input.replace(/<script/gi, "").replace(/onerror\s*=/gi, "").replace(/onload\s*=/gi, "");
}
router.get("/vuln/secondary-context", (req, res) => {
  const difficulty = C.difficultyOf(req);
  C.getOrInitSession(req, res);
  const name = req.query.name, msg = req.query.message;
  let confirmMsg = "";
  if (msg !== undefined) {
    TICKETS.push({ name: name || "anonymous", message: msg });
    confirmMsg = `<div class="result">✅ Ticket submitted. It looks perfectly safe here — but check the admin view.</div>`;
  }
  res.send(C.renderVulnPage({
    appName: "SecureCorp Support", difficulty,
    bodyHtml: `
      <h1>Submit a Support Ticket</h1>
      <form method="GET">
        <input type="hidden" name="difficulty" value="${difficulty}" />
        <label>Name</label><input type="text" name="name" />
        <label>Message</label><textarea name="message"></textarea>
        <button type="submit">Submit</button>
      </form>
      ${confirmMsg}
      <p class="note"><a href="/vuln/secondary-context/admin?difficulty=${difficulty}" target="_blank">Open the Admin Ticket Viewer →</a> (this is the "secondary context" where your input gets reused)</p>
    `
  }));
});
router.get("/vuln/secondary-context/admin", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  let flag = null;
  const rows = TICKETS.slice(-15).map((t) => {
    const rendered = sanitizeShared(t.message, difficulty);
    if (/<[a-z]/i.test(rendered)) flag = C.getFlag(session, "secondary-context", difficulty);
    return `<div class="result"><strong>${t.name}</strong>: ${rendered}</div>`;
  }).join("");
  res.send(C.renderVulnPage({
    appName: "SecureCorp Admin — Ticket Viewer", difficulty,
    bodyHtml: `<h1>All Tickets (admin view)</h1>${rows || '<p class="note">No tickets yet.</p>'}${flag ? `<div class="result" style="border-color:#4ade80;"><strong>🚩 Stored XSS triggered in the admin context.</strong>\nFLAG: ${flag}</div>` : ""}`
  }));
});

// ======================================================= RACE CONDITIONS ===
router.get("/vuln/race-conditions", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  const st = C.labState(session, "race-conditions", { balance: 50, redemptions: 0 });
  const suggestedN = difficulty === "easy" ? 3 : difficulty === "medium" ? 6 : 20;
  res.send(C.renderVulnPage({
    appName: "SecureCorp Gift Card", difficulty,
    bodyHtml: `
      <h1>Redeem Gift Card ($20 per redemption)</h1>
      <p class="note">Current balance: <strong id="bal">$${st.balance}</strong> · Redemptions so far: <strong id="cnt">${st.redemptions}</strong></p>
      <label>Simultaneous requests to fire</label>
      <input type="text" id="n" value="${suggestedN}" />
      <button onclick="fireRace()">Fire simultaneously</button>
      <div class="result" id="out"></div>
      <div class="result" id="flagBox" style="display:none;border-color:#4ade80;"></div>
      <script>
        async function fireRace(){
          const n = parseInt(document.getElementById('n').value,10) || 1;
          const calls = Array.from({length:n}, () => fetch('/vuln/race-conditions/redeem?difficulty=${difficulty}', {method:'POST'}).then(r=>r.json()));
          const results = await Promise.all(calls);
          const succeeded = results.filter(r=>r.success).length;
          const last = results[results.length-1];
          document.getElementById('bal').textContent = '$' + last.balance;
          document.getElementById('cnt').textContent = last.redemptions;
          document.getElementById('out').textContent = succeeded + ' of ' + n + ' requests succeeded. Balance is now $' + last.balance + ' after ' + last.redemptions + ' total redemptions (started at $50, should allow at most 2 redemptions if handled safely).';
          const withFlag = results.find(r => r.flag);
          if (withFlag) {
            document.getElementById('flagBox').style.display = 'block';
            document.getElementById('flagBox').innerHTML = '<strong>🚩 Race condition confirmed — over-redeemed.</strong>\\nFLAG: ' + withFlag.flag;
          }
        }
      </script>
    `
  }));
});
router.post("/vuln/race-conditions/redeem", async (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  const st = C.labState(session, "race-conditions", { balance: 50, redemptions: 0 });
  const delay = difficulty === "hard" ? 120 : difficulty === "medium" ? 220 : 400;
  if (st.balance >= 20) {
    await new Promise((r) => setTimeout(r, delay)); // <- the check-then-act gap
    st.balance -= 20;
    st.redemptions += 1;
    const flag = st.redemptions > 2 ? C.getFlag(session, "race-conditions", difficulty) : null;
    return res.json({ success: true, balance: st.balance, redemptions: st.redemptions, flag });
  }
  res.json({ success: false, balance: st.balance, redemptions: st.redemptions });
});

module.exports = { router };
