const express = require("express");
const router = express.Router();
const C = require("./vuln-common");

// ============================================================= XSS =========
function sanitizeForXss(input, difficulty) {
  if (difficulty === "easy") return input;
  if (difficulty === "medium") return input.replace(/<script/gi, "");
  return input.replace(/<script/gi, "").replace(/onerror\s*=/gi, "").replace(/onload\s*=/gi, "");
}
router.get("/vuln/xss", (req, res) => {
  const difficulty = C.difficultyOf(req);
  res.redirect(`/vuln/xss/search?difficulty=${difficulty}`);
});
router.get("/vuln/xss/search", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  const rawQuery = req.query.q || "";
  const rendered = rawQuery ? sanitizeForXss(rawQuery, difficulty) : "";
  const exploited = /<[a-z]/i.test(rendered);
  const flag = exploited ? C.getFlag(session, "xss", difficulty) : null;
  res.send(C.renderVulnPage({
    appName: "SecureCorp Notes Search", difficulty,
    bodyHtml: `
      <h1>Search Notes</h1>
      <form method="GET" action="/vuln/xss/search">
        <input type="hidden" name="difficulty" value="${difficulty}" />
        <input type="text" name="q" placeholder="Search notes..." value="${rendered.replace(/"/g, "&quot;")}" />
        <button type="submit">Search</button>
      </form>
      <div class="result">Results for: ${rendered || "(nothing yet — try a query)"}</div>
      ${flag ? `<div class="result" style="border-color:#4ade80;"><strong>🚩 A live tag survived the filter — your script would execute here.</strong>\nFLAG: ${flag}</div>` : ""}
      <p class="note">Session cookie is deliberately readable from JS for this lab (non-HttpOnly).</p>
    `
  }));
});

// ============================================================= CSRF ========
router.get("/vuln/csrf", (req, res) => {
  const difficulty = C.difficultyOf(req);
  res.redirect(`/vuln/csrf/account?difficulty=${difficulty}`);
});
router.get("/vuln/csrf/account", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  if (!session.canonicalId) session.canonicalId = C.USERS[Math.floor(Math.random() * C.USERS.length)].canonicalId;
  res.send(C.renderVulnPage({
    appName: "SecureCorp Account", difficulty,
    bodyHtml: `
      <h1>Account Settings</h1>
      <p class="note">Logged in as user #${session.canonicalId}.</p>
      <div class="result" style="border-color:#f2b8b5;background:#fff5f5;">
        <strong>⚠ Danger Zone</strong><br/><br/>
        <a class="btn danger" href="/vuln/csrf/delete?difficulty=${difficulty}">Delete My Account</a>
      </div>
      <p class="note" style="margin-top:16px;">This deletes the account via a plain GET request — no confirmation, no CSRF token.</p>
      <p class="note"><a href="/vuln/csrf/poc?difficulty=${difficulty}" target="_blank">Open the simulated attacker page →</a></p>
    `
  }));
});
router.get("/vuln/csrf/delete", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { sid, session } = C.getOrInitSession(req, res);

  if (difficulty === "medium") {
    const origin = req.headers.origin;
    if (origin && !origin.includes(req.headers.host)) {
      return res.send(C.renderVulnPage({ appName: "SecureCorp Account", difficulty, bodyHtml: `<h1>Blocked</h1><p class="note">Cross-origin Origin header present.</p>` }));
    }
  }
  if (difficulty === "hard") {
    const mode = req.headers["sec-fetch-mode"];
    if (mode && mode !== "navigate") {
      return res.send(C.renderVulnPage({ appName: "SecureCorp Account", difficulty, bodyHtml: `<h1>Blocked</h1><p class="note">Request looks like a subresource load (img/fetch), not a top-level navigation. Try a real link click.</p>` }));
    }
  }
  session.canonicalId = null;
  const flag = C.getFlag(session, "csrf", difficulty);
  res.send(C.renderVulnPage({
    appName: "SecureCorp Account", difficulty,
    bodyHtml: `<h1>💥 Account Deleted</h1><p class="note">This account was deleted via a forged GET request with no CSRF protection.</p><div class="result" style="border-color:#4ade80;"><strong>🚩 Exploit confirmed.</strong>\nFLAG: ${flag}</div>`
  }));
});
router.get("/vuln/csrf/poc", (req, res) => {
  const difficulty = C.difficultyOf(req);
  res.send(`<!DOCTYPE html><html><head><meta charset="utf-8" /><title>You Won a Prize!</title>
  <style>body{background:#111;color:#eee;font-family:sans-serif;padding:2rem;}</style></head>
  <body>
    <h2>🎉 You won a free prize! 🎉</h2>
    <p style="color:#999;">(Simulated attacker-controlled page embedding the CSRF exploit.)</p>
    <img src="/vuln/csrf/delete?difficulty=${difficulty}" style="display:none" alt="" />
    <p><a href="/vuln/csrf/delete?difficulty=${difficulty}">Click here to claim it</a> (a real top-level link click — needed for hard mode)</p>
  </body></html>`);
});

// ===================================================== OPEN REDIRECT =======
router.get("/vuln/open-redirect", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  const next = req.query.next;
  if (!next) {
    return res.send(C.renderVulnPage({
      appName: "SecureCorp SSO", difficulty,
      bodyHtml: `
        <h1>Continue to your destination</h1>
        <form method="GET">
          <input type="hidden" name="difficulty" value="${difficulty}" />
          <label>Continue to (next)</label>
          <input type="text" name="next" placeholder="/dashboard" />
          <button type="submit">Continue</button>
        </form>
        <p class="note">This mimics a real "log in, then continue to ?next=" SSO flow.</p>
      `
    }));
  }
  if (difficulty === "medium" && !next.startsWith("/")) {
    return res.send(C.renderVulnPage({ appName: "SecureCorp SSO", difficulty, bodyHtml: `<h1>Blocked</h1><p class="note">next must be a relative path starting with "/".</p>` }));
  }
  if (difficulty === "hard" && !next.includes("securecorp-demo.test")) {
    return res.send(C.renderVulnPage({ appName: "SecureCorp SSO", difficulty, bodyHtml: `<h1>Blocked</h1><p class="note">next must reference the securecorp-demo.test domain.</p>` }));
  }
  const offDomain = /^https?:\/\//i.test(next) || next.startsWith("//");
  const looksLikeRealAttackerTarget = offDomain && !/^https?:\/\/securecorp-demo\.test(\/|$|\?)/i.test(next.startsWith("//") ? "https:" + next : next);
  const flag = looksLikeRealAttackerTarget ? C.getFlag(session, "open-redirect", difficulty) : null;
  res.send(C.renderVulnPage({
    appName: "SecureCorp SSO", difficulty,
    bodyHtml: `<h1>Redirecting…</h1><p class="note">This app would now redirect you to:</p><div class="result">${next}</div><p class="note">(No real external navigation happens in this sandbox — but a real app would call res.redirect(next) here.)</p>${flag ? `<div class="result" style="border-color:#4ade80;"><strong>🚩 Off-domain redirect confirmed.</strong>\nFLAG: ${flag}</div>` : ""}`
  }));
});

// ================================================ CLIENT-SIDE TEMPLATE INJ ==
router.get("/vuln/cstl", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  const flag = C.getFlag(session, "cstl", difficulty);
  const examplePayload = { easy: "{{constructor.constructor('alert(1)')()}}", medium: "{{Function('alert(1)')()}}", hard: "{{globalThis['Func'+'tion']('alert(1)')()}}" }[difficulty];
  res.send(C.renderVulnPage({
    appName: "SecureCorp Comment Preview", difficulty,
    bodyHtml: `
      <h1>Live Comment Preview</h1>
      <p class="note">This preview evaluates {{ }} expressions client-side as you type (a real, sandboxed AngularJS-style template evaluator, running only in your own browser tab).</p>
      <label>Your comment</label>
      <textarea id="commentInput" oninput="renderPreview()">Nice product, {{7*7}}!</textarea>
      <div class="result" id="preview"></div>
      <div class="result" id="flagBox" style="display:none;border-color:#4ade80;"></div>
      ${difficulty === "medium" ? `<p class="note">The word "constructor" is now stripped before evaluation. Try a payload built around the global <code>Function</code> instead.</p>` : ""}
      ${difficulty === "hard" ? `<p class="note">Both "constructor" and "Function" are stripped as literal words. Try building "Function" at runtime via string concatenation so the literal word never appears in your payload.</p>` : ""}
      <script>
        const SERVER_FLAG = ${JSON.stringify(flag)};
        const DIFFICULTY = ${JSON.stringify(difficulty)};
        function filterExpr(expr){
          if (DIFFICULTY === 'easy') return expr;
          if (DIFFICULTY === 'medium') return expr.replace(/constructor/gi, '');
          return expr.replace(/constructor/gi, '').replace(/\\bfunction\\b/gi, '');
        }
        function isExploited(rawExpr){
          const noConstructor = !/constructor/i.test(rawExpr);
          const noFunction = !/\\bfunction\\b/i.test(rawExpr);
          if (DIFFICULTY === 'easy') return /constructor/i.test(rawExpr);
          if (DIFFICULTY === 'medium') return noConstructor && /\\bfunction\\b/i.test(rawExpr);
          return noConstructor && noFunction && /globalthis/i.test(rawExpr);
        }
        function evalExpr(rawExpr){
          const filtered = filterExpr(rawExpr);
          try {
            const result = String(Function('"use strict"; return (' + filtered + ')')());
            if (isExploited(rawExpr)) {
              document.getElementById('flagBox').style.display = 'block';
              document.getElementById('flagBox').innerHTML = '<strong>🚩 Exploit confirmed — real JS execution achieved.</strong>\\nFLAG: ' + SERVER_FLAG;
            }
            return result;
          } catch(e){ return '[error: ' + e.message + ']'; }
        }
        function renderPreview(){
          const raw = document.getElementById('commentInput').value;
          const rendered = raw.replace(/\\{\\{(.*?)\\}\\}/g, (m, expr) => evalExpr(expr));
          document.getElementById('preview').innerHTML = rendered;
        }
        renderPreview();
      </script>
      <p class="note">Try: <code>${examplePayload}</code></p>
    `
  }));
});

// ============================================================ POSTMESSAGE ==
router.get("/vuln/postmessage", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  const flag = C.getFlag(session, "postmessage", difficulty);
  const st = C.labState(session, "postmessage", { token: C.randomHex(4) });
  const pageToken = st.token;
  const widgetMsg = difficulty === "easy"
    ? "parent.postMessage({balance:150.00},'*')"
    : difficulty === "medium"
    ? "parent.postMessage({balance:150.00, source:'legit-widget'},'*')"
    : `parent.postMessage({balance:150.00, source:'legit-widget', token:'${pageToken}'},'*')`;
  res.send(C.renderVulnPage({
    appName: "SecureCorp Wallet", difficulty,
    bodyHtml: `
      <h1>Wallet Widget</h1>
      <p class="note">Balance: <strong id="bal">$120.00</strong></p>
      <p class="note">This page listens for postMessage updates from the widget iframe below <strong>without checking the sender's origin</strong>.</p>
      <iframe style="width:100%;height:80px;border:1px solid #e2e5e9;border-radius:8px;" srcdoc="<button onclick=&quot;${widgetMsg}&quot;>Simulate legit widget update (+$30)</button>"></iframe>
      <p class="note" style="margin-top:14px;"><a href="/vuln/postmessage/attacker?difficulty=${difficulty}" target="_blank">Open the simulated attacker page →</a> (lets you craft a forged message)</p>
      ${difficulty === "medium" ? `<p class="note">The listener now also checks for a <code>source</code> field. View-source the widget iframe above to see what value it expects.</p>` : ""}
      ${difficulty === "hard" ? `<p class="note">The listener also checks a per-session <code>token</code> field. It's embedded in this page's source (view-source) as a hidden JS variable — not shown anywhere in the visible UI.</p><!-- PAGE_TOKEN (for view-source discovery): ${pageToken} -->` : ""}
      <div class="result" id="flagBox" style="display:none;border-color:#4ade80;"></div>
      <script>
        const SERVER_FLAG = ${JSON.stringify(flag)};
        const PAGE_TOKEN = ${JSON.stringify(pageToken)};
        const DIFFICULTY = ${JSON.stringify(difficulty)};
        window.addEventListener('message', function(event){
          // vulnerable: no event.origin check, at any difficulty
          if (!event.data || typeof event.data.balance !== 'number') return;
          if (DIFFICULTY !== 'easy' && event.data.source !== 'legit-widget') return;
          if (DIFFICULTY === 'hard' && event.data.token !== PAGE_TOKEN) return;
          document.getElementById('bal').textContent = '$' + event.data.balance.toFixed(2);
          if (event.data.balance !== 120 && event.data.balance !== 150) {
            document.getElementById('flagBox').style.display = 'block';
            document.getElementById('flagBox').innerHTML = '<strong>🚩 Forged balance accepted from an unverified origin.</strong>\\nFLAG: ' + SERVER_FLAG;
          }
        });
      </script>
    `
  }));
});
router.get("/vuln/postmessage/attacker", (req, res) => {
  const difficulty = C.difficultyOf(req);
  res.send(`<!DOCTYPE html><html><head><meta charset="utf-8"/><title>Attacker Page</title>
  <style>body{font-family:sans-serif;background:#111;color:#eee;padding:2rem;} input{padding:8px;margin:6px 0;width:280px;background:#222;border:1px solid #444;color:#eee;border-radius:4px;} label{display:block;font-size:.85rem;color:#aaa;margin-top:10px;} button{background:#f5a524;color:#1c1200;border:none;padding:10px 18px;border-radius:6px;font-weight:700;cursor:pointer;margin-top:14px;}</style></head><body>
    <h2>Attacker-controlled page</h2>
    <p>Open the Wallet Widget in another tab first (so this page's "opener" is set), then click the link back here, fill in the fields, and send.</p>
    <label>Forged balance</label><input type="text" id="balance" value="999999.99" />
    ${difficulty !== "easy" ? `<label>source field (find the expected value by viewing the wallet page's iframe source)</label><input type="text" id="source" placeholder="?" />` : ""}
    ${difficulty === "hard" ? `<label>token field (find it by viewing the wallet page's source)</label><input type="text" id="token" placeholder="?" />` : ""}
    <br/><button onclick="send()">Post forged message to opener</button>
    <p id="status" style="color:#4ade80;"></p>
    <script>
      function send(){
        if (!window.opener) { document.getElementById('status').textContent = 'Open this page BY CLICKING the link from the Wallet tab (so window.opener is set), not by typing the URL directly.'; return; }
        const msg = { balance: parseFloat(document.getElementById('balance').value) };
        const sourceEl = document.getElementById('source');
        if (sourceEl) msg.source = sourceEl.value;
        const tokenEl = document.getElementById('token');
        if (tokenEl) msg.token = tokenEl.value;
        window.opener.postMessage(msg, '*');
        document.getElementById('status').textContent = 'Message sent to opener window.';
      }
    </script>
  </body></html>`);
});

// ===================================================== PROTOTYPE POLLUTION =
router.get("/vuln/prototype-pollution", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  const flag = C.getFlag(session, "prototype-pollution", difficulty);
  res.send(C.renderVulnPage({
    appName: "SecureCorp Theme Customizer", difficulty,
    bodyHtml: `
      <h1>Theme Customizer</h1>
      <p class="note">This page merges URL query parameters into a settings object client-side (a common real-world "extend/merge" bug), then checks <code>settings.isAdmin</code> to decide whether to show the Admin Panel link.</p>
      <div id="adminLink" style="display:none;"><a class="btn" href="#">⚙ Admin Panel (unlocked)</a></div>
      <div class="result" id="settingsOut"></div>
      <div class="result" id="flagBox" style="display:none;border-color:#4ade80;"></div>
      ${difficulty === "easy" ? `<p class="note">Try visiting this page with <code>?__proto__[isAdmin]=true</code> appended to the URL.</p>` : ""}
      ${difficulty === "medium" ? `<p class="note">The direct <code>__proto__</code> key is now blocked by a denylist. Try going through <code>constructor[prototype]</code> instead — it reaches the same shared prototype.</p>` : ""}
      ${difficulty === "hard" ? `<p class="note">The denylist now blocks <code>__proto__</code>, <code>constructor</code>, AND <code>prototype</code> as keys at any level. This is actually a complete, correct fix for this class of bug — there's no bypass here. (Confirm that for yourself, and note it in your report.)</p>` : ""}
      <script>
        const SERVER_FLAG = ${JSON.stringify(flag)};
        const DIFFICULTY = ${JSON.stringify(difficulty)};
        const DENYLIST = DIFFICULTY === 'easy' ? [] : DIFFICULTY === 'medium' ? ['__proto__'] : ['__proto__','constructor','prototype'];
        function merge(target, src){
          for (const key in src){
            if (DENYLIST.includes(key)) continue;
            if (typeof src[key] === 'object' && src[key] !== null) { target[key] = target[key] || {}; merge(target[key], src[key]); }
            else target[key] = src[key];
          }
          return target;
        }
        function parseQueryToObject(qs){
          // Built with null-prototype objects so "__proto__" is just a normal
          // key while parsing — the ONLY place pollution can occur is inside
          // merge() below, exactly where the denylist check lives.
          const obj = Object.create(null);
          new URLSearchParams(qs).forEach((value, key) => {
            const parts = key.replace(/\\]/g,'').split('[');
            let cur = obj;
            for (let i=0;i<parts.length-1;i++){
              if (!cur[parts[i]] || typeof cur[parts[i]] !== 'object') cur[parts[i]] = Object.create(null);
              cur = cur[parts[i]];
            }
            cur[parts[parts.length-1]] = value;
          });
          return obj;
        }
        const settings = {};
        merge(settings, parseQueryToObject(location.search));
        document.getElementById('settingsOut').textContent = 'Merged settings: ' + JSON.stringify(settings) + ' | denylist active: [' + DENYLIST.join(', ') + ']';
        if (({}).isAdmin || settings.isAdmin) {
          document.getElementById('adminLink').style.display = 'block';
          document.getElementById('flagBox').style.display = 'block';
          document.getElementById('flagBox').innerHTML = '<strong>🚩 Object.prototype polluted — admin check bypassed.</strong>\\nFLAG: ' + SERVER_FLAG;
        }
      </script>
    `
  }));
});

module.exports = { router, sanitizeForXss };
