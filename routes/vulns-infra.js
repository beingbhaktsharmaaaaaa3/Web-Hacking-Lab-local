const express = require("express");
const router = express.Router();
const C = require("./vuln-common");

// =================================================== INFO DISCLOSURE =======
router.get("/vuln/info-disclosure", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  let flag = null;
  if (difficulty === "hard") {
    flag = C.getFlag(session, "info-disclosure", difficulty);
    res.setHeader("X-Internal-Build", `securecorp-app v3.2.1-rc4 (build 20260614, node18-alpine) FLAG:${flag}`);
  }
  const amount = req.query.amount;
  let errorBox = "";
  if (difficulty === "easy" && amount !== undefined && isNaN(Number(amount))) {
    flag = C.getFlag(session, "info-disclosure", difficulty);
    errorBox = `<div class="result">TypeError: Cannot convert "${amount}" to a number
  at calculateTotal (/app/src/controllers/checkout.js:42:18)
  at processOrder (/app/src/services/orderService.js:87:5)
  env dump: DB_PASS=Tr41n1ng_DB_2026! (fake, simulating a verbose error leaking env vars)
FLAG: ${flag}</div>`;
  }
  res.send(C.renderVulnPage({
    appName: "SecureCorp Checkout", difficulty,
    bodyHtml: `
      <h1>Checkout</h1>
      <form method="GET">
        <input type="hidden" name="difficulty" value="${difficulty}" />
        <label>Order amount</label><input type="text" name="amount" placeholder="49.99" />
        <button type="submit">Submit</button>
      </form>
      ${errorBox}
      ${difficulty === "medium" ? `<p class="note">Psst — some deployments accidentally ship their <code>.git</code> folder: <a href="/vuln/info-disclosure/.git-config?difficulty=${difficulty}">/.git-config</a></p>` : ""}
      ${difficulty === "hard" ? `<p class="note">Nothing looks unusual on the page itself here — check the response headers (Network tab / DevTools) for this request. The flag is inside the X-Internal-Build header value.</p>` : ""}
    `
  }));
});
router.get("/vuln/info-disclosure/.git-config", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  if (difficulty !== "medium") return res.status(404).send("Not found.");
  const flag = C.getFlag(session, "info-disclosure", difficulty);
  res.type("text/plain").send(`[remote "origin"]\n  url = https://ci:ghp_FAKEtoken1234567890abcdef@github.com/securecorp-demo/app.git\n[user]\n  db_password = Tr41n1ng_DB_2026! (fake credential)\n# FLAG: ${flag}`);
});

// ============================================== CLOUD STORAGE MISCONFIG ====
const FAKE_BUCKET = {
  "readme.txt": "Public readme — this one's actually meant to be public.",
  "employee-backup.csv": "id,name,note\n1,Alice,fake demo record\n2,Bob,fake demo record",
  "private/ceo-notes.txt": "Board meeting notes (fake, confidential) — Q3 numbers look good."
};
router.get("/vuln/cloud-storage-misconfig", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  const action = req.query.action;
  const key = req.query.key;
  const sig = req.query.sig;
  let output = "", flag = null;

  if (action === "list") {
    if (difficulty !== "easy") output = "🚫 403 — listing is disabled for this bucket.";
    else output = "Bucket contents:\n" + Object.keys(FAKE_BUCKET).join("\n");
  } else if (action === "get" && key) {
    if (difficulty === "hard" && !sig) {
      output = "🚫 403 — signed request required (sig param missing).";
    } else if (FAKE_BUCKET[key]) {
      output = `${key}:\n${FAKE_BUCKET[key]}`;
      if (key !== "readme.txt") flag = C.getFlag(session, "cloud-storage-misconfig", difficulty);
    } else {
      output = `404 — no object named "${key}".`;
    }
  }

  res.send(C.renderVulnPage({
    appName: "SecureCorp Cloud Storage", difficulty,
    bodyHtml: `
      <h1>Simulated Storage Bucket</h1>
      <p class="note">This mimics a real cloud storage bucket (e.g. S3) misconfiguration — no real cloud account involved.</p>
      <a class="btn secondary" href="/vuln/cloud-storage-misconfig?difficulty=${difficulty}&action=list">List bucket</a>
      <form method="GET" style="margin-top:14px;">
        <input type="hidden" name="difficulty" value="${difficulty}" />
        <input type="hidden" name="action" value="get" />
        <label>Object key</label><input type="text" name="key" placeholder="employee-backup.csv" />
        ${difficulty === "hard" ? `<label>sig</label><input type="text" name="sig" placeholder="(any value)" />` : ""}
        <button type="submit">Get object</button>
      </form>
      ${output ? `<div class="result">${output.replace(/</g, "&lt;")}</div>` : ""}
      ${flag ? `<div class="result" style="border-color:#4ade80;"><strong>🚩 Private object accessed without authorization.</strong>\nFLAG: ${flag}</div>` : ""}
    `
  }));
});

// ==================================================== SUBDOMAIN TAKEOVER ===
const CLAIMED_SLUGS = {};
function fakeDns(difficulty) {
  if (difficulty === "easy") {
    return {
      "www.securecorp-demo.test": { type: "A", value: "93.184.216.34" },
      "api.securecorp-demo.test": { type: "A", value: "93.184.216.35" },
      "shop.securecorp-demo.test": { type: "CNAME", value: "shop.trusted-cdn.test" },
      "old-blog.securecorp-demo.test": { type: "CNAME", value: "sc-oldblog.fakehost-service.test" }
    };
  }
  if (difficulty === "medium") {
    return {
      "www.securecorp-demo.test": { type: "A", value: "93.184.216.34" },
      "api.securecorp-demo.test": { type: "A", value: "93.184.216.35" },
      "shop.securecorp-demo.test": { type: "CNAME", value: "shop.trusted-cdn.test" },
      "mail.securecorp-demo.test": { type: "MX", value: "mail.securecorp-demo.test" },
      "cdn.securecorp-demo.test": { type: "CNAME", value: "cdn.trusted-cdn.test" },
      "status.securecorp-demo.test": { type: "CNAME", value: "status.trusted-statuspage.test" },
      "dev.securecorp-demo.test": { type: "A", value: "10.0.0.9" },
      "beta.securecorp-demo.test": { type: "CNAME", value: "sc-beta.fakehost-service.test" }
    };
  }
  return {
    "www.securecorp-demo.test": { type: "A", value: "93.184.216.34" },
    "api.securecorp-demo.test": { type: "A", value: "93.184.216.35" },
    "shop.securecorp-demo.test": { type: "CNAME", value: "shop.trusted-cdn.test" },
    "mail.securecorp-demo.test": { type: "MX", value: "mail.securecorp-demo.test" },
    "cdn.securecorp-demo.test": { type: "CNAME", value: "cdn.trusted-cdn.test" },
    "status.securecorp-demo.test": { type: "CNAME", value: "status.trusted-statuspage.test" },
    "dev.securecorp-demo.test": { type: "A", value: "10.0.0.9" },
    "archive.securecorp-demo.test": { type: "CNAME", value: "sc-archive.fakehost-service.test" }
  };
}
router.get("/vuln/subdomain-takeover", (req, res) => {
  const difficulty = C.difficultyOf(req);
  C.getOrInitSession(req, res);
  const host = req.query.host;
  const dns = fakeDns(difficulty);
  const danglingHost = difficulty === "easy" ? "old-blog.securecorp-demo.test" : difficulty === "medium" ? "beta.securecorp-demo.test" : "archive.securecorp-demo.test";
  let output = "";
  if (host) {
    const rec = dns[host];
    if (!rec) output = "NXDOMAIN — no such record.";
    else {
      output = `${host} → ${rec.type} ${rec.value}`;
      if (rec.type === "CNAME") {
        const isClaimed = difficulty === "hard" ? (req.query.verify === "true" ? !!CLAIMED_SLUGS[rec.value] : true) : !!CLAIMED_SLUGS[rec.value];
        output += isClaimed ? "\n✅ Target service slot is claimed." : "\n⚠️ Target service slot appears UNCLAIMED — a classic subdomain takeover setup.";
        if (difficulty === "hard" && req.query.verify !== "true") output += "\n(add the verify checkbox to actually check claim status)";
      }
    }
  }
  res.send(C.renderVulnPage({
    appName: "SecureCorp DNS Zone Lookup", difficulty,
    bodyHtml: `
      <h1>DNS Lookup Tool</h1>
      <form method="GET">
        <input type="hidden" name="difficulty" value="${difficulty}" />
        <label>Hostname</label><input type="text" name="host" placeholder="${danglingHost}" />
        ${difficulty === "hard" ? `<label><input type="checkbox" name="verify" value="true" style="width:auto;display:inline-block;margin-right:6px;" /> verify claim status</label>` : ""}
        <button type="submit">Lookup</button>
      </form>
      ${output ? `<div class="result">${output}</div>` : ""}
      <p class="note">Known subdomains to check: ${Object.keys(dns).join(", ")}</p>
      <p class="note" style="margin-top:12px;"><a href="/vuln/subdomain-takeover/claim?difficulty=${difficulty}">Claim an unclaimed hosting slot →</a></p>
    `
  }));
});
router.get("/vuln/subdomain-takeover/claim", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const slug = req.query.slug, content = req.query.content;
  const danglingHost = difficulty === "easy" ? "old-blog.securecorp-demo.test" : difficulty === "medium" ? "beta.securecorp-demo.test" : "archive.securecorp-demo.test";
  const danglingSlug = difficulty === "easy" ? "sc-oldblog.fakehost-service.test" : difficulty === "medium" ? "sc-beta.fakehost-service.test" : "sc-archive.fakehost-service.test";
  let message = "";
  if (slug) {
    CLAIMED_SLUGS[slug] = content || "(this space intentionally left blank by the attacker)";
    message = `<div class="result">✅ Claimed "${slug}". Now visit the subdomain preview to see your content served under SecureCorp's domain.</div>`;
  }
  res.send(C.renderVulnPage({
    appName: "Fakehost Hosting (simulated)", difficulty,
    bodyHtml: `
      <h1>Claim a Hosting Slot</h1>
      <p class="note">Simulates registering an abandoned third-party hosting slug that a dangling DNS CNAME still points to.</p>
      <form method="GET">
        <input type="hidden" name="difficulty" value="${difficulty}" />
        <label>Slug</label><input type="text" name="slug" placeholder="${danglingSlug}" />
        <label>Content to serve</label><input type="text" name="content" placeholder="Pwned by a training exercise" />
        <button type="submit">Claim</button>
      </form>
      ${message}
      <p class="note"><a href="/vuln/subdomain-takeover/preview?host=${danglingHost}&difficulty=${difficulty}" target="_blank">Preview ${danglingHost} →</a></p>
    `
  }));
});
router.get("/vuln/subdomain-takeover/preview", (req, res) => {
  const difficulty = C.difficultyOf(req);
  const { session } = C.getOrInitSession(req, res);
  const dns = fakeDns(difficulty);
  const rec = dns[req.query.host];
  const claimed = rec && rec.type === "CNAME" ? CLAIMED_SLUGS[rec.value] : null;
  const flag = claimed ? C.getFlag(session, "subdomain-takeover", difficulty) : null;
  res.send(C.renderVulnPage({
    appName: req.query.host || "Unknown host", difficulty,
    bodyHtml: claimed
      ? `<h1>${req.query.host}</h1><div class="result">${claimed}</div><p class="note">This content is now served under SecureCorp's own domain via the dangling CNAME.</p><div class="result" style="border-color:#4ade80;"><strong>🚩 Subdomain takeover confirmed.</strong>\nFLAG: ${flag}</div>`
      : `<h1>${req.query.host}</h1><p class="note">This hosting slot is currently unclaimed.</p>`
  }));
});

module.exports = { router };
