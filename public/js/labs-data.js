/**
 * LABS_DATA — full metadata for all 31 labs.
 *
 * NOTE ON STRUCTURE: reportSummary, reportImpact, and solutionSteps are now
 * keyed by difficulty ({easy, medium, hard}) — the Report tab shows genuinely
 * different content per severity, not one generic card reused everywhere.
 * answerPlaceholder always asks for the FLAG, since verification is now real
 * (server-issued, session-bound flags — see routes/vuln-common.js) rather
 * than pattern-matching whatever text was typed in.
 */
(function () {
  var LABS_DATA = {
    categories: [
      { id: "injection", label: "Injection" },
      { id: "server-logic", label: "Server Logic" },
      { id: "client-side", label: "Client-Side" },
      { id: "auth", label: "Authentication" },
      { id: "authz", label: "Authorization" },
      { id: "infra", label: "Infrastructure" },
      { id: "enum", label: "Web Enumeration" },
      { id: "final", label: "Final Challenge" }
    ],

    labs: [
      // ------------------------------------------------------------ AUTHZ --
      {
        id: "idor", category: "authz", title: "Insecure Direct Object Reference", shortTitle: "IDOR",
        demoApp: "SecureCorp Portal", blurb: "Access another user's data by changing an id in the URL.",
        goal: { explain: "IDOR happens when an app lets you access a record just by supplying its id, without checking you're entitled to see it.",
          example: "You're user 3. If the profile page trusts the id in the URL with no ownership check, visiting id=1 hands you someone else's data.",
          mission: ["Open the lab and note your id in the address bar.", "Change the id to view another user's profile.", "The FLAG appears once you've viewed someone else's data."] },
        difficultyNotes: { easy: "IDs are small sequential integers. Just change the number.", medium: "IDs are scrambled (not sequential) — enumerate nearby values.", hard: "The id is base64-encoded. Decode it, change the number, re-encode." },
        why: "The endpoint fetches a record by id and returns it directly with no check that the requester owns it.",
        fix: "Verify server-side that the authenticated session is authorized for the requested resource before returning data.",
        reportSummary: {
          easy: "The profile endpoint accepts a plain sequential integer id and returns any matching user's data with zero ownership check.",
          medium: "Even with scrambled (non-sequential) ids, the same missing ownership check applies — the ids just take a little enumeration to find.",
          hard: "Base64-encoding the id adds a decode step for the attacker, but is not a security control — the underlying integer is still trivially recoverable."
        },
        reportImpact: {
          easy: "Any user (or automated script) can enumerate ids 1, 2, 3... to harvest every account's PII in seconds.",
          medium: "Slightly slower to enumerate, but once the scrambling pattern is inferred, the whole user base is still harvestable.",
          hard: "Decoding base64 is a one-line operation for any attacker — the encoding provides no real protection against bulk enumeration."
        },
        solutionSteps: {
          easy: ["Note your own id (e.g. 6) shown on the page.", "Visit /vuln/idor/profile?id=1 (or any other small integer).", "The FLAG appears — you're viewing another account's data with no check."],
          medium: ["Note your own scrambled id.", "Try nearby integer values, e.g. id=225, id=262, id=299, until one resolves to a different real user.", "The FLAG appears on a successful cross-account view."],
          hard: ["Note your own base64 id, e.g. MTA= (decodes to 10).", "Decode it, pick a different number (e.g. 1), re-encode: MQ==.", "Visit /vuln/idor/profile?id=MQ== — the FLAG appears."]
        },
        answerPlaceholder: "FLAG{...}"
      },
      {
        id: "access-control", category: "authz", title: "Client-Side Access Controls", shortTitle: "Broken Access Control",
        demoApp: "SecureCorp Notes", blurb: "Bypass disabled buttons to perform actions the UI says you can't.",
        goal: { explain: "Access control enforced only in the UI (disabled buttons) is not real access control if the backend endpoint doesn't check permissions too.",
          example: "A 'read-only' user's Delete button is disabled in HTML, but the DELETE API might not check the user's role at all.",
          mission: ["Open the lab as a read-only viewer.", "Find a way to trigger a write action anyway.", "A successful bypass returns a FLAG in the API response."] },
        difficultyNotes: { easy: "No server-side role check exists at all — just re-enable the buttons in DevTools, or send the request directly.", medium: "The server checks a plain, editable 'role' cookie.", hard: "The role cookie is base64 JSON, and an undocumented X-Debug-Role header silently overrides your role." },
        why: "Authorization was decided from client-controlled data (HTML state, cookies, headers) instead of a trusted server-side session check.",
        fix: "Enforce authorization entirely server-side against a trusted session; never trust client-editable cookies or headers for privilege.",
        reportSummary: {
          easy: "The write endpoints (create/edit/delete note) perform zero server-side role check — the UI's disabled buttons are the only protection, and they're trivial to bypass.",
          medium: "The server checks a role cookie, but the cookie is plain text and fully editable by the client in DevTools.",
          hard: "The role cookie is base64-encoded JSON (still just obfuscation, not protection), and a leftover debug header overrides the role entirely."
        },
        reportImpact: {
          easy: "Any authenticated user, however low-privilege, can perform every write action in the app.",
          medium: "One cookie edit turns any viewer into an admin — no special tooling required, just DevTools.",
          hard: "A forgotten debug backdoor (X-Debug-Role) grants instant admin — exactly the kind of leftover from testing that ships to production by accident."
        },
        solutionSteps: {
          easy: ["Run in DevTools console: document.querySelectorAll('[disabled]').forEach(el=>el.removeAttribute('disabled'))", "Use the now-enabled Add/Edit/Delete buttons, or send the request directly with fetch().", "The FLAG appears in the API response on a successful write."],
          medium: ["Open DevTools → Application → Cookies.", "Edit the 'role' cookie value from 'viewer' to 'admin'.", "Retry the write action — the FLAG appears."],
          hard: ["Option A: send the request with header X-Debug-Role: admin.", "Option B: decode the role cookie, change it to {\"role\":\"admin\"}, base64 re-encode, and set it back.", "The FLAG appears in the API response."]
        },
        answerPlaceholder: "FLAG{...}"
      },
      {
        id: "info-disclosure", category: "authz", title: "Information Disclosure", shortTitle: "Info Disclosure",
        demoApp: "SecureCorp Checkout", blurb: "Find sensitive data exposed where it shouldn't be.",
        goal: { explain: "Apps often leak more than they mean to — verbose error messages, forgotten debug files, or revealing response headers.",
          example: "A stack trace can leak file paths and even environment variables. A stray .git folder can leak credentials.",
          mission: ["Try to trigger an error, find an exposed file, or inspect headers — depending on difficulty.", "The FLAG appears embedded in whatever gets disclosed."] },
        difficultyNotes: { easy: "Submit a non-numeric amount to trigger a verbose error with a fake env-var dump.", medium: "An exposed .git-config file leaks fake credentials.", hard: "A custom X-Internal-Build response header leaks internal version info — check DevTools Network tab." },
        why: "Debug-level detail (stack traces, VCS folders, internal headers) was exposed in a production-like response.",
        fix: "Disable verbose errors in production, never ship .git/.env folders, and strip internal headers before responses leave the server.",
        reportSummary: {
          easy: "Submitting invalid input to the checkout form triggers an unhandled error whose stack trace includes internal file paths and a fake environment-variable dump.",
          medium: "The application's .git folder is web-accessible, leaking repository credentials via a config file that should never be served.",
          hard: "A custom internal build/version header is sent on every response, giving an attacker reconnaissance data with no visible trace on the page itself."
        },
        reportImpact: {
          easy: "Stack traces reveal internal file structure and (in a real misconfiguration) could leak real secrets from process.env.",
          medium: "Exposed VCS metadata is a common real-world finding that frequently leaks live credentials directly.",
          hard: "Version/build fingerprinting helps attackers target known vulnerabilities for that exact internal build."
        },
        solutionSteps: {
          easy: ["Submit the checkout form with amount=abc (non-numeric).", "The verbose error response includes the FLAG alongside the fake stack trace."],
          medium: ["Visit /vuln/info-disclosure/.git-config directly.", "The leaked config file includes the FLAG as a comment."],
          hard: ["Open DevTools → Network tab.", "Reload the checkout page and inspect the response headers.", "The X-Internal-Build header value contains the FLAG."]
        },
        answerPlaceholder: "FLAG{...}"
      },

      // -------------------------------------------------------- CLIENT-SIDE
      {
        id: "xss", category: "client-side", title: "Cross-Site Scripting", shortTitle: "XSS",
        demoApp: "SecureCorp Notes Search", blurb: "Inject a script that runs in another user's browser.",
        goal: { explain: "Reflected XSS happens when user input is echoed into HTML without encoding, letting an attacker run JS in the victim's session.",
          example: "Search for <h1>pwned</h1> — if it renders as an actual heading instead of literal text, you've found it.",
          mission: ["Search for a payload that survives the filter for this difficulty.", "A FLAG appears in the results box once a live tag actually survives."] },
        difficultyNotes: { easy: "No filtering at all.", medium: "The literal text '<script' is stripped — try an event-handler payload.", hard: "<script, onerror=, and onload= are all stripped — try a handler the filter doesn't know about." },
        why: "User input is concatenated into the HTML response without encoding, and denylist filters are inherently incomplete.",
        fix: "Contextually encode all output, adopt a strict CSP, and mark session cookies HttpOnly.",
        reportSummary: {
          easy: "The search endpoint reflects the q parameter into the page with zero output encoding — any HTML/JS is injected as-is.",
          medium: "A denylist strips the literal string '<script', but any other tag or event handler still executes.",
          hard: "The denylist also strips onerror= and onload=, but doesn't cover every event handler — autofocus+onfocus still fires."
        },
        reportImpact: {
          easy: "Trivial full account takeover via cookie theft — any crafted link executes arbitrary JS in the victim's session.",
          medium: "The filter blocks the most obvious payload shape but is bypassed in seconds with a well-known alternate vector.",
          hard: "Even a two-keyword denylist leaves dozens of other event handlers open — denylisting HTML/JS injection points is fundamentally incomplete."
        },
        solutionSteps: {
          easy: ["Search for: <script>alert(document.cookie)</script>", "The script executes and the FLAG appears in the results box (a real tag survived unfiltered)."],
          medium: ["Search for: <img src=x onerror=alert(document.cookie)>", "'<script' isn't present, so the filter doesn't touch it — the FLAG appears."],
          hard: ["Search for: <input autofocus onfocus=alert(document.cookie)>", "autofocus triggers onfocus immediately, and onfocus isn't on the blocklist — the FLAG appears."]
        },
        answerPlaceholder: "FLAG{...}"
      },
      {
        id: "csrf", category: "client-side", title: "Cross-Site Request Forgery", shortTitle: "CSRF",
        demoApp: "SecureCorp Account", blurb: "Force a logged-in victim to perform an action they didn't intend.",
        goal: { explain: "CSRF happens when a state-changing action can be triggered by a simple cross-site request, since the browser auto-attaches cookies.",
          example: "Account deletion via plain GET, no token, no confirmation — any page can embed an <img> pointing at it.",
          mission: ["Log in and find the Danger Zone.", "Trigger the deletion via the appropriate technique for this difficulty.", "A FLAG appears once the deletion actually succeeds."] },
        difficultyNotes: { easy: "No protection — an <img> tag fires it.", medium: "A shallow Origin check exists but <img> requests don't send Origin, so it's still bypassed.", hard: "Subresource requests (img/fetch) are blocked, but a real top-level link click still works." },
        why: "A destructive action is reachable via GET with no CSRF token, relying only on the browser's ambient cookie authority.",
        fix: "Never perform state changes on GET; require a validated anti-CSRF token; set cookies SameSite=Lax/Strict as defense in depth.",
        reportSummary: {
          easy: "Account deletion is a plain GET request with no CSRF token, no confirmation, and no same-site cookie protection whatsoever.",
          medium: "A shallow Origin-header check was added, but it only inspects the header IF present — simple GETs like <img> don't send one.",
          hard: "Subresource loads are blocked via Fetch Metadata (Sec-Fetch-Mode), but a genuine top-level navigation is indistinguishable from a legitimate click and still succeeds."
        },
        reportImpact: {
          easy: "Any page the victim visits while logged in can silently delete their account.",
          medium: "The added check gives a false sense of security — the exact same <img> trick from 'easy' still works.",
          hard: "Even a real defense-in-depth control (Fetch Metadata) can't stop an attacker who lures the victim into clicking a real link."
        },
        solutionSteps: {
          easy: ["Open the CSRF PoC attacker page (or embed <img src='/vuln/csrf/delete'> anywhere).", "Just loading that page while logged in fires the deletion.", "The FLAG appears on the deletion confirmation page."],
          medium: ["Same <img> trick as easy — the Origin check never triggers because <img> doesn't send an Origin header.", "The FLAG appears once the account is actually deleted."],
          hard: ["The <img>/fetch trick is now blocked (Sec-Fetch-Mode check).", "Use the visible link on the attacker PoC page instead — a real click is a top-level navigation.", "The FLAG appears once the deletion succeeds via the link click."]
        },
        answerPlaceholder: "FLAG{...}"
      },
      {
        id: "open-redirect", category: "client-side", title: "Open Redirect", shortTitle: "Open Redirect",
        demoApp: "SecureCorp SSO", blurb: "Abuse a trusted domain's redirect to send victims somewhere malicious.",
        goal: { explain: "An open redirect lets an attacker craft a link on a trusted domain that actually sends the victim elsewhere — great for phishing.",
          example: "?next=https://attacker.test on a trusted login page looks safe to click but ends up off-domain.",
          mission: ["Get next to point somewhere genuinely off-domain.", "A FLAG appears once a real off-domain redirect is confirmed."] },
        difficultyNotes: { easy: "Any absolute URL works.", medium: "next must start with a single '/' — try a protocol-relative '//' URL instead.", hard: "next must merely contain 'securecorp-demo.test' anywhere — a domain like securecorp-demo.test.attacker.com passes." },
        why: "The redirect target is validated with a naive prefix/substring check instead of a strict allowlist of exact hosts.",
        fix: "Validate against an exact allowlist of hosts (or only allow relative paths validated with a real URL parser), never a substring/prefix check.",
        reportSummary: {
          easy: "The next parameter is used directly with no validation whatsoever.",
          medium: "A check requires next to start with '/', but protocol-relative URLs ('//host') also start with '/' and are still treated as absolute by browsers.",
          hard: "A substring check for 'securecorp-demo.test' is satisfied by any domain that merely contains that string anywhere, including as a subdomain of an attacker's own domain."
        },
        reportImpact: {
          easy: "Trivially usable in phishing — the link visibly points at the trusted domain right up until the redirect.",
          medium: "The '/' requirement looks like a fix but doesn't account for how browsers treat protocol-relative URLs as absolute.",
          hard: "Substring checks on domains are a classic, still-common real-world bug — 'contains' is not the same as 'is'."
        },
        solutionSteps: {
          easy: ["?next=https://attacker.test", "The FLAG appears confirming a genuine off-domain redirect."],
          medium: ["?next=//attacker.test", "This starts with '/' (passes the check) but browsers treat // as protocol-relative — an absolute redirect off-domain. FLAG appears."],
          hard: ["?next=https://securecorp-demo.test.attacker.test", "Contains the trusted substring but is actually attacker.test's subdomain. FLAG appears."]
        },
        answerPlaceholder: "FLAG{...}"
      },
      {
        id: "cstl", category: "client-side", title: "Client-Side Template Injection", shortTitle: "CSTI",
        demoApp: "SecureCorp Comment Preview", blurb: "Break out of a client-side template evaluator.",
        goal: { explain: "Some front-ends evaluate {{ }} expressions client-side (à la old AngularJS). If user input reaches that evaluator, it can execute arbitrary JS in your own browser.",
          example: "{{7*7}} rendering as 49 confirms live evaluation is happening on your input.",
          mission: ["Confirm {{7*7}} evaluates.", "Escalate to a real JS execution payload for this difficulty — a FLAG appears once it succeeds."] },
        difficultyNotes: { easy: "No filtering — the classic constructor-chain payload works directly.", medium: "The word 'constructor' is stripped before evaluation — try a payload built around the global Function instead.", hard: "Both 'constructor' and 'Function' are stripped as literal words — build 'Function' at runtime via string concatenation so it never appears literally in your payload." },
        why: "The client-side template evaluator runs on untrusted input with no sandboxing, and word-based denylists are trivially defeated by finding an equivalent primitive that doesn't contain the filtered word.",
        fix: "Never evaluate user input as a template expression client-side; use safe interpolation (textContent) instead — no denylist can fully close this class of bug.",
        reportSummary: {
          easy: "{{7*7}} evaluating to 49 confirms live evaluation, and the classic constructor-chain payload works with no filtering at all.",
          medium: "The literal word 'constructor' is stripped before evaluation, but the equally-capable global Function identifier isn't filtered.",
          hard: "Both 'constructor' and 'Function' are stripped as literal words, but building the string \"Function\" at runtime via concatenation ('Func'+'tion') never triggers either filter."
        },
        reportImpact: {
          easy: "Full arbitrary JS execution in whichever browser tab renders the comment.",
          medium: "Same full execution — filtering one keyword doesn't remove equivalent capabilities under a different name.",
          hard: "Same full execution — demonstrates that literal-string denylists are fundamentally bypassable via trivial string construction."
        },
        solutionSteps: {
          easy: ["Type {{7*7}} to confirm evaluation.", "Type {{constructor.constructor('alert(1)')()}}", "The FLAG appears."],
          medium: ["Type {{Function('alert(1)')()}} — avoids the filtered word 'constructor' entirely.", "The FLAG appears."],
          hard: ["Type {{globalThis['Func'+'tion']('alert(1)')()}} — 'Function' is built at runtime, so the literal word never appears in the source.", "The FLAG appears."]
        },
        answerPlaceholder: "FLAG{...}"
      },
      {
        id: "postmessage", category: "client-side", title: "postMessage Vulnerabilities", shortTitle: "postMessage",
        demoApp: "SecureCorp Wallet", blurb: "Forge cross-window messages because the origin is never checked.",
        goal: { explain: "window.postMessage lets pages talk across origins. If the receiver doesn't check event.origin, any page can send it forged data — even if it checks OTHER things about the message.",
          example: "A wallet widget updates your balance via postMessage — but from ANY sender, not just the real widget, since the receiver never confirms who actually sent it.",
          mission: ["Open the Wallet page, then open the linked attacker page from it (so window.opener is set).", "Fill in the fields required for this difficulty and send a forged balance.", "A FLAG appears when it's accepted."] },
        difficultyNotes: { easy: "No validation at all — any {balance:N} message is accepted.", medium: "The listener now also requires a source:'legit-widget' field — view-source the widget iframe to find the expected value.", hard: "The listener also requires a token field matching a per-session value embedded in the wallet page's source (view-source to find it) — not shown anywhere in the visible UI." },
        why: "Checking properties of the MESSAGE DATA (like a source label or even a token embedded in client-visible code) is not the same as checking WHO sent it — event.origin is the only thing an attacker's own page can't forge.",
        fix: "Always validate event.origin against an exact expected origin before trusting postMessage data — content-based checks alone are never sufficient since the attacker controls all the content.",
        reportSummary: {
          easy: "The wallet's message listener accepts a balance update from any origin with no verification of the data at all.",
          medium: "The listener now requires a source field, but since it's just part of the message content, an attacker can trivially include it too — origin still isn't checked.",
          hard: "The listener also requires a token, but it's exposed in the wallet page's own client-side source, so it's discoverable and equally forgeable."
        },
        reportImpact: {
          easy: "Any malicious tab can silently rewrite application state in another open tab.",
          medium: "Same impact as easy — a content-based check doesn't stop an attacker who can simply match the expected content.",
          hard: "Same impact as easy — even a 'secret' token doesn't help if it's reachable via the same client-side surface an attacker can already inspect."
        },
        solutionSteps: {
          easy: ["Open the attacker page from the Wallet tab.", "Enter a forged balance and send.", "The FLAG appears in the Wallet tab."],
          medium: ["View-source the Wallet page's widget iframe to find the required source value ('legit-widget').", "On the attacker page, enter the balance AND that source value, then send.", "The FLAG appears."],
          hard: ["View-source the Wallet page itself to find the embedded PAGE_TOKEN value.", "On the attacker page, enter the balance, source ('legit-widget'), and that token, then send.", "The FLAG appears."]
        },
        answerPlaceholder: "FLAG{...}"
      },
      {
        id: "prototype-pollution", category: "client-side", title: "Prototype Pollution", shortTitle: "Prototype Pollution",
        demoApp: "SecureCorp Theme Customizer", blurb: "Pollute Object.prototype to unlock a hidden admin link.",
        goal: { explain: "A naive recursive merge function that doesn't block dangerous keys can let you pollute Object.prototype itself — affecting every object in the page.",
          example: "?__proto__[isAdmin]=true merged in without a guard can make ({}).isAdmin true for the whole page.",
          mission: ["View the page source to see the merge() function and its denylist for this difficulty.", "Craft a query string that pollutes isAdmin using a key the denylist doesn't block.", "The FLAG appears alongside the unlocked Admin Panel link."] },
        difficultyNotes: { easy: "No denylist at all — __proto__ works directly.", medium: "The exact key '__proto__' is now blocked — reach the same prototype through constructor[prototype] instead.", hard: "'__proto__', 'constructor', AND 'prototype' are all blocked — this is actually a complete, correct fix for this bug. There's no bypass here." },
        why: "The merge function assigns into whatever key is given; at easy/medium it doesn't block every path that reaches the shared prototype.",
        fix: "Block __proto__, constructor, and prototype keys explicitly in any recursive merge/extend utility, or use Object.create(null) / Map instead of plain objects.",
        reportSummary: {
          easy: "The merge() function has no denylist for dangerous keys at all, so __proto__ is walked into like any other property.",
          medium: "The literal key '__proto__' is blocked, but 'constructor' and 'prototype' aren't — and constructor.prototype resolves to the exact same shared object.",
          hard: "'__proto__', 'constructor', and 'prototype' are all blocked at every recursion level — this genuinely closes off every path to the shared prototype for this merge pattern."
        },
        reportImpact: {
          easy: "A single crafted URL can flip a security-relevant flag for the entire page's lifetime.",
          medium: "Same impact as easy — blocking one of three equivalent paths to the same object isn't a real fix.",
          hard: "Not exploitable — included to show what a genuinely complete denylist looks like for this specific bug pattern."
        },
        solutionSteps: {
          easy: ["Visit /vuln/prototype-pollution?__proto__[isAdmin]=true", "The Admin Panel link unlocks and the FLAG appears."],
          medium: ["Visit /vuln/prototype-pollution?constructor[prototype][isAdmin]=true — reaches Object.prototype via a different, unblocked path.", "The FLAG appears."],
          hard: ["Not exploitable at this tier via this merge pattern — confirm that for yourself and note it in your report rather than guessing further payloads."]
        },
        answerPlaceholder: "FLAG{...}"
      },
      {
        id: "secondary-context", category: "server-logic", title: "Secondary Context Vulnerabilities", shortTitle: "Secondary Context",
        demoApp: "SecureCorp Support", blurb: "Input that's safe in one place gets executed unsafely somewhere else.",
        goal: { explain: "Some inputs look harmless where you enter them, but get reused unsafely in a totally different, later context — like an admin viewer.",
          example: "A support ticket message looks like plain text on the submission page, but the admin viewer renders it as raw HTML.",
          mission: ["Submit a ticket with an XSS payload as the message.", "Open the Admin Ticket Viewer — a FLAG appears there if your payload survives its filter."] },
        difficultyNotes: { easy: "No filtering in the admin viewer.", medium: "'<script' is stripped in the admin viewer — try an event handler.", hard: "<script/onerror/onload are all stripped — try an unfiltered handler like onfocus." },
        why: "The same output-encoding bug as XSS, but the vulnerable rendering happens in a different feature/context than where the input was collected — easy to miss in a review that only checks the input form.",
        fix: "Apply output encoding wherever data is rendered, not just where it's collected — audit every context a stored value can end up in.",
        reportSummary: {
          easy: "Ticket messages are rendered as raw HTML in the admin viewer with no encoding at all.",
          medium: "The admin viewer strips '<script' specifically, but other tags/handlers pass through untouched.",
          hard: "The admin viewer strips script/onerror/onload, but not every event handler — onfocus still works."
        },
        reportImpact: {
          easy: "Any user can submit a ticket that executes JS in a staff member's browser once viewed.",
          medium: "The partial filter is bypassed with the same well-known alternate vectors as reflected XSS.",
          hard: "Even a three-keyword denylist leaves real gaps — this is why context-aware output encoding, not filtering, is the real fix."
        },
        solutionSteps: {
          easy: ["Submit a ticket with message=<script>alert(document.cookie)</script>", "Open the Admin Ticket Viewer — the FLAG appears next to your payload."],
          medium: ["Submit a ticket with message=<img src=x onerror=alert(document.cookie)>", "Open the Admin Ticket Viewer — the FLAG appears."],
          hard: ["Submit a ticket with message=<input autofocus onfocus=alert(document.cookie)>", "Open the Admin Ticket Viewer — the FLAG appears."]
        },
        answerPlaceholder: "FLAG{...}"
      },

      // ---------------------------------------------------------- INJECTION
      {
        id: "sql-injection", category: "injection", title: "SQL Injection", shortTitle: "SQL Injection",
        demoApp: "SecureCorp Employee Directory", blurb: "Manipulate a real SQL query via unsanitized login/search fields.",
        goal: { explain: "SQL injection happens when user input is concatenated directly into a SQL query, letting an attacker change the query's logic.",
          example: "Username admin' -- turns WHERE username='admin' AND password='...' into a query that ignores the password check entirely.",
          mission: ["Try to log in as admin without knowing the password.", "If the login form gets locked down, try the department search box instead.", "A FLAG appears once the admin account is actually reached via injection."] },
        difficultyNotes: { easy: "Login form has no escaping at all.", medium: "Password field is escaped, username field isn't.", hard: "Login is fully safe — but the department search box is always vulnerable to UNION-based injection." },
        why: "Raw string concatenation builds the SQL query, so attacker-controlled quotes and keywords change its structure.",
        fix: "Use parameterized queries/prepared statements everywhere — never build SQL via string concatenation.",
        reportSummary: {
          easy: "The login query concatenates both username and password fields directly into SQL with zero escaping.",
          medium: "The password field is escaped, but the username field still reaches the query unescaped — the comment-based bypass still works.",
          hard: "The login form is fully parameterized and safe — but the separate department search field builds its query unsafely, permitting UNION-based extraction from any table."
        },
        reportImpact: {
          easy: "Full authentication bypass — any account, including admin, is reachable without a password.",
          medium: "Same full bypass — escaping only one of two concatenated fields doesn't fix the query.",
          hard: "The real password itself is exfiltrated via UNION — worse than a login bypass, since it also compromises the credential everywhere it's reused."
        },
        solutionSteps: {
          easy: ["Username: admin' --", "Password: (anything)", "This comments out the password check. The FLAG appears alongside the successful login."],
          medium: ["Username: admin' --", "Password: (anything) — the password field's escaping doesn't matter since the comment already ended the query.", "The FLAG appears."],
          hard: ["In the Department Search box: zzz' UNION SELECT username,password FROM employees --", "This pulls every username/password pair via UNION. The FLAG appears alongside the admin row."]
        },
        answerPlaceholder: "FLAG{...}"
      },
      {
        id: "command-injection", category: "injection", title: "Command Injection", shortTitle: "Command Injection",
        demoApp: "SecureCorp Network Diagnostics", blurb: "Break out of a 'ping' tool into arbitrary command execution.",
        goal: { explain: "Command injection happens when user input reaches a shell command unsanitized, letting an attacker chain in their own commands.",
          example: "host=10.0.0.5; whoami appends a second command after the intended ping.",
          mission: ["Get the tool to run whoami (or another recognized command) alongside the ping.", "A FLAG appears alongside any successfully injected command's output."] },
        difficultyNotes: { easy: "No filtering — ; && | and backticks all work.", medium: "; and & are stripped — try a pipe |.", hard: "; & | are all stripped — try command substitution with $(...)." },
        why: "Unsanitized input reaches a shell command construction step, and separator-based denylists are incomplete.",
        fix: "Never build shell commands from user input; use an argument-array API (no shell interpretation) and a strict allowlist of permitted characters.",
        reportSummary: {
          easy: "The hostname field reaches a simulated shell command with no filtering — every common separator works.",
          medium: "Semicolon and ampersand are stripped, but the pipe character is not — still a full bypass.",
          hard: "Semicolon, ampersand, and pipe are all stripped, but $(...) command substitution is not covered by the filter."
        },
        reportImpact: {
          easy: "Full arbitrary command execution (simulated) on the host running the vulnerable service.",
          medium: "Same impact as easy — the filter only removes 2 of the many shell metacharacters that enable chaining.",
          hard: "Command substitution is a well-known separator-denylist bypass — a mature filter needs an allowlist, not a blocklist, approach."
        },
        solutionSteps: {
          easy: ["Hostname: 10.0.0.5; whoami", "The FLAG appears alongside the simulated whoami output."],
          medium: ["Hostname: 10.0.0.5| whoami", "Semicolon is blocked but the pipe isn't. The FLAG appears."],
          hard: ["Hostname: $(whoami)", "None of the filtered characters (; & |) are used. The FLAG appears."]
        },
        answerPlaceholder: "FLAG{...}"
      },
      {
        id: "ssti", category: "injection", title: "Server-Side Template Injection", shortTitle: "SSTI",
        demoApp: "SecureCorp Greeting Card Generator", blurb: "Break out of a server-side template engine.",
        goal: { explain: "SSTI happens when user input is evaluated by a template engine server-side instead of just being inserted as data.",
          example: "{{7*7}} rendering as 49 (instead of literal text) proves the server is evaluating your input as code.",
          mission: ["Confirm {{7*7}} evaluates server-side.", "Escalate toward a code-execution-shaped payload for this difficulty — a FLAG appears when it lands."] },
        difficultyNotes: { easy: "No filtering — try the constructor-chain payload directly.", medium: "The word 'constructor' is stripped — try a payload using 'process' instead.", hard: "'constructor' and 'process' are both stripped — try 'global'." },
        why: "The template engine evaluates arbitrary expressions from user input, and keyword denylists are trivially incomplete.",
        fix: "Never render user input through a full template engine; use a logic-less templating mode or strict sandboxing with an allowlist of safe expressions.",
        reportSummary: {
          easy: "The greeting message is evaluated as a live template expression with no filtering — the classic constructor-chain payload works directly.",
          medium: "The literal word 'constructor' is stripped, but that's only one of several equivalent RCE-shaped keywords.",
          hard: "Both 'constructor' and 'process' are stripped, but 'global' is not — the denylist keeps missing equivalent paths to the same primitive."
        },
        reportImpact: {
          easy: "In a real (non-sandboxed) deployment, this is full server-side remote code execution.",
          medium: "Same severity as easy — keyword filtering doesn't remove the underlying capability, just one spelling of it.",
          hard: "Same severity as easy — three rounds of denylisting still didn't close the class of bug, only specific keywords."
        },
        solutionSteps: {
          easy: ["Message: {{constructor.constructor('return this')()}}", "The FLAG (simulated RCE proof) appears."],
          medium: ["Message: use a payload built around 'process' instead of 'constructor', e.g. referencing process.mainModule.", "The FLAG appears."],
          hard: ["Message: use a payload built around 'global' instead, e.g. referencing global.process.", "The FLAG appears."]
        },
        answerPlaceholder: "FLAG{...}"
      },
      {
        id: "xxe", category: "injection", title: "XML External Entity", shortTitle: "XXE",
        demoApp: "SecureCorp Feedback Importer", blurb: "Abuse XML entity expansion to read server files.",
        goal: { explain: "XXE happens when an XML parser resolves external entities, letting an attacker define an entity pointing at a local file.",
          example: "<!ENTITY xxe SYSTEM \"file:///etc/passwd\"> plus &xxe; in the body discloses that file's contents.",
          mission: ["Submit the default XML as-is to see normal behavior.", "At higher difficulty, work around the filtered keyword.", "A FLAG appears whenever a real file is actually disclosed."] },
        difficultyNotes: { easy: "SYSTEM and PUBLIC keywords both work directly.", medium: "'SYSTEM' is stripped — try 'PUBLIC' instead.", hard: "Both SYSTEM and PUBLIC are stripped — insert a space inside the keyword, e.g. 'SY STEM'." },
        why: "The parser resolves external entities from user-supplied XML, and the filters used at higher difficulty only match exact contiguous keywords.",
        fix: "Disable external entity resolution (DTDs) entirely in the XML parser configuration — the only real fix.",
        reportSummary: {
          easy: "The importer resolves SYSTEM/PUBLIC external entities with no filtering at all.",
          medium: "The literal string 'SYSTEM' is stripped, but 'PUBLIC' entities are resolved identically and aren't filtered.",
          hard: "Both keywords are stripped as contiguous strings, but the parser itself tolerates internal whitespace within the keyword — a filter/parser mismatch."
        },
        reportImpact: {
          easy: "Arbitrary local file disclosure, including credentials and private keys.",
          medium: "Same impact as easy — PUBLIC entities are just as capable of resolving external files as SYSTEM ones.",
          hard: "Same impact as easy — the disconnect between what the filter matches and what the parser accepts is a common, dangerous real-world pattern."
        },
        solutionSteps: {
          easy: ["Use the default payload's <!ENTITY xxe SYSTEM \"file:///etc/passwd\"> as-is.", "The FLAG appears alongside the disclosed /etc/passwd content."],
          medium: ["Change SYSTEM to PUBLIC \"\" \"file:///etc/passwd\" in the entity declaration.", "The FLAG appears."],
          hard: ["Insert a space inside the keyword: SY STEM instead of SYSTEM.", "The filter's exact-string match misses it, but the parser is lenient enough to still resolve it. The FLAG appears."]
        },
        answerPlaceholder: "FLAG{...}"
      },
      {
        id: "crlf-injection", category: "injection", title: "CRLF Injection", shortTitle: "CRLF Injection",
        demoApp: "SecureCorp Newsletter", blurb: "Inject line breaks to split an HTTP response.",
        goal: { explain: "CRLF injection happens when user input reaches a raw header/response value without stripping \\r\\n, letting an attacker inject extra headers or split the response.",
          example: "email=x%0d%0aSet-Cookie: admin=true injects a whole extra header into the response.",
          mission: ["Submit a normal email first.", "At higher difficulty, find the encoding that survives the filter.", "A FLAG appears whenever real response splitting is achieved."] },
        difficultyNotes: { easy: "%0d%0a decodes straight to real CRLF — works directly.", medium: "Real CRLF characters are stripped after decoding — blocked.", hard: "Same stripping as medium, but a second, downstream decode step resurrects double-URL-encoded CRLF (%250d%250a)." },
        why: "Raw CRLF characters are stripped only once; a component further downstream decodes the value a second time, resurrecting double-encoded sequences.",
        fix: "Never build raw header/response text from user input; use your framework's header-setting APIs, which reject invalid characters outright.",
        reportSummary: {
          easy: "%0d%0a decodes directly to real CRLF characters with no filtering, immediately splitting the simulated response.",
          medium: "Real CRLF characters are stripped after the first decode — this tier has no working bypass, demonstrating the filter functioning correctly.",
          hard: "The same stripping runs, but a second downstream decode step (simulating a real multi-layer app) resurrects double-encoded CRLF sequences that survived the first filter untouched."
        },
        reportImpact: {
          easy: "Header injection / response splitting, which can enable cache poisoning or session fixation in real deployments.",
          medium: "No successful bypass at this tier — included to show what a correctly-applied single-layer filter looks like.",
          hard: "Demonstrates why input validation must happen after ALL decoding layers a request will pass through, not just the first."
        },
        solutionSteps: {
          easy: ["Email: x%0d%0aSet-Cookie:%20admin=true", "The FLAG appears alongside the confirmed response split."],
          medium: ["Not exploitable at this tier — the filter correctly blocks single-encoded CRLF after decoding.", "(No FLAG available here — this tier is intentionally solid.)"],
          hard: ["Email: x%250d%250aSet-Cookie:%2520admin=true (double-encoded)", "The first filter pass doesn't touch it; a second decode downstream resurrects the real CRLF. The FLAG appears."]
        },
        answerPlaceholder: "FLAG{...}"
      },

      // ------------------------------------------------------- SERVER LOGIC
      {
        id: "ssrf", category: "server-logic", title: "Server-Side Request Forgery", shortTitle: "SSRF",
        demoApp: "SecureCorp Health Check Tool", blurb: "Trick the server into reaching an internal-only address.",
        goal: { explain: "SSRF happens when a server fetches a URL you control, letting you reach internal-only services it can access but you normally can't.",
          example: "A 'health check' tool that fetches any URL you give it can be pointed at internal metadata endpoints.",
          mission: ["Try the AWS-style metadata address directly.", "At higher difficulty, find an encoding or chaining trick past the blocklist.", "A FLAG appears whenever a fake internal service actually responds."] },
        difficultyNotes: { easy: "Internal addresses work directly — try 169.254.169.254, 127.0.0.1, localhost:6379, or internal-api.local.", medium: "Literal internal addresses are blocked — try a decimal or hex-encoded IP instead.", hard: "Encoded IPs are blocked too — try chaining through the trusted redirector (safe-redirector.securecorp-demo.test/go?to=)." },
        why: "The server fetches attacker-controlled URLs, and blocklists based on literal string matching miss alternate encodings and redirect chaining.",
        fix: "Use a strict allowlist of permitted destination hosts, resolve and re-check the IP after any redirect, and block link-local/loopback ranges at the network layer too.",
        reportSummary: {
          easy: "The health-check tool fetches any attacker-supplied URL with zero restriction on destination.",
          medium: "Literal internal IP/hostname strings are blocked, but the same addresses in decimal or hex form aren't recognized by the blocklist.",
          hard: "Encoded IPs are also blocked, but requests chained through a 'trusted' internal redirector are followed without re-checking the final destination."
        },
        reportImpact: {
          easy: "Direct access to cloud metadata endpoints, often yielding live cloud credentials.",
          medium: "The same metadata access is reachable with a one-line IP-encoding trick — the blocklist provides a false sense of security.",
          hard: "Demonstrates that blocking a destination isn't enough if a trusted redirector on your own infrastructure can be abused to reach it anyway."
        },
        solutionSteps: {
          easy: ["URL: http://169.254.169.254/latest/meta-data/iam/security-credentials/admin", "The FLAG appears alongside the fake leaked credentials."],
          medium: ["URL: http://0xA9FEA9FE/latest/meta-data/iam/security-credentials/admin (hex-encoded 169.254.169.254)", "The FLAG appears."],
          hard: ["URL: https://safe-redirector.securecorp-demo.test/go?to=http://169.254.169.254/latest/meta-data/iam/security-credentials/admin", "The FLAG appears once the chained request resolves."]
        },
        answerPlaceholder: "FLAG{...}"
      },
      {
        id: "file-upload", category: "server-logic", title: "Insecure File Upload", shortTitle: "File Upload",
        demoApp: "SecureCorp Profile Picture Upload", blurb: "Bypass extension checks on an upload form.",
        goal: { explain: "Insecure upload validation lets an attacker upload a file type that would execute as code if the storage location is web-accessible.",
          example: "Blocking '.php' case-sensitively still lets '.PHP' or '.pHp' through.",
          mission: ["Upload a normal file first.", "Try a blocked extension, then find the bypass for the current difficulty.", "A FLAG appears whenever the upload validation is actually bypassed."] },
        difficultyNotes: { easy: "No validation at all.", medium: "'.php' is blocked case-sensitively — try '.PHP'.", hard: "All php-like/executable extensions are blocked case-insensitively — but only the extension is checked, never real content, so a totally different name like 'shell.jpg' sails through regardless of content." },
        why: "Validation relies on a denylist of extensions (sometimes case-sensitive) and never inspects real file content — denylists are inherently incomplete.",
        fix: "Validate against a strict allowlist of safe extensions, verify actual file content (magic bytes), and serve uploads from a non-executable, isolated storage location.",
        reportSummary: {
          easy: "No file type validation exists at all — any extension, including executable ones, is accepted.",
          medium: "'.php' is blocked, but the check is case-sensitive, so '.PHP' or mixed-case variants pass straight through.",
          hard: "All php-like extensions are blocked case-insensitively, but validation never inspects real file content — any harmless-looking extension bypasses it entirely regardless of what's inside."
        },
        reportImpact: {
          easy: "In a misconfigured deployment, this leads directly to remote code execution via an uploaded web shell.",
          medium: "Same RCE risk as easy — case-sensitivity is a near-zero-effort bypass.",
          hard: "Same RCE risk as easy — proves that extension denylisting alone, however thorough, can't replace real content validation."
        },
        solutionSteps: {
          easy: ["Upload a file named shell.php (any content).", "The FLAG appears confirming the unrestricted upload."],
          medium: ["Upload a file named shell.PHP (uppercase extension).", "The case-sensitive check misses it. The FLAG appears."],
          hard: ["Upload a file named shell.jpg (any content, including non-image bytes).", "The extension denylist never matches '.jpg'. The FLAG appears."]
        },
        answerPlaceholder: "FLAG{...}"
      },
      {
        id: "path-traversal", category: "server-logic", title: "Path Traversal", shortTitle: "Path Traversal",
        demoApp: "SecureCorp Document Viewer", blurb: "Escape the intended folder to read arbitrary files.",
        goal: { explain: "Path traversal happens when user input builds a file path without stopping '../' sequences from escaping the intended directory.",
          example: "file=../../../etc/passwd walks up out of the documents folder to the filesystem root.",
          mission: ["View a normal document first.", "At higher difficulty, find the filter bypass.", "A FLAG appears whenever a file outside the documents folder is actually disclosed."] },
        difficultyNotes: { easy: "No sanitization — traverse directly.", medium: "A single pass strips '../' once — try '....//' (which collapses back into '../' after one strip).", hard: "'../' is stripped recursively — try double URL-encoding (%252e%252e%252f) instead." },
        why: "The path is normalized/filtered but a downstream step (or an incomplete single-pass filter) still permits traversal via nesting tricks or double-encoding.",
        fix: "Resolve the final path and verify it's still inside the allowed base directory (allowlist check on the resolved absolute path), not just filtering the raw string.",
        reportSummary: {
          easy: "The file parameter is used to build a path with no sanitization at all.",
          medium: "A single-pass filter removes one occurrence of '../', but nested dot sequences collapse back into a working traversal after that one pass.",
          hard: "The filter strips '../' recursively (closing the nesting trick), but doesn't account for a downstream component decoding the path a second time."
        },
        reportImpact: {
          easy: "Arbitrary file read anywhere the process has filesystem access.",
          medium: "Same impact as easy — the single-pass filter is a well-known incomplete defense.",
          hard: "Same impact as easy — recursive filtering alone still isn't enough without also controlling for double-encoding at the transport layer."
        },
        solutionSteps: {
          easy: ["file=../../../etc/passwd", "The FLAG appears alongside the disclosed file."],
          medium: ["file=....//....//....//etc/passwd", "Each '....//' collapses to '../' after the single-pass strip. The FLAG appears."],
          hard: ["file=%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd (double URL-encoded)", "Survives the recursive strip since it isn't literal '../' yet. The FLAG appears."]
        },
        answerPlaceholder: "FLAG{...}"
      },
      {
        id: "lfi", category: "server-logic", title: "Local File Inclusion", shortTitle: "LFI",
        demoApp: "SecureCorp Multilingual Loader", blurb: "Include arbitrary local files via a language-selection parameter.",
        goal: { explain: "LFI is path traversal applied to an 'include' feature — instead of just reading a file, the app pulls it into the page/template.",
          example: "lang=../../../etc/passwd tricks the template loader into including a file it was never meant to.",
          mission: ["Load a normal language first (en/fr/es).", "At higher difficulty, find the filter bypass.", "A FLAG appears whenever a file outside the templates folder is included."] },
        difficultyNotes: { easy: "No sanitization — traverse directly.", medium: "Single-pass '../' stripping — bypass with '....//'.", hard: "Recursive stripping — bypass with double URL-encoding." },
        why: "Same root cause as path traversal — user input reaches a file-inclusion step without validating the resolved path stays inside the intended directory.",
        fix: "Use a strict allowlist of valid language codes instead of building a file path from user input at all.",
        reportSummary: {
          easy: "The lang parameter is used to build an include path with no sanitization at all.",
          medium: "A single-pass '../' filter is bypassed the same way as path traversal's medium tier, via nested dot sequences.",
          hard: "Recursive stripping closes the nesting trick, but double URL-encoding still survives to a downstream decode step."
        },
        reportImpact: {
          easy: "Arbitrary local file disclosure, and in real PHP-style LFI, potential code execution via log/session poisoning.",
          medium: "Same impact as easy.",
          hard: "Same impact as easy — LFI chains are especially dangerous because 'include' semantics can escalate file read into code execution in some real stacks."
        },
        solutionSteps: {
          easy: ["lang=../../../etc/passwd", "The FLAG appears alongside the disclosed file."],
          medium: ["lang=....//....//....//etc/passwd", "The FLAG appears."],
          hard: ["lang=%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd", "The FLAG appears."]
        },
        answerPlaceholder: "FLAG{...}"
      },
      {
        id: "cache-poisoning", category: "server-logic", title: "Web Cache Poisoning", shortTitle: "Cache Poisoning",
        demoApp: "SecureCorp Homepage", blurb: "Poison a shared cache so every visitor sees your payload.",
        goal: { explain: "Cache poisoning happens when a cache key ignores an input that still affects the response, so a malicious response gets cached and served to everyone.",
          example: "A tracking parameter gets reflected into the page, but the cache key doesn't include it — so the poisoned response is served to the next visitor too, even with no query string.",
          mission: ["Find which tracking parameter is unkeyed for this difficulty.", "Load the page with a distinctive value for it, then reload with NO query string and confirm your value (and FLAG) persisted from cache."] },
        difficultyNotes: { easy: "utm_source is the unkeyed parameter — the cache key includes all other known tracking params.", medium: "utm_source is now included in the cache key (fixed) — but ref is unkeyed instead.", hard: "Both utm_source and ref are now keyed — but lang is unkeyed instead." },
        why: "Each time the obviously-unkeyed parameter gets added to the cache key, a similar parameter introduced elsewhere is missed — a realistic pattern of incomplete fixes.",
        fix: "Include every input that affects the response in the cache key, or explicitly strip/normalize every unrecognized query parameter before both rendering and caching.",
        reportSummary: {
          easy: "The cache key includes every known tracking parameter except utm_source, which is reflected into the response.",
          medium: "utm_source was added to the cache key, but a different parameter (ref) is reflected and still unkeyed.",
          hard: "Both utm_source and ref are now keyed, but a third parameter (lang) is reflected and still unkeyed."
        },
        reportImpact: {
          easy: "A single crafted request poisons what every subsequent visitor sees for the cache's TTL.",
          medium: "Same impact as easy — fixing one unkeyed parameter didn't catch a near-identical one.",
          hard: "Same impact as easy — demonstrates that partial fixes for this bug class tend to just relocate it."
        },
        solutionSteps: {
          easy: ["Visit /vuln/cache-poisoning?utm_source=YOUR_PAYLOAD", "Reload with no query string at all — your value (and the FLAG) are still shown, served from cache."],
          medium: ["Visit /vuln/cache-poisoning?ref=YOUR_PAYLOAD (utm_source no longer works).", "Reload with no query string — the FLAG persists."],
          hard: ["Visit /vuln/cache-poisoning?lang=YOUR_PAYLOAD (utm_source and ref no longer work).", "Reload with no query string — the FLAG persists."]
        },
        answerPlaceholder: "FLAG{...}"
      },
      {
        id: "cache-deception", category: "server-logic", title: "Web Cache Deception", shortTitle: "Cache Deception",
        demoApp: "SecureCorp My Account", blurb: "Trick a cache into storing a private, personalized response.",
        goal: { explain: "Cache deception happens when a cache decides to store a response just because the URL LOOKS static (e.g. ends in .js), even though it's actually private/personalized.",
          example: "/account/nonexistent.js still renders your private account page (ignored trailing segment) — and gets cached because of the .js-looking extension.",
          mission: ["Find the technique that still works for this difficulty.", "A FLAG appears alongside the private data once it's cached under a deceptive URL."] },
        difficultyNotes: { easy: "Appending a fake static filename to the path works directly (e.g. /account/x.js).", medium: "The path trick is fixed (extra segments now 404) — but a query string containing a static-looking extension anywhere still triggers caching (e.g. /account?a=x.js).", hard: "The query-string check is now stricter — the extension must appear specifically as a query VALUE (e.g. /account?callback=x.js), not just anywhere in the URL." },
        why: "Each fix narrowed the bug without fully closing the underlying issue — deciding cacheability from surface-level URL pattern matching instead of an explicit application decision.",
        fix: "Never key caching decisions on URL extension or pattern matching; only cache responses explicitly marked cacheable by the application, and route unmatched paths to a real 404.",
        reportSummary: {
          easy: "Appending a static-looking extension directly to the path causes the private response to be cached and replayable.",
          medium: "The path-based trick is fixed, but the cache rule still matches a static extension appearing anywhere in the full URL, including the query string.",
          hard: "The rule is narrowed further to only match a static extension in query-value position, but that's still enough to trigger caching of a private response."
        },
        reportImpact: {
          easy: "Sensitive account data (API key) becomes accessible to anyone who requests the same poisoned URL, no authentication required.",
          medium: "Same impact as easy — the fix only closed one specific construction, not the underlying pattern-matching approach.",
          hard: "Same impact as easy — demonstrates that narrowing a flawed detection rule usually just narrows the required payload, not the risk."
        },
        solutionSteps: {
          easy: ["Visit /vuln/cache-deception/account/anything.js", "The FLAG appears alongside the private API key."],
          medium: ["Visit /vuln/cache-deception/account?a=x.js (path stays clean, extension is in the query string).", "The FLAG appears."],
          hard: ["Visit /vuln/cache-deception/account?callback=x.js (extension specifically in a query VALUE position).", "The FLAG appears."]
        },
        answerPlaceholder: "FLAG{...}"
      },
      {
        id: "request-smuggling", category: "server-logic", title: "HTTP Request Smuggling", shortTitle: "Request Smuggling",
        demoApp: "SecureCorp Protocol Analyzer", blurb: "See how a front-end and back-end can disagree about where a request ends.",
        goal: { explain: "This lab is a textual analyzer (not a live two-server exploit): it shows how a Content-Length-based front-end and a Transfer-Encoding-based back-end can disagree about a request's boundary — the real mechanism behind CL.TE smuggling.",
          example: "A request with BOTH Content-Length and Transfer-Encoding: chunked headers can be read completely differently depending on how strictly the back-end parses the TE header.",
          mission: ["Get the analyzer to detect a desync using the specific header construction required for this difficulty.", "A FLAG appears whenever it does."] },
        difficultyNotes: { easy: "The back-end recognizes a plain Transfer-Encoding: chunked header — the pre-filled example already desyncs.", medium: "The back-end now only recognizes chunked encoding as part of a comma-separated list, e.g. 'Transfer-Encoding: identity, chunked' — edit the header to that form.", hard: "The back-end now requires TWO separate Transfer-Encoding header lines (it uses the last one) — add a line 'Transfer-Encoding: identity' directly above the existing chunked line." },
        why: "Real HTTP implementations genuinely vary in how strictly they parse Transfer-Encoding — some accept comma-lists, some only honor the last of duplicate headers — and any such disagreement between front-end and back-end is exploitable.",
        fix: "Ensure front-end and back-end servers agree on a single, strict parsing strategy (ideally reject any ambiguous request with both headers, or duplicate Transfer-Encoding headers, per RFC 7230).",
        reportSummary: {
          easy: "The back-end recognizes a simple, single Transfer-Encoding: chunked header, and the pre-filled example already contains a mismatched Content-Length, producing an immediate desync.",
          medium: "The back-end only recognizes chunked encoding within a comma-separated Transfer-Encoding value — the simple single-value header from the easy tier is no longer sufficient.",
          hard: "The back-end only recognizes chunked encoding when TWO separate Transfer-Encoding header lines are present, using the last one — neither the easy nor medium constructions are sufficient here."
        },
        reportImpact: {
          easy: "Can smuggle a hidden request into another user's connection in a real CL.TE setup, leading to request hijacking or cache poisoning.",
          medium: "Same impact as easy — a comma-separated Transfer-Encoding value is valid per spec and a realistic real-world parsing discrepancy.",
          hard: "Same impact as easy — duplicate Transfer-Encoding headers are a well-documented real desync technique when front-end and back-end pick different occurrences."
        },
        solutionSteps: {
          easy: ["Click Analyze on the pre-filled example (Content-Length + Transfer-Encoding: chunked, both present).", "The FLAG appears once a desync is detected."],
          medium: ["Edit the Transfer-Encoding header to: Transfer-Encoding: identity, chunked", "Click Analyze — the FLAG appears."],
          hard: ["Add a second header line above the existing one: Transfer-Encoding: identity, followed by the existing Transfer-Encoding: chunked line.", "Click Analyze — the FLAG appears."]
        },
        answerPlaceholder: "FLAG{...}"
      },
      {
        id: "race-conditions", category: "server-logic", title: "Race Conditions", shortTitle: "Race Conditions",
        demoApp: "SecureCorp Gift Card", blurb: "Redeem more value than should be possible by racing requests.",
        goal: { explain: "A race condition happens when a check ('is there enough balance?') and the action ('deduct it') aren't atomic, so concurrent requests can all pass the check before any of them updates the balance.",
          example: "Firing several redemption requests at the exact same time can let you redeem more than your balance should allow.",
          mission: ["Redeem once normally.", "Fire several requests simultaneously and over-redeem.", "A FLAG appears once you've redeemed MORE than 2 times from a $50 balance (2 is what a safe system would allow)."] },
        difficultyNotes: { easy: "Firing 3 requests simultaneously is enough to over-redeem (2 would just be the normal legitimate limit).", medium: "Needs about 6 simultaneous requests to reliably win the race (narrower window).", hard: "Needs ~20 simultaneous requests — the window is very narrow but still exploitable with enough concurrency." },
        why: "The balance check and the balance deduction happen in separate steps with a gap between them (simulated here with an artificial delay), so concurrent requests can all observe the pre-deduction balance.",
        fix: "Make the check-and-deduct operation atomic (e.g. a single conditional database update, or a proper lock/transaction) so concurrent requests can't both pass the same check.",
        reportSummary: {
          easy: "A relatively wide 400ms artificial delay between check and deduct makes the race trivially winnable with just 3 concurrent requests.",
          medium: "A narrower 220ms window requires more concurrent requests (around 6) to reliably land more than 2 inside the gap.",
          hard: "A tight 120ms window still yields to sheer concurrency — around 20 simultaneous requests reliably wins even a narrow race."
        },
        reportImpact: {
          easy: "Financial loss via double-spending / over-redemption of value — trivially achievable.",
          medium: "Same financial impact, requiring only moderately more concurrent requests.",
          hard: "Same financial impact — demonstrates that a narrow race window reduces but doesn't eliminate exploitability if an attacker can fire enough concurrent requests."
        },
        solutionSteps: {
          easy: ["Set 'simultaneous requests' to 3 and click Fire.", "More than 2 redemptions succeed from the $50 balance. The FLAG appears."],
          medium: ["Set 'simultaneous requests' to 6 and click Fire (may need a retry or two).", "The FLAG appears once redemptions exceed 2."],
          hard: ["Set 'simultaneous requests' to 20 and click Fire (may need a retry or two given the narrow window).", "The FLAG appears once redemptions exceed 2."]
        },
        answerPlaceholder: "FLAG{...}"
      },

      // -------------------------------------------------------------- AUTH
      {
        id: "2fa-bypass", category: "auth", title: "2FA Bypass", shortTitle: "2FA Bypass",
        demoApp: "SecureCorp Login", blurb: "Skip or brute-force past a two-factor step.",
        goal: { explain: "A 2FA implementation is only as strong as what happens AFTER password entry but BEFORE the OTP is verified.",
          example: "If the account page doesn't check an 'otpVerified' flag, you can navigate straight past the OTP screen.",
          mission: ["Log in with any username/password.", "Defeat the OTP step using the technique for this difficulty.", "A FLAG appears on successful access to the account page."] },
        difficultyNotes: { easy: "The account page never checks OTP status at all — just navigate straight to it.", medium: "OTP is required, but the verify endpoint accepts ANY code as correct.", hard: "The real code is checked, but there's no attempt limit — brute-force all 100 two-digit codes." },
        why: "The account page's authorization check doesn't (at easy) or barely (at medium/hard) validate that a real second factor was actually completed.",
        fix: "Only grant full session privileges after OTP success, validate the actual code value, and rate-limit/lock out after a few failed attempts.",
        reportSummary: {
          easy: "The account page grants access without ever checking whether OTP verification happened at all.",
          medium: "OTP verification is checked for, but the verification endpoint itself accepts any submitted code as correct.",
          hard: "The real code is properly checked, but with no rate limiting a full brute force of the 100-code space is trivially fast."
        },
        reportImpact: {
          easy: "Complete 2FA bypass — the second factor provides no protection whatsoever.",
          medium: "Same complete bypass — verification exists in form but not in substance.",
          hard: "2FA is only as strong as its rate limiting — a small code space with no throttling is brute-forceable in seconds."
        },
        solutionSteps: {
          easy: ["Log in with any credentials.", "Navigate directly to the account page, skipping /verify entirely.", "The FLAG appears."],
          medium: ["Log in with any credentials.", "Submit any 2-digit code (e.g. 00) to /verify.", "Navigate to the account page — the FLAG appears."],
          hard: ["Log in with any credentials.", "Use the 'Try all 100 codes' button to brute-force the real code.", "Navigate to the account page — the FLAG appears."]
        },
        answerPlaceholder: "FLAG{...}"
      },
      {
        id: "weak-password", category: "auth", title: "Weak Password Checks", shortTitle: "Weak Password Checks",
        demoApp: "SecureCorp Login", blurb: "Exploit missing complexity rules and missing rate limiting.",
        goal: { explain: "Weak password policy plus no rate limiting is a classic combo: guessable passwords, and nothing stopping you from guessing as many times as you like.",
          example: "Registration accepts '123' as a password, and the login endpoint never locks out repeated failed attempts.",
          mission: ["Register an account with a trivially weak password.", "Brute-force the admin account's password using the built-in wordlist.", "A FLAG appears on a successful login."] },
        difficultyNotes: { easy: "Admin's password is an obvious top-10 password, no attempt limit.", medium: "Admin's password needs the full built-in wordlist, still no attempt limit.", hard: "Same wordlist, but a lockout kicks in after 5 attempts — bypassable by starting a fresh session (clear cookies) between attempts." },
        why: "No password strength enforcement plus no (or session-keyed, easily reset) rate limiting allows practical brute-forcing.",
        fix: "Enforce a real password policy, and rate-limit/lock out by account (or IP), not by a client-resettable session.",
        reportSummary: {
          easy: "The admin account uses an obvious, top-10-list password with no login attempt limiting at all.",
          medium: "The admin password isn't in the top 10, but the built-in wordlist still finds it in a handful of attempts, still with no limiting.",
          hard: "A lockout exists after 5 failed attempts, but it's tracked per-session — a fresh session (new cookies) resets the counter entirely."
        },
        reportImpact: {
          easy: "Admin account takeover in a single guess for anyone who tries common passwords.",
          medium: "Admin account takeover within a small, automatable wordlist run.",
          hard: "The lockout is trivially bypassed by clearing cookies, so brute-forcing remains practical despite the apparent protection."
        },
        solutionSteps: {
          easy: ["Run the built-in wordlist against the admin account — 'admin123' hits almost immediately.", "The FLAG appears in the success response."],
          medium: ["Run the built-in wordlist — 'Summer2024!' succeeds after a few tries.", "The FLAG appears."],
          hard: ["Run the wordlist; if locked out after 5 attempts, clear cookies (or open a private window) and continue.", "'Tr41n1ng!2026' eventually succeeds. The FLAG appears."]
        },
        answerPlaceholder: "FLAG{...}"
      },
      {
        id: "brute-force", category: "auth", title: "Brute Force Attack", shortTitle: "Brute Force",
        demoApp: "SecureCorp Staff Portal", blurb: "Enumerate valid usernames via a side-channel, then brute-force the password.",
        goal: { explain: "Real brute-forcing usually starts with username enumeration: finding out WHICH usernames are valid before wasting effort guessing passwords for accounts that don't exist. Apps leak this in surprising ways even after 'fixing' the obvious one.",
          example: "An error message that says 'no such user' vs 'wrong password' tells an attacker exactly which usernames are worth attacking.",
          mission: ["Figure out which candidate username is real for this difficulty.", "Log in successfully — a FLAG appears once you do."] },
        difficultyNotes: { easy: "The error message itself reveals whether the username exists.", medium: "Messages are unified, but response time differs — check the serverProcessingMs field.", hard: "Message and timing are both unified — but a lockout only triggers for a REAL username after repeated attempts, itself proving validity." },
        why: "Removing the obvious enumeration vector (distinct error messages) doesn't remove every side-channel — timing and lockout behavior can leak the same information.",
        fix: "Return truly identical responses (message, timing, and any side-effects like lockout) regardless of whether the username exists, and rate-limit by IP/account in a way that doesn't itself leak validity.",
        reportSummary: {
          easy: "Login error messages explicitly differ between 'no such user' and 'incorrect password', trivially enabling username enumeration.",
          medium: "Error messages are unified, but the server's response time differs measurably depending on whether the username is valid.",
          hard: "Both message and timing are unified, but an account lockout after repeated failures only occurs for valid usernames — the lockout message itself is a side-channel."
        },
        reportImpact: {
          easy: "Trivial, instant username enumeration followed by targeted password brute-forcing.",
          medium: "Same enumeration outcome via a subtler but still practical timing side-channel.",
          hard: "Same enumeration outcome via a lockout side-channel — demonstrates that fixing the obvious vectors doesn't guarantee the underlying information isn't still leaking."
        },
        solutionSteps: {
          easy: ["Try each candidate username with any password; only 'jsmith' returns \"Incorrect password\" instead of \"No such user.\"", "Log in as jsmith with password Winter2025!", "The FLAG appears."],
          medium: ["Try each candidate username; jsmith's response takes noticeably longer (serverProcessingMs: 300 vs 50).", "Log in as jsmith with password Winter2025!", "The FLAG appears."],
          hard: ["Send 5 failed attempts against a candidate username; only jsmith eventually returns a lockout message, proving it's valid.", "(The lockout response itself includes the FLAG confirming enumeration — no further login needed.)"]
        },
        answerPlaceholder: "FLAG{...}"
      },
      {
        id: "password-reset", category: "auth", title: "Password Reset Issues", shortTitle: "Password Reset",
        demoApp: "SecureCorp Password Reset", blurb: "Exploit a predictable or reusable reset token.",
        goal: { explain: "Password reset flows are only as safe as their tokens — predictable tokens or tokens that can be reused both defeat the whole mechanism.",
          example: "If a token is just base64(username), anyone can compute a valid token for any account without ever requesting a reset for them.",
          mission: ["Compute (don't request!) a token for the 'admin' account directly.", "A FLAG appears once admin's password is reset via a token you computed or found, not one legitimately issued to you."] },
        difficultyNotes: { easy: "The token is just base64(username) — compute it directly.", medium: "The token is the username reversed plus '-2024' — compute it directly.", hard: "The token is properly random — but a leaked, already-used token for 'admin' is shown in a debug log, and reuse isn't blocked." },
        why: "Tokens are either derived predictably from public information (easy/medium) or never invalidated after use and exposed via a debug log (hard).",
        fix: "Use cryptographically random, single-use, short-expiry tokens, and never log/expose them anywhere outside the actual email delivery.",
        reportSummary: {
          easy: "Reset tokens are simply base64(username) — computable for any account without ever triggering a real reset request.",
          medium: "Reset tokens follow a slightly obfuscated but still fully predictable pattern (reversed username + fixed suffix).",
          hard: "Tokens are properly random and unpredictable, but a debug log exposes an already-used token, and the reset endpoint doesn't reject reused tokens."
        },
        reportImpact: {
          easy: "Instant account takeover of any user, including admin, with zero interaction with the real reset flow.",
          medium: "Same takeover risk — the obfuscation adds negligible attacker effort.",
          hard: "Even properly random tokens are unsafe if reuse isn't blocked and they're exposed via logging — a different but equally real failure mode."
        },
        solutionSteps: {
          easy: ["Compute token = base64('admin') = YWRtaW4=", "Submit it on the reset form with a new password.", "The FLAG appears."],
          medium: ["Compute token = reverse('admin') + '-2024' = nimda-2024", "Submit it with a new password.", "The FLAG appears."],
          hard: ["Copy the leaked token shown in the 'recently sent emails' debug panel (marked used).", "Submit it with a new password anyway — reuse isn't blocked.", "The FLAG appears."]
        },
        answerPlaceholder: "FLAG{...}"
      },
      {
        id: "oauth-misconfig", category: "auth", title: "OAuth Misconfiguration", shortTitle: "OAuth Misconfig",
        demoApp: "SecureCorp ID — OAuth", blurb: "Redirect an authorization code to an attacker-controlled URL.",
        goal: { explain: "If an OAuth authorize endpoint doesn't strictly validate redirect_uri, an attacker can have the authorization code delivered to their own server instead of the real app.",
          example: "redirect_uri=https://attacker.test with no validation sends the code straight to the attacker.",
          mission: ["Try an attacker redirect_uri directly.", "At higher difficulty, find the bypass for the validation in place.", "A FLAG appears whenever the code would genuinely be delivered off-domain."] },
        difficultyNotes: { easy: "No validation on redirect_uri at all.", medium: "Validated via a naive substring check — try a lookalike domain containing the trusted string.", hard: "Validated via a startsWith check — chain through the Open Redirect lab, which itself starts with the trusted domain." },
        why: "redirect_uri validation uses a substring or prefix check instead of an exact allowlist match, and doesn't account for open-redirect chaining on the trusted domain itself.",
        fix: "Validate redirect_uri against an exact, pre-registered allowlist of full URLs — never a substring/prefix check — and fix any open redirects on the trusted domain too.",
        reportSummary: {
          easy: "No validation whatsoever on redirect_uri — any destination is accepted.",
          medium: "A substring check for 'securecorp-demo.test' is satisfied by any domain that merely contains that string, including an attacker's own lookalike domain.",
          hard: "A startsWith check on the trusted domain is satisfied by chaining through an existing open redirect ON that trusted domain."
        },
        reportImpact: {
          easy: "Authorization codes (and the account access they grant) are trivially exfiltrated to any attacker-chosen domain.",
          medium: "Same exfiltration risk — the substring check is bypassed with a single crafted lookalike domain.",
          hard: "Demonstrates that fixing redirect_uri validation isn't enough on its own if the trusted domain has its own unrelated open redirect to chain through."
        },
        solutionSteps: {
          easy: ["redirect_uri=https://attacker.test", "The FLAG appears confirming off-domain delivery."],
          medium: ["redirect_uri=https://securecorp-demo.test.attacker.test", "Contains the trusted substring but resolves to attacker.test. The FLAG appears."],
          hard: ["redirect_uri=https://securecorp-demo.test/vuln/open-redirect?next=https://attacker.test", "Starts with the trusted domain, then redirects off-domain via the chained bug. The FLAG appears."]
        },
        answerPlaceholder: "FLAG{...}"
      },
      {
        id: "saml-vulns", category: "auth", title: "SAML Vulnerabilities", shortTitle: "SAML",
        demoApp: "SecureCorp SSO — SAML", blurb: "Forge a SAML assertion because the signature isn't really checked.",
        goal: { explain: "SAML SSO trusts the assertion's claims (who you are, your role) — but only if the cryptographic signature is actually verified. If it isn't, you can just edit the assertion.",
          example: "Changing <Subject>guest</Subject> to <Subject>admin</Subject> in the base64 blob and resubmitting logs you in as admin.",
          mission: ["Decode the sample assertion.", "Edit the Subject to admin and satisfy whatever check exists at this difficulty.", "A FLAG appears once you're logged in as admin specifically."] },
        difficultyNotes: { easy: "Signature is ignored entirely — just tamper and resubmit.", medium: "A Signature field must be present, but its value is never actually verified — any placeholder text works.", hard: "Also requires a NotOnOrAfter timestamp — but since it's part of the assertion you control, just set it in the future." },
        why: "The server parses claims out of the assertion but never cryptographically verifies the signature against the identity provider's public key.",
        fix: "Always cryptographically verify the SAML assertion's signature against a trusted, pinned IdP certificate before trusting any claim inside it.",
        reportSummary: {
          easy: "The Signature field is completely ignored — any Subject/role claim is trusted as-is.",
          medium: "A Signature field must merely be present (any non-empty text) — its value is never cryptographically checked.",
          hard: "A NotOnOrAfter expiry is also required, but since it's part of the attacker-controlled assertion body, it's trivially set to a future date."
        },
        reportImpact: {
          easy: "Complete authentication bypass — impersonate any user, including admin, with a hand-edited assertion.",
          medium: "Same complete bypass — a placeholder signature satisfies a presence check that isn't a real verification.",
          hard: "Same complete bypass — every 'protection' added is itself just another attacker-controlled field, since real signature verification is never performed."
        },
        solutionSteps: {
          easy: ["Decode the sample assertion, change Subject to admin and role to admin.", "Re-encode as base64 and submit.", "The FLAG appears."],
          medium: ["Same edit as easy, plus add any placeholder <Signature>x</Signature>.", "Re-encode and submit. The FLAG appears."],
          hard: ["Same edits as medium, plus add <NotOnOrAfter>2099-01-01T00:00:00Z</NotOnOrAfter>.", "Re-encode and submit. The FLAG appears."]
        },
        answerPlaceholder: "FLAG{...}"
      },

      // ------------------------------------------------------------- INFRA
      {
        id: "cloud-storage-misconfig", category: "infra", title: "Cloud Storage Misconfiguration", shortTitle: "Cloud Storage",
        demoApp: "SecureCorp Cloud Storage", blurb: "Access data in a misconfigured public storage bucket.",
        goal: { explain: "Cloud storage buckets (S3-style) are sometimes left publicly listable and/or readable by mistake.",
          example: "Listing the bucket reveals object keys you were never meant to see, like employee-backup.csv.",
          mission: ["Try listing the bucket.", "Fetch an interesting-looking private object directly.", "A FLAG appears whenever a private (non-public) object is actually read."] },
        difficultyNotes: { easy: "Both listing and reading any object work with no restriction.", medium: "Listing is disabled, but any object is still directly readable if you know/guess its exact key.", hard: "Both need a 'sig' parameter — but its value is never actually validated, so any value works." },
        why: "Access control relies on 'security through obscurity' (no listing) or a signature parameter that's checked for presence but never cryptographically validated.",
        fix: "Require real authenticated, least-privilege access to every object (not just disabling listing), and validate signed URLs cryptographically with expiry.",
        reportSummary: {
          easy: "Both listing and object reads work with zero access control — the entire bucket is openly browsable.",
          medium: "Listing is disabled, but this is 'security through obscurity' — any guessed or known key is still directly readable.",
          hard: "A 'sig' parameter is required, giving the appearance of signed-URL protection, but its value is never actually validated cryptographically."
        },
        reportImpact: {
          easy: "Full disclosure of every object in the bucket, including private backups and confidential files.",
          medium: "Same disclosure risk for any attacker who guesses or learns object key names through other means.",
          hard: "The 'signed URL' pattern is present in name only — it provides no real protection since any signature value is accepted."
        },
        solutionSteps: {
          easy: ["Click 'List bucket' to enumerate all object keys.", "Fetch any listed key, e.g. private/ceo-notes.txt.", "The FLAG appears."],
          medium: ["Skip listing (it's disabled) — directly request key=private/ceo-notes.txt or key=employee-backup.csv.", "The FLAG appears."],
          hard: ["Request the same private key, adding any value to the sig field, e.g. sig=x.", "The FLAG appears."]
        },
        answerPlaceholder: "FLAG{...}"
      },
      {
        id: "subdomain-takeover", category: "infra", title: "Subdomain Takeover", shortTitle: "Subdomain Takeover",
        demoApp: "SecureCorp DNS Zone Lookup", blurb: "Claim an abandoned service that a dangling DNS record still points to.",
        goal: { explain: "If a DNS CNAME still points at a third-party service that's since been deleted/abandoned, anyone can often register that same slug on the third-party service and serve their own content under the trusted domain.",
          example: "A subdomain's CNAME can still point at a hosting slug nobody claimed anymore — the domain itself differs by difficulty here.",
          mission: ["Look up subdomains to find the dangling one for this difficulty.", "Claim it and preview the result.", "A FLAG appears once your claimed content is served under SecureCorp's domain."] },
        difficultyNotes: { easy: "old-blog.securecorp-demo.test is dangling, among only 4 subdomains to check.", medium: "old-blog no longer exists — beta.securecorp-demo.test is dangling instead, among 8 subdomains.", hard: "beta no longer exists — archive.securecorp-demo.test is dangling instead, and you must explicitly request claim verification to see its real status." },
        why: "DNS wasn't cleaned up when the underlying third-party service/slug was decommissioned, leaving a dangling pointer anyone can claim — a pattern that keeps recurring as different subdomains get decommissioned over time.",
        fix: "Remove DNS records immediately when decommissioning any third-party-hosted service, and periodically audit all CNAMEs for dangling targets.",
        reportSummary: {
          easy: "old-blog.securecorp-demo.test's CNAME target is immediately visible as unclaimed among a short list of 4 subdomains.",
          medium: "A different subdomain (beta) is now the dangling one, found by checking a longer, more realistic list of 8.",
          hard: "Yet another subdomain (archive) is dangling, and its claim status is hidden by default — requiring an explicit verification step before it's confirmed."
        },
        reportImpact: {
          easy: "Full content control of a legitimate-looking subdomain — useful for phishing or malware hosting.",
          medium: "Same impact, requiring more reconnaissance effort across a realistic-sized subdomain list.",
          hard: "Same impact — demonstrates that dangling records can hide in plain sight until someone actually checks claim status explicitly."
        },
        solutionSteps: {
          easy: ["Look up old-blog.securecorp-demo.test — it's flagged as unclaimed immediately.", "Claim sc-oldblog.fakehost-service.test with your own content, then preview the subdomain.", "The FLAG appears."],
          medium: ["Check each of the 8 known subdomains until beta.securecorp-demo.test shows as unclaimed.", "Claim sc-beta.fakehost-service.test and preview — the FLAG appears."],
          hard: ["Look up archive.securecorp-demo.test with the verify checkbox enabled to see its real claim status.", "Claim sc-archive.fakehost-service.test and preview — the FLAG appears."]
        },
        answerPlaceholder: "FLAG{...}"
      },

      // ------------------------------------------------------ WEB ENUM -----
      {
        id: "enum-files", category: "enum", title: "Files & Directories", shortTitle: "Files & Directories",
        demoApp: "SecureCorp Web Server", blurb: "Discover hidden files and directories with no visible links.",
        goal: { explain: "Sites often leave sensitive files reachable but unlinked — backups, old admin panels, config files — discoverable only by guessing paths (what tools like gobuster/ffuf automate).",
          example: "A file like /backup.zip might sit right at the web root, invisible in navigation but fully downloadable if you know (or guess) the name.",
          mission: ["Probe common paths using the tool or built-in wordlist.", "A FLAG appears once a genuinely hidden file is found."] },
        difficultyNotes: { easy: "The hidden file has an obvious, common name — a short wordlist finds it immediately.", medium: "The hidden path is a less obvious legacy directory name — needs a bigger wordlist.", hard: "The hidden file only exists as a backup-extension variant of a known filename (e.g. .bak) — a common real technique for source disclosure." },
        why: "Files were never removed from the web root after use, and 'no link to it' was mistaken for 'not accessible'.",
        fix: "Never rely on obscurity — remove unneeded files entirely, and serve only an explicit allowlist of paths from the web root.",
        reportSummary: {
          easy: "An obvious, commonly-named backup file (/backup.zip) sits at the web root with no access control.",
          medium: "A decommissioned legacy admin directory is still reachable at a less obvious, less-guessable path.",
          hard: "A backup-extension variant of a real source file (.bak) discloses source code that was never meant to be served as-is."
        },
        reportImpact: {
          easy: "Full site backup disclosure to anyone who guesses (or wordlist-fuzzes) the filename.",
          medium: "Access to a decommissioned admin interface that may retain working functionality or credentials.",
          hard: "Source code disclosure, including any hardcoded credentials — worse than a simple file leak since it reveals application internals."
        },
        solutionSteps: {
          easy: ["Probe /backup.zip directly, or run the built-in wordlist.", "The FLAG appears alongside the discovered file."],
          medium: ["Probe /old_admin_2019/ (or run the built-in wordlist, which includes it).", "The FLAG appears."],
          hard: ["Probe /config.php.bak (or run the built-in wordlist).", "The FLAG appears alongside the disclosed fake source code."]
        },
        answerPlaceholder: "FLAG{...}"
      },
      {
        id: "virtual-hosts", category: "enum", title: "Virtual Host Enumeration", shortTitle: "Virtual Hosts",
        demoApp: "SecureCorp Virtual Host Prober", blurb: "Discover hidden internal sites hosted on the same server.",
        goal: { explain: "One server can host many different sites, distinguished only by the Host header sent in the request — including internal sites never linked publicly.",
          example: "The same IP address might serve a public marketing site for Host: www.example.com and a completely different internal admin panel for Host: admin.example.com.",
          mission: ["Try candidate Host header values in the prober.", "A FLAG appears once a genuinely hidden vhost responds."] },
        difficultyNotes: { easy: "The hidden vhost name is short and guessable.", medium: "The hidden vhost name is longer/less obvious — needs a bigger wordlist.", hard: "The check is case-sensitive, and the real vhost uses mixed case — a plain wordlist (usually all-lowercase) will miss it unless you try case variations." },
        why: "The server responds to any Host header matching a configured vhost, including ones never advertised publicly, with no additional authentication.",
        fix: "Don't rely on an unlisted hostname as access control — internal vhosts need real authentication, and ideally shouldn't be reachable from the public internet at all.",
        reportSummary: {
          easy: "An internal admin console responds to a short, easily-guessed Host header value.",
          medium: "An internal staging environment responds to a longer, less obvious Host header value.",
          hard: "An internal API gateway responds only to an exact-case Host header value that most wordlists (typically all-lowercase) wouldn't naturally produce."
        },
        reportImpact: {
          easy: "Full access to an internal admin console from the public internet, using only a Host header change.",
          medium: "Access to a staging environment that may contain pre-release code or weaker security controls.",
          hard: "Access to an internal API gateway — case-sensitivity is a weak, easily-defeated protection once an attacker tries capitalization variants."
        },
        solutionSteps: {
          easy: ["Send Host header: admin.securecorp-demo.test", "The FLAG appears."],
          medium: ["Send Host header: staging-internal.securecorp-demo.test", "The FLAG appears."],
          hard: ["Send Host header: Internal-API.securecorp-demo.test (exact case).", "The FLAG appears."]
        },
        answerPlaceholder: "FLAG{...}"
      },
      {
        id: "fuzz-params", category: "enum", title: "Fuzzing & HTTP Parameters", shortTitle: "Fuzzing & Parameters",
        demoApp: "SecureCorp Dashboard", blurb: "Discover undocumented parameters that unlock hidden behavior.",
        goal: { explain: "Applications sometimes have undocumented parameters — debug flags, internal toggles, nested filters — reachable only by guessing (what tools like ffuf, Arjun, or x8 automate).",
          example: "?debug=true might unlock a hidden debug panel that's never mentioned anywhere in the visible UI.",
          mission: ["Try adding query parameters to the dashboard URL.", "A FLAG appears once the right parameter (and value/shape) unlocks hidden functionality."] },
        difficultyNotes: { easy: "The parameter name is the obvious one (debug=true).", medium: "The obvious name doesn't work — try a different, related name.", hard: "A flat parameter isn't enough — the hidden functionality only unlocks via a nested/bracket-style parameter." },
        why: "A debug/internal feature flag was left reachable via an undocumented parameter with no authentication check at all.",
        fix: "Remove debug/internal toggles from production entirely, or gate them behind real authentication — never behind an obscure, unauthenticated parameter name.",
        reportSummary: {
          easy: "An undocumented debug=true parameter unlocks hidden functionality with no authentication.",
          medium: "A differently-named but functionally identical parameter (internal=1) unlocks the same hidden functionality.",
          hard: "The hidden functionality requires a nested/bracket-style parameter (filter[status]=admin) that flat-parameter fuzzing wordlists wouldn't naturally try."
        },
        reportImpact: {
          easy: "Anyone who guesses (or fuzzes) the parameter name gets unauthenticated access to hidden functionality.",
          medium: "Same impact as easy — renaming the parameter doesn't add real security, just requires slightly more guessing.",
          hard: "Same impact as easy — demonstrates that nested parameter fuzzing finds bugs flat-parameter wordlists alone would miss."
        },
        solutionSteps: {
          easy: ["Visit /vuln/fuzz-params?debug=true", "The FLAG appears."],
          medium: ["Visit /vuln/fuzz-params?internal=1", "The FLAG appears."],
          hard: ["Visit /vuln/fuzz-params?filter[status]=admin", "The FLAG appears."]
        },
        answerPlaceholder: "FLAG{...}"
      },
      {
        id: "dns-zone-transfer", category: "enum", title: "DNS Zone Transfer", shortTitle: "DNS Zone Transfer",
        demoApp: "SecureCorp DNS Zone Transfer Tool", blurb: "Dump an entire DNS zone via an unauthorized AXFR request.",
        goal: { explain: "A DNS zone transfer (AXFR) is meant only for secondary nameservers to sync zone data — but a misconfigured server can let anyone request the FULL zone, including internal-only hostnames never otherwise discoverable.",
          example: "Instead of guessing subdomains one at a time, a successful AXFR just hands you the entire list at once — internal VPN hosts, backup servers, everything.",
          mission: ["Request a zone transfer.", "A FLAG appears once the full zone is actually disclosed."] },
        difficultyNotes: { easy: "The transfer succeeds for any requester with no restriction at all.", medium: "The transfer requires claiming to be a specific nameserver (ns1.securecorp-demo.test) — a claim that's never actually verified.", hard: "The transfer also requires a transfer key — but it's leaked in an internal ops changelog you can find on the same site." },
        why: "The DNS server doesn't restrict AXFR to genuinely authenticated/trusted secondary servers — at medium it trusts a self-reported identity, and at hard the 'secret' key is exposed elsewhere in the same application.",
        fix: "Restrict zone transfers to specific IP addresses AND require real TSIG cryptographic authentication — never a spoofable claimed identity, and never leak transfer keys in any internal documentation reachable from the same host.",
        reportSummary: {
          easy: "The DNS zone transfer succeeds for any request with zero restriction.",
          medium: "The transfer is 'restricted' only by a self-reported server identity string that's never actually verified.",
          hard: "The transfer requires a real-looking key, but that key is leaked via an internal changelog page reachable from the same application."
        },
        reportImpact: {
          easy: "Complete internal network reconnaissance — every subdomain, including internal-only hosts, in one request.",
          medium: "Same complete disclosure — the 'restriction' is trivially satisfied by just claiming the expected identity.",
          hard: "Same complete disclosure — demonstrates how a leaked internal document can undermine an otherwise real-looking access control."
        },
        solutionSteps: {
          easy: ["Request an AXFR with any server value.", "The FLAG appears alongside the full zone dump."],
          medium: ["Request an AXFR with server=ns1.securecorp-demo.test.", "The FLAG appears."],
          hard: ["Check the ops changelog link for the current transfer key.", "Request an AXFR with server=ns1.securecorp-demo.test and that key.", "The FLAG appears."]
        },
        answerPlaceholder: "FLAG{...}"
      },

      // ------------------------------------------------------------- FINAL
      {
        id: "final", category: "final", title: "Redacted Final Challenge", shortTitle: "[REDACTED]",
        demoApp: "SecureCorp — Classified", blurb: "This lab is locked. Or is it?", locked: true,
        goal: { explain: "Combine what you learned in Broken Access Control and IDOR. Somewhere in this application, an admin note points to something. Find user 100's password.",
          example: "No examples this time.", mission: ["Read the admin-only notes.", "Follow where they point.", "Retrieve and submit the actual password (not a FLAG — this one's the real secret)."] },
        difficultyNotes: { easy: "The trail is short and discoverable from the UI.", medium: "You'll need the medium-mode Access Control bypass before the trail appears.", hard: "Combine the hard-mode Access Control bypass with the hard-mode IDOR technique." },
        why: "This chains two independently real bugs — broken access control gets you the pointer, IDOR gets you the data — exactly how real bug bounty chains work.",
        fix: "Fixing either underlying bug breaks the whole chain.",
        reportSummary: {
          easy: "The admin note is reachable via the trivial access-control bypass, and the linked profile is reachable via plain sequential IDOR.",
          medium: "The admin note requires the medium-tier cookie-editing bypass; the linked profile requires enumerating a scrambled id.",
          hard: "The admin note requires the hard-tier debug-header/cookie bypass; the linked profile requires decoding/re-encoding a base64 id."
        },
        reportImpact: {
          easy: "Full compromise of the admin account by chaining two independently minor-looking bugs.",
          medium: "Same full compromise, requiring both bypasses to be chained correctly at this tier.",
          hard: "Same full compromise — demonstrates how real attackers chain multiple 'medium severity' bugs into a critical one."
        },
        solutionSteps: {
          easy: ["Read the admin note via the Broken Access Control bypass (no check needed at easy).", "It references user 100's profile.", "View that profile via plain IDOR — the password field is in the response."],
          medium: ["Bypass Access Control by editing the role cookie to admin.", "Read the admin note referencing user 100.", "View that profile via the scrambled-id IDOR technique — retrieve the password."],
          hard: ["Bypass Access Control via X-Debug-Role or the base64 role cookie.", "Read the admin note referencing user 100.", "View that profile via the base64-encoded IDOR technique — retrieve the password."]
        },
        answerPlaceholder: "User 100's password"
      }
    ]
  };

  if (typeof module !== "undefined" && module.exports) module.exports = LABS_DATA;
  if (typeof window !== "undefined") window.LABS_DATA = LABS_DATA;
})();
