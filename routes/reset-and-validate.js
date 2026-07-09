const express = require("express");
const router = express.Router();
const C = require("./vuln-common");

router.post("/api/reset-lab", (req, res) => {
  const { session } = C.getOrInitSession(req, res);
  const labId = req.body.labId;
  if (labId) {
    C.resetLabState(session, labId);
    if (labId === "csrf") session.canonicalId = null;
  }
  res.json({ success: true });
});

// Real verification: the submitted answer must be the exact flag that was
// revealed to THIS session by THIS lab at THIS difficulty after genuinely
// triggering the vulnerable code path. See routes/vuln-common.js (getFlag)
// and each vulns-*.js file for where flags are revealed.
router.post("/api/validate-lab", (req, res) => {
  const { session } = C.getOrInitSession(req, res);
  const { labId, difficulty, answer } = req.body;
  const trimmed = (answer || "").trim();
  if (trimmed.length < 3) return res.json({ success: false, message: "That doesn't look like a real flag yet. Go exploit the lab first — the flag appears in the response when the exploit actually works." });
  const success = C.checkFlag(session, labId, difficulty || "easy", trimmed);
  res.json({
    success,
    message: success
      ? "✅ Correct flag — verified. This lab is now marked solved."
      : "❌ That's not the flag for this lab/difficulty in your current session. Make sure you actually triggered the exploit (not just a guess), and that you're on the right difficulty."
  });
});

module.exports = { router };
