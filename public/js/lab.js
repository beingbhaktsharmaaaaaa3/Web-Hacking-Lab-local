(function () {
  const params = new URLSearchParams(location.search);
  const labId = params.get("id");
  const lab = LABS_DATA.labs.find((l) => l.id === labId);
  const CATS = LABS_DATA.categories.reduce((m, c) => ((m[c.id] = c.label), m), {});

  const PROGRESS_KEY = "whl_progress_v2";
  const DIFFICULTY_KEY = "whl_difficulty_v2";

  function getProgress() { try { return JSON.parse(localStorage.getItem(PROGRESS_KEY)) || {}; } catch (e) { return {}; } }
  function isSolved() { return !!getProgress()[labId]; }
  function markSolved(id) { const p = getProgress(); p[id] = true; localStorage.setItem(PROGRESS_KEY, JSON.stringify(p)); }
  function clearSolved(id) { const p = getProgress(); delete p[id]; localStorage.setItem(PROGRESS_KEY, JSON.stringify(p)); }
  function getDifficulty() { return localStorage.getItem(DIFFICULTY_KEY) || "easy"; }
  function setDifficulty(level) {
    localStorage.setItem(DIFFICULTY_KEY, level);
    document.cookie = "difficulty=" + level + ";path=/;max-age=" + 60 * 60 * 24 * 30;
    renderDifficultyToggle();
    render();
  }
  function renderDifficultyToggle() {
    const level = getDifficulty();
    document.querySelectorAll("#difficultyToggle button").forEach((btn) => btn.classList.toggle("active", btn.dataset.level === level));
  }
  document.querySelectorAll("#difficultyToggle button").forEach((btn) => btn.addEventListener("click", () => setDifficulty(btn.dataset.level)));

  function toast(message, type) {
    const el = document.createElement("div");
    el.className = "toast " + (type || "success");
    el.textContent = message;
    document.getElementById("toastRoot").appendChild(el);
    setTimeout(() => el.remove(), 4000);
  }
  window.copyPayload = function (btn, text) {
    navigator.clipboard.writeText(text).then(() => {
      const original = btn.textContent;
      btn.textContent = "copied!";
      setTimeout(() => (btn.textContent = original), 1200);
    });
  };

  let activeTab = "goal";

  function updateHeaderSolvedBadge() {
    const existing = document.getElementById("solvedBadge");
    if (isSolved() && !existing) {
      const badge = document.createElement("span");
      badge.className = "badge solved";
      badge.id = "solvedBadge";
      badge.textContent = "✓ solved";
      document.querySelector(".lab-title-row").insertBefore(badge, document.getElementById("resetLabBtn"));
    } else if (!isSolved() && existing) {
      existing.remove();
    }
  }

  function shell() {
    if (!lab) { document.getElementById("labShell").innerHTML = `<p>Unknown lab. <a href="/index.html">Back to labs</a></p>`; return; }
    const difficulty = getDifficulty();
    document.getElementById("labShell").innerHTML = `
      <a class="back-link" href="/index.html">← Back</a>
      <div class="lab-title-row">
        <span class="badge ${lab.category}">${lab.locked ? "[CLASSIFIED]" : (CATS[lab.category] || lab.category)}</span>
        <h1>${lab.shortTitle} Lab</h1>
        <span class="difficulty-pill ${difficulty}">${difficulty}</span>
        ${isSolved() ? '<span class="badge solved" id="solvedBadge">✓ solved</span>' : ""}
        <button class="reset-lab-btn" id="resetLabBtn" title="Reset this lab's demo data and solved status">↺ Reset this lab</button>
      </div>
      <div class="tabs">
        <button class="tab-btn" data-tab="goal">Goal</button>
        <button class="tab-btn" data-tab="lab">Lab</button>
        <button class="tab-btn" data-tab="exploit">Exploit</button>
        <button class="tab-btn" data-tab="report">Report</button>
      </div>
      <div class="panel" id="tabPanel"></div>
    `;
    document.querySelectorAll(".tab-btn").forEach((btn) => btn.addEventListener("click", () => { activeTab = btn.dataset.tab; render(); }));
    document.getElementById("resetLabBtn").addEventListener("click", resetThisLab);
  }

  async function resetThisLab() {
    if (!confirm(`Reset the "${lab.shortTitle}" lab? This clears its demo data and your solved status so you can practice again.`)) return;
    try { await fetch("/api/reset-lab", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ labId: lab.id }) }); } catch (e) {}
    clearSolved(lab.id);
    toast("Lab reset — practice away!", "success");
    activeTab = "goal";
    shell();
    render();
  }

  function renderTabHighlight() {
    document.querySelectorAll(".tab-btn").forEach((btn) => btn.classList.toggle("active", btn.dataset.tab === activeTab));
  }

  function renderGoal(panel, difficulty) {
    panel.innerHTML = `
      <h4>What is this?</h4>
      <p>${lab.goal.explain}</p>
      <h4>Example</h4>
      <div class="example-box">${lab.goal.example}</div>
      <h4>Your Mission</h4>
      <ol class="mission-list">${lab.goal.mission.map((m) => `<li>${m}</li>`).join("")}</ol>
      <h4>At this difficulty (${difficulty})</h4>
      <div class="hint-box">${lab.difficultyNotes[difficulty]}</div>
      <div style="margin-top:20px;"><button class="btn" id="goToLab">Open Live Lab →</button></div>
    `;
    document.getElementById("goToLab").addEventListener("click", () => { activeTab = "lab"; render(); });
  }

  function renderLabTab(panel, difficulty) {
    const url = `/vuln/${lab.id}?difficulty=${difficulty}`;
    panel.innerHTML = `
      <div class="open-lab-cta">
        <div class="app-name">${lab.demoApp}</div>
        <p>This opens a real, standalone target application in a new tab. Log in there, then try editing the URL, form fields, or headers as described in the Goal tab.</p>
        <a class="btn" href="${url}" target="_blank" rel="noopener">Open Vulnerable App →</a>
      </div>
      <p class="note" style="color:var(--text-dim);font-size:.85rem;">Direct link: <code>${url}</code></p>
    `;
  }

  function renderExploit(panel, difficulty) {
    panel.innerHTML = `
      <h4>Show Hint</h4>
      <button class="btn secondary" id="hintBtn">Show Hint</button>
      <div id="hintArea"></div>
      <h4>Solution (${difficulty})</h4>
      <details class="solution"><summary>Show step-by-step solution</summary><ol>${lab.solutionSteps[difficulty].map((s) => `<li>${s}</li>`).join("")}</ol></details>
      <h4>Why This Happens</h4>
      <p>${lab.why}</p>
      <h4>How To Fix It</h4>
      <p>${lab.fix}</p>
    `;
    document.getElementById("hintBtn").addEventListener("click", () => {
      document.getElementById("hintArea").innerHTML = `<div class="hint-box">${lab.difficultyNotes[difficulty]}</div>`;
    });
  }

  function renderReport(panel, difficulty) {
    const alreadySolved = isSolved();
    panel.innerHTML = `
      <div class="difficulty-pill ${difficulty}" style="margin-bottom:14px;">${difficulty} severity report</div>
      <h4>Summary</h4><p>${lab.reportSummary[difficulty]}</p>
      <h4>Reproduction Steps</h4><ol>${lab.solutionSteps[difficulty].map((s) => `<li>${s}</li>`).join("")}</ol>
      <h4>Impact</h4><p>${lab.reportImpact[difficulty]}</p>
      ${alreadySolved ? `<div class="solved-flag">✓ Lab solved. You can submit again to practice, or use "Reset this lab" above to start fresh.</div>` : ""}
      <h4 style="margin-top:22px;">Submit Your Flag</h4>
      <p style="color:var(--text-dim);font-size:.85rem;">This is checked for real — the flag is only generated server-side, in your session, once the exploit above actually succeeds. Typing a payload here won't work; you have to trigger it on the live app first.</p>
      <div class="form-row">
        <label>${lab.id === "final" ? "User 100's password" : "Flag"}</label>
        <textarea id="answerInput" placeholder="${lab.answerPlaceholder}"></textarea>
      </div>
      <button class="btn" id="submitAnswer">Submit</button>
      <div id="answerResult"></div>
    `;
    document.getElementById("submitAnswer").addEventListener("click", async () => {
      const answer = document.getElementById("answerInput").value;
      const resultEl = document.getElementById("answerResult");
      resultEl.innerHTML = "";
      try {
        let success = false, message = "";
        if (lab.id === "final") {
          const res = await fetch("/api/final-challenge", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ password: answer }) });
          const data = await res.json();
          success = data.success; message = data.message;
        } else {
          const res = await fetch("/api/validate-lab", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ labId: lab.id, difficulty, answer }) });
          const data = await res.json();
          success = data.success; message = data.message;
        }
        if (success) {
          markSolved(lab.id);
          if (lab.id === "final") LABS_DATA.labs.forEach((l) => markSolved(l.id));
          resultEl.innerHTML = `<div class="solved-flag">✓ ${message}</div>`;
          toast("Lab solved! 🎉", "success");
          updateHeaderSolvedBadge();
        } else {
          resultEl.innerHTML = `<div class="fail-flag">✕ ${message}</div>`;
          toast(message, "error");
        }
      } catch (e) {
        toast("Something went wrong contacting the server.", "error");
      }
    });
  }

  function render() {
    if (!lab) return;
    const difficulty = getDifficulty();
    renderTabHighlight();
    const panel = document.getElementById("tabPanel");
    if (activeTab === "goal") renderGoal(panel, difficulty);
    else if (activeTab === "lab") renderLabTab(panel, difficulty);
    else if (activeTab === "exploit") renderExploit(panel, difficulty);
    else if (activeTab === "report") renderReport(panel, difficulty);
  }

  renderDifficultyToggle();
  shell();
  render();
  renderTabHighlight();
})();
