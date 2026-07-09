(function () {
  const LABS = LABS_DATA.labs;
  const CATS = LABS_DATA.categories.reduce((m, c) => ((m[c.id] = c.label), m), {});

  const PROGRESS_KEY = "whl_progress_v2";
  const DIFFICULTY_KEY = "whl_difficulty_v2";

  function getProgress() {
    try { return JSON.parse(localStorage.getItem(PROGRESS_KEY)) || {}; } catch (e) { return {}; }
  }
  function setDifficultyCookie(level) {
    document.cookie = "difficulty=" + level + ";path=/;max-age=" + 60 * 60 * 24 * 30;
  }
  function getDifficulty() { return localStorage.getItem(DIFFICULTY_KEY) || "easy"; }
  function setDifficulty(level) {
    localStorage.setItem(DIFFICULTY_KEY, level);
    setDifficultyCookie(level);
    renderDifficultyToggle();
  }
  function renderDifficultyToggle() {
    const level = getDifficulty();
    document.querySelectorAll("#difficultyToggle button").forEach((btn) => {
      btn.classList.toggle("active", btn.dataset.level === level);
    });
  }
  document.querySelectorAll("#difficultyToggle button").forEach((btn) => {
    btn.addEventListener("click", () => setDifficulty(btn.dataset.level));
  });

  let activeFilter = "all";
  let searchTerm = "";

  const searchInput = document.getElementById("searchInput");
  if (searchInput) {
    searchInput.addEventListener("input", () => {
      searchTerm = searchInput.value.trim().toLowerCase();
      renderGrid();
    });
  }

  function matchesSearch(lab) {
    if (!searchTerm) return true;
    const haystack = [lab.title, lab.shortTitle, lab.blurb, lab.demoApp, CATS[lab.category] || ""].join(" ").toLowerCase();
    return haystack.includes(searchTerm);
  }

  function renderFilters() {
    const presentCats = [...new Set(LABS.map((l) => l.category))];
    const order = LABS_DATA.categories.map((c) => c.id).filter((id) => presentCats.includes(id));
    const el = document.getElementById("filters");
    const btns = [{ id: "all", label: "All" }].concat(order.map((id) => ({ id, label: CATS[id] || id })));
    el.innerHTML = btns.map((b) => `<button class="filter-btn ${b.id === activeFilter ? "active" : ""}" data-filter="${b.id}">${b.label}</button>`).join("");
    el.querySelectorAll(".filter-btn").forEach((btn) => {
      btn.addEventListener("click", () => { activeFilter = btn.dataset.filter; renderFilters(); renderGrid(); });
    });
  }

  function renderProgress() {
    const progress = getProgress();
    const total = LABS.length;
    const solved = LABS.filter((l) => progress[l.id]).length;
    document.getElementById("progressDots").innerHTML = LABS.map((l) => `<div class="progress-dot ${progress[l.id] ? "filled" : ""}" title="${l.shortTitle}"></div>`).join("");
    document.getElementById("progressText").textContent = `${solved} / ${total} labs solved`;
  }

  function labCard(lab) {
    const progress = getProgress();
    const solved = !!progress[lab.id];
    if (lab.locked) {
      const unlockable = LABS.filter((l) => l.id !== "final").every((l) => progress[l.id]);
      return `
      <div class="card locked">
        <div class="card-row"><span class="badge final">[CLASSIFIED]</span>${solved ? '<span class="badge solved">✓ complete</span>' : ""}</div>
        <h3 class="card-title">[REDACTED]</h3>
        <div class="redacted-block"></div>
        <p class="card-desc">${lab.blurb}</p>
        <a class="btn ${unlockable || solved ? "" : "secondary"}" href="/lab.html?id=final">${unlockable || solved ? "Start Lab →" : "Attempt Anyway →"}</a>
      </div>`;
    }
    return `
    <div class="card">
      <div class="card-row"><span class="badge ${lab.category}">${CATS[lab.category] || lab.category}</span>${solved ? '<span class="badge solved">✓ solved</span>' : ""}</div>
      <h3 class="card-title">${lab.shortTitle}</h3>
      <p class="card-sub">${lab.title}</p>
      <p class="card-desc">${lab.blurb}</p>
      <a class="btn" href="/lab.html?id=${lab.id}">Start Lab →</a>
    </div>`;
  }

  function renderGrid() {
    const filtered = LABS.filter((l) => (activeFilter === "all" || l.category === activeFilter) && matchesSearch(l));
    document.getElementById("labGrid").innerHTML = filtered.length
      ? filtered.map(labCard).join("")
      : `<p style="grid-column:1/-1;text-align:center;color:var(--text-dim);font-family:var(--mono);padding:40px 0;">No labs match "${searchTerm}".</p>`;
    renderProgress();
  }

  document.getElementById("resetBtn").addEventListener("click", () => {
    if (confirm("Reset ALL lab progress? This clears your local solved status for every lab.")) {
      localStorage.removeItem(PROGRESS_KEY);
      renderGrid();
    }
  });

  renderDifficultyToggle();
  setDifficultyCookie(getDifficulty());
  renderFilters();
  renderGrid();
})();
