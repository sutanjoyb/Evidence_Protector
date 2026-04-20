/**
 * Theme manager — handles dark/light toggle with localStorage persistence.
 * Include this script in both index.html and dashboard.html.
 */
(function () {
  const STORAGE_KEY = "ep_theme";
  const root = document.documentElement;

  function applyTheme(theme) {
    root.setAttribute("data-theme", theme);
    const icon = document.querySelector("#themeToggle i");
    if (icon) {
      icon.className = theme === "light" ? "fas fa-moon" : "fas fa-sun";
    }
  }

  function initTheme() {
    const saved = localStorage.getItem(STORAGE_KEY) || "dark";
    applyTheme(saved);
  }

  function toggleTheme() {
    const current = root.getAttribute("data-theme") || "dark";
    const next = current === "dark" ? "light" : "dark";
    localStorage.setItem(STORAGE_KEY, next);
    applyTheme(next);
  }

  // Apply immediately to avoid flash
  initTheme();

  document.addEventListener("DOMContentLoaded", () => {
    initTheme(); // re-apply after DOM ready (icon update)
    const btn = document.getElementById("themeToggle");
    if (btn) btn.addEventListener("click", toggleTheme);
  });
})();
