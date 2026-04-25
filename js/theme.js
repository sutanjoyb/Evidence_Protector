(function () {
  const STORAGE_KEY = "ep_theme";
  const root = document.documentElement;

  function applyTheme(theme) {
    root.setAttribute("data-theme", theme);

    // Update the Icon
    const icon = document.querySelector("#themeToggle i");
    if (icon) {
      icon.className = theme === "light" ? "fas fa-moon" : "fas fa-sun";
    }

    // SPECIAL: Update Chart.js Global Defaults for readability
    if (window.Chart) {
      const textColor = theme === "light" ? "#334155" : "#94a3b8";
      const gridColor =
        theme === "light" ? "rgba(0,0,0,0.05)" : "rgba(255,255,255,0.05)";

      Chart.defaults.color = textColor;
      Chart.defaults.scale.grid.color = gridColor;

      // Refresh existing chart if it exists
      if (window.chart) {
        window.chart.options.scales.y.ticks.color = textColor;
        window.chart.options.scales.x.ticks.color = textColor;
        window.chart.update();
      }
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

  // Apply immediately
  initTheme();

  document.addEventListener("DOMContentLoaded", () => {
    initTheme();
    const btn = document.getElementById("themeToggle");
    if (btn) {
      // Remove old listener if exists and add new
      btn.onclick = toggleTheme;
    }
  });
})();
