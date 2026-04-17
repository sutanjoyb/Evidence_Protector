let chart;
let lastScanResults = null;
let flaggedIncidents = new Set();

// 1. IMPROVED VERTICAL SCANNER PLUGIN
const verticalLinePlugin = {
  id: "verticalLine",
  afterDraw: (chart) => {
    if (chart.tooltip?._active?.length) {
      const x = chart.tooltip._active[0].element.x;
      const yAxis = chart.scales.y;
      const ctx = chart.ctx;
      ctx.save();
      ctx.beginPath();
      ctx.moveTo(x, yAxis.top);
      ctx.lineTo(x, yAxis.bottom);
      ctx.lineWidth = 1;
      ctx.strokeStyle = "rgba(59, 130, 246, 0.6)"; // Slightly brighter blue
      ctx.setLineDash([5, 5]);
      ctx.stroke();
      ctx.restore();
    }
  },
};

window.addEventListener("DOMContentLoaded", () => {
  if (!sessionStorage.getItem("isLoggedIn")) {
    window.location.href = "index.html";
    return;
  }
  const savedFlags = localStorage.getItem("flagged_items");
  if (savedFlags) {
    flaggedIncidents = new Set(JSON.parse(savedFlags));
    updateFlagCount();
  }
  loadLastSession();
});

function loadLastSession() {
  const savedData = localStorage.getItem("last_forensic_scan");
  const savedMeta = localStorage.getItem("last_scan_metadata");
  if (savedData && savedMeta) {
    lastScanResults = JSON.parse(savedData);
    const meta = JSON.parse(savedMeta);
    const timeEl = document.getElementById("lastScanTime");
    const fileEl = document.getElementById("lastFileName");
    if (timeEl) timeEl.innerText = meta.timestamp;
    if (fileEl) fileEl.innerText = meta.fileName;
    renderResults(lastScanResults);
  }
}

async function analyzeLogs(event) {
  const fileInput = document.getElementById("logFile");
  const file = fileInput.files[0];
  if (!file) return showToast("Critical: No source file selected");

  const overlay = document.getElementById("scanOverlay");
  const statusText = document.getElementById("loaderStatus");
  overlay.classList.remove("hidden");

  const formData = new FormData();
  formData.append("file", file);
  formData.append("threshold", 60);

  try {
    const res = await fetch("http://localhost:8000/analyze", {
      method: "POST",
      body: formData,
    });
    if (!res.ok) throw new Error("Connection Refused");
    const data = await res.json();

    const steps = [
      "Hashing Payload...",
      "Mapping Voids...",
      "Assessing Risk...",
      "Finalizing Reports...",
    ];
    for (const step of steps) {
      statusText.innerText = step;
      await new Promise((r) => setTimeout(r, 400)); // Shorter delay for better UX
    }

    const meta = {
      timestamp: new Date().toLocaleString().toUpperCase(),
      fileName: file.name,
    };
    localStorage.setItem("last_forensic_scan", JSON.stringify(data));
    localStorage.setItem("last_scan_metadata", JSON.stringify(meta));

    lastScanResults = data;
    renderResults(data);
    showToast("Analysis Finalized");
  } catch (e) {
    showToast("Backend Link Error: Ensure server is online");
  } finally {
    overlay.classList.add("hidden");
  }
}

function renderResults(data) {
  if (!data) return;
  const score = parseFloat(data.integrity_score);

  // 1. Core KPIs
  const scoreEl = document.getElementById("integrityScoreCard");
  const gapEl = document.getElementById("gapCount");
  const riskEl = document.getElementById("financialRisk");

  if (scoreEl) scoreEl.innerText = score.toFixed(1) + "%";
  if (gapEl) gapEl.innerText = data.total_gaps;

  const risk = (100 - score).toFixed(1);
  if (riskEl) {
    riskEl.innerText = risk + "%";
    riskEl.className =
      risk > 50
        ? "text-3xl font-black text-red-500"
        : risk > 20
          ? "text-3xl font-black text-amber-500"
          : "text-3xl font-black text-emerald-500";
  }

  // 2. Hash & Metadata
  const hashEl = document.getElementById("fileHash");
  if (hashEl) {
    hashEl.innerText = `ID: ${Math.random().toString(36).substring(7).toUpperCase()}`;
    hashEl.classList.remove("hidden");
  }

  // 3. Dynamic Remediation Actions
  const actionList = document.getElementById("actionList");
  if (actionList) {
    const actions = [];
    if (score < 60) {
      actions.push({
        icon: "fa-shield-virus",
        text: "Isolate network Node immediately.",
      });
      actions.push({ icon: "fa-key", text: "Rotate Admin SSL Certificates." });
    } else if (score < 90) {
      actions.push({
        icon: "fa-user-lock",
        text: "Audit Operator account permissions.",
      });
      actions.push({
        icon: "fa-sync",
        text: "Verify backup log synchronization.",
      });
    } else {
      actions.push({
        icon: "fa-check",
        text: "Integrity verified. Schedule weekly audit.",
      });
    }
    actionList.innerHTML = actions
      .map(
        (a) => `
      <div class="flex items-center gap-3 p-3 bg-slate-950/50 rounded-xl border border-white/5 text-[10px]">
          <i class="fas ${a.icon} text-amber-500"></i>
          <span class="text-slate-300 uppercase tracking-tighter">${a.text}</span>
      </div>`,
      )
      .join("");
  }

  // 4. Heatmap & Table
  updateHeatmapBar(data.incidents);
  const tbody = document.getElementById("incidentBody");
  if (tbody) {
    tbody.innerHTML = data.incidents
      .map((inc, i) => {
        const isFlagged = flaggedIncidents.has(i);
        return `<tr id="row-${i}" class="border-b border-white/5 hover:bg-white/5 transition-all ${isFlagged ? "flagged-row" : ""}">
          <td class="p-6 font-mono text-blue-400 text-[10px]">${inc.start.split(" ")[1]}<br>${inc.end.split(" ")[1]}</td>
          <td class="p-6 text-center font-bold text-white">${inc.duration}s</td>
          <td class="p-6"><span class="px-2 py-1 rounded border text-[9px] ${inc.severity === "CRITICAL" ? "text-red-400 border-red-500/20" : "text-amber-400 border-amber-500/20"}">${inc.severity}</span></td>
          <td class="p-6 text-right"><button onclick="toggleFlag(${i})" class="${isFlagged ? "text-blue-500" : "text-slate-700 hover:text-blue-400"}"><i class="${isFlagged ? "fas" : "far"} fa-flag"></i></button></td>
      </tr>`;
      })
      .join("");
  }

  // 5. Update Chart
  updateChart(data.incidents);
}

function updateHeatmapBar(incidents) {
  const container = document.getElementById("forensicHeatmap");
  if (!container || !incidents.length) return;

  const startEl = document.getElementById("heatmap-start");
  const endEl = document.getElementById("heatmap-end");
  if (startEl) startEl.innerText = incidents[0].start.split(" ")[1];
  if (endEl)
    endEl.innerText = incidents[incidents.length - 1].end.split(" ")[1];

  const resolution = 100;
  const barHtml = [];
  for (let i = 0; i < resolution; i++) {
    const isAnomaly = incidents.some(
      (inc, idx) => Math.abs(idx / incidents.length - i / resolution) < 0.02,
    );
    const statusClass = isAnomaly ? "status-red" : "status-green";
    barHtml.push(
      `<div class="heatmap-segment ${statusClass}" style="width: ${100 / resolution}%"></div>`,
    );
  }
  container.innerHTML = barHtml.join("");
}

function updateChart(incidents) {
  const canvas = document.getElementById("timelineChart");
  if (!canvas) return;
  const ctx = canvas.getContext("2d");
  if (chart) chart.destroy();

  const precision =
    document.getElementById("timePrecision")?.value || "minutes";
  const divider =
    precision === "seconds" ? 1 : precision === "minutes" ? 60 : 3600;

  const chartLabels = incidents.map((i) => i.start.split(" ")[1]);
  const chartData = incidents.map((i) =>
    Math.max(0, 100 - i.duration / (divider * 5)),
  );

  chart = new Chart(ctx, {
    type: "line",
    data: {
      labels: chartLabels,
      datasets: [
        {
          label: "Integrity",
          data: chartData,
          borderColor: "#3b82f6",
          backgroundColor: "rgba(59, 130, 246, 0.15)",
          fill: "origin",
          tension: 0,
          borderWidth: 2,
          pointRadius: 0, // Keeps it clean, points appear on hover
          pointHitRadius: 20,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      interaction: {
        mode: "index",
        intersect: false, // This allows the vertical line to show anywhere along the X-axis
      },
      scales: {
        y: {
          beginAtZero: true,
          min: 0,
          max: 100,
          ticks: {
            callback: (v) => v + "%",
            color: "#64748b",
            font: { family: "JetBrains Mono" },
          },
          grid: { color: "rgba(255,255,255,0.03)" },
        },
        x: {
          ticks: {
            color: "#64748b",
            autoSkip: true,
            maxTicksLimit: 10,
            font: { family: "JetBrains Mono" },
          },
          grid: { display: false },
        },
      },
      plugins: {
        legend: { display: false },
        tooltip: {
          enabled: true,
          backgroundColor: "rgba(15, 23, 42, 0.95)",
          titleFont: { size: 13, family: "JetBrains Mono" },
          bodyFont: { size: 12, family: "JetBrains Mono" },
          padding: 12,
          displayColors: false,
          callbacks: {
            title: (items) => `Timestamp: ${items[0].label}`,
            label: (item) => {
              const index = item.dataIndex;
              const gap = incidents[index].duration;
              return [
                `Integrity: ${item.parsed.y.toFixed(1)}%`,
                `Gap Duration: ${gap}s`,
              ];
            },
          },
        },
      },
    },
    plugins: [verticalLinePlugin],
  });
}

function switchTab(tabId) {
  document
    .querySelectorAll(".nav-item")
    .forEach((el) => el.classList.remove("active", "text-blue-500"));
  const navItem = document.getElementById(`nav-${tabId}`);
  if (navItem) navItem.classList.add("active", "text-blue-500");

  const titles = {
    dashboard: "Executive Overview",
    lab: "Forensic Lab",
    threats: "Neural Triage Map",
    registry: "Incident Registry",
    nodes: "Strategic Timeline",
    compliance: "Export Center",
  };
  const titleEl = document.getElementById("viewTitle");
  if (titleEl) titleEl.innerText = titles[tabId];

  document
    .querySelectorAll(".tab-view")
    .forEach((view) => view.classList.add("hidden"));
  const targetView = document.getElementById(`view-${tabId}`);
  if (targetView) targetView.classList.remove("hidden");

  // Re-init chart if switching back to dashboard
  if (lastScanResults && tabId === "dashboard") {
    setTimeout(() => updateChart(lastScanResults.incidents), 50);
  }
}

function toggleFlag(index) {
  if (flaggedIncidents.has(index)) flaggedIncidents.delete(index);
  else flaggedIncidents.add(index);
  localStorage.setItem(
    "flagged_items",
    JSON.stringify(Array.from(flaggedIncidents)),
  );
  renderResults(lastScanResults);
}

function updateFlagCount() {
  const el = document.getElementById("flag-count");
  if (el) el.innerText = `${flaggedIncidents.size} Flagged`;
}

function showToast(msg) {
  const toast = document.getElementById("toast");
  const msgEl = document.getElementById("toastMsg");
  if (!toast || !msgEl) return;
  msgEl.innerText = msg;
  toast.classList.replace("translate-y-24", "translate-y-0");
  toast.classList.replace("opacity-0", "opacity-100");
  setTimeout(() => {
    toast.classList.replace("translate-y-0", "translate-y-24");
    toast.classList.replace("opacity-100", "opacity-0");
  }, 3000);
}

function updateFileName() {
  const f = document.getElementById("logFile").files[0];
  const display = document.getElementById("fileNameDisplay");
  if (display) display.innerText = f ? f.name : "Select Log Source";
}

function logout() {
  sessionStorage.clear();
  localStorage.clear();
  window.location.href = "index.html";
}
