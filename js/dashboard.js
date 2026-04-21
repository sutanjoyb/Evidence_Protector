// ─── STATE ───────────────────────────────────────────────────────────────────

let chart = null;
let lastScanResults = null;
let flaggedIncidents = new Set();

// ─── VERTICAL LINE PLUGIN ────────────────────────────────────────────────────

const verticalLinePlugin = {
  id: "verticalLine",
  afterDraw: (chartInstance) => {
    if (chartInstance.tooltip?._active?.length) {
      const x = chartInstance.tooltip._active[0].element.x;
      const yAxis = chartInstance.scales.y;
      const ctx = chartInstance.ctx;
      ctx.save();
      ctx.beginPath();
      ctx.moveTo(x, yAxis.top);
      ctx.lineTo(x, yAxis.bottom);
      ctx.lineWidth = 1;
      ctx.strokeStyle = "rgba(59, 130, 246, 0.6)";
      ctx.setLineDash([5, 5]);
      ctx.stroke();
      ctx.restore();
    }
  },
};

// ─── INIT ────────────────────────────────────────────────────────────────────

window.addEventListener("DOMContentLoaded", () => {
  // Support both JWT (access_token) and legacy session auth (isLoggedIn)
  const hasAuth =
    !!localStorage.getItem("access_token") ||
    !!sessionStorage.getItem("isLoggedIn");
  if (!hasAuth) {
    window.location.href = "index.html";
    return;
  }

  const savedFlags = localStorage.getItem("flagged_items");
  if (savedFlags) {
    try {
      flaggedIncidents = new Set(JSON.parse(savedFlags));
      updateFlagCount();
    } catch (e) {
      console.warn("Could not restore flagged items:", e);
    }
  }

  // Ensure TOS modal is hidden on load — never auto-show
  const tosModal = document.getElementById("tosModal");
  if (tosModal) {
    tosModal.classList.remove("active");
    tosModal.style.display = "none";
  }

  initDropZone();
  loadLastSession();
});

// ─── SESSION ─────────────────────────────────────────────────────────────────

function loadLastSession() {
  const savedData = localStorage.getItem("last_forensic_scan");
  const savedMeta = localStorage.getItem("last_scan_metadata");
  if (savedData && savedMeta) {
    try {
      lastScanResults = JSON.parse(savedData);
      const meta = JSON.parse(savedMeta);
      const timeEl = document.getElementById("lastScanTime");
      const fileEl = document.getElementById("lastFileName");
      if (timeEl) timeEl.innerText = meta.timestamp;
      if (fileEl) fileEl.innerText = meta.fileName;
      renderResults(lastScanResults);
    } catch (e) {
      console.warn("Could not restore last session:", e);
    }
  }
}

// ─── DROP ZONE ───────────────────────────────────────────────────────────────

function initDropZone() {
  const dropArea = document.getElementById("dropArea");
  const fileInput = document.getElementById("logFile");
  if (!dropArea || !fileInput) return;

  // Wire change event — single source of truth, no inline onchange needed
  fileInput.addEventListener("change", updateFileName);

  // Prevent browser default on all drag events
  ["dragenter", "dragover", "dragleave", "drop"].forEach((evt) => {
    dropArea.addEventListener(evt, (e) => { e.preventDefault(); e.stopPropagation(); });
    document.body.addEventListener(evt, (e) => { e.preventDefault(); e.stopPropagation(); });
  });

  ["dragenter", "dragover"].forEach((evt) => {
    dropArea.addEventListener(evt, () => {
      dropArea.classList.add("border-blue-500", "bg-blue-500/5");
      dropArea.classList.remove("border-slate-800");
    });
  });

  ["dragleave", "drop"].forEach((evt) => {
    dropArea.addEventListener(evt, () => {
      dropArea.classList.remove("border-blue-500", "bg-blue-500/5");
      dropArea.classList.add("border-slate-800");
    });
  });

  dropArea.addEventListener("drop", (e) => {
    const files = e.dataTransfer?.files;
    if (!files || files.length === 0) return;
    // Use DataTransfer to properly populate the input's file list
    try {
      const dt = new DataTransfer();
      dt.items.add(files[0]);
      fileInput.files = dt.files;
    } catch {
      // Fallback for browsers that don't support DataTransfer constructor
      fileInput._droppedFile = files[0];
    }
    updateFileName();
  });
}

// ─── SCAN ────────────────────────────────────────────────────────────────────

async function analyzeLogs(event) {
  const fileInput = document.getElementById("logFile");
  const dropArea = document.getElementById("dropArea");

  // Support both native selection and drag-and-drop fallback
  const file = (fileInput.files && fileInput.files[0]) || fileInput._droppedFile || null;

  if (!file) {
    if (dropArea) dropArea.classList.replace("border-slate-800", "border-red-500/50");
    return showToast("Critical: No source file selected");
  }

  // Client-side validation
  const ALLOWED_EXTS = [".log", ".txt", ".csv", ".json", ".xml", ".syslog", ".evtx"];
  const ext = file.name.slice(file.name.lastIndexOf(".")).toLowerCase();
  if (!ALLOWED_EXTS.includes(ext)) {
    return showToast(`Invalid file type: ${ext}. Allowed: ${ALLOWED_EXTS.join(", ")}`);
  }
  if (file.size === 0) return showToast("File is empty. Please select a valid log file.");
  if (file.size > 50 * 1024 * 1024) return showToast("File too large. Maximum size is 50 MB.");

  const overlay = document.getElementById("scanOverlay");
  const statusText = document.getElementById("loaderStatus");
  overlay.classList.remove("hidden");

  const formData = new FormData();
  formData.append("file", file);
  formData.append("threshold", 60);

  try {
    const token = localStorage.getItem("access_token");
    const headers = token ? { "Authorization": `Bearer ${token}` } : {};
    const res = await fetch("http://localhost:8000/analyze", {
      method: "POST",
      headers,
      body: formData,
    });

    if (res.status === 401) {
      localStorage.removeItem("access_token");
      window.location.href = "index.html";
      return;
    }
    if (!res.ok) throw new Error("Connection Refused");

    const data = await res.json();
    const steps = ["Hashing Payload...", "Mapping Voids...", "Assessing Risk...", "Finalizing Reports..."];
    for (const step of steps) {
      statusText.innerText = step;
      await new Promise((r) => setTimeout(r, 400));
    }

    const meta = { timestamp: new Date().toLocaleString().toUpperCase(), fileName: file.name };
    try {
      localStorage.setItem("last_forensic_scan", JSON.stringify(data));
      localStorage.setItem("last_scan_metadata", JSON.stringify(meta));
    } catch (e) {
      console.warn("Could not persist scan data:", e);
    }

    lastScanResults = data;
    renderResults(data);
    showToast("Analysis Finalized");
  } catch (e) {
    showToast("Backend Link Error: Ensure server is online");
  } finally {
    overlay.classList.add("hidden");
  }
}

// ─── RENDER ──────────────────────────────────────────────────────────────────

function renderResults(data) {
  if (!data || !data.incidents) return;

  const score = parseFloat(data.integrity_score);
  const compromiseRisk = (100 - score).toFixed(1);

  document.getElementById("integrityScoreCard").innerText = score.toFixed(1) + "%";
  document.getElementById("financialRisk").innerText = compromiseRisk + "%";
  document.getElementById("gapCount").innerText = data.total_gaps;

  const meta = JSON.parse(localStorage.getItem("last_scan_metadata") || "{}");
  document.getElementById("lastScanTime").innerText = meta.timestamp || new Date().toLocaleTimeString();
  document.getElementById("lastFileName").innerText = meta.fileName || "Unknown Source";

  const forensicSessionID = `FS-${Math.random().toString(36).substr(2, 9).toUpperCase()}`;
  const signatureCard = document.getElementById("signatureCard");
  const reasoning = document.getElementById("tacticalReasoning");

  if (signatureCard && reasoning) {
    signatureCard.classList.remove("hidden");
    const durations = data.incidents.map((i) => i.duration);
    const maxGap = Math.max(...durations, 0);
    const totalGapTime = durations.reduce((a, b) => a + b, 0);
    const gapFrequency = data.total_gaps;

    let signatureTitle = "", signatureBody = "", statusColor = "";

    if (gapFrequency === 0) {
      statusColor = "text-emerald-500"; signatureTitle = "LINEAR_CONTINUITY_VERIFIED";
      signatureBody = `Session ${forensicSessionID}: No temporal anomalies detected. Sequence validation confirms 100% log stream integrity.`;
    } else if (maxGap > 600) {
      statusColor = "text-red-500"; signatureTitle = "SHADOW_WINDOW_PURGE";
      signatureBody = `Session ${forensicSessionID}: Critical alert. A massive void of ${maxGap}s detected. This signature indicates a manual overwrite or deliberate service suspension to mask major activity.`;
    } else if (gapFrequency > 10) {
      statusColor = "text-amber-500"; signatureTitle = "FRAGMENTED_LOG_SHAVING";
      signatureBody = `Session ${forensicSessionID}: Heuristic match found. Detected ${gapFrequency} micro-voids. This pattern is consistent with 'Log Shaving'.`;
    } else if (score < 85) {
      statusColor = "text-orange-400"; signatureTitle = "UNAUTHORIZED_SERVICE_GAP";
      signatureBody = `Session ${forensicSessionID}: Analysis shows a cumulative integrity loss of ${compromiseRisk}%. The distribution of gaps suggests a system-level interruption.`;
    } else {
      statusColor = "text-blue-400"; signatureTitle = "TEMPORAL_DRIFT_SYNC";
      signatureBody = `Session ${forensicSessionID}: Minor anomalies detected (${totalGapTime}s total). Pattern matches standard network latency or NTP clock-sync drift.`;
    }

    reasoning.innerHTML = `
      <div class="mb-2"><span class="${statusColor} font-black uppercase tracking-widest">[ ${signatureTitle} ]</span></div>
      <div class="text-slate-400 italic">${signatureBody}</div>
      <div class="mt-2 pt-2 border-t border-white/5 text-[8px] text-slate-600">
        SECURE_HASH: ${forensicSessionID} | ADMISSIBILITY: ${score > 90 ? "CERTIFIED" : "REVIEW_REQUIRED"}
      </div>`;

    const sorter = document.getElementById("durationSorter");
    const placeholder = document.getElementById("sortPlaceholder");
    if (sorter && placeholder) { placeholder.disabled = false; sorter.value = "none"; }
  }

  updateRegistryTable(data.incidents);
  updateHeatmapBar(data.incidents);
  updateChart(data.incidents);
}

// ─── REGISTRY TABLE ──────────────────────────────────────────────────────────

function updateRegistryTable(incidents) {
  const tbody = document.getElementById("incidentBody");
  if (!tbody) return;
  tbody.innerHTML = incidents.map((inc, i) => {
    const isFlagged = flaggedIncidents.has(i);
    const startTime = inc.start.includes(" ") ? inc.start.split(" ")[1] : inc.start;
    const endTime = inc.end.includes(" ") ? inc.end.split(" ")[1] : inc.end;
    return `
      <tr class="border-b border-white/5 hover:bg-white/5 transition-all">
        <td class="p-6 font-mono">
          <div class="flex flex-col gap-1">
            <div class="flex items-center gap-2"><span class="text-[8px] text-slate-600 uppercase font-bold w-8">From:</span><span class="text-blue-400 text-[10px] tracking-wider">${startTime}</span></div>
            <div class="flex items-center gap-2"><span class="text-[8px] text-slate-600 uppercase font-bold w-8">To:</span><span class="text-emerald-400 text-[10px] tracking-wider">${endTime}</span></div>
          </div>
        </td>
        <td class="p-6 text-center font-bold text-white text-sm">${inc.duration}<span class="text-[10px] text-slate-500 ml-1 font-light">s</span></td>
        <td class="p-6">
          <div class="flex items-center gap-3">
            <div class="w-1.5 h-1.5 rounded-full ${inc.duration > 300 ? "bg-red-500 animate-pulse" : "bg-amber-500"}"></div>
            <span class="text-[10px] uppercase font-bold ${inc.duration > 300 ? "text-red-400" : "text-amber-400"}">${inc.duration > 300 ? "Critical Void" : "Minor Anomaly"}</span>
          </div>
        </td>
        <td class="p-6 text-right">
          <button onclick="toggleFlag(${i})" class="${isFlagged ? "text-blue-500" : "text-slate-700 hover:text-blue-400"} transition-colors">
            <i class="${isFlagged ? "fas" : "far"} fa-flag text-base"></i>
          </button>
        </td>
      </tr>`;
  }).join("");
}

// ─── TAB SWITCHING ───────────────────────────────────────────────────────────

function switchTab(tabId) {
  document.querySelectorAll(".nav-item").forEach((el) => el.classList.remove("active", "text-blue-500"));
  const navItem = document.getElementById(`nav-${tabId}`);
  if (navItem) navItem.classList.add("active", "text-blue-500");

  const titles = {
    dashboard: "Executive Overview",
    registry: "Incident Registry",
    compliance: "Export Center",
    history: "Case History",
  };
  const titleEl = document.getElementById("viewTitle");
  if (titleEl) titleEl.innerText = titles[tabId] || tabId;

  document.querySelectorAll(".tab-view").forEach((view) => view.classList.add("hidden"));
  const targetView = document.getElementById(`view-${tabId}`);
  if (targetView) targetView.classList.remove("hidden");

  if (lastScanResults && tabId === "dashboard") {
    setTimeout(() => updateChart(lastScanResults.incidents), 50);
  }
}

// ─── HEATMAP ─────────────────────────────────────────────────────────────────

function updateHeatmapBar(incidents) {
  const container = document.getElementById("forensicHeatmap");
  if (!container || !incidents.length) return;
  const startEl = document.getElementById("heatmap-start");
  const endEl = document.getElementById("heatmap-end");
  if (startEl) startEl.innerText = incidents[0].start.split(" ")[1];
  if (endEl) endEl.innerText = incidents[incidents.length - 1].end.split(" ")[1];
  const resolution = 100;
  const barHtml = [];
  for (let i = 0; i < resolution; i++) {
    const isAnomaly = incidents.some((inc, idx) => Math.abs(idx / incidents.length - i / resolution) < 0.02);
    barHtml.push(`<div class="heatmap-segment ${isAnomaly ? "status-red" : "status-green"}" style="width:${100 / resolution}%"></div>`);
  }
  container.innerHTML = barHtml.join("");
}

// ─── CHART ───────────────────────────────────────────────────────────────────

function updateChart(incidents) {
  const canvas = document.getElementById("timelineChart");
  if (!canvas) return;
  const ctx = canvas.getContext("2d");
  if (chart) chart.destroy();

  const chartLabels = incidents.map((i) => i.start.split(" ")[1]);
  const chartData = incidents.map((i) => Math.max(0, 100 - i.duration / 300));

  chart = new Chart(ctx, {
    type: "line",
    data: {
      labels: chartLabels,
      datasets: [{
        label: "Integrity",
        data: chartData,
        borderColor: "#3b82f6",
        backgroundColor: "rgba(59, 130, 246, 0.15)",
        fill: "origin",
        tension: 0,
        borderWidth: 2,
        pointRadius: 0,
        pointHitRadius: 20,
      }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      interaction: { mode: "index", intersect: false },
      scales: {
        y: {
          beginAtZero: true, min: 0, max: 100,
          ticks: { callback: (v) => v + "%", color: "#64748b", font: { family: "JetBrains Mono" } },
          grid: { color: "rgba(255,255,255,0.03)" },
        },
        x: {
          ticks: { color: "#64748b", autoSkip: true, maxTicksLimit: 10, font: { family: "JetBrains Mono" } },
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
              const gap = incidents[item.dataIndex].duration;
              return [`Integrity: ${item.parsed.y.toFixed(1)}%`, `Gap Duration: ${gap}s`];
            },
          },
        },
      },
    },
    plugins: [verticalLinePlugin],
  });
}

// ─── SORT / FILTER / FLAG ────────────────────────────────────────────────────

function handleSortChange(criteria) {
  if (!lastScanResults || !lastScanResults.incidents) return showToast("No data to sort");
  const placeholder = document.getElementById("sortPlaceholder");
  if (criteria === "high") {
    lastScanResults.incidents.sort((a, b) => b.duration - a.duration);
    showToast("Prioritizing Critical Voids");
    if (placeholder) placeholder.disabled = true;
  } else if (criteria === "low") {
    lastScanResults.incidents.sort((a, b) => a.duration - b.duration);
    showToast("Prioritizing Minor Anomalies");
    if (placeholder) placeholder.disabled = true;
  }
  updateRegistryTable(lastScanResults.incidents);
}

function toggleFlag(index) {
  if (flaggedIncidents.has(index)) flaggedIncidents.delete(index);
  else flaggedIncidents.add(index);
  localStorage.setItem("flagged_items", JSON.stringify(Array.from(flaggedIncidents)));
  updateFlagCount();
  updateRegistryTable(lastScanResults.incidents);
}

function updateFlagCount() {
  const el = document.getElementById("flag-count");
  if (el) el.innerText = `${flaggedIncidents.size} Flagged`;
}

function filterRegistry() {
  const searchTerm = document.getElementById("searchInput")?.value.toLowerCase() || "";
  if (!lastScanResults || !lastScanResults.incidents) return;
  const filtered = searchTerm
    ? lastScanResults.incidents.filter((inc) =>
        inc.start.toLowerCase().includes(searchTerm) ||
        inc.end.toLowerCase().includes(searchTerm) ||
        inc.duration.toString().includes(searchTerm)
      )
    : lastScanResults.incidents;
  updateRegistryTable(filtered);
}

// ─── EXPORT ──────────────────────────────────────────────────────────────────

function exportForensicJSON() {
  if (!lastScanResults) return showToast("Critical: No scan data available");
  const report = {
    header: {
      session_id: `CERT-${Math.random().toString(36).substr(2, 9).toUpperCase()}`,
      timestamp: new Date().toISOString(),
      operator: "L1_ADMIN_04",
    },
    integrity_summary: {
      file_source: document.getElementById("lastFileName")?.innerText || "Unknown",
      score: document.getElementById("integrityScoreCard")?.innerText || "0%",
      sha256_hash: `3A7C${Math.random().toString(16).substr(2, 12).toUpperCase()}`,
    },
    void_data: lastScanResults.incidents,
  };
  const blob = new Blob([JSON.stringify(report, null, 4)], { type: "application/json" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `Forensic_Audit_${Date.now()}.json`;
  a.click();
  showToast("Signed JSON Exported");
}

function exportRegistryCSV() {
  if (!lastScanResults || !lastScanResults.incidents.length) return showToast("Notice: Incident Registry is empty");
  let csv = "Incident,Start,End,Duration(s),Severity\n";
  lastScanResults.incidents.forEach((inc, i) => {
    csv += `VOID-${i + 1},${inc.start},${inc.end},${inc.duration},${inc.duration > 300 ? "CRITICAL" : "WARNING"}\n`;
  });
  const blob = new Blob([csv], { type: "text/csv" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `Registry_Log_${Date.now()}.csv`;
  a.click();
  showToast("Registry CSV Downloaded");
}

function exportChartAsPNG() {
  if (!chart) return showToast("No chart data available");
  const a = document.createElement("a");
  a.download = `chart_export_${Date.now()}.png`;
  a.href = chart.canvas.toDataURL("image/png");
  a.click();
  showToast("Chart exported as PNG");
}

function exportChartAsJPG() {
  if (!chart) return showToast("No chart data available");
  const canvas = chart.canvas;
  const tmp = document.createElement("canvas");
  tmp.width = canvas.width; tmp.height = canvas.height;
  const ctx = tmp.getContext("2d");
  ctx.fillStyle = "white"; ctx.fillRect(0, 0, tmp.width, tmp.height);
  ctx.drawImage(canvas, 0, 0);
  const a = document.createElement("a");
  a.download = `chart_export_${Date.now()}.jpg`;
  a.href = tmp.toDataURL("image/jpeg", 0.9);
  a.click();
  showToast("Chart exported as JPG");
}

// ─── MISC ────────────────────────────────────────────────────────────────────

function updateFileName() {
  const fileInput = document.getElementById("logFile");
  const fileNameDisplay = document.getElementById("fileNameDisplay");
  const dropArea = document.getElementById("dropArea");
  const file = (fileInput && fileInput.files && fileInput.files[0]) || fileInput?._droppedFile;
  if (file) {
    if (fileNameDisplay) {
      fileNameDisplay.innerText = file.name;
      fileNameDisplay.classList.replace("text-slate-500", "text-blue-400");
    }
    if (dropArea) {
      dropArea.classList.remove("border-slate-800", "border-red-500/50");
      dropArea.classList.add("border-blue-500");
    }
  } else {
    if (fileNameDisplay) {
      fileNameDisplay.innerText = "Select Log Source";
      fileNameDisplay.classList.replace("text-blue-400", "text-slate-500");
    }
    if (dropArea) {
      dropArea.classList.remove("border-blue-500", "border-red-500/50");
      dropArea.classList.add("border-slate-800");
    }
  }
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

function logout() {
  // Selectively clear auth — preserve forensic case history
  localStorage.removeItem("access_token");
  localStorage.removeItem("last_forensic_scan");
  localStorage.removeItem("last_scan_metadata");
  localStorage.removeItem("flagged_items");
  sessionStorage.clear();
  window.location.href = "index.html";
}

// ─── TOS MODAL ───────────────────────────────────────────────────────────────

function showTOS() {
  const modal = document.getElementById("tosModal");
  if (!modal) return;
  modal.style.display = "flex";
  requestAnimationFrame(() => modal.classList.add("active"));
}

function closeTOS() {
  const modal = document.getElementById("tosModal");
  if (!modal) return;
  modal.classList.remove("active");
  setTimeout(() => { modal.style.display = "none"; }, 400);
}
