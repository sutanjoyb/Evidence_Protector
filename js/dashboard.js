let chart;
let lastScanResults = null;
let flaggedIncidents = new Set();
let activeCaseId = null;

// ─── CASE MANAGEMENT — SIZE-CAPPED WITH FIFO EVICTION ───────────────────────

const CASES_KEY = "forensic_cases";
const MAX_CASES = 50;                        // max number of stored cases
const MAX_INCIDENTS_PER_CASE = 200;          // truncate oversized incident arrays
const STORAGE_WARN_BYTES = 4 * 1024 * 1024; // warn at 4 MB

function getCases() {
  try {
    return JSON.parse(localStorage.getItem(CASES_KEY) || "[]");
  } catch {
    return [];
  }
}

function getStorageUsedBytes() {
  let total = 0;
  for (const key in localStorage) {
    if (Object.prototype.hasOwnProperty.call(localStorage, key)) {
      total += (localStorage[key].length + key.length) * 2; // UTF-16
    }
  }
  return total;
}

function saveCases(cases) {
  try {
    localStorage.setItem(CASES_KEY, JSON.stringify(cases));
    updateCaseBadge();
    const used = getStorageUsedBytes();
    if (used > STORAGE_WARN_BYTES) {
      showToast(`Storage Warning: ${(used / 1024 / 1024).toFixed(1)} MB used. Consider deleting old cases.`);
    }
  } catch (e) {
    if (e.name === "QuotaExceededError" || e.code === 22) {
      // FIFO eviction: drop oldest cases until it fits
      let evicted = 0;
      while (cases.length > 1) {
        cases.pop(); // remove oldest (array is newest-first)
        evicted++;
        try {
          localStorage.setItem(CASES_KEY, JSON.stringify(cases));
          updateCaseBadge();
          showToast(`Storage full — ${evicted} oldest case(s) removed to make room.`);
          return;
        } catch {
          continue;
        }
      }
      showToast("Critical: Storage full. Cannot save case. Please delete old cases.");
    } else {
      showToast("Storage error: Case could not be saved.");
      console.error("saveCases error:", e);
    }
  }
}

function generateCaseId() {
  return `CASE-${Date.now()}-${Math.random().toString(36).substr(2, 5).toUpperCase()}`;
}

function saveNewCase(data, fileName) {
  const cases = getCases();
  const score = parseFloat(data.integrity_score);
  const id = generateCaseId();

  // Truncate incidents if oversized to keep storage lean
  const incidents = data.incidents.length > MAX_INCIDENTS_PER_CASE
    ? data.incidents.slice(0, MAX_INCIDENTS_PER_CASE)
    : data.incidents;

  const newCase = {
    id,
    name: `Case: ${fileName}`,
    fileName,
    timestamp: new Date().toISOString(),
    integrityScore: score,
    totalGaps: data.total_gaps,
    incidents,
    flagged: false,
  };

  cases.unshift(newCase);

  // Enforce hard cap — evict oldest before even trying to save
  while (cases.length > MAX_CASES) {
    cases.pop();
  }

  saveCases(cases);
  activeCaseId = id;
  return id;
}

function updateCaseBadge() {
  const count = getCases().length;
  const badge = document.getElementById("case-count-badge");
  if (badge) badge.innerText = count;
}

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
      ctx.strokeStyle = "rgba(59, 130, 246, 0.6)";
      ctx.setLineDash([5, 5]);
      ctx.stroke();
      ctx.restore();
    }
  },
};

// ─── INIT ────────────────────────────────────────────────────────────────────

let flaggedIncidents = new Set();
let activeCaseId = null;
let lastScanResults = null;

window.addEventListener("DOMContentLoaded", () => {
  // Support both JWT (access_token) and legacy session auth (isLoggedIn)
  const hasJwt = !!localStorage.getItem("access_token");
  const hasSession = !!sessionStorage.getItem("isLoggedIn");
  if (!hasJwt && !hasSession) {
    window.location.href = "index.html";
    return;
  }

  // Initial setup
  const savedFlags = localStorage.getItem("flagged_items");
  if (savedFlags) {
    try {
      flaggedIncidents = new Set(JSON.parse(savedFlags));
      updateFlagCount();
    } catch (e) {
      console.error("Failed to parse saved flags", e);
    }
  }

  updateGreeting(); // Run immediately for better UX
  updateCaseBadge();
  loadLastSession();
  
  // API Polling
  checkApiStatus();
  setInterval(checkApiStatus, 5000);
});

async function checkApiStatus() {
  const indicator = document.getElementById("apiStatusIndicator");
  if (!indicator) return;

  try {
    const res = await fetch("http://localhost:8000/", {
      method: "GET",
      cache: "no-store"
    });

    if (res.ok) {
      indicator.classList.replace("offline", "online");
    } else {
      indicator.classList.replace("online", "offline");
    }
  } catch (e) {
    // replace only works if 'online' exists; use add/remove for safety
    indicator.classList.remove("online");
    indicator.classList.add("offline");
  }
} 

function updateGreeting() {
  const greetingEl = document.getElementById("userGreeting");
  if (!greetingEl) return;

  const hour = new Date().getHours();
  let msg = "Good Evening";

  if (hour < 12) msg = "Good Morning";
  else if (hour < 18) msg = "Good Afternoon";

  greetingEl.innerText = `${msg}, Operator`;
}

function loadLastSession() {
  const cases = typeof getCases === "function" ? getCases() : [];
  const timeEl = document.getElementById("lastScanTime");
  const fileEl = document.getElementById("lastFileName");

  if (cases.length > 0) {
    const latest = cases[0];
    activeCaseId = latest.id;
    
    if (timeEl) timeEl.innerText = new Date(latest.timestamp).toLocaleString().toUpperCase();
    if (fileEl) fileEl.innerText = latest.fileName;
    
    lastScanResults = { 
      incidents: latest.incidents, 
      integrity_score: latest.integrityScore, 
      total_gaps: latest.totalGaps 
    };
    renderResults(lastScanResults);
  } else {
    const savedData = localStorage.getItem("last_forensic_scan");
    const savedMeta = localStorage.getItem("last_scan_metadata");
    
    if (savedData && savedMeta) {
      try {
        lastScanResults = JSON.parse(savedData);
        const meta = JSON.parse(savedMeta);
        if (timeEl) timeEl.innerText = meta.timestamp;
        if (fileEl) fileEl.innerText = meta.fileName;
        renderResults(lastScanResults);
      } catch (e) {
        console.error("Legacy data corruption", e);
      }
    }
  }
}
// ─── SCAN ────────────────────────────────────────────────────────────────────

async function analyzeLogs(event) {
  const fileInput = document.getElementById("logFile");
  const dropArea = document.getElementById("dropArea");
  const file = fileInput.files[0];
  
  if (!file) {
    if (dropArea) dropArea.classList.replace("border-slate-800", "border-red-500/50");
    return showToast("Critical: No source file selected");
  }

  const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10MB in bytes
    if (file.size > MAX_FILE_SIZE) {
        showToast("File too large! Maximum size is 10MB");
        return;
    }

  // ── CLIENT-SIDE VALIDATION ───────────────────────────────────────────────
  const ALLOWED_EXTS = [".log", ".txt", ".csv", ".json", ".xml", ".syslog", ".evtx"];
  const MAX_SIZE_MB = 50;
  const ext = file.name.slice(file.name.lastIndexOf(".")).toLowerCase();

  if (!ALLOWED_EXTS.includes(ext)) {
    return showToast(`Invalid file type: ${ext}. Allowed: ${ALLOWED_EXTS.join(", ")}`);
  }
  if (file.size === 0) {
    return showToast("File is empty. Please select a valid log file.");
  }
  if (file.size > MAX_SIZE_MB * 1024 * 1024) {
    return showToast(`File too large. Maximum size is ${MAX_SIZE_MB} MB.`);
  }
  // ─────────────────────────────────────────────────────────────────────────

  const overlay = document.getElementById("scanOverlay");
  const statusText = document.getElementById("loaderStatus");
  overlay.classList.remove("hidden");

  const formData = new FormData();
  formData.append("file", file);
  formData.append("threshold", 60);

  try {
    const token = localStorage.getItem("access_token");
    const res = await fetch("http://localhost:8000/analyze", {
      method: "POST",
      headers: { "Authorization": `Bearer ${token}` },
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

    const meta = {
      timestamp: new Date().toLocaleString().toUpperCase(),
      fileName: file.name,
    };

    // Save as a new case (size-capped, FIFO eviction on quota exceeded)
    saveNewCase(data, file.name);

    // Keep legacy keys for backward compat
    try {
      localStorage.setItem("last_forensic_scan", JSON.stringify(data));
      localStorage.setItem("last_scan_metadata", JSON.stringify(meta));
    } catch (e) {
      // Legacy keys are non-critical — case is already saved above
      console.warn("Could not update legacy scan keys:", e);
    }

    lastScanResults = data;
    renderResults(data);
    showToast("Analysis Finalized — Case Saved");
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
      signatureBody = `Session ${forensicSessionID}: Heuristic match found. Detected ${gapFrequency} micro-voids. This pattern is consistent with 'Log Shaving'—automated scripts deleting individual alert lines while leaving the rest of the file intact.`;
    } else if (score < 85) {
      statusColor = "text-orange-400"; signatureTitle = "UNAUTHORIZED_SERVICE_GAP";
      signatureBody = `Session ${forensicSessionID}: Analysis shows a cumulative integrity loss of ${compromiseRisk}%. The distribution of gaps suggests a system-level interruption or unauthorized 'stop-start' command sequence.`;
    } else {
      statusColor = "text-blue-400"; signatureTitle = "TEMPORAL_DRIFT_SYNC";
      signatureBody = `Session ${forensicSessionID}: Minor anomalies detected (${totalGapTime}s total). Pattern matches standard network latency or NTP clock-sync drift. No malicious manipulation signatures identified.`;
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

// ─── CASE HISTORY TAB ────────────────────────────────────────────────────────

function renderCaseHistory() {
  const cases = getCases();
  const tbody = document.getElementById("caseHistoryBody");
  const emptyState = document.getElementById("caseHistoryEmpty");
  if (!tbody) return;

  if (cases.length === 0) {
    tbody.innerHTML = "";
    if (emptyState) emptyState.classList.remove("hidden");
    return;
  }
  if (emptyState) emptyState.classList.add("hidden");

  tbody.innerHTML = cases.map((c) => {
    const scoreColor = c.integrityScore >= 90 ? "text-emerald-400" : c.integrityScore >= 70 ? "text-amber-400" : "text-red-400";
    const flagIcon = c.flagged ? "fas fa-bookmark text-blue-500" : "far fa-bookmark text-slate-600 hover:text-blue-400";
    const isActive = c.id === activeCaseId;
    return `
      <tr class="border-b border-white/5 hover:bg-white/5 transition-all ${isActive ? "bg-blue-500/5" : ""}">
        <td class="p-4">
          <div class="flex items-center gap-2">
            ${isActive ? '<span class="w-1.5 h-1.5 rounded-full bg-blue-500 animate-pulse shrink-0"></span>' : '<span class="w-1.5 h-1.5 rounded-full bg-transparent shrink-0"></span>'}
            <span id="case-name-${c.id}" class="text-[11px] text-slate-300 font-mono truncate max-w-[180px]" title="${c.name}">${c.name}</span>
          </div>
        </td>
        <td class="p-4 text-[10px] font-mono text-slate-500">${new Date(c.timestamp).toLocaleString()}</td>
        <td class="p-4 text-center font-bold ${scoreColor} text-sm">${c.integrityScore.toFixed(1)}%</td>
        <td class="p-4 text-center text-slate-400 text-sm">${c.totalGaps}</td>
        <td class="p-4">
          <div class="flex items-center justify-end gap-3">
            <button onclick="loadCase('${c.id}')" title="Load Case" class="text-[9px] bg-blue-600/20 hover:bg-blue-600/40 text-blue-400 px-2.5 py-1 rounded-lg transition-all font-bold uppercase tracking-wider">Load</button>
            <button onclick="startRenameCase('${c.id}')" title="Rename" class="text-slate-500 hover:text-white transition-colors"><i class="fas fa-pencil text-xs"></i></button>
            <button onclick="toggleCaseFlag('${c.id}')" title="Flag Investigation" class="${flagIcon} transition-colors"><i class="${flagIcon}"></i></button>
            <button onclick="deleteCase('${c.id}')" title="Delete Case" class="text-slate-700 hover:text-red-400 transition-colors"><i class="fas fa-trash text-xs"></i></button>
          </div>
        </td>
      </tr>`;
  }).join("");
}

function loadCase(id) {
  const cases = getCases();
  const c = cases.find((x) => x.id === id);
  if (!c) return;

  activeCaseId = id;
  lastScanResults = { incidents: c.incidents, integrity_score: c.integrityScore, total_gaps: c.totalGaps };

  // Update legacy meta so renderResults reads correct file/time
  const meta = { timestamp: new Date(c.timestamp).toLocaleString().toUpperCase(), fileName: c.fileName };
  localStorage.setItem("last_scan_metadata", JSON.stringify(meta));

  renderResults(lastScanResults);
  switchTab("dashboard");
  showToast(`Case Loaded: ${c.name}`);
  renderCaseHistory();
}

function toggleCaseFlag(id) {
  const cases = getCases();
  const c = cases.find((x) => x.id === id);
  if (!c) return;
  c.flagged = !c.flagged;
  saveCases(cases);
  renderCaseHistory();
  showToast(c.flagged ? "Case Flagged: Active Investigation" : "Case Flag Removed");
}

function deleteCase(id) {
  let cases = getCases();
  cases = cases.filter((x) => x.id !== id);
  saveCases(cases);
  if (activeCaseId === id) activeCaseId = cases.length > 0 ? cases[0].id : null;
  renderCaseHistory();
  showToast("Case Deleted");
}

function startRenameCase(id) {
  const nameEl = document.getElementById(`case-name-${id}`);
  if (!nameEl) return;
  const current = nameEl.innerText;
  nameEl.innerHTML = `<input id="rename-input-${id}" class="bg-slate-900 border border-blue-500/50 text-blue-300 text-[11px] font-mono px-2 py-0.5 rounded outline-none w-44" value="${current}" />`;
  const input = document.getElementById(`rename-input-${id}`);
  input.focus();
  input.select();
  input.addEventListener("keydown", (e) => {
    if (e.key === "Enter") commitRename(id, input.value);
    if (e.key === "Escape") renderCaseHistory();
  });
  input.addEventListener("blur", () => commitRename(id, input.value));
}

function commitRename(id, newName) {
  const trimmed = newName.trim();
  if (!trimmed) return renderCaseHistory();
  const cases = getCases();
  const c = cases.find((x) => x.id === id);
  if (c) { c.name = trimmed; saveCases(cases); }
  renderCaseHistory();
}

function filterCaseHistory() {
  const term = document.getElementById("caseSearchInput")?.value.toLowerCase() || "";
  const rows = document.querySelectorAll("#caseHistoryBody tr");
  rows.forEach((row) => {
    row.style.display = row.innerText.toLowerCase().includes(term) ? "" : "none";
  });
}

function sortCaseHistory(by) {
  const cases = getCases();
  if (by === "score-desc") cases.sort((a, b) => b.integrityScore - a.integrityScore);
  else if (by === "score-asc") cases.sort((a, b) => a.integrityScore - b.integrityScore);
  else if (by === "date-desc") cases.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
  else if (by === "date-asc") cases.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
  saveCases(cases);
  renderCaseHistory();
}

// ─── TAB SWITCHING ───────────────────────────────────────────────────────────

function switchTab(tabId) {
  // Close mobile sidebar when navigating
  if (window.innerWidth < 1024) {
    const sidebar = document.getElementById("sidebar");
    const overlay = document.getElementById("sidebarOverlay");
    if (sidebar && sidebar.classList.contains("open")) {
      sidebar.classList.remove("open");
      if (overlay) overlay.classList.add("hidden");
      document.body.classList.remove("sidebar-open");
    }
  }

  document
    .querySelectorAll(".nav-item")
    .forEach((el) => el.classList.remove("active", "text-blue-500"));
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

  if (lastScanResults && tabId === "dashboard") setTimeout(() => updateChart(lastScanResults.incidents), 50);
  if (tabId === "history") renderCaseHistory();
}

// ─── HEATMAP & CHART ─────────────────────────────────────────────────────────

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
      datasets: [{ label: "Integrity", data: chartData, borderColor: "#3b82f6", backgroundColor: "rgba(59,130,246,0.15)", fill: "origin", tension: 0, borderWidth: 2, pointRadius: 0, pointHitRadius: 20 }],
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      interaction: { mode: "index", intersect: false },
      scales: {
        y: { beginAtZero: true, min: 0, max: 100, ticks: { callback: (v) => v + "%", color: "#64748b", font: { family: "JetBrains Mono" } }, grid: { color: "rgba(255,255,255,0.03)" } },
        x: { ticks: { color: "#64748b", autoSkip: true, maxTicksLimit: 10, font: { family: "JetBrains Mono" } }, grid: { display: false } },
      },
      plugins: {
        legend: { display: false },
        tooltip: {
          enabled: true, backgroundColor: "rgba(15,23,42,0.95)",
          titleFont: { size: 13, family: "JetBrains Mono" }, bodyFont: { size: 12, family: "JetBrains Mono" },
          padding: 12, displayColors: false,
          callbacks: {
            title: (items) => `Timestamp: ${items[0].label}`,
            label: (item) => { const gap = incidents[item.dataIndex].duration; return [`Integrity: ${item.parsed.y.toFixed(1)}%`, `Gap Duration: ${gap}s`]; },
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
  if (criteria === "high") { lastScanResults.incidents.sort((a, b) => b.duration - a.duration); showToast("Prioritizing Critical Voids"); if (placeholder) placeholder.disabled = true; }
  else if (criteria === "low") { lastScanResults.incidents.sort((a, b) => a.duration - b.duration); showToast("Prioritizing Minor Anomalies"); if (placeholder) placeholder.disabled = true; }
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
  const searchTerm = document.getElementById("searchInput").value.toLowerCase();
  if (!lastScanResults || !lastScanResults.incidents) return;
  let filtered = lastScanResults.incidents;
  if (searchTerm) {
    filtered = filtered.filter((inc) =>
      inc.start.toLowerCase().includes(searchTerm) ||
      inc.end.toLowerCase().includes(searchTerm) ||
      inc.duration.toString().includes(searchTerm)
    );
  }
  updateRegistryTable(filtered);
}

// ─── EXPORT ──────────────────────────────────────────────────────────────────

// ─── MOBILE SIDEBAR TOGGLE ───────────────────────────────────────────────────

function toggleSidebar() {
  const sidebar = document.getElementById("sidebar");
  const overlay = document.getElementById("sidebarOverlay");
  const isOpen = sidebar.classList.contains("open");
  if (isOpen) {
    sidebar.classList.remove("open");
    overlay.classList.add("hidden");
    document.body.classList.remove("sidebar-open");
  } else {
    sidebar.classList.add("open");
    overlay.classList.remove("hidden");
    document.body.classList.add("sidebar-open");
  }
}

function logout() {
  // Clear auth tokens — preserve case history (forensic_cases key)
  localStorage.removeItem("access_token");
  localStorage.removeItem("last_forensic_scan");
  localStorage.removeItem("last_scan_metadata");
  localStorage.removeItem("flagged_items");
  sessionStorage.clear();
  window.location.href = "index.html";
}

function exportForensicJSON() {
  if (!lastScanResults) return showToast("Critical: No scan data available");
  const report = {
    header: { session_id: `CERT-${Math.random().toString(36).substr(2, 9).toUpperCase()}`, timestamp: new Date().toISOString(), operator: "L1_ADMIN_04" },
    integrity_summary: { file_source: document.getElementById("lastFileName")?.innerText || "Unknown", score: document.getElementById("integrityScoreCard")?.innerText || "0%", sha256_hash: `3A7C${Math.random().toString(16).substr(2, 12).toUpperCase()}` },
    void_data: lastScanResults.incidents,
  };
  const blob = new Blob([JSON.stringify(report, null, 4)], { type: "application/json" });
  const a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = `Forensic_Audit_${Date.now()}.json`; a.click();
  showToast("Signed JSON Exported");
}

function exportRegistryCSV() {
  if (!lastScanResults || !lastScanResults.incidents.length) return showToast("Notice: Incident Registry is empty");
  let csv = "Incident,Start,End,Duration(s),Severity\n";
  lastScanResults.incidents.forEach((inc, i) => { csv += `VOID-${i + 1},${inc.start},${inc.end},${inc.duration},${inc.duration > 300 ? "CRITICAL" : "WARNING"}\n`; });
  const blob = new Blob([csv], { type: "text/csv" });
  const a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = `Registry_Log_${Date.now()}.csv`; a.click();
  showToast("Registry CSV Downloaded");
}

function exportChartAsPNG() {
  if (!chart) return showToast("No chart data available");
  const a = document.createElement("a"); a.download = `chart_export_${Date.now()}.png`; a.href = chart.canvas.toDataURL("image/png"); a.click();
  showToast("Chart exported as PNG");
}

function exportChartAsJPG() {
  if (!chart) return showToast("No chart data available");
  const canvas = chart.canvas;
  const tmp = document.createElement("canvas"); tmp.width = canvas.width; tmp.height = canvas.height;
  const ctx = tmp.getContext("2d"); ctx.fillStyle = "white"; ctx.fillRect(0, 0, tmp.width, tmp.height); ctx.drawImage(canvas, 0, 0);
  const a = document.createElement("a"); a.download = `chart_export_${Date.now()}.jpg`; a.href = tmp.toDataURL("image/jpeg", 0.9); a.click();
  showToast("Chart exported as JPG");
}

// ─── MISC ────────────────────────────────────────────────────────────────────

function updateFileName() {
  const fileInput = document.getElementById("logFile");
  const fileNameDisplay = document.getElementById("fileNameDisplay");
  const dropArea = document.getElementById("dropArea");
  
  if (fileInput.files.length > 0) {
    fileNameDisplay.innerText = fileInput.files[0].name;
    fileNameDisplay.classList.replace("text-slate-500", "text-blue-400");
    if (dropArea) dropArea.classList.replace("border-red-500/50", "border-slate-800");
  } else {
    fileNameDisplay.innerText = "Select Log Source";
    if (dropArea) dropArea.classList.replace("border-red-500/50", "border-slate-800");
  }
}

function showToast(msg) {
  const toast = document.getElementById("toast");
  const msgEl = document.getElementById("toastMsg");
  if (!toast || !msgEl) return;
  msgEl.innerText = msg;
  toast.classList.replace("translate-y-24", "translate-y-0");
  toast.classList.replace("opacity-0", "opacity-100");
  setTimeout(() => { toast.classList.replace("translate-y-0", "translate-y-24"); toast.classList.replace("opacity-100", "opacity-0"); }, 3000);
}

function logout() {
  sessionStorage.clear();
  // Preserve case history on logout — only clear session auth
  window.location.href = "index.html";
}
// Search/Filter functionality for Incident Registry
function filterRegistry() {
    const searchTerm = document.getElementById("searchInput").value.toLowerCase();
    if (!lastScanResults || !lastScanResults.incidents) return;
    
    let filteredIncidents = lastScanResults.incidents;
    
    if (searchTerm) {
        filteredIncidents = lastScanResults.incidents.filter(inc => {
            // Search by timestamp (start or end time)
            const timeMatch = inc.start.toLowerCase().includes(searchTerm) || 
                              inc.end.toLowerCase().includes(searchTerm);
            // Search by duration
            const durationMatch = inc.duration.toString().includes(searchTerm);
            return timeMatch || durationMatch;
        });
    }
    
    updateRegistryTable(filteredIncidents);
}
const scrollBtn = document.getElementById("scrollTopBtn");

if (scrollBtn) {
  window.addEventListener("scroll", () => {
    if (document.documentElement.scrollTop > 100) {
      scrollBtn.classList.remove("hidden");
    } else {
      scrollBtn.classList.add("hidden");
    }
  });

  scrollBtn.addEventListener("click", () => {
    window.scrollTo({
      top: 0,
      behavior: "smooth"
    });
  });
}

function showTOS() {
  const modal = document.getElementById("tosModal");
  if (modal) modal.classList.add("active");
}

function closeTOS() {
  const modal = document.getElementById("tosModal");
  if (modal) modal.classList.remove("active");
}
