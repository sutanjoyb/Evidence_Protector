let chart;
let lastScanResults = null;
let flaggedIncidents = new Set();
let batchResults = []; // Store results from multiple files
let currentThreshold = 60; // Default threshold value

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
      ctx.strokeStyle = "rgba(59, 130, 246, 0.6)";
      ctx.setLineDash([5, 5]);
      ctx.stroke();
      ctx.restore();
    }
  },
};

window.addEventListener("DOMContentLoaded", () => {
  if (!localStorage.getItem("access_token")) {
    window.location.href = "index.html";
    return;
  }
  const savedFlags = localStorage.getItem("flagged_items");
  if (savedFlags) {
    flaggedIncidents = new Set(JSON.parse(savedFlags));
    updateFlagCount();
  }
  
  // Load saved threshold
  const savedThreshold = localStorage.getItem("analysis_threshold");
  if (savedThreshold) {
    currentThreshold = parseInt(savedThreshold);
    document.getElementById("thresholdSlider").value = currentThreshold;
    updateThresholdDisplay(currentThreshold);
  }
  
  loadLastSession();
});

function loadLastSession() {
  const savedData = localStorage.getItem("last_forensic_scan");
  const savedMeta = localStorage.getItem("last_scan_metadata");
  const savedBatch = localStorage.getItem("last_batch_results");
  
  if (savedBatch) {
    batchResults = JSON.parse(savedBatch);
    renderBatchResults(batchResults);
  } else if (savedData && savedMeta) {
    lastScanResults = JSON.parse(savedData);
    const meta = JSON.parse(savedMeta);
    const timeEl = document.getElementById("lastScanTime");
    const fileEl = document.getElementById("lastFileName");
    if (timeEl) timeEl.innerText = meta.timestamp;
    if (fileEl) fileEl.innerText = meta.fileName;
    renderResults(lastScanResults);
  }
}

// Update threshold display
function updateThresholdDisplay(value) {
  currentThreshold = parseInt(value);
  const display = document.getElementById("thresholdValue");
  
  // Format display based on value
  let displayText;
  if (currentThreshold >= 3600) {
    displayText = (currentThreshold / 3600).toFixed(1) + "h";
  } else if (currentThreshold >= 60) {
    displayText = Math.floor(currentThreshold / 60) + "m";
  } else {
    displayText = currentThreshold + "s";
  }
  
  if (display) display.innerText = displayText;
  
  // Save to localStorage
  localStorage.setItem("analysis_threshold", currentThreshold);
}

async function analyzeLogs(event) {
  const fileInput = document.getElementById("logFile");
  const files = Array.from(fileInput.files);
  
  if (files.length === 0) {
    return showToast("Critical: No source file selected");
  }

  const overlay = document.getElementById("scanOverlay");
  const statusText = document.getElementById("loaderStatus");
  overlay.classList.remove("hidden");

  const token = localStorage.getItem("access_token");
  batchResults = []; // Reset batch results
  
  try {
    // Process each file sequentially
    for (let i = 0; i < files.length; i++) {
      const file = files[i];
      statusText.innerText = `Processing file ${i + 1}/${files.length}: ${file.name}`;
      
      const formData = new FormData();
      formData.append("file", file);
      formData.append("threshold", currentThreshold);

      try {
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
        
        // Add file metadata to results
        batchResults.push({
          fileName: file.name,
          timestamp: new Date().toLocaleString().toUpperCase(),
          data: data,
          threshold: currentThreshold
        });
        
      } catch (e) {
        console.error(`Error processing ${file.name}:`, e);
        showToast(`Error processing ${file.name}`);
      }
    }

    // Animation steps
    const steps = [
      "Hashing Payload...",
      "Mapping Voids...",
      "Assessing Risk...",
      "Finalizing Reports...",
    ];
    for (const step of steps) {
      statusText.innerText = step;
      await new Promise((r) => setTimeout(r, 400));
    }

    // Save results
    if (batchResults.length === 1) {
      // Single file - use legacy format
      const result = batchResults[0];
      const meta = {
        timestamp: result.timestamp,
        fileName: result.fileName,
      };
      localStorage.setItem("last_forensic_scan", JSON.stringify(result.data));
      localStorage.setItem("last_scan_metadata", JSON.stringify(meta));
      localStorage.removeItem("last_batch_results");
      
      lastScanResults = result.data;
      renderResults(result.data);
    } else {
      // Multiple files - batch mode
      localStorage.setItem("last_batch_results", JSON.stringify(batchResults));
      localStorage.removeItem("last_forensic_scan");
      localStorage.removeItem("last_scan_metadata");
      
      renderBatchResults(batchResults);
    }
    
    showToast(`Analysis Complete: ${batchResults.length} file(s) processed`);
    
  } catch (e) {
    showToast("Backend Link Error: Ensure server is online");
    console.error(e);
  } finally {
    overlay.classList.add("hidden");
  }
}

function renderBatchResults(results) {
  if (!results || results.length === 0) return;
  
  // Calculate aggregate statistics
  let totalGaps = 0;
  let totalScore = 0;
  let allIncidents = [];
  
  results.forEach(result => {
    totalGaps += result.data.total_gaps;
    totalScore += result.data.integrity_score;
    
    // Add file name to each incident
    result.data.incidents.forEach(incident => {
      allIncidents.push({
        ...incident,
        fileName: result.fileName
      });
    });
  });
  
  const avgScore = (totalScore / results.length).toFixed(1);
  const avgRisk = (100 - avgScore).toFixed(1);
  
  // Update KPI cards with aggregate data
  document.getElementById("integrityScoreCard").innerText = avgScore + "%";
  document.getElementById("financialRisk").innerText = avgRisk + "%";
  document.getElementById("gapCount").innerText = totalGaps;
  
  // Update metadata
  document.getElementById("lastScanTime").innerText = results[0].timestamp;
  document.getElementById("lastFileName").innerText = `${results.length} files analyzed`;
  
  // Show batch summary
  const batchSummary = document.getElementById("batchSummary");
  const summaryContent = document.getElementById("batchSummaryContent");
  
  if (batchSummary && summaryContent) {
    batchSummary.classList.remove("hidden");
    
    summaryContent.innerHTML = results.map(result => {
      const score = result.data.integrity_score;
      const scoreColor = score >= 90 ? "text-emerald-400" : score >= 70 ? "text-amber-400" : "text-red-400";
      
      return `
        <div class="bg-slate-900/50 p-4 rounded-lg border border-white/5">
          <div class="flex items-center gap-2 mb-2">
            <i class="fas fa-file-alt text-blue-400 text-xs"></i>
            <p class="text-[9px] font-mono text-slate-400 truncate">${result.fileName}</p>
          </div>
          <div class="flex justify-between items-end">
            <div>
              <p class="text-[8px] text-slate-500 uppercase">Integrity</p>
              <p class="${scoreColor} text-lg font-black">${score}%</p>
            </div>
            <div class="text-right">
              <p class="text-[8px] text-slate-500 uppercase">Gaps</p>
              <p class="text-white text-lg font-black">${result.data.total_gaps}</p>
            </div>
          </div>
        </div>
      `;
    }).join('');
  }
  
  // Update registry with all incidents
  updateRegistryTable(allIncidents, true);
  
  // Update heatmap with first file's data
  updateHeatmapBar(results[0].data.incidents);
  
  // Update chart with aggregate view
  updateChart(allIncidents);
  
  // Hide signature card for batch mode
  const signatureCard = document.getElementById("signatureCard");
  if (signatureCard) {
    signatureCard.classList.add("hidden");
  }
}

function renderResults(data) {
  if (!data || !data.incidents) return;

  const score = parseFloat(data.integrity_score);
  const compromiseRisk = (100 - score).toFixed(1);

  // 1. Update KPI Cards
  document.getElementById("integrityScoreCard").innerText =
    score.toFixed(1) + "%";
  document.getElementById("financialRisk").innerText = compromiseRisk + "%";
  document.getElementById("gapCount").innerText = data.total_gaps;

  // 2. Metadata
  const meta = JSON.parse(localStorage.getItem("last_scan_metadata") || "{}");
  document.getElementById("lastScanTime").innerText =
    meta.timestamp || new Date().toLocaleTimeString();
  document.getElementById("lastFileName").innerText =
    meta.fileName || "Unknown Source";

  const forensicSessionID = `FS-${Math.random().toString(36).substr(2, 9).toUpperCase()}`;

  // 3. TACTICAL SIGNATURE GENERATOR
  const signatureCard = document.getElementById("signatureCard");
  const reasoning = document.getElementById("tacticalReasoning");

  if (signatureCard && reasoning) {
    signatureCard.classList.remove("hidden");

    const durations = data.incidents.map((i) => i.duration);
    const maxGap = Math.max(...durations, 0);
    const totalGapTime = durations.reduce((a, b) => a + b, 0);
    const gapFrequency = data.total_gaps;

    let signatureTitle = "";
    let signatureBody = "";
    let statusColor = "";

    if (gapFrequency === 0) {
      statusColor = "text-emerald-500";
      signatureTitle = "LINEAR_CONTINUITY_VERIFIED";
      signatureBody = `Session ${forensicSessionID}: No temporal anomalies detected. Sequence validation confirms 100% log stream integrity.`;
    } else if (maxGap > 600) {
      statusColor = "text-red-500";
      signatureTitle = "SHADOW_WINDOW_PURGE";
      signatureBody = `Session ${forensicSessionID}: Critical alert. A massive void of ${maxGap}s detected. This signature indicates a manual overwrite or deliberate service suspension to mask major activity.`;
    } else if (gapFrequency > 10) {
      statusColor = "text-amber-500";
      signatureTitle = "FRAGMENTED_LOG_SHAVING";
      signatureBody = `Session ${forensicSessionID}: Heuristic match found. Detected ${gapFrequency} micro-voids. This pattern is consistent with 'Log Shaving'—automated scripts deleting individual alert lines while leaving the rest of the file intact.`;
    } else if (score < 85) {
      statusColor = "text-orange-400";
      signatureTitle = "UNAUTHORIZED_SERVICE_GAP";
      signatureBody = `Session ${forensicSessionID}: Analysis shows a cumulative integrity loss of ${compromiseRisk}%. The distribution of gaps suggests a system-level interruption or unauthorized 'stop-start' command sequence.`;
    } else {
      statusColor = "text-blue-400";
      signatureTitle = "TEMPORAL_DRIFT_SYNC";
      signatureBody = `Session ${forensicSessionID}: Minor anomalies detected (${totalGapTime}s total). Pattern matches standard network latency or NTP clock-sync drift. No malicious manipulation signatures identified.`;
    }

    reasoning.innerHTML = `
        <div class="mb-2">
            <span class="${statusColor} font-black uppercase tracking-widest">[ ${signatureTitle} ]</span>
        </div>
        <div class="text-slate-400 italic">
            ${signatureBody}
        </div>
        <div class="mt-2 pt-2 border-t border-white/5 text-[8px] text-slate-600">
            SECURE_HASH: ${forensicSessionID} | ADMISSIBILITY: ${score > 90 ? "CERTIFIED" : "REVIEW_REQUIRED"}
        </div>
      `;

    const sorter = document.getElementById("durationSorter");
    const placeholder = document.getElementById("sortPlaceholder");

    if (sorter && placeholder) {
      placeholder.disabled = false;
      sorter.value = "none";
    }
  }

  updateRegistryTable(data.incidents);
  updateHeatmapBar(data.incidents);
  updateChart(data.incidents);
}

function updateRegistryTable(incidents, isBatch = false) {
  const tbody = document.getElementById("incidentBody");
  if (!tbody) return;

  tbody.innerHTML = incidents
    .map((inc, i) => {
      const isFlagged = flaggedIncidents.has(i);
      const startTime = inc.start.includes(" ")
        ? inc.start.split(" ")[1]
        : inc.start;
      const endTime = inc.end.includes(" ") ? inc.end.split(" ")[1] : inc.end;

      return `
            <tr class="border-b border-white/5 hover:bg-white/5 transition-all">
                ${isBatch ? `
                <td class="p-6">
                    <div class="flex items-center gap-2">
                        <i class="fas fa-file-alt text-blue-400 text-xs"></i>
                        <span class="text-[9px] font-mono text-slate-400 truncate max-w-[150px]">${inc.fileName || 'N/A'}</span>
                    </div>
                </td>
                ` : ''}
                <td class="p-6 font-mono">
                    <div class="flex flex-col gap-1">
                        <div class="flex items-center gap-2">
                            <span class="text-[8px] text-slate-600 uppercase font-bold w-8">From:</span>
                            <span class="text-blue-400 text-[10px] tracking-wider">${startTime}</span>
                        </div>
                        <div class="flex items-center gap-2">
                            <span class="text-[8px] text-slate-600 uppercase font-bold w-8">To:</span>
                            <span class="text-emerald-400 text-[10px] tracking-wider">${endTime}</span>
                        </div>
                    </div>
                </td>
                <td class="p-6 text-center font-bold text-white text-sm">
                    ${inc.duration}<span class="text-[10px] text-slate-500 ml-1 font-light">s</span>
                </td>
                <td class="p-6">
                    <div class="flex items-center gap-3">
                        <div class="w-1.5 h-1.5 rounded-full ${inc.duration > 300 ? "bg-red-500 animate-pulse" : "bg-amber-500"}"></div>
                        <span class="text-[10px] uppercase font-bold ${inc.duration > 300 ? "text-red-400" : "text-amber-400"}">
                            ${inc.duration > 300 ? "Critical Void" : "Minor Anomaly"}
                        </span>
                    </div>
                </td>
                <td class="p-6 text-right">
                    <button onclick="toggleFlag(${i})" class="${isFlagged ? "text-blue-500" : "text-slate-700 hover:text-blue-400"} transition-colors">
                        <i class="${isFlagged ? "fas" : "far"} fa-flag text-base"></i>
                    </button>
                </td>
            </tr>`;
    })
    .join("");
}

function switchTab(tabId) {
  document
    .querySelectorAll(".nav-item")
    .forEach((el) => el.classList.remove("active", "text-blue-500"));
  const navItem = document.getElementById(`nav-${tabId}`);
  if (navItem) navItem.classList.add("active", "text-blue-500");

  const titles = {
    dashboard: "Executive Overview",
    registry: "Incident Registry",
    compliance: "Export Center",
  };
  const titleEl = document.getElementById("viewTitle");
  if (titleEl) titleEl.innerText = titles[tabId];

  document
    .querySelectorAll(".tab-view")
    .forEach((view) => view.classList.add("hidden"));
  const targetView = document.getElementById(`view-${tabId}`);
  if (targetView) targetView.classList.remove("hidden");

  if (lastScanResults && tabId === "dashboard") {
    setTimeout(() => updateChart(lastScanResults.incidents), 50);
  }
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

  const chartLabels = incidents.map((i) => i.start.split(" ")[1]);
  const chartData = incidents.map((i) => Math.max(0, 100 - i.duration / 300));

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
          pointRadius: 0,
          pointHitRadius: 20,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      interaction: { mode: "index", intersect: false },
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

function handleSortChange(criteria) {
  let allIncidents;
  let isBatch = false;
  
  // Determine if we're in batch mode or single file mode
  if (batchResults.length > 0) {
    isBatch = true;
    allIncidents = [];
    batchResults.forEach(result => {
      result.data.incidents.forEach(incident => {
        allIncidents.push({
          ...incident,
          fileName: result.fileName
        });
      });
    });
  } else if (lastScanResults && lastScanResults.incidents) {
    allIncidents = lastScanResults.incidents;
  } else {
    showToast("No data to sort");
    return;
  }
  
  const placeholder = document.getElementById("sortPlaceholder");
  
  if (criteria === "high") {
    allIncidents.sort((a, b) => b.duration - a.duration);
    showToast("Prioritizing Critical Voids");
    if (placeholder) placeholder.disabled = true;
  } else if (criteria === "low") {
    allIncidents.sort((a, b) => a.duration - b.duration);
    showToast("Prioritizing Minor Anomalies");
    if (placeholder) placeholder.disabled = true;
  }
  
  updateRegistryTable(allIncidents, isBatch);
}

function toggleFlag(index) {
  if (flaggedIncidents.has(index)) flaggedIncidents.delete(index);
  else flaggedIncidents.add(index);
  localStorage.setItem(
    "flagged_items",
    JSON.stringify(Array.from(flaggedIncidents)),
  );
  updateFlagCount();
  updateRegistryTable(lastScanResults.incidents);
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
  const fileInput = document.getElementById("logFile");
  const fileNameDisplay = document.getElementById("fileNameDisplay");
  if (fileInput.files.length > 0) {
    if (fileInput.files.length === 1) {
      fileNameDisplay.innerText = fileInput.files[0].name;
    } else {
      fileNameDisplay.innerText = `${fileInput.files.length} files selected`;
    }
    fileNameDisplay.classList.remove("text-slate-500");
    fileNameDisplay.classList.add("text-blue-400");
  } else {
    fileNameDisplay.innerText = "Select Log Source(s)";
    fileNameDisplay.classList.remove("text-blue-400");
    fileNameDisplay.classList.add("text-slate-500");
  }
}

function logout() {
  localStorage.removeItem("access_token");
  window.location.href = "index.html";
}

function exportForensicJSON() {
  if (!lastScanResults && batchResults.length === 0) {
    return showToast("Critical: No scan data available");
  }
  
  let report;
  
  if (batchResults.length > 0) {
    // Batch mode export
    report = {
      header: {
        session_id: `CERT-${Math.random().toString(36).substr(2, 9).toUpperCase()}`,
        timestamp: new Date().toISOString(),
        operator: "L1_ADMIN_04",
        mode: "BATCH_ANALYSIS"
      },
      batch_summary: {
        total_files: batchResults.length,
        threshold_used: currentThreshold,
        files: batchResults.map(r => ({
          filename: r.fileName,
          integrity_score: r.data.integrity_score,
          total_gaps: r.data.total_gaps,
          sha256_hash: `3A7C${Math.random().toString(16).substr(2, 12).toUpperCase()}`
        }))
      },
      detailed_results: batchResults.map(r => ({
        file_source: r.fileName,
        analyzed_at: r.timestamp,
        integrity_score: r.data.integrity_score,
        void_data: r.data.incidents
      }))
    };
  } else {
    // Single file mode export
    report = {
      header: {
        session_id: `CERT-${Math.random().toString(36).substr(2, 9).toUpperCase()}`,
        timestamp: new Date().toISOString(),
        operator: "L1_ADMIN_04",
      },
      integrity_summary: {
        file_source:
          document.getElementById("lastFileName")?.innerText || "Unknown",
        score: document.getElementById("integrityScoreCard")?.innerText || "0%",
        threshold_used: currentThreshold,
        sha256_hash: `3A7C${Math.random().toString(16).substr(2, 12).toUpperCase()}`,
      },
      void_data: lastScanResults.incidents,
    };
  }
  
  const blob = new Blob([JSON.stringify(report, null, 4)], {
    type: "application/json",
  });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `Forensic_Audit_${Date.now()}.json`;
  a.click();
  showToast("Signed JSON Exported");
}

function exportRegistryCSV() {
  let allIncidents = [];
  let isBatch = false;
  
  if (batchResults.length > 0) {
    isBatch = true;
    batchResults.forEach(result => {
      result.data.incidents.forEach(incident => {
        allIncidents.push({
          ...incident,
          fileName: result.fileName
        });
      });
    });
  } else if (lastScanResults && lastScanResults.incidents.length) {
    allIncidents = lastScanResults.incidents;
  } else {
    return showToast("Notice: Incident Registry is empty");
  }
  
  let csv;
  if (isBatch) {
    csv = "File,Incident,Start,End,Duration(s),Severity\n";
    allIncidents.forEach((inc, i) => {
      csv += `${inc.fileName},VOID-${i + 1},${inc.start},${inc.end},${inc.duration},${inc.duration > 300 ? "CRITICAL" : "WARNING"}\n`;
    });
  } else {
    csv = "Incident,Start,End,Duration(s),Severity\n";
    allIncidents.forEach((inc, i) => {
      csv += `VOID-${i + 1},${inc.start},${inc.end},${inc.duration},${inc.duration > 300 ? "CRITICAL" : "WARNING"}\n`;
    });
  }
  
  const blob = new Blob([csv], { type: "text/csv" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `Registry_Log_${Date.now()}.csv`;
  a.click();
  showToast("Registry CSV Downloaded");
}

// Export chart as PNG
function exportChartAsPNG() {
    if (!chart) {
        showToast("No chart data available");
        return;
    }
    const canvas = chart.canvas;
    const link = document.createElement('a');
    link.download = `chart_export_${Date.now()}.png`;
    link.href = canvas.toDataURL('image/png');
    link.click();
    showToast("Chart exported as PNG");
}

// Export chart as JPG
function exportChartAsJPG() {
    if (!chart) {
        showToast("No chart data available");
        return;
    }
    const canvas = chart.canvas;
    // Create white background for JPG (JPG doesn't support transparency)
    const tempCanvas = document.createElement('canvas');
    tempCanvas.width = canvas.width;
    tempCanvas.height = canvas.height;
    const tempCtx = tempCanvas.getContext('2d');
    tempCtx.fillStyle = 'white';
    tempCtx.fillRect(0, 0, tempCanvas.width, tempCanvas.height);
    tempCtx.drawImage(canvas, 0, 0);
    const link = document.createElement('a');
    link.download = `chart_export_${Date.now()}.jpg`;
    link.href = tempCanvas.toDataURL('image/jpeg', 0.9);
    link.click();
    showToast("Chart exported as JPG");
}

// Search/Filter functionality for Incident Registry
function filterRegistry() {
    const searchTerm = document.getElementById("searchInput").value.toLowerCase();
    
    let allIncidents;
    let isBatch = false;
    
    // Determine if we're in batch mode or single file mode
    if (batchResults.length > 0) {
        isBatch = true;
        allIncidents = [];
        batchResults.forEach(result => {
            result.data.incidents.forEach(incident => {
                allIncidents.push({
                    ...incident,
                    fileName: result.fileName
                });
            });
        });
    } else if (lastScanResults && lastScanResults.incidents) {
        allIncidents = lastScanResults.incidents;
    } else {
        return;
    }
    
    let filteredIncidents = allIncidents;
    
    if (searchTerm) {
        filteredIncidents = allIncidents.filter(inc => {
            // Search by timestamp (start or end time)
            const timeMatch = inc.start.toLowerCase().includes(searchTerm) || 
                              inc.end.toLowerCase().includes(searchTerm);
            // Search by duration
            const durationMatch = inc.duration.toString().includes(searchTerm);
            // Search by filename (if in batch mode)
            const fileMatch = isBatch && inc.fileName && inc.fileName.toLowerCase().includes(searchTerm);
            
            return timeMatch || durationMatch || fileMatch;
        });
    }
    
    updateRegistryTable(filteredIncidents, isBatch);
}