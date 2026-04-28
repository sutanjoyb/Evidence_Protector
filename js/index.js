// ─── AOS INIT ────────────────────────────────────────────────────────────────

AOS.init({
  duration: 1000,
  easing: "ease-out-quad",
  once: false,
  mirror: true,
  anchorPlacement: "top-bottom",
});

// ─── PAGE LOAD ───────────────────────────────────────────────────────────────

window.onload = function () {
  const navEntries = performance.getEntriesByType("navigation");
  if (navEntries.length > 0 && navEntries[0].type === "reload") {
    localStorage.removeItem("access_token");
    window.location.href = "index.html";
    return;
  }
  updateNavState();
};

// ─── NAV STATE ───────────────────────────────────────────────────────────────

function isLoggedIn() {
  return !!localStorage.getItem("access_token");
}

function updateNavState() {
  const terminalLink = document.getElementById("terminalLink");
  const loginBtn = document.getElementById("loginBtnNav");
  const signUpBtn = document.getElementById("signUpBtnNav");
  const heroBtn = document.getElementById("heroActionBtn");

  if (isLoggedIn()) {
    if (terminalLink) {
      terminalLink.classList.remove("hidden");
      terminalLink.setAttribute("onclick", "triggerTerminalTransition()");
    }
    if (loginBtn) {
      loginBtn.innerText = "LOGOUT";
      loginBtn.onclick = logout;
    }
    if (signUpBtn) signUpBtn.classList.add("hidden");
    if (heroBtn) {
      heroBtn.innerText = "ENTER DASHBOARD";
      heroBtn.onclick = triggerTerminalTransition;
    }
  } else {
    if (terminalLink) terminalLink.classList.add("hidden");
    if (loginBtn) {
      loginBtn.innerText = "LOGIN";
      loginBtn.onclick = () => { toggleAuthMode("login"); showLogin(); };
    }
    if (signUpBtn) signUpBtn.classList.remove("hidden");
    if (heroBtn) {
      heroBtn.innerText = "INITIALIZE SCAN";
      heroBtn.onclick = handleHeroAction;
    }
  }
}

// ─── NAVIGATION ──────────────────────────────────────────────────────────────

const FORENSIC_PHRASES = [
  "Decrypting packets...",
  "Analyzing deltas...",
  "Bypassing Firewall...",
  "Synchronizing Forensic Buffers...",
  "Extracting Metadata...",
  "Verifying Integrity...",
  "Mapping Temporal Voids...",
  "Detecting Anomalies...",
  "Scanning Hash Tables...",
  "Reconstructing Log Chains...",
  "Isolating Malicious Signatures...",
  "Tracing IP Origins...",
  "Validating Node Signatures...",
  "Hashing Data Fragments...",
];

function getRandomPhrase(exclude = []) {
  const filtered = FORENSIC_PHRASES.filter((p) => !exclude.includes(p));
  return filtered[Math.floor(Math.random() * filtered.length)];
}

function triggerTerminalTransition() {
  const loader = document.getElementById("terminalLoader");
  if (loader) {
    loader.style.display = "flex";
    const statusText = loader.querySelector(".status-text");
    const p1 = getRandomPhrase();
    const p2 = getRandomPhrase([p1]);
    setTimeout(() => { if (statusText) statusText.innerText = p1; }, 600);
    setTimeout(() => { if (statusText) statusText.innerText = p2; }, 1200);
    setTimeout(() => { window.location.href = "dashboard.html"; }, 2000);
  } else {
    window.location.href = "dashboard.html";
  }
}

function handleHeroAction() {
  if (isLoggedIn()) triggerTerminalTransition();
  else showLogin();
}

function logout() {
  localStorage.removeItem("access_token");
  window.location.href = "index.html";
}

// ─── AUTH MODAL ──────────────────────────────────────────────────────────────

function showLogin() {
  const modal = document.getElementById("authModal");
  if (!modal) return;
  modal.classList.toggle("hidden");

  const userField = document.getElementById("loginUser");
  const passField = document.getElementById("loginPass");
  if (userField) { userField.value = ""; userField.classList.remove("border-red-500/50"); }
  if (passField) { passField.value = ""; passField.classList.remove("border-red-500/50"); }

  if (!modal.classList.contains("hidden") && userField) userField.focus();
}

function closeLogin() {
  const modal = document.getElementById("authModal");
  if (!modal) return;
  modal.classList.add("hidden");

  const loginView = document.getElementById("loginView");
  const registerView = document.getElementById("registerView");
  if (loginView) loginView.classList.remove("hidden");
  if (registerView) registerView.classList.add("hidden");

  ["loginUser", "loginPass", "regUser", "regPass"].forEach((id) => {
    const el = document.getElementById(id);
    if (el) { el.value = ""; el.classList.remove("border-red-500/50", "border-emerald-500/50"); }
  });
}

function toggleAuthMode(mode) {
  const loginView = document.getElementById("loginView");
  const registerView = document.getElementById("registerView");
  if (mode === "register") {
    if (loginView) loginView.classList.add("hidden");
    if (registerView) registerView.classList.remove("hidden");
    const regUser = document.getElementById("regUser");
    if (regUser) regUser.focus();
  } else {
    if (registerView) registerView.classList.add("hidden");
    if (loginView) loginView.classList.remove("hidden");
    const loginUser = document.getElementById("loginUser");
    if (loginUser) loginUser.focus();
  }
}

// ─── LOGIN HANDLER ───────────────────────────────────────────────────────────

async function handleLogin() {
  const userField = document.getElementById("loginUser");
  const passField = document.getElementById("loginPass");
  const u = userField.value.trim();
  const p = passField.value.trim();

  if (!u || !p) {
    if (!u) userField.classList.add("border-red-500/50");
    if (!p) passField.classList.add("border-red-500/50");
    showToast("Access Denied: Empty Credentials");
    return;
  }

  userField.classList.remove("border-red-500/50");
  passField.classList.remove("border-red-500/50");

  const formData = new FormData();
  formData.append("username", u);
  formData.append("password", p);

  const loginBtn = document.querySelector("#loginView button#authBtn");

  try {
    const res = await fetch("http://127.0.0.1:8000/login", {
      method: "POST",
      body: formData,
    });

    if (res.ok) {
      const data = await res.json();
      localStorage.setItem("access_token", data.access_token);
      if (loginBtn) {
        loginBtn.innerText = "UPLINK ESTABLISHED";
        loginBtn.classList.replace("bg-blue-600", "bg-emerald-600");
      }
      updateNavState();
      setTimeout(() => { triggerTerminalTransition(); }, 600);
    } else {
      showToast("Access Denied: Invalid Credentials");
    }
  } catch (e) {
    showToast("Offline: Check Forensic Backend");
  }
}

// ─── REGISTER HANDLER ────────────────────────────────────────────────────────

async function handleRegister() {
  const userField = document.getElementById("regUser");
  const passField = document.getElementById("regPass");
  const u = userField.value.trim();
  const p = passField.value.trim();

  if (!u || !p) {
    if (!u) userField.classList.add("border-red-500/50");
    if (!p) passField.classList.add("border-red-500/50");
    showToast("Registration Failed: Empty Fields");
    return;
  }

  const formData = new FormData();
  formData.append("username", u);
  formData.append("password", p);

  const regBtn = document.getElementById("regBtn");

  try {
    const res = await fetch("http://127.0.0.1:8000/register", {
      method: "POST",
      body: formData,
    });
    const data = await res.json();

    if (res.ok) {
      localStorage.setItem("access_token", data.access_token);
      if (regBtn) {
        regBtn.innerText = "UPLINK ESTABLISHED";
        regBtn.classList.replace("bg-emerald-600", "bg-blue-600");
      }
      showToast("Registration Successful");
      updateNavState();
      setTimeout(() => { triggerTerminalTransition(); }, 1000);
    } else {
      showToast(`Error: ${data.detail || "Registration Failed"}`);
    }
  } catch (e) {
    showToast("Offline: Check Forensic Backend");
  }
}

// ─── TOAST ───────────────────────────────────────────────────────────────────

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

// ─── TOS MODAL ───────────────────────────────────────────────────────────────

function showTOS() {
  const modal = document.getElementById("tosModal");
  if (modal) modal.classList.add("active");
}

function closeTOS() {
  const modal = document.getElementById("tosModal");
  if (modal) modal.classList.remove("active");
}

// ─── SINGLE DOMContentLoaded ─────────────────────────────────────────────────

document.addEventListener("DOMContentLoaded", () => {
  ["loginUser", "loginPass", "regUser", "regPass"].forEach((id) => {
    const el = document.getElementById(id);
    if (el) el.addEventListener("input", () => el.classList.remove("border-red-500/50", "border-emerald-500/50"));
  });
});

// ─── SINGLE KEYBOARD HANDLER ─────────────────────────────────────────────────

document.addEventListener("keydown", (e) => {
  const modal = document.getElementById("authModal");
  const isVisible = modal && !modal.classList.contains("hidden");
  if (!isVisible) return;

  if (e.key === "Enter") {
    e.preventDefault();
    e.stopImmediatePropagation();
    const isLoginView = document.getElementById("loginView") &&
      !document.getElementById("loginView").classList.contains("hidden");
    if (isLoginView) handleLogin();
    else handleRegister();
  }

  if (e.key === "Escape") closeLogin();
});

// ─── REACTIVE SCROLL TO TOP ───────────────────────────────────────────────────
// Enhanced: fade+slide in/out · scroll progress ring · smooth scroll
// Threshold: 300px (was 100px — gives user time to read before showing)

(function initScrollToTop() {
  const btn = document.getElementById("scrollTopBtn");
  const ring = document.getElementById("scrollProgressRing");
  if (!btn) return;

  // Ring circumference for r=20 circle: 2 * π * 20 ≈ 125.66
  const CIRCUMFERENCE = 125.66;
  const SHOW_THRESHOLD = 300; // px scrolled before button appears

  function updateScrollBtn() {
    const scrollTop = document.documentElement.scrollTop || document.body.scrollTop;
    const docHeight = document.documentElement.scrollHeight - document.documentElement.clientHeight;
    const scrollPct = docHeight > 0 ? scrollTop / docHeight : 0;

    // Show / hide with .visible class (CSS handles fade + slide)
    if (scrollTop > SHOW_THRESHOLD) {
      btn.classList.add("visible");
    } else {
      btn.classList.remove("visible");
    }

    // Update progress ring
    if (ring) {
      const offset = CIRCUMFERENCE - scrollPct * CIRCUMFERENCE;
      ring.style.strokeDashoffset = offset;
    }
  }

  // Passive listener for performance
  window.addEventListener("scroll", updateScrollBtn, { passive: true });

  // Click — smooth scroll to top
  btn.addEventListener("click", () => {
    window.scrollTo({ top: 0, behavior: "smooth" });
  });

  // Run once on load in case page is already scrolled
  updateScrollBtn();
})();