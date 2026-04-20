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
    sessionStorage.removeItem("isLoggedIn");
    window.location.href = "index.html";
    return;
  }
  updateNavState();
};

// ─── NAV STATE ───────────────────────────────────────────────────────────────

function updateNavState() {
  const isLoggedIn = sessionStorage.getItem("isLoggedIn");
  const terminalLink = document.getElementById("terminalLink");
  const loginBtn = document.getElementById("loginBtnNav");
  const heroBtn = document.getElementById("heroActionBtn");

  if (isLoggedIn) {
    if (terminalLink) {
      terminalLink.classList.remove("hidden");
      terminalLink.setAttribute("onclick", "triggerTerminalTransition()");
    }
    if (loginBtn) {
      loginBtn.innerText = "LOGOUT";
      loginBtn.onclick = logout;
    }
    if (heroBtn) {
      heroBtn.innerText = "ENTER DASHBOARD";
      heroBtn.onclick = triggerTerminalTransition;
    }
  }
}

// ─── NAVIGATION ──────────────────────────────────────────────────────────────

function triggerTerminalTransition() {
  const loader = document.getElementById("terminalLoader");
  if (loader) {
    loader.style.display = "flex";
    const statusText = loader.querySelector(".status-text");
    setTimeout(() => { if (statusText) statusText.innerText = "Bypassing Firewall..."; }, 600);
    setTimeout(() => { if (statusText) statusText.innerText = "Synchronizing Forensic Buffers..."; }, 1200);
    setTimeout(() => { window.location.href = "dashboard.html"; }, 2000);
  } else {
    window.location.href = "dashboard.html";
  }
}

function handleHeroAction() {
  if (sessionStorage.getItem("isLoggedIn")) triggerTerminalTransition();
  else showLogin();
}

function logout() {
  sessionStorage.removeItem("isLoggedIn");
  window.location.href = "index.html";
}

// ─── LOGIN MODAL ─────────────────────────────────────────────────────────────

function showLogin() {
  const modal = document.getElementById("authModal");
  if (!modal) return;
  modal.classList.toggle("hidden");

  const userField = document.getElementById("loginUser");
  const passField = document.getElementById("loginPass");

  // Reset fields and validation styles on every open/close
  if (userField) { userField.value = ""; userField.classList.remove("border-red-500/50"); }
  if (passField) { passField.value = ""; passField.classList.remove("border-red-500/50"); }

  if (!modal.classList.contains("hidden") && userField) {
    userField.focus();
  }
}

function closeLogin() {
  const modal = document.getElementById("authModal");
  if (!modal) return;
  modal.classList.add("hidden");
  const userField = document.getElementById("loginUser");
  const passField = document.getElementById("loginPass");
  if (userField) userField.value = "";
  if (passField) passField.value = "";
}

// ─── LOGIN HANDLER ───────────────────────────────────────────────────────────

async function handleLogin() {
  const userField = document.getElementById("loginUser");
  const passField = document.getElementById("loginPass");
  const u = userField.value.trim();
  const p = passField.value.trim();

  // Validation
  if (!u || !p) {
    alert("ACCESS DENIED: Please fill in all credentials.");
    if (!u) userField.classList.add("border-red-500/50");
    if (!p) passField.classList.add("border-red-500/50");
    return;
  }

  userField.classList.remove("border-red-500/50");
  passField.classList.remove("border-red-500/50");

  const formData = new FormData();
  formData.append("username", u);
  formData.append("password", p);

  const loginBtn = document.querySelector("#loginView button");

  try {
    const res = await fetch("http://127.0.0.1:8000/login", {
      method: "POST",
      body: formData,
    });

    if (res.ok) {
      sessionStorage.setItem("isLoggedIn", "true");
      if (loginBtn) {
        loginBtn.innerText = "UPLINK ESTABLISHED";
        loginBtn.classList.replace("bg-blue-600", "bg-emerald-600");
      }
      updateNavState();
      setTimeout(() => { window.location.href = "dashboard.html"; }, 600);
    } else {
      alert("ACCESS DENIED: Invalid Credentials");
    }
  } catch (e) {
    alert("OFFLINE: Ensure Forensic Backend is running.");
  }
}

// ─── SINGLE DOMContentLoaded ─────────────────────────────────────────────────

document.addEventListener("DOMContentLoaded", () => {
  // Auto-clear validation styles on input
  ["loginUser", "loginPass"].forEach((id) => {
    const el = document.getElementById(id);
    if (el) el.addEventListener("input", () => el.classList.remove("border-red-500/50"));
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
    handleLogin();
  }

  if (e.key === "Escape") {
    closeLogin();
  }
});
