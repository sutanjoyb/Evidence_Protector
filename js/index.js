AOS.init({
  duration: 1000,
  easing: "ease-out-quad",
  once: false,
  mirror: true,
  anchorPlacement: "top-bottom",
});

window.onload = function () {
  const navEntries = performance.getEntriesByType("navigation");
  if (navEntries.length > 0 && navEntries[0].type === "reload") {
    localStorage.removeItem("access_token");
    window.location.href = "index.html";
    return;
  }
  updateNavState();
};

function isLoggedIn() {
  return !!localStorage.getItem("access_token");
}

function updateNavState() {
  const terminalLink = document.getElementById("terminalLink");
  const loginBtn = document.getElementById("loginBtnNav");
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
    if (heroBtn) {
      heroBtn.innerText = "ENTER DASHBOARD";
      heroBtn.onclick = triggerTerminalTransition;
    }
  }
}

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
  "Hashing Data Fragments..."
];

function getRandomPhrase(exclude = []) {
  const filtered = FORENSIC_PHRASES.filter(p => !exclude.includes(p));
  return filtered[Math.floor(Math.random() * filtered.length)];
}

function triggerTerminalTransition() {
  const loader = document.getElementById("terminalLoader");
  if (loader) {
    loader.style.display = "flex";
    const statusText = loader.querySelector(".status-text");

    const p1 = getRandomPhrase();
    const p2 = getRandomPhrase([p1]);

    setTimeout(() => {
      if (statusText) statusText.innerText = p1;
    }, 600);
    setTimeout(() => {
      if (statusText) statusText.innerText = p2;
    }, 1200);
    setTimeout(() => {
      window.location.href = "dashboard.html";
    }, 2000);
  } else {
    window.location.href = "dashboard.html";
  }
}

function handleHeroAction() {
  if (isLoggedIn()) triggerTerminalTransition();
  else showLogin();
}

function showLogin() {
  const modal = document.getElementById("authModal");
  if (modal) {
    modal.classList.toggle("hidden");
    const userField = document.getElementById("loginUser");
    const passField = document.getElementById("loginPass");
    userField.value = "";
    passField.value = "";
    userField.classList.remove("border-red-500/50");
    passField.classList.remove("border-red-500/50");
    if (!modal.classList.contains("hidden")) {
      userField.focus();
    }
  }
}

function closeLogin() {
  const modal = document.getElementById("authModal");
  if (modal) {
    modal.classList.add("hidden");
    document.getElementById("loginUser").value = "";
    document.getElementById("loginPass").value = "";
  }
}

function logout() {
  localStorage.removeItem("access_token");
  window.location.href = "index.html";
}

async function handleLogin() {
  const userField = document.getElementById("loginUser");
  const passField = document.getElementById("loginPass");
  const u = userField.value.trim();
  const p = passField.value.trim();

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
      const data = await res.json();
      localStorage.setItem("access_token", data.access_token);

      loginBtn.innerText = "UPLINK ESTABLISHED";
      loginBtn.classList.replace("bg-blue-600", "bg-emerald-600");

      updateNavState();

      setTimeout(() => {
        triggerTerminalTransition();
      }, 600);
    } else {
      alert("ACCESS DENIED: Invalid Credentials");
    }
  } catch (e) {
    alert("OFFLINE: Ensure Forensic Backend is running.");
  }
}

// Auto-clear red borders on input
document.addEventListener("DOMContentLoaded", () => {
  ["loginUser", "loginPass"].forEach((id) => {
    const el = document.getElementById(id);
    if (el) el.addEventListener("input", () => el.classList.remove("border-red-500/50"));
  });
});

// Keyboard controls
document.addEventListener("keydown", (event) => {
  const authModal = document.getElementById("authModal");
  const isModalVisible = authModal && !authModal.classList.contains("hidden");

  if (isModalVisible) {
    if (event.key === "Enter") {
      event.preventDefault();
      event.stopImmediatePropagation();
      handleLogin();
    }
    if (event.key === "Escape") {
      closeLogin();
    }
  }
});
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
