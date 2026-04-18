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
    sessionStorage.removeItem("isLoggedIn");
    window.location.href = "index.html";
    return;
  }
  updateNavState();
};

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

function triggerTerminalTransition() {
  const loader = document.getElementById("terminalLoader");
  if (loader) {
    loader.style.display = "flex";
    const statusText = loader.querySelector(".status-text");
    setTimeout(() => {
      if (statusText) statusText.innerText = "Bypassing Firewall...";
    }, 600);
    setTimeout(() => {
      if (statusText)
        statusText.innerText = "Synchronizing Forensic Buffers...";
    }, 1200);
    setTimeout(() => {
      window.location.href = "dashboard.html";
    }, 2000);
  } else {
    window.location.href = "dashboard.html";
  }
}

function handleHeroAction() {
  if (sessionStorage.getItem("isLoggedIn")) triggerTerminalTransition();
  else showLogin();
}

function showLogin() {
  document.getElementById("authModal").classList.toggle("hidden");
}
function logout() {
  sessionStorage.removeItem("isLoggedIn");
  window.location.href = "index.html";
}

/**
 * Main Login Handler with Validation & Backend Uplink
 */
/**
 * Main Login Handler with Conditional Red Boundaries
 */
/**
 * Main Login Handler
 */
async function handleLogin() {
  const userField = document.getElementById("loginUser");
  const passField = document.getElementById("loginPass");
  const u = userField.value.trim();
  const p = passField.value.trim();

  // 1. VALIDATION: Check for empty fields
  if (!u || !p) {
    // One alert only
    alert("ACCESS DENIED: Please fill in all credentials.");

    if (!u) userField.classList.add("border-red-500/50");
    if (!p) passField.classList.add("border-red-500/50");
    return;
  }

  // Clear red styling if valid
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
      loginBtn.innerText = "UPLINK ESTABLISHED";
      loginBtn.classList.replace("bg-blue-600", "bg-emerald-600");

      if (typeof updateNavState === "function") updateNavState();

      setTimeout(() => {
        window.location.href = "dashboard.html";
      }, 600);
    } else {
      alert("ACCESS DENIED: Invalid Credentials");
    }
  } catch (e) {
    alert("OFFLINE: Ensure Forensic Backend is running.");
  }
}

/**
 * KEYBOARD CONTROLS
 */
document.addEventListener("keydown", (event) => {
  const authModal = document.getElementById("authModal");
  const isModalVisible = authModal && !authModal.classList.contains("hidden");

  if (isModalVisible) {
    if (event.key === "Enter") {
      // This prevents the event from bubbling up and firing twice
      event.preventDefault();
      event.stopImmediatePropagation();
      handleLogin();
    }

    if (event.key === "Escape") {
      showLogin();
    }
  }
});

/**
 * AUTO-CLEAN RED BOUNDARY
 */
document.addEventListener("DOMContentLoaded", () => {
  const fields = ["loginUser", "loginPass"];
  fields.forEach((id) => {
    const el = document.getElementById(id);
    if (el) {
      el.addEventListener("input", () => {
        el.classList.remove("border-red-500/50");
      });
    }
  });
});

/**
 * UTILITY: Modal Toggle
 */
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

/**
 * AUTO-CLEAN: Remove red boundary when user starts typing
 */
document.addEventListener("DOMContentLoaded", () => {
  const fields = [
    document.getElementById("loginUser"),
    document.getElementById("loginPass"),
  ];
  fields.forEach((field) => {
    if (field) {
      field.addEventListener("input", () => {
        field.classList.remove("border-red-500/50");
      });
    }
  });
});

/**
 * KEYBOARD CONTROLS: ENTER & ESCAPE
 */
document.addEventListener("keydown", (event) => {
  const authModal = document.getElementById("authModal");
  const isModalVisible = authModal && !authModal.classList.contains("hidden");

  if (event.key === "Enter" && isModalVisible) {
    event.preventDefault();
    handleLogin(); // This triggers the red boundary if empty
  }

  if (event.key === "Escape" && isModalVisible) {
    showLogin();
  }
});

/**
 * UTILITY: Modal Toggle
 */
function showLogin() {
  const modal = document.getElementById("authModal");
  if (modal) {
    modal.classList.toggle("hidden");
    const userField = document.getElementById("loginUser");
    const passField = document.getElementById("loginPass");

    // Reset fields and remove any error boundaries when opening/closing
    userField.value = "";
    passField.value = "";
    userField.classList.remove("border-red-500/50");
    passField.classList.remove("border-red-500/50");

    if (!modal.classList.contains("hidden")) {
      userField.focus();
    }
  }
}

/**
 * KEYBOARD CONTROLS: ENTER & ESCAPE
 */
document.addEventListener("keydown", (event) => {
  const authModal = document.getElementById("authModal");
  const isModalVisible = authModal && !authModal.classList.contains("hidden");

  // Press ENTER to Login
  if (event.key === "Enter" && isModalVisible) {
    event.preventDefault(); // Stop accidental form refresh
    handleLogin();
  }

  // Press ESCAPE to close
  if (event.key === "Escape" && isModalVisible) {
    showLogin(); // Assuming showLogin() toggles the 'hidden' class
  }
});

/**
 * UTILITY: Modal Toggle
 */
function showLogin() {
  const modal = document.getElementById("authModal");
  if (modal) {
    modal.classList.toggle("hidden");
    // Clear fields when toggling
    document.getElementById("loginUser").value = "";
    document.getElementById("loginPass").value = "";
    // Focus on first input for speed
    if (!modal.classList.contains("hidden")) {
      document.getElementById("loginUser").focus();
    }
  }
}

// Function to handle the keyboard "Enter" key trigger
function handleKeyPress(event) {
  if (event.key === "Enter") {
    // Prevent default form behavior if inside a form tag
    event.preventDefault();
    // Call your existing login function
    handleLogin();
  }
}

// Attach listeners to input fields once the DOM is loaded
document.addEventListener("DOMContentLoaded", () => {
  const userInput = document.getElementById("loginUser");
  const passInput = document.getElementById("loginPass");

  if (userInput && passInput) {
    userInput.addEventListener("keypress", handleKeyPress);
    passInput.addEventListener("keypress", handleKeyPress);
  }
});

// Global listener for the Escape key
document.addEventListener("keydown", (event) => {
  if (event.key === "Escape") {
    const modal = document.getElementById("authModal");

    // Only trigger if the modal is currently visible
    if (modal && !modal.classList.contains("hidden")) {
      closeLogin(); // Assuming you have a closeLogin function
      // If you don't have closeLogin, use: modal.classList.add("hidden");
    }
  }
});

/**
 * Helper to close the login modal
 */
function closeLogin() {
  const modal = document.getElementById("authModal");
  if (modal) {
    modal.classList.add("hidden");
    // Optional: Clear fields when closing
    document.getElementById("loginUser").value = "";
    document.getElementById("loginPass").value = "";
  }
}
