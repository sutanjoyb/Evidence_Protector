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

async function handleLogin() {
  const u = document.getElementById("loginUser").value;
  const p = document.getElementById("loginPass").value;
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
      updateNavState();
      setTimeout(() => {
        showLogin();
      }, 600);
    } else {
      alert("ACCESS DENIED");
    }
  } catch (e) {
    alert("OFFLINE: Ensure Forensic Backend is running.");
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
