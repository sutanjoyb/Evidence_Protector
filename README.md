# 🛡️ Evidence Protector Pro

**Enterprise-Grade Forensic Log Analysis & Data Integrity Suite**

Evidence Protector Pro is a specialized forensic utility designed to bridge the gap between raw system logs and actionable legal evidence. By identifying **"Time Voids"** and log-shaving attempts, it ensures that digital evidence remains untampered, transparent, and admissible through local, high-speed analysis.

---

## 🛠️ How To Run

Get your local forensic environment up and running with these steps:

---

### 1. Prerequisites

- **Python 3.9+**
- **Live Server** (VS Code extension) or any local web server

---

### 2. Backend Setup (FastAPI)

```bash
# Clone the repository
git clone https://github.com/your-username/evidence-protector-pro.git
cd evidence-protector-pro

# Create a virtual environment
python -m venv venv

# Activate environment
# macOS/Linux:
source venv/bin/activate

# Windows:
venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run the FastAPI server
uvicorn main:app --reload
```

### 3. Frontend Setup

- **Open Project**
  - Open the project folder in your preferred code editor

- **Run Frontend**
  - Right-click `index.html` → **Open with Live Server** (recommended)
  - OR manually open the file in your browser

- **Backend Requirement**
  - Ensure the FastAPI backend server is running
  - Required for **SSE (Server-Sent Events) Analysis Stream**

- **Verify Functionality**
  - Real-time updates should stream without page reload
  - UI should dynamically respond to incoming analysis data

> ⚠️ **Note:**  
> The application uses **localized session persistence** to ensure maximum data privacy.

## 🚀 Key Capabilities

- 🔍 **Anomaly Detection**
  - Detects missing timestamps (seconds/minutes)
  - Identifies log tampering and "Time Voids"

- 📊 **Interactive Analytics**
  - Dynamic integrity delta charts
  - Session-based heatmaps for pattern analysis

- 📂 **Export Center**
  - Supports multiple formats:
    - PDF (legal documentation)
    - CSV (data analysis)
    - JSON (system integration)

- ⚡ **Real-Time Progress (SSE)**
  - Live updates using Server-Sent Events
  - No page refresh required

- 🔒 **Privacy-First Architecture**
  - 100% local processing
  - No external data transmission

- 🌓 **Adaptive Interface**
  - Mobile-first responsive design
  - Supports Dark Mode and Light Mode

## 🤝 Contribution Rules

Contributions are welcome! You can contribute by improving code, suggesting features, or reporting issues.

---

### 🐛 Issues

- Creating issues is **open to everyone**
- Report bugs, suggest features, or propose improvements
- Clearly describe the problem or idea for better discussion

---

### 📥 Pull Request (PR) Guidelines

- Link your PR to an existing issue
  - Example: `Fix: Resolved mobile overflow in #42`

- Keep changes **focused and minimal**

- Ensure:
  - UI remains responsive (mobile-friendly)
  - No data integrity issues (use safe file handling like `uuid4`)

---

### 🔄 Contribution Workflow

# 1. Star and fork the repository

# 2. Create a feature branch

git checkout -b feature/issue-ID

# 3. Commit changes

git commit -m "feat: meaningful description"

# 4. Push changes

git push origin feature/issue-ID

# 5. Open a Pull Request referencing the Issue ID

---

## ⭐ Support

If you find this project useful, consider giving it a **Star ⭐** on GitHub.  
It helps the project grow and reach more developers.
