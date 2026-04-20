# 🛡️ Evidence Protector

**Evidence Protector** is a log analysis tool designed to verify the integrity of digital evidence. It detects **temporal gaps** in system logs to identify potential tampering, data loss, or system blackouts.

---

## 📂 Project Structure

```
Evidence_Protector/
├── main.py          # FastAPI application entry point
├── logic.py         # Core log analysis logic (gap detection)
├── .env.example     # Environment variables template
├── requirements.txt # Python dependencies
├── uploads/         # Temporary storage for uploaded files
└── README.md        # Project documentation
```

---

## 🚀 Getting Started

### Prerequisites

* Python 3.9+
* Git

### Installation & Setup

```bash
git clone https://github.com/sutanjoyb/Evidence_Protector.git
cd Evidence_Protector
```

```bash
python -m venv venv
# Activate (Windows)
venv\Scripts\activate
# Activate (macOS/Linux)
source venv/bin/activate
```

```bash
pip install -r requirements.txt
```

```bash
python main.py
```

Server runs at: **http://127.0.0.1:8000**

---

## 🔑 API Endpoints

### Login

```
POST /login
```

### Analyze Logs

```
POST /analyze
```

* Upload log file
* Optional: `threshold` (default: 60 seconds)

---

## 🔍 Core Features

* **Temporal Gap Detection** — Identifies time gaps between log entries
* **Severity Classification** — Categorizes gaps as `WARNING` or `CRITICAL`
* **Integrity Score** — Provides a reliability score for logs
* **JWT Authentication** — Secure API access
* **Multi-format Support** — Handles multiple timestamp formats

---

## 📄 Supported Log Formats

The tool supports common timestamp formats:

```
2026-04-15T10:30:00 message
2026-04-15 10:30:00 message
2026/04/15 10:30:00 message
```

---

## 🤝 Contributing

Contributions are welcome!

1. Go to the **Issues** section
2. Pick an issue and comment to get assigned
3. Create a new branch
4. Make your changes
5. Open a Pull Request with:

```
Fixes #IssueNumber
```

---

## ⚠️ Notes

* Default credentials: `admin / admin123`
* Use `.env` file for configuring secret keys in production
* Uploaded files are temporary and deleted after processing

---
