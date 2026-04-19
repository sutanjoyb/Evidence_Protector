# 🛡️ Evidence Protector

**Evidence Protector** is a powerful log analysis tool designed to verify the integrity of digital evidence. It analyzes system log files to detect temporal gaps (time jumps) and identify potential evidence tampering or system blackouts.

---

## 🎯 Project Overview

The primary purpose of this project is to **preserve and protect digital evidence**. When a log file is analyzed, the tool performs the following operations:

- ✅ Extracts timestamps from log entries
- ⏱️ Calculates the time gap between consecutive events
- 🚨 Detects unusual gaps that may indicate evidence tampering
- 📊 Generates an integrity score for the analyzed file

**Use Cases:**
- Forensic log analysis
- Security incident investigation
- Compliance auditing
- System integrity monitoring

---

## 🚀 Features

- **FastAPI Backend** — High-performance REST API
- **JWT Authentication** — Secure token-based access control
- **Log Analysis Engine** — Supports multiple timestamp formats
- **Severity Classification** — Categorizes incidents as `CRITICAL` or `WARNING`
- **File Upload Support** — Upload and analyze any log file directly
- **CORS Enabled** — Seamless integration with frontend applications

---

## 📋 Prerequisites

Before contributing, ensure you have the following installed:

```bash
Python 3.9+
Git
```

A basic understanding of **FastAPI**, **JWT authentication**, and **Python** is recommended.

---

## 🛠️ Installation & Setup

### 1. Clone the Repository

```bash
git clone https://github.com/sutanjoyb/Evidence_Protector.git
cd Evidence_Protector
```

### 2. Create a Virtual Environment

```bash
# Windows
python -m venv venv
venv\Scripts\activate

# macOS / Linux
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

If `requirements.txt` does not exist, install the required packages manually:

```bash
pip install fastapi uvicorn python-jose[cryptography] passlib[bcrypt] python-dotenv
```

### 4. Configure Environment Variables

Copy the example environment file and update it with your settings:

```bash
cp .env.example .env
```

Generate a secure secret key and add it to your `.env` file:

```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

### 5. Run the Application

```bash
python main.py
```

The server will start at: `http://127.0.0.1:8000`

To verify the setup, open your browser and navigate to `http://127.0.0.1:8000`.

---

## 📚 API Usage Guide

### 1. Login — Obtain an Access Token

```bash
curl -X POST "http://127.0.0.1:8000/login" \
  -d "username=admin&password=admin123"
```

**Response:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "token_type": "bearer"
}
```

### 2. Analyze a Log File

```bash
curl -X POST "http://127.0.0.1:8000/analyze" \
  -H "Authorization: Bearer YOUR_TOKEN_HERE" \
  -F "file=@/path/to/your/logfile.log" \
  -F "threshold=60"
```

**Parameters:**

| Parameter   | Type    | Required | Description                              |
|-------------|---------|----------|------------------------------------------|
| `file`      | File    | Yes      | The log file to analyze                  |
| `threshold` | Integer | No       | Time gap threshold in seconds (default: 60) |

**Sample Response:**
```json
{
  "total_gaps": 3,
  "integrity_score": 85.0,
  "incidents": [
    {
      "start": "2026-04-15 10:30:00",
      "end": "2026-04-15 12:45:00",
      "duration": 8100,
      "severity": "CRITICAL",
      "details": "Extended System Blackout / High Risk Log Erasure"
    }
  ]
}
```

---

## 🧪 Testing the API with Python

```python
import requests

# Step 1: Authenticate and retrieve token
login_data = {
    "username": "admin",
    "password": "admin123"
}
response = requests.post("http://127.0.0.1:8000/login", data=login_data)
token = response.json()["access_token"]

# Step 2: Analyze a log file
headers = {"Authorization": f"Bearer {token}"}
files = {"file": open("sample.log", "rb")}
data = {"threshold": "60"}

result = requests.post(
    "http://127.0.0.1:8000/analyze",
    headers=headers,
    files=files,
    data=data
)
print(result.json())
```

---

## 🤝 Contribution Guidelines

Contributions are welcome and greatly appreciated. Please follow the steps below to get started.

### Step 1: Find an Issue

- Navigate to the [Issues tab](https://github.com/sutanjoyb/Evidence_Protector/issues).
- Select an unassigned issue that interests you.
- Comment `"I would like to work on this issue"` to request assignment.

### Step 2: Create a Branch

```bash
git checkout -b feature/your-feature-name
# or
git checkout -b fix/your-bug-fix
```

### Step 3: Make Your Changes

- Follow the existing code style (PEP 8 for Python).
- Add comments where appropriate to improve readability.
- Update documentation if your changes affect existing behavior.
- Write tests for any new features introduced.

### Step 4: Commit Your Changes

```bash
git add .
git commit -m "feat: add log encryption feature"
```

**Commit Message Conventions:**

| Prefix       | Purpose                   |
|--------------|---------------------------|
| `feat:`      | New feature               |
| `fix:`       | Bug fix                   |
| `docs:`      | Documentation changes     |
| `refactor:`  | Code refactoring          |
| `test:`      | Adding or updating tests  |

### Step 5: Push and Open a Pull Request

```bash
git push origin feature/your-feature-name
```

Then:
1. Go to the GitHub repository.
2. Click **"Compare & pull request"**.
3. Provide a clear description of your changes.
4. Link the related issue (e.g., `Closes #21`).
5. Submit the pull request for review.

---

## 📂 Project Structure

```
Evidence_Protector/
├── main.py              # FastAPI application entry point
├── logic.py             # Core log analysis logic
├── .env.example         # Environment variables template
├── requirements.txt     # Python dependencies
├── uploads/             # Temporary storage for uploaded files
└── README.md            # Project documentation
```

---

## 🔒 Security Notes

- ⚠️ **Never commit** your `.env` file — it contains sensitive credentials.
- 🔐 Always use a strong, randomly generated `SECRET_KEY` in production environments.
- 👥 Replace hardcoded user credentials with a proper database-backed authentication system before deploying to production.
- 📁 Uploaded files are automatically deleted from the server after analysis.

---

## 🧪 Supported Log Formats

The tool currently supports the following timestamp formats:

```
2026-04-15T10:30:00 User login successful
2026-04-15 10:31:00 File accessed
2026/04/15 10:32:00 Configuration changed
2026.04.15 10:33:00 System backup started
```

---

## 🐛 Reporting Issues

If you encounter a bug, please open an issue and include the following information:

1. **Title:** A concise summary of the problem
2. **Description:** What occurred and under what conditions
3. **Steps to Reproduce:** A detailed sequence of steps to replicate the issue
4. **Expected Behavior:** What the correct behavior should be
5. **Screenshots / Logs:** Attach any relevant output or error messages

---

## 📞 Getting Help

- Open a [new issue](https://github.com/sutanjoyb/Evidence_Protector/issues) on GitHub.
- Comment on an existing issue.
- Refer to the official [FastAPI Documentation](https://fastapi.tiangolo.com/) for framework-related questions.

---

## 🌟 Planned Enhancements

We welcome contributions toward the following upcoming features:

- [ ] Database integration (PostgreSQL / SQLite)
- [ ] Frontend dashboard (React / Vue)
- [ ] Docker containerization
- [ ] Support for additional log format parsers
- [ ] Real-time log monitoring
- [ ] Email alerts for critical incidents
- [ ] Export reports in PDF and CSV formats

---

## 📄 License

This project is currently unlicensed. Please contact the repository owner for licensing information.

---

**🙏 Thank you for contributing to Evidence Protector.**

*Together, we can build more reliable and trustworthy digital evidence protection tools.*