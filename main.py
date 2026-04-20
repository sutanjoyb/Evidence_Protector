from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Depends, Request
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
import bcrypt
from datetime import datetime, timedelta
from dotenv import load_dotenv
import shutil
import os
import magic  # python-magic for MIME sniffing

# --- FILE VALIDATION CONSTANTS ---
ALLOWED_EXTENSIONS = {".log", ".txt", ".csv", ".json", ".xml", ".syslog", ".evtx"}
ALLOWED_MIME_TYPES = {
    "text/plain",
    "text/csv",
    "application/json",
    "application/xml",
    "text/xml",
    "text/x-log",
    "application/octet-stream",  # fallback for .log/.evtx on some systems
}
MAX_FILE_SIZE_BYTES = 50 * 1024 * 1024  # 50 MB
import json

load_dotenv()

try:
    from logic import analyze_logs
except ImportError:
    print("WARNING: logic.py not found. Ensure it is in the same directory.")

app = FastAPI()

# --- MIDDLEWARE ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- EXCEPTION HANDLERS ---

@app.exception_handler(404)
async def custom_404_handler(request: Request, __):
    try:
        # Resolve path relative to this script
        base_path = os.path.dirname(os.path.abspath(__file__))
        file_path = os.path.join(base_path, "html", "404.html")
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
        return HTMLResponse(content=content, status_code=404)
    except Exception:
        return HTMLResponse(content="<h1>404 | Data Void Detected</h1>", status_code=404)

@app.exception_handler(Exception)
async def custom_exception_handler(request: Request, exc: Exception):
    # Log for debugging
    print(f"CRITICAL SYSTEM ERROR: {exc}")
    try:
        base_path = os.path.dirname(os.path.abspath(__file__))
        file_path = os.path.join(base_path, "html", "404.html")
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
        return HTMLResponse(content=content, status_code=500)
    except Exception:
        return HTMLResponse(content="<h1>500 | System Breach Detected</h1>", status_code=500)

# --- CONFIGURATION ---
UPLOAD_DIR = "uploads"
if not os.path.exists(UPLOAD_DIR):
    os.makedirs(UPLOAD_DIR)

SECRET_KEY = os.getenv("SECRET_KEY", "fallback-secret-change-me")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 60))

# --- AUTH SETUP ---
USERS_FILE = "users.json"

def load_users():
    if not os.path.exists(USERS_FILE):
        # Initial default admin user
        default_users = {
            "admin": bcrypt.hashpw("admin123".encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        }
        with open(USERS_FILE, "w") as f:
            json.dump(default_users, f, indent=4)
        return default_users
    try:
        with open(USERS_FILE, "r") as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return {}

def save_user(username, hashed_password):
    users = load_users()
    users[username] = hashed_password
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=4)

# Authentication setup using direct bcrypt for compatibility
bearer_scheme = HTTPBearer()

# --- JWT HELPERS ---

def create_access_token(data: dict) -> str:
    payload = data.copy()
    payload["exp"] = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)) -> str:
    """Dependency that validates the JWT and returns the username."""
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token payload")
        return username
    except JWTError:
        raise HTTPException(status_code=401, detail="Token expired or invalid")

# --- ENDPOINTS ---

@app.get("/")
async def root():
    return {"status": "online", "system": "Evidence Protector Pro"}

@app.post("/login")
async def login(username: str = Form(...), password: str = Form(...)):
    users = load_users()
    hashed = users.get(username)
    if not hashed or not bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8')):
        raise HTTPException(status_code=401, detail="Invalid Credentials")
    token = create_access_token({"sub": username})
    return {"access_token": token, "token_type": "bearer"}

@app.post("/register")
async def register(username: str = Form(...), password: str = Form(...)):
    users = load_users()
    if username in users:
        raise HTTPException(status_code=400, detail="Operator ID already registered in the system.")
    
    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    save_user(username, hashed)
    
    token = create_access_token({"sub": username})
    return {
        "message": "Forensic Uplink Established. Operator Registered.",
        "access_token": token,
        "token_type": "bearer"
    }

@app.post("/analyze")
async def upload_log(file: UploadFile = File(...), threshold: str = Form("60")):
    # ── 1. FILENAME / EXTENSION VALIDATION ──────────────────────────────────
    if not file.filename:
        raise HTTPException(status_code=400, detail="No filename provided.")

    _, ext = os.path.splitext(file.filename.lower())
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"File type '{ext}' is not allowed. Accepted types: {', '.join(sorted(ALLOWED_EXTENSIONS))}"
        )

    # ── 2. FILE SIZE VALIDATION ──────────────────────────────────────────────
    contents = await file.read()
    if len(contents) > MAX_FILE_SIZE_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"File exceeds maximum allowed size of {MAX_FILE_SIZE_BYTES // (1024*1024)} MB."
        )
    if len(contents) == 0:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")

    # ── 3. MIME TYPE VALIDATION (magic-byte sniffing) ────────────────────────
    try:
        detected_mime = magic.from_buffer(contents, mime=True)
    except Exception:
        detected_mime = "unknown"

    if detected_mime not in ALLOWED_MIME_TYPES:
        raise HTTPException(
            status_code=400,
            detail=f"File content type '{detected_mime}' is not permitted. Only log/text files are accepted."
        )

    # ── 4. SAFE FILENAME (prevent path traversal) ────────────────────────────
    safe_name = os.path.basename(file.filename).replace("..", "").replace("/", "").replace("\\", "")
    temp_path = os.path.join(UPLOAD_DIR, safe_name)

    # ── 5. WRITE & ANALYZE ───────────────────────────────────────────────────
    try:
        with open(temp_path, "wb") as buffer:
            buffer.write(contents)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"File save failed: {str(e)}")

    try:
        numeric_threshold = int(threshold)
        results = analyze_logs(temp_path, numeric_threshold)
        return results
    except Exception as e:
        print(f"Analysis Error: {e}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
