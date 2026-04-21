from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Depends, Request
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.staticfiles import StaticFiles   # ✅ ADDED
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from jose import JWTError, jwt
import bcrypt
from datetime import datetime, timedelta
from dotenv import load_dotenv
import shutil
import os
import json
import logging
import magic

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("evidence_protector")

ALLOWED_EXTENSIONS = {".log", ".txt", ".csv", ".json", ".xml", ".syslog", ".evtx"}
ALLOWED_MIME_TYPES = {
    "text/plain",
    "text/csv",
    "application/json",
    "application/xml",
    "text/xml",
    "text/x-log",
    "application/octet-stream",
}
MAX_FILE_SIZE_BYTES = 50 * 1024 * 1024

SECRET_KEY = os.getenv("SECRET_KEY", "fallback-secret-change-me-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 60))
USERS_FILE = "users.json"

limiter = Limiter(key_func=get_remote_address)

try:
    from logic import analyze_logs
except ImportError:
    logger.warning("logic.py not found.")

app = FastAPI(title="Evidence Protector Pro")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ✅ ONLY REQUIRED FIX (STATIC FILES)
app.mount("/js", StaticFiles(directory="js"), name="js")
app.mount("/styles", StaticFiles(directory="styles"), name="styles")
app.mount("/html", StaticFiles(directory="html"), name="html")

@app.exception_handler(404)
async def custom_404_handler(request: Request, __):
    try:
        base_path = os.path.dirname(os.path.abspath(__file__))
        file_path = os.path.join(base_path, "html", "404.html")
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
        return HTMLResponse(content=content, status_code=404)
    except Exception:
        return HTMLResponse(content="<h1>404 | Data Void Detected</h1>", status_code=404)

@app.exception_handler(Exception)
async def custom_exception_handler(request: Request, exc: Exception):
    logger.error("CRITICAL SYSTEM ERROR: %s", exc)
    return HTMLResponse(content="<h1>500 | System Breach Detected</h1>", status_code=500)

UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

def load_users() -> dict:
    if not os.path.exists(USERS_FILE):
        default_hash = bcrypt.hashpw("admin123".encode(), bcrypt.gensalt()).decode()
        default_users = {"admin": default_hash}
        with open(USERS_FILE, "w") as f:
            json.dump(default_users, f, indent=4)
        return default_users
    with open(USERS_FILE, "r") as f:
        return json.load(f)

def save_user(username: str, hashed_password: str):
    users = load_users()
    users[username] = hashed_password
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=4)

bearer_scheme = HTTPBearer()

def create_access_token(data: dict) -> str:
    payload = data.copy()
    payload["exp"] = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)) -> str:
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if not username:
            raise HTTPException(status_code=401, detail="Invalid token")
        return username
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

@app.get("/dashboard")
async def dashboard():
    return FileResponse("html/dashboard.html")

@app.get("/")
async def root():
    return FileResponse("html/index.html")

# ---------------- API ----------------

@app.post("/login")
@limiter.limit("10/minute")
async def login(request: Request, username: str = Form(...), password: str = Form(...)):
    users = load_users()
    hashed = users.get(username)
    if not hashed or not bcrypt.checkpw(password.encode(), hashed.encode()):
        raise HTTPException(status_code=401, detail="Invalid Credentials")
    token = create_access_token({"sub": username})
    return {"access_token": token, "token_type": "bearer"}

@app.post("/register")
@limiter.limit("5/minute")
async def register(request: Request, username: str = Form(...), password: str = Form(...)):
    users = load_users()
    if username in users:
        raise HTTPException(status_code=400, detail="User exists")
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    save_user(username, hashed)
    token = create_access_token({"sub": username})
    return {"access_token": token, "token_type": "bearer"}

@app.post("/analyze")
@limiter.limit("30/minute")
async def upload_log(
    request: Request,
    file: UploadFile = File(...),
    threshold: str = Form("60"),
    current_user: str = Depends(get_current_user),
):
    contents = await file.read()
    temp_path = os.path.join(UPLOAD_DIR, file.filename)

    with open(temp_path, "wb") as f:
        f.write(contents)

    results = analyze_logs(temp_path, int(threshold))
    os.remove(temp_path)
    return results

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)