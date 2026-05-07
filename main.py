from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Depends, Request
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from jose import JWTError, jwt
import bcrypt
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv
import shutil
import os
import asyncio
import sys
import json
import logging
import uuid
import magic
import secrets
import threading
import re

load_dotenv()

# ─── LOGGING ─────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("evidence_protector")

# ─── STARTUP SECRET VALIDATION ───────────────────────────────────────────────

_SECRET_KEY = os.getenv("SECRET_KEY", "")
_INSECURE_DEFAULTS = {
    "",
    "fallback-secret-change-me",
    "fallback-secret-change-me-in-production",
    "change-this-to-a-long-random-secret-in-production",
    "REPLACE_WITH_A_STRONG_RANDOM_SECRET",
}
if _SECRET_KEY in _INSECURE_DEFAULTS:
    print(
        "\n[FATAL] SECRET_KEY is not set or is using an insecure default value.\n"
        "        Generate a secure key with:\n"
        "            python -c \"import secrets; print(secrets.token_hex(32))\"\n"
        "        Then add it to your .env file.\n"
        "        Never commit .env to version control.\n",
        file=sys.stderr,
    )
    sys.exit(1)

# ─── FILE VALIDATION CONSTANTS ───────────────────────────────────────────────

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

# ─── AUTH CONFIGURATION ──────────────────────────────────────────────────────

SECRET_KEY = _SECRET_KEY
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 60))
USERS_FILE = "users.json"
users_lock = threading.Lock()
token_blacklist = set()

# ─── RATE LIMITER ────────────────────────────────────────────────────────────

limiter = Limiter(key_func=get_remote_address)

# ─── APP ─────────────────────────────────────────────────────────────────────

try:
    from logic import analyze_logs
except ImportError:
    logger.warning("logic.py not found. Ensure it is in the same directory.")

app = FastAPI(title="Evidence Protector Pro", description="Forensic Log Analysis API", version="1.0.0")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8000", "http://127.0.0.1:8000", "http://localhost:5500", "http://127.0.0.1:5500"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── EXCEPTION HANDLERS ──────────────────────────────────────────────────────

@app.exception_handler(404)
async def custom_404_handler(request: Request, __):
    return HTMLResponse(content="<h1>404 | Data Void Detected</h1>", status_code=404)

@app.exception_handler(Exception)
async def custom_exception_handler(request: Request, exc: Exception):
    logger.error("CRITICAL SYSTEM ERROR: %s", exc)
    return HTMLResponse(content="<h1>500 | System Breach Detected</h1>", status_code=500)

# ─── UPLOAD DIR ──────────────────────────────────────────────────────────────

UPLOAD_DIR = os.path.abspath("uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

# Startup cleanup of uploads
for f in os.listdir(UPLOAD_DIR):
    try:
        os.remove(os.path.join(UPLOAD_DIR, f))
    except Exception:
        pass

# ─── USER STORE ──────────────────────────────────────────────────────────────

def load_users() -> dict:
    with users_lock:
        if not os.path.exists(USERS_FILE):
            default_pass = secrets.token_urlsafe(12)
            default_hash = bcrypt.hashpw(default_pass.encode(), bcrypt.gensalt()).decode()
            default_users = {"admin": default_hash}
            with open(USERS_FILE, "w") as f:
                json.dump(default_users, f, indent=4)
            logger.info(f"Created default admin account. Password: {default_pass}")
            return default_users
        try:
            with open(USERS_FILE, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            return {}

def save_user(username: str, hashed_password: str):
    with users_lock:
        users = load_users()
        users[username] = hashed_password
        with open(USERS_FILE, "w") as f:
            json.dump(users, f, indent=4)

# ─── JWT HELPERS ─────────────────────────────────────────────────────────────

bearer_scheme = HTTPBearer()

def create_access_token(data: dict) -> str:
    payload = data.copy()
    payload["exp"] = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
) -> str:
    token = credentials.credentials
    if token in token_blacklist:
        raise HTTPException(status_code=401, detail="Token has been revoked")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if not username:
            raise HTTPException(status_code=401, detail="Invalid token payload")
        return username
    except JWTError:
        raise HTTPException(status_code=401, detail="Token expired or invalid")

# ─── ENDPOINTS ───────────────────────────────────────────────────────────────

@app.get("/")
async def root():
    return {"status": "online", "system": "Evidence Protector Pro"}

@app.post("/login", summary="Authenticate Operator")
@limiter.limit("10/minute")
async def login(request: Request, username: str = Form(...), password: str = Form(...)):
    users = load_users()
    hashed = users.get(username)
    if not hashed or not bcrypt.checkpw(password.encode(), hashed.encode()):
        logger.warning("Failed login attempt for user: %s from %s", username, request.client.host)
        raise HTTPException(status_code=401, detail="Invalid Credentials")
    token = create_access_token({"sub": username})
    logger.info("Successful login: %s from %s", username, request.client.host)
    return {"access_token": token, "token_type": "bearer"}

@app.post("/logout", summary="Logout Operator")
async def logout(credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)):
    token = credentials.credentials
    token_blacklist.add(token)
    return {"message": "Logged out successfully"}

@app.post("/register", summary="Register Operator")
@limiter.limit("5/minute")
async def register(request: Request, username: str = Form(...), password: str = Form(...)):
    if len(password) < 8 or not re.search(r"\d", password) or not re.search(r"[A-Z]", password):
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters, with 1 uppercase and 1 number.")
    
    users = load_users()
    if username in users:
        raise HTTPException(status_code=400, detail="Operator ID already registered in the system.")
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    save_user(username, hashed)
    token = create_access_token({"sub": username})
    logger.info("New operator registered: %s from %s", username, request.client.host)
    return {
        "message": "Forensic Uplink Established. Operator Registered.",
        "access_token": token,
        "token_type": "bearer",
    }

@app.post("/analyze", summary="Analyze Log File")
@limiter.limit("30/minute")
async def upload_log(
    request: Request,
    file: UploadFile = File(...),
    threshold: str = Form("60"),
    current_user: str = Depends(get_current_user),
):
    logger.info("Analyze request from user '%s' | file: %s | ip: %s",
                current_user, file.filename, request.client.host)

    if not file.filename:
        raise HTTPException(status_code=400, detail="No filename provided.")

    if file.content_type and "multipart" in file.content_type:
        pass # Allow multipart

    _, ext = os.path.splitext(file.filename.lower())
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"File type '{ext}' is not allowed. Accepted types: {', '.join(sorted(ALLOWED_EXTENSIONS))}"
        )

    contents = await file.read()
    if len(contents) == 0:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")
    if len(contents) > MAX_FILE_SIZE_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"File exceeds maximum allowed size of {MAX_FILE_SIZE_BYTES // (1024 * 1024)} MB."
        )

    try:
        detected_mime = magic.from_buffer(contents, mime=True)
    except Exception:
        detected_mime = "unknown"

    if detected_mime not in ALLOWED_MIME_TYPES:
        raise HTTPException(
            status_code=400,
            detail=f"File content type '{detected_mime}' is not permitted. Only log/text files are accepted."
        )

    safe_name = os.path.basename(file.filename)
    unique_name = f"{uuid.uuid4().hex}_{safe_name}"
    temp_path = os.path.join(UPLOAD_DIR, unique_name)

    try:
        with open(temp_path, "wb") as buffer:
            buffer.write(contents)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"File save failed: {str(e)}")

    try:
        numeric_threshold = int(threshold)
        loop = asyncio.get_event_loop()
        results = await loop.run_in_executor(None, analyze_logs, temp_path, numeric_threshold)
        logger.info("Analysis complete for user '%s' | gaps: %s | score: %s",
                    current_user, results.get("total_gaps"), results.get("integrity_score"))
        return results
    except Exception as e:
        logger.error("Analysis error for user '%s': %s", current_user, e)
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)

@app.get("/analyze-process", summary="Streaming Process Analysis")
async def analyze_process(
    file_path: str,
    threshold: int = 60,
    current_user: str = Depends(get_current_user),
):
    abs_file_path = os.path.abspath(file_path)
    if not abs_file_path.startswith(UPLOAD_DIR):
        raise HTTPException(status_code=403, detail="Path traversal detected.")

    if not os.path.exists(abs_file_path):
        raise HTTPException(status_code=404, detail="File not found.")

    queue: asyncio.Queue = asyncio.Queue()

    def progress_callback(percent: int, message: str):
        queue.put_nowait({"percent": percent, "message": message})

    async def event_generator():
        loop = asyncio.get_event_loop()
        analysis_task = loop.run_in_executor(
            None,
            lambda: analyze_logs(
                abs_file_path,
                threshold_seconds=threshold,
                progress_callback=progress_callback,
            ),
        )

        while True:
            try:
                event = await asyncio.wait_for(queue.get(), timeout=0.5)
                yield f"data: {json.dumps(event)}\n\n"
                if event.get("percent") == 100:
                    break
            except asyncio.TimeoutError:
                if analysis_task.done():
                    break

        try:
            result = await analysis_task
            yield f"data: {json.dumps({'percent': 100, 'message': 'Analysis completed.', 'result': result})}\n\n"
        except Exception as e:
            logger.error("SSE analysis error: %s", e)
            yield f"data: {json.dumps({'percent': 100, 'message': f'Error: {str(e)}'})}\n\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )

@app.post("/verify-chain", summary="Verify Custody Chain")
@limiter.limit("30/minute")
async def verify_chain_manifest(
    request: Request,
    manifest: list = None,
    current_user: str = Depends(get_current_user),
):
    try:
        from chain_of_custody import verify_chain_manifest
    except ImportError:
        raise HTTPException(
            status_code=501,
            detail="Chain of custody module not available. Ensure chain_of_custody.py exists."
        )
    
    if manifest is None or not isinstance(manifest, list):
        raise HTTPException(
            status_code=400,
            detail="Manifest must be a non-empty list of session entries."
        )
    
    if len(manifest) == 0:
        return {
            "is_intact": True,
            "broken_index": None,
            "verified_entries": 0,
            "verification_details": [],
            "message": "Empty manifest - no entries to verify."
        }
    
    try:
        is_intact, broken_index = verify_chain_manifest(manifest)
        
        verification_details = []
        for i, entry in enumerate(manifest):
            entry_detail = {
                "entry_index": i,
                "session_id": entry.get("session_id", "unknown"),
                "timestamp": entry.get("timestamp", "unknown"),
                "valid": i < broken_index if broken_index is not None else True,
            }
            
            if i == 0:
                entry_detail["notes"] = "Genesis entry (first session)"
            elif broken_index is not None and i == broken_index:
                entry_detail["notes"] = "Chain broken at this entry - previous link failed"
            elif broken_index is not None and i > broken_index:
                entry_detail["notes"] = "Invalid (downstream of broken link)"
            else:
                entry_detail["notes"] = "Valid - linked to previous session"
            
            verification_details.append(entry_detail)
        
        logger.info(
            "Chain verification for user '%s': is_intact=%s, broken_index=%s",
            current_user, is_intact, broken_index
        )
        
        return {
            "is_intact": is_intact,
            "broken_index": broken_index,
            "verified_entries": len(manifest),
            "verification_details": verification_details,
            "message": (
                "Chain integrity verified" if is_intact 
                else f"Chain broken at entry #{broken_index}"
            )
        }
    
    except Exception as e:
        logger.error(
            "Chain verification error for user '%s': %s",
            current_user, e
        )
        raise HTTPException(
            status_code=500,
            detail=f"Verification failed: {str(e)}"
        )

@app.get("/chain-status", summary="Get Chain Status")
@limiter.limit("30/minute")
async def get_chain_status(
    request: Request,
    current_user: str = Depends(get_current_user),
):
    return {
        "storage_location": "Browser localStorage['analysis_chain_manifest']",
        "chain_type": "SHA-256 hash chaining",
        "features": [
            "File integrity (SHA-256 of uploaded log)",
            "Findings integrity (SHA-256 of analysis output)",
            "Session linking (cryptographic chain)",
            "Tampering detection (broken chain indicates modification)",
            "Export integration (PDF/JSON include manifest)"
        ],
        "endpoints": {
            "verify": "POST /verify-chain",
            "info": "GET /chain-status"
        },
        "documentation": "See CHAIN_OF_CUSTODY.md for full details"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)