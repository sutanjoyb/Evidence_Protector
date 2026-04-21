from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Depends, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, StreamingResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from jose import JWTError, jwt
from datetime import datetime, timedelta
from dotenv import load_dotenv
from pydantic import BaseModel
import bcrypt
import shutil
import os
import uuid
import hashlib
import io
import json
import logging
import magic  # python-magic for MIME sniffing

load_dotenv()

# ─── LOGGING ─────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("evidence_protector")

# ─── FILE VALIDATION CONSTANTS ───────────────────────────────────────────────

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

# ─── AUTH CONFIGURATION ──────────────────────────────────────────────────────

SECRET_KEY = os.getenv("SECRET_KEY", "fallback-secret-change-me-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 60))
USERS_FILE = "users.json"

# ─── RATE LIMITER ────────────────────────────────────────────────────────────

limiter = Limiter(key_func=get_remote_address)

# ─── APP ─────────────────────────────────────────────────────────────────────

try:
    from logic import analyze_logs
except ImportError:
    logger.warning("logic.py not found. Ensure it is in the same directory.")

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

app.mount("/js", StaticFiles(directory="js"), name="js")
app.mount("/styles", StaticFiles(directory="styles"), name="styles")
app.mount("/html", StaticFiles(directory="html"), name="html")

# ─── EXCEPTION HANDLERS ──────────────────────────────────────────────────────

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
    try:
        base_path = os.path.dirname(os.path.abspath(__file__))
        file_path = os.path.join(base_path, "html", "404.html")
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
        return HTMLResponse(content=content, status_code=500)
    except Exception:
        return HTMLResponse(content="<h1>500 | System Breach Detected</h1>", status_code=500)

# ─── UPLOAD DIR ──────────────────────────────────────────────────────────────

UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

# ─── USER STORE ──────────────────────────────────────────────────────────────

def load_users() -> dict:
    if not os.path.exists(USERS_FILE):
        default_hash = bcrypt.hashpw("admin123".encode(), bcrypt.gensalt()).decode()
        default_users = {"admin": default_hash}
        with open(USERS_FILE, "w") as f:
            json.dump(default_users, f, indent=4)
        return default_users
    try:
        with open(USERS_FILE, "r") as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return {}

def save_user(username: str, hashed_password: str):
    users = load_users()
    users[username] = hashed_password
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=4)

# ─── JWT HELPERS ─────────────────────────────────────────────────────────────

bearer_scheme = HTTPBearer()

def create_access_token(data: dict) -> str:
    payload = data.copy()
    payload["exp"] = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
) -> str:
    """JWT dependency — validates token and returns username. Raises 401 on failure."""
    token = credentials.credentials
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
    return FileResponse("html/index.html")

@app.get("/index.html")
async def index_html():
    return FileResponse("html/index.html")

@app.get("/dashboard")
async def dashboard():
    return FileResponse("html/dashboard.html")

@app.get("/dashboard.html")
async def dashboard_html():
    return FileResponse("html/dashboard.html")

@app.post("/login")
@limiter.limit("10/minute")
async def login(request: Request, username: str = Form(...), password: str = Form(...)):
    """Authenticate operator and return a signed JWT."""
    users = load_users()
    hashed = users.get(username)
    if not hashed or not bcrypt.checkpw(password.encode(), hashed.encode()):
        logger.warning("Failed login attempt for user: %s from %s", username, request.client.host)
        raise HTTPException(status_code=401, detail="Invalid Credentials")
    token = create_access_token({"sub": username})
    logger.info("Successful login: %s from %s", username, request.client.host)
    return {"access_token": token, "token_type": "bearer"}

@app.post("/register")
@limiter.limit("5/minute")
async def register(request: Request, username: str = Form(...), password: str = Form(...)):
    """Register a new operator account."""
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

@app.post("/analyze")
@limiter.limit("30/minute")
async def upload_log(
    request: Request,
    file: UploadFile = File(...),
    threshold: str = Form("60"),
    current_user: str = Depends(get_current_user),
):
    """
    Protected forensic analysis endpoint.
    Requires a valid Bearer token issued by /login or /register.
    """
    logger.info("Analyze request from user '%s' | file: %s | ip: %s",
                current_user, file.filename, request.client.host)

    if not file.filename:
        raise HTTPException(status_code=400, detail="No filename provided.")

    _, ext = os.path.splitext(file.filename.lower())
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"File type '{ext}' is not allowed."
        )

    contents = await file.read()
    if len(contents) == 0:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")
    if len(contents) > MAX_FILE_SIZE_BYTES:
        raise HTTPException(status_code=413, detail="File too large.")

    try:
        detected_mime = magic.from_buffer(contents, mime=True)
    except Exception:
        detected_mime = "unknown"

    if detected_mime not in ALLOWED_MIME_TYPES:
        raise HTTPException(status_code=400, detail=f"Invalid MIME type: {detected_mime}")

    safe_name = os.path.basename(file.filename).replace("..", "").replace("/", "").replace("\\", "")
    temp_path = os.path.join(UPLOAD_DIR, f"{uuid.uuid4().hex}_{safe_name}")

    try:
        with open(temp_path, "wb") as buffer:
            buffer.write(contents)
            
        numeric_threshold = int(threshold)
        results = analyze_logs(temp_path, numeric_threshold)
        results["file_hash"] = hashlib.sha256(contents).hexdigest()
        
        logger.info("Analysis complete for user '%s'", current_user)
        return results
    except Exception as e:
        logger.error("Analysis error: %s", e)
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)

class ReportData(BaseModel):
    file_name: str
    scan_time: str
    score: str
    file_hash: str
    incidents: list

@app.post("/export_pdf")
async def export_pdf(data: ReportData, current_user: str = Depends(get_current_user)):
    print(f"Generating PDF for {data.file_name}...")
    
    def clean_text(text):
        if not text: return ""
        return str(text).encode('ascii', 'ignore').decode('ascii')

    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.pdfgen import canvas

        buffer = io.BytesIO()
        c = canvas.Canvas(buffer, pagesize=letter)
        width, height = letter
        
        c.setFont("Helvetica-Bold", 20)
        c.drawString(50, height - 50, "Evidence Protector Pro - Forensic Scan Report")
        
        c.setFont("Helvetica-Bold", 14)
        c.drawString(50, height - 90, "Scan Metadata")
        c.setFont("Helvetica", 12)
        c.drawString(50, height - 110, f"Scan ID: {uuid.uuid4().hex[:8].upper()}")
        c.drawString(50, height - 130, f"File Name: {clean_text(data.file_name)}")
        c.drawString(50, height - 150, f"Scan Time: {clean_text(data.scan_time)}")
        
        c.setFont("Helvetica-Bold", 14)
        c.drawString(50, height - 190, "Integrity Metrics")
        c.setFont("Helvetica", 12)
        c.drawString(50, height - 210, f"Integrity Score: {clean_text(data.score)}")
        c.drawString(50, height - 230, "Score Logic: Starts at 100%, deducts 5% per anomaly incident detected.")
        
        c.setFont("Helvetica-Bold", 14)
        c.drawString(50, height - 270, "Cryptographic Verification")
        c.setFont("Helvetica", 12)
        c.drawString(50, height - 290, f"SHA-256 Hash: {clean_text(data.file_hash)}")
        
        c.setFont("Helvetica-Bold", 14)
        c.drawString(50, height - 330, "Detected Anomalies")
        
        y = height - 350
        c.setFont("Helvetica", 10)
        if not data.incidents:
            c.drawString(50, y, "No anomalies detected.")
            y -= 20
        else:
            for inc in data.incidents:
                if y < 100:
                    c.showPage()
                    y = height - 50
                    c.setFont("Helvetica", 10)
                    
                start = clean_text(inc.get("start", ""))
                end = clean_text(inc.get("end", ""))
                dur = clean_text(inc.get("duration", ""))
                sev = clean_text(inc.get("severity", ""))
                details = clean_text(inc.get("details", ""))
                c.drawString(50, y, f"• {start} to {end} | Duration: {dur}s | Severity: {sev} | {details}")
                y -= 20
            
        c.setFont("Helvetica-Oblique", 8)
        c.drawString(50, 30, f"Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        c.save()
        buffer.seek(0)
        
        return StreamingResponse(
            buffer, 
            media_type="application/pdf", 
            headers={"Content-Disposition": "attachment; filename=Forensic_Report.pdf"}
        )
    except Exception as e:
        import traceback
        print(f"PDF Generation Error:\n{traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
