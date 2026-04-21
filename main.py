from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Depends
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from passlib.context import CryptContext
from datetime import datetime, timedelta
from dotenv import load_dotenv
from pydantic import BaseModel
import shutil
import os
import uuid
import hashlib
import io

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

app.mount("/js", StaticFiles(directory="js"), name="js")
app.mount("/styles", StaticFiles(directory="styles"), name="styles")
app.mount("/html", StaticFiles(directory="html"), name="html")

# --- CONFIGURATION ---
UPLOAD_DIR = "uploads"
if not os.path.exists(UPLOAD_DIR):
    os.makedirs(UPLOAD_DIR)

SECRET_KEY = os.getenv("SECRET_KEY", "fallback-secret-change-me")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 60))

# --- AUTH SETUP ---
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
bearer_scheme = HTTPBearer()

# In production, replace this with a real user database with hashed passwords.
# To generate a hash: pwd_context.hash("your-password")
USERS = {
    "admin": pwd_context.hash("admin123")
}

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
    return FileResponse("html/index.html")

@app.get("/dashboard")
async def dashboard():
    return FileResponse("html/dashboard.html")

@app.get("/dashboard.html")
async def dashboard_html():
    return FileResponse("html/dashboard.html")

@app.post("/login")
async def login(username: str = Form(...), password: str = Form(...)):
    hashed = USERS.get(username)
    if not hashed or not pwd_context.verify(password, hashed):
        raise HTTPException(status_code=401, detail="Invalid Credentials")
    token = create_access_token({"sub": username})
    return {"access_token": token, "token_type": "bearer"}

@app.post("/analyze")
async def upload_log(
    file: UploadFile = File(...),
    threshold: str = Form("60"),
    current_user: str = Depends(get_current_user),  # protected
):
    safe_filename = f"{uuid.uuid4().hex}.log"
    temp_path = os.path.join(UPLOAD_DIR, safe_filename)
    try:
        with open(temp_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"File save failed: {str(e)}")

    try:
        numeric_threshold = int(threshold)
        results = analyze_logs(temp_path, numeric_threshold)
        with open(temp_path, "rb") as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()
        results["file_hash"] = file_hash
        return results
    except Exception as e:
        print(f"Analysis Error: {e}")
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
        """Sanitizes text for ReportLab's default fonts."""
        if not text: return ""
        return str(text).encode('ascii', 'ignore').decode('ascii')

    try:
        try:
            from reportlab.lib.pagesizes import letter
            from reportlab.pdfgen import canvas
        except ImportError:
            print("ERROR: ReportLab not installed")
            raise HTTPException(status_code=500, detail="ReportLab is not installed")

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
