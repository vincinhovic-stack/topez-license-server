"""
TOP EZ License Server
- /api/validate - Dashboard license validation
- /admin - Admin panel for managing licenses
- /api/webhook/authorize - Authorize.net payment webhook
- /api/webhook/keap - (future) Keap email trigger
"""

from fastapi import FastAPI, Request, HTTPException, Depends, Form, Response
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from typing import Optional
import sqlite3
import uuid
import hashlib
import secrets
import datetime
import json
import os

app = FastAPI(title="TOP EZ License Server")
templates = Jinja2Templates(directory="templates")

DATABASE = os.environ.get("DATABASE_PATH", "licenses.db")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "topez2026")
ADMIN_TOKEN_SECRET = os.environ.get("ADMIN_TOKEN_SECRET", secrets.token_hex(32))


# ═══════════════════════════════════════════════════════════════
# DATABASE
# ═══════════════════════════════════════════════════════════════

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS licenses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            license_key TEXT UNIQUE NOT NULL,
            email TEXT DEFAULT '',
            machine_id TEXT DEFAULT '',
            products TEXT DEFAULT '["ME_Dashboard","HFT_Dashboard"]',
            active INTEGER DEFAULT 1,
            expiry_date TEXT DEFAULT '',
            created_at TEXT NOT NULL,
            last_validated TEXT DEFAULT '',
            notes TEXT DEFAULT ''
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS validation_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            license_key TEXT,
            machine_id TEXT,
            product_id TEXT,
            result TEXT,
            timestamp TEXT
        )
    """)
    conn.commit()
    conn.close()

init_db()


# ═══════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════

def generate_license_key():
    """Generate a key like: TOPEZ-XXXX-XXXX-XXXX-XXXX"""
    parts = [secrets.token_hex(2).upper() for _ in range(4)]
    return f"TOPEZ-{parts[0]}-{parts[1]}-{parts[2]}-{parts[3]}"

def hash_token(password):
    return hashlib.sha256(password.encode()).hexdigest()

def verify_admin(request: Request):
    token = request.cookies.get("admin_token")
    if not token or token != hash_token(ADMIN_PASSWORD):
        return False
    return True


# ═══════════════════════════════════════════════════════════════
# VALIDATE ENDPOINT (called by NT8 / TradeStation dashboards)
# ═══════════════════════════════════════════════════════════════

class ValidateRequest(BaseModel):
    license_key: str
    machine_id: str
    product_id: Optional[str] = ""

@app.post("/api/validate")
async def validate_license(req: ValidateRequest):
    conn = get_db()
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    
    # Find license
    row = conn.execute(
        "SELECT * FROM licenses WHERE license_key = ?", (req.license_key,)
    ).fetchone()
    
    if not row:
        conn.execute(
            "INSERT INTO validation_log (license_key, machine_id, product_id, result, timestamp) VALUES (?,?,?,?,?)",
            (req.license_key, req.machine_id, req.product_id, "DENIED_NOT_FOUND", now)
        )
        conn.commit()
        conn.close()
        return {"status": "denied", "reason": "Invalid license key"}
    
    # Check active
    if not row["active"]:
        conn.execute(
            "INSERT INTO validation_log (license_key, machine_id, product_id, result, timestamp) VALUES (?,?,?,?,?)",
            (req.license_key, req.machine_id, req.product_id, "DENIED_INACTIVE", now)
        )
        conn.commit()
        conn.close()
        return {"status": "denied", "reason": "License is inactive"}
    
    # Check expiry
    if row["expiry_date"] and row["expiry_date"] != "":
        try:
            expiry = datetime.datetime.fromisoformat(row["expiry_date"])
            if datetime.datetime.now(datetime.timezone.utc) > expiry:
                conn.execute(
                    "INSERT INTO validation_log (license_key, machine_id, product_id, result, timestamp) VALUES (?,?,?,?,?)",
                    (req.license_key, req.machine_id, req.product_id, "DENIED_EXPIRED", now)
                )
                conn.commit()
                conn.close()
                return {"status": "denied", "reason": "License has expired"}
        except:
            pass
    
    # Check machine ID - first use locks it
    if row["machine_id"] == "" or row["machine_id"] is None:
        conn.execute(
            "UPDATE licenses SET machine_id = ?, last_validated = ? WHERE license_key = ?",
            (req.machine_id, now, req.license_key)
        )
    elif row["machine_id"] != req.machine_id:
        conn.execute(
            "INSERT INTO validation_log (license_key, machine_id, product_id, result, timestamp) VALUES (?,?,?,?,?)",
            (req.license_key, req.machine_id, req.product_id, "DENIED_MACHINE", now)
        )
        conn.commit()
        conn.close()
        return {"status": "denied", "reason": "License is locked to a different machine"}
    
    # Check product permission
    if req.product_id:
        try:
            products = json.loads(row["products"])
            if req.product_id not in products and "*" not in products:
                conn.execute(
                    "INSERT INTO validation_log (license_key, machine_id, product_id, result, timestamp) VALUES (?,?,?,?,?)",
                    (req.license_key, req.machine_id, req.product_id, "DENIED_PRODUCT", now)
                )
                conn.commit()
                conn.close()
                return {"status": "denied", "reason": f"License does not include {req.product_id}"}
        except:
            pass
    
    # All good
    conn.execute(
        "UPDATE licenses SET last_validated = ? WHERE license_key = ?",
        (now, req.license_key)
    )
    conn.execute(
        "INSERT INTO validation_log (license_key, machine_id, product_id, result, timestamp) VALUES (?,?,?,?,?)",
        (req.license_key, req.machine_id, req.product_id, "APPROVED", now)
    )
    conn.commit()
    conn.close()
    
    return {"status": "approved", "message": "License valid"}


# ═══════════════════════════════════════════════════════════════
# ADMIN LOGIN
# ═══════════════════════════════════════════════════════════════

@app.get("/admin/login", response_class=HTMLResponse)
async def admin_login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.post("/admin/login")
async def admin_login(request: Request, password: str = Form(...)):
    if password == ADMIN_PASSWORD:
        response = RedirectResponse(url="/admin", status_code=303)
        response.set_cookie("admin_token", hash_token(ADMIN_PASSWORD), httponly=True, max_age=86400)
        return response
    return templates.TemplateResponse("login.html", {"request": request, "error": "Wrong password"})

@app.get("/admin/logout")
async def admin_logout():
    response = RedirectResponse(url="/admin/login")
    response.delete_cookie("admin_token")
    return response


# ═══════════════════════════════════════════════════════════════
# ADMIN PANEL
# ═══════════════════════════════════════════════════════════════

@app.get("/admin", response_class=HTMLResponse)
async def admin_panel(request: Request):
    if not verify_admin(request):
        return RedirectResponse(url="/admin/login")
    
    conn = get_db()
    licenses = conn.execute("SELECT * FROM licenses ORDER BY created_at DESC").fetchall()
    recent_logs = conn.execute(
        "SELECT * FROM validation_log ORDER BY timestamp DESC LIMIT 50"
    ).fetchall()
    conn.close()
    
    return templates.TemplateResponse("admin.html", {
        "request": request,
        "licenses": licenses,
        "logs": recent_logs
    })

@app.post("/admin/create")
async def admin_create_license(
    request: Request,
    email: str = Form(""),
    products: str = Form('["ME_Dashboard","HFT_Dashboard"]'),
    expiry_date: str = Form(""),
    notes: str = Form("")
):
    if not verify_admin(request):
        return RedirectResponse(url="/admin/login")
    
    conn = get_db()
    key = generate_license_key()
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    
    conn.execute(
        "INSERT INTO licenses (license_key, email, products, expiry_date, created_at, notes) VALUES (?,?,?,?,?,?)",
        (key, email, products, expiry_date, now, notes)
    )
    conn.commit()
    conn.close()
    
    return RedirectResponse(url="/admin", status_code=303)

@app.post("/admin/toggle/{license_id}")
async def admin_toggle_license(request: Request, license_id: int):
    if not verify_admin(request):
        return RedirectResponse(url="/admin/login")
    
    conn = get_db()
    row = conn.execute("SELECT active FROM licenses WHERE id = ?", (license_id,)).fetchone()
    if row:
        new_status = 0 if row["active"] else 1
        conn.execute("UPDATE licenses SET active = ? WHERE id = ?", (new_status, license_id))
        conn.commit()
    conn.close()
    
    return RedirectResponse(url="/admin", status_code=303)

@app.post("/admin/reset-machine/{license_id}")
async def admin_reset_machine(request: Request, license_id: int):
    if not verify_admin(request):
        return RedirectResponse(url="/admin/login")
    
    conn = get_db()
    conn.execute("UPDATE licenses SET machine_id = '' WHERE id = ?", (license_id,))
    conn.commit()
    conn.close()
    
    return RedirectResponse(url="/admin", status_code=303)

@app.post("/admin/delete/{license_id}")
async def admin_delete_license(request: Request, license_id: int):
    if not verify_admin(request):
        return RedirectResponse(url="/admin/login")
    
    conn = get_db()
    conn.execute("DELETE FROM licenses WHERE id = ?", (license_id,))
    conn.commit()
    conn.close()
    
    return RedirectResponse(url="/admin", status_code=303)


# ═══════════════════════════════════════════════════════════════
# AUTHORIZE.NET WEBHOOK (future)
# ═══════════════════════════════════════════════════════════════

@app.post("/api/webhook/authorize")
async def authorize_webhook(request: Request):
    """Placeholder for Authorize.net webhook integration"""
    body = await request.json()
    # TODO: Verify webhook signature
    # TODO: Extract email + product from payment
    # TODO: Generate license key
    # TODO: Trigger Keap email with key
    return {"status": "received"}


# ═══════════════════════════════════════════════════════════════
# HEALTH CHECK
# ═══════════════════════════════════════════════════════════════

@app.get("/")
async def root():
    return {"status": "online", "service": "TOP EZ License Server"}

@app.get("/health")
async def health():
    return {"status": "healthy"}
