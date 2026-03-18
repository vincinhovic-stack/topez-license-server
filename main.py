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
import urllib.request
import urllib.parse
import urllib.error
import base64

app = FastAPI(title="TOP EZ License Server")
templates = Jinja2Templates(directory="templates")

DATABASE = os.environ.get("DATABASE_PATH", "licenses.db")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "topez2026")
ADMIN_TOKEN_SECRET = os.environ.get("ADMIN_TOKEN_SECRET", secrets.token_hex(32))

# Authorize.net
AUTHNET_LOGIN_ID = os.environ.get("AUTHNET_LOGIN_ID", "9bx3f3rQHaq")
AUTHNET_TRANSACTION_KEY = os.environ.get("AUTHNET_TRANSACTION_KEY", "4X4V369q3Wv3zskM")

# Keap OAuth2
KEAP_CLIENT_ID = os.environ.get("KEAP_CLIENT_ID", "lPsO8u88W6W6jIHpRhuRMxuwakHMavPneG6XMwPsEfsXMzC1")
KEAP_CLIENT_SECRET = os.environ.get("KEAP_CLIENT_SECRET", "f5o9Upmg4Iz6mBAUpGkVN9E8kBdEyhuEASKu3xlCJU0NpxUMelKpVrYjgWHThfkO")
KEAP_REDIRECT_URI = os.environ.get("KEAP_REDIRECT_URI", "")  # Set after deployment
KEAP_ACCESS_TOKEN = ""  # Set via OAuth flow
KEAP_REFRESH_TOKEN = ""


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
    conn.execute("""
        CREATE TABLE IF NOT EXISTS keap_tokens (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            access_token TEXT DEFAULT '',
            refresh_token TEXT DEFAULT '',
            updated_at TEXT DEFAULT ''
        )
    """)
    conn.execute("INSERT OR IGNORE INTO keap_tokens (id) VALUES (1)")
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
    keap_row = conn.execute("SELECT * FROM keap_tokens WHERE id = 1").fetchone()
    keap_connected = keap_row and keap_row["access_token"] != "" if keap_row else False
    conn.close()
    
    return templates.TemplateResponse("admin.html", {
        "request": request,
        "licenses": licenses,
        "logs": recent_logs,
        "keap_connected": keap_connected,
        "webhook_url": str(request.base_url) + "api/webhook/authorize"
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
# KEAP OAUTH2 FLOW
# ═══════════════════════════════════════════════════════════════

def get_keap_tokens():
    conn = get_db()
    row = conn.execute("SELECT access_token, refresh_token FROM keap_tokens WHERE id = 1").fetchone()
    conn.close()
    if row:
        return row["access_token"], row["refresh_token"]
    return "", ""

def save_keap_tokens(access_token, refresh_token):
    conn = get_db()
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    conn.execute(
        "UPDATE keap_tokens SET access_token = ?, refresh_token = ?, updated_at = ? WHERE id = 1",
        (access_token, refresh_token, now)
    )
    conn.commit()
    conn.close()

@app.get("/admin/keap/connect")
async def keap_connect(request: Request):
    """Start Keap OAuth2 flow"""
    if not verify_admin(request):
        return RedirectResponse(url="/admin/login")
    
    redirect_uri = KEAP_REDIRECT_URI
    if not redirect_uri:
        # Auto-detect from request
        redirect_uri = str(request.base_url) + "admin/keap/callback"
    
    auth_url = (
        f"https://accounts.infusionsoft.com/app/oauth/authorize"
        f"?client_id={KEAP_CLIENT_ID}"
        f"&redirect_uri={urllib.parse.quote(redirect_uri)}"
        f"&response_type=code"
        f"&scope=full"
    )
    return RedirectResponse(url=auth_url)

@app.get("/admin/keap/callback")
async def keap_callback(request: Request, code: str = ""):
    """Handle Keap OAuth2 callback"""
    if not code:
        return HTMLResponse("<h3>Error: No authorization code received</h3>")
    
    redirect_uri = KEAP_REDIRECT_URI
    if not redirect_uri:
        redirect_uri = str(request.base_url) + "admin/keap/callback"
    
    # Exchange code for tokens
    try:
        token_data = urllib.parse.urlencode({
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri
        }).encode()
        
        auth_header = base64.b64encode(f"{KEAP_CLIENT_ID}:{KEAP_CLIENT_SECRET}".encode()).decode()
        
        req = urllib.request.Request(
            "https://api.infusionsoft.com/token",
            data=token_data,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Authorization": f"Basic {auth_header}"
            }
        )
        
        with urllib.request.urlopen(req) as resp:
            result = json.loads(resp.read().decode())
        
        save_keap_tokens(result["access_token"], result["refresh_token"])
        return RedirectResponse(url="/admin")
    except Exception as e:
        return HTMLResponse(f"<h3>Keap OAuth Error: {str(e)}</h3>")

def refresh_keap_token():
    """Refresh Keap access token using refresh token"""
    _, refresh_token = get_keap_tokens()
    if not refresh_token:
        return False
    
    try:
        token_data = urllib.parse.urlencode({
            "grant_type": "refresh_token",
            "refresh_token": refresh_token
        }).encode()
        
        auth_header = base64.b64encode(f"{KEAP_CLIENT_ID}:{KEAP_CLIENT_SECRET}".encode()).decode()
        
        req = urllib.request.Request(
            "https://api.infusionsoft.com/token",
            data=token_data,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Authorization": f"Basic {auth_header}"
            }
        )
        
        with urllib.request.urlopen(req) as resp:
            result = json.loads(resp.read().decode())
        
        save_keap_tokens(result["access_token"], result["refresh_token"])
        return True
    except:
        return False


# ═══════════════════════════════════════════════════════════════
# KEAP EMAIL SENDING
# ═══════════════════════════════════════════════════════════════

def send_keap_email(to_email: str, subject: str, body_html: str):
    """Send email via Keap API"""
    access_token, _ = get_keap_tokens()
    if not access_token:
        print("KEAP: No access token - skipping email")
        return False
    
    for attempt in range(2):  # Try once, refresh token if fails, try again
        try:
            email_data = json.dumps({
                "address": to_email,
                "subject": subject,
                "html_content": body_html
            }).encode()
            
            req = urllib.request.Request(
                "https://api.infusionsoft.com/crm/rest/v1/emails/queue",
                data=email_data,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {access_token}"
                },
                method="POST"
            )
            
            with urllib.request.urlopen(req) as resp:
                print(f"KEAP: Email sent to {to_email}")
                return True
                
        except urllib.error.HTTPError as e:
            if e.code == 401 and attempt == 0:
                # Token expired, try refresh
                if refresh_keap_token():
                    access_token, _ = get_keap_tokens()
                    continue
            print(f"KEAP ERROR: {e.code} {e.read().decode()}")
            return False
        except Exception as e:
            print(f"KEAP ERROR: {str(e)}")
            return False
    
    return False

def send_license_email(to_email: str, license_key: str, products: str):
    """Send license key email to customer"""
    subject = "Your TOP EZ Dashboard License Key"
    body = f"""
    <h2>Welcome to TOP EZ Dashboard!</h2>
    <p>Thank you for your purchase. Here is your license key:</p>
    <p style="font-size: 18px; font-family: Courier New, monospace; 
       background: #f0f0f0; padding: 15px; border-radius: 5px; 
       display: inline-block; font-weight: bold;">
       {license_key}
    </p>
    <p><strong>Products included:</strong> {products}</p>
    <h3>How to activate:</h3>
    <ol>
        <li>Open your dashboard in NinjaTrader 8 or TradeStation</li>
        <li>When prompted, paste your license key</li>
        <li>Click "Activate" — you're all set!</li>
    </ol>
    <p>Your key is locked to one machine. If you need to switch machines, 
       please contact us for a reset.</p>
    <p>Happy trading!</p>
    """
    return send_keap_email(to_email, subject, body)


# ═══════════════════════════════════════════════════════════════
# AUTHORIZE.NET WEBHOOK
# ═══════════════════════════════════════════════════════════════

@app.post("/api/webhook/authorize")
async def authorize_webhook(request: Request):
    """
    Authorize.net sends webhook on payment.
    We generate a license key and email it via Keap.
    
    Authorize.net webhook payload contains eventType and payload.
    For net.authorize.payment.authcapture.created events.
    """
    try:
        body = await request.json()
        print(f"AUTHNET WEBHOOK: {json.dumps(body)[:500]}")
        
        event_type = body.get("eventType", "")
        
        # Only process successful payments
        if "authcapture.created" not in event_type and "payment" not in event_type.lower():
            print(f"AUTHNET: Ignoring event type: {event_type}")
            return {"status": "ignored", "event": event_type}
        
        payload = body.get("payload", {})
        
        # Extract email from payload
        email = ""
        if "billTo" in payload:
            email = payload["billTo"].get("email", "")
        elif "customerEmail" in payload:
            email = payload["customerEmail"]
        elif "customer" in payload:
            email = payload["customer"].get("email", "")
        
        if not email:
            # Try deeper in the payload
            for key, val in payload.items():
                if isinstance(val, dict) and "email" in val:
                    email = val["email"]
                    break
        
        # Extract product info if available (from line items or description)
        products = '["ME_Dashboard","HFT_Dashboard"]'  # Default: both dashboards
        description = str(payload.get("description", ""))
        if "ME" in description and "HFT" not in description:
            products = '["ME_Dashboard"]'
        elif "HFT" in description and "ME" not in description:
            products = '["HFT_Dashboard"]'
        
        # Generate license key
        conn = get_db()
        key = generate_license_key()
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        
        conn.execute(
            "INSERT INTO licenses (license_key, email, products, created_at, notes) VALUES (?,?,?,?,?)",
            (key, email, products, now, f"Auto-generated via Authorize.net: {event_type}")
        )
        conn.commit()
        conn.close()
        
        print(f"AUTHNET: Generated key {key} for {email}")
        
        # Send email via Keap
        if email:
            send_license_email(email, key, products)
        else:
            print("AUTHNET: No email found in payload - key created but email not sent")
        
        return {"status": "processed", "license_key": key, "email": email}
        
    except Exception as e:
        print(f"AUTHNET WEBHOOK ERROR: {str(e)}")
        return {"status": "error", "message": str(e)}


# ═══════════════════════════════════════════════════════════════
# HEALTH CHECK
# ═══════════════════════════════════════════════════════════════

@app.get("/")
async def root():
    return {"status": "online", "service": "TOP EZ License Server"}

@app.get("/health")
async def health():
    return {"status": "healthy"}
