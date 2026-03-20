"""
TOP EZ License Server v4
- License validation with per-platform machine locking (NT8 with machine_id, TS without)
- Admin panel with license management
- File upload for product delivery ZIPs (4 files: ME_NT8, HFT_NT8, ME_TS, HFT_TS)
- Authorize.net webhook for auto-provisioning
- Keap OAuth integration for CRM tagging
- Email delivery of license key + download links to buyers
"""

import os
import json
import uuid
import hashlib
import secrets
from datetime import datetime, timedelta
from pathlib import Path

from fastapi import FastAPI, Request, HTTPException, UploadFile, File, Form, Depends, Response
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from typing import Optional, List
import httpx

# ═══════════════════════════════════════════════════════════════
# CONFIG
# ═══════════════════════════════════════════════════════════════

DATABASE_FILE = os.environ.get("DATABASE_FILE", "/data/licenses.json")
UPLOADS_DIR = os.environ.get("UPLOADS_DIR", "/data/uploads")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "topez2024admin")
SESSION_SECRET = os.environ.get("SESSION_SECRET", secrets.token_hex(32))
BASE_URL = os.environ.get("BASE_URL", "https://web-production-272d8.up.railway.app")

# Authorize.net
AUTHORIZE_LOGIN_ID = os.environ.get("AUTHORIZE_LOGIN_ID", "9bx3f3rQHaq")

# Keap
KEAP_CLIENT_ID = os.environ.get("KEAP_CLIENT_ID", "lPsO8u88W6W6jIHpRhuRMxuwakHMavPneG6XMwPsEfsXMzC1")
KEAP_CLIENT_SECRET = os.environ.get("KEAP_CLIENT_SECRET", "")
KEAP_REDIRECT_URI = f"{BASE_URL}/admin/keap/callback"

# SMTP (for email delivery)
SMTP_HOST = os.environ.get("SMTP_HOST", "")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASS = os.environ.get("SMTP_PASS", "")
SMTP_FROM = os.environ.get("SMTP_FROM", "")

app = FastAPI(title="TOP EZ License Server", version="4.0")

# Ensure directories exist
Path(UPLOADS_DIR).mkdir(parents=True, exist_ok=True)
Path(DATABASE_FILE).parent.mkdir(parents=True, exist_ok=True)


# ═══════════════════════════════════════════════════════════════
# DATABASE
# ═══════════════════════════════════════════════════════════════

def load_db():
    if os.path.exists(DATABASE_FILE):
        with open(DATABASE_FILE, "r") as f:
            return json.load(f)
    return {
        "licenses": {},
        "validation_log": [],
        "keap_tokens": {},
        "settings": {
            "product_files": {
                "TOP_EZ_Complete": ""
            }
        }
    }

def save_db(db):
    with open(DATABASE_FILE, "w") as f:
        json.dump(db, f, indent=2, default=str)

def generate_key():
    parts = [secrets.token_hex(2).upper() for _ in range(4)]
    return f"TOPEZ-{parts[0]}-{parts[1]}-{parts[2]}-{parts[3]}"


# ═══════════════════════════════════════════════════════════════
# MODELS
# ═══════════════════════════════════════════════════════════════

class ValidateRequest(BaseModel):
    license_key: str
    machine_id: Optional[str] = None
    product_id: Optional[str] = None


# ═══════════════════════════════════════════════════════════════
# SESSION MANAGEMENT
# ═══════════════════════════════════════════════════════════════

active_sessions = {}

def check_admin(request: Request):
    session_id = request.cookies.get("session_id")
    if not session_id or session_id not in active_sessions:
        raise HTTPException(status_code=303, headers={"Location": "/admin/login"})
    if active_sessions[session_id]["expires"] < datetime.now():
        del active_sessions[session_id]
        raise HTTPException(status_code=303, headers={"Location": "/admin/login"})
    return True


# ═══════════════════════════════════════════════════════════════
# LICENSE VALIDATION API
# ═══════════════════════════════════════════════════════════════

@app.post("/api/validate")
async def validate_license(req: ValidateRequest):
    db = load_db()
    key = req.license_key.strip()
    machine_id = (req.machine_id or "").strip()
    product_id = (req.product_id or "").strip()

    # Find license
    if key not in db["licenses"]:
        log_validation(db, key, machine_id, product_id, "denied", "Key not found")
        save_db(db)
        return {"status": "denied", "reason": "Invalid license key"}

    lic = db["licenses"][key]

    # Check if active
    if lic.get("status") != "active":
        log_validation(db, key, machine_id, product_id, "denied", f"License {lic.get('status')}")
        save_db(db)
        return {"status": "denied", "reason": "License is not active"}

    # Check expiry
    if lic.get("expiry") and lic["expiry"] != "Never":
        try:
            exp_date = datetime.fromisoformat(lic["expiry"])
            if datetime.now() > exp_date:
                log_validation(db, key, machine_id, product_id, "denied", "Expired")
                save_db(db)
                return {"status": "denied", "reason": "License has expired"}
        except:
            pass

    # Check product
    products = lic.get("products", [])
    if product_id and product_id not in products:
        log_validation(db, key, machine_id, product_id, "denied", f"Product {product_id} not in {products}")
        save_db(db)
        return {"status": "denied", "reason": f"License not valid for {product_id}"}

    # ═══════════════════════════════════════════════════════════
    # MACHINE LOCKING LOGIC (per-platform)
    # ═══════════════════════════════════════════════════════════
    # 
    # Strategy:
    # - NT8 sends machine_id WITHOUT "TS-" prefix (e.g. "DESKTOP-ABC_Leslie")
    # - TS sends machine_id WITH "TS-" prefix (e.g. "TS-48271653-91037284")
    # - Per key: max 1 NT8 machine + 1 TS device
    # - machine_locks: {"nt8": "DESKTOP-ABC_Leslie", "ts": "TS-48271653-91037284"}
    
    if "machine_locks" not in lic:
        lic["machine_locks"] = {}

    locks = lic["machine_locks"]

    if machine_id:
        if machine_id.startswith("TS-"):
            # TradeStation path: machine_id starts with "TS-"
            current_ts_machine = locks.get("ts", "")
            if current_ts_machine == "" or current_ts_machine == machine_id:
                locks["ts"] = machine_id
            else:
                log_validation(db, key, machine_id, product_id, "denied",
                              f"TS locked to {current_ts_machine}")
                save_db(db)
                return {
                    "status": "denied",
                    "reason": "License is locked to a different machine"
                }
        else:
            # NinjaTrader path: no "TS-" prefix
            current_nt8_machine = locks.get("nt8", "")
            if current_nt8_machine == "" or current_nt8_machine == machine_id:
                locks["nt8"] = machine_id
            else:
                log_validation(db, key, machine_id, product_id, "denied", 
                              f"NT8 locked to {current_nt8_machine}")
                save_db(db)
                return {
                    "status": "denied",
                    "reason": "License is locked to a different machine"
                }

    # Update last check
    lic["last_check"] = datetime.now().isoformat()
    lic["machine_locks"] = locks
    db["licenses"][key] = lic

    log_validation(db, key, machine_id or "(TS-no-machine)", product_id, "approved", "OK")
    save_db(db)

    return {"status": "approved", "message": "License valid"}


def log_validation(db, key, machine_id, product_id, result, detail):
    entry = {
        "time": datetime.now().isoformat(),
        "key": key[:15] + "..." if len(key) > 15 else key,
        "machine": machine_id or "(none)",
        "product": product_id or "(none)",
        "result": result,
        "detail": detail
    }
    if "validation_log" not in db:
        db["validation_log"] = []
    db["validation_log"].insert(0, entry)
    # Keep last 100 entries
    db["validation_log"] = db["validation_log"][:100]


# ═══════════════════════════════════════════════════════════════
# ADMIN: LOGIN
# ═══════════════════════════════════════════════════════════════

@app.get("/admin/login", response_class=HTMLResponse)
async def admin_login_page():
    return """<!DOCTYPE html>
<html><head><title>TOP EZ License Server - Login</title>
<style>
body { font-family: -apple-system, sans-serif; background: #1a1a2e; color: #fff; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
.login-box { background: #16213e; padding: 40px; border-radius: 12px; width: 350px; }
h2 { text-align: center; color: #0ff; margin-bottom: 30px; }
input { width: 100%; padding: 12px; margin: 8px 0; border: 1px solid #333; border-radius: 6px; background: #0f3460; color: #fff; box-sizing: border-box; font-size: 16px; }
button { width: 100%; padding: 12px; background: #0ff; color: #000; border: none; border-radius: 6px; cursor: pointer; font-size: 16px; font-weight: bold; margin-top: 15px; }
button:hover { background: #0dd; }
</style></head><body>
<div class="login-box">
<h2>TOP EZ License Server</h2>
<form method="POST" action="/admin/login">
<input type="password" name="password" placeholder="Admin Password" required>
<button type="submit">Login</button>
</form></div></body></html>"""

@app.post("/admin/login")
async def admin_login(request: Request):
    form = await request.form()
    password = form.get("password", "")
    if password == ADMIN_PASSWORD:
        session_id = secrets.token_hex(32)
        active_sessions[session_id] = {"expires": datetime.now() + timedelta(hours=24)}
        response = RedirectResponse(url="/admin", status_code=303)
        response.set_cookie("session_id", session_id, httponly=True, max_age=86400)
        return response
    return RedirectResponse(url="/admin/login", status_code=303)


# ═══════════════════════════════════════════════════════════════
# ADMIN: DASHBOARD
# ═══════════════════════════════════════════════════════════════

@app.get("/admin", response_class=HTMLResponse)
async def admin_dashboard(request: Request):
    session_id = request.cookies.get("session_id")
    if not session_id or session_id not in active_sessions:
        return RedirectResponse(url="/admin/login")
    if active_sessions[session_id]["expires"] < datetime.now():
        return RedirectResponse(url="/admin/login")

    db = load_db()
    licenses = db.get("licenses", {})
    logs = db.get("validation_log", [])[:20]
    settings = db.get("settings", {})
    product_files = settings.get("product_files", {})
    keap_connected = bool(db.get("keap_tokens", {}).get("access_token"))

    # Stats
    total = len(licenses)
    active = sum(1 for l in licenses.values() if l.get("status") == "active")
    inactive = total - active

    # Build license rows
    license_rows = ""
    for key, lic in licenses.items():
        products_html = ""
        for p in lic.get("products", []):
            products_html += f'<span class="badge">{p}</span>'
        
        machine_info = ""
        locks = lic.get("machine_locks", {})
        if locks.get("nt8"):
            machine_info += f'NT8: {locks["nt8"]}'
        if locks.get("ts"):
            if machine_info:
                machine_info += " | "
            machine_info += f'TS: {locks["ts"]}'
        if not machine_info:
            machine_info = "-"

        status_class = "active" if lic.get("status") == "active" else "inactive"
        
        license_rows += f"""<tr>
<td><code>{key}</code></td>
<td>{lic.get('email', '-')}</td>
<td>{machine_info}</td>
<td>{products_html}</td>
<td><span class="status-{status_class}">{lic.get('status', 'unknown')}</span></td>
<td>{lic.get('expiry', 'Never')}</td>
<td>{lic.get('last_check', 'Never')[:16] if lic.get('last_check') else 'Never'}</td>
<td>{lic.get('notes', '')}</td>
<td>
<form method="POST" action="/admin/deactivate" style="display:inline">
<input type="hidden" name="key" value="{key}">
<button class="btn-danger" type="submit">Deactivate</button>
</form>
<form method="POST" action="/admin/reset-machine" style="display:inline">
<input type="hidden" name="key" value="{key}">
<button class="btn-warning" type="submit">Reset Machine</button>
</form>
<form method="POST" action="/admin/delete" style="display:inline">
<input type="hidden" name="key" value="{key}">
<button class="btn-delete" type="submit" onclick="return confirm('Delete this license?')">Delete</button>
</form>
</td></tr>"""

    # Build log rows
    log_rows = ""
    for entry in logs:
        result_class = "approved" if entry.get("result") == "approved" else "denied"
        log_rows += f"""<tr>
<td>{entry.get('time', '')[:19]}</td>
<td><code>{entry.get('key', '')}</code></td>
<td>{entry.get('machine', '')}</td>
<td>{entry.get('product', '')}</td>
<td><span class="result-{result_class}">{entry.get('result', '')}</span></td>
</tr>"""

    # Product files status
    file_status = {}
    for fname, fpath in product_files.items():
        if fpath and os.path.exists(os.path.join(UPLOADS_DIR, fpath)):
            file_status[fname] = f'✅ {fpath}'
        else:
            file_status[fname] = '❌ Not uploaded'

    webhook_url = f"{BASE_URL}/api/webhook/authorize"

    return f"""<!DOCTYPE html>
<html><head><title>TOP EZ License Server</title>
<style>
* {{ box-sizing: border-box; }}
body {{ font-family: -apple-system, sans-serif; background: #1a1a2e; color: #eee; margin: 0; padding: 20px; }}
h1 {{ color: #0ff; margin-bottom: 5px; }}
h2 {{ color: #0ff; margin-top: 30px; border-bottom: 1px solid #333; padding-bottom: 8px; }}
.stats {{ display: flex; gap: 20px; margin: 20px 0; }}
.stat-box {{ background: #16213e; padding: 20px 30px; border-radius: 10px; text-align: center; min-width: 120px; }}
.stat-box .number {{ font-size: 36px; font-weight: bold; color: #0ff; }}
.stat-box .label {{ font-size: 12px; color: #888; text-transform: uppercase; }}
table {{ width: 100%; border-collapse: collapse; margin: 15px 0; }}
th {{ background: #16213e; padding: 10px; text-align: left; color: #0ff; font-size: 12px; text-transform: uppercase; }}
td {{ padding: 8px 10px; border-bottom: 1px solid #222; font-size: 13px; }}
tr:hover {{ background: #16213e44; }}
code {{ background: #0f3460; padding: 2px 6px; border-radius: 3px; font-size: 12px; }}
.badge {{ background: #0f3460; color: #0ff; padding: 2px 8px; border-radius: 10px; font-size: 11px; margin: 0 2px; display: inline-block; }}
.status-active {{ background: #0a5; color: #fff; padding: 2px 10px; border-radius: 10px; font-size: 12px; }}
.status-inactive {{ background: #a00; color: #fff; padding: 2px 10px; border-radius: 10px; font-size: 12px; }}
.result-approved {{ color: #0f0; font-weight: bold; }}
.result-denied {{ color: #f44; font-weight: bold; }}
.btn-danger {{ background: #c00; color: #fff; border: none; padding: 4px 10px; border-radius: 4px; cursor: pointer; font-size: 11px; }}
.btn-warning {{ background: #f80; color: #fff; border: none; padding: 4px 10px; border-radius: 4px; cursor: pointer; font-size: 11px; }}
.btn-delete {{ background: #600; color: #fff; border: none; padding: 4px 10px; border-radius: 4px; cursor: pointer; font-size: 11px; }}
.btn-success {{ background: #0a5; color: #fff; border: none; padding: 8px 20px; border-radius: 6px; cursor: pointer; font-size: 14px; font-weight: bold; }}
.btn-primary {{ background: #06d; color: #fff; border: none; padding: 8px 20px; border-radius: 6px; cursor: pointer; font-size: 14px; }}
input, select {{ padding: 8px; border: 1px solid #333; border-radius: 4px; background: #0f3460; color: #fff; }}
.form-row {{ display: flex; gap: 10px; align-items: end; flex-wrap: wrap; margin: 10px 0; }}
.form-group {{ display: flex; flex-direction: column; gap: 4px; }}
.form-group label {{ font-size: 11px; color: #888; text-transform: uppercase; }}
.section {{ background: #16213e; padding: 20px; border-radius: 10px; margin: 15px 0; }}
.copy-btn {{ background: #333; border: 1px solid #555; color: #fff; padding: 4px 10px; border-radius: 4px; cursor: pointer; font-size: 11px; }}
.copy-btn:hover {{ background: #555; }}
.file-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 15px; }}
.file-card {{ background: #0f3460; padding: 15px; border-radius: 8px; }}
.file-card h4 {{ margin: 0 0 10px 0; color: #0ff; font-size: 14px; }}
.file-status {{ font-size: 12px; margin: 5px 0; }}
.logout {{ float: right; color: #888; text-decoration: none; font-size: 13px; }}
.logout:hover {{ color: #fff; }}
</style></head><body>

<a href="/admin/logout" class="logout">Logout</a>
<h1>TOP EZ License Server</h1>

<div class="stats">
<div class="stat-box"><div class="number">{total}</div><div class="label">Total Licenses</div></div>
<div class="stat-box"><div class="number">{active}</div><div class="label">Active</div></div>
<div class="stat-box"><div class="number">{inactive}</div><div class="label">Inactive</div></div>
</div>

<!-- Integrations -->
<h2>Integrations</h2>
<div class="section">
<div class="form-row">
<div class="form-group">
<label>Authorize.net Webhook URL</label>
<div style="display:flex;gap:8px;align-items:center">
<code id="webhookUrl">{webhook_url}</code>
<button class="copy-btn" onclick="navigator.clipboard.writeText(document.getElementById('webhookUrl').textContent)">Copy</button>
</div>
</div>
</div>
<div class="form-row" style="margin-top:15px">
<div class="form-group">
<label>Keap Email</label>
<span>{'Connected' if keap_connected else 'Not connected'}</span>
</div>
<a href="/admin/keap/connect"><button class="btn-primary">{'Reconnect' if keap_connected else 'Connect'} Keap</button></a>
</div>
</div>

<!-- Product Files -->
<h2>Product File (for delivery)</h2>
<div class="section">
<div class="file-card" style="max-width:500px">
<h4>TOP EZ Dashboard Complete Package</h4>
<div class="file-status">{file_status.get('TOP_EZ_Complete', '❌')}</div>
<p style="font-size:12px;color:#888;margin:5px 0">Upload a single ZIP containing all 4 dashboard files (ME + HFT for NT8 and TradeStation)</p>
<form method="POST" action="/admin/upload-product" enctype="multipart/form-data">
<input type="hidden" name="product_key" value="TOP_EZ_Complete">
<input type="file" name="file" accept=".zip" style="font-size:12px;margin:5px 0">
<button class="btn-primary" type="submit" style="font-size:12px;padding:4px 12px">Upload</button>
</form>
</div>
</div>

<!-- Create License -->
<h2>Create New License</h2>
<div class="section">
<form method="POST" action="/admin/create">
<div class="form-row">
<div class="form-group">
<label>Email</label>
<input type="email" name="email" placeholder="customer@email.com">
</div>
<div class="form-group">
<label>Products (JSON)</label>
<input type="text" name="products" value='["ME_Dashboard","HFT_Dashboard"]' style="width:250px">
</div>
<div class="form-group">
<label>Expiry (YYYY-MM-DD or empty)</label>
<input type="text" name="expiry" placeholder="Never">
</div>
<div class="form-group">
<label>Notes</label>
<input type="text" name="notes" placeholder="Optional note">
</div>
<button class="btn-success" type="submit">Generate Key</button>
</div>
</form>
</div>

<!-- Licenses -->
<h2>Licenses</h2>
<table>
<tr><th>Key</th><th>Email</th><th>Machine</th><th>Products</th><th>Status</th><th>Expiry</th><th>Last Check</th><th>Notes</th><th>Actions</th></tr>
{license_rows}
</table>

<!-- Validation Log -->
<h2>Recent Validation Log</h2>
<table>
<tr><th>Time</th><th>Key</th><th>Machine</th><th>Product</th><th>Result</th></tr>
{log_rows}
</table>

</body></html>"""


# ═══════════════════════════════════════════════════════════════
# ADMIN: ACTIONS
# ═══════════════════════════════════════════════════════════════

@app.get("/admin/logout")
async def admin_logout(request: Request):
    session_id = request.cookies.get("session_id")
    if session_id and session_id in active_sessions:
        del active_sessions[session_id]
    response = RedirectResponse(url="/admin/login")
    response.delete_cookie("session_id")
    return response

@app.post("/admin/create")
async def admin_create(request: Request):
    session_id = request.cookies.get("session_id")
    if not session_id or session_id not in active_sessions:
        return RedirectResponse(url="/admin/login")

    form = await request.form()
    email = form.get("email", "")
    products_str = form.get("products", '["ME_Dashboard","HFT_Dashboard"]')
    expiry = form.get("expiry", "").strip() or "Never"
    notes = form.get("notes", "")

    try:
        products = json.loads(products_str)
    except:
        products = ["ME_Dashboard", "HFT_Dashboard"]

    key = generate_key()
    db = load_db()
    db["licenses"][key] = {
        "email": email,
        "products": products,
        "status": "active",
        "expiry": expiry,
        "notes": notes,
        "created": datetime.now().isoformat(),
        "last_check": None,
        "machine_locks": {}
    }
    save_db(db)
    return RedirectResponse(url="/admin", status_code=303)

@app.post("/admin/deactivate")
async def admin_deactivate(request: Request):
    session_id = request.cookies.get("session_id")
    if not session_id or session_id not in active_sessions:
        return RedirectResponse(url="/admin/login")

    form = await request.form()
    key = form.get("key")
    db = load_db()
    if key in db["licenses"]:
        db["licenses"][key]["status"] = "inactive"
        save_db(db)
    return RedirectResponse(url="/admin", status_code=303)

@app.post("/admin/reset-machine")
async def admin_reset_machine(request: Request):
    session_id = request.cookies.get("session_id")
    if not session_id or session_id not in active_sessions:
        return RedirectResponse(url="/admin/login")

    form = await request.form()
    key = form.get("key")
    db = load_db()
    if key in db["licenses"]:
        db["licenses"][key]["machine_locks"] = {}
        save_db(db)
    return RedirectResponse(url="/admin", status_code=303)

@app.post("/admin/delete")
async def admin_delete(request: Request):
    session_id = request.cookies.get("session_id")
    if not session_id or session_id not in active_sessions:
        return RedirectResponse(url="/admin/login")

    form = await request.form()
    key = form.get("key")
    db = load_db()
    if key in db["licenses"]:
        del db["licenses"][key]
        save_db(db)
    return RedirectResponse(url="/admin", status_code=303)


# ═══════════════════════════════════════════════════════════════
# ADMIN: PRODUCT FILE UPLOAD
# ═══════════════════════════════════════════════════════════════

@app.post("/admin/upload-product")
async def upload_product(request: Request, product_key: str = Form(...), file: UploadFile = File(...)):
    session_id = request.cookies.get("session_id")
    if not session_id or session_id not in active_sessions:
        return RedirectResponse(url="/admin/login")

    valid_keys = ["TOP_EZ_Complete"]
    if product_key not in valid_keys:
        return RedirectResponse(url="/admin", status_code=303)

    # Save file
    filename = f"{product_key}.zip"
    filepath = os.path.join(UPLOADS_DIR, filename)
    content = await file.read()
    with open(filepath, "wb") as f:
        f.write(content)

    # Update settings
    db = load_db()
    if "settings" not in db:
        db["settings"] = {}
    if "product_files" not in db["settings"]:
        db["settings"]["product_files"] = {}
    db["settings"]["product_files"][product_key] = filename
    save_db(db)

    return RedirectResponse(url="/admin", status_code=303)


# ═══════════════════════════════════════════════════════════════
# DOWNLOAD ENDPOINT (for product files)
# ═══════════════════════════════════════════════════════════════

@app.get("/api/download/{product_key}")
async def download_product(product_key: str, key: str = ""):
    """Download product file - requires valid license key as query param"""
    if not key:
        raise HTTPException(status_code=401, detail="License key required")

    db = load_db()
    
    # Validate the key
    if key not in db["licenses"]:
        raise HTTPException(status_code=401, detail="Invalid license key")
    
    lic = db["licenses"][key]
    if lic.get("status") != "active":
        raise HTTPException(status_code=401, detail="License not active")

    # Check product file exists
    settings = db.get("settings", {})
    product_files = settings.get("product_files", {})
    filename = product_files.get(product_key, "")
    
    if not filename:
        raise HTTPException(status_code=404, detail="Product file not available")
    
    filepath = os.path.join(UPLOADS_DIR, filename)
    if not os.path.exists(filepath):
        raise HTTPException(status_code=404, detail="File not found")
    
    return FileResponse(filepath, filename=filename, media_type="application/zip")


# ═══════════════════════════════════════════════════════════════
# AUTHORIZE.NET WEBHOOK
# ═══════════════════════════════════════════════════════════════

@app.post("/api/webhook/authorize")
async def authorize_webhook(request: Request):
    """Handle Authorize.net payment notifications - auto-provision license"""
    try:
        body = await request.json()
    except:
        body = {}

    # Extract customer email from webhook payload
    email = ""
    try:
        # Authorize.net webhook format varies - try common paths
        if "payload" in body:
            payload = body["payload"]
            if "customerEmail" in payload:
                email = payload["customerEmail"]
            elif "billTo" in payload:
                email = payload["billTo"].get("email", "")
        elif "customerEmail" in body:
            email = body["customerEmail"]
    except:
        pass

    if not email:
        email = f"webhook-{datetime.now().strftime('%Y%m%d%H%M%S')}@unknown.com"

    # Auto-generate license
    key = generate_key()
    db = load_db()
    db["licenses"][key] = {
        "email": email,
        "products": ["ME_Dashboard", "HFT_Dashboard"],
        "status": "active",
        "expiry": "Never",
        "notes": "Auto-provisioned via Authorize.net",
        "created": datetime.now().isoformat(),
        "last_check": None,
        "machine_locks": {},
        "webhook_data": json.dumps(body)[:500]
    }
    save_db(db)

    # Try to send email with license key + download links
    await send_license_email(email, key, db)

    # Try to tag in Keap
    await tag_keap_contact(email, key, db)

    return {"status": "ok", "key": key}


# ═══════════════════════════════════════════════════════════════
# EMAIL DELIVERY
# ═══════════════════════════════════════════════════════════════

async def send_license_email(email: str, key: str, db: dict):
    """Send license key and download links to customer"""
    if not SMTP_HOST or not SMTP_USER:
        print(f"SMTP not configured - skipping email to {email}")
        return

    try:
        import smtplib
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart

        download_link = f"{BASE_URL}/api/download/TOP_EZ_Complete?key={key}"
        
        html = f"""
<html><body style="font-family: Arial, sans-serif; background: #f5f5f5; padding: 20px;">
<div style="max-width: 600px; margin: 0 auto; background: #fff; border-radius: 10px; padding: 30px;">
<h1 style="color: #0066cc; text-align: center;">TOP EZ Dashboard</h1>
<h2 style="text-align: center;">Your License Key</h2>
<div style="background: #f0f8ff; border: 2px solid #0066cc; border-radius: 8px; padding: 20px; text-align: center; margin: 20px 0;">
<code style="font-size: 24px; font-weight: bold; color: #333;">{key}</code>
</div>
<h3>Download Your Dashboards:</h3>
<p style="text-align: center;"><a href="{download_link}" style="display: inline-block; background: #0066cc; color: #fff; padding: 12px 30px; border-radius: 6px; text-decoration: none; font-weight: bold; font-size: 16px;">Download TOP EZ Dashboard Package</a></p>
<p style="text-align: center; color: #888; font-size: 12px;">Contains ME + HFT dashboards for both NinjaTrader 8 and TradeStation</p>
<h3>Installation:</h3>
<ol>
<li>Download and extract the ZIP file</li>
<li>Install the dashboard for your platform (NinjaTrader 8 or TradeStation)</li>
<li>Enter your license key when prompted</li>
</ol>
<p style="color: #888; font-size: 12px; margin-top: 30px; text-align: center;">
This license is valid for one computer. If you need to transfer it, contact support.
</p>
</div></body></html>"""

        msg = MIMEMultipart("alternative")
        msg["Subject"] = "Your TOP EZ Dashboard License Key"
        msg["From"] = SMTP_FROM or SMTP_USER
        msg["To"] = email
        msg.attach(MIMEText(html, "html"))

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.send_message(msg)
        
        print(f"License email sent to {email}")
    except Exception as e:
        print(f"Email send error: {e}")


# ═══════════════════════════════════════════════════════════════
# KEAP OAUTH
# ═══════════════════════════════════════════════════════════════

@app.get("/admin/keap/connect")
async def keap_connect(request: Request):
    session_id = request.cookies.get("session_id")
    if not session_id or session_id not in active_sessions:
        return RedirectResponse(url="/admin/login")

    auth_url = (
        f"https://accounts.infusionsoft.com/app/oauth/authorize"
        f"?client_id={KEAP_CLIENT_ID}"
        f"&redirect_uri={KEAP_REDIRECT_URI}"
        f"&response_type=code"
        f"&scope=full"
    )
    return RedirectResponse(url=auth_url)

@app.get("/admin/keap/callback")
async def keap_callback(request: Request, code: str = ""):
    if not code:
        return RedirectResponse(url="/admin")

    try:
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                "https://api.infusionsoft.com/token",
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "client_id": KEAP_CLIENT_ID,
                    "client_secret": KEAP_CLIENT_SECRET,
                    "redirect_uri": KEAP_REDIRECT_URI
                }
            )
            tokens = resp.json()
    except Exception as e:
        print(f"Keap token error: {e}")
        return RedirectResponse(url="/admin")

    db = load_db()
    db["keap_tokens"] = {
        "access_token": tokens.get("access_token", ""),
        "refresh_token": tokens.get("refresh_token", ""),
        "expires_at": (datetime.now() + timedelta(seconds=tokens.get("expires_in", 86400))).isoformat()
    }
    save_db(db)
    return RedirectResponse(url="/admin")


async def tag_keap_contact(email: str, key: str, db: dict):
    """Tag contact in Keap as license holder and set license custom fields"""
    tokens = db.get("keap_tokens", {})
    access_token = tokens.get("access_token")
    if not access_token:
        print("Keap not connected - skipping tag")
        return

    # Build download link
    download_link = f"{BASE_URL}/api/download/TOP_EZ_Complete?key={key}"

    try:
        async with httpx.AsyncClient() as client:
            headers = {
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json"
            }

            # Find or create contact
            resp = await client.get(
                f"https://api.infusionsoft.com/crm/rest/v1/contacts?email={email}&optional_properties=custom_fields",
                headers=headers
            )
            contacts = resp.json().get("contacts", [])

            if contacts:
                contact_id = contacts[0]["id"]
                existing_fields = contacts[0].get("custom_fields", [])
            else:
                # Create contact with marketable email status
                resp = await client.post(
                    "https://api.infusionsoft.com/crm/rest/v1/contacts",
                    headers=headers,
                    json={
                        "email_addresses": [{"email": email, "field": "EMAIL1"}],
                        "opt_in_reason": "Purchased TOP EZ Dashboard"
                    }
                )
                result = resp.json()
                contact_id = result.get("id")
                existing_fields = result.get("custom_fields", [])

            if not contact_id:
                print("Keap: Could not find or create contact")
                return

            # Find custom field IDs by matching field name
            license_key_field_id = None
            download_links_field_id = None

            # Get all custom fields from the contact model
            model_resp = await client.get(
                "https://api.infusionsoft.com/crm/rest/v1/contacts/model",
                headers=headers
            )
            model_data = model_resp.json()
            custom_fields_model = model_data.get("custom_fields", [])

            for field in custom_fields_model:
                label = field.get("label", "")
                if "License Key" in label and "TOP EZ" in label:
                    license_key_field_id = field.get("id")
                    print(f"Keap: Found License Key field ID: {license_key_field_id}")
                elif "Download Links" in label and "TOP EZ" in label:
                    download_links_field_id = field.get("id")
                    print(f"Keap: Found Download Links field ID: {download_links_field_id}")

            # Build custom fields update array
            custom_fields_update = []
            if license_key_field_id:
                custom_fields_update.append({"content": key, "id": license_key_field_id})
            if download_links_field_id:
                custom_fields_update.append({"content": download_link, "id": download_links_field_id})

            # Update contact with custom fields and ensure marketable status
            if custom_fields_update:
                update_resp = await client.patch(
                    f"https://api.infusionsoft.com/crm/rest/v1/contacts/{contact_id}",
                    headers=headers,
                    json={
                        "custom_fields": custom_fields_update,
                        "opt_in_reason": "Purchased TOP EZ Dashboard"
                    }
                )
                print(f"Keap: Updated custom fields for contact {contact_id}: {update_resp.status_code}")
                if update_resp.status_code != 200:
                    print(f"Keap: Custom field update response: {update_resp.text}")
            else:
                print("Keap: Could not find custom field IDs - skipping field update")

            # Find tag ID for "Licensed Customer"
            tag_resp = await client.get(
                "https://api.infusionsoft.com/crm/rest/v1/tags?name=Licensed Customer&limit=100",
                headers=headers
            )
            tag_data = tag_resp.json()
            tag_id = None
            for tag in tag_data.get("tags", []):
                if tag.get("name") == "Licensed Customer":
                    tag_id = tag["id"]
                    break

            if tag_id:
                await client.post(
                    f"https://api.infusionsoft.com/crm/rest/v1/contacts/{contact_id}/tags",
                    headers=headers,
                    json={"tagIds": [tag_id]}
                )
                print(f"Keap: Tagged contact {contact_id} with 'Licensed Customer' (tag {tag_id})")
            else:
                print("Keap: Tag 'Licensed Customer' not found - skipping tag")

    except Exception as e:
        print(f"Keap tag error: {e}")
        import traceback
        traceback.print_exc()


# ═══════════════════════════════════════════════════════════════
# HEALTH CHECK
# ═══════════════════════════════════════════════════════════════

@app.get("/")
async def root():
    return {"status": "ok", "service": "TOP EZ License Server", "version": "4.0"}

@app.get("/health")
async def health():
    return {"status": "healthy"}
