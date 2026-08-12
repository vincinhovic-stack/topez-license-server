"""
TOP EZ License Server v5 - Multi-Product
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
# Known product IDs (used for admin product selection / license assignment).
# NOTE: /api/validate is product-agnostic — it only checks whether a requested
# product_id is present in a license's own "products" list. This list only drives
# the admin UI checkboxes; it is not a global gate on validation.
KNOWN_PRODUCTS = ["ME_Dashboard", "HFT_Dashboard", "Bracket_Pro_Dashboard"]
PRODUCT_LABELS = {
    "ME_Dashboard": "ME Dashboard",
    "HFT_Dashboard": "HFT Dashboard",
    "Bracket_Pro_Dashboard": "Bracket Pro",
}
# Products pre-checked when creating a new license (business default).
# Bracket Pro is intentionally NOT pre-checked until the subscription model is
# decided with Leslie (separate license vs. bundled into the existing package).
DEFAULT_NEW_LICENSE_PRODUCTS = ["ME_Dashboard", "HFT_Dashboard"]

# Keap-driven provisioning map. ClickFunnels/Keap knows what was bought; a Keap
# campaign (triggered by the product tag) calls POST /api/keap/provision?product=<key>.
# The server then provisions ONLY that product and writes the key + download links
# back to Keap. keap_license_field_label = exact Keap custom-field label for this
# product's license key (matched case-insensitively). CONFIRM the real label from
# Keap; until then the write-back is skipped gracefully.
PRODUCT_MAP = {
    "bracket_pro": {
        "products": ["Bracket_Pro_Dashboard"],
        "keap_tag_id": 3266,                       # "06. Membership - EZ Bracket Pro"
        "download_slots": ["NT8_Bracket_Pro", "NT8_Market_Energy", "Bracket_Pro_DP", "Bracket_Pro_Guide", "TS_Bracket_Pro", "TS_Market_Energy", "TS_Dollars_Profit", "TS_Guide"],
        "keap_license_field_label": "EZ Bracket Pro License Key",   # Keap merge: [[contact.custom_fields.EZBracketProLicenseKey]]
        "keap_links_field_label": "",  # combined field no longer used - individual fields below
        # One Keap field per download. Matched by name, ignoring spaces/case, so either the
        # label ("EZ Bracket Pro ...") or the merge tag ("EZBracketPro...") works.
        "download_field_labels": {
            "NT8_Bracket_Pro":   "EZBracketProDownloadLink",       # [[contact.custom_fields.EZBracketProDownloadLink]]
            "NT8_Market_Energy": "EZBracketProMESetupIndicator",   # [[contact.custom_fields.EZBracketProMESetupIndicator]]
            "Bracket_Pro_DP":    "EZBracketProDollarsProfit",      # [[contact.custom_fields.EZBracketProDollarsProfit]]
            "Bracket_Pro_Guide": "EZBracketProUserGuide",          # [[contact.custom_fields.EZBracketProUserGuide]]
            "TS_Bracket_Pro":    "EZBracketProTSDownloadLink",     # [[contact.custom_fields.EZBracketProTSDownloadLink]]
            "TS_Market_Energy":  "EZBracketProTSMESetup",          # [[contact.custom_fields.EZBracketProTSMESetup]]
            "TS_Dollars_Profit": "EZBracketProTSDollarsProfit",    # [[contact.custom_fields.EZBracketProTSDollarsProfit]]
            "TS_Guide":          "EZBracketProTSPDFGuide",         # [[contact.custom_fields.EZBracketProTSPDFGuide]]
        },
    },
}
# Friendly labels for the download links written into Keap / the welcome email.
DOWNLOAD_LABELS = {
    "NT8_Bracket_Pro": "Bracket Pro Dashboard (NinjaTrader 8)",
    "NT8_Market_Energy": "Market Energy Setup Indicator (NinjaTrader 8)",
    "Bracket_Pro_DP": "Bracket Pro Dollars Profit Indicator (NinjaTrader 8)",
    "Bracket_Pro_Guide": "User Guide (PDF)",
    "NT8_ME": "ME Dashboard (NinjaTrader 8)",
    "NT8_HFT": "HFT Dashboard (NinjaTrader 8)",
    "TS": "TradeStation",
    "TS_Bracket_Pro": "Bracket Pro Dashboard (TradeStation)",
    "TS_Market_Energy": "Market Energy Setup Indicator (TradeStation)",
    "TS_Dollars_Profit": "Bracket Pro Dollars Profit Indicator (TradeStation)",
    "TS_Guide": "User Guide (PDF)",
    "PDF_Guides": "User Guides (PDF)",
}

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
# Shared secret Keap must include when calling /api/keap/provision (query ?token= or
# X-Provision-Token header). REQUIRED in production - without it anyone could mint keys.
PROVISION_SECRET = os.environ.get("PROVISION_SECRET", "")
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
                "NT8_ME": "",
                "NT8_HFT": "",
                "NT8_Bracket_Pro": "",
                "NT8_Market_Energy": "",
                "Bracket_Pro_DP": "",
                "TS": "",
                "TS_Bracket_Pro": "",
                "TS_Market_Energy": "",
                "TS_Dollars_Profit": "",
                "TS_Guide": "",
                "PDF_Guides": "",
                "Bracket_Pro_Guide": ""
            },
            "product_files_updated": {}
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
async def admin_dashboard(request: Request, view: str = ""):
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
    product_files_updated = settings.get("product_files_updated", {})
    keap_connected = bool(db.get("keap_tokens", {}).get("access_token"))
    # Stats
    total = len(licenses)
    active = sum(1 for l in licenses.values() if l.get("status") == "active")
    inactive = total - active
    # Count leftover webhook junk licenses (webhook-...@unknown.com)
    webhook_junk_count = sum(
        1 for l in licenses.values()
        if str(l.get("email", "")).startswith("webhook-") and str(l.get("email", "")).endswith("@unknown.com")
    )
    # Duplicate licences: same email holding more than one active key. Counts the
    # SURPLUS keys (a customer legitimately has one), so the button says exactly
    # how many would be removed.
    _by_email = {}
    for _k, _l in licenses.items():
        if _l.get("status") != "active":
            continue
        _e = str(_l.get("email", "")).strip().lower()
        if not _e:
            continue
        _by_email.setdefault(_e, []).append(_k)
    duplicate_count = sum(len(v) - 1 for v in _by_email.values() if len(v) > 1)
    duplicate_emails = sum(1 for v in _by_email.values() if len(v) > 1)
    # Keys that belong to an email holding more than one active licence
    duplicate_keys = {k for v in _by_email.values() if len(v) > 1 for k in v}
    # For each duplicated email, which key would "Merge" keep? Shown in the table so
    # nothing is deleted blind. None means no key of that customer has ever been used,
    # so the merge leaves them alone and they are handled by hand.
    keeper_by_email = {}
    unresolved_emails = set()
    for _e, _keys in _by_email.items():
        if len(_keys) < 2:
            continue
        _k = pick_keeper(licenses, _keys)
        if _k:
            keeper_by_email[_e] = _k
        else:
            unresolved_emails.add(_e)
    unresolved_count = sum(len(_by_email[_e]) for _e in unresolved_emails)
    mergeable_count = sum(
        len(_by_email[_e]) - 1 for _e in keeper_by_email
    )
    # Build license rows
    # Download slots that actually have an uploaded file -> used to show
    # copy-paste download links per license (skips slots with no file yet).
    DOWNLOAD_SLOT_LABELS = {
        "NT8_ME": "NT8 ME",
        "NT8_HFT": "NT8 HFT",
        "NT8_Bracket_Pro": "NT8 Bracket Pro",
        "NT8_Market_Energy": "NT8 Market Energy Setup",
        "Bracket_Pro_DP": "Bracket Pro Dollars Profit",
        "TS": "TradeStation",
        "TS_Bracket_Pro": "TS Bracket Pro",
        "TS_Market_Energy": "TS Market Energy Setup",
        "TS_Dollars_Profit": "TS Dollars Profit",
        "TS_Guide": "TS Guide (PDF)",
        "PDF_Guides": "PDF Guides",
        "Bracket_Pro_Guide": "Bracket Pro Guide (PDF)",
    }
    available_slots = [
        slot for slot in DOWNLOAD_SLOT_LABELS
        if product_files.get(slot) and os.path.exists(os.path.join(UPLOADS_DIR, product_files.get(slot)))
    ]
    license_rows = ""
    show_dupes_only = (view == "duplicates")
    for key, lic in licenses.items():
        if show_dupes_only and key not in duplicate_keys:
            continue
        _email_l = str(lic.get("email", "")).strip().lower()
        is_dupe = key in duplicate_keys
        keeper = keeper_by_email.get(_email_l)
        # Badge tells the operator what "Merge" would do with this row.
        if not is_dupe:
            dupe_badge = ""
        elif keeper == key:
            dupe_badge = '<div style="font-size:10px;color:#0f0;font-weight:bold">KEEP (in use)</div>'
        elif keeper:
            dupe_badge = '<div style="font-size:10px;color:#f80;font-weight:bold">duplicate &rarr; will be merged</div>'
        else:
            dupe_badge = '<div style="font-size:10px;color:#f55;font-weight:bold">duplicate &mdash; never activated, delete by hand</div>'
        row_style = ' style="background:#3a2a00"' if is_dupe else ""
        current_products = lic.get("products", [])
        checkboxes = ""
        for pid in KNOWN_PRODUCTS:
            checked = "checked" if pid in current_products else ""
            label = PRODUCT_LABELS.get(pid, pid)
            checkboxes += (
                f'<label style="display:block;font-size:11px;white-space:nowrap">'
                f'<input type="checkbox" name="products" value="{pid}" {checked}> {label}</label>'
            )
        products_html = (
            f'<form method="POST" action="/admin/set-products" style="margin:0">'
            f'<input type="hidden" name="key" value="{key}">'
            f'{checkboxes}'
            f'<button class="btn-primary" type="submit" style="font-size:11px;padding:3px 10px;margin-top:4px">Save</button>'
            f'</form>'
        )
        # Copy-paste download links for this license (one per available product file)
        if available_slots:
            link_fields = ""
            for slot in available_slots:
                link = f"{BASE_URL}/api/download/{slot}?key={key}"
                link_fields += (
                    f'<div style="margin:3px 0">'
                    f'<div style="font-size:10px;color:#6cf">{DOWNLOAD_SLOT_LABELS[slot]}</div>'
                    f'<input readonly value="{link}" onclick="this.select();navigator.clipboard.writeText(this.value)" '
                    f'title="Click to copy" style="width:250px;font-size:10px;padding:2px;background:#0d1b2a;color:#cde;border:1px solid #345">'
                    f'</div>'
                )
            downloads_html = (
                f'<details style="font-size:11px">'
                f'<summary style="cursor:pointer;color:#0ff">Links</summary>'
                f'<div style="margin-top:4px">{link_fields}</div>'
                f'</details>'
            )
        else:
            downloads_html = '<span style="font-size:11px;color:#888">No files uploaded</span>'
        
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
        
        license_rows += f"""<tr{row_style}>
<td><code>{key}</code>{dupe_badge}</td>
<td>{lic.get('email', '-')}</td>
<td>{machine_info}</td>
<td>{products_html}</td>
<td><span class="status-{status_class}">{lic.get('status', 'unknown')}</span></td>
<td>{lic.get('expiry', 'Never')}</td>
<td>{lic.get('last_check', 'Never')[:16] if lic.get('last_check') else 'Never'}</td>
<td>{lic.get('notes', '')}</td>
<td>{downloads_html}</td>
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
            ts = product_files_updated.get(fname, "")
            upd = (f'<br><span style="color:#8ad;font-size:11px">Last updated: {ts}</span>'
                   if ts else '<br><span style="color:#c80;font-size:11px">Last updated: unknown</span>')
            file_status[fname] = f'✅ {fpath}{upd}'
        else:
            file_status[fname] = '❌ Not uploaded'
    webhook_url = f"{BASE_URL}/api/webhook/authorize"
    # Product checkboxes for the create-license form
    create_product_checkboxes = ""
    for pid in KNOWN_PRODUCTS:
        checked = "checked" if pid in DEFAULT_NEW_LICENSE_PRODUCTS else ""
        label = PRODUCT_LABELS.get(pid, pid)
        create_product_checkboxes += (
            f'<label style="display:block;font-size:13px;white-space:nowrap">'
            f'<input type="checkbox" name="products" value="{pid}" {checked}> {label}</label>'
        )
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
<h2>Product Files (for delivery)</h2>
<div class="section" style="display:grid;grid-template-columns:1fr 1fr;gap:15px">
<div class="file-card">
<h4>NT8 ME Dashboard</h4>
<div class="file-status">{file_status.get('NT8_ME', '❌')}</div>
<form method="POST" action="/admin/upload-product" enctype="multipart/form-data">
<input type="hidden" name="product_key" value="NT8_ME">
<input type="file" name="file" accept=".zip" style="font-size:12px;margin:5px 0">
<button class="btn-primary" type="submit" style="font-size:12px;padding:4px 12px">Upload</button>
</form>
</div>
<div class="file-card">
<h4>NT8 HFT Dashboard</h4>
<div class="file-status">{file_status.get('NT8_HFT', '❌')}</div>
<form method="POST" action="/admin/upload-product" enctype="multipart/form-data">
<input type="hidden" name="product_key" value="NT8_HFT">
<input type="file" name="file" accept=".zip" style="font-size:12px;margin:5px 0">
<button class="btn-primary" type="submit" style="font-size:12px;padding:4px 12px">Upload</button>
</form>
</div>
<div class="file-card">
<h4>NT8 Bracket Pro Dashboard</h4>
<div class="file-status">{file_status.get('NT8_Bracket_Pro', '❌')}</div>
<form method="POST" action="/admin/upload-product" enctype="multipart/form-data">
<input type="hidden" name="product_key" value="NT8_Bracket_Pro">
<input type="file" name="file" accept=".zip" style="font-size:12px;margin:5px 0">
<button class="btn-primary" type="submit" style="font-size:12px;padding:4px 12px">Upload</button>
</form>
</div>
<div class="file-card">
<h4>TradeStation (ME + HFT)</h4>
<div class="file-status">{file_status.get('TS', '❌')}</div>
<form method="POST" action="/admin/upload-product" enctype="multipart/form-data">
<input type="hidden" name="product_key" value="TS">
<input type="file" name="file" accept=".zip" style="font-size:12px;margin:5px 0">
<button class="btn-primary" type="submit" style="font-size:12px;padding:4px 12px">Upload</button>
</form>
</div>
<div class="file-card">
<h4>PDF Guides (NT8 + TS)</h4>
<div class="file-status">{file_status.get('PDF_Guides', '❌')}</div>
<form method="POST" action="/admin/upload-product" enctype="multipart/form-data">
<input type="hidden" name="product_key" value="PDF_Guides">
<input type="file" name="file" accept=".zip,.pdf" style="font-size:12px;margin:5px 0">
<button class="btn-primary" type="submit" style="font-size:12px;padding:4px 12px">Upload</button>
</form>
</div>
<div class="file-card">
<h4>NT8 Market Energy Setup</h4>
<div class="file-status">{file_status.get('NT8_Market_Energy', '❌')}</div>
<form method="POST" action="/admin/upload-product" enctype="multipart/form-data">
<input type="hidden" name="product_key" value="NT8_Market_Energy">
<input type="file" name="file" accept=".zip" style="font-size:12px;margin:5px 0">
<button class="btn-primary" type="submit" style="font-size:12px;padding:4px 12px">Upload</button>
</form>
</div>
<div class="file-card">
<h4>Bracket Pro Dollars Profit</h4>
<div class="file-status">{file_status.get('Bracket_Pro_DP', '❌')}</div>
<form method="POST" action="/admin/upload-product" enctype="multipart/form-data">
<input type="hidden" name="product_key" value="Bracket_Pro_DP">
<input type="file" name="file" accept=".zip" style="font-size:12px;margin:5px 0">
<button class="btn-primary" type="submit" style="font-size:12px;padding:4px 12px">Upload</button>
</form>
</div>
<div class="file-card">
<h4>Bracket Pro Guide (PDF)</h4>
<div class="file-status">{file_status.get('Bracket_Pro_Guide', '❌')}</div>
<form method="POST" action="/admin/upload-product" enctype="multipart/form-data">
<input type="hidden" name="product_key" value="Bracket_Pro_Guide">
<input type="file" name="file" accept=".pdf,.zip" style="font-size:12px;margin:5px 0">
<button class="btn-primary" type="submit" style="font-size:12px;padding:4px 12px">Upload</button>
</form>
</div>
<div class="file-card">
<h4>TS Bracket Pro Dashboard</h4>
<div class="file-status">{file_status.get('TS_Bracket_Pro', '❌')}</div>
<form method="POST" action="/admin/upload-product" enctype="multipart/form-data">
<input type="hidden" name="product_key" value="TS_Bracket_Pro">
<input type="file" name="file" accept=".eld,.zip" style="font-size:12px;margin:5px 0">
<button class="btn-primary" type="submit" style="font-size:12px;padding:4px 12px">Upload</button>
</form>
</div>
<div class="file-card">
<h4>TS Market Energy Setup</h4>
<div class="file-status">{file_status.get('TS_Market_Energy', '❌')}</div>
<form method="POST" action="/admin/upload-product" enctype="multipart/form-data">
<input type="hidden" name="product_key" value="TS_Market_Energy">
<input type="file" name="file" accept=".eld,.zip" style="font-size:12px;margin:5px 0">
<button class="btn-primary" type="submit" style="font-size:12px;padding:4px 12px">Upload</button>
</form>
</div>
<div class="file-card">
<h4>TS Dollars Profit</h4>
<div class="file-status">{file_status.get('TS_Dollars_Profit', '❌')}</div>
<form method="POST" action="/admin/upload-product" enctype="multipart/form-data">
<input type="hidden" name="product_key" value="TS_Dollars_Profit">
<input type="file" name="file" accept=".eld,.zip" style="font-size:12px;margin:5px 0">
<button class="btn-primary" type="submit" style="font-size:12px;padding:4px 12px">Upload</button>
</form>
</div>
<div class="file-card">
<h4>TS Bracket Pro Guide (PDF)</h4>
<div class="file-status">{file_status.get('TS_Guide', '❌')}</div>
<form method="POST" action="/admin/upload-product" enctype="multipart/form-data">
<input type="hidden" name="product_key" value="TS_Guide">
<input type="file" name="file" accept=".pdf,.zip" style="font-size:12px;margin:5px 0">
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
<label>Products</label>
<div style="padding:4px 0">{create_product_checkboxes}</div>
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
<form method="POST" action="/admin/cleanup-webhooks" style="margin:0 0 12px 0; display:inline-block">
<button class="btn-danger" type="submit" onclick="return confirm('Delete {webhook_junk_count} leftover webhook-...@unknown.com license(s)? Real customer licenses are not affected.')" {"disabled" if webhook_junk_count == 0 else ""}>Clean up webhook entries ({webhook_junk_count})</button>
</form>
<form method="POST" action="/admin/merge-duplicates" style="margin:0 0 12px 8px; display:inline-block">
<button class="btn-danger" type="submit" onclick="return confirm('Merge duplicates?\n\n{mergeable_count} surplus key(s) will be deleted. For each customer the key that is ACTUALLY IN USE is kept, and machine locks from the deleted keys are carried over, so nobody has to re-activate.\n\nCustomers whose keys were never activated are skipped and left for you to delete by hand.')" {"disabled" if mergeable_count == 0 else ""}>Merge duplicate licenses ({mergeable_count})</button>
</form>
<a href="/admin?view={"" if show_dupes_only else "duplicates"}" style="display:inline-block;margin:0 0 12px 8px;padding:8px 14px;border-radius:4px;text-decoration:none;background:{"#0a4" if show_dupes_only else "#345"};color:#fff;font-size:13px">{"Show all licenses" if show_dupes_only else f"Show duplicates only ({duplicate_count})"}</a>
{f'<div style="margin:0 0 12px 0;padding:8px 12px;background:#3a1010;border-left:3px solid #f55;color:#fca;font-size:12px">{unresolved_count} key(s) belong to customers where no key was ever activated - the merge skips these, delete the unwanted ones by hand.</div>' if unresolved_count else ""}
<table>
<tr><th>Key</th><th>Email</th><th>Machine</th><th>Products</th><th>Status</th><th>Expiry</th><th>Last Check</th><th>Notes</th><th>Downloads</th><th>Actions</th></tr>
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
    products = [p for p in form.getlist("products") if p in KNOWN_PRODUCTS]
    expiry = form.get("expiry", "").strip() or "Never"
    notes = form.get("notes", "")
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
@app.post("/admin/set-products")
async def admin_set_products(request: Request):
    session_id = request.cookies.get("session_id")
    if not session_id or session_id not in active_sessions:
        return RedirectResponse(url="/admin/login")
    form = await request.form()
    key = form.get("key")
    products = [p for p in form.getlist("products") if p in KNOWN_PRODUCTS]
    db = load_db()
    if key in db["licenses"]:
        db["licenses"][key]["products"] = products
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
@app.post("/admin/cleanup-webhooks")
async def admin_cleanup_webhooks(request: Request):
    """Delete leftover junk licenses created by webhook test pings
    (email like webhook-...@unknown.com). Real customer licenses are untouched."""
    session_id = request.cookies.get("session_id")
    if not session_id or session_id not in active_sessions:
        return RedirectResponse(url="/admin/login")
    db = load_db()
    to_delete = [
        k for k, l in db["licenses"].items()
        if str(l.get("email", "")).startswith("webhook-") and str(l.get("email", "")).endswith("@unknown.com")
    ]
    for k in to_delete:
        del db["licenses"][k]
    if to_delete:
        save_db(db)
    print(f"Cleanup: removed {len(to_delete)} webhook junk license(s)")
    return RedirectResponse(url="/admin", status_code=303)
# ═══════════════════════════════════════════════════════════════
# ADMIN: PRODUCT FILE UPLOAD
# ═══════════════════════════════════════════════════════════════
@app.post("/admin/merge-duplicates")
async def admin_merge_duplicates(request: Request):
    """Collapse multiple active licences for the same email down to one.

    Keeps the OLDEST key per customer (that is the one already sitting in their
    key file and in their welcome email) and carries over the machine locks from
    the surplus keys, so an existing installation keeps working without the
    customer having to re-activate. Only exact duplicate emails are touched.
    """
    session_id = request.cookies.get("session_id")
    if not session_id or session_id not in active_sessions:
        return RedirectResponse(url="/admin/login")

    db = load_db()
    licenses = db.get("licenses", {})

    by_email = {}
    for k, l in licenses.items():
        if l.get("status") != "active":
            continue
        e = str(l.get("email", "")).strip().lower()
        if not e:
            continue
        by_email.setdefault(e, []).append(k)

    removed = 0
    skipped = 0
    for email, keys in by_email.items():
        if len(keys) < 2:
            continue
        keep = pick_keeper(licenses, keys)
        if keep is None:
            # None of these keys was ever activated - no safe way to know which one
            # the customer will use, so leave the decision to a human.
            skipped += len(keys)
            print(f"Merge: {email} skipped - none of {len(keys)} keys was ever activated")
            continue
        surplus = [k for k in keys if k != keep]

        keep_rec = licenses[keep]
        merged_products = set(keep_rec.get("products") or [])
        merged_locks = dict(keep_rec.get("machine_locks") or {})

        for k in surplus:
            rec = licenses[k]
            merged_products |= set(rec.get("products") or [])
            for machine, val in (rec.get("machine_locks") or {}).items():
                merged_locks.setdefault(machine, val)
            del licenses[k]
            removed += 1

        keep_rec["products"] = sorted(merged_products)
        keep_rec["machine_locks"] = merged_locks
        note = str(keep_rec.get("notes") or "")
        stamp = f"merged {len(surplus)} duplicate key(s) on {datetime.now().strftime('%Y-%m-%d')}"
        keep_rec["notes"] = f"{note} | {stamp}".strip(" |")
        print(f"Merge: {email} -> kept {keep}, removed {len(surplus)}")

    if removed:
        save_db(db)
    print(f"Merge duplicates: removed {removed} surplus license(s), skipped {skipped} unactivated")
    return RedirectResponse(url="/admin?view=duplicates" if skipped else "/admin", status_code=303)


@app.post("/admin/upload-product")
async def upload_product(request: Request, product_key: str = Form(...), file: UploadFile = File(...)):
    session_id = request.cookies.get("session_id")
    if not session_id or session_id not in active_sessions:
        return RedirectResponse(url="/admin/login")
    valid_keys = ["NT8_ME", "NT8_HFT", "NT8_Bracket_Pro", "NT8_Market_Energy", "Bracket_Pro_DP", "TS", "TS_Bracket_Pro", "TS_Market_Energy", "TS_Dollars_Profit", "TS_Guide", "PDF_Guides", "Bracket_Pro_Guide"]
    if product_key not in valid_keys:
        return RedirectResponse(url="/admin", status_code=303)
    # Save file with friendly names
    upload_names = {
        "NT8_ME": "TOPEZDashboard_ME.zip",
        "NT8_HFT": "TOPEZDashboard_HFT.zip",
        "NT8_Bracket_Pro": "TOPEZDashboard_Bracket_Pro.zip",
        "NT8_Market_Energy": "TOPEZ_Market_Energy_Setup.zip",
        "Bracket_Pro_DP": "TOPEZ_Bracket_Pro_Dollars_Profit.zip",
        "TS": "TOPEZDASHBOARD_TS.zip",
        "TS_Bracket_Pro": "TOPEZ_Bracket_Pro_TS.eld",
        "TS_Market_Energy": "TOPEZ_Market_Energy_Setup_TS.eld",
        "TS_Dollars_Profit": "TOPEZ_Dollars_Profit_TS.eld",
        "TS_Guide": "TOPEZ_Bracket_Pro_Guide_TS.pdf",
        "PDF_Guides": "TOPEZ_PDF_Guides.zip",
        "Bracket_Pro_Guide": "TOPEZDashboard_Bracket_Pro_Guide.pdf"
    }
    filename = upload_names.get(product_key, f"{product_key}.zip")
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
    if "product_files_updated" not in db["settings"]:
        db["settings"]["product_files_updated"] = {}
    db["settings"]["product_files_updated"][product_key] = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
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
    
    # Friendly download filenames for customers
    download_names = {
        "NT8_ME": "TOPEZDashboard_ME.zip",
        "NT8_HFT": "TOPEZDashboard_HFT.zip",
        "NT8_Bracket_Pro": "TOPEZDashboard_Bracket_Pro.zip",
        "NT8_Market_Energy": "TOPEZ_Market_Energy_Setup.zip",
        "Bracket_Pro_DP": "TOPEZ_Bracket_Pro_Dollars_Profit.zip",
        "TS": "TOPEZDASHBOARD_TS.zip",
        "TS_Bracket_Pro": "TOPEZ_Bracket_Pro_TS.eld",
        "TS_Market_Energy": "TOPEZ_Market_Energy_Setup_TS.eld",
        "TS_Dollars_Profit": "TOPEZ_Dollars_Profit_TS.eld",
        "TS_Guide": "TOPEZ_Bracket_Pro_Guide_TS.pdf",
        "PDF_Guides": "TOPEZ_PDF_Guides.zip",
        "Bracket_Pro_Guide": "TOPEZDashboard_Bracket_Pro_Guide.pdf"
    }
    friendly_name = download_names.get(product_key, filename)
    _fn = friendly_name.lower()
    if _fn.endswith(".pdf"):
        media_type = "application/pdf"
    elif _fn.endswith(".eld"):
        media_type = "application/octet-stream"
    else:
        media_type = "application/zip"
    return FileResponse(filepath, filename=friendly_name, media_type=media_type)
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
    # Guard: never auto-provision without a real customer email.
    # Authorize.net test pings (and malformed events) arrive with no email and
    # previously created junk "webhook-...@unknown.com" licenses. We skip those
    # instead — a real purchase always carries an email; if one ever doesn't,
    # the license can be created manually in the admin panel.
    email = (email or "").strip()
    if not email or "@" not in email:
        print(f"Webhook: no valid customer email in payload - skipping provisioning. Body: {json.dumps(body)[:200]}")
        return {"status": "skipped", "reason": "no customer email"}
    # Auto-generate license (idempotent: Authorize.net retries webhooks, and a
    # duplicate delivery must not create a second key for the same customer)
    db = load_db()
    wh_products = ["ME_Dashboard", "HFT_Dashboard"]
    key, existing = find_existing_license(db, email, wh_products)
    if existing is not None:
        print(f"Webhook: {email} already holds active key {key} - not creating another")
        return {"status": "ok", "key": key, "reused": True}
    key = generate_key()
    db["licenses"][key] = {
        "email": email,
        "products": wh_products,
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
        dl_nt8_me = f"{BASE_URL}/api/download/NT8_ME?key={key}"
        dl_nt8_hft = f"{BASE_URL}/api/download/NT8_HFT?key={key}"
        dl_nt8_bracket_pro = f"{BASE_URL}/api/download/NT8_Bracket_Pro?key={key}"
        dl_ts = f"{BASE_URL}/api/download/TS?key={key}"
        dl_guides = f"{BASE_URL}/api/download/PDF_Guides?key={key}"
        
        html = f"""
<html><body style="font-family: Arial, sans-serif; background: #f5f5f5; padding: 20px;">
<div style="max-width: 600px; margin: 0 auto; background: #fff; border-radius: 10px; padding: 30px;">
<h1 style="color: #0066cc; text-align: center;">TOP EZ Dashboard</h1>
<h2 style="text-align: center;">Your License Key</h2>
<div style="background: #f0f8ff; border: 2px solid #0066cc; border-radius: 8px; padding: 20px; text-align: center; margin: 20px 0;">
<code style="font-size: 24px; font-weight: bold; color: #333;">{key}</code>
</div>
<h3>Download Your Dashboards:</h3>
<div style="margin: 20px 0;">
<p style="margin: 10px 0;"><a href="{dl_nt8_me}" style="display: inline-block; background: #0066cc; color: #fff; padding: 10px 24px; border-radius: 6px; text-decoration: none; font-weight: bold; width: 100%; text-align: center; box-sizing: border-box;">1. NinjaTrader 8 - ME Dashboard</a></p>
<p style="margin: 10px 0;"><a href="{dl_nt8_hft}" style="display: inline-block; background: #0066cc; color: #fff; padding: 10px 24px; border-radius: 6px; text-decoration: none; font-weight: bold; width: 100%; text-align: center; box-sizing: border-box;">2. NinjaTrader 8 - HFT Dashboard</a></p>
<p style="margin: 10px 0;"><a href="{dl_nt8_bracket_pro}" style="display: inline-block; background: #0066cc; color: #fff; padding: 10px 24px; border-radius: 6px; text-decoration: none; font-weight: bold; width: 100%; text-align: center; box-sizing: border-box;">3. NinjaTrader 8 - Bracket Pro Dashboard</a></p>
<p style="margin: 10px 0;"><a href="{dl_ts}" style="display: inline-block; background: #28a745; color: #fff; padding: 10px 24px; border-radius: 6px; text-decoration: none; font-weight: bold; width: 100%; text-align: center; box-sizing: border-box;">4. TradeStation - ME + HFT Dashboard</a></p>
<p style="margin: 10px 0;"><a href="{dl_guides}" style="display: inline-block; background: #6c757d; color: #fff; padding: 10px 24px; border-radius: 6px; text-decoration: none; font-weight: bold; width: 100%; text-align: center; box-sizing: border-box;">5. PDF Installation Guides</a></p>
</div>
<h3>Installation:</h3>
<ol>
<li>Download the dashboard(s) for your platform</li>
<li>Download the PDF Guide for step-by-step installation instructions</li>
<li>Enter your license key when prompted on first launch</li>
</ol>
<p style="color: #888; font-size: 12px; margin-top: 30px; text-align: center;">
This license is valid for one computer per platform. If you need to transfer it, contact support.
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
async def get_valid_keap_token(db: dict) -> str:
    """Get a valid Keap access token, refreshing if expired"""
    tokens = db.get("keap_tokens", {})
    access_token = tokens.get("access_token")
    refresh_token = tokens.get("refresh_token")
    expires_at = tokens.get("expires_at", "")
    if not access_token:
        return None
    # Check if token is expired or about to expire (5 min buffer)
    try:
        if expires_at:
            exp = datetime.fromisoformat(expires_at)
            if datetime.now() < exp - timedelta(minutes=5):
                return access_token  # Still valid
    except:
        pass
    # Token expired or no expiry info - try to refresh
    if not refresh_token:
        print("Keap: No refresh token available")
        return access_token  # Try anyway
    print("Keap: Token expired, refreshing...")
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                "https://api.infusionsoft.com/token",
                data={
                    "grant_type": "refresh_token",
                    "refresh_token": refresh_token,
                    "client_id": KEAP_CLIENT_ID,
                    "client_secret": KEAP_CLIENT_SECRET
                }
            )
            new_tokens = resp.json()
            if "access_token" in new_tokens:
                db["keap_tokens"] = {
                    "access_token": new_tokens["access_token"],
                    "refresh_token": new_tokens.get("refresh_token", refresh_token),
                    "expires_at": (datetime.now() + timedelta(seconds=new_tokens.get("expires_in", 86400))).isoformat()
                }
                save_db(db)
                print(f"Keap: Token refreshed successfully")
                return new_tokens["access_token"]
            else:
                print(f"Keap: Token refresh failed: {new_tokens}")
                return access_token
    except Exception as e:
        print(f"Keap: Token refresh error: {e}")
        return access_token
async def tag_keap_contact(email: str, key: str, db: dict):
    """Tag contact in Keap as license holder and set license custom fields"""
    access_token = await get_valid_keap_token(db)
    if not access_token:
        print("Keap not connected - skipping tag")
        return
    # Build download link
    dl_nt8_me = f"{BASE_URL}/api/download/NT8_ME?key={key}"
    dl_nt8_hft = f"{BASE_URL}/api/download/NT8_HFT?key={key}"
    dl_nt8_bracket_pro = f"{BASE_URL}/api/download/NT8_Bracket_Pro?key={key}"
    dl_ts = f"{BASE_URL}/api/download/TS?key={key}"
    dl_guides = f"{BASE_URL}/api/download/PDF_Guides?key={key}"
    download_link = f"{dl_nt8_me}\n{dl_nt8_hft}\n{dl_nt8_bracket_pro}\n{dl_ts}\n{dl_guides}"
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
                # Create contact with opted-in email status
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
            # Opt-in email via XML-RPC API (REST API doesn't support opt-in)
            try:
                xml_payload = f"""<?xml version='1.0' encoding='UTF-8'?>
<methodCall>
<methodName>APIEmailService.optIn</methodName>
<params>
<param><value><string>{access_token}</string></value></param>
<param><value><string>{email}</string></value></param>
<param><value><string>Purchased TOP EZ Dashboard</string></value></param>
</params>
</methodCall>"""
                optin_resp = await client.post(
                    "https://api.infusionsoft.com/crm/xmlrpc/v1",
                    content=xml_payload,
                    headers={"Content-Type": "application/xml", "Authorization": f"Bearer {access_token}"}
                )
                print(f"Keap: XML-RPC Opt-in for {email}: {optin_resp.status_code}")
                if "faultString" in optin_resp.text:
                    print(f"Keap: Opt-in fault: {optin_resp.text[:200]}")
            except Exception as oe:
                print(f"Keap: Opt-in error: {oe}")
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
# KEAP-DRIVEN PROVISIONING  (ClickFunnels/Keap -> server)
# ═══════════════════════════════════════════════════════════════
async def write_keap_license_fields(email: str, key: str, links_text: str, slot_links: dict, pm: dict, db: dict):
    """Best-effort: write the license key (and optional download links) into the
    product-specific Keap custom field(s). Skips gracefully if Keap is not connected
    or the field label is not found."""
    access_token = await get_valid_keap_token(db)
    if not access_token:
        print("Keap provision: not connected - skipping field write")
        return
    def _norm(x):
        return (x or "").replace(" ", "").strip().lower()
    key_label = _norm(pm.get("keap_license_field_label"))
    links_label = _norm(pm.get("keap_links_field_label"))
    dl_field_labels = pm.get("download_field_labels") or {}
    dl_label_to_slot = {_norm(lbl): slot for slot, lbl in dl_field_labels.items() if lbl}
    try:
        async with httpx.AsyncClient() as client:
            headers = {"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"}
            resp = await client.get(
                f"https://api.infusionsoft.com/crm/rest/v1/contacts?email={email}&optional_properties=custom_fields",
                headers=headers)
            contacts = resp.json().get("contacts", [])
            if contacts:
                contact_id = contacts[0]["id"]
            else:
                resp = await client.post(
                    "https://api.infusionsoft.com/crm/rest/v1/contacts",
                    headers=headers,
                    json={"email_addresses": [{"email": email, "field": "EMAIL1"}],
                          "opt_in_reason": "Purchased TOP EZ Dashboard"})
                contact_id = resp.json().get("id")
            if not contact_id:
                print("Keap provision: could not find/create contact")
                return
            model_resp = await client.get(
                "https://api.infusionsoft.com/crm/rest/v1/contacts/model", headers=headers)
            fields = model_resp.json().get("custom_fields", [])
            key_field_id = None
            links_field_id = None
            dl_slot_field = {}
            for fld in fields:
                lbl = _norm(fld.get("label", ""))
                if key_label and lbl == key_label:
                    key_field_id = fld.get("id")
                if links_label and lbl == links_label:
                    links_field_id = fld.get("id")
                if lbl in dl_label_to_slot:
                    dl_slot_field[dl_label_to_slot[lbl]] = fld.get("id")
            updates = []
            if key_field_id:
                updates.append({"content": key, "id": key_field_id})
            else:
                print(f"Keap provision: license-key field {pm.get('keap_license_field_label')!r} not found - skipping key write")
            if links_field_id and links_text:
                updates.append({"content": links_text, "id": links_field_id})
            for _slot, _fid in dl_slot_field.items():
                _url = slot_links.get(_slot)
                if _fid and _url:
                    updates.append({"content": _url, "id": _fid})
            if updates:
                r = await client.patch(
                    f"https://api.infusionsoft.com/crm/rest/v1/contacts/{contact_id}",
                    headers=headers, json={"custom_fields": updates})
                print(f"Keap provision: wrote fields for contact {contact_id}: {r.status_code}")
    except Exception as e:
        print(f"Keap provision field-write error: {e}")


@app.post("/api/keap/provision")
def license_in_use(rec: dict) -> bool:
    """Has this licence ever actually been activated on a machine?"""
    if rec.get("last_check"):
        return True
    return bool(rec.get("machine_locks"))


def pick_keeper(licenses: dict, keys: list):
    """Choose which of a customer's duplicate keys to keep.

    The key the customer is actually RUNNING wins - it sits in their key file, and
    deleting it would lock them out. Oldest-first is only a tie-break for keys that
    have never been used. Returns None when NONE of the keys was ever activated:
    in that case there is no safe automatic answer, so the merge skips that customer
    and leaves them for manual review.
    """
    used = [k for k in keys if license_in_use(licenses[k])]
    if not used:
        return None
    if len(used) == 1:
        return used[0]
    # More than one activated: keep the most recently checked in.
    used.sort(key=lambda k: licenses[k].get("last_check") or licenses[k].get("created") or "", reverse=True)
    return used[0]


def find_existing_license(db: dict, email: str, products: list):
    """Return (key, record) of an ACTIVE licence already covering this email+products.

    Provisioning must be idempotent: Keap retries a failed HTTP-post step, a campaign
    can fire more than once, and a customer can be pushed through the funnel again.
    Without this check every one of those events minted another key for the same
    person, which is how a single user ended up holding four licences.
    """
    want = set(products or [])
    email_l = (email or "").strip().lower()
    for k, rec in (db.get("licenses") or {}).items():
        if (rec.get("email") or "").strip().lower() != email_l:
            continue
        if rec.get("status") != "active":
            continue
        if want and not want.issubset(set(rec.get("products") or [])):
            continue
        return k, rec
    return None, None


async def keap_provision(request: Request, product: str = "bracket_pro", token: str = ""):
    """Called by a Keap campaign (HTTP Post step) after the product tag is applied.
    Provisions ONLY the purchased product and returns the license key + download links.
    Keap sends the welcome email itself; this endpoint does not send email and does not
    set the tag (Keap already set it - that is what triggered this call)."""
    supplied = token or request.headers.get("X-Provision-Token", "")
    if PROVISION_SECRET and supplied != PROVISION_SECRET:
        raise HTTPException(status_code=401, detail="Invalid provision token")
    pm = PRODUCT_MAP.get(product)
    if not pm:
        raise HTTPException(status_code=400, detail=f"Unknown product {product!r}")
    # email: accept JSON body, form, or query param (Keap HTTP-post format varies)
    email = ""
    try:
        body = await request.json()
        if isinstance(body, dict):
            email = body.get("email") or body.get("Email") or ""
    except:
        try:
            form = await request.form()
            email = form.get("email", "") or form.get("Email", "")
        except:
            pass
    if not email:
        email = request.query_params.get("email", "")
    email = (email or "").strip()
    if not email or "@" not in email:
        raise HTTPException(status_code=400, detail="Valid email required")
    db = load_db()
    # Reuse an existing active licence for this customer + product instead of
    # creating a second one. Re-sending the same key is harmless (the customer
    # gets the links again); minting a new one is not.
    key, existing = find_existing_license(db, email, pm["products"])
    reused = existing is not None
    if not reused:
        key = generate_key()
        db["licenses"][key] = {
            "email": email,
            "products": list(pm["products"]),
            "status": "active",
            "expiry": "Never",
            "notes": f"Provisioned via Keap ({product})",
            "created": datetime.now().isoformat(),
            "last_check": None,
            "machine_locks": {},
        }
        save_db(db)
    else:
        print(f"Provision: reusing existing key {key} for {email} ({product})")
    slot_links = {slot: f"{BASE_URL}/api/download/{slot}?key={key}" for slot in pm.get("download_slots", [])}
    links = list(slot_links.values())
    # combined labelled + blank-line-separated block for the single "Download Link" field
    links_text = "\n\n".join(
        f"{DOWNLOAD_LABELS.get(slot, slot)}:\n{url}" for slot, url in slot_links.items())
    await write_keap_license_fields(email, key, links_text, slot_links, pm, db)
    return {"status": "ok", "key": key, "reused": reused, "products": pm["products"], "download_links": links}

# ═══════════════════════════════════════════════════════════════
# HEALTH CHECK
# ═══════════════════════════════════════════════════════════════
@app.get("/")
async def root():
    return {"status": "ok", "service": "TOP EZ License Server", "version": "4.0"}
@app.get("/health")
async def health():
    return {"status": "healthy"}
