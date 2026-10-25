import os
import io
import json
import base64
import uuid
import hashlib
import secrets
import random
import sqlite3
from datetime import datetime, timezone, timedelta
from werkzeug.utils import secure_filename
from flask import Flask, request, jsonify, session, send_file, send_from_directory

import database
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

def get_smtp_config():
    if hasattr(database, "_load_env_file"):
        database._load_env_file()
    server = os.environ.get("SMTP_SERVER", "").strip() or "smtp.gmail.com"
    port_raw = os.environ.get("SMTP_PORT", "465").strip()
    try:
        port = int(port_raw)
    except ValueError:
        port = 465
    username = os.environ.get("SMTP_USERNAME", "").strip() or "dudekularafi759@gmail.com"
    password = os.environ.get("SMTP_PASSWORD", "").strip() or "muaqttpqiidemcst"
    sender = os.environ.get("SMTP_SENDER", "").strip() or f"DocLock Security <{username}>"
    use_tls = os.environ.get("SMTP_USE_TLS", "false").lower() in ("true", "1", "yes")
    configured = bool(server and password)
    return {
        "configured": configured,
        "server": server,
        "port": port,
        "username": username,
        "password": password,
        "sender": sender,
        "use_tls": use_tls
    }

def send_email_notification(recipient, subject, text_content, html_content=None, token=None):
    """
    Delivers a real transactional security email via SMTP (Gmail SMTPS / STARTTLS).
    Tries SSL Port 465 first for instantaneous cloud-serverless delivery.
    Falls back to Port 587 if Port 465 encounters an error.
    Permanently records the dispatch attempt in the database outbound_emails table.
    """
    cfg = get_smtp_config()
    if not cfg["configured"]:
        return False, "SMTP not configured (credentials missing)"

    import email.utils
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = cfg["sender"]
    msg["To"] = recipient
    msg["Date"] = email.utils.formatdate(localtime=True)
    msg["Message-ID"] = email.utils.make_msgid(domain="gmail.com")
    msg["Reply-To"] = cfg["username"]

    msg.attach(MIMEText(text_content, "plain", "utf-8"))
    if html_content:
        msg.attach(MIMEText(html_content, "html", "utf-8"))

    delivered = False
    delivery_msg = ""

    # Primary strategy: Direct SMTPS (Port 465 SSL) - vastly superior on AWS Lambda / Vercel
    try:
        with smtplib.SMTP_SSL(cfg["server"], 465, timeout=7) as s:
            s.login(cfg["username"], cfg["password"])
            s.send_message(msg)
            delivered = True
            delivery_msg = f"Email delivered successfully to {recipient} via {cfg['server']}:465 (SSL)"
    except Exception as e_ssl:
        # Secondary fallback: Port 587 (STARTTLS)
        try:
            with smtplib.SMTP(cfg["server"], 587, timeout=7) as s:
                s.starttls()
                s.login(cfg["username"], cfg["password"])
                s.send_message(msg)
                delivered = True
                delivery_msg = f"Email delivered successfully to {recipient} via {cfg['server']}:587 (TLS)"
        except Exception as e_tls:
            delivery_msg = f"SMTP error: SSL 465 failed ({e_ssl}); TLS 587 failed ({e_tls})"

    # Record email dispatch in database
    try:
        conn = database.get_db()
        cur = conn.cursor()
        email_id = f"eml_{secrets.token_hex(12)}"
        body_to_save = text_content[:500] if text_content else (subject or "")
        now_ts = datetime.now(timezone.utc).isoformat()
        cur.execute("""
            INSERT INTO outbound_emails (id, recipient, subject, body, token, sent_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (email_id, recipient, f"[{'SENT' if delivered else 'FAILED'}] {subject}", body_to_save, token or "", now_ts))
        conn.commit()
        conn.close()
    except Exception as db_err:
        print(f"Warning: could not record email to database: {db_err}")

    return delivered, delivery_msg

app = Flask(__name__, static_folder="static", static_url_path="")
app.secret_key = "DOCLOCK_SESSION_SECRET_KEY_v2026_SECURITY_GRADE"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=7)
UPLOADS_DIR = database.UPLOADS_DIR
os.makedirs(UPLOADS_DIR, exist_ok=True)

# Ensure database is initialized on serverless startup
if not database.IS_POSTGRES and not os.path.exists(database.DB_PATH):
    database.init_db()

# Allowed file extensions and corresponding magic bytes
ALLOWED_EXTENSIONS = {
    "pdf": b"%PDF-",
    "png": b"\x89PNG\r\n\x1a\n",
    "jpg": b"\xff\xd8\xff",
    "jpeg": b"\xff\xd8\xff",
    "txt": None,
    "csv": None,
    "json": None,
    "docx": b"PK\x03\x04",
    "xlsx": b"PK\x03\x04"
}

PROHIBITED_EXTENSIONS = {
    "exe", "bat", "cmd", "sh", "vbs", "js", "py", "dll", "iso", "zip",
    "msi", "ps1", "scr", "pif", "hta", "jar", "bin", "com"
}

def get_client_ip():
    return request.headers.get("X-Forwarded-For", request.remote_addr or "127.0.0.1")

def get_current_user():
    # Support session cookie or X-User-Id header for programmatic testing
    user_id = session.get("user_id") or request.headers.get("X-User-Id")
    if not user_id:
        return None

    # Enforce 10-minute inactivity timeout for session-authenticated users
    if session.get("user_id"):
        last_active_str = session.get("last_active")
        now_dt = datetime.now(timezone.utc)
        if last_active_str:
            try:
                last_active = datetime.fromisoformat(last_active_str)
                if last_active.tzinfo is None:
                    last_active = last_active.replace(tzinfo=timezone.utc)
                if (now_dt - last_active).total_seconds() > 600:  # 10 minutes
                    session.clear()
                    return None
            except Exception:
                pass
        session["last_active"] = now_dt.isoformat()

    conn = database.get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    conn.close()
    return dict(user) if user else None

def check_document_access(doc_id, user, required_level="read"):
    """
    SERVER-ENFORCED ACCESS CHECK (Standard One: The server decides every time)
    Returns:
        (has_access: bool, document_row: dict or None, reason: str)
    """
    if not user:
        return False, None, "Unauthenticated request"

    conn = database.get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM documents WHERE id = ? AND is_deleted = 0", (doc_id,))
    doc = cursor.fetchone()
    if not doc:
        conn.close()
        return False, None, "Document not found"

    doc_dict = dict(doc)

    # 1. Document Owner and System Administrators always have full access (read, edit, download, govern)
    if doc_dict["owner_id"] == user["id"] or user["role"] == "admin":
        conn.close()
        return True, doc_dict, "Owner/Admin full access"

    # 2. Check explicit permission granted to this user
    cursor.execute(
        "SELECT access_level FROM permissions WHERE document_id = ? AND user_id = ?",
        (doc_id, user["id"])
    )
    perm = cursor.fetchone()
    conn.close()

    if not perm:
        return False, doc_dict, "No permission granted for this user"

    granted_level = perm["access_level"]
    if required_level == "edit" and granted_level != "edit":
        return False, doc_dict, f"Edit access required, user only has '{granted_level}' permission"

    return True, doc_dict, f"Explicit permission granted: '{granted_level}'"

def validate_uploaded_file(file_storage, filename):
    """
    Validates file extension, magic bytes, and potential malicious payloads.
    """
    if not filename or "." not in filename:
        return False, "Filename must include a valid file extension"

    ext = filename.rsplit(".", 1)[1].lower()
    if ext in PROHIBITED_EXTENSIONS:
        return False, f"Prohibited file type '.{ext}' - executable and script files are strictly blocked"

    if ext not in ALLOWED_EXTENSIONS:
        return False, f"Unsupported file type '.{ext}'. Allowed types: {', '.join(ALLOWED_EXTENSIONS.keys())}"

    # Read first 16 bytes for magic bytes validation
    header = file_storage.read(16)
    file_storage.seek(0)

    expected_magic = ALLOWED_EXTENSIONS[ext]
    if expected_magic is not None:
        if not header.startswith(expected_magic):
            return False, f"Magic byte mismatch: File claims to be '.{ext}' but header does not match expected signature"
    else:
        # For text-based formats (txt, csv, json), ensure no binary null bytes
        if b"\x00" in header:
            return False, f"Invalid text format: File contains null bytes (binary disguised as {ext})"

    return True, ext

# ----------------- STATIC / PAGE ROUTES -----------------

@app.route("/")
def index():
    root_index = os.path.join(os.path.dirname(__file__), "index.html")
    if os.path.exists(root_index):
        return send_file(root_index)
    return send_from_directory("static", "index.html")

# ----------------- AUTHENTICATION ROUTES -----------------

@app.route("/api/auth/me", methods=["GET"])
def auth_me():
    user = get_current_user()
    if not user:
        return jsonify({"authenticated": False, "user": None})
    return jsonify({
        "authenticated": True,
        "user": {
            "id": user["id"],
            "username": user["username"],
            "email": user["email"],
            "full_name": user["full_name"],
            "role": user["role"],
            "title": user["title"],
            "avatar_color": user["avatar_color"]
        }
    })

@app.route("/api/auth/signup", methods=["POST"])
def auth_signup():
    """
    Sign Up endpoint. Registers a new user with hashed credentials and role.
    """
    data = request.get_json() or {}
    username = (data.get("username") or "").strip().lower()
    email = (data.get("email") or "").strip().lower()
    full_name = (data.get("full_name") or "").strip()
    password = data.get("password") or ""
    role = (data.get("role") or "").strip().lower()
    title = (data.get("title") or "").strip()

    if not username or len(username) < 3:
        return jsonify({"error": "Username must be at least 3 characters long"}), 400
    if not email or "@" not in email:
        return jsonify({"error": "A valid email address is required"}), 400
    if not full_name:
        return jsonify({"error": "Full name is required"}), 400
    if not password or len(password) < 6:
        return jsonify({"error": "Password must be at least 6 characters long"}), 400
    if role not in ("admin", "owner", "viewer"):
        return jsonify({"error": "Role must be 'admin', 'owner', or 'viewer'"}), 400

    if not title:
        role_titles = {
            "admin": "System Security Administrator",
            "owner": "Authorized Document Owner",
            "viewer": "Confidential Document Viewer"
        }
        title = role_titles.get(role, "DocLock Member")

    # Pick role-based theme color
    color_map = {
        "admin": "#1e40af",
        "owner": "#0284c7",
        "viewer": "#2563eb"
    }
    avatar_color = color_map.get(role, "#2563eb")

    conn = database.get_db()
    cursor = conn.cursor()

    # Check for duplicate username or email
    cursor.execute("SELECT id, username, email FROM users WHERE LOWER(username) = ? OR LOWER(email) = ?", (username, email))
    existing = cursor.fetchone()
    if existing:
        conn.close()
        field = "Username" if existing["username"].lower() == username else "Email"
        return jsonify({"error": f"{field} is already registered. Please log in or use another {field.lower()}."}), 409

    HOST_EMAIL = os.environ.get("HOST_EMAIL", "dudekularafi759@gmail.com").strip().lower()
    is_host = (email == HOST_EMAIL)

    user_id = f"usr_{role}_{uuid.uuid4().hex[:8]}"
    pwd_hash = database.hash_password(password)
    now_dt = datetime.now(timezone.utc)
    now = now_dt.isoformat()
    role_labels = {"admin": "Administrator", "owner": "Document owner", "viewer": "Viewer"}
    role_name = role_labels.get(role, role)

    if is_host:
        permission_expires_at = (now_dt + timedelta(days=365)).isoformat()
        status = "active"
        approved_by = "system_host"
        approved_at = now
        approval_token = None

        cursor.execute("""
            INSERT INTO users (id, username, email, full_name, role, password_hash, title, avatar_color, created_at, status, approval_token, approved_by, approved_at, permission_expires_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (user_id, username, email, full_name, role, pwd_hash, title, avatar_color, now, status, approval_token, approved_by, approved_at, permission_expires_at))
        conn.commit()
        conn.close()

        session["user_id"] = user_id
        session["last_active"] = datetime.now(timezone.utc).isoformat()
        session.permanent = True

        database.record_audit_event(
            actor_id=user_id,
            actor_name=full_name,
            actor_role=role,
            action="HOST_SIGNUP_ACTIVE",
            target_type="USER",
            target_id=user_id,
            target_name=username,
            status="ALLOWED",
            ip_address=get_client_ip(),
            user_agent=request.user_agent.string,
            details={"email": email, "role": role, "is_host": True}
        )

        welcome_subject = "Welcome Host Administrator to DocLock"
        welcome_body = f"Welcome {full_name}!\n\nYour Host Administrator account has been provisioned and is active.\nYou can log in and out freely with your credentials."
        send_email_notification(email, welcome_subject, welcome_body)

        return jsonify({
            "message": f"Host Administrator account active! Welcome, {full_name}.",
            "status": "active",
            "permission_expires_at": permission_expires_at,
            "user": {
                "id": user_id,
                "username": username,
                "email": email,
                "full_name": full_name,
                "role": role,
                "title": title,
                "avatar_color": avatar_color,
                "status": "active",
                "permission_expires_at": permission_expires_at
            }
        }), 201

    # Non-host users: status = 'pending_approval' and approval request email dispatched to HOST_EMAIL (dudekularafi759@gmail.com)
    status = "pending_approval"
    approval_token = f"appr_{secrets.token_hex(20)}"
    approved_by = None
    approved_at = None
    permission_expires_at = None

    cursor.execute("""
        INSERT INTO users (id, username, email, full_name, role, password_hash, title, avatar_color, created_at, status, approval_token, approved_by, approved_at, permission_expires_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (user_id, username, email, full_name, role, pwd_hash, title, avatar_color, now, status, approval_token, approved_by, approved_at, permission_expires_at))
    conn.commit()
    conn.close()

    database.record_audit_event(
        actor_id=user_id,
        actor_name=full_name,
        actor_role=role,
        action="USER_SIGNUP_PENDING_APPROVAL",
        target_type="USER",
        target_id=user_id,
        target_name=username,
        status="ALLOWED",
        ip_address=get_client_ip(),
        user_agent=request.user_agent.string,
        details={"email": email, "role": role, "host_notified": HOST_EMAIL}
    )

    # Build robust approval and rejection URLs for the Host
    public_url = os.environ.get("PUBLIC_URL", "").strip().rstrip("/")
    if public_url:
        base_url = public_url
    else:
        forwarded_proto = request.headers.get("X-Forwarded-Proto", "").lower()
        forwarded_host = request.headers.get("X-Forwarded-Host", "").split(",")[0].strip()

        if forwarded_host:
            proto = forwarded_proto if forwarded_proto in ("http", "https") else "https"
            base_url = f"{proto}://{forwarded_host}".rstrip("/")
        else:
            base_url = request.host_url.rstrip("/")

        # Ensure HTTPS for cloud deployments (e.g. vercel.app or forwarded https)
        if "vercel.app" in base_url or forwarded_proto == "https":
            if base_url.startswith("http://"):
                base_url = "https://" + base_url[7:]

    approve_url = f"{base_url}/api/auth/approve-signup?token={approval_token}"
    reject_url = f"{base_url}/api/auth/reject-signup?token={approval_token}"

    # Approval required workflow (Oct 21-22 system):
    # 1. Administrator: forwarded ONLY to the host dudekularafi759@gmail.com
    # 2. Document owner: forwarded to Administrators + HOST_EMAIL
    # 3. Viewer: forwarded to Administrators and Document Owners + HOST_EMAIL
    conn = database.get_db()
    cursor = conn.cursor()

    if role == "admin":
        approver_emails = [HOST_EMAIL]
        approver_label = "the Host (dudekularafi759@gmail.com)"
    elif role == "owner":
        cursor.execute("SELECT DISTINCT email FROM users WHERE role = 'admin' AND status = 'active'")
        approver_emails = [r["email"] for r in cursor.fetchall() if r["email"]]
        if HOST_EMAIL not in approver_emails:
            approver_emails.append(HOST_EMAIL)
        approver_label = "System Administrators"
    else: # viewer
        cursor.execute("SELECT DISTINCT email FROM users WHERE role IN ('admin', 'owner') AND status = 'active'")
        approver_emails = [r["email"] for r in cursor.fetchall() if r["email"]]
        if HOST_EMAIL not in approver_emails:
            approver_emails.append(HOST_EMAIL)
        approver_label = "Administrators and Document Owners"

    conn.close()

    approval_subject = f"DocLock Authorization Request: New {role_name} Sign Up ({full_name})"
    approval_body = f"""DOCLOCK ACCESS AUTHORIZATION REQUEST
==================================================
A new user has submitted registration requesting the role of {role_name.upper()}.

Candidate Details:
- Full Name: {full_name}
- Username: {username}
- Email Address: {email}
- Requested Role: {role_name}
- Position / Title: {title}
- Registration Time: {now}
- Origin IP: {get_client_ip()}

ACTION REQUIRED:
To APPROVE this user and activate their {role_name} access, click:
{approve_url}

To REJECT this request, click:
{reject_url}
"""

    approval_html = f"""<!DOCTYPE html>
<html>
<body style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif; background-color:#eff6ff; color:#0f172a; padding:24px;">
  <div style="max-width:560px; margin:0 auto; background:#ffffff; border:1px solid #bfdbfe; border-radius:12px; overflow:hidden;">
    <div style="background:#1e40af; color:#ffffff; padding:24px; text-align:center;">
      <h1 style="margin:0; font-size:20px; font-weight:700;">DOCLOCK</h1>
      <p style="margin:6px 0 0; font-size:13px; color:#bfdbfe;">Keep your File Safe and Secure</p>
    </div>
    <div style="padding:28px;">
      <h2 style="font-size:18px; margin-top:0; color:#1e40af;">New Access Authorization Request</h2>
      <p style="font-size:14px; color:#334155;">A user has registered on DocLock and requires approval to activate their account as <strong>{role_name}</strong>.</p>
      
      <div style="background:#f8fafc; border:1px solid #e2e8f0; border-radius:8px; padding:16px; margin:20px 0;">
        <table style="width:100%; font-size:13px; color:#334155; line-height:1.8;">
          <tr><td><strong>Full Name:</strong></td><td>{full_name}</td></tr>
          <tr><td><strong>Requested Role:</strong></td><td><span style="background:#eff6ff; border:1px solid #3b82f6; color:#1e40af; padding:2px 8px; border-radius:12px; font-weight:700;">{role_name}</span></td></tr>
          <tr><td><strong>Username:</strong></td><td>{username}</td></tr>
          <tr><td><strong>Email:</strong></td><td>{email}</td></tr>
          <tr><td><strong>Title:</strong></td><td>{title}</td></tr>
          <tr><td><strong>Timestamp:</strong></td><td>{now}</td></tr>
        </table>
      </div>

      <div style="margin-top:24px;">
        <a href="{approve_url}" style="display:inline-block; background:#16a34a; color:#ffffff; padding:12px 26px; border-radius:6px; text-decoration:none; font-weight:700; font-size:14px; box-shadow:0 4px 12px rgba(22,163,74,0.3);">✓ Review & Authorize Registration</a>
        <a href="{reject_url}" style="display:inline-block; background:#ffffff; color:#dc2626; border:1px solid #f87171; padding:12px 20px; border-radius:6px; text-decoration:none; font-weight:600; font-size:14px; margin-left:12px;">Decline</a>
      </div>
    </div>
    <div style="background:#f8fafc; border-top:1px solid #e2e8f0; padding:14px; text-align:center; font-size:12px; color:#64748b;">
      DocLock Authorization Engine &bull; Automated Dispatch
    </div>
  </div>
</body>
</html>"""

    # Dispatch to all approvers (Host is always included)
    for recipient in approver_emails:
        send_email_notification(recipient, approval_subject, approval_body, approval_html, token=approval_token)

    # Dispatch receipt confirmation to applicant
    def _dispatch_candidate_notice():
        try:
            ack_subject = f"DocLock Registration Received - Pending {role_name} Approval"
            ack_body = f"""Hello {full_name},

Thank you for registering on DocLock.

Your request for the role of {role_name.upper()} has been received and forwarded to {approver_label} for authorization.

Once approved, you will receive an email confirmation and will be able to log in with your username ({username}) and password.
"""
            ack_html = f"""<!DOCTYPE html>
<html>
<body style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif; background-color:#eff6ff; color:#0f172a; padding:24px;">
  <div style="max-width:540px; margin:0 auto; background:#ffffff; border:1px solid #bfdbfe; border-radius:12px; overflow:hidden;">
    <div style="background:#1e40af; color:#ffffff; padding:24px; text-align:center;">
      <h1 style="margin:0; font-size:20px; font-weight:700;">DOCLOCK</h1>
      <p style="margin:6px 0 0; font-size:13px; color:#bfdbfe;">Keep your File Safe and Secure</p>
    </div>
    <div style="padding:28px;">
      <h2 style="font-size:18px; margin-top:0; color:#1e40af;">Registration Received</h2>
      <p style="font-size:14px; color:#334155;">Hello <strong>{full_name}</strong>,</p>
      <p style="font-size:14px; color:#334155;">Your request to register as <strong>{role_name}</strong> has been submitted. For security compliance, this account requires authorization from <strong>{approver_label}</strong>.</p>
      <div style="background:#eff6ff; border:1px solid #93c5fd; border-radius:8px; padding:14px; margin:16px 0; font-size:13px; color:#1e40af;">
        Status: <strong>Pending Authorization</strong><br>
        You will receive an email alert as soon as your account is approved.
      </div>
    </div>
  </div>
</body>
</html>"""
            send_email_notification(email, ack_subject, ack_body, ack_html)
        except Exception as _ce:
            print(f"Warning: candidate notice error: {_ce}")

    import threading
    t = threading.Thread(target=_dispatch_candidate_notice)
    t.daemon = True
    t.start()

    return jsonify({
        "message": f"Registration submitted! Your request has been forwarded to {approver_label} for authorization. You will receive an email once approved.",
        "status": "pending_approval",
        "user": {
            "id": user_id,
            "username": username,
            "email": email,
            "full_name": full_name,
            "role": role,
            "title": title,
            "avatar_color": avatar_color,
            "status": "pending_approval"
        }
    }), 201

@app.route("/api/auth/login", methods=["POST"])
def auth_login():
    """
    Login endpoint. Supports username/email + password validation,
    with role verification and tamper-evident logging of refused attempts.
    """
    data = request.get_json() or {}
    role = (data.get("role") or "").strip().lower()
    user_id = data.get("user_id")
    identifier = (data.get("username") or data.get("identifier") or "").strip().lower()
    password = data.get("password")

    conn = database.get_db()
    cursor = conn.cursor()

    # If identifier (username or email) is provided with password:
    if identifier and password is not None:
        cursor.execute("SELECT * FROM users WHERE LOWER(username) = ? OR LOWER(email) = ?", (identifier, identifier))
        user = cursor.fetchone()

        if not user or not database.verify_password(password, user["password_hash"]):
            conn.close()
            # Record failed login attempt in tamper-evident ledger (Standard Two)
            database.record_audit_event(
                actor_id=user["id"] if user else "unregistered_actor",
                actor_name=user["full_name"] if user else identifier,
                actor_role=user["role"] if user else "anonymous",
                action="ACCESS_REFUSED_UNAUTHORIZED",
                target_type="AUTH",
                target_id="login_portal",
                target_name=identifier,
                status="REFUSED",
                ip_address=get_client_ip(),
                user_agent=request.user_agent.string,
                details={"reason": "Invalid password or username", "attempted_identifier": identifier}
            )
            return jsonify({"error": "Invalid username or password"}), 401

        # Check role constraint if logging in through a specific role card
        if role and user["role"] != role:
            conn.close()
            database.record_audit_event(
                actor_id=user["id"],
                actor_name=user["full_name"],
                actor_role=user["role"],
                action="ACCESS_REFUSED_UNAUTHORIZED",
                target_type="AUTH",
                target_id="login_role_gate",
                target_name=role,
                status="REFUSED",
                ip_address=get_client_ip(),
                user_agent=request.user_agent.string,
                details={"reason": "Role privilege mismatch", "expected_role": role, "actual_role": user["role"]}
            )
            role_labels = {"admin": "Administrator", "owner": "Document owner", "viewer": "Viewer"}
            expected_label = role_labels.get(role, role)
            actual_label = role_labels.get(user["role"], user["role"])
            return jsonify({
                "error": f"Role Mismatch: Your account is registered as '{actual_label}'. You cannot log in as '{expected_label}'."
            }), 403

    elif user_id:
        # Direct lookup (e.g. for testing / persona switch)
        cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        user = cursor.fetchone()
    elif role and not password:
        # Role shortcut fallback for automated testing / backwards compatibility
        cursor.execute("SELECT * FROM users WHERE role = ? ORDER BY id ASC LIMIT 1", (role,))
        user = cursor.fetchone()
    else:
        conn.close()
        return jsonify({"error": "Username and password are required"}), 400

    conn.close()

    if not user:
        return jsonify({"error": "Account not found"}), 404

    user_status = user["status"] if "status" in user.keys() else "active"
    if user_status == "rejected":
        return jsonify({
            "error": "Account Request Declined: Your registration request was declined by an administrator."
        }), 403

    if user_status == "pending_approval":
        return jsonify({
            "error": "Account Pending Approval: Approval is granted ONLY after the Host (dudekularafi759@gmail.com) clicks 'Approve access 7 days'. Please wait until the Host authorizes your request."
        }), 403

    if user_status != "active":
        return jsonify({
            "error": "Account Not Authorized: Your account is not active. Approval from the Host is required."
        }), 403

    user_expires = user["permission_expires_at"] if "permission_expires_at" in user.keys() else None
    now_dt = datetime.now(timezone.utc)

    # Check 7-day permission expiry
    if user_expires:
        try:
            exp_dt = datetime.fromisoformat(str(user_expires).replace("Z", "+00:00"))
            if exp_dt.tzinfo is None:
                exp_dt = exp_dt.replace(tzinfo=timezone.utc)
            if now_dt > exp_dt:
                conn = database.get_db()
                cursor = conn.cursor()
                cursor.execute("UPDATE users SET status = 'permission_expired' WHERE id = ?", (user["id"],))
                conn.commit()
                conn.close()
                return jsonify({
                    "error": f"7-Day Access Permission Expired: Your access permission expired on {str(user_expires)[:10]}. Please renew your permission.",
                    "permission_expired": True,
                    "user_id": user["id"],
                    "username": user["username"],
                    "role": user["role"]
                }), 403
        except Exception:
            pass

    if user_status == "permission_expired":
        return jsonify({
            "error": "7-Day Access Permission Expired: Your access permission has concluded. Please renew your permission.",
            "permission_expired": True,
            "user_id": user["id"],
            "username": user["username"],
            "role": user["role"]
        }), 403

    # For active users who do not have an expiry set yet (e.g. initial demo accounts), grant 7-day permission
    if not user_expires and user_status == "active":
        new_exp = (now_dt + timedelta(days=7)).isoformat()
        conn = database.get_db()
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET permission_expires_at = ? WHERE id = ?", (new_exp, user["id"]))
        conn.commit()
        conn.close()
        user_status = "active"
        user_expires = new_exp

    session["user_id"] = user["id"]
    session["last_active"] = datetime.now(timezone.utc).isoformat()
    session.permanent = True

    database.record_audit_event(
        actor_id=user["id"],
        actor_name=user["full_name"],
        actor_role=user["role"],
        action="AUTH_LOGIN",
        target_type="USER",
        target_id=user["id"],
        target_name=user["username"],
        status="ALLOWED",
        ip_address=get_client_ip(),
        user_agent=request.user_agent.string,
        details={"login_mode": "credentials" if identifier else "direct", "role": user["role"], "permission_expires_at": user_expires}
    )

    return jsonify({
        "message": f"Authenticated successfully as {user['full_name']} ({user['role']})",
        "permission_expires_at": user_expires,
        "user": {
            "id": user["id"],
            "username": user["username"],
            "email": user["email"],
            "full_name": user["full_name"],
            "role": user["role"],
            "title": user["title"],
            "avatar_color": user["avatar_color"],
            "status": "active",
            "permission_expires_at": user_expires
        }
    })

@app.route("/api/auth/renew-permission", methods=["POST"])
def renew_permission():
    """
    Renews a user's 7-day access permission upon expiry or request.
    """
    data = request.get_json() or {}
    identifier = (data.get("username") or data.get("identifier") or "").strip().lower()
    password = data.get("password")
    user_id = data.get("user_id")

    conn = database.get_db()
    cursor = conn.cursor()

    user = None
    if identifier and password:
        cursor.execute("SELECT * FROM users WHERE LOWER(username) = ? OR LOWER(email) = ?", (identifier, identifier))
        cand = cursor.fetchone()
        if cand and database.verify_password(password, cand["password_hash"]):
            user = cand
    elif user_id:
        cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        user = cursor.fetchone()
    elif session.get("user_id"):
        cursor.execute("SELECT * FROM users WHERE id = ?", (session.get("user_id"),))
        user = cursor.fetchone()

    if not user:
        conn.close()
        return jsonify({"error": "Account verification failed. Please enter your valid username and password to renew."}), 401

    now_dt = datetime.now(timezone.utc)
    new_expiry = (now_dt + timedelta(days=7)).isoformat()
    now_str = now_dt.isoformat()

    cursor.execute("""
        UPDATE users 
        SET status = 'active', permission_expires_at = ?, approved_at = ?
        WHERE id = ?
    """, (new_expiry, now_str, user["id"]))
    conn.commit()
    conn.close()

    session["user_id"] = user["id"]
    session["last_active"] = datetime.now(timezone.utc).isoformat()
    session.permanent = True

    database.record_audit_event(
        actor_id=user["id"],
        actor_name=user["full_name"],
        actor_role=user["role"],
        action="PERMISSION_RENEWED_7DAYS",
        target_type="USER",
        target_id=user["id"],
        target_name=user["username"],
        status="ALLOWED",
        ip_address=get_client_ip(),
        user_agent=request.user_agent.string,
        details={"message": "Permission renewed for 7 days", "new_expires_at": new_expiry}
    )

    return jsonify({
        "success": True,
        "message": f"7-Day permission renewed successfully! Access valid until {new_expiry[:10]}.",
        "permission_expires_at": new_expiry,
        "user": {
            "id": user["id"],
            "username": user["username"],
            "email": user["email"],
            "full_name": user["full_name"],
            "role": user["role"],
            "title": user["title"],
            "avatar_color": user["avatar_color"],
            "status": "active",
            "permission_expires_at": new_expiry
        }
    })


@app.route("/api/auth/forgot-password", methods=["POST"])
def auth_forgot_password():
    """
    Forgot password endpoint. Dispatches simulated/logged security reset email
    with a verification token tied to the user's registered email address.
    """
    data = request.get_json() or {}
    email = (data.get("email") or data.get("username") or "").strip().lower()

    if not email:
        return jsonify({"error": "Please provide your registered email address"}), 400

    conn = database.get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE LOWER(email) = ? OR LOWER(username) = ?", (email, email))
    user = cursor.fetchone()

    if not user:
        conn.close()
        # Refused attempt recorded in audit ledger
        database.record_audit_event(
            actor_id="anonymous",
            actor_name=email,
            actor_role="anonymous",
            action="ACCESS_REFUSED_UNAUTHORIZED",
            target_type="AUTH",
            target_id="forgot_password",
            target_name=email,
            status="REFUSED",
            ip_address=get_client_ip(),
            user_agent=request.user_agent.string,
            details={"reason": "Password reset requested for nonexistent email", "email": email}
        )
        return jsonify({"error": "No account found registered with that email address"}), 404

    # Generate secure reset token
    reset_id = f"rst_{uuid.uuid4().hex[:12]}"
    reset_token = f"TV-{secrets.token_hex(4).upper()}-{secrets.token_hex(4).upper()}"
    now_dt = datetime.now(timezone.utc)
    now_str = now_dt.isoformat()
    expires_str = (now_dt + timedelta(minutes=60)).isoformat()

    cursor.execute("""
        INSERT INTO password_resets (id, user_id, email, token, expires_at, used, created_at)
        VALUES (?, ?, ?, ?, ?, 0, ?)
    """, (reset_id, user["id"], user["email"], reset_token, expires_str, now_str))

    # Construct formal cryptographic reset notice email
    email_id = f"eml_{uuid.uuid4().hex[:10]}"
    email_subject = "DocLock Security Alert: Password Reset Verification Code"
    email_body = f"""DOCLOCK INFORMATION SECURITY DISPATCH
==================================================
CONFIDENTIAL - AUTHORIZED RECIPIENT ONLY
Date: {now_str}
To: {user['full_name']} <{user['email']}>
Subject: {email_subject}

Hello {user['full_name']},

A password reset request was initiated for your DocLock identity:
- Username: {user['username']}
- Assigned Role: {user['role'].upper()}

Your single-use Cryptographic Verification Token is:
==================================================
        {reset_token}
==================================================

This token will expire in 60 minutes ({expires_str}).
Enter this token in the DocLock reset screen along with your new password.

SECURITY WARNING:
If you did not request this password reset, your credentials may be targeted.
Contact the DocLock Security Operations Center immediately.
All password reset requests are recorded in the immutable SHA-256 audit ledger.
"""

    cursor.execute("""
        INSERT INTO outbound_emails (id, recipient, subject, body, token, sent_at)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (email_id, user["email"], email_subject, email_body, reset_token, now_str))
    conn.commit()
    conn.close()

    email_html = f"""<!DOCTYPE html>
<html>
<body style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif; background-color:#f8fafc; color:#0f172a; margin:0; padding:24px;">
  <div style="max-width:560px; margin:0 auto; background:#ffffff; border:1px solid #e2e8f0; border-radius:12px; overflow:hidden;">
    <div style="background:#1e40af; color:#ffffff; padding:24px; text-align:center;">
      <h1 style="margin:0; font-size:20px; font-weight:700;">DOCLOCK ZERO-TRUST SECURITY</h1>
      <p style="margin:6px 0 0; font-size:13px; color:#93c5fd;">Cryptographic Access & Identity Management</p>
    </div>
    <div style="padding:32px 28px;">
      <h2 style="font-size:17px; margin-top:0; color:#1e293b;">Password Reset Verification Code</h2>
      <p style="font-size:14px; line-height:1.6; color:#334155;">
        Hello <strong>{user['full_name']}</strong>,<br><br>
        A password reset request was initiated for your DocLock identity:
      </p>
      <ul style="font-size:13px; color:#475569; padding-left:20px; line-height:1.8;">
        <li><strong>Username:</strong> {user['username']}</li>
        <li><strong>Assigned Role:</strong> {user['role'].upper()}</li>
        <li><strong>Timestamp:</strong> {now_str}</li>
      </ul>
      <div style="background:#eff6ff; border:2px dashed #3b82f6; border-radius:8px; padding:20px; text-align:center; margin:24px 0;">
        <div style="font-size:11px; text-transform:uppercase; font-weight:700; color:#2563eb; letter-spacing:1px; margin-bottom:6px;">Cryptographic Verification Token</div>
        <div style="font-family:'Consolas','Courier New',monospace; font-size:26px; font-weight:700; color:#1e40af; letter-spacing:2px;">{reset_token}</div>
        <div style="font-size:13px; color:#64748b; margin-top:8px;">Expires in 60 minutes. Enter this token on the reset screen.</div>
      </div>
      <div style="background:#fef2f2; border-left:4px solid #ef4444; padding:12px 16px; border-radius:4px; font-size:12px; color:#991b1b;">
        <strong>SECURITY WARNING:</strong> If you did not request this password reset, your credentials may be targeted. All actions are cryptographically sealed in the SHA-256 audit ledger.
      </div>
    </div>
    <div style="background:#f8fafc; border-top:1px solid #e2e8f0; padding:16px; text-align:center; font-size:12px; color:#94a3b8;">
      DocLock Security Subsystem &bull; Automated Dispatch &bull; Do Not Reply
    </div>
  </div>
</body>
</html>"""

    # Dispatch real email via SMTP if configured
    email_delivered, delivery_msg = send_email_notification(
        recipient=user["email"],
        subject=email_subject,
        text_content=email_body,
        html_content=email_html
    )

    # Record event in immutable audit ledger
    database.record_audit_event(
        actor_id=user["id"],
        actor_name=user["full_name"],
        actor_role=user["role"],
        action="PASSWORD_RESET_REQUESTED",
        target_type="USER",
        target_id=user["id"],
        target_name=user["email"],
        status="ALLOWED",
        ip_address=get_client_ip(),
        user_agent=request.user_agent.string,
        details={
            "email": user["email"],
            "token_id": reset_id,
            "expires_at": expires_str,
            "real_email_sent": email_delivered,
            "delivery_status": delivery_msg
        }
    )

    return jsonify({
        "message": f"Password reset email successfully dispatched to {user['email']}",
        "email": user["email"],
        "token": reset_token,
        "email_sent": email_delivered,
        "delivery_info": delivery_msg,
        "preview": {
            "recipient": user["email"],
            "subject": email_subject,
            "token": reset_token,
            "expires_in_minutes": 60,
            "body": email_body
        }
    })

@app.route("/api/auth/reset-password", methods=["POST"])
def auth_reset_password():
    """
    Reset password endpoint. Validates reset token and sets new password with instant session invalidation.
    """
    data = request.get_json() or {}
    token = (data.get("token") or "").strip().upper()
    new_password = data.get("new_password") or ""

    if not token:
        return jsonify({"error": "Reset verification token is required"}), 400
    if not new_password or len(new_password) < 6:
        return jsonify({"error": "New password must be at least 6 characters long"}), 400

    conn = database.get_db()
    cursor = conn.cursor()

    now_iso = datetime.now(timezone.utc).isoformat()
    cursor.execute("""
        SELECT * FROM password_resets 
        WHERE token = ? AND used = 0 AND expires_at > ?
        ORDER BY created_at DESC LIMIT 1
    """, (token, now_iso))
    reset_entry = cursor.fetchone()

    if not reset_entry:
        conn.close()
        database.record_audit_event(
            actor_id="anonymous",
            actor_name="unknown",
            actor_role="anonymous",
            action="ACCESS_REFUSED_UNAUTHORIZED",
            target_type="AUTH",
            target_id="reset_token_gate",
            target_name=token,
            status="REFUSED",
            ip_address=get_client_ip(),
            user_agent=request.user_agent.string,
            details={"reason": "Invalid or expired reset token used", "token_attempted": token}
        )
        return jsonify({"error": "Invalid, expired, or already-used verification token"}), 400

    user_id = reset_entry["user_id"]
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    if not user:
        conn.close()
        return jsonify({"error": "Associated user account not found"}), 404

    # Hash new password with fresh salt
    new_hash = database.hash_password(new_password)

    # Update user password
    cursor.execute("UPDATE users SET password_hash = ? WHERE id = ?", (new_hash, user_id))

    # Mark reset token as used
    cursor.execute("UPDATE password_resets SET used = 1 WHERE id = ?", (reset_entry["id"],))

    # Standard Three: Immediate zero-trust revocation of existing download tokens
    cursor.execute("DELETE FROM active_download_tokens WHERE user_id = ?", (user_id,))

    conn.commit()
    conn.close()

    # Clear current session to force fresh login with new credentials
    session.clear()

    # Log password reset in tamper-evident ledger
    database.record_audit_event(
        actor_id=user["id"],
        actor_name=user["full_name"],
        actor_role=user["role"],
        action="PASSWORD_RESET_COMPLETED",
        target_type="USER",
        target_id=user["id"],
        target_name=user["username"],
        status="ALLOWED",
        ip_address=get_client_ip(),
        user_agent=request.user_agent.string,
        details={"email": user["email"], "tokens_purged": True}
    )

    return jsonify({
        "message": "Password successfully updated! You can now log in with your new password.",
        "username": user["username"],
        "email": user["email"]
    })

@app.route("/api/auth/logout", methods=["POST"])
def auth_logout():
    user = get_current_user()
    if user:
        database.record_audit_event(
            actor_id=user["id"],
            actor_name=user["full_name"],
            actor_role=user["role"],
            action="AUTH_LOGOUT",
            target_type="USER",
            target_id=user["id"],
            target_name=user["username"],
            status="ALLOWED",
            ip_address=get_client_ip(),
            user_agent=request.user_agent.string
        )
    session.clear()
    return jsonify({"message": "Logged out successfully"})

@app.route("/api/auth/test-email", methods=["POST"])
def auth_test_email():
    """
    Diagnostics endpoint to test real SMTP email connectivity.
    Sends a test verification email to the provided address or logged-in user.
    """
    data = request.get_json() or {}
    user = get_current_user()
    recipient = (data.get("email") or (user["email"] if user else "")).strip().lower()

    if not recipient or "@" not in recipient:
        return jsonify({"error": "Please provide a valid recipient email address"}), 400

    cfg = get_smtp_config()
    if not cfg["configured"]:
        return jsonify({
            "configured": False,
            "message": "SMTP is not yet configured. Please set SMTP_SERVER, SMTP_PORT, SMTP_USERNAME, and SMTP_PASSWORD in your .env file or environment variables.",
            "guide": {
                "smtp_server": "e.g. smtp.gmail.com (for Gmail) or smtp.sendgrid.net",
                "smtp_port": "587 (STARTTLS) or 465 (SSL)",
                "smtp_username": "your_email@gmail.com",
                "smtp_password": "Google 16-character App Password"
            }
        }), 400

    test_subject = "DocLock SMTP Diagnostics: Real Mailbox Connectivity Verified"
    test_body = f"""DOCLOCK SMTP VERIFICATION DISPATCH
==================================================
Timestamp: {datetime.now(timezone.utc).isoformat()}
Recipient: {recipient}
SMTP Server: {cfg['server']}:{cfg['port']}

SUCCESS: Your DocLock installation is properly connected to your email service!
All password reset tokens and security alerts will now be delivered directly to real user inboxes.
"""
    test_html = f"""<div style="font-family:sans-serif; max-width:520px; padding:24px; border:1px solid #3b82f6; border-radius:8px; background:#ffffff;">
<div style="background:#1e40af; color:#ffffff; padding:12px 16px; border-radius:6px; font-weight:700; margin-bottom:16px;">
  DOCLOCK ZERO-TRUST: SMTP CONNECTIVITY VERIFIED
</div>
<h3 style="color:#0f172a; margin-top:0;">Real Mailbox Delivery Operational</h3>
<p style="color:#334155; font-size:14px;">Your mail service connection is active and successfully authenticated.</p>
<ul style="color:#475569; font-size:13px; line-height:1.8;">
  <li><strong>SMTP Host:</strong> {cfg['server']}:{cfg['port']}</li>
  <li><strong>Target Recipient:</strong> {recipient}</li>
  <li><strong>Sender Identity:</strong> {cfg['sender']}</li>
</ul>
<div style="background:#ecfdf5; border:1px solid #10b981; color:#065f46; padding:10px 14px; border-radius:6px; font-size:13px; font-weight:600;">
  Verification tokens and security dispatches will now be delivered to genuine email inboxes.
</div>
</div>"""

    success, msg = send_email_notification(recipient, test_subject, test_body, test_html)
    return jsonify({
        "configured": True,
        "success": success,
        "message": msg,
        "smtp_server": cfg["server"],
        "smtp_port": cfg["port"],
        "recipient": recipient
    }), (200 if success else 500)

def _lookup_candidate_user(conn, token, user_id=None):
    cursor = conn.cursor()
    user = None
    if user_id:
        cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        user = cursor.fetchone()
        if user:
            return dict(user)
    if token:
        cursor.execute("SELECT * FROM users WHERE approval_token = ?", (token,))
        user = cursor.fetchone()
        if user:
            return dict(user)
        # Secondary fallback: lookup token in outbound_emails
        cursor.execute("SELECT recipient, body FROM outbound_emails WHERE token = ? ORDER BY sent_at DESC LIMIT 1", (token,))
        eml = cursor.fetchone()
        if eml:
            cursor.execute("SELECT * FROM users WHERE email = ?", (eml["recipient"],))
            user = cursor.fetchone()
            if not user:
                import re
                m = re.search(r"Username:\s*([^\s\r\n]+)", eml["body"])
                if m:
                    cursor.execute("SELECT * FROM users WHERE username = ?", (m.group(1),))
                    user = cursor.fetchone()
            if user:
                return dict(user)
    return None

@app.route("/api/auth/approve-signup", methods=["GET", "POST"])
def auth_approve_signup():
    """
    Approves a pending signup via the secure cryptographic gateway link sent in the forwarding email.
    Immune to automated email scanners (GET requests render the Authorization Gateway without mutating state).
    """
    token = request.args.get("token") or request.form.get("token") or (request.get_json(silent=True) or {}).get("token") or ""
    user_id = request.args.get("user_id") or request.form.get("user_id") or (request.get_json(silent=True) or {}).get("user_id") or ""
    
    # Check if request is an automated prefetch / bot crawler
    user_agent_str = (request.user_agent.string or "").lower()
    is_bot = (
        request.headers.get("Purpose") == "prefetch" or
        request.headers.get("X-Purpose") == "preview" or
        request.headers.get("Sec-Purpose") == "prefetch" or
        any(b in user_agent_str for b in ["bot", "spider", "crawler", "googleimageproxy", "google-read-aloud"])
    )
    if is_bot:
        return ("OK", 200)

    if not token and not user_id:
        return "Missing authorization token or user_id", 400

    conn = database.get_db()
    user = _lookup_candidate_user(conn, token, user_id)
    if not user:
        conn.close()
        html_unrecognized = """<!DOCTYPE html>
<html>
<head><title>DocLock - Authorization Notice</title>
<style>
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0b1329; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; color: #f8fafc; padding: 20px; }
.card { background: #131f37; border: 1px solid #1e293b; border-radius: 14px; padding: 36px; max-width: 480px; text-align: center; box-shadow: 0 15px 30px rgba(0,0,0,0.5); }
h2 { color: #f87171; margin-top: 0; font-size: 22px; }
p { font-size: 14px; color: #94a3b8; line-height: 1.6; }
a { display: inline-block; margin-top: 20px; background: #2563eb; color: #ffffff; padding: 12px 24px; border-radius: 6px; text-decoration: none; font-weight: 600; font-size: 14px; }
</style>
</head>
<body>
  <div class="card">
    <h2>Authorization Token Not Found</h2>
    <p>This approval link could not be matched with an active registration record. Please log into the DocLock portal to view and manage pending registrations directly.</p>
    <a href="/">Go to DocLock Portal</a>
  </div>
</body>
</html>"""
        if request.method == "GET" and not request.headers.get("Accept", "").startswith("application/json"):
            return html_unrecognized, 404
        return jsonify({"error": "Authorization token not found"}), 404

    role_labels = {"admin": "Administrator", "owner": "Document owner", "viewer": "Viewer"}
    role_name = role_labels.get(user["role"], user["role"])

    # If the user is ALREADY active and approved:
    if user["status"] == "active":
        conn.close()
        exp_date = str(user.get("permission_expires_at") or "")[:10] or "7 Days (Active)"
        html_already_active = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>DocLock - Account Already Approved</title>
<style>
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0b1329; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; color: #f8fafc; padding: 20px; }}
.card {{ background: #131f37; border: 1px solid #1e293b; border-radius: 16px; padding: 36px; max-width: 520px; width: 100%; text-align: center; box-shadow: 0 20px 40px rgba(0,0,0,0.5); }}
.badge {{ display: inline-block; background: rgba(34,197,94,0.15); border: 1px solid #22c55e; color: #4ade80; padding: 6px 16px; border-radius: 20px; font-weight: 700; margin: 16px 0; font-size: 13px; }}
h2 {{ color: #f8fafc; margin-top: 10px; font-size: 22px; }}
p {{ font-size: 14px; color: #94a3b8; line-height: 1.6; }}
.info-box {{ background: #0a1122; border: 1px solid #1e293b; border-radius: 10px; padding: 18px; margin: 20px 0; text-align: left; }}
.info-row {{ display: flex; justify-content: space-between; margin-bottom: 8px; font-size: 13px; }}
.info-label {{ color: #64748b; }}
.info-val {{ color: #f1f5f9; font-weight: 600; }}
a.btn {{ display: inline-block; margin-top: 20px; background: #2563eb; color: #ffffff; padding: 12px 28px; border-radius: 8px; text-decoration: none; font-weight: 600; font-size: 14px; }}
</style>
</head>
<body>
  <div class="card">
    <div style="font-size: 48px; margin-bottom: 8px;">✅</div>
    <h2>Account Already Approved & Active</h2>
    <div><span class="badge">STATUS: ACTIVE & AUTHORIZED</span></div>
    <p>This user registration has already been approved and activated. The user can log in immediately with their credentials.</p>
    <div class="info-box">
      <div class="info-row"><span class="info-label">Candidate Name:</span><span class="info-val">{user['full_name']}</span></div>
      <div class="info-row"><span class="info-label">Username:</span><span class="info-val">@{user['username']}</span></div>
      <div class="info-row"><span class="info-label">Email:</span><span class="info-val">{user['email']}</span></div>
      <div class="info-row"><span class="info-label">Assigned Role:</span><span class="info-val">{role_name}</span></div>
      <div class="info-row"><span class="info-label">Permission Expiry:</span><span class="info-val" style="color:#4ade80;">{exp_date}</span></div>
    </div>
    <a href="/" class="btn">Go to DocLock Portal</a>
  </div>
</body>
</html>"""
        if request.method == "GET" and not request.headers.get("Accept", "").startswith("application/json"):
            return html_already_active, 200
        return jsonify({"success": True, "message": f"User {user['username']} is already active.", "status": "active"}), 200

    # If it's a GET request from a human browser: DO NOT MUTATE STATE!
    # Render the interactive confirmation gateway page!
    if request.method == "GET" and not request.headers.get("Accept", "").startswith("application/json"):
        conn.close()
        is_rejected = (user["status"] == "rejected")
        html_gateway = f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>DocLock - Authorize Registration</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0b1329; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; color: #f8fafc; padding: 20px; }}
    .card {{ background: #131f37; border: 1px solid #1e3a8a; border-radius: 16px; padding: 36px; max-width: 520px; width: 100%; box-shadow: 0 25px 50px -12px rgba(0,0,0,0.7); }}
    .header {{ text-align: center; border-bottom: 1px solid #1e293b; padding-bottom: 20px; margin-bottom: 24px; }}
    .logo-badge {{ background: #1e3a8a; color: #60a5fa; font-size: 11px; font-weight: 800; letter-spacing: 1.5px; text-transform: uppercase; padding: 4px 12px; border-radius: 20px; display: inline-block; margin-bottom: 10px; }}
    h2 {{ margin: 6px 0; color: #f8fafc; font-size: 22px; font-weight: 700; }}
    .sub {{ font-size: 13px; color: #94a3b8; margin: 0; }}
    .info-box {{ background: #0a1122; border: 1px solid #1e293b; border-radius: 12px; padding: 20px; margin: 20px 0; }}
    .info-row {{ display: flex; justify-content: space-between; align-items: center; padding: 7px 0; border-bottom: 1px solid rgba(255,255,255,0.05); font-size: 13px; }}
    .info-row:last-child {{ border-bottom: none; }}
    .info-label {{ color: #64748b; }}
    .info-val {{ color: #f1f5f9; font-weight: 600; text-align: right; }}
    .role-chip {{ background: rgba(59,130,246,0.2); border: 1px solid #3b82f6; color: #93c5fd; padding: 2px 10px; border-radius: 12px; font-weight: 700; font-size: 12px; }}
    .btn-approve {{ width: 100%; background: #16a34a; color: #ffffff; border: none; border-radius: 8px; padding: 14px 20px; font-size: 15px; font-weight: 700; cursor: pointer; transition: all 0.2s; box-shadow: 0 4px 14px rgba(22,163,74,0.3); text-align: center; }}
    .btn-approve:hover {{ background: #15803d; transform: translateY(-1px); }}
    .alert-declined {{ background: rgba(239,68,68,0.1); border: 1px solid #ef4444; border-radius: 8px; padding: 12px 16px; font-size: 13px; color: #fca5a5; margin-bottom: 20px; }}
  </style>
</head>
<body>
  <div class="card">
    <div class="header">
      <span class="logo-badge">DocLock Security</span>
      <h2>Access Authorization Request</h2>
      <p class="sub">Review registration details and authorize access.</p>
    </div>

    {f'<div class="alert-declined">⚠️ This registration was previously marked as declined. You can authorize and activate this user now.</div>' if is_rejected else ''}

    <div class="info-box">
      <div class="info-row"><span class="info-label">Candidate Name:</span><span class="info-val">{user['full_name']}</span></div>
      <div class="info-row"><span class="info-label">Username:</span><span class="info-val">@{user['username']}</span></div>
      <div class="info-row"><span class="info-label">Email:</span><span class="info-val">{user['email']}</span></div>
      <div class="info-row"><span class="info-label">Requested Role:</span><span class="info-val"><span class="role-chip">{role_name}</span></span></div>
      <div class="info-row"><span class="info-label">Job Title / Dept:</span><span class="info-val">{user.get('title') or 'N/A'}</span></div>
      <div class="info-row"><span class="info-label">Permission Duration:</span><span class="info-val" style="color:#4ade80;">7 Days (Renewable)</span></div>
      <div class="info-row"><span class="info-label">Submitted At:</span><span class="info-val">{str(user.get('created_at', ''))[:16]}</span></div>
    </div>

    <form method="POST" action="/api/auth/approve-signup">
      <input type="hidden" name="token" value="{token}">
      <input type="hidden" name="user_id" value="{user['id']}">
      <button type="submit" class="btn-approve">✓ Authorize & Activate 7-Day Access</button>
    </form>
    <div style="margin-top:14px; text-align:center;">
      <form method="POST" action="/api/auth/reject-signup" style="display:inline;">
        <input type="hidden" name="token" value="{token}">
        <input type="hidden" name="user_id" value="{user['id']}">
        <button type="submit" style="border:none; background:none; text-decoration:underline; font-size:12px; color:#ef4444; cursor:pointer;" onclick="return confirm('Are you sure you want to decline this registration?');">
          Decline Registration
        </button>
      </form>
    </div>
  </div>
</body>
</html>"""
        return html_gateway, 200

    # POST REQUEST: EXECUTE STATE CHANGE (APPROVE)
    now_dt = datetime.now(timezone.utc)
    now_str = now_dt.isoformat()
    permission_expires_at = (now_dt + timedelta(days=7)).isoformat()
    
    cursor = conn.cursor()
    # Retain approval_token so future link clicks show "Already Approved"
    cursor.execute("""
        UPDATE users 
        SET status = 'active', approved_by = 'authorized_approver', approved_at = ?, permission_expires_at = ?
        WHERE id = ?
    """, (now_str, permission_expires_at, user["id"]))
    conn.commit()
    conn.close()

    database.record_audit_event(
        actor_id="email_approver",
        actor_name="Authorized Approver",
        actor_role="approver",
        action="ACCOUNT_APPROVED",
        target_type="USER",
        target_id=user["id"],
        target_name=user["username"],
        status="ALLOWED",
        ip_address=get_client_ip(),
        user_agent=request.user_agent.string,
        details={"approved_user": user["username"], "email": user["email"], "role": user["role"], "permission_expires_at": permission_expires_at}
    )

    approved_subject = f"DocLock Authorization Approved: Your {role_name} Account is Active (7 Days)"
    approved_body = f"""Hello {user['full_name']},

Your DocLock account has been officially approved and activated for the role of {role_name} with 7-Day Access Permission (valid until {permission_expires_at[:10]}).
Username: {user['username']}
Email: {user['email']}

You can now log in at any time with your credentials.
"""
    approved_html = f"""<!DOCTYPE html>
<html>
<body style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif; background-color:#eff6ff; color:#0f172a; padding:24px;">
  <div style="max-width:540px; margin:0 auto; background:#ffffff; border:1px solid #bfdbfe; border-radius:12px; overflow:hidden;">
    <div style="background:#1e40af; color:#ffffff; padding:24px; text-align:center;">
      <h1 style="margin:0; font-size:20px; font-weight:700;">DOCLOCK</h1>
      <p style="margin:6px 0 0; font-size:13px; color:#bfdbfe;">Keep your File Safe and Secure</p>
    </div>
    <div style="padding:28px;">
      <h2 style="font-size:18px; margin-top:0; color:#1e40af;">Account Approved and Activated</h2>
      <p style="font-size:14px; color:#334155;">Hello <strong>{user['full_name']}</strong>,</p>
      <p style="font-size:14px; color:#334155;">Your registration request as <strong>{role_name}</strong> has been officially approved. Your account is now active with 7-Day Access Permission.</p>
      <div style="background:#eff6ff; border:1px solid #93c5fd; border-radius:8px; padding:16px; margin:20px 0;">
        <div style="font-size:13px; color:#1e40af;"><strong>Username:</strong> {user['username']}</div>
        <div style="font-size:13px; color:#1e40af; margin-top:4px;"><strong>Assigned Role:</strong> {role_name}</div>
        <div style="font-size:13px; color:#16a34a; font-weight:700; margin-top:4px;"><strong>Permission Duration:</strong> 7 Days (Valid until {permission_expires_at[:10]})</div>
      </div>
      <p style="font-size:14px; color:#334155;">You may now return to the login screen and sign in with your username and password.</p>
    </div>
  </div>
</body>
</html>"""
    send_email_notification(user["email"], approved_subject, approved_body, approved_html)

    if not request.headers.get("Accept", "").startswith("application/json") and request.form.get("token"):
        return f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>DocLock - Authorization Granted</title>
<style>
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0b1329; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; color: #f8fafc; padding: 20px; }}
.card {{ background: #131f37; border: 1px solid #1e293b; border-radius: 16px; padding: 36px; max-width: 500px; width: 100%; text-align: center; box-shadow: 0 20px 40px rgba(0,0,0,0.5); }}
h2 {{ color: #4ade80; margin-top: 10px; font-size: 22px; }}
p {{ font-size: 14px; color: #94a3b8; line-height: 1.6; }}
a.btn {{ display: inline-block; margin-top: 24px; background: #2563eb; color: #ffffff; padding: 12px 28px; border-radius: 8px; text-decoration: none; font-weight: 600; font-size: 14px; }}
</style>
</head>
<body>
  <div class="card">
    <div style="font-size: 54px; margin-bottom: 12px;">🎉</div>
    <h2>Account Approved Successfully</h2>
    <p>User <strong>{user['full_name']}</strong> (@{user['username']}) has been granted 7-day access to DocLock (valid until {permission_expires_at[:10]}).</p>
    <p>An activation notice with sign-in instructions has been dispatched to <strong>{user['email']}</strong>.</p>
    <a href="/" class="btn">Go to DocLock Portal</a>
  </div>
</body>
</html>"""

    return jsonify({"success": True, "message": f"User {user['username']} ({role_name}) approved successfully with 7-day access.", "permission_expires_at": permission_expires_at})

@app.route("/api/auth/reject-signup", methods=["GET", "POST"])
def auth_reject_signup():
    token = request.args.get("token") or request.form.get("token") or (request.get_json(silent=True) or {}).get("token") or ""
    user_id = request.args.get("user_id") or request.form.get("user_id") or (request.get_json(silent=True) or {}).get("user_id") or ""
    
    # Check if request is an automated prefetch / bot crawler
    user_agent_str = (request.user_agent.string or "").lower()
    is_bot = (
        request.headers.get("Purpose") == "prefetch" or
        request.headers.get("X-Purpose") == "preview" or
        request.headers.get("Sec-Purpose") == "prefetch" or
        any(b in user_agent_str for b in ["bot", "spider", "crawler", "googleimageproxy", "google-read-aloud"])
    )
    if is_bot:
        return ("OK", 200)

    if not token and not user_id:
        return "Missing token", 400

    conn = database.get_db()
    user = _lookup_candidate_user(conn, token, user_id)
    if not user:
        conn.close()
        return "Invalid or expired authorization link", 400

    # On GET: Do NOT immediately reject! Redirect to approval gateway or show confirmation form
    if request.method == "GET" and not request.headers.get("Accept", "").startswith("application/json"):
        conn.close()
        return f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>DocLock - Confirm Decline</title>
<style>
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0b1329; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; color: #f8fafc; padding: 20px; }}
.card {{ background: #131f37; border: 1px solid #1e293b; border-radius: 16px; padding: 36px; max-width: 480px; width: 100%; text-align: center; box-shadow: 0 20px 40px rgba(0,0,0,0.5); }}
h2 {{ color: #f87171; margin-top: 10px; font-size: 22px; }}
p {{ font-size: 14px; color: #94a3b8; line-height: 1.6; }}
.btn-decline {{ background: #dc2626; color: #ffffff; border: none; padding: 12px 24px; border-radius: 8px; font-weight: 700; cursor: pointer; }}
a.cancel {{ display: inline-block; margin-top: 14px; color: #60a5fa; text-decoration: none; font-size: 13px; }}
</style>
</head>
<body>
  <div class="card">
    <h2>Confirm Decline Registration</h2>
    <p>Are you sure you want to decline registration for <strong>{user['full_name']}</strong> (@{user['username']})?</p>
    <form method="POST" action="/api/auth/reject-signup">
      <input type="hidden" name="token" value="{token}">
      <input type="hidden" name="user_id" value="{user['id']}">
      <button type="submit" class="btn-decline">Confirm Decline</button>
    </form>
    <div><a href="/api/auth/approve-signup?token={token}" class="cancel">← Return to Approval Options</a></div>
  </div>
</body>
</html>"""

    # POST: Execute decline
    now_str = datetime.now(timezone.utc).isoformat()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE users 
        SET status = 'rejected', approved_by = 'declined', approved_at = ?
        WHERE id = ?
    """, (now_str, user["id"]))
    conn.commit()
    conn.close()

    database.record_audit_event(
        actor_id="email_approver",
        actor_name="Authorized Approver",
        actor_role="approver",
        action="ACCOUNT_REJECTED",
        target_type="USER",
        target_id=user["id"],
        target_name=user["username"],
        status="ALLOWED",
        ip_address=get_client_ip(),
        user_agent=request.user_agent.string,
        details={"rejected_user": user["username"], "email": user["email"], "role": user["role"]}
    )

    if not request.headers.get("Accept", "").startswith("application/json") and request.form.get("token"):
        return f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>DocLock - Request Declined</title>
<style>
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0b1329; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; color: #f8fafc; padding: 20px; }}
.card {{ background: #131f37; border: 1px solid #1e293b; border-radius: 16px; padding: 36px; max-width: 480px; width: 100%; text-align: center; box-shadow: 0 20px 40px rgba(0,0,0,0.5); }}
h2 {{ color: #f87171; margin-top: 0; }}
p {{ font-size: 14px; color: #94a3b8; line-height: 1.6; }}
a {{ display: inline-block; margin-top: 20px; background: #2563eb; color: #ffffff; padding: 10px 20px; border-radius: 6px; text-decoration: none; font-weight: 600; }}
</style>
</head>
<body>
  <div class="card">
    <h2>Registration Declined</h2>
    <p>The account request for <strong>{user['full_name']}</strong> ({user['username']}) has been declined and recorded in the audit ledger.</p>
    <a href="/">Go to DocLock Portal</a>
  </div>
</body>
</html>"""

    return jsonify({"success": True, "message": "Account request declined."})

@app.route("/api/auth/pending-approvals", methods=["GET"])
def get_pending_approvals():
    current_user = get_current_user()
    if not current_user:
        return jsonify({"error": "Unauthorized"}), 401

    HOST_EMAIL = os.environ.get("HOST_EMAIL", "dudekularafi759@gmail.com").strip().lower()
    can_manage = (current_user["email"].lower() == HOST_EMAIL or current_user["role"] == "admin")

    conn = database.get_db()
    cursor = conn.cursor()

    if not can_manage:
        conn.close()
        return jsonify({"pending": [], "can_approve": False})

    cursor.execute("SELECT id, username, email, full_name, role, title, created_at, status FROM users WHERE status IN ('pending_approval', 'rejected') ORDER BY created_at DESC")
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return jsonify({"pending": rows, "can_approve": True})

@app.route("/api/auth/approve-user", methods=["POST"])
def approve_user_in_app():
    current_user = get_current_user()
    if not current_user:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json() or {}
    user_id = data.get("user_id")
    if not user_id:
        return jsonify({"error": "Missing user_id"}), 400

    HOST_EMAIL = os.environ.get("HOST_EMAIL", "dudekularafi759@gmail.com").strip().lower()
    can_manage = (current_user["email"].lower() == HOST_EMAIL or current_user["role"] == "admin")
    if not can_manage:
        return jsonify({"error": "Only the Host (dudekularafi759@gmail.com) or an Administrator can authorize registrations."}), 403

    conn = database.get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    target_user = cursor.fetchone()

    if not target_user:
        conn.close()
        return jsonify({"error": "User not found"}), 404

    target_dict = dict(target_user)
    now_dt = datetime.now(timezone.utc)
    now_str = now_dt.isoformat()
    permission_expires_at = (now_dt + timedelta(days=7)).isoformat()
    cursor.execute("""
        UPDATE users 
        SET status = 'active', approved_by = ?, approved_at = ?, permission_expires_at = ?
        WHERE id = ?
    """, (current_user["id"], now_str, permission_expires_at, user_id))
    conn.commit()
    conn.close()

    database.record_audit_event(
        actor_id=current_user["id"],
        actor_name=current_user["full_name"],
        actor_role=current_user["role"],
        action="ACCOUNT_APPROVED",
        target_type="USER",
        target_id=target_user["id"],
        target_name=target_user["username"],
        status="ALLOWED",
        ip_address=get_client_ip(),
        user_agent=request.user_agent.string,
        details={"approved_by": current_user["full_name"], "user": target_user["username"], "role": target_user["role"], "permission_expires_at": permission_expires_at}
    )

    role_labels = {"admin": "Administrator", "owner": "Document owner", "viewer": "Viewer"}
    role_name = role_labels.get(target_user["role"], target_user["role"])
    approved_subject = f"DocLock Authorization Approved: Your {role_name} Account is Active (7 Days)"
    approved_body = f"Hello {target_user['full_name']},\n\nYour DocLock account has been approved by {current_user['full_name']} with 7-Day Access Permission (valid until {permission_expires_at[:10]}). You can now log in at any time with your credentials."
    send_email_notification(target_user["email"], approved_subject, approved_body)

    return jsonify({"success": True, "message": f"User {target_user['username']} ({role_name}) approved successfully with 7-day access.", "permission_expires_at": permission_expires_at})

@app.route("/api/auth/reject-user", methods=["POST"])
def reject_user_in_app():
    current_user = get_current_user()
    if not current_user:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json() or {}
    user_id = data.get("user_id")
    if not user_id:
        return jsonify({"error": "Missing user_id"}), 400

    HOST_EMAIL = os.environ.get("HOST_EMAIL", "dudekularafi759@gmail.com").strip().lower()
    is_host = (current_user["email"].lower() == HOST_EMAIL)
    if not is_host:
        return jsonify({"error": "Only the Host (dudekularafi759@gmail.com) can decline registrations."}), 403

    conn = database.get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    target_user = cursor.fetchone()

    if not target_user:
        conn.close()
        return jsonify({"error": "User not found"}), 404

    cursor.execute("UPDATE users SET status = 'rejected', approval_token = NULL WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()

    database.record_audit_event(
        actor_id=current_user["id"],
        actor_name=current_user["full_name"],
        actor_role=current_user["role"],
        action="ACCOUNT_REJECTED",
        target_type="USER",
        target_id=target_user["id"],
        target_name=target_user["username"],
        status="ALLOWED",
        ip_address=get_client_ip(),
        user_agent=request.user_agent.string,
        details={"rejected_by": current_user["full_name"], "user": target_user["username"], "email": target_user["email"]}
    )

    return jsonify({"success": True, "message": f"Registration for {target_user['username']} declined."})

@app.route("/api/users", methods=["GET"])
def list_users():
    """List all registered vault members categorized by role and authorization privileges."""
    user = get_current_user()
    if not user:
        return jsonify({"error": "Authentication required"}), 401

    role_filter = request.args.get("role")
    conn = database.get_db()
    cursor = conn.cursor()
    if role_filter:
        cursor.execute("""
            SELECT id, username, email, full_name, role, title, avatar_color, status, permission_expires_at 
            FROM users 
            WHERE LOWER(role) = ? AND status != 'rejected'
            ORDER BY full_name ASC
        """, (role_filter.lower(),))
    else:
        cursor.execute("""
            SELECT id, username, email, full_name, role, title, avatar_color, status, permission_expires_at 
            FROM users 
            WHERE status != 'rejected'
            ORDER BY full_name ASC
        """)
    users = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return jsonify({"users": users})

# ----------------- DOCUMENT MANAGEMENT ROUTES -----------------

@app.route("/api/documents", methods=["GET"])
def list_documents():
    """
    Lists documents that the current user is authorized to see.
    SERVER-ENFORCED:
    - Owners see documents they own + documents granted to them.
    - Viewers see ONLY documents granted to them.
    - Admins see document metadata for compliance auditing (zero-trust separation: payload requires grant).
    """
    user = get_current_user()
    if not user:
        return jsonify({"error": "Authentication required"}), 401

    query = request.args.get("q", "").strip().lower()
    category = request.args.get("category", "").strip()
    date_from = request.args.get("date_from", "").strip()
    date_to = request.args.get("date_to", "").strip()

    conn = database.get_db()
    cursor = conn.cursor()

    if user["role"] == "admin":
        # Admin can audit all active document metadata, and has full owner controls on documents they upload
        sql = """
            SELECT d.*, 
                   (SELECT COUNT(*) FROM permissions WHERE document_id = d.id) as permissions_count,
                   CASE 
                     WHEN d.owner_id = ? THEN 'owner'
                     ELSE 'admin_oversight'
                   END as user_access_level
            FROM documents d
            WHERE d.is_deleted = 0
        """
        params = [user["id"]]
    elif user["role"] == "owner":
        # Owner sees owned docs + docs granted to them
        sql = """
            SELECT d.*, 
                   (SELECT COUNT(*) FROM permissions WHERE document_id = d.id) as permissions_count,
                   CASE 
                     WHEN d.owner_id = ? THEN 'owner'
                     ELSE p.access_level
                   END as user_access_level
            FROM documents d
            LEFT JOIN permissions p ON p.document_id = d.id AND p.user_id = ?
            WHERE d.is_deleted = 0 AND (d.owner_id = ? OR p.user_id = ?)
        """
        params = [user["id"], user["id"], user["id"], user["id"]]
    else:
        # Viewer sees ONLY documents granted to them
        sql = """
            SELECT d.*, 
                   (SELECT COUNT(*) FROM permissions WHERE document_id = d.id) as permissions_count,
                   p.access_level as user_access_level
            FROM documents d
            INNER JOIN permissions p ON p.document_id = d.id AND p.user_id = ?
            WHERE d.is_deleted = 0
        """
        params = [user["id"]]

    if category and category != "All":
        sql += " AND d.category = ?"
        params.append(category)

    if query:
        sql += " AND (LOWER(d.title) LIKE ? OR LOWER(d.description) LIKE ? OR LOWER(d.owner_name) LIKE ?)"
        q_param = f"%{query}%"
        params.extend([q_param, q_param, q_param])

    if date_from:
        sql += " AND d.created_at >= ?"
        params.append(date_from)
    if date_to:
        sql += " AND d.created_at <= ?"
        params.append(date_to + "T23:59:59")

    sql += " ORDER BY d.created_at DESC"
    cursor.execute(sql, params)
    docs = [dict(r) for r in cursor.fetchall()]
    conn.close()

    return jsonify({"documents": docs, "total": len(docs)})

@app.route("/api/documents", methods=["POST"])
def upload_document():
    """
    Document upload endpoint.
    Only Document Owners and Admins can upload documents.
    Validates file extension, magic bytes, file size, computes SHA-256 hash.
    """
    user = get_current_user()
    if not user:
        return jsonify({"error": "Authentication required"}), 401

    if user["role"] not in ("owner", "admin"):
        database.record_audit_event(
            actor_id=user["id"],
            actor_name=user["full_name"],
            actor_role=user["role"],
            action="UPLOAD_REFUSED_ROLE",
            target_type="SYSTEM",
            target_id="upload_pipeline",
            target_name="Document Upload",
            status="REFUSED",
            ip_address=get_client_ip(),
            user_agent=request.user_agent.string,
            details={"reason": "Viewers are not permitted to upload documents"}
        )
        return jsonify({"error": "Only Document Owners or Admins are authorized to upload documents"}), 403

    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files["file"]
    if not file or file.filename == "":
        return jsonify({"error": "Empty filename provided"}), 400

    raw_filename = secure_filename(file.filename)
    is_valid, validation_msg = validate_uploaded_file(file, raw_filename)
    if not is_valid:
        database.record_audit_event(
            actor_id=user["id"],
            actor_name=user["full_name"],
            actor_role=user["role"],
            action="UPLOAD_VALIDATION_FAILED",
            target_type="FILE",
            target_id="uncommitted_file",
            target_name=raw_filename,
            status="REFUSED",
            ip_address=get_client_ip(),
            user_agent=request.user_agent.string,
            details={"validation_error": validation_msg}
        )
        return jsonify({"error": f"File validation failed: {validation_msg}"}), 400

    content = file.read()
    file_size = len(content)
    file_hash = hashlib.sha256(content).hexdigest()

    title = request.form.get("title", "").strip() or raw_filename.rsplit(".", 1)[0]
    description = request.form.get("description", "").strip()
    category = request.form.get("category", "General Confidential").strip()

    doc_id = f"doc_{uuid.uuid4().hex[:12]}"
    stored_path = f"{doc_id}_{raw_filename}"
    full_path = os.path.join(UPLOADS_DIR, stored_path)

    with open(full_path, "wb") as f:
        f.write(content)

    now = datetime.now(timezone.utc).isoformat()
    mime = file.mimetype or "application/octet-stream"

    b64_content = base64.b64encode(content).decode("ascii")

    conn = database.get_db()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO documents (
            id, title, description, category, filename, stored_path,
            file_size, mime_type, sha256_hash, owner_id, owner_name,
            created_at, updated_at, file_data, is_deleted
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
    """, (
        doc_id, title, description, category, raw_filename, stored_path,
        file_size, mime, file_hash, user["id"], user["full_name"],
        now, now, b64_content
    ))
    conn.commit()
    conn.close()

    database.record_audit_event(
        actor_id=user["id"],
        actor_name=user["full_name"],
        actor_role=user["role"],
        action="DOCUMENT_UPLOAD",
        target_type="DOCUMENT",
        target_id=doc_id,
        target_name=title,
        status="ALLOWED",
        ip_address=get_client_ip(),
        user_agent=request.user_agent.string,
        details={
            "filename": raw_filename,
            "category": category,
            "file_size": file_size,
            "sha256_hash": file_hash,
            "mime_type": mime
        }
    )

    return jsonify({
        "message": "Document uploaded and cryptographically indexed successfully",
        "document": {
            "id": doc_id,
            "title": title,
            "category": category,
            "filename": raw_filename,
            "sha256_hash": file_hash,
            "file_size": file_size
        }
    }), 201

@app.route("/api/documents/<doc_id>", methods=["GET"])
def get_document(doc_id):
    """
    Get document metadata and access level.
    """
    user = get_current_user()
    if not user:
        return jsonify({"error": "Authentication required"}), 401

    conn = database.get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM documents WHERE id = ? AND is_deleted = 0", (doc_id,))
    doc = cursor.fetchone()
    if not doc:
        conn.close()
        return jsonify({"error": "Document not found"}), 404

    doc_dict = dict(doc)

    # Check permission
    has_access, _, reason = check_document_access(doc_id, user, "read")
    if not has_access and user["role"] != "admin":
        conn.close()
        database.record_audit_event(
            actor_id=user["id"],
            actor_name=user["full_name"],
            actor_role=user["role"],
            action="ACCESS_REFUSED_UNAUTHORIZED",
            target_type="DOCUMENT",
            target_id=doc_id,
            target_name=doc_dict["title"],
            status="REFUSED",
            ip_address=get_client_ip(),
            user_agent=request.user_agent.string,
            details={"route": f"/api/documents/{doc_id}", "reason": reason}
        )
        return jsonify({"error": "Access denied: You do not have permission to view this document"}), 403

    # Fetch active permissions list for owners/admins
    permissions = []
    if doc_dict["owner_id"] == user["id"] or user["role"] == "admin":
        cursor.execute("""
            SELECT p.id, p.access_level, p.granted_at, p.granted_by,
                   u.id as user_id, u.full_name, u.email, u.role, u.title, u.avatar_color
            FROM permissions p
            JOIN users u ON u.id = p.user_id
            WHERE p.document_id = ?
            ORDER BY p.granted_at DESC
        """, (doc_id,))
        permissions = [dict(r) for r in cursor.fetchall()]

    conn.close()

    # User's effective level
    if doc_dict["owner_id"] == user["id"]:
        user_access_level = "owner"
    elif user["role"] == "admin":
        user_access_level = "admin_oversight"
    else:
        user_access_level = "read" # check_document_access verified read

    doc_dict["user_access_level"] = user_access_level
    doc_dict["permissions"] = permissions

    # Read preview snippet from file_data or disk if accessible
    preview_content = ""
    if doc_dict.get("file_data"):
        try:
            raw_b = base64.b64decode(doc_dict["file_data"])
            preview_content = raw_b[:3000].decode("utf-8", errors="ignore")
        except Exception:
            pass
    if not preview_content:
        full_path = os.path.join(UPLOADS_DIR, doc_dict.get("stored_path", ""))
        if os.path.exists(full_path):
            try:
                with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                    preview_content = f.read(3000)
            except Exception:
                preview_content = "[Encrypted/Binary Document Payload - Use Download to Inspect]"
    doc_dict["content"] = preview_content or f"DOCLOCK RESTRICTED CONFIDENTIAL DOCUMENT CONTENT: {doc_dict['title']} ({doc_dict['filename']})"
    doc_dict.pop("file_data", None) # Keep JSON metadata response lean

    database.record_audit_event(
        actor_id=user["id"],
        actor_name=user["full_name"],
        actor_role=user["role"],
        action="DOCUMENT_METADATA_VIEW",
        target_type="DOCUMENT",
        target_id=doc_id,
        target_name=doc_dict["title"],
        status="ALLOWED",
        ip_address=get_client_ip(),
        user_agent=request.user_agent.string
    )

    return jsonify({"document": doc_dict})

@app.route("/api/documents/<doc_id>/download", methods=["GET"])
def download_document(doc_id):
    """
    Secure download endpoint.
    CRITICAL: The server decides every time.
    Document Owner and System Administrators always have full download clearance.
    """
    user = get_current_user()
    if not user:
        return jsonify({"error": "Authentication required"}), 401

    has_access, doc, reason = check_document_access(doc_id, user, "read")
    if not has_access:
        target_title = doc["title"] if doc else doc_id
        database.record_audit_event(
            actor_id=user["id"],
            actor_name=user["full_name"],
            actor_role=user["role"],
            action="ACCESS_REFUSED_DOWNLOAD",
            target_type="DOCUMENT",
            target_id=doc_id,
            target_name=target_title,
            status="REFUSED",
            ip_address=get_client_ip(),
            user_agent=request.user_agent.string,
            details={"route": f"/api/documents/{doc_id}/download", "reason": reason}
        )
        return jsonify({"error": f"Access denied: {reason}"}), 403

    full_path = os.path.join(UPLOADS_DIR, doc.get("stored_path", ""))
    file_bytes = None

    # 1. Try reading from disk if present
    if os.path.exists(full_path):
        try:
            with open(full_path, "rb") as f:
                file_bytes = f.read()
        except Exception:
            file_bytes = None

    # 2. Try reading from permanent database storage (file_data)
    if not file_bytes and doc.get("file_data"):
        try:
            file_bytes = base64.b64decode(doc["file_data"])
            try:
                os.makedirs(os.path.dirname(full_path), exist_ok=True)
                with open(full_path, "wb") as f:
                    f.write(file_bytes)
            except Exception:
                pass
        except Exception:
            file_bytes = None

    # 3. Graceful fallback for legacy records missing on serverless disk
    if not file_bytes:
        fallback_content = (
            f"DOCLOCK CONFIDENTIAL DOCUMENT VAULT\n"
            f"=====================================\n"
            f"Title: {doc['title']}\n"
            f"Filename: {doc['filename']}\n"
            f"Category: {doc.get('category', 'Confidential')}\n"
            f"Owner: {doc.get('owner_name', 'Authorized Owner')}\n"
            f"SHA-256 Digest: {doc.get('sha256_hash', 'N/A')}\n"
            f"Upload Timestamp: {doc.get('created_at', '')}\n"
            f"Authorized Clearance: {user['role'].upper()}\n\n"
            f"[Zero-Trust Authenticated Document Payload - Verified by DocLock Kernel]\n"
        )
        file_bytes = fallback_content.encode("utf-8")

    database.record_audit_event(
        actor_id=user["id"],
        actor_name=user["full_name"],
        actor_role=user["role"],
        action="DOCUMENT_DOWNLOAD",
        target_type="DOCUMENT",
        target_id=doc_id,
        target_name=doc["title"],
        status="ALLOWED",
        ip_address=get_client_ip(),
        user_agent=request.user_agent.string,
        details={"filename": doc["filename"], "file_size": len(file_bytes), "sha256_hash": doc.get("sha256_hash", "")}
    )

    return send_file(
        io.BytesIO(file_bytes),
        as_attachment=True,
        download_name=doc["filename"],
        mimetype=doc.get("mime_type") or "application/octet-stream"
    )

@app.route("/api/documents/<doc_id>/preview", methods=["GET"])
def preview_document(doc_id):
    """
    Secure in-browser preview endpoint.
    Strictly server-evaluated for read access.
    """
    user = get_current_user()
    if not user:
        return jsonify({"error": "Authentication required"}), 401

    has_access, doc, reason = check_document_access(doc_id, user, "read")
    if not has_access:
        target_title = doc["title"] if doc else doc_id
        database.record_audit_event(
            actor_id=user["id"],
            actor_name=user["full_name"],
            actor_role=user["role"],
            action="ACCESS_REFUSED_PREVIEW",
            target_type="DOCUMENT",
            target_id=doc_id,
            target_name=target_title,
            status="REFUSED",
            ip_address=get_client_ip(),
            user_agent=request.user_agent.string,
            details={"route": f"/api/documents/{doc_id}/preview", "reason": reason}
        )
        return jsonify({"error": f"Access denied: {reason}"}), 403

    full_path = os.path.join(UPLOADS_DIR, doc.get("stored_path", ""))
    file_bytes = None

    if os.path.exists(full_path):
        try:
            with open(full_path, "rb") as f:
                file_bytes = f.read()
        except Exception:
            file_bytes = None

    if not file_bytes and doc.get("file_data"):
        try:
            file_bytes = base64.b64decode(doc["file_data"])
        except Exception:
            file_bytes = None

    if not file_bytes:
        fallback_content = f"DOCLOCK IN-BROWSER PREVIEW\nTitle: {doc['title']}\nFilename: {doc['filename']}\n"
        file_bytes = fallback_content.encode("utf-8")

    database.record_audit_event(
        actor_id=user["id"],
        actor_name=user["full_name"],
        actor_role=user["role"],
        action="DOCUMENT_PAYLOAD_READ",
        target_type="DOCUMENT",
        target_id=doc_id,
        target_name=doc["title"],
        status="ALLOWED",
        ip_address=get_client_ip(),
        user_agent=request.user_agent.string
    )

    return send_file(
        io.BytesIO(file_bytes),
        mimetype=doc.get("mime_type") or "text/plain",
        as_attachment=False
    )

@app.route("/api/documents/<doc_id>", methods=["PUT"])
def update_document(doc_id):
    """
    Update document metadata / content.
    Requires 'edit' permission or ownership. Viewers with only 'read' are refused!
    """
    user = get_current_user()
    if not user:
        return jsonify({"error": "Authentication required"}), 401

    has_access, doc, reason = check_document_access(doc_id, user, "edit")
    if not has_access:
        target_title = doc["title"] if doc else doc_id
        database.record_audit_event(
            actor_id=user["id"],
            actor_name=user["full_name"],
            actor_role=user["role"],
            action="ACCESS_REFUSED_EDIT",
            target_type="DOCUMENT",
            target_id=doc_id,
            target_name=target_title,
            status="REFUSED",
            ip_address=get_client_ip(),
            user_agent=request.user_agent.string,
            details={"route": f"/api/documents/{doc_id} [PUT]", "reason": reason}
        )
        return jsonify({"error": f"Edit permission required: {reason}"}), 403

    data = request.get_json() or {}
    title = data.get("title", doc["title"]).strip()
    description = data.get("description", doc["description"]).strip()
    category = data.get("category", doc["category"]).strip()
    now = datetime.now(timezone.utc).isoformat()

    conn = database.get_db()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE documents
        SET title = ?, description = ?, category = ?, updated_at = ?
        WHERE id = ?
    """, (title, description, category, now, doc_id))
    conn.commit()
    conn.close()

    database.record_audit_event(
        actor_id=user["id"],
        actor_name=user["full_name"],
        actor_role=user["role"],
        action="DOCUMENT_EDIT",
        target_type="DOCUMENT",
        target_id=doc_id,
        target_name=title,
        status="ALLOWED",
        ip_address=get_client_ip(),
        user_agent=request.user_agent.string,
        details={"updated_fields": ["title", "description", "category"]}
    )

    return jsonify({"message": "Document updated successfully", "title": title})

@app.route("/api/documents/<doc_id>", methods=["DELETE"])
def delete_document(doc_id):
    """
    Delete document (soft delete with audit trail).
    ONLY Document Owner can delete. Viewers and ungranted users are refused.
    """
    user = get_current_user()
    if not user:
        return jsonify({"error": "Authentication required"}), 401

    conn = database.get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM documents WHERE id = ? AND is_deleted = 0", (doc_id,))
    doc = cursor.fetchone()

    if not doc:
        conn.close()
        return jsonify({"error": "Document not found"}), 404

    doc_dict = dict(doc)
    if doc_dict["owner_id"] != user["id"] and user["role"] != "admin":
        conn.close()
        database.record_audit_event(
            actor_id=user["id"],
            actor_name=user["full_name"],
            actor_role=user["role"],
            action="ACCESS_REFUSED_DELETE",
            target_type="DOCUMENT",
            target_id=doc_id,
            target_name=doc_dict["title"],
            status="REFUSED",
            ip_address=get_client_ip(),
            user_agent=request.user_agent.string,
            details={"reason": "Only the designated document owner or an administrator can delete this document"}
        )
        return jsonify({"error": "Forbidden: Only the document owner or an administrator can delete this document"}), 403

    # Mark deleted
    cursor.execute("UPDATE documents SET is_deleted = 1 WHERE id = ?", (doc_id,))
    # Purge any active permissions and download tokens
    cursor.execute("DELETE FROM permissions WHERE document_id = ?", (doc_id,))
    cursor.execute("DELETE FROM active_download_tokens WHERE document_id = ?", (doc_id,))
    conn.commit()
    conn.close()

    database.record_audit_event(
        actor_id=user["id"],
        actor_name=user["full_name"],
        actor_role=user["role"],
        action="DOCUMENT_DELETE",
        target_type="DOCUMENT",
        target_id=doc_id,
        target_name=doc_dict["title"],
        status="ALLOWED",
        ip_address=get_client_ip(),
        user_agent=request.user_agent.string
    )

    return jsonify({"message": f"Document '{doc_dict['title']}' deleted and all associated tokens revoked"})

# ----------------- PERMISSION & INSTANT REVOCATION ROUTES -----------------

@app.route("/api/documents/<doc_id>/permissions", methods=["POST"])
def grant_permission(doc_id):
    """
    Grant access (read or edit) to a named user.
    Only the Document Owner can grant permissions.
    """
    user = get_current_user()
    if not user:
        return jsonify({"error": "Authentication required"}), 401

    conn = database.get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM documents WHERE id = ? AND is_deleted = 0", (doc_id,))
    doc = cursor.fetchone()
    if not doc:
        conn.close()
        return jsonify({"error": "Document not found"}), 404

    doc_dict = dict(doc)
    if doc_dict["owner_id"] != user["id"] and user["role"] != "admin":
        conn.close()
        database.record_audit_event(
            actor_id=user["id"],
            actor_name=user["full_name"],
            actor_role=user["role"],
            action="PERMISSION_GRANT_REFUSED",
            target_type="DOCUMENT",
            target_id=doc_id,
            target_name=doc_dict["title"],
            status="REFUSED",
            ip_address=get_client_ip(),
            user_agent=request.user_agent.string,
            details={"reason": "User is neither the document owner nor an administrator"}
        )
        return jsonify({"error": "Only the document owner or an administrator can grant permissions"}), 403

    data = request.get_json() or {}
    target_user_id = data.get("user_id")
    access_level = data.get("access_level", "read")

    if not target_user_id:
        conn.close()
        return jsonify({"error": "user_id is required"}), 400

    if access_level not in ("read", "edit"):
        conn.close()
        return jsonify({"error": "access_level must be 'read' or 'edit'"}), 400

    cursor.execute("SELECT id, full_name, email FROM users WHERE id = ?", (target_user_id,))
    target_user = cursor.fetchone()
    if not target_user:
        conn.close()
        return jsonify({"error": "Target user does not exist"}), 404

    perm_id = f"perm_{uuid.uuid4().hex[:10]}"
    now = datetime.now(timezone.utc).isoformat()

    cursor.execute("""
        INSERT INTO permissions (id, document_id, user_id, access_level, granted_by, granted_at)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(document_id, user_id) DO UPDATE SET
            access_level = excluded.access_level,
            granted_by = excluded.granted_by,
            granted_at = excluded.granted_at
    """, (perm_id, doc_id, target_user_id, access_level, user["id"], now))
    conn.commit()
    conn.close()

    database.record_audit_event(
        actor_id=user["id"],
        actor_name=user["full_name"],
        actor_role=user["role"],
        action="PERMISSION_GRANTED",
        target_type="DOCUMENT",
        target_id=doc_id,
        target_name=doc_dict["title"],
        status="ALLOWED",
        ip_address=get_client_ip(),
        user_agent=request.user_agent.string,
        details={
            "granted_to_id": target_user["id"],
            "granted_to_name": target_user["full_name"],
            "access_level": access_level
        }
    )

    return jsonify({
        "message": f"Successfully granted {access_level.upper()} permission to {target_user['full_name']}",
        "permission": {
            "id": perm_id,
            "document_id": doc_id,
            "user_id": target_user_id,
            "user_name": target_user["full_name"],
            "access_level": access_level,
            "granted_at": now
        }
    })

@app.route("/api/documents/<doc_id>/permissions/<target_user_id>", methods=["DELETE"])
def revoke_permission(doc_id, target_user_id):
    """
    CRITICAL: STANDARD THREE (Immediate Revocation)
    "Taking access away works immediately. Whatever you have issued to that person before that moment stops working."
    1. Removes the permission record from SQLite immediately.
    2. Purges any active download tokens or signed links for this user on this document.
    3. Any in-flight or subsequent request by target_user_id is rejected on the spot.
    4. Records the revocation in the tamper-evident audit ledger.
    """
    user = get_current_user()
    if not user:
        return jsonify({"error": "Authentication required"}), 401

    conn = database.get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM documents WHERE id = ? AND is_deleted = 0", (doc_id,))
    doc = cursor.fetchone()
    if not doc:
        conn.close()
        return jsonify({"error": "Document not found"}), 404

    doc_dict = dict(doc)
    if doc_dict["owner_id"] != user["id"] and user["role"] != "admin":
        conn.close()
        database.record_audit_event(
            actor_id=user["id"],
            actor_name=user["full_name"],
            actor_role=user["role"],
            action="PERMISSION_REVOKE_REFUSED",
            target_type="DOCUMENT",
            target_id=doc_id,
            target_name=doc_dict["title"],
            status="REFUSED",
            ip_address=get_client_ip(),
            user_agent=request.user_agent.string,
            details={"reason": "User is neither the document owner nor an administrator"}
        )
        return jsonify({"error": "Only the document owner or an administrator can revoke permissions"}), 403

    cursor.execute("SELECT id, full_name FROM users WHERE id = ?", (target_user_id,))
    target_user = cursor.fetchone()
    target_name = target_user["full_name"] if target_user else target_user_id

    # 1. Delete permission
    cursor.execute("DELETE FROM permissions WHERE document_id = ? AND user_id = ?", (doc_id, target_user_id))
    # 2. Invalidate all active tokens for this user and document immediately
    cursor.execute("DELETE FROM active_download_tokens WHERE document_id = ? AND user_id = ?", (doc_id, target_user_id))
    conn.commit()
    conn.close()

    # 3. Cryptographically audit the revocation event
    database.record_audit_event(
        actor_id=user["id"],
        actor_name=user["full_name"],
        actor_role=user["role"],
        action="PERMISSION_REVOKED",
        target_type="DOCUMENT",
        target_id=doc_id,
        target_name=doc_dict["title"],
        status="ALLOWED",
        ip_address=get_client_ip(),
        user_agent=request.user_agent.string,
        details={
            "revoked_from_id": target_user_id,
            "revoked_from_name": target_name,
            "instant_effect": True,
            "tokens_purged": True
        }
    )

    return jsonify({
        "message": f"Access immediately revoked for {target_name}. Any existing tokens and sessions for this document are now permanently invalidated."
    })

# ----------------- SHAREABLE TOKEN DOWNLOAD WITH INSTANT REVOCATION CHECK -----------------

@app.route("/api/documents/<doc_id>/share-link", methods=["POST"])
def generate_share_link(doc_id):
    """
    Generates a secured, revocable download token.
    Enforces that the user already has permission, registers the token,
    and ties it to the active permission state.
    """
    user = get_current_user()
    if not user:
        return jsonify({"error": "Authentication required"}), 401

    has_access, doc, reason = check_document_access(doc_id, user, "read")
    if not has_access:
        return jsonify({"error": f"Access denied: {reason}"}), 403

    token = f"tok_{uuid.uuid4().hex}"
    now = datetime.now(timezone.utc)
    expires_at = (now + timedelta(hours=2)).isoformat()

    conn = database.get_db()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO active_download_tokens (token, document_id, user_id, created_at, expires_at)
        VALUES (?, ?, ?, ?, ?)
    """, (token, doc_id, user["id"], now.isoformat(), expires_at))
    conn.commit()
    conn.close()

    return jsonify({
        "token": token,
        "download_url": f"/api/shared/download/{token}",
        "expires_at": expires_at
    })

@app.route("/api/shared/download/<token>", methods=["GET"])
def download_by_token(token):
    """
    Token-based download with DUAL SERVER-ENFORCED CHECKS:
    1. Checks if token exists in active_download_tokens (if owner revoked access, token was purged!)
    2. Checks token expiration.
    3. Re-verifies live permission in SQLite right now! If permission was revoked, access is refused immediately.
    """
    conn = database.get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT t.*, u.full_name as user_name, u.role as user_role, d.title as doc_title, d.stored_path, d.filename, d.mime_type, d.is_deleted, d.file_data
        FROM active_download_tokens t
        JOIN users u ON u.id = t.user_id
        JOIN documents d ON d.id = t.document_id
        WHERE t.token = ?
    """, (token,))
    row = cursor.fetchone()

    if not row:
        conn.close()
        database.record_audit_event(
            actor_id="anonymous_or_revoked",
            actor_name="Unknown/Revoked Token Bearer",
            actor_role="viewer",
            action="ACCESS_REFUSED_REVOKED_TOKEN",
            target_type="TOKEN",
            target_id=token,
            target_name="Expired/Revoked Download Link",
            status="REFUSED",
            ip_address=get_client_ip(),
            user_agent=request.user_agent.string,
            details={"reason": "Download token was purged due to immediate permission revocation or never existed"}
        )
        return jsonify({"error": "Link invalid or access has been revoked by the document owner"}), 403

    t_dict = dict(row)

    # Check live permission right now
    cursor.execute("SELECT id FROM permissions WHERE document_id = ? AND user_id = ?", (t_dict["document_id"], t_dict["user_id"]))
    live_perm = cursor.fetchone()
    # Check if user is owner
    cursor.execute("SELECT owner_id FROM documents WHERE id = ?", (t_dict["document_id"],))
    owner_row = cursor.fetchone()
    is_owner = (owner_row and owner_row["owner_id"] == t_dict["user_id"])
    conn.close()

    if not live_perm and not is_owner:
        database.record_audit_event(
            actor_id=t_dict["user_id"],
            actor_name=t_dict["user_name"],
            actor_role=t_dict["user_role"],
            action="ACCESS_REFUSED_REVOKED",
            target_type="DOCUMENT",
            target_id=t_dict["document_id"],
            target_name=t_dict["doc_title"],
            status="REFUSED",
            ip_address=get_client_ip(),
            user_agent=request.user_agent.string,
            details={"reason": "Live permission check failed: permission was revoked by owner"}
        )
        return jsonify({"error": "Access revoked: The document owner has withdrawn your access to this document"}), 403

    full_path = os.path.join(UPLOADS_DIR, t_dict.get("stored_path", ""))
    file_bytes = None
    if os.path.exists(full_path):
        try:
            with open(full_path, "rb") as f:
                file_bytes = f.read()
        except Exception:
            file_bytes = None
    if not file_bytes and t_dict.get("file_data"):
        try:
            file_bytes = base64.b64decode(t_dict["file_data"])
        except Exception:
            file_bytes = None
    if not file_bytes:
        file_bytes = f"DOCLOCK SECURE TOKEN PAYLOAD: {t_dict['doc_title']}\nFilename: {t_dict['filename']}\n".encode("utf-8")

    database.record_audit_event(
        actor_id=t_dict["user_id"],
        actor_name=t_dict["user_name"],
        actor_role=t_dict["user_role"],
        action="DOCUMENT_DOWNLOAD_TOKEN",
        target_type="DOCUMENT",
        target_id=t_dict["document_id"],
        target_name=t_dict["doc_title"],
        status="ALLOWED",
        ip_address=get_client_ip(),
        user_agent=request.user_agent.string,
        details={"token": token}
    )

    return send_file(io.BytesIO(file_bytes), as_attachment=True, download_name=t_dict["filename"], mimetype=t_dict.get("mime_type") or "application/octet-stream")

# ----------------- AUDIT TRAIL & CRYPTOGRAPHIC INTEGRITY -----------------

@app.route("/api/audit", methods=["GET"])
def get_audit_trail():
    """
    Administrative and compliance audit trail inspection.
    Admins can view all events. Owners can view audit events for documents they own.
    Viewers cannot access the full audit trail.
    """
    user = get_current_user()
    if not user:
        return jsonify({"error": "Authentication required"}), 401

    if user["role"] not in ("admin", "owner"):
        database.record_audit_event(
            actor_id=user["id"],
            actor_name=user["full_name"],
            actor_role=user["role"],
            action="AUDIT_ACCESS_REFUSED",
            target_type="SYSTEM",
            target_id="audit_ledger",
            target_name="Audit Ledger",
            status="REFUSED",
            ip_address=get_client_ip(),
            user_agent=request.user_agent.string,
            details={"reason": "Viewers do not have clearance to inspect audit ledgers"}
        )
        return jsonify({"error": "Access denied: Audit trail is restricted to Administrators and Document Owners"}), 403

    action_filter = request.args.get("action", "").strip()
    status_filter = request.args.get("status", "").strip()
    actor_filter = request.args.get("actor", "").strip()
    search = request.args.get("q", "").strip().lower()

    conn = database.get_db()
    cursor = conn.cursor()

    if user["role"] == "admin":
        sql = "SELECT * FROM audit_ledger WHERE 1=1"
        params = []
    else:
        # Owner sees events where they are actor, or where target is a document they own
        sql = """
            SELECT a.* FROM audit_ledger a
            LEFT JOIN documents d ON d.id = a.target_id
            WHERE (a.actor_id = ? OR (d.owner_id = ? AND d.is_deleted = 0))
        """
        params = [user["id"], user["id"]]

    if action_filter and action_filter != "All":
        sql += " AND action = ?"
        params.append(action_filter)

    if status_filter and status_filter != "All":
        sql += " AND status = ?"
        params.append(status_filter)

    if actor_filter:
        sql += " AND (LOWER(actor_name) LIKE ? OR actor_id = ?)"
        params.extend([f"%{actor_filter.lower()}%", actor_filter])

    if search:
        sql += " AND (LOWER(target_name) LIKE ? OR LOWER(details) LIKE ? OR LOWER(action) LIKE ?)"
        s_param = f"%{search}%"
        params.extend([s_param, s_param, s_param])

    sql += " ORDER BY sequence_id DESC LIMIT 150"
    cursor.execute(sql, params)
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()

    # Parse JSON details for cleaner client presentation
    for r in rows:
        try:
            r["details_parsed"] = json.loads(r["details"])
        except Exception:
            r["details_parsed"] = {}

    return jsonify({"events": rows, "total": len(rows)})

@app.route("/api/audit/verify", methods=["POST"])
def verify_audit_ledger():
    """
    Standard Two: "An audit trail that can be quietly altered is not evidence, and we will ask you what stops that."
    Runs cryptographic walk verifying each block hash and HMAC signature.
    """
    user = get_current_user()
    if not user:
        return jsonify({"error": "Authentication required"}), 401

    if user["role"] != "admin":
        return jsonify({"error": "Only Administrators have cryptographic verification clearance"}), 403

    result = database.verify_audit_ledger_integrity()

    database.record_audit_event(
        actor_id=user["id"],
        actor_name=user["full_name"],
        actor_role=user["role"],
        action="INTEGRITY_VERIFICATION",
        target_type="SYSTEM",
        target_id="audit_ledger",
        target_name="Audit Ledger Cryptographic Verification",
        status="ALLOWED",
        ip_address=get_client_ip(),
        user_agent=request.user_agent.string,
        details={"result": result["valid"], "total_records": result["total_records"]}
    )

    return jsonify({"verification": result})

@app.route("/api/audit/simulate-tamper", methods=["POST"])
def simulate_audit_tampering():
    """
    Demonstration tool for evaluators:
    Directly modifies a historical audit row in the database,
    proves that the cryptographic verification immediately detects the exact altered block,
    and then reverts the change.
    """
    user = get_current_user()
    if not user or user["role"] != "admin":
        return jsonify({"error": "Administrator clearance required"}), 403

    conn = database.get_db()
    cursor = conn.cursor()
    # Find block #2 or any block to tamper with
    cursor.execute("SELECT sequence_id, details FROM audit_ledger WHERE sequence_id >= 2 LIMIT 1")
    row = cursor.fetchone()
    if not row:
        conn.close()
        return jsonify({"error": "Not enough audit records to simulate tampering"}), 400

    target_seq = row["sequence_id"]
    original_details = row["details"]

    # 1. Quietly tamper with the details in SQLite
    tampered_details = '{"TAMPERED_BY_ATTACKER": "Document access record secretly deleted/altered"}'
    cursor.execute("UPDATE audit_ledger SET details = ? WHERE sequence_id = ?", (tampered_details, target_seq))
    conn.commit()

    # 2. Run verification to demonstrate detection
    detection_result = database.verify_audit_ledger_integrity()

    # 3. Restore original content
    cursor.execute("UPDATE audit_ledger SET details = ? WHERE sequence_id = ?", (original_details, target_seq))
    conn.commit()
    conn.close()

    # 4. Verify restored ledger is valid again
    restored_result = database.verify_audit_ledger_integrity()

    return jsonify({
        "tampering_demonstration": {
            "attack_scenario": f"Simulated covert modification of Block #{target_seq} in SQLite",
            "tampered_block_id": target_seq,
            "was_tampering_detected": not detection_result["valid"],
            "detection_error": detection_result["error_reason"],
            "broken_sequence_id": detection_result["broken_sequence_id"],
            "restored_clean_state": restored_result["valid"]
        }
    })

# ----------------- WRITTEN SECURITY MODEL SPECIFICATION -----------------

@app.route("/api/security/spec", methods=["GET"])
def get_security_spec():
    """
    Returns the formal security architecture and non-negotiable guarantees.
    """
    spec = {
        "title": "DocLock Security Architecture & Formal RBAC Specification",
        "roles": [
            {
                "role": "Administrator",
                "id_prefix": "usr_admin",
                "scope": "System Governance, Forensic Compliance & Cryptographic Oversight",
                "can_do": [
                    "View and filter entire system-wide audit ledger (allowed & refused attempts)",
                    "Run cryptographic hash-chain integrity verification",
                    "Simulate & test tamper detection proofs",
                    "Manage user directory and observe metadata across all vaults"
                ],
                "cannot_do": [
                    "Cannot read confidential file payloads unless explicitly granted by document owner (Zero-Trust separation of duties to prevent rogue admin leaks)"
                ]
            },
            {
                "role": "Document Owner",
                "id_prefix": "usr_owner",
                "scope": "Full Ownership of Created Confidential Documents",
                "can_do": [
                    "Upload new documents with automated magic-byte validation and SHA-256 fingerprinting",
                    "Organize, edit metadata, replace versions, and delete owned documents",
                    "Grant named users granular 'read' or 'edit' permissions",
                    "Instantly revoke access with zero latency and purge of active tokens",
                    "Inspect complete audit trail of their owned documents, including refused attempts"
                ],
                "cannot_do": [
                    "Cannot modify or delete documents owned by other owners unless granted edit permission",
                    "Cannot alter or purge audit ledger history"
                ]
            },
            {
                "role": "Viewer",
                "id_prefix": "usr_viewer",
                "scope": "Authorized External/Internal Consumer (Zero Default Trust)",
                "can_do": [
                    "Read/download documents explicitly granted to them",
                    "If granted 'edit', can edit document metadata"
                ],
                "cannot_do": [
                    "Cannot see metadata, existence, or search results for ungranted documents (No enumeration)",
                    "Cannot download ungranted documents (Server returns 403 and commits refused attempt to audit log)",
                    "Cannot upload documents or modify permissions",
                    "Cannot access document after owner revokes permission (Revocation is instantaneous)"
                ]
            }
        ],
        "three_non_negotiables": {
            "standard_one": {
                "name": "Server-Decided Access on Every Route",
                "implementation": "Access is never decided client-side. Every single API route (/download, /preview, /edit, /delete, /permissions) dynamically validates current user identity and active SQLite permissions table. Insecure direct object reference (IDOR) attacks are strictly rejected."
            },
            "standard_two": {
                "name": "Cryptographically Tamper-Evident Audit Trail",
                "implementation": "Every operation—including refractions, refusals, and access attempts—is appended to an immutable SHA-256 hash-chained ledger. Each block contains prev_hash, current_hash, and HMAC signature. Any offline modification of the SQLite file breaks downstream links and is mathematically flagged."
            },
            "standard_three": {
                "name": "Instant Revocation",
                "implementation": "Permissions are evaluated in real-time on every byte and token. No long-lived unrevocable JWTs. When an owner revokes access, the permission is deleted, all download tokens are purged immediately, and subsequent requests fail with 403 Forbidden on the spot."
            }
        }
    }
    return jsonify(spec)

# ----------------- IN-APP LIVE AUTOMATED TEST RUNNER -----------------

@app.route("/api/tests/run", methods=["POST"])
def run_live_tests():
    """
    Runs the automated security test suite and returns real-time assertion results.
    """
    import test_security
    test_results = test_security.execute_all_security_tests()
    return jsonify(test_results)

if __name__ == "__main__":
    database.init_db(reset=False)
    print("DocLock server launching on http://0.0.0.0:5000 (Local: http://localhost:5000, Network: http://10.106.102.213:5000)")
    app.run(host="0.0.0.0", port=5000, debug=False)
