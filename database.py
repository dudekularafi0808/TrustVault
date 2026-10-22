import sqlite3
import os
import json
import hashlib
import hmac
import uuid
from datetime import datetime, timezone

# Auto-load .env file if present
def _load_env_file():
    env_file = os.path.join(os.path.dirname(__file__), ".env")
    if os.path.exists(env_file):
        try:
            with open(env_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        k, v = line.split("=", 1)
                        k = k.strip()
                        v = v.strip().strip("'\"")
                        if k and k not in os.environ:
                            os.environ[k] = v
        except Exception:
            pass

_load_env_file()

DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()
IS_POSTGRES = DATABASE_URL.startswith("postgresql://") or DATABASE_URL.startswith("postgres://")

def _normalize_pg_url(url: str) -> str:
    if url.count("@") > 1 and "://" in url:
        prefix, rest = url.split("://", 1)
        user_info, host_info = rest.rsplit("@", 1)
        if ":" in user_info:
            user, pwd = user_info.split(":", 1)
            import urllib.parse
            url = f"{prefix}://{user}:{urllib.parse.quote(pwd, safe='')}@{host_info}"
    if "sslmode=" not in url:
        sep = "&" if "?" in url else "?"
        url = f"{url}{sep}sslmode=require"
    return url

if IS_POSTGRES:
    import psycopg2
    import psycopg2.extras

    class PostgresCursorWrapper:
        def __init__(self, raw_cursor):
            self._cur = raw_cursor

        def _convert_query(self, query):
            if "?" in query:
                return query.replace("?", "%s")
            return query

        def execute(self, query, params=None):
            converted = self._convert_query(query)
            if params is not None:
                return self._cur.execute(converted, params)
            return self._cur.execute(converted)

        def executemany(self, query, param_seq):
            converted = self._convert_query(query)
            return self._cur.executemany(converted, param_seq)

        def executescript(self, script):
            return self._cur.execute(script)

        def fetchone(self):
            return self._cur.fetchone()

        def fetchall(self):
            return self._cur.fetchall()

        def fetchmany(self, size=None):
            return self._cur.fetchmany(size) if size else self._cur.fetchmany()

        @property
        def rowcount(self):
            return self._cur.rowcount

        @property
        def description(self):
            return self._cur.description

        def close(self):
            try:
                self._cur.close()
            except Exception:
                pass

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_val, exc_tb):
            self.close()

    class PostgresConnWrapper:
        def __init__(self, raw_conn):
            self._conn = raw_conn

        def cursor(self):
            raw_cur = self._conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
            return PostgresCursorWrapper(raw_cur)

        def execute(self, query, params=None):
            cur = self.cursor()
            cur.execute(query, params)
            return cur

        def executescript(self, script):
            cur = self.cursor()
            cur.executescript(script)
            return cur

        def commit(self):
            self._conn.commit()

        def rollback(self):
            self._conn.rollback()

        def close(self):
            try:
                self._conn.close()
            except Exception:
                pass

        @property
        def row_factory(self):
            return None

        @row_factory.setter
        def row_factory(self, val):
            pass

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_val, exc_tb):
            if exc_type:
                self.rollback()
            else:
                self.commit()
            self.close()

# Support custom DATABASE_PATH or Vercel serverless writable /tmp directory
if os.environ.get("DATABASE_PATH"):
    DB_PATH = os.environ.get("DATABASE_PATH")
    UPLOADS_DIR = os.environ.get("UPLOADS_DIR") or os.path.join(os.path.dirname(DB_PATH), "uploads")
elif os.environ.get("VERCEL"):
    DB_PATH = "/tmp/trustvault.db"
    UPLOADS_DIR = "/tmp/uploads"
else:
    DB_PATH = os.path.join(os.path.dirname(__file__), "trustvault.db")
    UPLOADS_DIR = os.path.join(os.path.dirname(__file__), "uploads")

VAULT_HMAC_KEY = b"TRUSTVAULT_IMMUTABLE_AUDIT_SECRET_KEY_v2026_DEEPMIND"

def _get_connection():
    if IS_POSTGRES:
        normalized_url = _normalize_pg_url(DATABASE_URL)
        raw_conn = psycopg2.connect(normalized_url)
        return PostgresConnWrapper(raw_conn)
    else:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("PRAGMA journal_mode = WAL;")
        return conn

def get_db():
    if not IS_POSTGRES and not os.path.exists(DB_PATH):
        init_db(reset=False)
    return _get_connection()


def compute_record_hash(sequence_id, prev_hash, timestamp, actor_id, action, target_id, status, details):
    content = f"{sequence_id}|{prev_hash}|{timestamp}|{actor_id}|{action}|{target_id}|{status}|{details}"
    return hashlib.sha256(content.encode("utf-8")).hexdigest()

def compute_signature(record_hash):
    return hmac.new(VAULT_HMAC_KEY, record_hash.encode("utf-8"), hashlib.sha256).hexdigest()

def record_audit_event(actor_id, actor_name, actor_role, action, target_type, target_id, target_name, status, ip_address="127.0.0.1", user_agent="Internal/Client", details=None):
    """
    Append-only cryptographically verifiable hash-chained audit log.
    Every event - whether allowed or refused - is permanently chained.
    """
    if details is None:
        details = {}
    details_str = json.dumps(details, sort_keys=True)
    timestamp = datetime.now(timezone.utc).isoformat()

    conn = get_db()
    cursor = conn.cursor()

    try:
        # Get the previous record's hash and sequence
        cursor.execute("SELECT sequence_id, current_hash FROM audit_ledger ORDER BY sequence_id DESC LIMIT 1")
        last_row = cursor.fetchone()

        if last_row:
            next_seq = last_row["sequence_id"] + 1
            prev_hash = last_row["current_hash"]
        else:
            next_seq = 1
            prev_hash = "0" * 64  # Genesis block

        current_hash = compute_record_hash(next_seq, prev_hash, timestamp, actor_id, action, target_id, status, details_str)
        signature = compute_signature(current_hash)

        cursor.execute("""
            INSERT INTO audit_ledger (
                sequence_id, prev_hash, current_hash, timestamp,
                actor_id, actor_name, actor_role, action,
                target_type, target_id, target_name, status,
                ip_address, user_agent, details, signature
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            next_seq, prev_hash, current_hash, timestamp,
            actor_id, actor_name, actor_role, action,
            target_type, target_id, target_name, status,
            ip_address, user_agent, details_str, signature
        ))
        conn.commit()
        return next_seq, current_hash
    finally:
        conn.close()

def verify_audit_ledger_integrity():
    """
    Cryptographically verifies the entire audit ledger from Genesis block to the tip.
    Returns:
        dict: {
            "valid": bool,
            "total_records": int,
            "refused_events_count": int,
            "broken_sequence_id": int or None,
            "error_reason": str or None,
            "genesis_hash": str,
            "head_hash": str
        }
    """
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM audit_ledger ORDER BY sequence_id ASC")
    rows = cursor.fetchall()
    conn.close()

    if not rows:
        return {
            "valid": True,
            "total_records": 0,
            "refused_events_count": 0,
            "broken_sequence_id": None,
            "error_reason": None,
            "genesis_hash": None,
            "head_hash": None
        }

    expected_prev = "0" * 64
    refused_count = 0

    for i, r in enumerate(rows):
        seq = r["sequence_id"]
        if r["status"] == "REFUSED":
            refused_count += 1

        # 1. Verify prev_hash matches prior link
        if r["prev_hash"] != expected_prev:
            return {
                "valid": False,
                "total_records": len(rows),
                "refused_events_count": refused_count,
                "broken_sequence_id": seq,
                "error_reason": f"Broken chain link at Block #{seq}: prev_hash does not match preceding Block's hash",
                "genesis_hash": rows[0]["current_hash"],
                "head_hash": rows[-1]["current_hash"]
            }

        # 2. Recompute SHA-256
        recomputed = compute_record_hash(
            seq, r["prev_hash"], r["timestamp"], r["actor_id"],
            r["action"], r["target_id"], r["status"], r["details"]
        )
        if recomputed != r["current_hash"]:
            return {
                "valid": False,
                "total_records": len(rows),
                "refused_events_count": refused_count,
                "broken_sequence_id": seq,
                "error_reason": f"Cryptographic integrity failed at Block #{seq}: content payload hash mismatch (tampered record data)",
                "genesis_hash": rows[0]["current_hash"],
                "head_hash": rows[-1]["current_hash"]
            }

        # 3. Verify digital signature
        expected_sig = compute_signature(recomputed)
        if not hmac.compare_digest(expected_sig, r["signature"]):
            return {
                "valid": False,
                "total_records": len(rows),
                "refused_events_count": refused_count,
                "broken_sequence_id": seq,
                "error_reason": f"Invalid signature at Block #{seq}: HMAC signature verification failed",
                "genesis_hash": rows[0]["current_hash"],
                "head_hash": rows[-1]["current_hash"]
            }

        expected_prev = r["current_hash"]

    return {
        "valid": True,
        "total_records": len(rows),
        "refused_events_count": refused_count,
        "broken_sequence_id": None,
        "error_reason": None,
        "genesis_hash": rows[0]["current_hash"],
        "head_hash": rows[-1]["current_hash"]
    }

def hash_password(password: str, salt: str = None) -> str:
    """Generate salted cryptographic password hash."""
    if not salt:
        salt = uuid.uuid4().hex[:16]
    hashed = hashlib.sha256(f"{salt}${password}".encode("utf-8")).hexdigest()
    return f"{salt}${hashed}"

def verify_password(password: str, stored_hash: str) -> bool:
    """Verify password against stored salt$hash or legacy salt_ hash."""
    if not stored_hash:
        return False
    if "$" in stored_hash:
        salt, expected_hash = stored_hash.split("$", 1)
        computed_hash = hashlib.sha256(f"{salt}${password}".encode("utf-8")).hexdigest()
        return hmac.compare_digest(expected_hash, computed_hash)
    # Legacy fallback for early seed format
    legacy_hash = hashlib.sha256(f"salt_{password}".encode("utf-8")).hexdigest()
    return hmac.compare_digest(stored_hash, legacy_hash)

def init_db(reset=False):
    if IS_POSTGRES:
        conn = _get_connection()
        cursor = conn.cursor()
        if reset:
            cursor.executescript("""
                DROP TABLE IF EXISTS audit_ledger CASCADE;
                DROP TABLE IF EXISTS outbound_emails CASCADE;
                DROP TABLE IF EXISTS password_resets CASCADE;
                DROP TABLE IF EXISTS active_download_tokens CASCADE;
                DROP TABLE IF EXISTS permissions CASCADE;
                DROP TABLE IF EXISTS documents CASCADE;
                DROP TABLE IF EXISTS users CASCADE;
            """)
            conn.commit()

        cursor.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id VARCHAR(255) PRIMARY KEY,
                username VARCHAR(255) UNIQUE NOT NULL,
                email VARCHAR(255) UNIQUE NOT NULL,
                full_name VARCHAR(255) NOT NULL,
                role VARCHAR(50) NOT NULL CHECK(role IN ('admin', 'owner', 'viewer')),
                password_hash VARCHAR(255) NOT NULL,
                title VARCHAR(255) NOT NULL,
                avatar_color VARCHAR(50) NOT NULL,
                created_at VARCHAR(100) NOT NULL,
                status VARCHAR(50) NOT NULL DEFAULT 'active',
                approval_token VARCHAR(255),
                approved_by VARCHAR(255),
                approved_at VARCHAR(100),
                permission_expires_at VARCHAR(100)
            );

            CREATE TABLE IF NOT EXISTS documents (
                id VARCHAR(255) PRIMARY KEY,
                title VARCHAR(255) NOT NULL,
                description TEXT,
                category VARCHAR(100) NOT NULL,
                filename VARCHAR(255) NOT NULL,
                stored_path VARCHAR(255) NOT NULL,
                file_size BIGINT NOT NULL,
                mime_type VARCHAR(100) NOT NULL,
                sha256_hash VARCHAR(255) NOT NULL,
                owner_id VARCHAR(255) NOT NULL REFERENCES users(id),
                owner_name VARCHAR(255) NOT NULL,
                created_at VARCHAR(100) NOT NULL,
                updated_at VARCHAR(100) NOT NULL,
                is_deleted INTEGER DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS permissions (
                id VARCHAR(255) PRIMARY KEY,
                document_id VARCHAR(255) NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
                user_id VARCHAR(255) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                access_level VARCHAR(50) NOT NULL CHECK(access_level IN ('read', 'edit')),
                granted_by VARCHAR(255) NOT NULL REFERENCES users(id),
                granted_at VARCHAR(100) NOT NULL,
                UNIQUE(document_id, user_id)
            );

            CREATE TABLE IF NOT EXISTS active_download_tokens (
                token VARCHAR(255) PRIMARY KEY,
                document_id VARCHAR(255) NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
                user_id VARCHAR(255) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                created_at VARCHAR(100) NOT NULL,
                expires_at VARCHAR(100) NOT NULL
            );

            CREATE TABLE IF NOT EXISTS password_resets (
                id VARCHAR(255) PRIMARY KEY,
                user_id VARCHAR(255) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                email VARCHAR(255) NOT NULL,
                token VARCHAR(255) NOT NULL,
                expires_at VARCHAR(100) NOT NULL,
                used INTEGER DEFAULT 0,
                created_at VARCHAR(100) NOT NULL
            );

            CREATE TABLE IF NOT EXISTS outbound_emails (
                id VARCHAR(255) PRIMARY KEY,
                recipient VARCHAR(255) NOT NULL,
                subject VARCHAR(255) NOT NULL,
                body TEXT NOT NULL,
                token VARCHAR(255),
                sent_at VARCHAR(100) NOT NULL
            );

            CREATE TABLE IF NOT EXISTS audit_ledger (
                sequence_id BIGINT PRIMARY KEY,
                prev_hash VARCHAR(255) NOT NULL,
                current_hash VARCHAR(255) NOT NULL,
                timestamp VARCHAR(100) NOT NULL,
                actor_id VARCHAR(255) NOT NULL,
                actor_name VARCHAR(255) NOT NULL,
                actor_role VARCHAR(50) NOT NULL,
                action VARCHAR(100) NOT NULL,
                target_type VARCHAR(100) NOT NULL,
                target_id VARCHAR(255) NOT NULL,
                target_name VARCHAR(255) NOT NULL,
                status VARCHAR(50) NOT NULL CHECK(status IN ('ALLOWED', 'REFUSED')),
                ip_address VARCHAR(100) NOT NULL,
                user_agent TEXT NOT NULL,
                details TEXT NOT NULL,
                signature VARCHAR(255) NOT NULL
            );
        """)
        conn.commit()

        # Ensure Host user exists with active admin role
        host_email = os.environ.get("HOST_EMAIL", "23jr1a0460@gmail.com").strip().lower()
        cursor.execute("SELECT id FROM users WHERE LOWER(email) = ?", (host_email,))
        if not cursor.fetchone():
            now_str = datetime.now(timezone.utc).isoformat()
            cursor.execute("""
                INSERT INTO users (id, username, email, full_name, role, password_hash, title, avatar_color, created_at, status, approved_by, approved_at)
                VALUES (?, ?, ?, ?, 'admin', ?, 'Platform Host & Root Administrator', '#1e40af', ?, 'active', 'system', ?)
            """, ("usr_host_root", "host.admin", host_email, "Platform Host", hash_password("admin123"), now_str, now_str))

        conn.commit()
        conn.close()

        seed_data_if_empty()
        return

    if reset and os.path.exists(DB_PATH):
        os.remove(DB_PATH)


    conn = _get_connection()
    cursor = conn.cursor()

    cursor.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            full_name TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('admin', 'owner', 'viewer')),
            password_hash TEXT NOT NULL,
            title TEXT NOT NULL,
            avatar_color TEXT NOT NULL,
            created_at TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'active',
            approval_token TEXT,
            approved_by TEXT,
            approved_at TEXT,
            permission_expires_at TEXT
        );

        CREATE TABLE IF NOT EXISTS documents (
            id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            description TEXT,
            category TEXT NOT NULL,
            filename TEXT NOT NULL,
            stored_path TEXT NOT NULL,
            file_size INTEGER NOT NULL,
            mime_type TEXT NOT NULL,
            sha256_hash TEXT NOT NULL,
            owner_id TEXT NOT NULL REFERENCES users(id),
            owner_name TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            is_deleted INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS permissions (
            id TEXT PRIMARY KEY,
            document_id TEXT NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
            user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            access_level TEXT NOT NULL CHECK(access_level IN ('read', 'edit')),
            granted_by TEXT NOT NULL REFERENCES users(id),
            granted_at TEXT NOT NULL,
            UNIQUE(document_id, user_id)
        );

        CREATE TABLE IF NOT EXISTS active_download_tokens (
            token TEXT PRIMARY KEY,
            document_id TEXT NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
            user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS password_resets (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            email TEXT NOT NULL,
            token TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            used INTEGER DEFAULT 0,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS outbound_emails (
            id TEXT PRIMARY KEY,
            recipient TEXT NOT NULL,
            subject TEXT NOT NULL,
            body TEXT NOT NULL,
            token TEXT,
            sent_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS audit_ledger (
            sequence_id INTEGER PRIMARY KEY,
            prev_hash TEXT NOT NULL,
            current_hash TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            actor_id TEXT NOT NULL,
            actor_name TEXT NOT NULL,
            actor_role TEXT NOT NULL,
            action TEXT NOT NULL,
            target_type TEXT NOT NULL,
            target_id TEXT NOT NULL,
            target_name TEXT NOT NULL,
            status TEXT NOT NULL CHECK(status IN ('ALLOWED', 'REFUSED')),
            ip_address TEXT NOT NULL,
            user_agent TEXT NOT NULL,
            details TEXT NOT NULL,
            signature TEXT NOT NULL
        );
    """)
    # Dynamic migration for existing users table
    cursor.execute("PRAGMA table_info(users)")
    existing_cols = [c["name"] for c in cursor.fetchall()]
    if "status" not in existing_cols:
        cursor.execute("ALTER TABLE users ADD COLUMN status TEXT NOT NULL DEFAULT 'active'")
    if "approval_token" not in existing_cols:
        cursor.execute("ALTER TABLE users ADD COLUMN approval_token TEXT")
    if "approved_by" not in existing_cols:
        cursor.execute("ALTER TABLE users ADD COLUMN approved_by TEXT")
    if "approved_at" not in existing_cols:
        cursor.execute("ALTER TABLE users ADD COLUMN approved_at TEXT")
    if "permission_expires_at" not in existing_cols:
        cursor.execute("ALTER TABLE users ADD COLUMN permission_expires_at TEXT")

    # Ensure Host user exists with active admin role
    host_email = os.environ.get("HOST_EMAIL", "23jr1a0460@gmail.com").strip().lower()
    cursor.execute("SELECT id FROM users WHERE LOWER(email) = ?", (host_email,))
    if not cursor.fetchone():
        now_str = datetime.now(timezone.utc).isoformat()
        cursor.execute("""
            INSERT INTO users (id, username, email, full_name, role, password_hash, title, avatar_color, created_at, status, approved_by, approved_at)
            VALUES (?, ?, ?, ?, 'admin', ?, 'Platform Host & Root Administrator', '#1e40af', ?, 'active', 'system', ?)
        """, ("usr_host_root", "host.admin", host_email, "Platform Host", hash_password("admin123"), now_str, now_str))

    conn.commit()
    conn.close()

    seed_data_if_empty()

def seed_data_if_empty():
    conn = _get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) as count FROM users")
    if cursor.fetchone()["count"] > 0:
        conn.close()
        return

    now = datetime.now(timezone.utc).isoformat()

    # Three primary roles and realistic personas with salted password hashes
    users = [
        ("usr_admin_1", "sarah.admin", "sarah.chen@trustvault.internal", "Sarah Chen", "admin", hash_password("admin123"), "Head of Information Security & Compliance", "#1e40af", now),
        ("usr_owner_1", "marcus.vance", "marcus.vance@trustvault.internal", "Marcus Vance", "owner", hash_password("owner123"), "VP of Commercial Operations", "#0284c7", now),
        ("usr_owner_2", "dr.thorne", "aris.thorne@trustvault.internal", "Dr. Aris Thorne", "owner", hash_password("owner456"), "Lead Research Architect", "#2563eb", now),
        ("usr_viewer_1", "elena.rostova", "elena.rostova@external-audit.com", "Elena Rostova", "viewer", hash_password("viewer123"), "Senior Regulatory Auditor (KPMG External)", "#d97706", now),
        ("usr_viewer_2", "david.kim", "david.kim@client-corp.com", "David Kim", "viewer", hash_password("viewer456"), "Client Procurement Director (Apex Global)", "#4338ca", now),
        ("usr_viewer_3", "priya.nair", "priya.nair@regulatory.gov", "Priya Nair", "viewer", hash_password("viewer789"), "Federal Compliance Officer (SEC)", "#0891b2", now)
    ]

    cursor.executemany("""
        INSERT INTO users (id, username, email, full_name, role, password_hash, title, avatar_color, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, users)
    conn.commit()
    conn.close()

    # Create uploads directory and mock secure files
    uploads_dir = UPLOADS_DIR
    os.makedirs(uploads_dir, exist_ok=True)

    # Document 1: Salary Review (HR Confidential)
    doc1_content = """TRUSTVAULT CONFIDENTIAL HR MEMORANDUM
==================================================
DOCUMENT REF: HR-2026-SAL-EXEC-09
CLASSIFICATION: RESTRICTED - EXECUTIVE EYES ONLY
DATE: October 19, 2026

EXECUTIVE SALARY & BONUS ALLOCATION - Q3/Q4 2026
--------------------------------------------------
1. Marcus Vance (VP Commercial): Base $280,000 | Stock Incentive: 45,000 Units
2. Dr. Aris Thorne (Lead Architect): Base $310,000 | Retention Grant: $75,000
3. Sarah Chen (Head of Security): Base $295,000 | Equity Bonus: 38,000 Units

WARNING: Unauthorized viewing or dissemination violates Section 4.2 of Corporate Policy.
Access attempts are cryptographically timestamped and audited.
""".encode("utf-8")

    # Document 2: Master Service Agreement (Legal / Customer Contract)
    doc2_content = """MASTER SERVICES AGREEMENT (MSA)
==================================================
CONTRACT ID: MSA-2026-APEX-049
PARTIES: TrustVault Systems Inc. & Apex Global Partners (Attn: David Kim)
DATE OF EXECUTION: October 12, 2026

TERMS OF ENGAGEMENT:
1. Scope of Services: Tier-1 Enterprise Vaulting & Cryptographic Proof Engine
2. Contractual Value: $1,450,000 USD Annual Recurring
3. Confidentiality & Non-Disclosure: Strict bilateral adherence. 
4. Revocation of Access: Client-designated representatives are granted read-only access 
   which can be revoked unilaterally upon contract expiration or security notice.
""".encode("utf-8")

    # Document 3: Autonomous Drone Propulsion Blueprints (Engineering)
    doc3_content = """ENGINEERING SPECIFICATION & HARDWARE SCHEMATICS
==================================================
PROJECT CODENAME: AEGIS-VII HYPERSONIC TURBINE
LEAD DESIGNER: Dr. Aris Thorne
SECURITY LEVEL: DEFENSE ITAR RESTRICTED

TECHNICAL SPECIFICATIONS:
- Thrust Vectoring: Dual-axis magnetohydrodynamic nozzle
- Cryptographic Firmware Hash: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
- Material: Single-crystal Nickel-Titanium Superalloy Grade 5

ALL ACCESS REQUESTS REQUIRE TWO-PARTY CRYPTOGRAPHIC AUTHORIZATION.
""".encode("utf-8")

    # Document 4: Regulatory Audit Review (Audit / Compliance)
    doc4_content = """INDEPENDENT SOX / ISO 27001 AUDIT WORKPAPERS
==================================================
AUDIT FIRM: KPMG External Oversight Team
LEAD AUDITOR: Elena Rostova
PERIOD UNDER REVIEW: FY2026 Q1 - Q3

FINDINGS SUMMARY:
- Document access control integrity: 100% server-enforced
- Append-only hash chain audit logs: Validated across 1,420 prior events
- Immediate revocation test: Zero latency token invalidation confirmed
- Recommendation: Maintain real-time cryptographic audit trail inspection for regulators.
""".encode("utf-8")

    docs = [
        ("doc_hr_salary", "Q3-2026-Executive-Salary-Review.pdf", "Executive compensation, bonus structures, and restricted stock grants for leadership.", "Executive & HR", doc1_content, "usr_owner_1", "Marcus Vance"),
        ("doc_legal_msa", "Master-Service-Agreement-ApexGlobal.pdf", "Executed bilateral enterprise services contract with Apex Global Procurement.", "Contracts & Legal", doc2_content, "usr_owner_1", "Marcus Vance"),
        ("doc_eng_drone", "Aegis-VII-Hypersonic-Drone-Blueprints.pdf", "Proprietary aerodynamic calculations, telemetry schemas, and defense specs.", "Engineering & Blueprints", doc3_content, "usr_owner_2", "Dr. Aris Thorne"),
        ("doc_reg_audit", "SOX-Compliance-Audit-Report-2026.pdf", "Formal regulatory audit findings and compliance verification workpapers.", "Regulatory & Audit", doc4_content, "usr_owner_1", "Marcus Vance")
    ]

    conn = get_db()
    cursor = conn.cursor()

    for doc_id, filename, desc, cat, content, owner_id, owner_name in docs:
        stored_path = f"{doc_id}_{filename}"
        full_stored_path = os.path.join(uploads_dir, stored_path)
        with open(full_stored_path, "wb") as f:
            f.write(content)

        file_size = len(content)
        file_hash = hashlib.sha256(content).hexdigest()

        cursor.execute("""
            INSERT INTO documents (
                id, title, description, category, filename, stored_path,
                file_size, mime_type, sha256_hash, owner_id, owner_name,
                created_at, updated_at, is_deleted
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
        """, (
            doc_id, filename.replace(".pdf", ""), desc, cat, filename, stored_path,
            file_size, "application/pdf", file_hash, owner_id, owner_name,
            now, now
        ))
    conn.commit()
    conn.close()

    # Pre-seed realistic permissions:
    # 1. David Kim (viewer) has READ on Master-Service-Agreement-ApexGlobal
    # 2. Elena Rostova (viewer) has READ on SOX-Compliance-Audit-Report-2026
    # 3. Dr. Aris Thorne has not granted ANY access to Q3-2026-Executive-Salary-Review or Aegis-VII Drone
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO permissions (id, document_id, user_id, access_level, granted_by, granted_at)
        VALUES 
        ('perm_1', 'doc_legal_msa', 'usr_viewer_2', 'read', 'usr_owner_1', ?),
        ('perm_2', 'doc_reg_audit', 'usr_viewer_1', 'read', 'usr_owner_1', ?)
    """, (now, now))
    conn.commit()
    conn.close()

    # Pre-seed genesis block and historical audit trail
    record_audit_event("usr_admin_1", "Sarah Chen", "admin", "SYSTEM_GENESIS", "SYSTEM", "vault_system", "TrustVault Core Ledger", "ALLOWED", details={"message": "Tamper-evident cryptographically verifiable audit ledger initialized."})
    record_audit_event("usr_owner_1", "Marcus Vance", "owner", "DOCUMENT_UPLOAD", "DOCUMENT", "doc_hr_salary", "Q3-2026-Executive-Salary-Review", "ALLOWED", details={"file_size": len(doc1_content), "category": "Executive & HR"})
    record_audit_event("usr_owner_1", "Marcus Vance", "owner", "DOCUMENT_UPLOAD", "DOCUMENT", "doc_legal_msa", "Master-Service-Agreement-ApexGlobal", "ALLOWED", details={"file_size": len(doc2_content), "category": "Contracts & Legal"})
    record_audit_event("usr_owner_2", "Dr. Aris Thorne", "owner", "DOCUMENT_UPLOAD", "DOCUMENT", "doc_eng_drone", "Aegis-VII-Hypersonic-Drone-Blueprints", "ALLOWED", details={"file_size": len(doc3_content), "category": "Engineering & Blueprints"})
    record_audit_event("usr_owner_1", "Marcus Vance", "owner", "DOCUMENT_UPLOAD", "DOCUMENT", "doc_reg_audit", "SOX-Compliance-Audit-Report-2026", "ALLOWED", details={"file_size": len(doc4_content), "category": "Regulatory & Audit"})
    record_audit_event("usr_owner_1", "Marcus Vance", "owner", "PERMISSION_GRANTED", "DOCUMENT", "doc_legal_msa", "Master-Service-Agreement-ApexGlobal", "ALLOWED", details={"granted_to": "David Kim (usr_viewer_2)", "level": "read"})
    record_audit_event("usr_owner_1", "Marcus Vance", "owner", "PERMISSION_GRANTED", "DOCUMENT", "doc_reg_audit", "SOX-Compliance-Audit-Report-2026", "ALLOWED", details={"granted_to": "Elena Rostova (usr_viewer_1)", "level": "read"})
    
    # Pre-seed a refusal attempt: Elena Rostova attempted to open Salary Review (Unauthorized) -> Refused!
    record_audit_event("usr_viewer_1", "Elena Rostova", "viewer", "ACCESS_REFUSED_UNAUTHORIZED", "DOCUMENT", "doc_hr_salary", "Q3-2026-Executive-Salary-Review", "REFUSED", ip_address="198.51.100.42", details={"reason": "User not in authorized permission roster", "route": "/api/documents/doc_hr_salary/download", "http_status": 403})

if __name__ == "__main__":
    init_db(reset=True)
    print("TrustVault database initialized and pre-seeded successfully.")
