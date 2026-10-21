# TrustVault — Cryptographic Zero-Trust Document Security Platform

TrustVault is a zero-compromise confidential document security platform where unauthorized entities cannot reach a document, and where you can mathematically prove exactly who accessed it, who attempted to access it, and when.

---

## 🌟 Key Highlights & Design Standards

### 1. Title & Branding
- **Title:** `TrustVault`
- **Palette:** Strict High-Contrast White and Blue enterprise styling (`#1e40af`, `#2563eb`, `#eff6ff`, `#ffffff`).
- **Access Portal:** Prominently and cleanly features **"Login as"** with three role gates:
  - **Administrator** (`Sarah Chen`, CISO & Head of Compliance)
  - **Document owner** (`Marcus Vance`, VP Commercial Operations)
  - **Viewer** (`Elena Rostova`, Senior Regulatory Auditor)
- **Authentication:** Mandatory username & password login, user registration ("Sign Up" button on top-right), and email-based password reset verification codes.

---

## 🔒 The Three Non-Negotiable Standards

1. **Standard One: The Server Decides, Every Time**
   - No client-side trust or hidden button tricks. Every route (`/download`, `/preview`, `/edit`, `/delete`, `/permissions`) dynamically queries live permissions on every request.
   - Non-sequential UUIDs and database-level query scoping completely prevent Insecure Direct Object References (IDOR) and information enumeration leaks.
2. **Standard Two: Mathematically Provable, Tamper-Evident Audit Trail**
   - Every operation (uploads, downloads, views, grants, revokes, and crucially, **refused/blocked access attempts**) is committed to an append-only, SHA-256 hash-chained ledger.
   - Each block links to its predecessor's hash and is HMAC-signed.
   - Any external tampering with the database breaks downstream hash links and is mathematically flagged with the exact corrupted block sequence ID.
3. **Standard Three: Immediate Revocation**
   - No unrevocable, long-lived JWTs.
   - When an owner clicks **"Revoke Access"**, the permission row is deleted and all pre-issued download tokens are purged in the exact same transaction.
   - The very next millisecond, any in-flight or subsequent request returns `403 Forbidden: Access Revoked`.

---

## 📧 How to Connect to Your Mail (Email Service)

TrustVault has native SMTP support built into `app.py`. When configured, real verification tokens and password reset emails are delivered directly to actual user email inboxes.

### Option A: Using Gmail (Fastest & Free)

1. Go to your **Google Account**: [https://myaccount.google.com/security](https://myaccount.google.com/security)
2. Under "How you sign in to Google", turn on **2-Step Verification**.
3. Open **App Passwords**: [https://myaccount.google.com/apppasswords](https://myaccount.google.com/apppasswords)
4. Enter an app name (e.g., `TrustVault`) and click **Create**.
5. Copy the 16-character password provided (e.g., `abcd efgh ijkl mnop`).
6. Create a `.env` file in the project root (or copy `.env.example` to `.env`) with:

```env
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your_actual_email@gmail.com
SMTP_PASSWORD=abcdefghijklmnop
SMTP_SENDER=TrustVault Security <your_actual_email@gmail.com>
SMTP_USE_TLS=true
```

### Option B: Using Other Providers (SendGrid, Outlook, SES)

- **Outlook / Office 365:**
  ```env
  SMTP_SERVER=smtp.office365.com
  SMTP_PORT=587
  SMTP_USERNAME=your_email@outlook.com
  SMTP_PASSWORD=your_password
  ```
- **SendGrid:**
  ```env
  SMTP_SERVER=smtp.sendgrid.net
  SMTP_PORT=587
  SMTP_USERNAME=apikey
  SMTP_PASSWORD=SG.your_sendgrid_api_key
  ```

### Testing Your Mail Connection
Test your email setup immediately using the built-in diagnostic endpoint:
```powershell
curl -X POST http://127.0.0.1:5000/api/auth/test-email -H "Content-Type: application/json" -d "{\"email\": \"your_actual_email@gmail.com\"}"
```

---

## 🗄️ How to Connect to Your Database

### 1. Built-in SQLite (Default — Zero Setup)
By default, TrustVault creates and uses `trustvault.db` in the project root with WAL mode (`journal_mode = WAL`) and full foreign-key constraints.

### 2. Custom Database File Location (Mounted Volumes / Disks)
Set `DATABASE_PATH` in your `.env` file to point to any custom path on your local drive or persistent volume:
```env
DATABASE_PATH=C:/data/trustvault.db
# Or on Linux / Docker:
DATABASE_PATH=/var/data/trustvault.db
```

### 3. Cloud PostgreSQL / Supabase / Neon
If you prefer a cloud PostgreSQL database:
1. Open your **Supabase SQL Editor**, **Neon Console**, or **psql**.
2. Run the included [`schema_postgres.sql`](schema_postgres.sql) script. It creates all tables (`users`, `documents`, `permissions`, `active_download_tokens`, `password_resets`, `outbound_emails`, `audit_ledger`) with appropriate indexes and primary keys.

---

## 📁 Project Structure

```
trustvault/
├── app.py                      # Flask web server, auth endpoints, & SMTP delivery
├── database.py                 # SQLite WAL engine & SHA-256 hash-chained audit ledger
├── schema_postgres.sql         # Production DDL schema for PostgreSQL / Supabase / Neon
├── .env.example                # Sample environment configuration for Mail & Database
├── test_security.py            # Automated test suite (10/10 security assertions)
├── tests/test_auth_flow.py     # Live authentication and password reset test suite
├── index.html                  # Single-page web app with White & Blue theme
├── static/
│   └── index.html              # Static bundle served by Flask
└── requirements.txt            # Python dependencies
```

---

## 🚀 Running the Platform

1. **Install Dependencies:**
   ```powershell
   pip install -r requirements.txt
   ```

2. **Start the Web Server:**
   ```powershell
   python app.py
   ```
   Open **[http://127.0.0.1:5000](http://127.0.0.1:5000)** in your browser.

3. **Run the Automated Security Test Suite:**
   ```powershell
   python test_security.py
   ```
