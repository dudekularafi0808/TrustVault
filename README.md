# TrustVault — Cryptographic Zero-Trust Document Security Platform

TrustVault is a zero-compromise confidential document security platform where the wrong person cannot reach a document, and where you can mathematically prove exactly who reached it, who attempted to reach it, and when.

---

## 🌟 Key Highlights & Design Standards

### 1. Title & Branding
- **Title:** `TrustVault`
- **Logo:** Custom SVG cryptographic vault shield with electric cyan/emerald circuits.
- **First Page Experience:** Prominently and cleanly features the heading **"Login as"** with exactly three options:
  - **Administrator** (`Sarah Chen`, CISO & Head of Compliance)
  - **Document owner** (`Marcus Vance`, VP Commercial Operations)
  - **Viewer** (`Elena Rostova`, Senior Regulatory Auditor)

---

## 🔒 The Three Non-Negotiable Standards

1. **Standard One: The Server Decides, Every Time**
   - No client-side trust or hidden button tricks. Every route (`/download`, `/preview`, `/edit`, `/delete`, `/permissions`) dynamically queries live permissions in SQLite on every request.
   - Non-sequential UUIDs and database-level query scoping (`WHERE (owner_id = ? OR id IN (SELECT doc_id FROM permissions WHERE user_id = ?))`) completely prevent Insecure Direct Object References (IDOR) and information enumeration leaks.
2. **Standard Two: Mathematically Provable, Tamper-Evident Audit Trail**
   - Every operation (uploads, downloads, views, grants, revokes, and crucially, **refused/blocked access attempts**) is committed to an append-only, SHA-256 hash-chained ledger.
   - Each block links to its predecessor's hash and is HMAC-signed.
   - Any external alteration of the SQLite database breaks downstream hash links and is mathematically flagged with the exact corrupted block sequence ID.
3. **Standard Three: Immediate Revocation**
   - No unrevocable, long-lived JWTs.
   - When an owner clicks **"Revoke Access"**, the permission row is deleted and all pre-issued download tokens are purged in the exact same transaction.
   - The very next millisecond, any in-flight or subsequent request returns `403 Forbidden: Access Revoked`.

---

## 📁 Project Structure

```
trustvault/
├── app.py                      # Core Flask web server & zero-trust API endpoints
├── database.py                 # SQLite WAL engine & SHA-256 hash-chained audit ledger
├── test_security.py            # Automated test suite (10/10 security assertions)
├── SECURITY_SPECIFICATION.md   # Written formal RBAC specification & security model
├── uploads/                    # Secure local storage for confidential payloads
├── static/
│   ├── index.html              # Modern single-page web app with "Login as" first page
│   ├── css/
│   │   └── style.css           # Modern cyber-vault dark theme & micro-animations
│   ├── js/
│   │   └── app.js              # Single-page UI routing, modals, audit verification
│   └── img/
│       └── logo.svg            # Custom cryptographic vault shield logo
```

---

## 🚀 Running the Platform

1. **Start the TrustVault Web Server:**
   ```powershell
   cd C:\Users\envy2\.gemini\antigravity-ide\scratch\trustvault
   python app.py
   ```
   Access the web application at: **[http://127.0.0.1:5000](http://127.0.0.1:5000)**

2. **Run the Automated Security Test Suite (CLI):**
   ```powershell
   python -m pytest test_security.py
   # Or run directly:
   python test_security.py
   ```

3. **In-Browser Test Runner:**
   Click **"Security Test Suite"** in the top navigation bar to execute all 10 security assertions live with real-time latency feedback.
