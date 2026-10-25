# DocLock — Security Architecture & Formal Specification

> **Platform Mission:** A zero-compromise cryptographic document security platform where the wrong person cannot reach a document, and where you can mathematically prove exactly who reached it, who attempted to reach it, and when.

---

## 1. Problem Statement & Threat Model

Confidential document sharing suffers from two catastrophic and expensive failure modes:

1. **Permission Creep & Stale Links:**
   - Over-provisioning folder access allows unauthorized lateral movement (accessing one file grants visibility into forty).
   - Departed contractors or employees retain functional share links.
   - Files intended for Customer A are accidentally or intentionally accessed by Customer B.
2. **The "Who Opened This?" Crisis:**
   - Following a breach, leak, or regulatory inquiry, companies are unable to produce forensic, tamper-evident proof of access.
   - Traditional application logs can be quietly deleted, modified by database administrators, or simply fail to record failed/refused attempts.

---

## 2. Formal Role-Based Access Control (RBAC) Specification

DocLock implements a formal access control model with strict separation of duties.

| Capability / Action | Administrator | Document Owner | Viewer (Read) | Viewer (Edit) |
| :--- | :---: | :---: | :---: | :---: |
| **System Audit Ledger Inspection** | **YES** (Global) | **YES** (Owned Docs) | **NO** (403) | **NO** (403) |
| **Cryptographic Hash-Chain Verification** | **YES** | **NO** | **NO** | **NO** |
| **Upload New Documents** | **YES** | **YES** | **NO** (403) | **NO** (403) |
| **View Document Metadata** | **YES** (Compliance) | **YES** (Owned Docs) | **YES** (Granted Only) | **YES** (Granted Only) |
| **Download / View Confidential Payload** | **NO** *(Zero-Trust)* | **YES** (Owned Docs) | **YES** (Granted Only) | **YES** (Granted Only) |
| **Edit Document Metadata** | **NO** | **YES** | **NO** (403) | **YES** (Granted) |
| **Grant / Revoke Permissions** | **NO** | **YES** | **NO** (403) | **NO** (403) |
| **Instant Token Purge on Revocation** | **AUTOMATIC** | **AUTOMATIC** | N/A | N/A |
| **Delete Document** | **NO** | **YES** | **NO** (403) | **NO** (403) |

### Detailed Role Definitions

#### 1. Administrator (`sarah.admin`)
- **Scope:** Governance, forensic auditing, and cryptographic ledger verification.
- **Can Do:**
  - View full system audit ledger containing both `ALLOWED` and `REFUSED` access events.
  - Run the cryptographic hash-chain verification engine to prove zero tampering.
  - Inspect document metadata (title, category, SHA-256 fingerprint, owner) for regulatory compliance.
- **Cannot Do:**
  - **Zero-Trust Separation of Duties:** Administrators *cannot* view or download confidential file payloads unless the document owner explicitly grants them permission. This prevents compromised admin accounts or rogue operators from leaking executive salaries, trade secrets, or client contracts.

#### 2. Document Owner (`marcus.vance`, `dr.thorne`)
- **Scope:** Complete ownership and discretionary access control of created documents.
- **Can Do:**
  - Upload documents with automated file validation (magic bytes, extensions, SHA-256 checksums).
  - Organize documents by category and search across their repository.
  - Grant named collaborators `read` or `edit` permissions.
  - Revoke access instantaneously with zero latency.
  - Inspect the audit trail and access logs (including unauthorized refused attempts) for all documents they own.
  - Edit or delete owned documents.

#### 3. Viewer (`elena.rostova`, `david.kim`, `priya.nair`)
- **Scope:** External clients, auditors, or non-owner employees.
- **Can Do:**
  - View and download documents explicitly granted to them by the owner.
  - If granted `edit` permission, can update title or description.
- **Cannot Do:**
  - Cannot see metadata or existence of ungranted documents (prevents enumeration leakage).
  - Cannot download ungranted documents through any route (direct API, URL guessing, forged IDs).
  - Cannot upload documents or grant permissions to others.
  - Cannot access a document the moment an owner revokes permission.

---

## 3. The Three Non-Negotiable Standards

### Standard One: The Server Decides, Every Time
> *"A document is reachable only by someone who was granted it. Not 'the button is hidden'. Not 'the page checks'. Through any route at all, including ones you did not think of. The server decides, every time."*

#### Architectural Guarantee:
- Every request to `/api/documents/<id>/download`, `/api/documents/<id>/preview`, `/api/documents/<id> [PUT]`, and `/api/documents/<id> [DELETE]` executes `check_document_access(doc_id, user, required_level)`.
- Access is never determined by client-side flags, cookies, or hidden UI components.
- Insecure Direct Object Reference (IDOR) attacks fail unconditionally: UUID identifiers prevent sequential enumeration, and direct route access evaluates live database permissions.
- Inaccessible documents are filtered at the SQL query level (`WHERE (d.owner_id = ? OR p.user_id = ?)`), preventing attackers from even discovering the titles or existence of confidential files.

---

### Standard Two: Mathematically Provable, Tamper-Evident Audit Trail
> *"You can prove who reached it. Afterwards, from the record, including the attempts that were refused. An audit trail that can be quietly altered is not evidence, and we will ask you what stops that."*

#### Architectural Guarantee:
DocLock implements an **append-only, cryptographically hash-chained audit ledger** modeled on blockchain primitives:

1. **Hash Chaining:**
   - Every audit record contains `prev_hash` (the SHA-256 hash of the immediately preceding record) and its own `current_hash`:
   $$\text{current\_hash} = \text{SHA256}(\text{sequence\_id} \parallel \text{prev\_hash} \parallel \text{timestamp} \parallel \text{actor\_id} \parallel \text{action} \parallel \text{target\_id} \parallel \text{status} \parallel \text{details})$$
2. **HMAC Signature:**
   - Each block hash is signed using an HMAC-SHA256 master key.
3. **Refused Attempts Recorded:**
   - Every unauthorized request (e.g. attempting to download without permission, attempting to guess document IDs, attempting to use a revoked token) is immediately committed to the ledger with `status = 'REFUSED'` and detailed forensic telemetry (IP address, user agent, route, reason).
4. **Tamper Detection:**
   - Any covert modification of an existing database row breaks the hash link with the subsequent row and invalidates the HMAC signature.
   - The built-in verification engine walks the chain from Genesis block #1 to the latest block, mathematically identifying the exact altered block sequence ID.

---

### Standard Three: Immediate Revocation
> *"Taking access away works immediately. Whatever you have issued to that person before that moment stops working."*

#### Architectural Guarantee:
- **No Stale JWT Claims:** Permissions are never cached in unrevocable client tokens.
- **Atomic Database Revocation:** When an owner revokes access:
  1. The permission record in `permissions` is deleted immediately.
  2. All shareable download tokens in `active_download_tokens` associated with that user and document are purged in the same transaction.
  3. A `PERMISSION_REVOKED` audit event is written to the immutable ledger.
- **Zero-Latency Invalidation:** In-flight or subsequent requests—whether using browser sessions, direct API calls, or previously copied share links—check the live database state on every single request. The very next millisecond, access returns `403 Forbidden: Access Revoked`.

---

## 4. Upload Validation & Defense Against Malicious Files

1. **Extension Whitelisting:** Strictly permits `.pdf`, `.docx`, `.xlsx`, `.csv`, `.txt`, `.png`, `.jpg`, `.jpeg`, `.json`.
2. **Executable & Script Blacklist:** Explicitly rejects `.exe`, `.bat`, `.cmd`, `.sh`, `.vbs`, `.js`, `.py`, `.dll`, `.iso`, `.zip`, `.msi`, `.ps1`.
3. **Magic Byte Verification:** Inspects the first 16 bytes of the file binary stream:
   - PDF files must start with `%PDF-` (`0x25 0x50 0x44 0x46 0x2D`).
   - PNG files must start with `\x89PNG\r\n\x1a\n`.
   - JPEG files must start with `\xFF\xD8\xFF`.
   - Plain text/CSV/JSON files are inspected to ensure they contain no binary execution headers or null bytes (`0x00`).
4. **Cryptographic Checksum:** Generates a SHA-256 fingerprint of the binary content on upload to ensure file integrity.
5. **Path Traversal Sanitization:** Filenames are sanitized using `secure_filename()` and stored with isolated UUID prefixes.

---

## 5. Automated Verification Test Suite

The test suite (`test_security.py`) contains 10 rigorous assertions executable via `pytest` or via the in-app interactive test runner:

- `test_01`: Unauthorized user cannot see metadata or enumerate ungranted documents.
- `test_02`: Server blocks direct download route (`/api/documents/<id>/download`) with 403 Forbidden.
- `test_03`: Refused attempts are recorded in the audit ledger with `status = 'REFUSED'`.
- `test_04`: Document owner grants access -> authorized user can immediately read.
- `test_05`: Owner revokes access -> access terminates on the exact same millisecond.
- `test_06`: Issued download tokens stop working immediately upon permission revocation.
- `test_07`: Viewers with Read permission cannot edit metadata or delete documents.
- `test_08`: File upload rejects malicious executables, prohibited extensions, and spoofed magic bytes.
- `test_09`: Audit ledger cryptographically detects covert database tampering.
- `test_10`: Separation of duties: Administrators cannot download confidential payloads without owner grant.
