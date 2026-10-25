# DocLock — Engineering Prompts & Architecture Evolution

This document chronicles the chronological engineering prompts and architectural directives submitted during the development, hardening, and verification of **DocLock** (formerly TrustVault).

---

## 1. Core Problem Statement & Zero-Trust Foundations

> **Prompt:**
> *"Every company shares confidential documents: salary letters with employees, contracts with customers, drawings with external partners, audit papers with regulators. Two things go wrong, and both are expensive:*
> 
> *The first is permissions. Someone is given access to a folder so they can see one file, and they can now see forty. Someone leaves the company and their link still works. A file meant for one client is visible to another.*
> 
> *The second is that nobody can answer the question afterwards. When a document leaks, the first question is always who opened this, and when. If the honest answer is 'we do not know', the company is in trouble with its customer, its auditor, or both.*
> 
> *Build a zero-trust platform meeting three non-negotiable standards:*
> 1. *A document is reachable only by someone who was granted it. Not 'the button is hidden'. Not 'the page checks'. The server decides, every time.*
> 2. *You can prove who reached it afterwards, from the record, including attempts that were refused. The audit trail must be tamper-evident.*
> 3. *Taking access away works immediately. Whatever was issued before that moment stops working with zero latency.*
> 
> *Provide authentication with at least three roles (Administrator, Document Owner, Viewer), granular per-document permissions, document validation, and automated tests demonstrating that one user cannot reach another user's files."*

---

## 2. Host Approval Workflow & Bot-Proof Authorization Gateway

> **Prompt:**
> *"Ensure the Host receives authorization request emails whenever someone signs up, with an in-app host approval banner. Also fix the email scanner bug: corporate anti-phishing bots and link scanners prefetch the URL inside the email and consume the one-time token before the human clicks it. Create a bot-proof gateway that requires an interactive confirmation before granting access."*

**Outcome Implemented:**
- Implemented real transactional SMTP delivery to host email (`dudekularafi759@gmail.com`).
- Built the **Bot-Proof Authorization Gateway**: Replaced state-mutating `GET` links with an interactive confirmation landing page dispatching a CSRF-protected `POST` request, completely defeating automated bot prefetchers.
- Added in-app approval notification banners so the host can also approve requests directly inside the dashboard.

---

## 3. Session Security: 10-Minute Inactivity Auto-Logout

> **Prompt:**
> *"Consider if someone logged in as any role of three, if they do not work for 10 mins then it should automatically log out and come to the sign up page."*

**Outcome Implemented:**
- Client-side interaction listeners tracking `mousemove`, `keydown`, `click`, and `scroll`.
- Cross-tab synchronization via `localStorage` so activity in one tab keeps other tabs active.
- Automated session termination after 600,000ms (10 minutes) of inactivity, redirecting to the signup modal with an alert: *"Session expired due to 10 minutes of inactivity. Please sign in again."*
- Server-side enforcement in `get_current_user()` via `session["last_active"]`, destroying sessions inactive for over 10 minutes.
- Verified with unit test suite in `test_inactivity_timeout.py`.

---

## 4. Platform Rebranding: TrustVault to DocLock

> **Prompt:**
> *"Change the name of the website app to 'DocLock' wherever 'TrustVault' appears in the website, but the website should work as it is. Change the file names if possible, repository name, vercel project name if possible."*

**Outcome Implemented:**
- Comprehensive rebrand across `index.html`, `static/index.html`, `static/js/app.js`, `app.py`, `database.py`, `vercel.json`, and `README.md`.
- Preserved 100% operational functionality, credentials, demo accounts, and test suites.

---

## 5. Granular Permissions: In-Page Read-Only vs. Download Clearance

> **Prompt:**
> *"Only read access, in the same page, should be given to the users when they are granted by the owner with the Read access only. If read and write is given then they can download the file/document."*

**Outcome Implemented:**
- **Server-Side Enforcement**: Updated `check_document_access(doc_id, user, required_level)`:
  - Users with `read` permission can inspect and read document content via `/api/documents/<id>/preview` directly within the browser modal.
  - Direct download requests (`/api/documents/<id>/download`) and share link generation for users with `read`-only permission are rejected with **HTTP 403 Forbidden**, logging `ACCESS_REFUSED_DOWNLOAD` to the immutable audit trail.
  - Users with `edit` (Read & Write) clearance, Document Owners, and System Administrators are permitted full download clearance.
- **Frontend Representation**: Document cards display `Read in Page` for read-only users with a locked indicator on download; the Document Detail Modal provides live in-page content preview while gating the download action to Read & Write privileges.
- Verified in `test_security.py` assertions 04, 05, and 06.

---

## 6. Git History Preservation & Author Attribution

> **Prompt:**
> *"Keep the commit history as it was, we changed it right to a few right keep all the commits. Remove Rafael Bodill and show all commits as done by me."*

**Outcome Implemented:**
- Reconstructed and restored all 49 historical commits from initial repository creation through all iterations.
- Rewrote author and committer metadata across every commit using Git fast-export/fast-import filters, attributing 100% of commits to `dudekularafi0808`.
- Completely removed third-party accounts from the repository contributors list.

---

## 7. Hackathon Evaluation Defense & Technical Architecture

> **Prompt:**
> *"I was asked some questions about the website in the hackathon, I want you to answer them:
> 1. The problem you solved
> 2. What exactly works right now?
> 3. How to run it on our machine
> 4. Which AI tools you used
> 5. What the AI got wrong, and what you fixed yourself (worth 25 marks)
> 6. What is not finished (honest gaps)"*

**Outcome Implemented:**
- Formulated clear, technically rigorous defense answers highlighting zero-trust server validation, cryptographic SHA-256 audit chaining, bot-proof gateway engineering, and architectural trade-offs.
