# TrustVault — Keep your File Safe and Secure

FOR DEMO THE
ADMINISTRATOR LOGIN: 
              Username : ADMINISTRATOR_DEMO 
              Password : ADMIN1
DOCUMENT OWNER LOGIN:
              Username : OWNER_DEMO 
              Password : OWNER
VIEWER LOGIN:
        Username : VIEWER_DEMO 
        Password : VIEWER
**"Keep your File Safe and Secure. Permit and revoke the Access Whenever, whomever you want."**

TrustVault is a zero-compromise confidential document security platform where unauthorized entities cannot reach a document, and where you can mathematically prove exactly who accessed it, who attempted to access it, and when.

Firstly, there is a host in the top end. Host has all the permissions access, everything. Host is the one who approves the request for any Sign up. The host is me at present.
Secondly, Administrator is the one who takes the approval to sign up as ADMIN. Admin can upload document and grant access to anyone read or write etc. 
then, A document owner should take permission form either Admin or Host to sign up. Then Doc Owner can upload, access and Grant/revoke permission to desired Viewers. 
Finally, A Viewer can only access the Document if someone grants them the permission. 

Everyone have to renovate the registration every 7 days for security purpose.


---


##  Project Structure

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
3. **Run the Automated Security Test Suite:**
   ```powershell
   python test_security.py
   ```
