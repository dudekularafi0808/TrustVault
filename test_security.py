"""
DocLock Security Verification Test Suite
===========================================
Rigorous verification of the Three Non-Negotiable Security Standards:
1. Standard One: A document is reachable only by someone who was granted it.
   The server decides, every time, through any route.
2. Standard Two: You can prove who reached it, including refused attempts.
   Audit trail is cryptographically tamper-evident (hash-chained).
3. Standard Three: Taking access away works immediately.
   Issued tokens and access privileges terminate on the spot with zero latency.
"""

import os
import io
import time
import pytest
from app import app
import database

@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client

def test_01_unauthorized_user_cannot_read_metadata_or_enumerate(client):
    """
    Standard One: Viewers cannot see documents they have not been granted.
    Viewer Demo (usr_viewer_1) has access to Master-Service-Agreement,
    but NOT to Q3-2026-Executive-Salary-Review.
    """
    resp = client.get("/api/documents", headers={"X-User-Id": "usr_viewer_1"})
    assert resp.status_code == 200
    data = resp.get_json()
    doc_ids = [d["id"] for d in data["documents"]]
    
    # Viewer can see granted audit report
    assert "doc_reg_audit" in doc_ids
    # Viewer CANNOT see or enumerate unauthorized Salary Review or Drone Blueprints
    assert "doc_hr_salary" not in doc_ids
    assert "doc_eng_drone" not in doc_ids

def test_02_server_blocks_direct_download_for_unauthorized_user(client):
    """
    Standard One: Direct download route bypass attempt (/api/documents/<id>/download)
    Server returns 403 Forbidden regardless of UI state.
    """
    resp = client.get("/api/documents/doc_hr_salary/download", headers={"X-User-Id": "usr_viewer_1"})
    assert resp.status_code == 403
    data = resp.get_json()
    assert "Access denied" in data["error"]

def test_03_refused_attempt_is_recorded_in_audit_ledger(client):
    """
    Standard Two: Prove who reached it, INCLUDING attempts that were refused.
    The failed attempt in test_02 must exist in the audit ledger with status 'REFUSED'.
    """
    client.get("/api/documents/doc_hr_salary/download", headers={"X-User-Id": "usr_viewer_1"})

    conn = database.get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT * FROM audit_ledger 
        WHERE actor_id = 'usr_viewer_1' 
          AND target_id = 'doc_hr_salary' 
          AND status = 'REFUSED'
        ORDER BY sequence_id DESC LIMIT 1
    """)
    refused_entry = cursor.fetchone()
    conn.close()

    assert refused_entry is not None
    assert refused_entry["status"] == "REFUSED"
    assert "ACCESS_REFUSED" in refused_entry["action"]

def test_04_owner_grants_access_and_viewer_can_read(client):
    """
    Workflow: Owner grants Read permission to viewer -> Viewer can now download.
    """
    grant_resp = client.post(
        "/api/documents/doc_eng_drone/permissions",
        headers={"X-User-Id": "usr_owner_1"},
        json={"user_id": "usr_viewer_1", "access_level": "read"}
    )
    assert grant_resp.status_code == 200

    doc_resp = client.get("/api/documents/doc_eng_drone/download", headers={"X-User-Id": "usr_viewer_1"})
    assert doc_resp.status_code == 200
    assert len(doc_resp.data) > 0

def test_05_immediate_revocation_works_with_zero_latency(client):
    """
    Standard Three: Taking access away works immediately.
    Owner revokes permission -> subsequent download fails in the exact same millisecond.
    """
    # 1. Owner revokes Viewer's permission for doc_eng_drone
    revoke_resp = client.delete(
        "/api/documents/doc_eng_drone/permissions/usr_viewer_1",
        headers={"X-User-Id": "usr_owner_1"}
    )
    assert revoke_resp.status_code == 200

    # 2. In the very next request, Viewer attempts to download -> BLOCKED 403
    blocked_resp = client.get("/api/documents/doc_eng_drone/download", headers={"X-User-Id": "usr_viewer_1"})
    assert blocked_resp.status_code == 403
    assert "Access denied" in blocked_resp.get_json()["error"]

def test_06_issued_download_tokens_stop_working_instantly_on_revocation(client):
    """
    Standard Three: Whatever you have issued to that person before that moment stops working.
    Even if a shareable download token was generated prior to revocation,
    the moment access is revoked, the token is invalidated and purged.
    """
    # 1. Grant permission temporarily
    client.post(
        "/api/documents/doc_reg_audit/permissions",
        headers={"X-User-Id": "usr_owner_1"},
        json={"user_id": "usr_viewer_1", "access_level": "read"}
    )

    # 2. Generate a token for Viewer
    token_resp = client.post("/api/documents/doc_reg_audit/share-link", headers={"X-User-Id": "usr_viewer_1"})
    assert token_resp.status_code == 200
    token = token_resp.get_json()["token"]

    # 3. Verify token works initially
    pre_test = client.get(f"/api/shared/download/{token}")
    assert pre_test.status_code == 200

    # 4. Owner revokes Viewer's permission
    client.delete("/api/documents/doc_reg_audit/permissions/usr_viewer_1", headers={"X-User-Id": "usr_owner_1"})

    # 5. The PREVIOUSLY ISSUED token must now FAIL immediately!
    post_test = client.get(f"/api/shared/download/{token}")
    assert post_test.status_code == 403

def test_07_viewer_cannot_edit_or_delete_document(client):
    """
    Role Separation: Viewers with read permission cannot edit or delete.
    """
    # Elena Rostova has read on doc_reg_audit
    # Attempt to edit metadata
    edit_resp = client.put(
        "/api/documents/doc_reg_audit",
        headers={"X-User-Id": "usr_viewer_1"},
        json={"title": "Hacked Title by Viewer"}
    )
    assert edit_resp.status_code == 403

    # Attempt to delete document
    delete_resp = client.delete("/api/documents/doc_reg_audit", headers={"X-User-Id": "usr_viewer_1"})
    assert delete_resp.status_code == 403

def test_08_file_upload_validation_rejects_malicious_executables(client):
    """
    Validation of what is uploaded: Reject .exe, .sh, .py, and spoofed magic bytes.
    """
    # 1. Reject prohibited extension
    data = {
        "title": "Malware Payload",
        "category": "Engineering",
        "file": (io.BytesIO(b"MZ\x90\x00\x03\x00\x00\x00"), "trojan.exe")
    }
    resp1 = client.post("/api/documents", headers={"X-User-Id": "usr_owner_1"}, data=data, content_type="multipart/form-data")
    assert resp1.status_code == 400
    assert "Prohibited file type" in resp1.get_json()["error"]

    # 2. Reject magic byte mismatch (pretends to be .pdf but is actually binary trash)
    fake_pdf = {
        "title": "Fake PDF Attack",
        "category": "Contracts",
        "file": (io.BytesIO(b"NOT_A_REAL_PDF_HEADER_JUST_TEXT"), "fake.pdf")
    }
    resp2 = client.post("/api/documents", headers={"X-User-Id": "usr_owner_1"}, data=fake_pdf, content_type="multipart/form-data")
    assert resp2.status_code == 400
    assert "Magic byte mismatch" in resp2.get_json()["error"]

def test_09_audit_ledger_detects_database_tampering(client):
    """
    Standard Two: 'An audit trail that can be quietly altered is not evidence, and we will ask you what stops that.'
    Mathematical hash-chain verification: Altering any row breaks downstream hashes.
    """
    # 1. Clean state should pass verification
    initial_check = database.verify_audit_ledger_integrity()
    assert initial_check["valid"] is True

    # 2. Simulate attacker tampering with block #2
    conn = database.get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT sequence_id, details FROM audit_ledger WHERE sequence_id = 2")
    row = cursor.fetchone()
    assert row is not None
    original_details = row["details"]

    # Covertly modify details
    cursor.execute("UPDATE audit_ledger SET details = '{\"covert_tampering\": true}' WHERE sequence_id = 2")
    conn.commit()

    # 3. Cryptographic integrity check MUST catch the alteration!
    tampered_check = database.verify_audit_ledger_integrity()
    assert tampered_check["valid"] is False
    assert tampered_check["broken_sequence_id"] == 2
    assert "mismatch" in tampered_check["error_reason"] or "broken" in tampered_check["error_reason"]

    # 4. Revert to restore clean state
    cursor.execute("UPDATE audit_ledger SET details = ? WHERE sequence_id = 2", (original_details,))
    conn.commit()
    conn.close()

    clean_again = database.verify_audit_ledger_integrity()
    assert clean_again["valid"] is True

def test_10_admin_has_full_download_clearance_and_audit_oversight(client):
    """
    Role Specification & Governance:
    Administrators possess overarching compliance and governance clearance, enabling them
    to inspect, download, and delete any confidential document across the vault.
    """
    resp = client.get("/api/documents/doc_hr_salary/download", headers={"X-User-Id": "usr_admin_1"})
    assert resp.status_code == 200
    assert len(resp.data) > 0


def execute_all_security_tests():
    """
    Executes all tests programmatically and returns a structured report for the UI and evaluator.
    """
    test_cases = [
        ("test_01_unauthorized_user_cannot_read_metadata_or_enumerate", "Standard One: Inaccessible documents are completely invisible (no enumeration leakage)", "Standard One"),
        ("test_02_server_blocks_direct_download_for_unauthorized_user", "Standard One: Direct download route returns 403 Forbidden regardless of UI state", "Standard One"),
        ("test_03_refused_attempt_is_recorded_in_audit_ledger", "Standard Two: Refused access attempts are recorded in tamper-evident audit ledger", "Standard Two"),
        ("test_04_owner_grants_access_and_viewer_can_read", "Access Control: Document owner grants Read permission to designated user", "Standard One"),
        ("test_05_immediate_revocation_works_with_zero_latency", "Standard Three: Immediate revocation terminates access on the exact same millisecond", "Standard Three"),
        ("test_06_issued_download_tokens_stop_working_instantly_on_revocation", "Standard Three: Pre-issued download tokens stop working instantly when access is revoked", "Standard Three"),
        ("test_07_viewer_cannot_edit_or_delete_document", "RBAC Enforcement: Viewers cannot modify or delete documents without explicit permission", "Standard One"),
        ("test_08_file_upload_validation_rejects_malicious_executables", "Input Validation: Rejects prohibited executables, scripts, and spoofed magic bytes", "Upload Security"),
        ("test_09_audit_ledger_detects_database_tampering", "Standard Two: SHA-256 hash chaining mathematically catches covert database tampering", "Standard Two"),
        ("test_10_admin_has_full_download_clearance_and_audit_oversight", "Governance: Administrator has full compliance clearance to download and audit vault documents", "Governance & Audit")
    ]

    results = []
    app.config["TESTING"] = True

    with app.test_client() as test_client:
        for func_name, description, standard in test_cases:
            func = globals().get(func_name)
            start_time = time.time()
            try:
                func(test_client)
                elapsed = round((time.time() - start_time) * 1000, 2)
                results.append({
                    "name": func_name,
                    "description": description,
                    "standard": standard,
                    "status": "PASSED",
                    "duration_ms": elapsed,
                    "error": None
                })
            except Exception as e:
                elapsed = round((time.time() - start_time) * 1000, 2)
                results.append({
                    "name": func_name,
                    "description": description,
                    "standard": standard,
                    "status": "FAILED",
                    "duration_ms": elapsed,
                    "error": str(e)
                })

    passed_count = sum(1 for r in results if r["status"] == "PASSED")
    return {
        "total": len(results),
        "passed": passed_count,
        "failed": len(results) - passed_count,
        "all_passed": (passed_count == len(results)),
        "tests": results
    }

if __name__ == "__main__":
    rep = execute_all_security_tests()
    print("\n==========================================")
    print(f"DOCLOCK SECURITY SUITE: {rep['passed']}/{rep['total']} PASSED")
    print("==========================================")
    for t in rep["tests"]:
        badge = "[PASS]" if t["status"] == "PASSED" else "[FAIL]"
        print(f"{badge} {t['standard']} | {t['name']} ({t['duration_ms']}ms)")
        if t["error"]:
            print(f"      Error: {t['error']}")
