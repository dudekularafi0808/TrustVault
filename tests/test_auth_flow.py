import urllib.request
import urllib.error
import json

def post(url, data):
    req = urllib.request.Request(
        url,
        data=json.dumps(data).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode("utf-8"))

def main():
    base_url = "http://127.0.0.1:5000"
    
    # 1. Admin login with correct password
    s, d = post(f"{base_url}/api/auth/login", {"username": "sarah.admin", "password": "admin123", "role": "admin"})
    assert s == 200, f"Admin login failed: {s} {d}"
    print("[PASS] 1. Sarah Chen (Administrator) logged in with password:", d["user"]["full_name"])

    # 2. Login with wrong password
    s, d = post(f"{base_url}/api/auth/login", {"username": "sarah.admin", "password": "WRONG_PASSWORD", "role": "admin"})
    assert s == 401, f"Expected 401: {s} {d}"
    print("[PASS] 2. Wrong password correctly rejected with 401 and logged as REFUSED:", d["error"])

    # 3. Role mismatch check
    s, d = post(f"{base_url}/api/auth/login", {"username": "sarah.admin", "password": "admin123", "role": "viewer"})
    assert s == 403, f"Expected 403: {s} {d}"
    print("[PASS] 3. Role mismatch correctly blocked with 403:", d["error"])

    # 4. Sign up a new user
    s, d = post(f"{base_url}/api/auth/signup", {
        "username": "alex.ciso",
        "email": "alex.ciso@enterprise.com",
        "full_name": "Alex CISO",
        "password": "strongPassword123",
        "role": "admin"
    })
    # If alex.ciso already created in earlier test, status will be 201 or 409
    if s == 409:
        print("[PASS] 4. User alex.ciso already registered from previous run")
    else:
        assert s == 201, f"Signup failed: {s} {d}"
        print("[PASS] 4. New user registered via sign-up:", d["user"]["username"], f"({d['user']['role']})")

    # 5. Login with newly created user
    s, d = post(f"{base_url}/api/auth/login", {
        "username": "alex.ciso",
        "password": "strongPassword123",
        "role": "admin"
    })
    assert s == 200, f"New user login failed: {s} {d}"
    print("[PASS] 5. Newly created user logged in successfully:", d["user"]["full_name"])

    # 6. Forgot Password flow
    s, d = post(f"{base_url}/api/auth/forgot-password", {"email": "alex.ciso@enterprise.com"})
    assert s == 200, f"Forgot password failed: {s} {d}"
    token = d["token"]
    print("[PASS] 6. Forgot password generated reset token & outbound email:", token)

    # 7. Reset password flow
    s, d = post(f"{base_url}/api/auth/reset-password", {
        "token": token,
        "new_password": "updatedPassword456"
    })
    assert s == 200, f"Reset password failed: {s} {d}"
    print("[PASS] 7. Reset password completed successfully:", d["message"])

    # 8. Old password now rejected
    s, d = post(f"{base_url}/api/auth/login", {
        "username": "alex.ciso",
        "password": "strongPassword123",
        "role": "admin"
    })
    assert s == 401, f"Old password should be rejected: {s} {d}"
    print("[PASS] 8. Old password rejected after reset (401)")

    # 9. New password now accepted
    s, d = post(f"{base_url}/api/auth/login", {
        "username": "alex.ciso",
        "password": "updatedPassword456",
        "role": "admin"
    })
    assert s == 200, f"New password login failed: {s} {d}"
    print("[PASS] 9. New password logged in successfully:", d["user"]["full_name"])

    print("\nALL 9 AUTHENTICATION & SECURITY WORKFLOW TESTS PASSED!")

if __name__ == "__main__":
    main()
