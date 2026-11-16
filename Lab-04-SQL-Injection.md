# Lab 4: SQL Injection Attack and Prevention

**Module:** 5 – Web Security and Application Protection
**Unit:** 2 – Web Application Security
**Estimated Duration:** 90 minutes
**Difficulty:** Intermediate

## Objective
Exploit a SQL injection vulnerability in a deliberately vulnerable web application, then remediate it using parameterized queries.

## Prerequisites
- Basic SQL knowledge
- Basic understanding of HTTP requests

## Tools Required
- DVWA (Damn Vulnerable Web Application) or OWASP Juice Shop, deployed locally (Docker recommended)
- Browser with developer tools
- Burp Suite Community Edition (optional, for intercepting requests)

## Ethics & Safety Note
Only test applications you deploy yourself in an isolated lab. Never attempt SQL injection against live or third-party websites.

## Step-by-Step Instructions

### Step 1: Deploy the Vulnerable Application
Using Docker:
```
docker run --rm -it -p 80:80 vulnerables/web-dvwa
```
Browse to `http://localhost` and log in with default credentials (`admin` / `password`).

### Step 2: Set DVWA Security Level
1. Navigate to **DVWA Security**.
2. Set security level to **Low**.
3. Click **Submit**.

### Step 3: Locate the SQL Injection Module
Navigate to **SQL Injection** in the left menu.

### Step 4: Confirm Normal Behavior
1. Enter a valid User ID (e.g., `1`) and submit.
2. Observe the returned user record.

### Step 5: Test for Injection
Enter the following into the User ID field:
```
1' OR '1'='1
```
Submit and observe that the query returns all user records instead of just one — confirming the input is not sanitized.

### Step 6: Extract Database Information
Try a UNION-based injection to pull database metadata:
```
1' UNION SELECT user, password FROM users -- -
```
Record the returned usernames/password hashes.

### Step 7: Identify the Vulnerable Code
1. Click **View Source** (bottom of the DVWA page).
2. Locate the raw SQL query construction, e.g.:
   ```php
   $query = "SELECT first_name, last_name FROM users WHERE user_id = '$id';";
   ```
3. Note that `$id` is concatenated directly into the query string with no sanitization.

### Step 8: Remediate with Parameterized Queries
Rewrite the vulnerable query using a prepared statement (example in PHP/PDO):
```php
$stmt = $pdo->prepare("SELECT first_name, last_name FROM users WHERE user_id = :id");
$stmt->bindParam(':id', $id, PDO::PARAM_STR);
$stmt->execute();
```
Explain why this prevents injection: user input is treated strictly as data, never as executable SQL syntax.

### Step 9: Re-test at Higher Security Levels
1. Set DVWA Security to **Medium** or **High**.
2. Repeat Step 5's payload and observe that it now fails or is sanitized.
3. Document the specific input validation/escaping DVWA applies at each level.

### Step 10: Document Findings
Write a short vulnerability report including:
- Vulnerability description and risk (CVSS-style severity estimate)
- Proof-of-concept payload used
- Remediation applied
- Retest result confirming the fix

## Expected Outcome
Learners understand how unsanitized input leads to SQL injection, can extract data using UNION-based attacks, and can apply/validate parameterized query remediation.

## Cleanup
- Stop the Docker container: `docker stop <container_id>`.
- Do not leave DVWA or Juice Shop running or exposed outside the lab network.

## Review Questions
1. Why does `1' OR '1'='1` always evaluate to true in a WHERE clause?
2. What is the difference between in-band, blind, and out-of-band SQL injection?
3. Besides parameterized queries, name two additional defenses (e.g., least-privilege DB accounts, input validation, WAF).
