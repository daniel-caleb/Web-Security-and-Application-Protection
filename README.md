# Web Security and Application Protection

**Practical Cybersecurity Labs | IST**

A hands-on collection of practical labs exploring network traffic analysis, web application vulnerabilities, application-layer attacks, authentication security, API protection, and container security.

## About This Repository

This repository contains 15 guided cybersecurity labs designed to develop practical skills in identifying, testing, analyzing, and mitigating security vulnerabilities affecting networks and web applications.

The exercises combine offensive security techniques with defensive controls, allowing learners to understand how vulnerabilities are exploited and how appropriate security measures can prevent, detect, and mitigate attacks.

The labs are intended for educational use in controlled environments, using authorized targets and deliberately vulnerable applications where applicable.

## Learning Objectives

By completing these labs, learners should be able to:

- Capture and analyze network traffic using Wireshark.
- Perform authorized host discovery, port scanning, and service enumeration.
- Understand network-level attacks and techniques for detecting them.
- Identify and demonstrate common web application vulnerabilities.
- Apply secure coding practices to prevent injection and client-side attacks.
- Evaluate HTTP security headers, cookies, sessions, and application configurations.
- Deploy and assess a Web Application Firewall (WAF).
- Test API security controls and authentication mechanisms.
- Understand OAuth 2.0, JSON Web Tokens (JWT), and API rate limiting.
- Apply basic Docker container security practices.
- Document security findings and recommend effective remediation measures.

## Lab Catalogue

### Module 1: Network Traffic Analysis and Attacks

| Lab | Title | Main Focus |
|---|---|---|
| 01 | Wireshark Packet Capture and Analysis | Packet capture, HTTP traffic, DNS queries, and display filters |
| 02 | ARP Spoofing and Network Sniffing Detection | ARP behavior, traffic interception concepts, detection, and mitigation |
| 03 | Network Scanning with Nmap and Netcat | Host discovery, port scanning, service detection, and banner grabbing |
| 10 | Man-in-the-Middle (MITM) Attack Simulation | Traffic interception concepts, traffic analysis, and defensive measures |
| 11 | DNS Spoofing and DNSSEC Verification | DNS resolution, spoofing concepts, DNS integrity, and DNSSEC |

### Module 2: Web Application Vulnerabilities

| Lab | Title | Main Focus |
|---|---|---|
| 04 | SQL Injection Attack and Prevention | SQL injection testing, vulnerable queries, and parameterized queries |
| 05 | Cross-Site Scripting (XSS) Exploitation and Mitigation | Reflected, stored, and DOM-based XSS; output encoding and CSP |
| 06 | Cross-Site Request Forgery (CSRF) Attack and Defense | Forged requests, anti-CSRF tokens, and request validation |
| 07 | Identifying Security Misconfigurations and Session Flaws | Default credentials, error messages, directory listing, session fixation, and timeouts |
| 08 | Deploying a Web Application Firewall (WAF) | Reverse-proxy protection, attack detection, WAF logs, and rule tuning |
| 09 | Cookie Security Inspection and Content Security Policy (CSP) Configuration | Cookie attributes, browser security controls, and CSP configuration |

### Module 3: API and Authentication Security

| Lab | Title | Main Focus |
|---|---|---|
| 12 | API Security Testing with Postman | API requests, responses, authentication, and security testing |
| 13 | OAuth 2.0 and JWT Authentication Demo | Authorization flows, token structure, validation, and authentication security |
| 14 | API Rate Limiting and Gateway Configuration | Rate limits, gateway controls, abuse prevention, and request handling |

### Module 4: Container Security

| Lab | Title | Main Focus |
|---|---|---|
| 15 | Docker Container Security Basics | Container configuration, attack surface reduction, and security hardening |

## Tools and Technologies

The labs use tools and technologies appropriate to each exercise, including:

- **Wireshark** - Network packet capture and analysis.
- **Nmap** - Host discovery, port scanning, and service enumeration.
- **Netcat** - Network connectivity testing and banner grabbing.
- **Kali Linux** - Security testing utilities in controlled lab environments.
- **DVWA** - Deliberately Vulnerable Web Application for web security exercises.
- **Burp Suite / OWASP ZAP** - Web traffic inspection and application security testing where applicable.
- **Postman** - API requests and authentication testing.
- **Docker** - Container deployment and security exercises.
- **ModSecurity** - Web Application Firewall deployment and testing.
- **Browser Developer Tools** - Inspection of cookies, HTTP headers, and browser behavior.
- **DNS and DNSSEC utilities** - DNS testing and verification.

Refer to each lab's instructions for its exact tool requirements, prerequisites, and environment setup.

## Prerequisites

Learners should have a basic understanding of:

- Networking fundamentals, including TCP/IP, ARP, DNS, and HTTP/HTTPS.
- Linux command-line operations.
- Basic web application architecture.
- HTTP requests and responses.
- Fundamental security concepts and responsible testing practices.

Some exercises may require virtual machines, a deliberately vulnerable web application, Docker, or additional software. Check the relevant lab instructions before starting.

## Repository Structure

Each lab is provided as a separate Markdown file to make instructions easy to read, follow, and update.

```text
Web-Security-and-Application-Protection/
├── README.md
├── Lab-01-Wireshark-Packet-Analysis.md
├── Lab-02-ARP-Spoofing-Sniffing.md
├── Lab-03-Nmap-Netcat-Scanning.md
├── Lab-04-SQL-Injection.md
├── Lab-05-Cross-Site-Scripting.md
├── Lab-06-CSRF.md
├── Lab-07-Misconfig-Session-Flaws.md
├── Lab-08-Web-Application-Firewall.md
├── Lab-09-Cookie-Security-CSP.md
├── Lab-10-MITM-Simulation.md
├── Lab-11-DNS-Spoofing-DNSSEC.md
├── Lab-12-API-Security-Postman.md
├── Lab-13-OAuth2-JWT.md
├── Lab-14-Rate-Limiting-API-Gateway.md
└── Lab-15-Docker-Container-Security.md
```

## Getting Started

1. Clone or download this repository.
2. Review this README to understand the available labs.
3. Open the Markdown file for the lab you want to complete.
4. Check the prerequisites and prepare the required environment.
5. Follow the instructions step by step.
6. Record your observations, results, and relevant evidence.
7. Explain the vulnerabilities identified and the recommended mitigations.
8. Complete the review questions provided in the lab.

### Clone the Repository

```bash
git clone https://github.com/daniel-caleb/Web-Security-and-Application-Protection.git
cd Web-Security-and-Application-Protection
```

## Lab Reporting Guidelines

For each practical exercise, learners should aim to document:

- **Objective:** What the lab is intended to demonstrate.
- **Environment:** The virtual machines, applications, and tools used.
- **Procedure:** The steps followed during the exercise.
- **Observations:** What happened and what the results mean.
- **Evidence:** Relevant screenshots, packet captures, logs, or command output.
- **Security Analysis:** The vulnerability, attack mechanism, or configuration weakness identified.
- **Mitigation:** Recommended preventive and detective controls.
- **Conclusion:** Key lessons learned.

## Safety and Ethical Use

These labs are intended strictly for education, authorized security testing, and defensive security training.

- Perform attacks and scans only against systems you own or have explicit permission to test.
- Use isolated virtual machines and designated lab networks for network attack simulations.
- Use deliberately vulnerable applications for exploitation exercises.
- Do not perform ARP spoofing, MITM simulations, DNS spoofing, or other interception activities on shared or public networks.
- Do not test public APIs, websites, or production environments without authorization.
- Avoid collecting, exposing, or retaining real credentials, session tokens, or personal information.
- Restore lab systems and stop testing tools after each exercise.

The goal is to understand security weaknesses, demonstrate their impact safely, and apply effective defensive measures.

## References and Learning Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [OWASP Application Security Verification Standard](https://owasp.org/www-project-application-security-verification-standard/)
- [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/)
- [Damn Vulnerable Web Application (DVWA)](https://github.com/digininja/DVWA)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [Wireshark Documentation](https://www.wireshark.org/docs/)
- [Nmap Reference Guide](https://nmap.org/book/man.html)
- [Postman Learning Center](https://learning.postman.com/)
- [Docker Documentation](https://docs.docker.com/)

## Disclaimer

The materials in this repository are provided for educational and authorized cybersecurity testing purposes. Learners are responsible for ensuring that their activities comply with applicable laws, institutional policies, and authorization requirements.

---

**Web Security and Application Protection**  
*Practical Cybersecurity Labs | Learn. Test. Analyze. Defend.*
