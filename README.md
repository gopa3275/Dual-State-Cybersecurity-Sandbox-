# Dual-State-Cybersecurity-Sandbox-
Dual-State Cybersecurity Sandbox & Security Testing Lab

An interactive, full-stack cybersecurity training environment and security testing lab built using Python Flask and Tailwind CSS. This suite demonstrates critical OWASP Top 10 web application vulnerabilities side-by-side with real-time programmatic defensive mitigations, forensic log indexing, and system state integrity audits.

## Quick start

1. Create and activate a virtual environment.
2. Install dependencies: `py -m pip install -r requirements.txt`
3. Run the app: `py app.py`
4. Open `http://localhost:5000/` in a browser.

Set `SECRET_KEY` in the environment if you want a stable session secret for a longer-lived deployment.

The primary engine behavior depends entirely on the state of the Global Security Protection Switch at the top of the interface:

                  +-----------------------------------+
                  |   Incoming HTTP Request Stream    |
                  +-----------------------------------+
                                    |
                    [Security Protection Toggle State]
                                   / \
                                  /   \
                       [OFF / Vulnerable] [ON / Secure]
                                  
   
  - No Request Rate Limiting      |   |  - Enforced Failure Tracking       |
  - Direct Dynamic Code Reflection|   |  - Automatic 429 Lockout Timers    |
  - Raw Malicious Input Execution |   |  - Strict Context HTML Escaping    |
  

### Features Implemented
The suite consists of multiple security modules mapping to real-world defensive engineering tools and OWASP Top 10 vulnerabilities:

*   **SQL Injection (SQLi) Sandbox (01):** Demonstrates how attackers can bypass authentication or exfiltrate data by manipulating database queries. The secure mode uses parameterized queries (prepared statements) to neutralize the attack.

*   **Cross-Site Scripting (XSS) Sandbox (02):** Shows how malicious scripts can be reflected from a web application to a user's browser. The secure mode uses contextual HTML entity encoding and a strict Content-Security-Policy (CSP) header to prevent script execution.

*   **Password & Auth Audit (03 & 04):**
    *   **Password Entropy:** Computes password strength based on character set size and length, providing real-time feedback on resistance to brute-force attacks.
    *   **Brute-Force Simulator:** Simulates automated dictionary attacks. The secure mode employs an active failure-tracking matrix that returns an HTTP `429 Too Many Requests` and initiates an IP lockout after a set number of failed attempts.

*   **Phishing Link Scanner (05):** A heuristic engine that inspects URLs for common malicious patterns, including raw IP addresses, typosquatting keywords, and excessive subdomains.

*   **SIEM & Forensics (06):**
    *   **Log Analyzer:** A SIEM simulation that parses raw HTTP logs to detect signatures of SQL injection, XSS, and path traversal attacks.
    *   **File Integrity Checker:** Simulates a file integrity monitor by comparing the SHA-256 hash of a configuration file against a trusted baseline to detect unauthorized modifications.

*   **Security Tools (07 & 08):** A utility suite for encoding/decoding common web payloads (Base64, URL, Hex) and generating SHA-256 hashes for arbitrary text strings.

*   **Cross-Site Request Forgery (CSRF) Demo (09):** An interactive demo showing how an attacker can trick an authenticated user's browser into performing an unwanted action. The secure mode defends against this using a unique, synchronized token in the user's session and form data.

*   **Server-Side Request Forgery (SSRF) Demo (10):** Demonstrates how an attacker can abuse server functionality to read internal data or interact with other backend systems. The secure mode mitigates this by validating requested URLs against a strict domain allowlist.

*   **CTF Arena:** A "Capture The Flag" challenge space where users can submit flags they've discovered by successfully exploiting vulnerabilities in the other modules. Includes a hint system and progress tracking.
