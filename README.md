# Dual-State-Cybersecurity-Sandbox-
Dual-State Cybersecurity Sandbox & Security Testing Lab

An interactive, full-stack cybersecurity training environment and security testing lab built using Python Flask and Tailwind CSS. This suite demonstrates critical OWASP Top 10 web application vulnerabilities side-by-side with real-time programmatic defensive mitigations, forensic log indexing, and system state integrity audits.

The primary engine behavior depends entirely on the state of the Global Security Protection Switch at the top of the interface:

                  +-----------------------------------+
                  |   Incoming HTTP Request Stream    |
                  +-----------------------------------+
                                    |
                    [Security Protection Toggle State]
                                   / \
                                  /   \
                       [OFF / Vulnerable] [ON / Secure]
                                /       \
  +-----------------------------------+   +------------------------------------+
  |  - No Request Rate Limiting       |   |  - Enforced Failure Tracking       |
  |  - Direct Dynamic Code Reflection |   |  - Automatic 429 Lockout Timers    |
  |  - Raw Malicious Input Execution  |   |  - Strict Context HTML Escaping    |
  +-----------------------------------+   +------------------------------------+

 Features Implemented

The suite consists of 6 core security modules mapping to real-world defensive engineering tools:

01 // Password Strength & Entropy Analyzer
Computes real-time Shannon Entropy to evaluate mathematical password complexity and guards against simple dictionary sequences (e.g., admin123).
Entropy Formula:
$$H = -\sum_{i=1}^{n} p_i \log_2(p_i)$$
Vulnerable State: Allows weak password entries with zero restriction, leaving users highly susceptible to automated credential guessing.
Secure State: Quantifies password resistance and flags entropy deficiencies or bad patterns before processing.

02 // Phishing Link Detector
A scanning engine that inspects candidate URLs for common malicious redirects and domain typosquatting tricks.
IP Host Masking Detection: Flags raw IP structures bypassing DNS registration layers (e.g., http://192.168.2.14).
Keyword Analysis: Identifies high-risk string parameters like secure-signin or update-banking commonly utilized in social-engineering vectors.

03 // Reflected XSS Injection Sandbox
Demonstrates client-side parameter injection vulnerabilities and the critical need for strict input sanitization.
Vulnerable State: Reflects query input directly into the runtime web page DOM. Injected scripts execute natively within the target browser.
Secure State: Filters input streams using contextual HTML entity encoding (mapping < to &lt; and > to &gt;), rendering arbitrary payloads completely harmless.

04 // Automated Login Brute Force Simulator
Simulates automated dictionary attacks to contrast insecure authentication loops against proactive network firewall rules.
Vulnerable State: Accepts infinite, rapid authentication attempts without enforcement delays.
Secure State: Employs an active failure-tracking matrix. On the 3rd consecutive failed request, the engine returns an HTTP status code 429 Too Many Requests and initiates a 10-second system-wide IP lockout cooldown.

05 // Security Log Analyzer (SIEM Simulation)
Parses raw syslog buffers to automate threat hunting and isolate anomalous malicious transaction signatures.
Anomaly Identification: Automatically correlates multiple sequential 401 Unauthorized responses to flag brute-force loops and reports unauthorized 403 Forbidden folder traversals.

06 // Cryptographic File Integrity Checker
Ensures critical server configuration files haven't been tampered with or modified by malware.
Avalanche Effect Verification: Generates a real-time SHA-256 hash of active settings files and compares it to a trusted baseline. Even a 1-byte alteration breaks the checksum validation and triggers a critical integrity alarm.
