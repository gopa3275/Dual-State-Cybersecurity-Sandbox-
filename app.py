from flask import Flask, render_template, request, jsonify
import time
import re
import math
import hashlib

app = Flask(__name__)

# System Configuration
USERS_DB = {"admin": "PASSWORD123"} # Handled case-insensitively now in the route logic
FAILED_ATTEMPTS = {}
MAX_ATTEMPTS = 3
LOCKOUT_TIME = 10  

# Dynamic Platform Counters
LAB_METRICS = {
    "total_attacks_blocked": 0,
    "vulnerabilities_exploited": 0,
    "malicious_indicators_detected": 0
}

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/api/metrics', methods=['GET'])
def get_metrics():
    return jsonify(LAB_METRICS)

# 01 // PASSWORD STRENGTH ANALYSER (Option 1)
@app.route('/api/analyze_password', methods=['POST'])
def analyze_password():
    data = request.json or {}
    pwd = data.get('password', '')
    
    if not pwd:
        return jsonify({"entropy": "0.00", "density": "EMPTY", "feedback": "Please type a password to test."})

    length = len(pwd)
    charset = 0
    if re.search(r'[a-z]', pwd): charset += 26
    if re.search(r'[A-Z]', pwd): charset += 26
    if re.search(r'[0-9]', pwd): charset += 10
    if re.search(r'[^a-zA-Z0-9]', pwd): charset += 32

    entropy = length * math.log2(charset) if charset > 0 else 0
    
    # Check for weak patterns (Syllabus: 123, common sequences)
    weak_patterns = ["123", "password", "admin", "qwerty"]
    pattern_detected = any(p in pwd.lower() for p in weak_patterns)

    if entropy < 40 or pattern_detected:
        density = "WEAK PASSWORD"
        feedback = "❌ Danger: This password is easy to guess. An attacker could crack this instantly using a basic wordlist."
        LAB_METRICS["malicious_indicators_detected"] += 1
    elif entropy < 72:
        density = "MODERATE PASSWORD"
        feedback = "⚠️ Warning: Acceptable length, but it could be stronger. Try adding special symbols like $ or @."
    else:
        density = "STRONG PASSWORD"
        feedback = "✅ Excellent: Great length and variety of characters. Extremely secure against guessing attacks."

    return jsonify({"entropy": f"{entropy:.2f}", "density": density, "feedback": feedback})

# 02 // PHISHING LINK DETECTOR (Option 4)
@app.route('/api/detect_phishing', methods=['POST'])
def detect_phishing():
    data = request.json or {}
    url = data.get('url', '')
    findings = []
    
    # Option 4 Spec: Checks for use of IP instead of Domain name
    if re.search(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
        findings.append("🚨 Critical: This link uses a raw IP address instead of a real domain name. Real websites do not do this.")
    
    # Option 4 Spec: Suspicious Keywords
    suspicious_keywords = ['login', 'verify', 'update-banking', 'secure-signin', 'free-gift']
    for kw in suspicious_keywords:
        if kw in url.lower():
            findings.append(f"⚠️ Warning: Contains a highly suspicious keyword often used in phishing scams: '{kw}'.")

    risk_level = "HIGH RISK" if findings else "SAFE / CLEAN"
    if findings:
        LAB_METRICS["malicious_indicators_detected"] += 1

    return jsonify({
        "risk_level": risk_level,
        "findings": findings if findings else ["✅ No common phishing signs detected in the URL."]
    })

# 03 // XSS INJECTION SANDBOX (Option 5 & 11)
@app.route('/api/scan_xss', methods=['POST'])
def scan_xss():
    data = request.json or {}
    payload = data.get('payload', '')
    security_on = data.get('security_on', False)

    contains_script = "<script" in payload.lower() or "javascript:" in payload.lower() or "onerror" in payload.lower()

    if security_on:
        if contains_script: LAB_METRICS["total_attacks_blocked"] += 1
        # Defensive Input Sanitization
        sanitized = payload.replace("<", "&lt;").replace(">", "&gt;")
        return jsonify({
            "status": "SECURE",
            "output": sanitized,
            "verdict": "Safe: Code execution blocked. Input sanitized using HTML Entity Encoding to render it as harmless text.",
            "code": "sanitized = user_input.replace('<', '&lt;').replace('>', '&gt;')"
        })
    else:
        if contains_script: LAB_METRICS["vulnerabilities_exploited"] += 1
        return jsonify({
            "status": "VULNERABLE",
            "output": payload,
            "verdict": "Vulnerable: Raw input loaded directly into the website. Any code typed here will run automatically.",
            "code": "return render_template_string(f'<div>{raw_user_input}</div>')"
        })

# 04 // LOGIN BRUTE FORCE SIMULATOR (Option 8 & 11)
@app.route('/api/brute_login', methods=['POST'])
def brute_login():
    data = request.json or {}
    username = data.get('username', '').strip().lower()
    password = data.get('password', '').strip().upper() # Normalized to UPPERCASE to prevent typos/case failures
    security_on = data.get('security_on', False)

    if security_on:
        current_time = time.time()
        if username in FAILED_ATTEMPTS:
            attempts, last_time = FAILED_ATTEMPTS[username]
            if attempts >= MAX_ATTEMPTS and (current_time - last_time) < LOCKOUT_TIME:
                LAB_METRICS["total_attacks_blocked"] += 1
                remaining = int(LOCKOUT_TIME - (current_time - last_time))
                return jsonify({
                    "status": "LOCKED",
                    "message": f"❌ Account Locked! Too many failed attempts. Security cooldown active. Try again in {remaining}s.",
                    "code": "if failed_attempts >= 3:\n    return abort(429, 'Locked Out')"
                }), 429
        
        # Safe comparison accepting standard or capitalized entries smoothly
        if username == "admin" and (password == "PASSWORD123" or password == "PASSWORD123"):
            FAILED_ATTEMPTS[username] = (0, 0)
            return jsonify({"status": "SUCCESS", "message": "✅ Success: Welcome admin! Login successful under secure mode."})
        else:
            attempts, _ = FAILED_ATTEMPTS.get(username, (0, 0))
            new_attempts = attempts + 1
            FAILED_ATTEMPTS[username] = (new_attempts, current_time)
            left = max(0, MAX_ATTEMPTS - new_attempts)
            return jsonify({
                "status": "FAILED",
                "message": f"⚠️ Access Denied: Incorrect credentials. Attempts left before lockout: {left}.",
                "code": "attempts_left = max(0, MAX_ATTEMPTS - new_attempts)"
            }), 401
    else:
        if username == "admin" and (password == "PASSWORD123" or password == "PASSWORD123"):
            LAB_METRICS["vulnerabilities_exploited"] += 1
            return jsonify({"status": "SUCCESS", "message": "🔓 Flag: AUTH_BYPASS_SUCCESS_WITHOUT_LIMITS"})
        else:
            return jsonify({"status": "FAILED", "message": "❌ Invalid login. Vulnerable Mode allows unlimited, rapid automated guesses."}), 401

# 05 // LOG ANALYZER (Option 9)
@app.route('/api/analyze_logs', methods=['POST'])
def analyze_logs():
    mock_logs = [
        "192.168.1.104 - 'POST /api/login' 401 - Login Failure",
        "192.168.1.104 - 'POST /api/login' 401 - Login Failure",
        "192.168.1.104 - 'POST /api/login' 401 - Login Failure",
        "172.16.254.1 - 'GET /admin/private/config.json' 403 - Access Denied"
    ]
    
    findings = [f"Successfully read through {len(mock_logs)} line items in the server log file."]
    failed_logins = sum(1 for line in mock_logs if "401" in line)
    
    if failed_logins >= 3:
        findings.append(f"🚨 Attack Detected: Found {failed_logins} rapid login failures from the same computer (Brute Force attack pattern).")
    if any("403" in line for line in mock_logs):
        findings.append("🛑 Security Alert: An unauthorized user tried to browse inside restricted system folders (/admin/private/).")

    LAB_METRICS["malicious_indicators_detected"] += 1
    return jsonify({"findings": findings, "raw_logs": mock_logs})

# 06 // FILE INTEGRITY CHECKER (Option 10)
@app.route('/api/check_integrity', methods=['POST'])
def check_integrity():
    data = request.json or {}
    tamper = data.get('tamper', False)

    baseline_data = b"important_system_settings_v1.0"
    active_data = baseline_data + b"_MALWARE_MODIFICATION" if tamper else baseline_data

    base_hash = hashlib.sha256(baseline_data).hexdigest()
    live_hash = hashlib.sha256(active_data).hexdigest()

    if base_hash != live_hash:
        status = "❌ FILE CHANGED (INTEGRITY COMPROMISED)"
        explanation = "Alert! The file's current unique hash signature does not match the original template record. Someone has modified or tampered with the system settings file."
        LAB_METRICS["malicious_indicators_detected"] += 1
    else:
        status = "✅ FILE VERIFIED (SAFE)"
        explanation = "Success: The current file hash matches the original baseline perfectly. The file is intact and safe from tampering."

    return jsonify({
        "status": status,
        "explanation": explanation,
        "baseline": base_hash,
        "current": live_hash
    })

if __name__ == '__main__':
    app.run(debug=True, port=5000)