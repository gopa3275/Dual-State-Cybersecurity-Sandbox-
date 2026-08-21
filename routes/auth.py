from flask import Blueprint, request, jsonify, session, render_template, current_app
from utils import get_session_telemetry
import math
import re
import time

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/auth')
def auth_page():
    """Renders the Authentication Audit feature page."""
    return render_template('features/auth.html', active_page='auth')

# --- Password Entropy Logic ---
def calculate_entropy(password):
    """Calculates password entropy based on character set size and length."""
    if not password:
        return 0.0
    
    pool_size = 0
    if re.search(r'[a-z]', password):
        pool_size += 26
    if re.search(r'[A-Z]', password):
        pool_size += 26
    if re.search(r'\d', password):
        pool_size += 10
    if re.search(r'[^a-zA-Z\d]', password):
        pool_size += 32 # Common estimate for symbols
        
    if pool_size == 0:
        return 0.0
        
    # Entropy H = L * log2(N)
    # L = length of password, N = size of character pool
    entropy_bits = len(password) * math.log2(pool_size)
    return entropy_bits

def get_password_strength(total_bits):
    """Categorizes password strength based on total entropy bits."""
    # Stricter thresholds for better real-world alignment
    if total_bits < 50:
        density = "WEAK"
        crack_time = "Instantly to Hours"
        feedback = "Very predictable. Avoid common words, use a mix of uppercase, lowercase, numbers, and symbols, and increase length to at least 12 characters."
    elif total_bits < 75:
        density = "MODERATE"
        crack_time = "Days to Months"
        feedback = "Fairly resistant, but could be stronger. Try adding more complexity or increasing the length."
    else:
        density = "STRONG"
        crack_time = "Years to Millennia"
        feedback = "Excellent complexity and length. Highly resistant to brute-force attacks."
    return density, crack_time, feedback

@auth_bp.route('/api/analyze_password', methods=['POST'])
def analyze_password():
    """Analyzes password entropy and provides feedback."""
    data = request.get_json() or {}
    password = data.get('password', '')
    
    total_bits = calculate_entropy(password)
    density, crack_time, feedback = get_password_strength(total_bits)
    
    return jsonify({
        "password": password,
        "entropy": round(total_bits, 2),
        "density": density,
        "crack_time": crack_time,
        "feedback": feedback,
        "telemetry": get_session_telemetry()
    })

# --- Brute Force Logic ---
@auth_bp.route('/api/brute_login', methods=['POST'])
def brute_login():
    """Simulates a login attempt with distinct Vulnerable and Secure modes.

    Vulnerable mode: no rate limiting, iterate through a provided dictionary until the
    target password is found and report attempts_count + cracked_password.

    Secure mode: enforce defensive controls and stop the attack at the configured
    threshold (default 3). Return a structured JSON payload indicating block.
    """
    data = request.get_json() or {}
    # Read security mode from session (backend authoritative)
    is_secure = session.get('security_on', False)
    tel = get_session_telemetry()

    # --- Vulnerable Mode ---
    if not is_secure:
        # No rate limiting or lockout; attacker iterates the dictionary sequentially
        dictionary = data.get('dictionary', ['123456', 'password', 'admin', 'password123'])
        target_password = data.get('target_password', 'password123')

        attempts_count = 0
        tried_passwords = []
        cracked_password = None

        for pwd in dictionary:
            attempts_count += 1
            tried_passwords.append(pwd)
            if pwd == target_password:
                cracked_password = pwd
                break

        # Update telemetry
        tel['flaws_exploited'] = tel.get('flaws_exploited', 0) + 1
        session.modified = True

        return jsonify({
            "status": "vulnerable",
            "compromised": True if cracked_password else False,
            "cracked_password": cracked_password if cracked_password else None,
            "attempts_count": attempts_count,
            "message": "Account compromised! Dictionary attack succeeded without delay or lockout.",
            "tried_passwords": tried_passwords,
            "telemetry": get_session_telemetry()
        })

    # --- Secure Mode ---
    ip_address = request.remote_addr or 'unknown'
    if 'login_attempts' not in session:
        session['login_attempts'] = {}

    # Initialize per-IP attempts counter
    attempts = session['login_attempts'].get(ip_address, {"count": 0})

    threshold = current_app.config.get('BRUTE_FORCE_THRESHOLD', 3)

    # Simulate incoming rapid attempts by incrementing the counter once per API call
    attempts['count'] = attempts.get('count', 0) + 1
    session['login_attempts'][ip_address] = attempts
    session.modified = True

    # If threshold reached, block and report defensive outcome
    if attempts['count'] >= threshold:
        # Increment telemetry for blocked attacks
        tel['attacks_blocked'] = tel.get('attacks_blocked', 0) + 1
        # Reset or keep the counter depending on desired UX; reset here to simulate lockout
        attempts['count'] = 0
        session['login_attempts'][ip_address] = attempts
        session.modified = True

        return jsonify({
            "status": "secure",
            "compromised": False,
            "blocked": True,
            "attempts_count": threshold,
            "message": "Attack blocked! IP rate-limited and account locked after 3 failed attempts.",
            "telemetry": get_session_telemetry()
        })

    # Not yet at threshold: report a failed attempt
    return jsonify({
        "status": "secure",
        "compromised": False,
        "blocked": False,
        "attempts_count": attempts['count'],
        "message": f"Failed login attempt #{attempts['count']} from {ip_address}.",
        "telemetry": get_session_telemetry()
    })