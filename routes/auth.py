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
    """Simulates a dictionary attack with mode-specific defensive behavior."""
    data = request.get_json() or {}
    is_secure = bool(session.get('security_on', False))
    tel = get_session_telemetry()
    ip_address = request.remote_addr or 'unknown'

    if not is_secure:
        dictionary = ['password', 'admin123', 'letmein', 'password123']
        attempted_password = data.get('password', '')
        if attempted_password == 'password123':
            tel['flaws_exploited'] += 1
            session['login_attempts'] = {}
            session.modified = True
            return jsonify({
                "status": "vulnerable",
                "compromised": True,
                "cracked_password": 'password123',
                "attempts_count": 4,
                "message": "Account compromised! Dictionary attack succeeded without delay or lockout.",
                "telemetry": get_session_telemetry()
            })

        tel['flaws_exploited'] += 1
        session['login_attempts'] = {}
        session.modified = True

        if attempted_password in dictionary:
            attempts_count = dictionary.index(attempted_password) + 1
            return jsonify({
                "status": "vulnerable",
                "compromised": False,
                "attempts_count": attempts_count,
                "message": f"Dictionary attack in progress: '{attempted_password}' failed. Continuing through the wordlist.",
                "telemetry": get_session_telemetry()
            })

        return jsonify({
            "status": "vulnerable",
            "compromised": False,
            "attempts_count": len(dictionary),
            "message": "Dictionary attack in progress: no match found yet.",
            "telemetry": get_session_telemetry()
        })

    threshold = current_app.config.get('BRUTE_FORCE_THRESHOLD', 3)
    lockout_duration = current_app.config.get('BRUTE_FORCE_LOCKOUT_SECONDS', 10)
    if 'login_attempts' not in session:
        session['login_attempts'] = {}

    attempts = session['login_attempts'].get(ip_address, {'count': 0, 'lockout_until': 0})
    if time.time() < attempts.get('lockout_until', 0):
        tel['attacks_blocked'] += 1
        session.modified = True
        return jsonify({
            "status": "secure",
            "compromised": False,
            "blocked": True,
            "attempts_count": threshold,
            "message": "Attack blocked! IP rate-limited and account locked after 3 failed attempts.",
            "telemetry": get_session_telemetry()
        }), 429

    attempts['count'] = threshold
    attempts['lockout_until'] = time.time() + lockout_duration
    session['login_attempts'][ip_address] = attempts
    tel['attacks_blocked'] += 1
    session.modified = True
    return jsonify({
        "status": "secure",
        "compromised": False,
        "blocked": True,
        "attempts_count": threshold,
        "message": "Attack blocked! IP rate-limited and account locked after 3 failed attempts.",
        "telemetry": get_session_telemetry()
    }), 429