from flask import Blueprint, request, jsonify, session, render_template, make_response
import html 
from utils import get_session_telemetry

xss_bp = Blueprint('xss', __name__)

# Sample Payload Presets for quick UI testing
XSS_PRESETS = {
    "basic": "<script>alert('XSS!')</script>",
    "img_onerror": "<img src='x' onerror='alert(\"XSS Vector\")'>",
    "svg": "<svg onload=alert(1)>"
}

@xss_bp.route('/xss')
def xss_page():
    """Renders the XSS feature page, passing the active page for sidebar highlighting."""
    return render_template('features/xss.html', active_page='xss', show_live_logs=True)

@xss_bp.route('/api/xss/presets', methods=['GET'])
def get_presets():
    """Returns preset payload vectors for front-end dropdowns/buttons."""
    return jsonify(XSS_PRESETS)

@xss_bp.route('/api/xss/scan', methods=['POST'])
def scan_xss():
    """
    Handles XSS simulation using per-user Flask session state 
    for the Security Mode toggle.
    """
    data = request.get_json() or {}
    user_input = data.get('payload', '')
    
    # Use session for security mode and telemetry
    is_secure = session.get('security_on', False)
    tel = get_session_telemetry()

    if is_secure:
        tel['attacks_blocked'] += 1
        session.modified = True
        # Secure State: Escape HTML entities to neutralize execution
        sanitized = html.escape(user_input)

        response = make_response(jsonify({
            "status": "neutralized",
            "mode": "SECURE",
            "output": sanitized,
            "message": "Payload safely sanitized via HTML entity encoding. CSP is active.",
            "telemetry": get_session_telemetry()
        }))
        return response
    else:
        tel['flaws_exploited'] += 1
        session.modified = True
        # Vulnerable State: Echo unescaped input
        return jsonify({
            "status": "executed",
            "mode": "VULNERABLE",
            "output": user_input,
            "message": "Warning: Unsanitized input rendered directly!",
            "telemetry": get_session_telemetry()
        })