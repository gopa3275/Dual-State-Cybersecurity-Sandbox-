from flask import Blueprint, request, jsonify, session, render_template
from utils import get_session_telemetry

ctf_bp = Blueprint('ctf', __name__)

CORRECT_FLAGS = {
    "sqli_challenge": "FLAG{SQLi_ADMIN_BYPASS_SUCCESS}",
    "xss_challenge": "FLAG{XSS_DOM_INJECTION_EXPLOITED}",
    "entropy_challenge": "FLAG{SHANNON_ENTROPY_CRACKED}"
}

HINTS = {
    "sqli_challenge": "The goal is to bypass the username check. Think about how SQL handles string concatenation and boolean logic. What if you could make the WHERE clause always true?",
    "xss_challenge": "The application reflects your input into the page. Can you inject HTML tags that execute JavaScript? Look for an event handler.",
    "entropy_challenge": "This flag isn't found in a typical vulnerability. It's related to analyzing the strength of something. Where in the app do you evaluate strength or complexity?"
}

@ctf_bp.route('/ctf')
def ctf_page():
    return render_template('features/ctf.html', active_page='ctf')

@ctf_bp.route('/api/ctf/status', methods=['GET'])
def get_ctf_status():
    """Returns the number of total and captured flags."""
    captured_flags = session.get('captured_flags', [])
    return jsonify({
        "total_flags": len(CORRECT_FLAGS),
        "captured_count": len(captured_flags),
        "telemetry": get_session_telemetry()
    })

@ctf_bp.route('/api/ctf/hint', methods=['POST'])
def get_hint():
    """Provides a hint for a given challenge."""
    data = request.get_json() or {}
    challenge_id = data.get('challenge_id')
    
    if challenge_id in HINTS:
        tel = get_session_telemetry()
        tel['threats_spotted'] += 1 # Using a hint is a "threat" to solving it alone
        session.modified = True
        return jsonify({"success": True, "hint": HINTS[challenge_id], "telemetry": get_session_telemetry()})
    
    return jsonify({"success": False, "hint": "No hint available for this challenge.", "telemetry": get_session_telemetry()}), 404

@ctf_bp.route('/api/ctf/reset', methods=['POST'])
def reset_ctf_progress():
    """Resets the user's CTF progress in the session."""
    if 'captured_flags' in session:
        session.pop('captured_flags')
    
    # Also reset telemetry for a clean start
    if 'telemetry' in session:
        session.pop('telemetry')
        
    session.modified = True
    return jsonify({"success": True, "message": "CTF progress has been reset.", "telemetry": get_session_telemetry()})

@ctf_bp.route('/api/ctf/verify', methods=['POST'])
def verify_flag():
    data = request.get_json() or {}
    flag = data.get('flag', '').strip()
    
    # Check if the submitted flag is one of the correct flags
    if flag in CORRECT_FLAGS.values():
        # To avoid double-counting, check if this flag has already been submitted
        if 'captured_flags' not in session:
            session['captured_flags'] = []

        if flag in session['captured_flags']:
            return jsonify({"success": True, "message": "✅ Correct, but you've already submitted this flag.", "telemetry": get_session_telemetry()})

        tel = get_session_telemetry()
        tel['flaws_exploited'] += 1
        session['captured_flags'].append(flag)
        session.modified = True
        return jsonify({"success": True, "message": "🎉 Correct Flag! Challenge Completed.", "telemetry": get_session_telemetry()})
    
    # Return 200 with a structured response so clients can always rely on a JSON body containing telemetry
    return jsonify({"success": False, "message": "❌ Invalid Flag. Keep trying!", "telemetry": get_session_telemetry()}), 200