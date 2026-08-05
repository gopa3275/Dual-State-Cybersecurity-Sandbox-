from flask import Blueprint, request, jsonify, session
import base64
import urllib.parse
import html
import hashlib
from flask import render_template
from utils import get_session_telemetry

tools_bp = Blueprint('tools', __name__)

@tools_bp.route('/tools')
def tools_page():
    return render_template('features/tools.html', active_page='tools')

@tools_bp.route('/api/metrics', methods=['GET'])
def get_metrics():
    """Returns real-time session telemetry counters starting at 0."""
    return jsonify(get_session_telemetry())

@tools_bp.route('/api/security_mode', methods=['GET', 'POST'])
def security_mode():
    """Toggles or gets the global security mode in the session."""
    if request.method == 'POST':
        # Toggle the existing mode; default to False (Vulnerable) if not set
        session['security_mode'] = not session.get('security_mode', False)
        session.modified = True
    
    return jsonify({"security_mode": session.get('security_mode', False)})

@tools_bp.route('/api/reset_all', methods=['POST'])
def reset_all():
    """Clears the entire session to reset all user progress."""
    session.clear()
    return jsonify({"success": True, "message": "Session cleared."})

@tools_bp.route('/api/tools/encode', methods=['POST'])
def tools_encode():
    """Transforms strings into Base64, Hex, URL, or HTML Entities."""
    data = request.get_json() or {}
    text = data.get('text', '')
    mode = data.get('mode', 'base64_enc')
    
    try:
        if mode == 'base64_enc':
            result = base64.b64encode(text.encode()).decode()
        elif mode == 'base64_dec':
            result = base64.b64decode(text.encode()).decode()
        elif mode == 'url_enc':
            result = urllib.parse.quote(text)
        elif mode == 'url_dec':
            result = urllib.parse.unquote(text)
        elif mode == 'hex_enc':
            result = text.encode().hex()
        elif mode == 'hex_dec':
            result = bytes.fromhex(text).decode()
        elif mode == 'html_entity':
            result = html.escape(text)
        else:
            return jsonify({"success": False, "result": "Invalid mode specified."}), 400
        
        return jsonify({"success": True, "result": result})
    except Exception as e:
        return jsonify({"success": False, "result": f"Transformation Error: {str(e)}"}), 400

@tools_bp.route('/api/tools/hash', methods=['POST'])
def tools_hash():
    """Computes the SHA-256 hash of a given text string."""
    data = request.get_json() or {}
    text = data.get('text', '')
    hash_object = hashlib.sha256(text.encode())
    hex_dig = hash_object.hexdigest()
    return jsonify({"success": True, "hash": hex_dig})