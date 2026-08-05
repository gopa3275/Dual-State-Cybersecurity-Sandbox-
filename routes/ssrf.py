from flask import Blueprint, request, jsonify, session, render_template
import requests
from urllib.parse import urlparse
import ipaddress
from utils import get_session_telemetry

ssrf_bp = Blueprint('ssrf', __name__)

# A restrictive allowlist for Secure Mode
ALLOWED_DOMAINS = [
    'example.com',
    'api.github.com',
    'worldtimeapi.org'
]

@ssrf_bp.route('/ssrf')
def ssrf_page():
    """Renders the Server-Side Request Forgery feature page."""
    return render_template('features/ssrf.html', active_page='ssrf')

@ssrf_bp.route('/api/ssrf/fetch', methods=['POST'])
def fetch_url_content():
    data = request.get_json() or {}
    url = data.get('url', '')
    is_secure = data.get('security_on', session.get('security_mode', False))
    tel = get_session_telemetry()

    if not url:
        return jsonify({"error": "URL is required."}), 400

    if is_secure:
        # SECURE MODE: Validate the URL against a strict allowlist
        try:
            parsed_url = urlparse(url)
            # Use ipaddress library for robust IP validation
            try:
                ipaddress.ip_address(parsed_url.hostname or "")
                # If the above line doesn't raise a ValueError, it's a valid IP address
                raise ValueError("Direct IP address requests are forbidden.")
            except ValueError as ip_e:
                # This is expected if it's a domain name. If it was a valid IP, our custom error is re-raised.
                if "forbidden" in str(ip_e):
                    raise
            if parsed_url.hostname not in ALLOWED_DOMAINS:
                raise ValueError(f"Domain '{parsed_url.hostname}' is not in the allowed list.")
            if parsed_url.scheme not in ['http', 'https']:
                raise ValueError(f"Scheme '{parsed_url.scheme}' is not allowed.")
        except (ValueError, AttributeError) as e:
            tel['attacks_blocked'] += 1
            session.modified = True
            return jsonify({"error": f"ATTACK BLOCKED: Invalid URL. {str(e)}"}), 400
    else:
        # VULNERABLE MODE: No validation, just log the potential exploit
        tel['flaws_exploited'] += 1
        session.modified = True

    try:
        response = requests.get(url, timeout=3, headers={'User-Agent': 'CyberSandbox-SSRF-Scanner/1.0'})
        response.raise_for_status()
        
        content = response.text[:2048] + ('...' if len(response.text) > 2048 else '')
        
        return jsonify({"url": url, "content": content, "status_code": response.status_code})
    except requests.exceptions.RequestException as e:
        return jsonify({"error": f"Could not fetch URL: {str(e)}"}), 500