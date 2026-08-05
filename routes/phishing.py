from flask import Blueprint, request, jsonify, render_template, session
from urllib.parse import urlparse
import re
import ipaddress
from utils import get_session_telemetry

phishing_bp = Blueprint('phishing', __name__)

@phishing_bp.route('/phishing')
def phishing_page():
    return render_template('features/phishing.html', active_page='phishing')

@phishing_bp.route('/api/detect_phishing', methods=['POST'])
def detect_phishing():
    data = request.get_json() or {}
    url = data.get('url', '').strip()
    findings = []
    risk_score = 0
    
    try:
        # Improvement: Ensure a scheme is present for robust parsing.
        if not re.match(r'^[a-zA-Z]+://', url):
            url = 'http://' + url

        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        
        # Check IP Host Masking (using robust ipaddress library)
        try:
            ipaddress.ip_address(domain)
            findings.append("Critical: URL uses a raw IP address instead of a domain name. This is a major red flag.")
            risk_score += 50 # Increased penalty for raw IPs
        except ValueError:
            # This is expected for a domain name, so we pass.
            pass
            
        # Check suspicious keywords (expanded list)
        phish_words = ['secure', 'login', 'banking', 'update', 'verify', 'account', 'paypal', 'support', 'free', 'confirm', 'service', 'webscr', 'cmd']
        found_words = [w for w in phish_words if w in url.lower()]
        if found_words:
            findings.append(f"Suspicious Typosquatting Keywords Identified: {', '.join(found_words)}")
            risk_score += len(found_words) * 10 # Reduced multiplier
            
        # Check domain depth and hyphen count
        if domain.count('-') > 2:
            findings.append("Warning: Domain uses multiple hyphens, a common tactic to mimic legitimate sites.")
            risk_score += 15 # Reduced score
        if domain.count('.') > 3:
            findings.append("Warning: Excessive subdomains detected, which can be used to obscure the true domain.")
            risk_score += 15 # Reduced score

        risk_level = "HIGH RISK (PHISHING LIKELY)" if risk_score >= 50 else "MODERATE RISK" if risk_score >= 25 else "LOW RISK"
        if risk_score >= 50:
            tel = get_session_telemetry()
            tel["threats_spotted"] += 1
            session.modified = True
            
        return jsonify({
            "url": url,
            "domain": domain,
            "risk_level": risk_level,
            "risk_score": min(risk_score, 100),
            "findings": findings if findings else ["No common phishing heuristics triggered. URL appears to be safe."]
        })
    except Exception as e:
        return jsonify({"error": f"Could not process URL: Invalid format or unexpected error. Details: {str(e)}"}), 400
        
    # Check domain depth and hyphen count
    if domain.count('-') > 2:
        findings.append("Warning: Domain uses multiple hyphens, a common tactic to mimic legitimate sites.")
        risk_score += 15 # Reduced score
    if domain.count('.') > 3:
        findings.append("Warning: Excessive subdomains detected, which can be used to obscure the true domain.")
        risk_score += 15 # Reduced score

    risk_level = "HIGH RISK (PHISHING LIKELY)" if risk_score >= 50 else "MODERATE RISK" if risk_score >= 25 else "LOW RISK"
    if risk_score >= 50:
        tel = get_session_telemetry()
        tel["threats_spotted"] += 1
        session.modified = True
        
    return jsonify({
        "url": url,
        "domain": domain,
        "risk_level": risk_level,
        "risk_score": min(risk_score, 100),
        "findings": findings if findings else ["No common phishing heuristics triggered. URL appears to be safe."]
    })