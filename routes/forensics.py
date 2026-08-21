import hashlib
import os
import re
from flask import Blueprint, jsonify, request, render_template, session, current_app
from utils import get_session_telemetry

forensics_bp = Blueprint('forensics', __name__)

@forensics_bp.route('/forensics')
def forensics_page():
    return render_template('features/forensics.html', active_page='forensics')

def calculate_hash_from_content(content):
    """Calculates the SHA-256 hash of a string content."""
    return hashlib.sha256(content.encode()).hexdigest()

@forensics_bp.route('/api/forensics/check_integrity', methods=['POST'])
def check_integrity():
    """SHA-256 Checksum file audit simulator."""
    data = request.get_json() or {}
    tampered = data.get('tamper', False)
    
    try:
        # Get the absolute path to shared.py relative to the app's root
        shared_py_path = os.path.join(current_app.root_path, 'shared.py')
        with open(shared_py_path, 'r') as f:
            baseline_content = f.read()
    except Exception as e:
        return jsonify({"error": f"Could not read baseline file: {str(e)}"}), 500
    
    current_content = baseline_content + ("\n# UNAUTHORIZED_EDIT" if tampered else "")
    
    baseline_hash = calculate_hash_from_content(baseline_content)
    current_hash = calculate_hash_from_content(current_content)
    
    tel = get_session_telemetry()
    
    if tampered:
        tel['threats_spotted'] += 1
        session.modified = True
        return jsonify({
            "success": False,
            "status": "🚨 INTEGRITY VIOLATION DETECTED",
            "baseline": baseline_hash,
            "current": current_hash,
            "explanation": "SHA-256 mismatch! Configuration file was altered without authorization.",
            "telemetry": get_session_telemetry()
        })
    
    return jsonify({
        "success": True,
        "status": "✅ HASH INTEGRITY VERIFIED",
        "baseline": baseline_hash,
        "current": current_hash,
        "explanation": "Current SHA-256 checksum matches trusted baseline.",
        "telemetry": get_session_telemetry()
    })

@forensics_bp.route('/api/analyze_logs', methods=['POST'])
def analyze_logs():
    """
    Parses log data to find common web attack patterns (SIEM simulation).
    """
    data = request.get_json() or {}
    logs_input = data.get('logs', '')
    raw_logs = logs_input.splitlines()
    
    threats_found = []
    for log in raw_logs:
        if not log.strip():
            continue
        if "' OR '1'='1" in log:
            threats_found.append("🚨 [SQL Injection] SQL Syntax Injected in Auth Stream from 172.16.0.45")
        if "/etc/passwd" in log or "/.env" in log:
            threats_found.append("🛑 [Path Traversal / Recon] Access attempt on restricted system files.")
        if "<script>" in log:
            threats_found.append("⚠️ [Cross-Site Scripting] Reflected XSS script payload detected in parameters.")
            
    tel = get_session_telemetry()
    tel["threats_spotted"] += len(threats_found)
    session.modified = True

    return jsonify({
        "raw_logs": raw_logs,
        "threats_found": threats_found,
        "telemetry": get_session_telemetry()
    })