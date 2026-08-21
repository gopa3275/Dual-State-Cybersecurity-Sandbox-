from flask import Blueprint, request, jsonify, session, render_template
import sqlite3
from utils import get_session_telemetry

sqli_bp = Blueprint('sqli', __name__)

def init_sqli_db():
    """Creates a temporary in-memory database for SQL injection sandbox tests."""
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, role TEXT, salary INTEGER, secret_key TEXT)")
    cursor.execute("INSERT INTO users VALUES (1, 'admin', 'Administrator', 150000, 'FLAG{SQLi_ADMIN_BYPASS_SUCCESS}')")
    cursor.execute("INSERT INTO users VALUES (2, 'alice', 'Security Specialist', 95000, 'SECRET_ALICE_KEY_88')")
    cursor.execute("INSERT INTO users VALUES (3, 'bob', 'DevOps Lead', 88000, 'SECRET_BOB_KEY_99')")
    cursor.execute("INSERT INTO users VALUES (4, 'charlie', 'Junior Developer', 65000, 'SECRET_CHARLIE_KEY_11')")
    conn.commit()
    return conn

@sqli_bp.route('/sqli')
def sqli_page():
    return render_template('features/sqli.html', active_page='sqli')

@sqli_bp.route('/api/sqli_scan', methods=['POST'])
def sqli_scan():
    data = request.get_json() or {}
    username_input = data.get('username', '')
    # Consistently read security mode from session
    is_secure = session.get('security_on', False)
    
    tel = get_session_telemetry()
    # Create a fresh, isolated in-memory database for each request to ensure test purity.
    db_conn = init_sqli_db()
    cursor = db_conn.cursor()
    
    if is_secure:
        query_str = "SELECT id, username, role, salary FROM users WHERE username = ?"
        try:
            cursor.execute(query_str, (username_input,))
            results = cursor.fetchall()
            tel["attacks_blocked"] += 1
            session.modified = True
            return jsonify({
                "status": "SECURE",
                "query": query_str,
                "results": [{"id": r[0], "username": r[1], "role": r[2], "salary": r[3]} for r in results],
                "verdict": f"🛡️ Secure: Input '{username_input}' was bound safely as a parameter.",
                "code": "cursor.execute('SELECT * FROM users WHERE username = ?', (input_str,))",
                "telemetry": get_session_telemetry()
            })
        except Exception as e:
            return jsonify({"status": "ERROR", "message": str(e), "telemetry": get_session_telemetry()})
    else:
        query_str = f"SELECT id, username, role, salary FROM users WHERE username = '{username_input}'"
        try:
            cursor.execute(query_str)
            results = cursor.fetchall()
            tel["flaws_exploited"] += 1
            session.modified = True
            return jsonify({
                "status": "VULNERABLE",
                "query": query_str,
                "results": [{"id": r[0], "username": r[1], "role": r[2], "salary": r[3]} for r in results],
                "verdict": "🚨 Vulnerable: Raw string formatting allowed SQL manipulation!",
                "code": f"cursor.execute(f'SELECT * FROM users WHERE username = \"{{input_str}}\"')\n# Exploit Payload: ' OR '1'='1",
                "telemetry": get_session_telemetry()
            })
        except Exception as e:
            return jsonify({"status": "SQL_ERROR", "query": query_str, "message": f"SQL Syntax Error: {str(e)}", "telemetry": get_session_telemetry()})