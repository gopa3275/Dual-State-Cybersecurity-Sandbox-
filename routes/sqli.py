from flask import Blueprint, request, jsonify, session, render_template
import sqlite3
import difflib
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
    return render_template('features/sqli.html', active_page='sqli', show_live_logs=True)

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
        # SECURE: Use parameterized query representation and avoid leaking sensitive columns
        query_str = "SELECT id, username, role, salary FROM users WHERE username = ?"
        prepared_repr = {
            "prepared_query": query_str,
            "bound_values": [username_input]
        }
        vulnerable_code = f"cursor.execute(f\"SELECT * FROM users WHERE username = '{{input_str}}'\")"
        secure_code = "cursor.execute('SELECT * FROM users WHERE username = ?', (input_str,))"
        try:
            # Intentionally do NOT return secret_key or sensitive columns in secure mode
            # Execute to simulate behavior but only return non-sensitive columns and mask any secrets
            cursor.execute(query_str, (username_input,))
            results = []  # Secure mode intentionally returns 0 leaked rows for demo
            tel["attacks_blocked"] += 1
            session.modified = True
            # Build unified diff between vulnerable and secure snippets for visual diff UI
            try:
                vuln_lines = vulnerable_code.splitlines()
                sec_lines = secure_code.splitlines()
                unified = '\n'.join(difflib.unified_diff(vuln_lines, sec_lines, fromfile='vulnerable.py', tofile='secure.py', lineterm=''))
            except Exception:
                unified = ''

            return jsonify({
                "status": "SECURE",
                "query": query_str,
                "prepared": prepared_repr,
                "ast": {"type": "PreparedStatement", "query": query_str, "params": ["<bound_values>"]},
                "results": results,
                "verdict": f"🛡️ Secure: Input '{username_input}' was bound safely as a parameter.",
                "code_vulnerable": vulnerable_code,
                "code_secure": secure_code,
                "unified_diff": unified,
                "telemetry": get_session_telemetry()
            })
        except Exception as e:
            return jsonify({"status": "ERROR", "message": str(e), "telemetry": get_session_telemetry()})
    else:
        # VULNERABLE: Build raw concatenated query which may be exploited
        query_str = f"SELECT id, username, role, salary FROM users WHERE username = '{username_input}'"
        vulnerable_code = f"cursor.execute(f'" + "SELECT * FROM users WHERE username = \"{input_str}\"')\n# Exploit Payload: ' OR '1'='1"
        secure_code = "cursor.execute('SELECT * FROM users WHERE username = ?', (input_str,))"
        try:
            cursor.execute(query_str)
            results = cursor.fetchall()
            # Map results but intentionally include only non-secret columns
            mapped = [{"id": r[0], "username": r[1], "role": r[2], "salary": r[3]} for r in results]
            tel["flaws_exploited"] += 1
            session.modified = True
            # Build unified diff between vulnerable and secure snippets for visual diff UI
            try:
                vuln_lines = vulnerable_code.splitlines()
                sec_lines = secure_code.splitlines()
                unified = '\n'.join(difflib.unified_diff(vuln_lines, sec_lines, fromfile='vulnerable.py', tofile='secure.py', lineterm=''))
            except Exception:
                unified = ''

            return jsonify({
                "status": "VULNERABLE",
                "query": query_str,
                "ast": {"type": "ConcatenatedString", "structure": "BinaryOp(CONCAT, 'SELECT ... WHERE username = ', input)"},
                "results": mapped,
                "verdict": "🚨 Vulnerable: Raw string formatting allowed SQL manipulation!",
                "code_vulnerable": vulnerable_code,
                "code_secure": secure_code,
                "unified_diff": unified,
                "telemetry": get_session_telemetry()
            })
        except Exception as e:
            return jsonify({"status": "SQL_ERROR", "query": query_str, "message": f"SQL Syntax Error: {str(e)}", "telemetry": get_session_telemetry()})