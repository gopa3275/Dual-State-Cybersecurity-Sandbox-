from flask import session

def get_session_telemetry():
    """Gets or initializes a telemetry dictionary in the user's session."""
    if 'telemetry' not in session:
        session['telemetry'] = {
            "attacks_blocked": 0,
            "flaws_exploited": 0,
            "threats_spotted": 0
        }
    return session['telemetry']