from flask import Blueprint, render_template, session

welcome_bp = Blueprint('welcome', __name__)

@welcome_bp.route('/')
def index():
    # Use unified key 'security_on' for the dual-state guard
    if 'security_on' not in session:
        session['security_on'] = False
    if 'failed_logins' not in session:
        session['failed_logins'] = 0
    return render_template('index.html', active_page='welcome')