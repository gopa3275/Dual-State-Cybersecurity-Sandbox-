from flask import Blueprint, request, session, render_template, flash, redirect, url_for
import secrets
from utils import get_session_telemetry

csrf_bp = Blueprint('csrf', __name__)

@csrf_bp.route('/csrf', methods=['GET', 'POST'])
def csrf_page():
    # Use unified session key
    is_secure = session.get('security_on', False)
    
    if 'user_email' not in session:
        session['user_email'] = 'user@example.com'

    if request.method == 'POST':
        tel = get_session_telemetry()
        
        if is_secure:
            # SECURE MODE: Check for CSRF token
            submitted_token = request.form.get('csrf_token')
            session_token = session.pop('csrf_token', None)
            
            if not submitted_token or submitted_token != session_token:
                tel['attacks_blocked'] += 1
                session.modified = True
                flash('ATTACK BLOCKED: Invalid or missing CSRF token.', 'success')
                return redirect(url_for('csrf.csrf_page'))
        else:
            # VULNERABLE MODE: No token check, telemetry for exploit
            tel['flaws_exploited'] += 1
            session.modified = True
            flash('VULNERABLE MODE: State-changing action occurred without CSRF protection!', 'danger')

        # If we reach here, the action is processed
        old_email = session.get('user_email')
        new_email = request.form.get('email')
        if new_email:
            session['user_email'] = new_email
            flash(f'Email successfully updated from {old_email} to {new_email}.', 'info')
        
        return redirect(url_for('csrf.csrf_page'))

    # For GET requests, generate a new token for the form
    session['csrf_token'] = secrets.token_hex(16)
        
    return render_template('features/csrf.html', 
                           active_page='csrf', 
                           current_email=session.get('user_email'),
                           csrf_token=session.get('csrf_token'))

# This is a simulated attacker's page that will POST to our main app
@csrf_bp.route('/csrf/attacker')
def attacker_page():
    return render_template('features/csrf_attacker.html', target_url=url_for('csrf.csrf_page'))