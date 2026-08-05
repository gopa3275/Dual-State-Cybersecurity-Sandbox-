import os
from flask import Flask
from shared import config_by_name
from routes.welcome import welcome_bp
from routes.auth import auth_bp
from routes.xss import xss_bp
from routes.sqli import sqli_bp
from routes.phishing import phishing_bp
from routes.forensics import forensics_bp
from routes.tools import tools_bp
from routes.ctf import ctf_bp
from routes.csrf import csrf_bp
from routes.ssrf import ssrf_bp
from routes.errors import errors_bp

def create_app(config_name):
    """Application factory."""
    app = Flask(__name__)
    app.config.from_object(config_by_name[config_name])
    app.register_blueprint(welcome_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(xss_bp)
    app.register_blueprint(sqli_bp)
    app.register_blueprint(phishing_bp)
    app.register_blueprint(forensics_bp)
    app.register_blueprint(tools_bp)
    app.register_blueprint(ctf_bp)
    app.register_blueprint(csrf_bp)
    app.register_blueprint(ssrf_bp)
    app.register_blueprint(errors_bp)
    return app

env = os.getenv('FLASK_ENV', 'development')
app = create_app(env)

@app.after_request
def add_security_headers(response):
    """Add security headers to every response."""
    # Prevents clickjacking
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    # Prevents browsers from MIME-sniffing the content-type
    response.headers['X-Content-Type-Options'] = 'nosniff'
    
    # Defines an allowlist for content sources
    # This policy is relaxed to allow inline scripts for functionality. For
    # production, moving scripts to external files is recommended.
    csp = (
        "default-src 'self'; "
        "script-src 'self' https://cdn.jsdelivr.net 'unsafe-inline' 'unsafe-eval'; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data: https:; "
        "connect-src 'self' https://cdn.jsdelivr.net; "
        "object-src 'none'; frame-ancestors 'none'; form-action 'self';"
    )
    response.headers['Content-Security-Policy'] = csp
    
    return response

if __name__ == '__main__':
    app.run(port=5000)