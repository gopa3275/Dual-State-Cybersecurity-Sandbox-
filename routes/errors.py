from flask import Blueprint, render_template, jsonify, request

errors_bp = Blueprint('errors', __name__)

@errors_bp.app_errorhandler(404)
def not_found_error(error):
    """Handles 404 Not Found errors gracefully."""
    if request.path.startswith('/api/'):
        return jsonify(error="Not Found", message="The requested API endpoint does not exist."), 404
    return render_template('index.html'), 404

@errors_bp.app_errorhandler(500)
def internal_error(error):
    """Handles 500 Internal Server errors gracefully."""
    if request.path.startswith('/api/'):
        return jsonify(error="Internal Server Error", message="An unexpected server error occurred."), 500
    return render_template('errors/500.html'), 500