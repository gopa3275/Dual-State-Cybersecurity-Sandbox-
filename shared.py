import os

class Config:
    """Base configuration class with default settings."""
    # Fallback to random secret key if environment variable isn't set
    SECRET_KEY = os.environ.get('SECRET_KEY', os.urandom(24).hex())
    
    # Session Security Settings
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    
    # Security Sandbox Defaults
    MAX_PAYLOAD_LENGTH = 2048  # Prevent extremely large payload crash attempts
    BRUTE_FORCE_THRESHOLD = 3   # Attempts allowed in Secure Mode before lock out
    BRUTE_FORCE_LOCKOUT_SECONDS = 10 # Duration of IP lockout


class DevelopmentConfig(Config):
    """Development environment settings."""
    DEBUG = True
    TESTING = False


class ProductionConfig(Config):
    """Production deployment settings (e.g. Render/Heroku)."""
    DEBUG = False
    TESTING = False
    # Ensure secure cookies in production (requires HTTPS)
    SESSION_COOKIE_SECURE = True
    # Enforce HTTPS
    # response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'


# Config dictionary mapping
config_by_name = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}