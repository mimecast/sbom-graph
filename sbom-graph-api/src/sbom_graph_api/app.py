"""Flask application factory and main entry point.

This module provides the Flask application factory and configuration
for the AppSec Data Views service.
"""

import logging
import os
from datetime import timedelta

from flask import Flask, jsonify, redirect, render_template, session, url_for
from flask_jwt_extended import JWTManager
from flask_wtf.csrf import CSRFError, CSRFProtect

from sbom_graph_api.config import get_config
from sbom_graph_api.routes import api_v1, auth, exports, ingest, reports, schemas, visualizations

logger = logging.getLogger(__name__)

csrf = CSRFProtect()

_INSECURE_DEFAULT_SECRETS = frozenset({
    "dev-secret-key-change-in-production",
    "jwt-secret-key-change-in-production",
    "db-encryption-key-change-in-production",
})


def create_app() -> Flask:
    """Create and configure the Flask application.

    Returns:
        Configured Flask application instance
    """
    # Configure template folder relative to this module
    template_dir = os.path.join(os.path.dirname(__file__), "templates")
    static_dir = os.path.join(os.path.dirname(__file__), "static")
    app = Flask(__name__, template_folder=template_dir, static_folder=static_dir)

    config = get_config()

    # Reject known insecure default secrets in non-debug mode
    if not config.debug:
        for label, value in [
            ("FLASK_SECRET_KEY", config.secret_key),
            ("JWT_SECRET_KEY", config.jwt.secret_key),
            ("TOKEN_DB_ENCRYPTION_KEY", config.database.encryption_key),
        ]:
            if value in _INSECURE_DEFAULT_SECRETS:
                raise RuntimeError(
                    f"{label} is set to an insecure default value. "
                    f"Set a strong, unique value via environment variable before deploying."
                )

    # Warn if LDAP is enabled without SSL
    if config.ldap.enabled and not config.ldap.use_ssl:
        logger.warning(
            "LDAP is enabled without SSL (LDAP_USE_SSL=false). "
            "Credentials will be sent in cleartext. Set LDAP_USE_SSL=true for production."
        )

    # Flask configuration
    app.config["SECRET_KEY"] = config.secret_key
    app.config["DEBUG"] = config.debug

    # JWT configuration
    app.config["JWT_SECRET_KEY"] = config.jwt.secret_key
    app.config["JWT_ACCESS_TOKEN_EXPIRES"] = config.jwt.access_token_expires
    app.config["JWT_REFRESH_TOKEN_EXPIRES"] = config.jwt.refresh_token_expires
    app.config["JWT_ALGORITHM"] = config.jwt.algorithm
    app.config["JWT_TOKEN_LOCATION"] = config.jwt.token_location
    app.config["JWT_COOKIE_SECURE"] = config.tls.enabled  # Only send cookies over HTTPS
    app.config["JWT_COOKIE_CSRF_PROTECT"] = False  # Disable CSRF for cookies (session handles CSRF)
    app.config["JWT_COOKIE_SAMESITE"] = "Lax"

    # Session configuration
    app.config["SESSION_COOKIE_SECURE"] = config.tls.enabled
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=8)  # Session timeout

    # CSRF protection (Flask-WTF auto-exempts requests with Content-Type: application/json)
    app.config["WTF_CSRF_TIME_LIMIT"] = 3600
    csrf.init_app(app)

    # Initialize JWT extension
    jwt = JWTManager(app)

    # JWT error handlers
    @jwt.expired_token_loader
    def expired_token_callback(jwt_header, jwt_payload):
        if _is_api_request():
            return jsonify({"error": "Token has expired", "code": "token_expired"}), 401
        return redirect(url_for("auth.login"))

    @jwt.invalid_token_loader
    def invalid_token_callback(error):
        if _is_api_request():
            return jsonify({"error": "Invalid token", "code": "invalid_token"}), 401
        return redirect(url_for("auth.login"))

    @jwt.unauthorized_loader
    def missing_token_callback(error):
        if _is_api_request():
            return jsonify({"error": "Authorization required", "code": "missing_token"}), 401
        return redirect(url_for("auth.login"))

    # Enforce a maximum request body size (50 MB) to mitigate oversized payloads
    app.config.setdefault("MAX_CONTENT_LENGTH", 50 * 1024 * 1024)

    # Register blueprints
    app.register_blueprint(auth.bp)
    app.register_blueprint(visualizations.bp)
    app.register_blueprint(exports.bp)
    app.register_blueprint(reports.bp)
    app.register_blueprint(schemas.bp)
    app.register_blueprint(ingest.bp)
    app.register_blueprint(api_v1.bp)

    # Exempt JWT-only endpoints from CSRF (no browser form)
    csrf.exempt(app.view_functions["auth.refresh"])
    csrf.exempt(app.view_functions["ingest.upload_cyclonedx"])
    csrf.exempt(api_v1.bp)

    # Health check endpoint (no auth, no CSRF)
    @csrf.exempt
    @app.route("/health")
    def health():
        """Health check endpoint for Kubernetes probes."""
        return jsonify({"status": "healthy"})

    # Ready check endpoint (no auth, no CSRF)
    @csrf.exempt
    @app.route("/ready")
    def ready():
        """Readiness check endpoint for Kubernetes probes."""
        try:
            from sbom_graph_api.services.falkordb_service import get_falkordb_service

            service = get_falkordb_service()
            # Simple connectivity check
            service.execute_query("RETURN 1", {})
            return jsonify({"status": "ready"})
        except Exception as e:
            logger.error("Readiness check failed: %s", e)
            return jsonify({"status": "not_ready", "error": "Database connection failed"}), 503

    # Index/documentation endpoint
    @app.route("/")
    def index():
        """API documentation endpoint with interactive forms."""
        # Check authentication if enabled
        if config.auth_enabled:
            if not session.get("authenticated"):
                return redirect(url_for("auth.login"))
        return render_template(
            "api_docs.html",
            auth_enabled=config.auth_enabled,
            username=session.get("username"),
            is_admin=session.get("is_admin", False),
            ldap_enabled=config.ldap.enabled,
        )

    @app.after_request
    def set_security_headers(response):
        """Add security headers to every response."""
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = (
            "geolocation=(), microphone=(), camera=()"
        )
        return response

    @app.errorhandler(CSRFError)
    def handle_csrf_error(e):
        """Return a user-friendly message for CSRF failures."""
        if _is_api_request():
            return jsonify({"error": "CSRF token missing or invalid"}), 400
        return render_template(
            "error.html",
            error="Session Expired",
            message="Your session has expired or the form token is invalid. "
            "Please go back and try again.",
        ), 400

    return app


def _is_api_request() -> bool:
    """Check if the current request is an API request."""
    from flask import request

    return (
        request.is_json
        or request.headers.get("Accept") == "application/json"
        or request.headers.get("Authorization") is not None
    )


def main() -> None:
    """Main entry point for development server."""
    config = get_config()
    app = create_app()

    # Configure SSL if enabled
    ssl_context = None
    if config.tls.enabled and config.tls.cert_file and config.tls.key_file:
        ssl_context = (config.tls.cert_file, config.tls.key_file)

    app.run(
        host=config.host,
        port=config.port,
        debug=config.debug,
        ssl_context=ssl_context,
    )


if __name__ == "__main__":
    main()
