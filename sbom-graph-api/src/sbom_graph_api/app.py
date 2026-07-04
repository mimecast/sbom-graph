"""Flask application factory and main entry point.

This module provides the Flask application factory and configuration
for the AppSec Data Views service.
"""

import logging
import os
from datetime import timedelta

from flask import Flask, Response, jsonify, redirect, render_template, request, session, url_for
from flask_jwt_extended import JWTManager
from flask_wtf.csrf import CSRFError, CSRFProtect
from werkzeug.middleware.proxy_fix import ProxyFix

from sbom_graph_api.config import get_config
from sbom_graph_api.routes import (
    admin,
    api_v1,
    auth,
    ingest,
    reports,
    schemas,
    visualizations,
)

logger = logging.getLogger(__name__)

csrf = CSRFProtect()

_INSECURE_DEFAULT_SECRETS = frozenset(
    {
        "dev-secret-key-change-in-production",
        "jwt-secret-key-change-in-production",
        "db-encryption-key-change-in-production",
    }
)


def create_app() -> Flask:
    """Create and configure the Flask application.

    Returns:
        Configured Flask application instance
    """
    # Configure template folder relative to this module
    template_dir = os.path.join(os.path.dirname(__file__), "templates")
    static_dir = os.path.join(os.path.dirname(__file__), "static")
    app = Flask(__name__, template_folder=template_dir, static_folder=static_dir)

    # Behind a reverse proxy / K8s ingress, trust X-Forwarded-* so request.remote_addr
    # reflects the real client IP (rate limiters key on it). TRUSTED_PROXY_HOPS=0
    # disables this for direct-exposure deployments (where XFF would be spoofable).
    _proxy_hops = int(os.environ.get("TRUSTED_PROXY_HOPS", "1"))
    if _proxy_hops > 0:
        app.wsgi_app = ProxyFix(  # type: ignore[method-assign]
            app.wsgi_app, x_for=_proxy_hops, x_proto=_proxy_hops, x_host=_proxy_hops
        )

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

    # LDAP without TLS sends bind credentials in cleartext (CWE-319).
    if config.ldap.enabled and not config.ldap.use_ssl:
        if not config.debug:
            raise RuntimeError(
                "LDAP is enabled without TLS (LDAP_USE_SSL=false); bind credentials "
                "would be sent in cleartext. Set LDAP_USE_SSL=true before deploying."
            )
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
    # CSRF for cookies handled by session; disable JWT-cookie CSRF
    app.config["JWT_COOKIE_CSRF_PROTECT"] = False
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
    def expired_token_callback(_jwt_header, _jwt_payload):
        if _is_api_request():
            return jsonify({"error": "Token has expired", "code": "token_expired"}), 401
        return redirect(url_for("auth.login"))

    @jwt.invalid_token_loader
    def invalid_token_callback(_error):
        if _is_api_request():
            return jsonify({"error": "Invalid token", "code": "invalid_token"}), 401
        return redirect(url_for("auth.login"))

    @jwt.unauthorized_loader
    def missing_token_callback(_error):
        if _is_api_request():
            return jsonify({"error": "Authorization required", "code": "missing_token"}), 401
        return redirect(url_for("auth.login"))

    # Enforce a maximum request body size (50 MB) to mitigate oversized payloads
    app.config.setdefault("MAX_CONTENT_LENGTH", 50 * 1024 * 1024)

    # Register blueprints
    app.register_blueprint(admin.bp)
    app.register_blueprint(auth.bp)
    app.register_blueprint(visualizations.bp)
    app.register_blueprint(reports.bp)
    app.register_blueprint(schemas.bp)
    app.register_blueprint(ingest.bp)
    app.register_blueprint(api_v1.bp)

    # CSRF exemptions — these endpoints authenticate exclusively via JWT
    # Bearer tokens (not cookies), so CSRF does not apply.  See CWE-352.
    csrf.exempt(app.view_functions["auth.refresh"])
    csrf.exempt(app.view_functions["ingest.upload_cyclonedx"])
    csrf.exempt(app.view_functions["ingest.upload_spdx"])
    csrf.exempt(app.view_functions["ingest.upload_sbom"])
    csrf.exempt(app.view_functions["ingest.upload_vex"])
    csrf.exempt(api_v1.bp)

    @app.after_request
    def _set_security_headers(response: Response) -> Response:
        response.headers.setdefault(
            "X-Content-Type-Options", "nosniff"
        )
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault(
            "Referrer-Policy",
            "strict-origin-when-cross-origin",
        )
        response.headers.setdefault(
            "Permissions-Policy",
            "geolocation=(), microphone=(), camera=()",
        )
        # PyVis visualizations embed inline JS/CSS (cdn_resources="in_line"), so
        # script/style-src must allow 'unsafe-inline'; everything else is locked to
        # 'self'. frame-ancestors 'none' complements X-Frame-Options: DENY.
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "base-uri 'self'; "
            "form-action 'self'; "
            "frame-ancestors 'none'",
        )
        return response

    @app.after_request
    def _inject_home_button(response: Response) -> Response:
        """Inject a floating home button into HTML pages for session-authenticated users.

        Only visible when the user is browsing via the UI (active Flask session),
        not when the response is served to a programmatic API client. Skips the
        home page itself, login/auth pages, and non-HTML responses.
        """
        if (
            response.content_type
            and "text/html" in response.content_type
            and session.get("authenticated")
            and response.status_code == 200
            and request.path != "/"
            and not request.path.startswith("/auth/")
            and not request.path.startswith("/health")
            and not request.path.startswith("/ready")
        ):
            home_btn = (
                '<a id="sbom-home-btn" href="/" title="Back to Home" style="'
                "position:fixed;top:14px;left:14px;z-index:10000;"
                "width:40px;height:40px;border-radius:50%;"
                "background:#2c3e50;color:#fff;display:flex;"
                "align-items:center;justify-content:center;"
                "text-decoration:none;font-size:20px;"
                "box-shadow:0 2px 8px rgba(0,0,0,0.25);"
                "transition:background 0.2s,transform 0.2s;"
                '"'
                ' onmouseenter="this.style.background=\'#3498db\';this.style.transform=\'scale(1.1)\'"'
                ' onmouseleave="this.style.background=\'#2c3e50\';this.style.transform=\'scale(1)\'"'
                ">"
                "&#8962;"
                "</a>"
            )
            data = response.get_data(as_text=True)
            if "</body>" in data:
                data = data.replace("</body>", f"{home_btn}</body>", 1)
                response.set_data(data)
        return response

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
        except Exception as e:  # pylint: disable=broad-exception-caught
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

    @app.errorhandler(CSRFError)
    def handle_csrf_error(e):  # pylint: disable=unused-argument
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
