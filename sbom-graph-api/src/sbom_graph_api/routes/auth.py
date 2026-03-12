"""Flask routes for authentication (login, logout, token management)."""

import logging
import threading
import time
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from functools import wraps
from typing import Any

from flask import (
    Blueprint,
    Response,
    jsonify,
    make_response,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask.typing import ResponseReturnValue
from flask_jwt_extended import (
    create_access_token,
    create_refresh_token,
    get_jwt_identity,
    jwt_required,
    set_access_cookies,
    set_refresh_cookies,
    unset_jwt_cookies,
    verify_jwt_in_request,
)

from sbom_graph_api.config import get_config
from sbom_graph_api.services.ldap_service import (
    LDAPAuthenticationError,
    LDAPUser,
    get_ldap_service,
)
from sbom_graph_api.services.token_storage import get_token_storage
from sbom_graph_api.services.user_storage import LocalUser, get_user_storage
from sbom_graph_api.utils.validation import (
    MAX_EXPIRES_DAYS,
    MAX_TOKEN_DESCRIPTION_LENGTH,
    get_safe_redirect_url,
    validate_format,
    validate_username,
)

logger = logging.getLogger(__name__)

bp = Blueprint("auth", __name__, url_prefix="/auth")


# ---------------------------------------------------------------------------
# In-memory per-IP login rate limiter (defense-in-depth)
#
# Each Gunicorn worker maintains its own dict.  This provides per-worker
# protection against brute-force attacks.  Network-level rate limiting at
# ingress / WAF remains the primary control; this is a secondary safeguard.
# ---------------------------------------------------------------------------

_LOGIN_MAX_ATTEMPTS = 10
_LOGIN_WINDOW_SECONDS = 900  # 15 minutes
_LOGIN_CLEANUP_INTERVAL = 300  # purge stale entries every 5 min

_login_attempts: dict[str, tuple[int, float]] = {}
_login_lock = threading.Lock()
_login_state = {"last_cleanup": time.monotonic()}


def _cleanup_stale_entries() -> None:
    """Remove entries whose window has expired.  Called under ``_login_lock``."""
    now = time.monotonic()
    stale_keys = [
        ip
        for ip, (_, window_start) in _login_attempts.items()
        if now - window_start > _LOGIN_WINDOW_SECONDS
    ]
    for ip in stale_keys:
        del _login_attempts[ip]


def _check_login_rate_limit() -> tuple[Response, int] | None:
    """Return a 429 response if the caller has exceeded the login rate limit.

    Returns ``None`` when the request is within limits.
    """

    client_ip = request.remote_addr or "unknown"
    now = time.monotonic()

    with _login_lock:
        # Periodic housekeeping to prevent unbounded memory growth
        last_cleanup = _login_state["last_cleanup"]
        if now - last_cleanup > _LOGIN_CLEANUP_INTERVAL:
            _cleanup_stale_entries()
            _login_state["last_cleanup"] = now

        entry = _login_attempts.get(client_ip)
        if entry is not None:
            count, window_start = entry
            elapsed = now - window_start
            if elapsed < _LOGIN_WINDOW_SECONDS:
                if count >= _LOGIN_MAX_ATTEMPTS:
                    retry_after = int(_LOGIN_WINDOW_SECONDS - elapsed) + 1
                    logger.warning(
                        "Login rate limit exceeded for IP %s (%d attempts in %.0fs)",
                        client_ip,
                        count,
                        elapsed,
                    )
                    resp = jsonify({"error": "Too many login attempts. Please try again later."})
                    resp.headers["Retry-After"] = str(retry_after)
                    return resp, 429
            else:
                # Window expired -- reset
                _login_attempts[client_ip] = (0, now)

    return None


def _record_login_attempt() -> None:
    """Increment the attempt counter for the current request IP."""
    client_ip = request.remote_addr or "unknown"
    now = time.monotonic()

    with _login_lock:
        entry = _login_attempts.get(client_ip)
        if entry is None or (now - entry[1]) >= _LOGIN_WINDOW_SECONDS:
            _login_attempts[client_ip] = (1, now)
        else:
            _login_attempts[client_ip] = (entry[0] + 1, entry[1])


def _reset_login_attempts() -> None:
    """Clear the counter after a successful login."""
    client_ip = request.remote_addr or "unknown"
    with _login_lock:
        _login_attempts.pop(client_ip, None)


def get_current_user() -> str | None:
    """Get the current authenticated user's username.

    Checks JWT token first, then falls back to session.

    Returns:
        Username string or None if not authenticated
    """

    # Try JWT first - silently fall back to session auth if JWT fails

    try:
        verify_jwt_in_request(optional=True)
        identity = get_jwt_identity()
        if identity:
            return identity
    except Exception:  # nosec B110  # pylint: disable=broad-exception-caught
        pass

    # Fall back to session
    if session.get("authenticated") and session.get("username"):
        return session.get("username")

    return None


def admin_required(fn: Callable) -> Callable:
    """Decorator to require admin privileges for an endpoint."""

    @wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        config = get_config()

        # If auth is disabled, allow all requests
        if not config.auth_enabled:
            return fn(*args, **kwargs)

        # Check if user is authenticated and is admin
        if not session.get("authenticated"):
            if request.is_json:
                return jsonify({"error": "Authentication required"}), 401
            return redirect(url_for("auth.login"))

        if not session.get("is_admin"):
            if request.is_json:
                return jsonify({"error": "Admin privileges required"}), 403
            return render_template(
                "error.html",
                error="Access Denied",
                message="You need administrator privileges to access this page.",
            ), 403

        return fn(*args, **kwargs)

    return wrapper


def auth_required(fn: Callable) -> Callable:
    """Decorator to require authentication for an endpoint.

    Checks for valid JWT token or active session. Returns 401 for API calls
    or redirects to login page for browser requests.
    """

    @wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        config = get_config()

        # If auth is disabled, allow all requests
        if not config.auth_enabled:
            return fn(*args, **kwargs)

        # Check for JWT token first
        try:
            verify_jwt_in_request(optional=True)
            identity = get_jwt_identity()
            if identity:
                return fn(*args, **kwargs)
        except Exception as e:  # pylint: disable=broad-exception-caught
            # JWT verification failed - fall back to session auth
            logger.debug("JWT verification failed, trying session auth: %s", e)

        # Check for session-based authentication
        if session.get("authenticated") and session.get("username"):
            return fn(*args, **kwargs)

        # Not authenticated - check if this is an API request or browser
        if request.is_json or request.headers.get("Accept") == "application/json":
            return jsonify({"error": "Authentication required"}), 401

        # Redirect to login page
        return redirect(url_for("auth.login", next=request.url))

    return wrapper


@bp.route("/login", methods=["GET", "POST"])
def login() -> ResponseReturnValue:
    """Login page and authentication endpoint.

    GET: Display login form
    POST: Authenticate user via LDAP or local authentication

    Returns:
        Login page HTML or redirect on success
    """
    config = get_config()
    error = None
    info = None

    # Get safe redirect URL to prevent open redirect attacks
    next_url = get_safe_redirect_url("index")

    # Check if this is the first user (local auth only)
    user_storage = get_user_storage()
    is_first_user = not config.ldap.enabled and not user_storage.has_any_users()

    if is_first_user:
        info = "Welcome! Create your admin account by entering your desired username and password."

    if request.method == "POST":
        # Defense-in-depth: per-IP rate limiting (per Gunicorn worker)
        rate_limit_resp = _check_login_rate_limit()
        if rate_limit_resp is not None:
            return rate_limit_resp

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            _record_login_attempt()
            error = "Username and password are required"
        else:
            # Try LDAP authentication if enabled
            user: LDAPUser | LocalUser | None
            if config.ldap.enabled:
                try:
                    ldap_service = get_ldap_service()
                    user = ldap_service.authenticate(username, password)

                    if user:
                        # Create session
                        session.permanent = True  # Use PERMANENT_SESSION_LIFETIME
                        session["authenticated"] = True
                        session["username"] = user.username
                        session["display_name"] = user.display_name or user.username
                        session["email"] = user.email
                        session["is_admin"] = user.is_admin  # Based on LDAP admin groups
                        session["auth_method"] = "ldap"
                        session["login_time"] = datetime.now(UTC).isoformat()

                        logger.info(
                            "LDAP user %s logged in (admin=%s, groups=%s)",
                            user.username,
                            user.is_admin,
                            user.groups,
                        )

                        # Set JWT cookies for API access
                        response = make_response(redirect(next_url))
                        access_token = create_access_token(
                            identity=user.username,
                            additional_claims={
                                "display_name": user.display_name,
                                "email": user.email,
                                "is_admin": user.is_admin,
                            },
                        )
                        refresh_token = create_refresh_token(identity=user.username)
                        set_access_cookies(response, access_token)
                        set_refresh_cookies(response, refresh_token)

                        _reset_login_attempts()
                        return response
                    _record_login_attempt()
                    error = "Invalid username or password"

                except LDAPAuthenticationError as e:
                    _record_login_attempt()
                    # Log the actual error for debugging, show generic message to user
                    logger.error("LDAP authentication error: %s", e)
                    error = "Authentication failed. Please try again."
            else:
                # LDAP not enabled - use local authentication
                # Check if this is the first user (auto-create admin)
                if not user_storage.has_any_users():
                    user = user_storage.create_first_user(username, password)
                    if user:
                        logger.info("First user '%s' created as admin", username)
                        # Auto-login the first user
                        session.permanent = True  # Use PERMANENT_SESSION_LIFETIME
                        session["authenticated"] = True
                        session["username"] = user.username
                        session["display_name"] = user.display_name or user.username
                        session["email"] = user.email
                        session["is_admin"] = True
                        session["auth_method"] = "local"
                        session["login_time"] = datetime.now(UTC).isoformat()

                        response = make_response(redirect(next_url))
                        access_token = create_access_token(
                            identity=user.username,
                            additional_claims={
                                "is_admin": True,
                            },
                        )
                        refresh_token = create_refresh_token(identity=user.username)
                        set_access_cookies(response, access_token)
                        set_refresh_cookies(response, refresh_token)

                        _reset_login_attempts()
                        return response
                    _record_login_attempt()
                    error = "Failed to create admin account. Please try again."
                else:
                    # Authenticate against local database
                    user = user_storage.authenticate(username, password)
                    if user and isinstance(user, LocalUser):
                        # Check if user must change password
                        if user.must_change_password:
                            session["pending_password_change"] = True
                            session["pending_username"] = username
                            return redirect(url_for("auth.change_password_required"))

                        # Create session
                        session.permanent = True  # Use PERMANENT_SESSION_LIFETIME
                        session["authenticated"] = True
                        session["username"] = user.username
                        session["display_name"] = user.display_name or user.username
                        session["email"] = user.email
                        session["is_admin"] = user.is_admin
                        session["auth_method"] = "local"
                        session["login_time"] = datetime.now(UTC).isoformat()

                        # Set JWT cookies for API access
                        response = make_response(redirect(next_url))
                        access_token = create_access_token(
                            identity=user.username,
                            additional_claims={
                                "is_admin": user.is_admin,
                            },
                        )
                        refresh_token = create_refresh_token(identity=user.username)
                        set_access_cookies(response, access_token)
                        set_refresh_cookies(response, refresh_token)

                        _reset_login_attempts()
                        return response
                    _record_login_attempt()
                    error = "Invalid username or password"

    return render_template(
        "login.html",
        error=error,
        info=info,
        next_url=next_url,
        ldap_enabled=config.ldap.enabled,
        is_first_user=is_first_user,
    )


@bp.route("/logout")
def logout() -> ResponseReturnValue:
    """Logout endpoint - clears session and JWT cookies.

    Returns:
        Redirect to login page
    """
    # Clear session
    session.clear()

    # Clear JWT cookies
    response = make_response(redirect(url_for("auth.login")))
    unset_jwt_cookies(response)

    return response


@bp.route("/refresh", methods=["POST"])
@jwt_required(refresh=True)
def refresh() -> ResponseReturnValue:
    """Refresh access token using refresh token.

    Returns:
        New access token in JSON response
    """
    identity = get_jwt_identity()
    if not identity:
        return jsonify({"error": "Invalid identity"}), 401
    access_token = create_access_token(identity=identity)

    if request.is_json:
        return jsonify({"access_token": access_token})

    # For cookie-based auth, set the new cookie
    response = make_response(jsonify({"message": "Token refreshed"}))
    set_access_cookies(response, access_token)
    return response


@bp.route("/tokens", methods=["GET"])
@auth_required
def list_tokens() -> ResponseReturnValue:
    """List user's stored API tokens.

    Returns:
        HTML page or JSON list of tokens
    """
    identity = get_current_user()
    if not identity:
        return jsonify({"error": "Authentication required"}), 401
    session_username = session.get("username")
    logger.info(
        "Listing tokens - get_current_user(): '%s', session username: '%s'",
        identity,
        session_username,
    )

    token_storage = get_token_storage()
    # Include revoked tokens so users can manage (delete) them
    tokens = token_storage.list_tokens(identity, include_revoked=True)
    logger.info("Found %d tokens for user '%s'", len(tokens), identity)

    if request.is_json or validate_format(request.args.get("format")) == "json":
        return jsonify(
            {
                "tokens": tokens,
                "current_user": identity,
                "session_user": session_username,
            }
        )

    return render_template("tokens.html", tokens=tokens, username=identity)


@bp.route("/tokens/create", methods=["GET", "POST"])
@auth_required
def create_token() -> ResponseReturnValue:
    """Create a new API token.

    GET: Display token creation form
    POST: Create new token and display it

    Returns:
        HTML page with form or created token
    """
    identity = get_current_user()
    if not identity:
        return jsonify({"error": "Authentication required"}), 401
    config = get_config()
    error = None
    created_token = None

    if request.method == "POST":
        token_name = request.form.get("token_name", "").strip()
        description = request.form.get("description", "").strip()
        expires_days = request.form.get("expires_days", type=int)

        if not token_name:
            error = "Token name is required"
        elif len(token_name) > 255:
            error = "Token name must be 255 characters or less"
        elif len(description) > MAX_TOKEN_DESCRIPTION_LENGTH:
            error = f"Description must be {MAX_TOKEN_DESCRIPTION_LENGTH} characters or less"
        elif expires_days is not None and (expires_days < 1 or expires_days > MAX_EXPIRES_DAYS):
            error = f"Expiration must be between 1 and {MAX_EXPIRES_DAYS} days"
        else:
            # Calculate expiration (use naive datetime for SQLite compatibility)
            expires_at = None
            if expires_days:
                expires_at = (datetime.now(UTC) + timedelta(days=expires_days)).replace(tzinfo=None)

            # Create the JWT token
            additional_claims = {
                "type": "api_token",
                "token_name": token_name,
            }
            access_token = create_access_token(
                identity=identity,
                expires_delta=timedelta(days=expires_days) if expires_days else False,
                additional_claims=additional_claims,
            )

            # Store the token
            token_storage = get_token_storage()
            try:
                token_storage.store_token(
                    username=identity,
                    token=access_token,
                    token_name=token_name,
                    expires_at=expires_at,
                    description=description or None,
                )
                created_token = access_token
            except Exception as e:  # pylint: disable=broad-exception-caught
                # Log the actual error for debugging, show generic message to user
                logger.error("Failed to store token: %s", e)
                error = "Failed to create token. Please try again."

    if request.is_json:
        if error:
            return jsonify({"error": error}), 400
        if created_token:
            return jsonify({"token": created_token, "message": "Token created successfully"})
        return jsonify({"error": "Invalid request"}), 400

    return render_template(
        "create_token.html",
        error=error,
        created_token=created_token,
        username=identity,
        default_expires_days=config.jwt.refresh_token_expires.days,
    )


@bp.route("/tokens/<int:token_id>", methods=["GET"])
@auth_required
def get_token(token_id: int) -> ResponseReturnValue:
    """Get a specific token's details (including the token value).

    Args:
        token_id: The token ID

    Returns:
        JSON with token details
    """
    identity = get_current_user()
    if not identity:
        return jsonify({"error": "Authentication required"}), 401
    token_storage = get_token_storage()
    token = token_storage.get_token(token_id, identity)

    if not token:
        return jsonify({"error": "Token not found"}), 404

    return jsonify(token)


@bp.route("/tokens/<int:token_id>/revoke", methods=["POST"])
@auth_required
def revoke_token(token_id: int) -> ResponseReturnValue:
    """Revoke a stored token.

    Args:
        token_id: The token ID to revoke

    Returns:
        JSON response indicating success or failure
    """
    identity = get_current_user()
    if not identity:
        return jsonify({"error": "Authentication required"}), 401
    token_storage = get_token_storage()

    if token_storage.revoke_token(token_id, identity):
        if request.is_json:
            return jsonify({"message": "Token revoked successfully"})
        return redirect(url_for("auth.list_tokens"))

    return jsonify({"error": "Token not found or already revoked"}), 404


@bp.route("/tokens/<int:token_id>/delete", methods=["POST"])
@auth_required
def delete_token(token_id: int) -> ResponseReturnValue:
    """Permanently delete a stored token.

    Args:
        token_id: The token ID to delete

    Returns:
        JSON response indicating success or failure
    """
    identity = get_current_user()
    if not identity:
        return jsonify({"error": "Authentication required"}), 401
    token_storage = get_token_storage()

    if token_storage.delete_token(token_id, identity):
        if request.is_json:
            return jsonify({"message": "Token deleted successfully"})
        return redirect(url_for("auth.list_tokens"))

    return jsonify({"error": "Token not found"}), 404


@bp.route("/tokens/debug", methods=["GET"])
@auth_required
def debug_tokens() -> ResponseReturnValue:
    """Debug endpoint to check token storage state.

    Returns:
        JSON with debug information about tokens
    """
    from sbom_graph_api.services.token_storage import StoredToken

    identity = get_current_user()
    if not identity:
        return jsonify({"error": "Authentication required"}), 401
    session_username = session.get("username")
    token_storage = get_token_storage()

    # Get raw database access
    db_session = token_storage._get_session()  # pylint: disable=protected-access
    all_tokens = db_session.query(StoredToken).all()

    debug_info = {
        "current_user_from_get_current_user": identity,
        "session_username": session_username,
        "session_authenticated": session.get("authenticated"),
        "total_tokens_in_db": len(all_tokens),
        "all_tokens": [
            {
                "id": t.id,
                "username": t.username,
                "token_name": t.token_name,
                "is_revoked": t.is_revoked,  # type: ignore[reportGeneralTypeIssues]
                "created_at": (
                    t.created_at.isoformat()  # type: ignore[reportGeneralTypeIssues]
                    if t.created_at
                    else None
                ),
            }
            for t in all_tokens
        ],
        "tokens_for_current_user": [
            t.token_name  # type: ignore[reportGeneralTypeIssues]
            for t in all_tokens
            if t.username == identity
        ],
    }

    db_session.close()
    return jsonify(debug_info)


@bp.route("/status")
def auth_status() -> ResponseReturnValue:
    """Get current authentication status.

    Returns:
        JSON with authentication status
    """
    config = get_config()

    status: dict[str, Any] = {
        "auth_enabled": config.auth_enabled,
        "ldap_enabled": config.ldap.enabled,
        "authenticated": False,
        "username": None,
    }

    # Check JWT
    try:
        verify_jwt_in_request(optional=True)
        identity = get_jwt_identity()
        if identity:
            status["authenticated"] = True
            status["username"] = identity
            status["auth_method"] = "jwt"
    except Exception as e:  # pylint: disable=broad-exception-caught
        # JWT not present or invalid - will check session next
        logger.debug("JWT check failed in auth_status: %s", e)

    # Check session
    if not status["authenticated"] and session.get("authenticated"):
        status["authenticated"] = True
        status["username"] = session.get("username")
        status["auth_method"] = "session"
        status["is_admin"] = session.get("is_admin", False)

    return jsonify(status)


# ============================================================================
# Password Change Routes
# ============================================================================


@bp.route("/change-password-required", methods=["GET", "POST"])
def change_password_required() -> ResponseReturnValue:
    """Force password change for users with temporary passwords.

    This page is shown after login when must_change_password is True.
    """
    # Check if user has pending password change
    if not session.get("pending_password_change"):
        return redirect(url_for("auth.login"))

    username = session.get("pending_username")
    if not username:
        return redirect(url_for("auth.login"))

    error = None

    if request.method == "POST":
        current_password = request.form.get("current_password", "")
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not current_password or not new_password or not confirm_password:
            error = "All fields are required"
        elif new_password != confirm_password:
            error = "New passwords do not match"
        elif len(new_password) < 8:
            error = "Password must be at least 8 characters"
        elif new_password == current_password:
            error = "New password must be different from current password"
        else:
            user_storage = get_user_storage()
            if user_storage.change_password(username, current_password, new_password):
                # Clear pending state and log user in
                session.pop("pending_password_change", None)
                session.pop("pending_username", None)

                # Get updated user and create session
                user = user_storage.get_user_by_username(username)
                if user:
                    session.permanent = True  # Use PERMANENT_SESSION_LIFETIME
                    session["authenticated"] = True
                    session["username"] = user.username
                    session["display_name"] = user.display_name or user.username
                    session["email"] = user.email
                    session["is_admin"] = user.is_admin
                    session["auth_method"] = "local"
                    session["login_time"] = datetime.now(UTC).isoformat()

                    response = make_response(redirect(url_for("index")))
                    access_token = create_access_token(
                        identity=user.username,
                        additional_claims={"is_admin": user.is_admin},
                    )
                    refresh_token = create_refresh_token(identity=user.username)
                    set_access_cookies(response, access_token)
                    set_refresh_cookies(response, refresh_token)

                    return response

                return redirect(url_for("auth.login"))
            error = "Current password is incorrect"

    return render_template(
        "change_password_required.html",
        username=username,
        error=error,
    )


@bp.route("/change-password", methods=["GET", "POST"])
@auth_required
def change_password() -> ResponseReturnValue:
    """Allow authenticated users to change their password."""
    config = get_config()

    # Only available for local auth users
    if config.ldap.enabled or session.get("auth_method") == "ldap":
        return render_template(
            "error.html",
            error="Not Available",
            message="Password changes are managed by your LDAP administrator.",
        ), 400

    username = session.get("username")
    if not username:
        return jsonify({"error": "Authentication required"}), 401
    error = None
    success = None

    if request.method == "POST":
        current_password = request.form.get("current_password", "")
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not current_password or not new_password or not confirm_password:
            error = "All fields are required"
        elif new_password != confirm_password:
            error = "New passwords do not match"
        elif len(new_password) < 8:
            error = "Password must be at least 8 characters"
        elif new_password == current_password:
            error = "New password must be different from current password"
        else:
            user_storage = get_user_storage()
            if user_storage.change_password(username, current_password, new_password):
                success = "Password changed successfully"
            else:
                error = "Current password is incorrect"

    return render_template(
        "change_password.html",
        username=username,
        error=error,
        success=success,
    )


# ============================================================================
# Admin User Management Routes
# ============================================================================


@bp.route("/admin/users")
@admin_required
def admin_users() -> ResponseReturnValue:
    """Admin page for managing users."""
    config = get_config()

    # Only available when LDAP is disabled
    if config.ldap.enabled:
        return render_template(
            "error.html",
            error="Not Available",
            message="User management is not available when LDAP is enabled.",
        ), 400

    user_storage = get_user_storage()
    users = user_storage.list_users()

    return render_template(
        "admin_users.html",
        users=users,
        current_user=session.get("username"),
    )


@bp.route("/admin/users/create", methods=["GET", "POST"])
@admin_required
def admin_create_user() -> ResponseReturnValue:
    """Admin page to create a new user."""
    config = get_config()

    if config.ldap.enabled:
        return render_template(
            "error.html",
            error="Not Available",
            message="User management is not available when LDAP is enabled.",
        ), 400

    error = None
    temp_password = None

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip() or None
        display_name = request.form.get("display_name", "").strip() or None
        is_admin = request.form.get("is_admin") == "true"

        if not username:
            error = "Username is required"
        elif not validate_username(username):
            error = "Invalid username format"
        else:
            try:
                user_storage = get_user_storage()
                user, temp_password = user_storage.create_user(
                    username=username,
                    email=email,
                    display_name=display_name,
                    is_admin=is_admin,
                    must_change_password=True,
                    created_by=session.get("username"),
                )
                if user and temp_password:
                    return render_template(
                        "admin_user_created.html",
                        user=user,
                        temp_password=temp_password,
                    )
                error = "Failed to create user"
            except Exception as e:  # pylint: disable=broad-exception-caught
                logger.error("Failed to create user: %s", e)
                if "already exists" in str(e):
                    error = "Username already exists"
                else:
                    error = "Failed to create user"

    return render_template(
        "admin_create_user.html",
        error=error,
    )


@bp.route("/admin/users/<username>/toggle-admin", methods=["POST"])
@admin_required
def admin_toggle_admin(  # pylint: disable=too-many-return-statements
    username: str,
) -> ResponseReturnValue:
    """Toggle admin status for a user."""
    if not validate_username(username):
        if request.is_json:
            return jsonify({"error": "Invalid username"}), 400
        return redirect(url_for("auth.admin_users"))

    config = get_config()

    if config.ldap.enabled:
        return jsonify({"error": "Not available with LDAP"}), 400

    # Prevent removing own admin status
    admin_username = get_current_user()
    if not admin_username:
        if request.is_json:
            return jsonify({"error": "Authentication required"}), 401
        return redirect(url_for("auth.login"))
    if username == admin_username:
        if request.is_json:
            return jsonify({"error": "Cannot change your own admin status"}), 400
        return redirect(url_for("auth.admin_users"))

    user_storage = get_user_storage()
    user = user_storage.get_user_by_username(username)

    if not user:
        if request.is_json:
            return jsonify({"error": "User not found"}), 404
        return redirect(url_for("auth.admin_users"))

    new_admin_status = not user.is_admin
    if user_storage.set_admin(username, new_admin_status, admin_username):
        if request.is_json:
            return jsonify({"message": "Admin status updated", "is_admin": new_admin_status})
        return redirect(url_for("auth.admin_users"))

    if request.is_json:
        return jsonify({"error": "Failed to update admin status"}), 500
    return redirect(url_for("auth.admin_users"))


@bp.route("/admin/users/<username>/toggle-active", methods=["POST"])
@admin_required
def admin_toggle_active(  # pylint: disable=too-many-return-statements
    username: str,
) -> ResponseReturnValue:
    """Toggle active status for a user."""
    if not validate_username(username):
        if request.is_json:
            return jsonify({"error": "Invalid username"}), 400
        return redirect(url_for("auth.admin_users"))

    config = get_config()

    if config.ldap.enabled:
        return jsonify({"error": "Not available with LDAP"}), 400

    # Prevent disabling own account
    admin_username = get_current_user()
    if not admin_username:
        if request.is_json:
            return jsonify({"error": "Authentication required"}), 401
        return redirect(url_for("auth.login"))
    if username == admin_username:
        if request.is_json:
            return jsonify({"error": "Cannot disable your own account"}), 400
        return redirect(url_for("auth.admin_users"))

    user_storage = get_user_storage()
    user = user_storage.get_user_by_username(username)

    if not user:
        if request.is_json:
            return jsonify({"error": "User not found"}), 404
        return redirect(url_for("auth.admin_users"))

    new_active_status = not user.is_active
    if user_storage.set_active(username, new_active_status, admin_username):
        if request.is_json:
            return jsonify({"message": "Active status updated", "is_active": new_active_status})
        return redirect(url_for("auth.admin_users"))

    if request.is_json:
        return jsonify({"error": "Failed to update active status"}), 500
    return redirect(url_for("auth.admin_users"))


@bp.route("/admin/users/<username>/reset-password", methods=["POST"])
@admin_required
def admin_reset_password(username: str) -> ResponseReturnValue:
    """Reset a user's password (admin action)."""
    if not validate_username(username):
        if request.is_json:
            return jsonify({"error": "Invalid username"}), 400
        return redirect(url_for("auth.admin_users"))

    config = get_config()

    if config.ldap.enabled:
        return jsonify({"error": "Not available with LDAP"}), 400

    admin_username = get_current_user()
    if not admin_username:
        if request.is_json:
            return jsonify({"error": "Authentication required"}), 401
        return redirect(url_for("auth.login"))

    user_storage = get_user_storage()
    temp_password = user_storage.reset_password(username, admin_username)

    if temp_password:
        if request.is_json:
            return jsonify({"message": "Password reset", "temp_password": temp_password})
        return render_template(
            "admin_password_reset.html",
            username=username,
            temp_password=temp_password,
        )

    if request.is_json:
        return jsonify({"error": "Failed to reset password"}), 500
    return redirect(url_for("auth.admin_users"))


@bp.route("/admin/users/<username>/delete", methods=["POST"])
@admin_required
def admin_delete_user(username: str) -> ResponseReturnValue:
    """Delete a user account."""
    if not validate_username(username):
        if request.is_json:
            return jsonify({"error": "Invalid username"}), 400
        return redirect(url_for("auth.admin_users"))

    config = get_config()

    if config.ldap.enabled:
        return jsonify({"error": "Not available with LDAP"}), 400

    # Prevent deleting own account
    admin_username = get_current_user()
    if not admin_username:
        if request.is_json:
            return jsonify({"error": "Authentication required"}), 401
        return redirect(url_for("auth.login"))
    if username == admin_username:
        if request.is_json:
            return jsonify({"error": "Cannot delete your own account"}), 400
        return redirect(url_for("auth.admin_users"))

    user_storage = get_user_storage()
    if user_storage.delete_user(username, admin_username):
        if request.is_json:
            return jsonify({"message": "User deleted"})
        return redirect(url_for("auth.admin_users"))

    if request.is_json:
        return jsonify({"error": "Failed to delete user"}), 500
    return redirect(url_for("auth.admin_users"))
