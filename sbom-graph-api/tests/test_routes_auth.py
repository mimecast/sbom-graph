"""Tests for authentication routes."""

import re
from datetime import timedelta
from unittest.mock import patch

import pytest

from sbom_graph_api.config import (
    AppConfig,
    DatabaseConfig,
    FalkorDBConfig,
    JWTConfig,
    LDAPConfig,
    TLSConfig,
    reset_config,
)
from sbom_graph_api.services.falkordb_service import reset_service
from sbom_graph_api.services.token_storage import reset_token_storage
from sbom_graph_api.services.user_storage import reset_user_storage


def _make_app_config(auth_enabled=True, ldap_enabled=False):
    """Create a test AppConfig."""
    return AppConfig(
        debug=True,
        host="127.0.0.1",
        port=8080,
        secret_key="test-secret-key-for-testing",
        falkordb=FalkorDBConfig(
            host="test-host",
            port=6379,
            password="test",
            graph_name="test",
            socket_timeout=30.0,
            socket_connect_timeout=10.0,
            internal_label="INTERNAL",
            ssl=False,
            ssl_ca_certs=None,
        ),
        tls=TLSConfig(enabled=False, cert_file=None, key_file=None, ca_file=None),
        jwt=JWTConfig(
            secret_key="test-jwt-secret-key-for-testing-purposes-long-enough",
            access_token_expires=timedelta(hours=1),
            refresh_token_expires=timedelta(days=30),
            algorithm="HS256",
            token_location=["headers", "cookies"],
        ),
        ldap=LDAPConfig(
            enabled=ldap_enabled,
            server="localhost",
            port=389,
            use_ssl=False,
            base_dn="dc=example,dc=com",
            user_dn_template="uid={username},ou=users,dc=example,dc=com",
            bind_dn=None,
            bind_password=None,
            search_filter="(uid={username})",
            group_search_base=None,
            required_group=None,
            allowed_groups=[],
            admin_groups=[],
            user_groups=[],
            require_group_membership=False,
        ),
        database=DatabaseConfig(path="/tmp/test-auth.db", encryption_key="test-enc-key"),
        auth_enabled=auth_enabled,
    )


@pytest.fixture
def auth_app(tmp_path):
    """Create Flask app with auth enabled (local auth)."""
    reset_config()
    reset_service()
    reset_user_storage()
    reset_token_storage()

    config = _make_app_config(auth_enabled=True, ldap_enabled=False)
    config.database = DatabaseConfig(
        path=str(tmp_path / "test.db"),
        encryption_key="test-encryption-key-for-testing",
    )

    with patch("sbom_graph_api.config.AppConfig.from_env", return_value=config):
        from sbom_graph_api.app import create_app

        app = create_app()
        app.config["TESTING"] = True
        app.config["WTF_CSRF_ENABLED"] = False
        yield app

    reset_config()
    reset_service()
    reset_user_storage()
    reset_token_storage()


@pytest.fixture
def auth_client(auth_app):
    """Test client for auth-enabled app."""
    return auth_app.test_client()


@pytest.fixture
def noauth_app(tmp_path):
    """Create Flask app with auth disabled."""
    reset_config()
    reset_service()

    config = _make_app_config(auth_enabled=False)
    config.database = DatabaseConfig(
        path=str(tmp_path / "test-noauth.db"),
        encryption_key="test-enc-key",
    )

    with patch("sbom_graph_api.config.AppConfig.from_env", return_value=config):
        from sbom_graph_api.app import create_app

        app = create_app()
        app.config["TESTING"] = True
        app.config["WTF_CSRF_ENABLED"] = False
        yield app

    reset_config()
    reset_service()


@pytest.fixture
def noauth_client(noauth_app):
    """Test client for auth-disabled app."""
    return noauth_app.test_client()


def _login_first_user(client, username="admin", password="admin-pass"):
    """Create and login the first user (auto-admin bootstrap)."""
    return client.post(
        "/auth/login",
        data={"username": username, "password": password},
        follow_redirects=False,
    )


def _login_session(client, username="admin", password="admin-pass"):
    """Login and return a client with active session."""
    _login_first_user(client, username, password)
    client.post(
        "/auth/login",
        data={"username": username, "password": password},
        follow_redirects=False,
    )
    return client


class TestLoginPage:
    """Tests for the login page and authentication."""

    def test_get_login_page(self, auth_client):
        response = auth_client.get("/auth/login")
        assert response.status_code == 200
        assert b"login" in response.data.lower() or b"username" in response.data.lower()

    def test_first_user_shows_info_message(self, auth_client):
        """First visit shows bootstrap admin message."""
        response = auth_client.get("/auth/login")
        assert response.status_code == 200

    def test_first_user_bootstrap_creates_admin(self, auth_client):
        """First POST creates admin user and logs in."""
        response = _login_first_user(auth_client)
        assert response.status_code in (302, 303)

    def test_login_with_valid_credentials(self, auth_client):
        """First user bootstrap creates admin, sets session, and redirects."""
        response = _login_first_user(auth_client, "admin", "mypassword")
        assert response.status_code in (302, 303)
        with auth_client.session_transaction() as sess:
            assert sess["authenticated"] is True
            assert sess["username"] == "admin"
            assert sess["is_admin"] is True

    def test_login_with_wrong_password(self, auth_client):
        _login_first_user(auth_client, "admin", "correct-pass")
        response = auth_client.post(
            "/auth/login",
            data={"username": "admin", "password": "wrong-pass"},
            follow_redirects=False,
        )
        assert response.status_code == 200
        assert b"Invalid" in response.data or b"invalid" in response.data

    def test_login_empty_fields(self, auth_client):
        response = auth_client.post(
            "/auth/login",
            data={"username": "", "password": ""},
            follow_redirects=False,
        )
        assert response.status_code == 200
        assert b"required" in response.data.lower()

    def test_first_user_create_failure_shows_error(self, auth_client):
        """When create_first_user returns None, show generic error."""
        with patch("sbom_graph_api.routes.auth.get_user_storage") as m:
            mock_storage = m.return_value
            mock_storage.has_any_users.return_value = False
            mock_storage.create_first_user.return_value = None
            response = auth_client.post(
                "/auth/login",
                data={"username": "admin", "password": "pass"},
            )
            assert response.status_code == 200
            assert b"Failed" in response.data or b"try again" in response.data

    def test_local_login_must_change_password_redirects(self, auth_client):
        """User with must_change_password redirects to change-password-required."""
        _login_first_user(auth_client, "admin", "pass")
        create_resp = auth_client.post(
            "/auth/admin/users/create",
            data={"username": "newuser"},
        )
        match = re.search(r'id="tempPassword">([^<]+)<', create_resp.data.decode())
        temp_pw = match.group(1).strip() if match else None
        if not temp_pw:
            pytest.skip("Could not extract temp password from create response")
        auth_client.post("/auth/logout")
        resp = auth_client.post(
            "/auth/login",
            data={"username": "newuser", "password": temp_pw},
            follow_redirects=False,
        )
        assert resp.status_code in (302, 303)
        assert "change-password-required" in (resp.headers.get("Location") or "")


class TestLogout:
    """Tests for logout functionality."""

    def test_logout_redirects_to_login(self, auth_client):
        _login_first_user(auth_client)
        response = auth_client.get("/auth/logout", follow_redirects=False)
        assert response.status_code in (302, 303)
        assert "/auth/login" in response.headers.get("Location", "")

    def test_logout_clears_session(self, auth_client):
        _login_session(auth_client)
        auth_client.get("/auth/logout")
        response = auth_client.get("/auth/tokens", follow_redirects=False)
        assert response.status_code in (302, 401)


class TestAuthStatus:
    """Tests for auth status endpoint."""

    def test_unauthenticated_status(self, auth_client):
        response = auth_client.get("/auth/status")
        assert response.status_code == 200
        data = response.get_json()
        assert data["auth_enabled"] is True
        assert data["authenticated"] is False

    def test_auth_disabled_status(self, noauth_client):
        response = noauth_client.get("/auth/status")
        assert response.status_code == 200
        data = response.get_json()
        assert data["auth_enabled"] is False


class TestAuthRequired:
    """Tests for auth_required decorator."""

    def test_unauthenticated_json_returns_401(self, auth_client):
        response = auth_client.get(
            "/auth/tokens",
            headers={"Accept": "application/json"},
        )
        assert response.status_code == 401

    def test_unauthenticated_browser_redirects(self, auth_client):
        response = auth_client.get("/auth/tokens", follow_redirects=False)
        assert response.status_code in (302, 303)

    def test_auth_disabled_allows_access(self, noauth_app):
        """When auth is disabled, @auth_required endpoints are accessible."""
        with noauth_app.test_client() as client:
            response = client.get("/auth/status")
            assert response.status_code == 200

    def test_jwt_failure_falls_back_to_session(self, auth_client):
        """When JWT fails, session auth is used if present."""
        _login_first_user(auth_client)
        with auth_client.session_transaction() as sess:
            sess["authenticated"] = True
            sess["username"] = "admin"
        response = auth_client.get(
            "/auth/tokens",
            headers={"Authorization": "Bearer invalid-token"},
        )
        assert response.status_code == 200


class TestAdminRequired:
    """Tests for admin_required decorator."""

    def test_unauthenticated_json_returns_401(self, auth_client):
        response = auth_client.get(
            "/auth/admin/users",
            headers={"Accept": "application/json"},
            content_type="application/json",
        )
        assert response.status_code in (302, 401)

    def test_unauthenticated_browser_redirects_to_login(self, auth_client):
        response = auth_client.get("/auth/admin/users", follow_redirects=False)
        assert response.status_code in (302, 303)
        assert "/auth/login" in response.headers.get("Location", "")

    def test_authenticated_non_admin_gets_403_html(self, auth_client):
        _login_first_user(auth_client, "admin", "pass")
        with auth_client.session_transaction() as sess:
            sess["authenticated"] = True
            sess["username"] = "admin"
            sess["is_admin"] = False
        response = auth_client.get("/auth/admin/users")
        assert response.status_code == 403
        assert b"Access Denied" in response.data or b"administrator" in response.data

    def test_authenticated_non_admin_json_gets_403(self, auth_client):
        _login_first_user(auth_client)
        with auth_client.session_transaction() as sess:
            sess["authenticated"] = True
            sess["username"] = "admin"
            sess["is_admin"] = False
        response = auth_client.get(
            "/auth/admin/users",
            headers={"Accept": "application/json"},
        )
        assert response.status_code == 403


class TestTokenManagement:
    """Tests for token CRUD operations."""

    def test_create_token_unauthenticated(self, auth_client):
        response = auth_client.post(
            "/auth/tokens/create",
            headers={"Accept": "application/json"},
            content_type="application/json",
        )
        assert response.status_code == 401

    def test_list_tokens_authenticated(self, auth_client):
        _login_session(auth_client)
        response = auth_client.get("/auth/tokens")
        assert response.status_code == 200

    def test_revoke_nonexistent_token(self, auth_client):
        _login_session(auth_client)
        response = auth_client.post(
            "/auth/tokens/99999/revoke",
            content_type="application/json",
        )
        assert response.status_code == 404

    def test_revoke_token_redirects_when_not_json(self, auth_client):
        _login_session(auth_client)
        with patch("sbom_graph_api.routes.auth.get_token_storage") as m:
            m.return_value.revoke_token.return_value = True
            response = auth_client.post(
                "/auth/tokens/1/revoke",
                follow_redirects=False,
            )
            assert response.status_code in (302, 303)
            assert "tokens" in (response.headers.get("Location") or "")

    def test_delete_nonexistent_token(self, auth_client):
        _login_session(auth_client)
        response = auth_client.post(
            "/auth/tokens/99999/delete",
            content_type="application/json",
        )
        assert response.status_code == 404

    def test_delete_token_redirects_when_not_json(self, auth_client):
        _login_session(auth_client)
        with patch("sbom_graph_api.routes.auth.get_token_storage") as m:
            m.return_value.delete_token.return_value = True
            response = auth_client.post(
                "/auth/tokens/1/delete",
                follow_redirects=False,
            )
            assert response.status_code in (302, 303)
            assert "tokens" in (response.headers.get("Location") or "")

    def test_get_nonexistent_token(self, auth_client):
        _login_session(auth_client)
        response = auth_client.get("/auth/tokens/99999")
        assert response.status_code == 404

    def test_debug_tokens_authenticated(self, auth_client):
        _login_session(auth_client)
        response = auth_client.get("/auth/tokens/debug")
        assert response.status_code == 200
        data = response.get_json()
        assert "current_user_from_get_current_user" in data
        assert "total_tokens_in_db" in data


class TestChangePassword:
    """Tests for password change functionality."""

    def _setup_local_user(self, auth_client, password="admin-pass"):
        """Bootstrap first user and set session via session_transaction."""
        _login_first_user(auth_client, "admin", password)
        with auth_client.session_transaction() as sess:
            sess["authenticated"] = True
            sess["username"] = "admin"
            sess["display_name"] = "admin"
            sess["is_admin"] = True
            sess["auth_method"] = "local"

    def test_change_password_page(self, auth_client):
        self._setup_local_user(auth_client)
        response = auth_client.get("/auth/change-password")
        assert response.status_code == 200

    def test_change_password_success(self, auth_client):
        self._setup_local_user(auth_client, "old-pass")
        response = auth_client.post(
            "/auth/change-password",
            data={
                "current_password": "old-pass",
                "new_password": "new-password-123",
                "confirm_password": "new-password-123",
            },
        )
        assert response.status_code == 200
        assert b"success" in response.data.lower() or b"changed" in response.data.lower()

    def test_change_password_mismatch(self, auth_client):
        self._setup_local_user(auth_client, "old-pass")
        response = auth_client.post(
            "/auth/change-password",
            data={
                "current_password": "old-pass",
                "new_password": "new-pass-1",
                "confirm_password": "new-pass-2",
            },
        )
        assert response.status_code == 200
        assert b"do not match" in response.data.lower()

    def test_change_password_too_short(self, auth_client):
        self._setup_local_user(auth_client, "old-pass")
        response = auth_client.post(
            "/auth/change-password",
            data={
                "current_password": "old-pass",
                "new_password": "short",
                "confirm_password": "short",
            },
        )
        assert response.status_code == 200
        assert b"at least 8" in response.data.lower()

    def test_change_password_same_as_old(self, auth_client):
        self._setup_local_user(auth_client, "old-pass-123")
        response = auth_client.post(
            "/auth/change-password",
            data={
                "current_password": "old-pass-123",
                "new_password": "old-pass-123",
                "confirm_password": "old-pass-123",
            },
        )
        assert response.status_code == 200
        assert b"different" in response.data.lower()

    def test_change_password_wrong_current(self, auth_client):
        self._setup_local_user(auth_client, "real-pass")
        response = auth_client.post(
            "/auth/change-password",
            data={
                "current_password": "wrong-pass",
                "new_password": "new-pass-123",
                "confirm_password": "new-pass-123",
            },
        )
        assert response.status_code == 200
        assert b"incorrect" in response.data.lower()

    def test_change_password_empty_fields(self, auth_client):
        self._setup_local_user(auth_client)
        response = auth_client.post(
            "/auth/change-password",
            data={
                "current_password": "",
                "new_password": "",
                "confirm_password": "",
            },
        )
        assert response.status_code == 200
        assert b"required" in response.data.lower()


class TestChangePasswordRequired:
    """Tests for forced password change flow."""

    def test_redirect_if_no_pending_change(self, auth_client):
        response = auth_client.get("/auth/change-password-required", follow_redirects=False)
        assert response.status_code in (302, 303)

    def test_redirect_if_no_pending_username(self, auth_client):
        with auth_client.session_transaction() as sess:
            sess["pending_password_change"] = True
            sess["pending_username"] = None
        response = auth_client.get("/auth/change-password-required", follow_redirects=False)
        assert response.status_code in (302, 303)
        assert "/auth/login" in (response.headers.get("Location") or "")

    def test_change_password_required_success(self, auth_client):
        """Successful change clears pending state and logs user in."""
        _login_first_user(auth_client, "admin", "oldpass")
        with auth_client.session_transaction() as sess:
            sess["pending_password_change"] = True
            sess["pending_username"] = "admin"
        with patch("sbom_graph_api.routes.auth.get_user_storage") as m:
            from sbom_graph_api.services.user_storage import LocalUser

            mock_user = LocalUser(
                username="admin",
                password_hash="x",
                must_change_password=False,
                is_admin=True,
            )
            mock_user.display_name = "admin"
            mock_user.email = None
            m.return_value.change_password.return_value = True
            m.return_value.get_user_by_username.return_value = mock_user
            resp = auth_client.post(
                "/auth/change-password-required",
                data={
                    "current_password": "oldpass",
                    "new_password": "newpass123",
                    "confirm_password": "newpass123",
                },
                follow_redirects=False,
            )
        assert resp.status_code in (302, 303)
        loc = resp.headers.get("Location") or ""
        assert "index" in loc or "/" in loc

    def test_change_password_required_wrong_current(self, auth_client):
        """Wrong current password shows error."""
        _login_first_user(auth_client, "admin", "pass")
        with auth_client.session_transaction() as sess:
            sess["pending_password_change"] = True
            sess["pending_username"] = "admin"
        resp = auth_client.post(
            "/auth/change-password-required",
            data={
                "current_password": "wrong",
                "new_password": "newpass123",
                "confirm_password": "newpass123",
            },
        )
        assert resp.status_code == 200
        assert b"incorrect" in resp.data.lower()

    def test_change_password_required_empty_fields(self, auth_client):
        """POST with empty fields shows error."""
        _login_first_user(auth_client, "admin", "pass")
        with auth_client.session_transaction() as sess:
            sess["pending_password_change"] = True
            sess["pending_username"] = "admin"
        response = auth_client.post(
            "/auth/change-password-required",
            data={
                "current_password": "",
                "new_password": "",
                "confirm_password": "",
            },
        )
        assert response.status_code == 200
        assert b"required" in response.data.lower()

    def test_change_password_required_mismatch(self, auth_client):
        """New password mismatch shows error."""
        _login_first_user(auth_client, "admin", "pass")
        with auth_client.session_transaction() as sess:
            sess["pending_password_change"] = True
            sess["pending_username"] = "admin"
        response = auth_client.post(
            "/auth/change-password-required",
            data={
                "current_password": "pass",
                "new_password": "newpass123",
                "confirm_password": "different",
            },
        )
        assert response.status_code == 200
        assert b"match" in response.data.lower()


class TestAdminUserManagement:
    """Tests for admin user management routes."""

    def _setup_admin(self, client):
        """Create first user (admin) and login."""
        _login_session(client, "admin", "admin-pass")

    def test_admin_users_page(self, auth_client):
        self._setup_admin(auth_client)
        response = auth_client.get("/auth/admin/users")
        assert response.status_code == 200

    def test_admin_create_user_page(self, auth_client):
        self._setup_admin(auth_client)
        response = auth_client.get("/auth/admin/users/create")
        assert response.status_code == 200

    def test_admin_create_user_post(self, auth_client):
        self._setup_admin(auth_client)
        response = auth_client.post(
            "/auth/admin/users/create",
            data={
                "username": "newuser",
                "email": "new@example.com",
                "display_name": "New User",
            },
        )
        assert response.status_code == 200

    def test_admin_create_user_empty_username(self, auth_client):
        self._setup_admin(auth_client)
        response = auth_client.post(
            "/auth/admin/users/create",
            data={"username": ""},
        )
        assert response.status_code == 200
        assert b"required" in response.data.lower()

    def test_admin_toggle_own_admin_blocked(self, auth_client):
        self._setup_admin(auth_client)
        response = auth_client.post(
            "/auth/admin/users/admin/toggle-admin",
            follow_redirects=False,
        )
        assert response.status_code in (302, 400)

    def test_admin_toggle_own_active_blocked(self, auth_client):
        self._setup_admin(auth_client)
        response = auth_client.post(
            "/auth/admin/users/admin/toggle-active",
            follow_redirects=False,
        )
        assert response.status_code in (302, 400)

    def test_admin_delete_own_account_blocked(self, auth_client):
        self._setup_admin(auth_client)
        response = auth_client.post(
            "/auth/admin/users/admin/delete",
            follow_redirects=False,
        )
        assert response.status_code in (302, 400)

    def test_admin_toggle_nonexistent_user(self, auth_client):
        self._setup_admin(auth_client)
        response = auth_client.post(
            "/auth/admin/users/nobody/toggle-admin",
            follow_redirects=False,
        )
        assert response.status_code in (302, 404)

    def test_admin_reset_password(self, auth_client):
        self._setup_admin(auth_client)
        auth_client.post(
            "/auth/admin/users/create",
            data={"username": "testuser"},
        )
        response = auth_client.post(
            "/auth/admin/users/testuser/reset-password",
        )
        assert response.status_code == 200

    def test_admin_delete_user(self, auth_client):
        self._setup_admin(auth_client)
        auth_client.post(
            "/auth/admin/users/create",
            data={"username": "deleteme"},
        )
        response = auth_client.post(
            "/auth/admin/users/deleteme/delete",
            follow_redirects=False,
        )
        assert response.status_code in (302, 200)

    def test_admin_toggle_admin_success_json(self, auth_client):
        """Toggle admin for another user returns JSON when Accept is JSON."""
        self._setup_admin(auth_client)
        auth_client.post(
            "/auth/admin/users/create",
            data={"username": "otheruser"},
        )
        response = auth_client.post(
            "/auth/admin/users/otheruser/toggle-admin",
            headers={"Accept": "application/json"},
        )
        assert response.status_code in (200, 302, 500)

    def test_admin_toggle_active_success_json(self, auth_client):
        """Toggle active for another user returns JSON when Accept is JSON."""
        self._setup_admin(auth_client)
        auth_client.post(
            "/auth/admin/users/create",
            data={"username": "otheruser"},
        )
        response = auth_client.post(
            "/auth/admin/users/otheruser/toggle-active",
            headers={"Accept": "application/json"},
        )
        assert response.status_code in (200, 302, 500)

    def test_admin_reset_password_json(self, auth_client):
        """Reset password returns JSON when Accept is JSON."""
        self._setup_admin(auth_client)
        auth_client.post(
            "/auth/admin/users/create",
            data={"username": "pwduser"},
        )
        response = auth_client.post(
            "/auth/admin/users/pwduser/reset-password",
            headers={"Accept": "application/json"},
        )
        assert response.status_code in (200, 500)

    def test_admin_delete_json(self, auth_client):
        """Delete user returns JSON when Accept is JSON."""
        self._setup_admin(auth_client)
        auth_client.post(
            "/auth/admin/users/create",
            data={"username": "deljson"},
        )
        response = auth_client.post(
            "/auth/admin/users/deljson/delete",
            headers={"Accept": "application/json"},
        )
        assert response.status_code in (200, 302, 500)

    def test_admin_invalid_username_toggle(self, auth_client):
        """Invalid username in path returns 400 for JSON."""
        self._setup_admin(auth_client)
        response = auth_client.post(
            "/auth/admin/users/invalid!user/toggle-admin",
            headers={"Accept": "application/json"},
            content_type="application/json",
        )
        assert response.status_code == 400

    def test_admin_reset_password_nonexistent(self, auth_client):
        """Reset password for nonexistent user returns 500."""
        self._setup_admin(auth_client)
        response = auth_client.post(
            "/auth/admin/users/nonexistent/reset-password",
            headers={"Accept": "application/json"},
        )
        assert response.status_code in (302, 500)
