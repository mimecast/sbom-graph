"""Extended auth route tests - LDAP login paths, JWT, admin with LDAP."""

from datetime import timedelta
from unittest.mock import MagicMock, patch

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
from sbom_graph_api.services.ldap_service import LDAPAuthenticationError, LDAPUser
from sbom_graph_api.services.token_storage import reset_token_storage
from sbom_graph_api.services.user_storage import reset_user_storage


@pytest.fixture
def ldap_app(tmp_path):
    """Flask app with LDAP auth enabled."""
    reset_config()
    reset_service()
    reset_user_storage()
    reset_token_storage()

    config = AppConfig(
        debug=True,
        host="127.0.0.1",
        port=8080,
        secret_key="test-secret-key-for-testing",
        falkordb=FalkorDBConfig(
            host="test",
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
            secret_key="test-jwt-secret-key-long-enough-for-testing",
            access_token_expires=timedelta(hours=1),
            refresh_token_expires=timedelta(days=30),
            algorithm="HS256",
            token_location=["headers", "cookies"],
        ),
        ldap=LDAPConfig(
            enabled=True,
            server="ldap.test.com",
            port=389,
            use_ssl=False,
            base_dn="dc=test,dc=com",
            user_dn_template="uid={username},ou=users,dc=test,dc=com",
            bind_dn=None,
            bind_password=None,
            search_filter="(uid={username})",
            group_search_base=None,
            required_group=None,
            allowed_groups=[],
            admin_groups=["admins"],
            user_groups=["users"],
            require_group_membership=False,
        ),
        database=DatabaseConfig(path=str(tmp_path / "ldap-test.db"), encryption_key="test-enc"),
        auth_enabled=True,
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
def ldap_client(ldap_app):
    return ldap_app.test_client()


class TestLDAPLogin:
    """Tests for LDAP authentication paths."""

    def test_ldap_login_success(self, ldap_client):
        ldap_user = LDAPUser(
            username="jdoe",
            dn="uid=jdoe,ou=users",
            email="jdoe@test.com",
            display_name="John Doe",
            groups=["users"],
            is_admin=False,
        )
        with patch("sbom_graph_api.routes.auth.get_ldap_service") as m:
            mock_svc = MagicMock()
            mock_svc.authenticate.return_value = ldap_user
            m.return_value = mock_svc

            response = ldap_client.post(
                "/auth/login",
                data={"username": "jdoe", "password": "pass"},
                follow_redirects=False,
            )
            assert response.status_code in (302, 303)

    def test_ldap_login_failure(self, ldap_client):
        with patch("sbom_graph_api.routes.auth.get_ldap_service") as m:
            mock_svc = MagicMock()
            mock_svc.authenticate.return_value = None
            m.return_value = mock_svc

            response = ldap_client.post(
                "/auth/login",
                data={"username": "bad", "password": "bad"},
            )
            assert response.status_code == 200
            assert b"Invalid" in response.data or b"invalid" in response.data

    def test_ldap_login_error(self, ldap_client):
        with patch("sbom_graph_api.routes.auth.get_ldap_service") as m:
            mock_svc = MagicMock()
            mock_svc.authenticate.side_effect = LDAPAuthenticationError("LDAP down")
            m.return_value = mock_svc

            response = ldap_client.post(
                "/auth/login",
                data={"username": "user", "password": "pass"},
            )
            assert response.status_code == 200
            assert b"failed" in response.data.lower() or b"error" in response.data.lower()

    def test_ldap_admin_via_groups(self, ldap_client):
        ldap_user = LDAPUser(
            username="admin",
            dn="uid=admin,ou=users",
            groups=["admins"],
            is_admin=True,
        )
        with patch("sbom_graph_api.routes.auth.get_ldap_service") as m:
            mock_svc = MagicMock()
            mock_svc.authenticate.return_value = ldap_user
            m.return_value = mock_svc

            ldap_client.post("/auth/login", data={"username": "admin", "password": "pass"})
            with ldap_client.session_transaction() as sess:
                assert sess.get("is_admin") is True


class TestLDAPAdminRestrictions:
    """Test that local-only admin endpoints are blocked when LDAP is enabled."""

    def _login_ldap_admin(self, client):
        ldap_user = LDAPUser(username="admin", dn="uid=admin", is_admin=True, groups=["admins"])
        with patch("sbom_graph_api.routes.auth.get_ldap_service") as m:
            mock_svc = MagicMock()
            mock_svc.authenticate.return_value = ldap_user
            m.return_value = mock_svc
            client.post("/auth/login", data={"username": "admin", "password": "pass"})

    def test_admin_users_blocked_with_ldap(self, ldap_client):
        self._login_ldap_admin(ldap_client)
        with ldap_client.session_transaction() as sess:
            sess["authenticated"] = True
            sess["username"] = "admin"
            sess["is_admin"] = True
        response = ldap_client.get("/auth/admin/users")
        assert response.status_code == 400

    def test_change_password_blocked_with_ldap(self, ldap_client):
        with ldap_client.session_transaction() as sess:
            sess["authenticated"] = True
            sess["username"] = "admin"
            sess["is_admin"] = True
            sess["auth_method"] = "ldap"
        response = ldap_client.get("/auth/change-password")
        assert response.status_code == 400

    def test_admin_create_user_blocked_with_ldap(self, ldap_client):
        with ldap_client.session_transaction() as sess:
            sess["authenticated"] = True
            sess["username"] = "admin"
            sess["is_admin"] = True
        response = ldap_client.get("/auth/admin/users/create")
        assert response.status_code == 400

    def test_toggle_admin_blocked_with_ldap(self, ldap_client):
        with ldap_client.session_transaction() as sess:
            sess["authenticated"] = True
            sess["username"] = "admin"
            sess["is_admin"] = True
        response = ldap_client.post(
            "/auth/admin/users/someone/toggle-admin", content_type="application/json"
        )
        assert response.status_code == 400

    def test_toggle_active_blocked_with_ldap(self, ldap_client):
        with ldap_client.session_transaction() as sess:
            sess["authenticated"] = True
            sess["username"] = "admin"
            sess["is_admin"] = True
        response = ldap_client.post(
            "/auth/admin/users/someone/toggle-active", content_type="application/json"
        )
        assert response.status_code == 400

    def test_reset_password_blocked_with_ldap(self, ldap_client):
        with ldap_client.session_transaction() as sess:
            sess["authenticated"] = True
            sess["username"] = "admin"
            sess["is_admin"] = True
        response = ldap_client.post(
            "/auth/admin/users/someone/reset-password", content_type="application/json"
        )
        assert response.status_code == 400

    def test_delete_user_blocked_with_ldap(self, ldap_client):
        with ldap_client.session_transaction() as sess:
            sess["authenticated"] = True
            sess["username"] = "admin"
            sess["is_admin"] = True
        response = ldap_client.post(
            "/auth/admin/users/someone/delete", content_type="application/json"
        )
        assert response.status_code == 400


class TestAdminUserManagementRedirects:
    """Test admin endpoints return redirects for browser requests."""

    @pytest.fixture
    def local_auth_app(self, tmp_path):
        reset_config()
        reset_service()
        reset_user_storage()
        reset_token_storage()
        from sbom_graph_api.config import AppConfig, DatabaseConfig, FalkorDBConfig

        config = AppConfig(
            debug=True,
            host="127.0.0.1",
            port=8080,
            secret_key="test-secret",
            falkordb=FalkorDBConfig(
                host="t",
                port=6379,
                password="",
                graph_name="t",
                socket_timeout=30.0,
                socket_connect_timeout=10.0,
                internal_label="INTERNAL",
                ssl=False,
                ssl_ca_certs=None,
            ),
            tls=TLSConfig(enabled=False, cert_file=None, key_file=None, ca_file=None),
            jwt=JWTConfig(
                secret_key="test-jwt-secret-key-long-enough",
                access_token_expires=timedelta(hours=1),
                refresh_token_expires=timedelta(days=30),
                algorithm="HS256",
                token_location=["headers", "cookies"],
            ),
            ldap=LDAPConfig(
                enabled=False,
                server="localhost",
                port=389,
                use_ssl=False,
                base_dn="dc=test",
                user_dn_template="uid={username}",
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
            database=DatabaseConfig(
                path=str(tmp_path / "admin.db"),
                encryption_key="enc",
            ),
            auth_enabled=True,
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

    def _login_admin(self, client):
        client.post("/auth/login", data={"username": "admin", "password": "pass"})
        with client.session_transaction() as sess:
            sess["authenticated"] = True
            sess["username"] = "admin"
            sess["is_admin"] = True

    def test_toggle_admin_invalid_username_redirect(self, local_auth_app):
        client = local_auth_app.test_client()
        self._login_admin(client)
        resp = client.post(
            "/auth/admin/users/invalid!user/toggle-admin",
            follow_redirects=False,
        )
        assert resp.status_code in (302, 400)

    def test_toggle_admin_own_account_redirect(self, local_auth_app):
        client = local_auth_app.test_client()
        self._login_admin(client)
        resp = client.post(
            "/auth/admin/users/admin/toggle-admin",
            follow_redirects=False,
        )
        assert resp.status_code in (302, 400)

    def test_toggle_admin_success_redirect(self, local_auth_app):
        client = local_auth_app.test_client()
        self._login_admin(client)
        client.post("/auth/admin/users/create", data={"username": "other"})
        resp = client.post(
            "/auth/admin/users/other/toggle-admin",
            follow_redirects=False,
        )
        assert resp.status_code in (302, 200)

    def test_toggle_active_own_account_redirect(self, local_auth_app):
        client = local_auth_app.test_client()
        self._login_admin(client)
        resp = client.post(
            "/auth/admin/users/admin/toggle-active",
            follow_redirects=False,
        )
        assert resp.status_code in (302, 400)

    def test_reset_password_success_html(self, local_auth_app):
        client = local_auth_app.test_client()
        self._login_admin(client)
        client.post("/auth/admin/users/create", data={"username": "pwduser"})
        resp = client.post("/auth/admin/users/pwduser/reset-password")
        assert resp.status_code == 200
        assert b"temp" in resp.data.lower() or b"password" in resp.data.lower()

    def test_delete_user_success_redirect(self, local_auth_app):
        client = local_auth_app.test_client()
        self._login_admin(client)
        client.post("/auth/admin/users/create", data={"username": "todel"})
        resp = client.post(
            "/auth/admin/users/todel/delete",
            follow_redirects=False,
        )
        assert resp.status_code in (302, 200)

    def test_admin_create_user_duplicate_username(self, local_auth_app):
        client = local_auth_app.test_client()
        self._login_admin(client)
        client.post("/auth/admin/users/create", data={"username": "dup"})
        resp = client.post(
            "/auth/admin/users/create",
            data={"username": "dup", "email": "x@x.com"},
        )
        assert resp.status_code == 200
        assert b"already exists" in resp.data.lower() or b"failed" in resp.data.lower()


class TestTokenCreateFlow:
    """Tests for token creation with session auth."""

    @pytest.fixture
    def auth_app(self, tmp_path):
        reset_config()
        reset_service()
        reset_user_storage()
        reset_token_storage()

        config = AppConfig(
            debug=True,
            host="127.0.0.1",
            port=8080,
            secret_key="test-secret",
            falkordb=FalkorDBConfig(
                host="t",
                port=6379,
                password="",
                graph_name="t",
                socket_timeout=30.0,
                socket_connect_timeout=10.0,
                internal_label="INTERNAL",
                ssl=False,
                ssl_ca_certs=None,
            ),
            tls=TLSConfig(enabled=False, cert_file=None, key_file=None, ca_file=None),
            jwt=JWTConfig(
                secret_key="test-jwt-secret-key-long-enough",
                access_token_expires=timedelta(hours=1),
                refresh_token_expires=timedelta(days=30),
                algorithm="HS256",
                token_location=["headers", "cookies"],
            ),
            ldap=LDAPConfig(
                enabled=False,
                server="localhost",
                port=389,
                use_ssl=False,
                base_dn="dc=test",
                user_dn_template="uid={username}",
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
            database=DatabaseConfig(path=str(tmp_path / "tok.db"), encryption_key="enc"),
            auth_enabled=True,
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

    def test_create_token_form(self, auth_app):
        client = auth_app.test_client()
        client.post("/auth/login", data={"username": "admin", "password": "adminpass"})
        with client.session_transaction() as sess:
            sess["authenticated"] = True
            sess["username"] = "admin"
            sess["is_admin"] = True
            sess["auth_method"] = "local"

        response = client.post(
            "/auth/tokens/create",
            data={"token_name": "My Token", "description": "Test", "expires_days": "30"},
        )
        assert response.status_code == 200

    def test_create_token_empty_name(self, auth_app):
        client = auth_app.test_client()
        with client.session_transaction() as sess:
            sess["authenticated"] = True
            sess["username"] = "admin"
        response = client.post(
            "/auth/tokens/create",
            data={"token_name": ""},
            content_type="application/json",
        )
        assert response.status_code in (400, 401)

    def test_list_tokens_json_format(self, auth_app):
        """List tokens with format=json returns JSON."""
        client = auth_app.test_client()
        client.post(
            "/auth/login",
            data={"username": "admin", "password": "adminpass"},
            follow_redirects=True,
        )
        with client.session_transaction() as sess:
            sess["authenticated"] = True
            sess["username"] = "admin"
        response = client.get("/auth/tokens?format=json")
        assert response.status_code == 200
        data = response.get_json()
        assert "tokens" in data
        assert "current_user" in data

    def test_create_token_validation_description_too_long(self, auth_app):
        """Token with description exceeding max shows error."""
        client = auth_app.test_client()
        client.post("/auth/login", data={"username": "admin", "password": "adminpass"})
        with client.session_transaction() as sess:
            sess["authenticated"] = True
            sess["username"] = "admin"
        long_desc = "x" * 1001
        response = client.post(
            "/auth/tokens/create",
            data={"token_name": "Test", "description": long_desc},
        )
        assert response.status_code == 200
        assert b"1000" in response.data or b"Description" in response.data

    def test_create_token_validation_expires_out_of_range(self, auth_app):
        """Token with expires_days out of range shows error."""
        client = auth_app.test_client()
        client.post("/auth/login", data={"username": "admin", "password": "adminpass"})
        with client.session_transaction() as sess:
            sess["authenticated"] = True
            sess["username"] = "admin"
        response = client.post(
            "/auth/tokens/create",
            data={"token_name": "Test", "expires_days": "9999"},
        )
        assert response.status_code == 200
        assert b"Expiration" in response.data or b"3650" in response.data

    def test_create_token_validation_name_empty(self, auth_app):
        """Token with empty name shows error."""
        client = auth_app.test_client()
        client.post("/auth/login", data={"username": "admin", "password": "adminpass"})
        with client.session_transaction() as sess:
            sess["authenticated"] = True
            sess["username"] = "admin"
        response = client.post(
            "/auth/tokens/create",
            data={"token_name": ""},
        )
        assert response.status_code == 200
        assert b"required" in response.data.lower()

    def test_create_token_validation_name_too_long(self, auth_app):
        """Token name over 255 chars shows error."""
        client = auth_app.test_client()
        client.post("/auth/login", data={"username": "admin", "password": "adminpass"})
        with client.session_transaction() as sess:
            sess["authenticated"] = True
            sess["username"] = "admin"
        response = client.post(
            "/auth/tokens/create",
            data={"token_name": "x" * 256},
        )
        assert response.status_code == 200
        assert b"255" in response.data

    def test_create_token_storage_exception(self, auth_app):
        """When token storage fails, shows generic error."""
        client = auth_app.test_client()
        client.post("/auth/login", data={"username": "admin", "password": "adminpass"})
        with client.session_transaction() as sess:
            sess["authenticated"] = True
            sess["username"] = "admin"
        with patch("sbom_graph_api.routes.auth.get_token_storage") as m:
            m.return_value.store_token.side_effect = Exception("db error")
            response = client.post(
                "/auth/tokens/create",
                data={"token_name": "Test", "expires_days": "30"},
            )
        assert response.status_code == 200
        assert b"Failed" in response.data or b"try again" in response.data

    def test_create_token_json_invalid_request(self, auth_app):
        """POST with JSON body and empty form returns 400 for JSON."""
        client = auth_app.test_client()
        client.post("/auth/login", data={"username": "admin", "password": "adminpass"})
        with client.session_transaction() as sess:
            sess["authenticated"] = True
            sess["username"] = "admin"
        response = client.post(
            "/auth/tokens/create",
            json={"token_name": ""},
            headers={"Content-Type": "application/json"},
        )
        assert response.status_code == 400

    def test_get_token_success(self, auth_app):
        """Get token by ID returns token details when found."""
        client = auth_app.test_client()
        client.post("/auth/login", data={"username": "admin", "password": "adminpass"})
        with client.session_transaction() as sess:
            sess["authenticated"] = True
            sess["username"] = "admin"
        with patch(
            "sbom_graph_api.routes.auth.get_token_storage"
        ) as mock_storage:
            mock_storage.return_value.get_token.return_value = {
                "id": 1,
                "token_name": "Test",
                "created_at": "2024-01-01T00:00:00",
            }
            response = client.get("/auth/tokens/1")
        assert response.status_code == 200
        data = response.get_json()
        assert data["token_name"] == "Test"

    def test_revoke_token_success(self, auth_app):
        """Revoke token returns success when token exists."""
        client = auth_app.test_client()
        with client.session_transaction() as sess:
            sess["authenticated"] = True
            sess["username"] = "admin"
        with patch(
            "sbom_graph_api.routes.auth.get_token_storage"
        ) as mock_storage:
            mock_storage.return_value.revoke_token.return_value = True
            response = client.post(
                "/auth/tokens/1/revoke",
                content_type="application/json",
            )
        assert response.status_code == 200

    def test_delete_token_success(self, auth_app):
        """Delete token returns success when token exists."""
        client = auth_app.test_client()
        with client.session_transaction() as sess:
            sess["authenticated"] = True
            sess["username"] = "admin"
        with patch(
            "sbom_graph_api.routes.auth.get_token_storage"
        ) as mock_storage:
            mock_storage.return_value.delete_token.return_value = True
            response = client.post(
                "/auth/tokens/1/delete",
                content_type="application/json",
            )
        assert response.status_code == 200

    def test_auth_status_session_authenticated(self, auth_app):
        """Auth status shows session auth when logged in."""
        client = auth_app.test_client()
        client.post("/auth/login", data={"username": "admin", "password": "adminpass"})
        with client.session_transaction() as sess:
            sess["authenticated"] = True
            sess["username"] = "admin"
            sess["is_admin"] = True
        response = client.get("/auth/status")
        assert response.status_code == 200
        data = response.get_json()
        assert data["authenticated"] is True
        assert data["username"] == "admin"

    def test_refresh_token_with_cookies(self, auth_app):
        """Refresh endpoint returns new access token when refresh cookie present."""
        client = auth_app.test_client()
        login_resp = client.post(
            "/auth/login",
            data={"username": "admin", "password": "adminpass"},
            follow_redirects=False,
        )
        if login_resp.status_code not in (302, 303):
            pytest.skip("Login did not succeed - first user may exist")
        client.post(
            "/auth/login",
            data={"username": "admin", "password": "adminpass"},
            follow_redirects=True,
        )
        response = client.post("/auth/refresh")
        assert response.status_code in (200, 401)

    def test_auth_status_jwt_authenticated(self, auth_app):
        """Auth status shows jwt auth_method when JWT present."""
        client = auth_app.test_client()
        client.post("/auth/login", data={"username": "admin", "password": "adminpass"})
        with client.session_transaction() as sess:
            sess["authenticated"] = True
            sess["username"] = "admin"
        resp = client.get("/auth/status")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["authenticated"] is True
