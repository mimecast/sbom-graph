"""Extended auth route tests - LDAP login paths, JWT, admin with LDAP."""

from datetime import timedelta
from unittest.mock import MagicMock, patch

import pytest
from flask import Flask

from appsec_data_views.config import (
    AppConfig, DatabaseConfig, FalkorDBConfig, JWTConfig, LDAPConfig, TLSConfig,
    reset_config,
)
from appsec_data_views.services.falkordb_service import reset_service
from appsec_data_views.services.ldap_service import LDAPUser, LDAPAuthenticationError
from appsec_data_views.services.token_storage import reset_token_storage
from appsec_data_views.services.user_storage import reset_user_storage


@pytest.fixture
def ldap_app(tmp_path):
    """Flask app with LDAP auth enabled."""
    reset_config()
    reset_service()
    reset_user_storage()
    reset_token_storage()

    config = AppConfig(
        debug=True, host="127.0.0.1", port=8080,
        secret_key="test-secret-key-for-testing",
        falkordb=FalkorDBConfig(
            host="test", port=6379, password="test", graph_name="test",
            socket_timeout=30.0, socket_connect_timeout=10.0, internal_label="INTERNAL",
        ),
        tls=TLSConfig(enabled=False, cert_file=None, key_file=None, ca_file=None),
        jwt=JWTConfig(
            secret_key="test-jwt-secret-key-long-enough-for-testing",
            access_token_expires=timedelta(hours=1),
            refresh_token_expires=timedelta(days=30),
            algorithm="HS256", token_location=["headers", "cookies"],
        ),
        ldap=LDAPConfig(
            enabled=True, server="ldap.test.com", port=389, use_ssl=False,
            base_dn="dc=test,dc=com",
            user_dn_template="uid={username},ou=users,dc=test,dc=com",
            bind_dn=None, bind_password=None,
            search_filter="(uid={username})", group_search_base=None,
            required_group=None, allowed_groups=[],
            admin_groups=["admins"], user_groups=["users"],
            require_group_membership=False,
        ),
        database=DatabaseConfig(path=str(tmp_path / "ldap-test.db"), encryption_key="test-enc"),
        auth_enabled=True,
    )

    with patch("appsec_data_views.config.AppConfig.from_env", return_value=config):
        from appsec_data_views.app import create_app
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
            username="jdoe", dn="uid=jdoe,ou=users",
            email="jdoe@test.com", display_name="John Doe",
            groups=["users"], is_admin=False,
        )
        with patch("appsec_data_views.routes.auth.get_ldap_service") as m:
            mock_svc = MagicMock()
            mock_svc.authenticate.return_value = ldap_user
            m.return_value = mock_svc

            response = ldap_client.post(
                "/auth/login", data={"username": "jdoe", "password": "pass"},
                follow_redirects=False,
            )
            assert response.status_code in (302, 303)

    def test_ldap_login_failure(self, ldap_client):
        with patch("appsec_data_views.routes.auth.get_ldap_service") as m:
            mock_svc = MagicMock()
            mock_svc.authenticate.return_value = None
            m.return_value = mock_svc

            response = ldap_client.post(
                "/auth/login", data={"username": "bad", "password": "bad"},
            )
            assert response.status_code == 200
            assert b"Invalid" in response.data or b"invalid" in response.data

    def test_ldap_login_error(self, ldap_client):
        with patch("appsec_data_views.routes.auth.get_ldap_service") as m:
            mock_svc = MagicMock()
            mock_svc.authenticate.side_effect = LDAPAuthenticationError("LDAP down")
            m.return_value = mock_svc

            response = ldap_client.post(
                "/auth/login", data={"username": "user", "password": "pass"},
            )
            assert response.status_code == 200
            assert b"failed" in response.data.lower() or b"error" in response.data.lower()

    def test_ldap_admin_via_groups(self, ldap_client):
        ldap_user = LDAPUser(
            username="admin", dn="uid=admin,ou=users",
            groups=["admins"], is_admin=True,
        )
        with patch("appsec_data_views.routes.auth.get_ldap_service") as m:
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
        with patch("appsec_data_views.routes.auth.get_ldap_service") as m:
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
        response = ldap_client.post("/auth/admin/users/someone/toggle-admin",
                                     content_type="application/json")
        assert response.status_code == 400

    def test_toggle_active_blocked_with_ldap(self, ldap_client):
        with ldap_client.session_transaction() as sess:
            sess["authenticated"] = True
            sess["username"] = "admin"
            sess["is_admin"] = True
        response = ldap_client.post("/auth/admin/users/someone/toggle-active",
                                     content_type="application/json")
        assert response.status_code == 400

    def test_reset_password_blocked_with_ldap(self, ldap_client):
        with ldap_client.session_transaction() as sess:
            sess["authenticated"] = True
            sess["username"] = "admin"
            sess["is_admin"] = True
        response = ldap_client.post("/auth/admin/users/someone/reset-password",
                                     content_type="application/json")
        assert response.status_code == 400

    def test_delete_user_blocked_with_ldap(self, ldap_client):
        with ldap_client.session_transaction() as sess:
            sess["authenticated"] = True
            sess["username"] = "admin"
            sess["is_admin"] = True
        response = ldap_client.post("/auth/admin/users/someone/delete",
                                     content_type="application/json")
        assert response.status_code == 400


class TestTokenCreateFlow:
    """Tests for token creation with session auth."""

    @pytest.fixture
    def auth_app(self, tmp_path):
        reset_config()
        reset_service()
        reset_user_storage()
        reset_token_storage()

        config = AppConfig(
            debug=True, host="127.0.0.1", port=8080,
            secret_key="test-secret",
            falkordb=FalkorDBConfig(
                host="t", port=6379, password="", graph_name="t",
                socket_timeout=30.0, socket_connect_timeout=10.0, internal_label="INTERNAL",
            ),
            tls=TLSConfig(enabled=False, cert_file=None, key_file=None, ca_file=None),
            jwt=JWTConfig(
                secret_key="test-jwt-secret-key-long-enough",
                access_token_expires=timedelta(hours=1),
                refresh_token_expires=timedelta(days=30),
                algorithm="HS256", token_location=["headers", "cookies"],
            ),
            ldap=LDAPConfig(
                enabled=False, server="localhost", port=389, use_ssl=False,
                base_dn="dc=test", user_dn_template="uid={username}",
                bind_dn=None, bind_password=None, search_filter="(uid={username})",
                group_search_base=None, required_group=None, allowed_groups=[],
                admin_groups=[], user_groups=[], require_group_membership=False,
            ),
            database=DatabaseConfig(path=str(tmp_path / "tok.db"), encryption_key="enc"),
            auth_enabled=True,
        )

        with patch("appsec_data_views.config.AppConfig.from_env", return_value=config):
            from appsec_data_views.app import create_app
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
