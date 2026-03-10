"""Tests for LDAP authentication service."""

from unittest.mock import MagicMock, patch

import pytest
from ldap3.core.exceptions import LDAPException

from sbom_graph_api.config import LDAPConfig
from sbom_graph_api.services.ldap_service import (
    LDAPAuthenticationError,
    LDAPService,
    LDAPUser,
    get_ldap_service,
    reset_ldap_service,
)


@pytest.fixture
def ldap_config():
    """LDAP config with auth enabled."""
    return LDAPConfig(
        enabled=True,
        server="ldap.example.com",
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
        admin_groups=["admins"],
        user_groups=["users"],
        require_group_membership=False,
    )


@pytest.fixture
def ldap_config_disabled():
    """LDAP config with auth disabled."""
    return LDAPConfig(
        enabled=False,
        server="ldap.example.com",
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
    )


@pytest.fixture
def ldap_config_group_required(ldap_config):
    """LDAP config requiring group membership."""
    ldap_config.require_group_membership = True
    return ldap_config


@pytest.fixture
def ldap_config_legacy_group(ldap_config):
    """LDAP config with legacy required_group."""
    ldap_config.required_group = "app-users"
    ldap_config.require_group_membership = False
    return ldap_config


def _make_mock_entry(
    mail=None,
    display_name=None,
    cn=None,
    member_of=None,
):
    """Create a mock LDAP search entry."""
    entry = MagicMock()

    entry.mail = MagicMock() if mail else None
    if mail:
        entry.mail.__str__ = lambda s: mail
        entry.mail.__bool__ = lambda s: True

    entry.displayName = MagicMock() if display_name else None
    if display_name:
        entry.displayName.__str__ = lambda s: display_name
        entry.displayName.__bool__ = lambda s: True

    entry.cn = MagicMock() if cn else None
    if cn:
        entry.cn.__str__ = lambda s: cn
        entry.cn.__bool__ = lambda s: True

    if member_of:
        entry.memberOf = member_of
    else:
        entry.memberOf = None

    return entry


class TestExtractGroupNames:
    """Tests for _extract_group_names method (no LDAP connection needed)."""

    # Positive tests

    def test_full_dn_extracts_cn(self, ldap_config):
        service = LDAPService(config=ldap_config)
        result = service._extract_group_names(["CN=admins,OU=groups,DC=example,DC=com"])
        assert result == ["admins"]

    def test_lowercase_cn(self, ldap_config):
        service = LDAPService(config=ldap_config)
        result = service._extract_group_names(["cn=users,ou=groups,dc=example"])
        assert result == ["users"]

    def test_plain_name_passthrough(self, ldap_config):
        service = LDAPService(config=ldap_config)
        result = service._extract_group_names(["admins"])
        assert result == ["admins"]

    def test_multiple_groups(self, ldap_config):
        service = LDAPService(config=ldap_config)
        result = service._extract_group_names(
            [
                "CN=admins,OU=groups,DC=example,DC=com",
                "CN=developers,OU=groups,DC=example,DC=com",
                "users",
            ]
        )
        assert result == ["admins", "developers", "users"]

    def test_empty_list(self, ldap_config):
        service = LDAPService(config=ldap_config)
        assert not service._extract_group_names([])

    def test_dn_without_cn_uses_full_string(self, ldap_config):
        service = LDAPService(config=ldap_config)
        result = service._extract_group_names(["OU=groups,DC=example"])
        assert result == ["OU=groups,DC=example"]

    def test_cn_with_spaces(self, ldap_config):
        service = LDAPService(config=ldap_config)
        result = service._extract_group_names([" CN=admins , OU=groups , DC=example"])
        assert result == ["admins"]


class TestLDAPUserDataclass:
    """Tests for LDAPUser dataclass."""

    def test_defaults(self):
        user = LDAPUser(username="alice", dn="uid=alice,ou=users,dc=example")
        assert user.email is None
        assert user.display_name is None
        assert user.groups is None
        assert user.is_admin is False

    def test_all_fields(self):
        user = LDAPUser(
            username="alice",
            dn="uid=alice,ou=users",
            email="alice@example.com",
            display_name="Alice Smith",
            groups=["admins", "users"],
            is_admin=True,
        )
        assert user.username == "alice"
        assert user.email == "alice@example.com"
        assert user.is_admin is True


class TestAuthenticate:
    """Tests for LDAP authenticate method."""

    # Positive tests

    @patch("sbom_graph_api.services.ldap_service.Connection")
    @patch("sbom_graph_api.services.ldap_service.Server")
    def test_successful_auth(self, mock_server_cls, mock_conn_cls, ldap_config):
        mock_conn = MagicMock()
        mock_conn_cls.return_value = mock_conn
        mock_conn.entries = [
            _make_mock_entry(
                mail="alice@example.com",
                display_name="Alice Smith",
                member_of=["CN=users,OU=groups,DC=example,DC=com"],
            )
        ]

        service = LDAPService(config=ldap_config)
        user = service.authenticate("alice", "password123")

        assert user is not None
        assert user.username == "alice"
        assert user.dn == "uid=alice,ou=users,dc=example,dc=com"
        assert user.email == "alice@example.com"
        assert user.display_name == "Alice Smith"
        mock_conn.unbind.assert_called_once()

    @patch("sbom_graph_api.services.ldap_service.Connection")
    @patch("sbom_graph_api.services.ldap_service.Server")
    def test_admin_group_grants_admin(self, mock_server_cls, mock_conn_cls, ldap_config):
        mock_conn = MagicMock()
        mock_conn_cls.return_value = mock_conn
        mock_conn.entries = [
            _make_mock_entry(
                member_of=["CN=admins,OU=groups,DC=example,DC=com"],
            )
        ]

        service = LDAPService(config=ldap_config)
        user = service.authenticate("admin_user", "password")

        assert user is not None
        assert user.is_admin is True

    @patch("sbom_graph_api.services.ldap_service.Connection")
    @patch("sbom_graph_api.services.ldap_service.Server")
    def test_non_admin_group_no_admin(self, mock_server_cls, mock_conn_cls, ldap_config):
        mock_conn = MagicMock()
        mock_conn_cls.return_value = mock_conn
        mock_conn.entries = [
            _make_mock_entry(
                member_of=["CN=users,OU=groups,DC=example,DC=com"],
            )
        ]

        service = LDAPService(config=ldap_config)
        user = service.authenticate("regular_user", "password")

        assert user is not None
        assert user.is_admin is False

    @patch("sbom_graph_api.services.ldap_service.Connection")
    @patch("sbom_graph_api.services.ldap_service.Server")
    def test_fallback_to_cn_for_display_name(self, mock_server_cls, mock_conn_cls, ldap_config):
        mock_conn = MagicMock()
        mock_conn_cls.return_value = mock_conn
        mock_conn.entries = [_make_mock_entry(cn="Alice")]

        service = LDAPService(config=ldap_config)
        user = service.authenticate("alice", "password")
        assert user is not None

    # Negative tests

    def test_disabled_raises_error(self, ldap_config_disabled):
        service = LDAPService(config=ldap_config_disabled)
        with pytest.raises(LDAPAuthenticationError, match="not enabled"):
            service.authenticate("alice", "password")

    def test_empty_username_returns_none(self, ldap_config):
        service = LDAPService(config=ldap_config)
        assert service.authenticate("", "password") is None

    def test_empty_password_returns_none(self, ldap_config):
        service = LDAPService(config=ldap_config)
        assert service.authenticate("alice", "") is None

    def test_none_username_returns_none(self, ldap_config):
        service = LDAPService(config=ldap_config)
        assert service.authenticate(None, "password") is None

    @patch("sbom_graph_api.services.ldap_service.Connection")
    @patch("sbom_graph_api.services.ldap_service.Server")
    def test_ldap_exception_returns_none(self, mock_server_cls, mock_conn_cls, ldap_config):
        mock_conn_cls.side_effect = LDAPException("Connection refused")

        service = LDAPService(config=ldap_config)
        result = service.authenticate("alice", "password")
        assert result is None

    @patch("sbom_graph_api.services.ldap_service.Connection")
    @patch("sbom_graph_api.services.ldap_service.Server")
    def test_unexpected_error_raises(self, mock_server_cls, mock_conn_cls, ldap_config):
        mock_conn_cls.side_effect = RuntimeError("Unexpected failure")

        service = LDAPService(config=ldap_config)
        with pytest.raises(LDAPAuthenticationError, match="Authentication error"):
            service.authenticate("alice", "password")


class TestGroupMembershipRequired:
    """Tests for group-based authorization."""

    @patch("sbom_graph_api.services.ldap_service.Connection")
    @patch("sbom_graph_api.services.ldap_service.Server")
    def test_allowed_group_passes(self, mock_server_cls, mock_conn_cls, ldap_config_group_required):
        mock_conn = MagicMock()
        mock_conn_cls.return_value = mock_conn
        mock_conn.entries = [
            _make_mock_entry(
                member_of=["CN=users,OU=groups,DC=example,DC=com"],
            )
        ]

        service = LDAPService(config=ldap_config_group_required)
        user = service.authenticate("alice", "password")
        assert user is not None

    @patch("sbom_graph_api.services.ldap_service.Connection")
    @patch("sbom_graph_api.services.ldap_service.Server")
    def test_no_matching_group_rejected(
        self, mock_server_cls, mock_conn_cls, ldap_config_group_required
    ):
        mock_conn = MagicMock()
        mock_conn_cls.return_value = mock_conn
        mock_conn.entries = [
            _make_mock_entry(
                member_of=["CN=other-group,OU=groups,DC=example,DC=com"],
            )
        ]

        service = LDAPService(config=ldap_config_group_required)
        user = service.authenticate("alice", "password")
        assert user is None
        mock_conn.unbind.assert_called_once()


class TestLegacyRequiredGroup:
    """Tests for legacy single required_group configuration."""

    @patch("sbom_graph_api.services.ldap_service.Connection")
    @patch("sbom_graph_api.services.ldap_service.Server")
    def test_in_required_group_passes(
        self, mock_server_cls, mock_conn_cls, ldap_config_legacy_group
    ):
        mock_conn = MagicMock()
        mock_conn_cls.return_value = mock_conn
        mock_conn.entries = [
            _make_mock_entry(
                member_of=["app-users"],
            )
        ]

        service = LDAPService(config=ldap_config_legacy_group)
        user = service.authenticate("alice", "password")
        assert user is not None

    @patch("sbom_graph_api.services.ldap_service.Connection")
    @patch("sbom_graph_api.services.ldap_service.Server")
    def test_not_in_required_group_rejected(
        self, mock_server_cls, mock_conn_cls, ldap_config_legacy_group
    ):
        mock_conn = MagicMock()
        mock_conn_cls.return_value = mock_conn
        mock_conn.entries = [
            _make_mock_entry(
                member_of=["other-group"],
            )
        ]

        service = LDAPService(config=ldap_config_legacy_group)
        user = service.authenticate("alice", "password")
        assert user is None


class TestTestConnection:
    """Tests for test_connection method."""

    def test_disabled_returns_false(self, ldap_config_disabled):
        service = LDAPService(config=ldap_config_disabled)
        assert service.test_connection() is False

    @patch("sbom_graph_api.services.ldap_service.Connection")
    @patch("sbom_graph_api.services.ldap_service.Server")
    def test_successful_connection(self, mock_server_cls, mock_conn_cls, ldap_config):
        mock_conn = MagicMock()
        mock_conn_cls.return_value = mock_conn

        service = LDAPService(config=ldap_config)
        assert service.test_connection() is True
        mock_conn.unbind.assert_called_once()

    @patch("sbom_graph_api.services.ldap_service.Connection")
    @patch("sbom_graph_api.services.ldap_service.Server")
    def test_connection_failure(self, mock_server_cls, mock_conn_cls, ldap_config):
        mock_conn_cls.side_effect = LDAPException("Connection refused")

        service = LDAPService(config=ldap_config)
        assert service.test_connection() is False

    @patch("sbom_graph_api.services.ldap_service.Connection")
    @patch("sbom_graph_api.services.ldap_service.Server")
    def test_uses_bind_dn_when_configured(self, mock_server_cls, mock_conn_cls, ldap_config):
        ldap_config.bind_dn = "cn=service,dc=example"
        ldap_config.bind_password = "service-pass"
        mock_conn = MagicMock()
        mock_conn_cls.return_value = mock_conn

        service = LDAPService(config=ldap_config)
        service.test_connection()

        mock_conn_cls.assert_called_once()
        call_kwargs = mock_conn_cls.call_args
        assert call_kwargs.kwargs.get("user") == "cn=service,dc=example"


class TestSingletonFunctions:
    """Tests for module-level singleton functions."""

    def test_reset_clears_singleton(self):
        reset_ldap_service()
        s1 = get_ldap_service()
        reset_ldap_service()
        s2 = get_ldap_service()
        assert s1 is not s2

    def test_get_returns_same_instance(self):
        reset_ldap_service()
        s1 = get_ldap_service()
        s2 = get_ldap_service()
        assert s1 is s2
        reset_ldap_service()
