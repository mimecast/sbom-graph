"""Pytest configuration and shared fixtures for tests."""

from datetime import timedelta
from unittest.mock import MagicMock, patch

import pytest

from sbom_graph_api.app import create_app
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


@pytest.fixture
def mock_falkordb_config():
    """Create a mock FalkorDB configuration."""
    return FalkorDBConfig(
        host="test-host",
        port=6379,
        password="test-password",
        graph_name="test-graph",
        socket_timeout=30.0,
        socket_connect_timeout=10.0,
        internal_label="INTERNAL",
        ssl=False,
        ssl_ca_certs=None,
    )


@pytest.fixture
def mock_tls_config():
    """Create a mock TLS configuration."""
    return TLSConfig(
        enabled=False,
        cert_file=None,
        key_file=None,
        ca_file=None,
    )


@pytest.fixture
def mock_jwt_config():
    """Create a mock JWT configuration."""
    return JWTConfig(
        secret_key="test-jwt-secret-key",
        access_token_expires=timedelta(hours=1),
        refresh_token_expires=timedelta(days=30),
        algorithm="HS256",
        token_location=["headers", "cookies"],
    )


@pytest.fixture
def mock_ldap_config():
    """Create a mock LDAP configuration."""
    return LDAPConfig(
        enabled=False,
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
    )


@pytest.fixture
def mock_database_config():
    """Create a mock database configuration."""
    return DatabaseConfig(
        path="/tmp/test-tokens.db",
        encryption_key="test-encryption-key-12345",
    )


@pytest.fixture
def mock_app_config(
    mock_falkordb_config,
    mock_tls_config,
    mock_jwt_config,
    mock_ldap_config,
    mock_database_config,
):
    """Create a mock application configuration."""
    return AppConfig(
        debug=True,
        host="127.0.0.1",
        port=8080,
        secret_key="test-secret-key",
        falkordb=mock_falkordb_config,
        tls=mock_tls_config,
        jwt=mock_jwt_config,
        ldap=mock_ldap_config,
        database=mock_database_config,
        auth_enabled=False,
    )


@pytest.fixture
def app(mock_app_config):
    """Create a Flask test application with mocked config."""
    reset_config()
    reset_service()

    with patch("sbom_graph_api.config.AppConfig.from_env", return_value=mock_app_config):
        app = create_app()
        app.config["TESTING"] = True
        app.config["WTF_CSRF_ENABLED"] = False
        yield app

    reset_config()
    reset_service()


@pytest.fixture
def client(app):
    """Create a Flask test client."""
    return app.test_client()


@pytest.fixture
def mock_graph():
    """Create a mock FalkorDB graph object."""
    mock = MagicMock()
    mock.ro_query.return_value = MagicMock(result_set=[])
    return mock


@pytest.fixture
def mock_falkordb(mock_graph):
    """Create a mock FalkorDB connection."""
    mock = MagicMock()
    mock.select_graph.return_value = mock_graph
    return mock


@pytest.fixture
def mock_node():
    """Create a mock FalkorDB node."""
    node = MagicMock()
    node.id = 1
    node.labels = ["Version", "INTERNAL"]
    node.properties = {
        "project_name": "test-project",
        "name": "1.0.0",
        "description": "Test project",
    }
    return node


@pytest.fixture
def mock_version_result(mock_node):
    """Create a mock query result for version lookup."""
    return [[mock_node]]


@pytest.fixture
def mock_projects_result():
    """Create a mock query result for projects listing."""
    return [
        ["project-a", "1.0.0"],
        ["project-a", "2.0.0"],
        ["project-b", "1.0.0"],
    ]


@pytest.fixture
def mock_dependants_result():
    """Create mock dependants data."""
    return [
        ["dependant-a", "1.0.0", "target-project", "1.0.0"],
        ["dependant-b", "2.0.0", "target-project", "1.0.0"],
    ]


@pytest.fixture
def mock_snapshot_result():
    """Create mock SNAPSHOT dependencies result."""
    return [
        ["app-a", "1.0.0", "lib-a", "1.0.0-SNAPSHOT"],
        ["app-b", "2.0.0", "lib-b", "2.0.0-SNAPSHOT"],
    ]


@pytest.fixture
def mock_self_dependency_result():
    """Create mock self-dependency result."""
    return [
        ["project-a", "1.0.0", "DEPENDS_ON"],
    ]
