"""Configuration management for AppSec Data Views application.

Configuration values are loaded from environment variables with sensible defaults.
In Kubernetes, these will be populated from ConfigMaps and Secrets.
"""

import os
from dataclasses import dataclass, field
from datetime import timedelta


@dataclass
class FalkorDBConfig:
    """FalkorDB connection configuration."""

    host: str
    port: int
    password: str | None
    graph_name: str
    socket_timeout: float
    socket_connect_timeout: float
    internal_label: str
    ssl: bool
    ssl_ca_certs: str | None

    @classmethod
    def from_env(cls) -> "FalkorDBConfig":
        """Load FalkorDB configuration from environment variables.

        Environment variables:
        - FALKORDB_HOST: FalkorDB server hostname (default: localhost)
        - FALKORDB_PORT: FalkorDB server port (default: 6379)
        - FALKORDB_PASSWORD: FalkorDB password (optional)
        - FALKORDB_GRAPH_NAME: Name of the graph to use (default: acme_corp)
        - FALKORDB_SOCKET_TIMEOUT: Socket timeout in seconds (default: 30.0)
        - FALKORDB_CONNECT_TIMEOUT: Connection timeout in seconds (default: 10.0)
        - FALKORDB_INTERNAL_LABEL: Label for internal nodes (default: INTERNAL)
          This label is used to filter internal-only views in reports and visualizations.
        - FALKORDB_SSL: Enable SSL for the FalkorDB connection (default: false)
        - FALKORDB_CA_FILE: Path to CA certificate file for SSL verification
        """
        return cls(
            host=os.environ.get("FALKORDB_HOST", "localhost"),
            port=int(os.environ.get("FALKORDB_PORT", "6379")),
            password=os.environ.get("FALKORDB_PASSWORD"),
            graph_name=os.environ.get("FALKORDB_GRAPH_NAME", "acme_corp"),
            socket_timeout=float(os.environ.get("FALKORDB_SOCKET_TIMEOUT", "30.0")),
            socket_connect_timeout=float(os.environ.get("FALKORDB_CONNECT_TIMEOUT", "10.0")),
            internal_label=os.environ.get("FALKORDB_INTERNAL_LABEL", "INTERNAL"),
            ssl=os.environ.get("FALKORDB_SSL", "false").lower() == "true",
            ssl_ca_certs=os.environ.get("FALKORDB_CA_FILE"),
        )


@dataclass
class TLSConfig:
    """TLS/SSL configuration for secure connections."""

    enabled: bool
    cert_file: str | None
    key_file: str | None
    ca_file: str | None

    @classmethod
    def from_env(cls) -> "TLSConfig":
        """Load TLS configuration from environment variables."""
        return cls(
            enabled=os.environ.get("TLS_ENABLED", "false").lower() == "true",
            cert_file=os.environ.get("TLS_CERT_FILE"),
            key_file=os.environ.get("TLS_KEY_FILE"),
            ca_file=os.environ.get("TLS_CA_FILE"),
        )


@dataclass
class JWTConfig:
    """JWT authentication configuration."""

    secret_key: str
    access_token_expires: timedelta
    refresh_token_expires: timedelta
    algorithm: str
    token_location: list[str] = field(default_factory=lambda: ["headers", "cookies"])

    @classmethod
    def from_env(cls) -> "JWTConfig":
        """Load JWT configuration from environment variables."""
        access_hours = int(os.environ.get("JWT_ACCESS_TOKEN_EXPIRES_HOURS", "1"))
        refresh_days = int(os.environ.get("JWT_REFRESH_TOKEN_EXPIRES_DAYS", "30"))
        return cls(
            secret_key=os.environ.get("JWT_SECRET_KEY", "jwt-secret-key-change-in-production"),
            access_token_expires=timedelta(hours=access_hours),
            refresh_token_expires=timedelta(days=refresh_days),
            algorithm=os.environ.get("JWT_ALGORITHM", "HS256"),
            token_location=os.environ.get("JWT_TOKEN_LOCATION", "headers,cookies").split(","),
        )


@dataclass
class LDAPConfig:
    """LDAP authentication configuration."""

    enabled: bool
    server: str
    port: int
    use_ssl: bool
    base_dn: str
    user_dn_template: str
    bind_dn: str | None
    bind_password: str | None
    search_filter: str
    group_search_base: str | None
    required_group: str | None
    allowed_groups: list[str]
    admin_groups: list[str]
    user_groups: list[str]
    require_group_membership: bool

    @classmethod
    def from_env(cls) -> "LDAPConfig":
        """Load LDAP configuration from environment variables.

        Group-based authorization:
        - LDAP_ADMIN_GROUPS: Comma-separated list of groups that grant admin access
        - LDAP_USER_GROUPS: Comma-separated list of groups that grant regular user access
        - LDAP_ALLOWED_GROUPS: Legacy - combined list (user must be in at least one)
        - LDAP_REQUIRED_GROUP: Legacy - single group (deprecated)

        If LDAP_ADMIN_GROUPS or LDAP_USER_GROUPS are set, users must be in at least
        one of those groups. Admin groups grant admin privileges.
        Set LDAP_REQUIRE_GROUP_MEMBERSHIP=true to enforce group checks.
        """
        # Parse admin groups from comma-separated string
        admin_groups_str = os.environ.get("LDAP_ADMIN_GROUPS", "")
        admin_groups = [g.strip() for g in admin_groups_str.split(",") if g.strip()]

        # Parse user groups from comma-separated string
        user_groups_str = os.environ.get("LDAP_USER_GROUPS", "")
        user_groups = [g.strip() for g in user_groups_str.split(",") if g.strip()]

        # Parse allowed groups (legacy, combines admin + user groups)
        allowed_groups_str = os.environ.get("LDAP_ALLOWED_GROUPS", "")
        allowed_groups = [g.strip() for g in allowed_groups_str.split(",") if g.strip()]

        # Fall back to required_group if nothing else is set
        required_group = os.environ.get("LDAP_REQUIRED_GROUP")
        if not allowed_groups and not admin_groups and not user_groups and required_group:
            allowed_groups = [required_group]

        # If admin/user groups are set but allowed_groups is empty, combine them
        if (admin_groups or user_groups) and not allowed_groups:
            allowed_groups = list(set(admin_groups + user_groups))

        return cls(
            enabled=os.environ.get("LDAP_ENABLED", "false").lower() == "true",
            server=os.environ.get("LDAP_SERVER", "localhost"),
            port=int(os.environ.get("LDAP_PORT", "389")),
            use_ssl=os.environ.get("LDAP_USE_SSL", "false").lower() == "true",
            base_dn=os.environ.get("LDAP_BASE_DN", "dc=example,dc=com"),
            user_dn_template=os.environ.get(
                "LDAP_USER_DN_TEMPLATE", "uid={username},ou=users,dc=example,dc=com"
            ),
            bind_dn=os.environ.get("LDAP_BIND_DN"),
            bind_password=os.environ.get("LDAP_BIND_PASSWORD"),
            search_filter=os.environ.get("LDAP_SEARCH_FILTER", "(uid={username})"),
            group_search_base=os.environ.get("LDAP_GROUP_SEARCH_BASE"),
            required_group=required_group,
            allowed_groups=allowed_groups,
            admin_groups=admin_groups,
            user_groups=user_groups,
            require_group_membership=os.environ.get(
                "LDAP_REQUIRE_GROUP_MEMBERSHIP", "false"
            ).lower()
            == "true",
        )


@dataclass
class DatabaseConfig:
    """Token storage database configuration."""

    path: str
    encryption_key: str

    @classmethod
    def from_env(cls) -> "DatabaseConfig":
        """Load database configuration from environment variables."""
        return cls(
            path=os.environ.get("TOKEN_DB_PATH", "/data/tokens.db"),
            encryption_key=os.environ.get(
                "TOKEN_DB_ENCRYPTION_KEY", "db-encryption-key-change-in-production"
            ),
        )


@dataclass
class AppConfig:
    """Application configuration."""

    debug: bool
    host: str
    port: int
    secret_key: str
    falkordb: FalkorDBConfig
    tls: TLSConfig
    jwt: JWTConfig
    ldap: LDAPConfig
    database: DatabaseConfig
    auth_enabled: bool

    @classmethod
    def from_env(cls) -> "AppConfig":
        """Load application configuration from environment variables."""
        return cls(
            debug=os.environ.get("FLASK_DEBUG", "false").lower() == "true",
            host=os.environ.get(  # nosec B104
                "FLASK_HOST",
                "0.0.0.0",
            ),
            port=int(os.environ.get("FLASK_PORT", "8080")),
            secret_key=os.environ.get("FLASK_SECRET_KEY", "dev-secret-key-change-in-production"),
            falkordb=FalkorDBConfig.from_env(),
            tls=TLSConfig.from_env(),
            jwt=JWTConfig.from_env(),
            ldap=LDAPConfig.from_env(),
            database=DatabaseConfig.from_env(),
            auth_enabled=os.environ.get("AUTH_ENABLED", "false").lower() == "true",
        )


# Global configuration instance
_config: AppConfig | None = None


def get_config() -> AppConfig:
    """Get the application configuration singleton."""
    global _config  # pylint: disable=global-statement
    if _config is None:
        _config = AppConfig.from_env()
    return _config


def reset_config() -> None:
    """Reset the configuration singleton (useful for testing)."""
    global _config  # pylint: disable=global-statement
    _config = None
