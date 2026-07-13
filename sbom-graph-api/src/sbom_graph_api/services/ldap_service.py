"""LDAP authentication service for user validation.

This module provides LDAP authentication functionality for validating
user credentials against an LDAP directory server.
"""

import logging
from dataclasses import dataclass
from typing import Any

from ldap3 import ALL, SUBTREE, Connection, Server
from ldap3.core.exceptions import LDAPException
from ldap3.utils.conv import escape_filter_chars
from ldap3.utils.dn import escape_rdn

from sbom_graph_api.config import LDAPConfig, get_config

logger = logging.getLogger(__name__)


@dataclass
class LDAPUser:
    """Represents an authenticated LDAP user."""

    username: str
    dn: str
    email: str | None = None
    display_name: str | None = None
    groups: list[str] | None = None
    is_admin: bool = False


class LDAPAuthenticationError(Exception):
    """Raised when LDAP authentication fails."""


class LDAPService:
    """Service for authenticating users against an LDAP server."""

    def __init__(self, config: LDAPConfig | None = None):
        """Initialize LDAP service with configuration.

        Args:
            config: LDAP configuration. If None, loads from environment.
        """
        self.config = config or get_config().ldap
        self._server: Server | None = None

    def _get_server(self) -> Server:
        """Get or create LDAP server connection."""
        if self._server is None:
            self._server = Server(
                self.config.server,
                port=self.config.port,
                use_ssl=self.config.use_ssl,
                get_info=ALL,
            )
        return self._server

    def authenticate(self, username: str, password: str) -> LDAPUser | None:
        """Authenticate a user against the LDAP server.

        Args:
            username: The username to authenticate
            password: The user's password

        Returns:
            LDAPUser object if authentication succeeds, None otherwise

        Raises:
            LDAPAuthenticationError: If there's an error during authentication
        """
        if not self.config.enabled:
            raise LDAPAuthenticationError("LDAP authentication is not enabled")

        if not username or not password:
            return None

        try:
            server = self._get_server()

            # Build user DN from template. Escape RDN special chars (CWE-90):
            # the username is attacker-controlled and is interpolated into the
            # bind DN, so a value like `alice,cn=admin` could otherwise alter the
            # DN structure. (The search *filter* is escaped separately in
            # _get_user_info via escape_filter_chars.)
            safe_dn_username = escape_rdn(username)
            user_dn = self.config.user_dn_template.format(username=safe_dn_username)

            # Attempt to bind with user credentials
            conn = Connection(
                server,
                user=user_dn,
                password=password,
                auto_bind=True,
                raise_exceptions=True,
            )

            # Get user attributes (including groups from memberOf attribute)
            user_info = self._get_user_info(conn, username)
            logger.debug("LDAP user info for %s: %s", username, user_info)

            # Get groups from memberOf attribute and extract CNs from full DNs
            groups = user_info.get("groups", [])
            group_names = self._extract_group_names(groups)
            logger.debug("User %s group names: %s", username, group_names)

            # Determine admin status based on admin groups
            is_admin = False
            if self.config.admin_groups:
                admin_matches = set(group_names) & set(self.config.admin_groups)
                is_admin = bool(admin_matches)
                if is_admin:
                    logger.info("User %s granted admin via groups: %s", username, admin_matches)

            # Check group membership if required
            if self.config.require_group_membership:
                # Build list of all allowed groups (admin + user groups)
                all_allowed = set(self.config.admin_groups + self.config.user_groups)
                if not all_allowed:
                    # Fall back to legacy allowed_groups
                    all_allowed = set(self.config.allowed_groups)

                if all_allowed:
                    user_allowed_groups = set(group_names) & all_allowed
                    if not user_allowed_groups:
                        logger.warning(
                            "User not in any allowed group "
                            "(checked %d user groups against %d allowed groups)",
                            len(group_names),
                            len(all_allowed),
                        )
                        conn.unbind()
                        return None

                    logger.info(
                        "User %s authorized via group membership: %s",
                        username,
                        user_allowed_groups,
                    )
            elif self.config.required_group:
                # Legacy single group check (backward compatibility)
                if self.config.required_group not in group_names:
                    logger.warning("User not in required group")
                    conn.unbind()
                    return None

            conn.unbind()

            return LDAPUser(
                username=username,
                dn=user_dn,
                email=user_info.get("email"),
                display_name=user_info.get("display_name"),
                groups=group_names,
                is_admin=is_admin,
            )

        except LDAPException as e:
            logger.warning("LDAP authentication failed for user %s: %s", username, e)
            return None
        except Exception as e:
            logger.error("Unexpected error during LDAP authentication: %s", e)
            raise LDAPAuthenticationError(f"Authentication error: {e}") from e

    def _get_user_info(self, conn: Connection, username: str) -> dict[str, Any]:
        """Get additional user information from LDAP.

        Args:
            conn: Active LDAP connection
            username: The username to look up

        Returns:
            Dictionary with user attributes
        """
        user_info: dict[str, Any] = {}

        try:
            # Escape user-controlled input before inserting into LDAP filter
            safe_username = escape_filter_chars(username)
            search_filter = self.config.search_filter.format(username=safe_username)
            conn.search(
                search_base=self.config.base_dn,
                search_filter=search_filter,
                search_scope=SUBTREE,
                attributes=["mail", "displayName", "cn", "sn", "givenName", "memberOf"],
            )

            if conn.entries:
                entry = conn.entries[0]
                if hasattr(entry, "mail") and entry.mail:
                    user_info["email"] = str(entry.mail)
                if hasattr(entry, "displayName") and entry.displayName:
                    user_info["display_name"] = str(entry.displayName)
                elif hasattr(entry, "cn") and entry.cn:
                    user_info["display_name"] = str(entry.cn)
                if hasattr(entry, "memberOf") and entry.memberOf:
                    user_info["groups"] = [str(group) for group in entry.memberOf]

        except LDAPException as e:
            logger.warning("Failed to get user info from LDAP: %s", e)

        return user_info

    def _extract_group_names(self, groups: list[str]) -> list[str]:
        """Extract group names (CNs) from full DNs or return as-is if already names.

        Args:
            groups: List of group identifiers (may be full DNs or just names)

        Returns:
            List of group names (CNs extracted from DNs)

        Examples:
            - "CN=admins,OU=groups,DC=example,DC=com" -> "admins"
            - "admins" -> "admins"
        """
        names: list[str] = []
        for group in groups:
            if "=" in group:
                # Parse DN to extract CN
                # Handle both "CN=name,..." and "cn=name,..." formats
                parts = group.split(",")
                for part in parts:
                    part = part.strip()
                    if part.upper().startswith("CN="):
                        names.append(part[3:])  # Extract value after "CN="
                        break
                else:
                    # No CN found, use the whole string
                    names.append(group)
            else:
                # Already just a name
                names.append(group)
        return names

    def test_connection(self) -> bool:
        """Test LDAP server connectivity.

        Returns:
            True if connection successful, False otherwise
        """
        if not self.config.enabled:
            return False

        try:
            server = self._get_server()

            # Use bind credentials if provided, otherwise anonymous bind
            if self.config.bind_dn and self.config.bind_password:
                conn = Connection(
                    server,
                    user=self.config.bind_dn,
                    password=self.config.bind_password,
                    auto_bind=True,
                )
            else:
                conn = Connection(server, auto_bind=True)

            conn.unbind()
            return True

        except LDAPException as e:
            logger.error("LDAP connection test failed: %s", e)
            return False


# Singleton instance
_ldap_service: LDAPService | None = None


def get_ldap_service() -> LDAPService:
    """Get the LDAP service singleton."""
    global _ldap_service  # pylint: disable=global-statement
    if _ldap_service is None:
        _ldap_service = LDAPService()
    return _ldap_service


def reset_ldap_service() -> None:
    """Reset the LDAP service singleton (useful for testing)."""
    global _ldap_service  # pylint: disable=global-statement
    _ldap_service = None
