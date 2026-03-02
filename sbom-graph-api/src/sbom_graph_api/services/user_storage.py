"""Local user storage service with password hashing.

This module provides local user authentication storage using SQLite with
secure password hashing via bcrypt/argon2.
"""

import hashlib
import logging
import os
import secrets
from datetime import UTC, datetime

from sqlalchemy import Boolean, Column, DateTime, Integer, String, create_engine
from sqlalchemy.orm import Session, declarative_base, sessionmaker

from sbom_graph_api.config import DatabaseConfig, get_config

logger = logging.getLogger(__name__)

Base = declarative_base()


class LocalUser(Base):
    """SQLAlchemy model for local users."""

    __tablename__ = "local_users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(255), nullable=False, unique=True, index=True)
    password_hash = Column(String(255), nullable=False)
    email = Column(String(255), nullable=True)
    display_name = Column(String(255), nullable=True)
    is_admin = Column(Boolean, nullable=False, default=False)
    is_active = Column(Boolean, nullable=False, default=True)
    must_change_password = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(UTC))
    updated_at = Column(DateTime, nullable=True, onupdate=lambda: datetime.now(UTC))
    last_login_at = Column(DateTime, nullable=True)
    created_by = Column(String(255), nullable=True)  # Username of admin who created


class UserStorageError(Exception):
    """Raised when user storage operations fail."""

    pass


class UserStorageService:
    """Service for managing local users with password authentication."""

    # Password hashing parameters
    HASH_ITERATIONS = 600000  # PBKDF2 iterations (OWASP recommendation)
    SALT_LENGTH = 32

    def __init__(self, config: DatabaseConfig | None = None):
        """Initialize user storage service.

        Args:
            config: Database configuration. If None, loads from environment.
        """
        self.config = config or get_config().database
        self._engine = None
        self._session_factory = None

    def _get_engine(self):
        """Get or create SQLAlchemy engine."""
        if self._engine is None:
            # Ensure directory exists
            db_dir = os.path.dirname(self.config.path)
            if db_dir and not os.path.exists(db_dir):
                os.makedirs(db_dir, mode=0o700)

            # Create SQLite engine (reuse the same DB as tokens)
            self._engine = create_engine(
                f"sqlite:///{self.config.path}",
                echo=False,
                connect_args={"check_same_thread": False},
            )

            # Create tables if they don't exist
            Base.metadata.create_all(self._engine)

            self._session_factory = sessionmaker(bind=self._engine)

        return self._engine

    def _get_session(self) -> Session:
        """Get a new database session."""
        self._get_engine()
        return self._session_factory()

    def _hash_password(self, password: str, salt: bytes | None = None) -> tuple[str, bytes]:
        """Hash a password using PBKDF2-SHA256.

        Args:
            password: The plain text password
            salt: Optional salt (generated if not provided)

        Returns:
            Tuple of (hash_hex, salt)
        """
        if salt is None:
            salt = os.urandom(self.SALT_LENGTH)

        # Use PBKDF2 with SHA-256
        password_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            self.HASH_ITERATIONS,
        )

        # Store as salt:hash in hex format
        combined = salt.hex() + ":" + password_hash.hex()
        return combined, salt

    def _verify_password(self, password: str, stored_hash: str) -> bool:
        """Verify a password against a stored hash.

        Args:
            password: The plain text password to verify
            stored_hash: The stored hash string (salt:hash format)

        Returns:
            True if password matches, False otherwise
        """
        try:
            salt_hex, hash_hex = stored_hash.split(":")
            salt = bytes.fromhex(salt_hex)

            # Compute hash with same salt
            computed_hash, _ = self._hash_password(password, salt)

            # Constant-time comparison
            return secrets.compare_digest(computed_hash, stored_hash)
        except (ValueError, AttributeError):
            return False

    def _generate_temp_password(self, length: int = 16) -> str:
        """Generate a secure temporary password.

        Args:
            length: Password length

        Returns:
            Random password string
        """
        # Use a mix of characters that are easy to read/type
        alphabet = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ23456789"
        return "".join(secrets.choice(alphabet) for _ in range(length))

    def has_any_users(self) -> bool:
        """Check if any users exist in the database.

        Returns:
            True if at least one user exists
        """
        try:
            session = self._get_session()
            count = session.query(LocalUser).count()
            session.close()
            return count > 0
        except Exception as e:
            logger.error(f"Failed to check user count: {e}")
            return False

    def create_user(
        self,
        username: str,
        password: str | None = None,
        email: str | None = None,
        display_name: str | None = None,
        is_admin: bool = False,
        must_change_password: bool = True,
        created_by: str | None = None,
    ) -> tuple[LocalUser | None, str | None]:
        """Create a new local user.

        Args:
            username: Unique username
            password: Password (if None, generates temporary password)
            email: Optional email address
            display_name: Optional display name
            is_admin: Whether user is an admin
            must_change_password: Whether user must change password on login
            created_by: Username of admin who created this user

        Returns:
            Tuple of (LocalUser object, temp_password if generated else None)
        """
        try:
            session = self._get_session()

            # Check if username already exists
            existing = session.query(LocalUser).filter(LocalUser.username == username).first()
            if existing:
                session.close()
                raise UserStorageError(f"Username '{username}' already exists")

            # Generate temp password if not provided
            temp_password = None
            if password is None:
                temp_password = self._generate_temp_password()
                password = temp_password

            password_hash, _ = self._hash_password(password)

            user = LocalUser(
                username=username,
                password_hash=password_hash,
                email=email,
                display_name=display_name or username,
                is_admin=is_admin,
                must_change_password=must_change_password,
                created_by=created_by,
            )

            session.add(user)
            session.commit()

            # Refresh to get the ID
            session.refresh(user)
            user_id = user.id

            session.close()

            logger.info(f"Created user '{username}' (admin={is_admin})")

            # Return a detached copy
            return self.get_user_by_id(user_id), temp_password

        except UserStorageError:
            raise
        except Exception as e:
            logger.error(f"Failed to create user: {e}")
            raise UserStorageError(f"Failed to create user: {e}") from e

    def create_first_user(self, username: str, password: str) -> LocalUser | None:
        """Create the first user as admin (bootstrap).

        This should only be called when no users exist. The first user
        is automatically made an admin and doesn't need to change password.

        Args:
            username: Username for the first user
            password: Password for the first user

        Returns:
            The created LocalUser or None if users already exist
        """
        if self.has_any_users():
            logger.warning("Attempted to create first user when users already exist")
            return None

        try:
            user, _ = self.create_user(
                username=username,
                password=password,
                is_admin=True,
                must_change_password=False,
                created_by="system",
            )
            logger.info(f"Created first admin user: {username}")
            return user
        except Exception as e:
            logger.error(f"Failed to create first user: {e}")
            return None

    def authenticate(self, username: str, password: str) -> LocalUser | None:
        """Authenticate a user with username and password.

        Args:
            username: The username
            password: The password

        Returns:
            LocalUser if authentication succeeds, None otherwise
        """
        try:
            session = self._get_session()

            user = (
                session.query(LocalUser)
                .filter(
                    LocalUser.username == username,
                    LocalUser.is_active == True,  # noqa: E712
                )
                .first()
            )

            if not user:
                session.close()
                return None

            if not self._verify_password(password, user.password_hash):
                session.close()
                return None

            # Update last login time
            user.last_login_at = datetime.now(UTC)
            session.commit()

            # Get user ID before closing session
            user_id = user.id
            session.close()

            # Return fresh copy
            return self.get_user_by_id(user_id)

        except Exception as e:
            logger.error(f"Authentication error: {e}")
            return None

    def get_user_by_id(self, user_id: int) -> LocalUser | None:
        """Get a user by ID.

        Args:
            user_id: The user ID

        Returns:
            LocalUser or None if not found
        """
        try:
            session = self._get_session()
            user = session.query(LocalUser).filter(LocalUser.id == user_id).first()

            if user:
                # Create a detached copy
                session.expunge(user)

            session.close()
            return user
        except Exception as e:
            logger.error(f"Failed to get user by ID: {e}")
            return None

    def get_user_by_username(self, username: str) -> LocalUser | None:
        """Get a user by username.

        Args:
            username: The username

        Returns:
            LocalUser or None if not found
        """
        try:
            session = self._get_session()
            user = session.query(LocalUser).filter(LocalUser.username == username).first()

            if user:
                session.expunge(user)

            session.close()
            return user
        except Exception as e:
            logger.error(f"Failed to get user by username: {e}")
            return None

    def list_users(self) -> list[LocalUser]:
        """List all users.

        Returns:
            List of LocalUser objects
        """
        try:
            session = self._get_session()
            users = session.query(LocalUser).order_by(LocalUser.username).all()

            # Detach all users
            for user in users:
                session.expunge(user)

            session.close()
            return users
        except Exception as e:
            logger.error(f"Failed to list users: {e}")
            return []

    def change_password(
        self,
        username: str,
        old_password: str,
        new_password: str,
    ) -> bool:
        """Change a user's password (requires old password).

        Args:
            username: The username
            old_password: Current password for verification
            new_password: New password to set

        Returns:
            True if password changed successfully
        """
        try:
            session = self._get_session()

            user = session.query(LocalUser).filter(LocalUser.username == username).first()

            if not user:
                session.close()
                return False

            # Verify old password
            if not self._verify_password(old_password, user.password_hash):
                session.close()
                return False

            # Set new password
            new_hash, _ = self._hash_password(new_password)
            user.password_hash = new_hash
            user.must_change_password = False
            user.updated_at = datetime.now(UTC)

            session.commit()
            session.close()

            logger.info(f"Password changed for user '{username}'")
            return True

        except Exception as e:
            logger.error(f"Failed to change password: {e}")
            return False

    def reset_password(self, username: str, admin_username: str) -> str | None:
        """Reset a user's password (admin action).

        Args:
            username: The username to reset
            admin_username: The admin performing the reset

        Returns:
            The new temporary password, or None if failed
        """
        try:
            session = self._get_session()

            user = session.query(LocalUser).filter(LocalUser.username == username).first()

            if not user:
                session.close()
                return None

            # Generate new temporary password
            temp_password = self._generate_temp_password()
            new_hash, _ = self._hash_password(temp_password)

            user.password_hash = new_hash
            user.must_change_password = True
            user.updated_at = datetime.now(UTC)

            session.commit()
            session.close()

            logger.info(f"Password reset for user '{username}' by admin '{admin_username}'")
            return temp_password

        except Exception as e:
            logger.error(f"Failed to reset password: {e}")
            return None

    def set_admin(self, username: str, is_admin: bool, admin_username: str) -> bool:
        """Set or remove admin status for a user.

        Args:
            username: The username to modify
            is_admin: New admin status
            admin_username: The admin performing the action

        Returns:
            True if successful
        """
        try:
            session = self._get_session()

            user = session.query(LocalUser).filter(LocalUser.username == username).first()

            if not user:
                session.close()
                return False

            user.is_admin = is_admin
            user.updated_at = datetime.now(UTC)

            session.commit()
            session.close()

            action = "granted admin to" if is_admin else "removed admin from"
            logger.info(f"Admin '{admin_username}' {action} user '{username}'")
            return True

        except Exception as e:
            logger.error(f"Failed to set admin status: {e}")
            return False

    def set_active(self, username: str, is_active: bool, admin_username: str) -> bool:
        """Enable or disable a user account.

        Args:
            username: The username to modify
            is_active: New active status
            admin_username: The admin performing the action

        Returns:
            True if successful
        """
        try:
            session = self._get_session()

            user = session.query(LocalUser).filter(LocalUser.username == username).first()

            if not user:
                session.close()
                return False

            user.is_active = is_active
            user.updated_at = datetime.now(UTC)

            session.commit()
            session.close()

            action = "enabled" if is_active else "disabled"
            logger.info(f"Admin '{admin_username}' {action} user '{username}'")
            return True

        except Exception as e:
            logger.error(f"Failed to set active status: {e}")
            return False

    def delete_user(self, username: str, admin_username: str) -> bool:
        """Delete a user account.

        Args:
            username: The username to delete
            admin_username: The admin performing the action

        Returns:
            True if successful
        """
        try:
            session = self._get_session()

            user = session.query(LocalUser).filter(LocalUser.username == username).first()

            if not user:
                session.close()
                return False

            session.delete(user)
            session.commit()
            session.close()

            logger.info(f"Admin '{admin_username}' deleted user '{username}'")
            return True

        except Exception as e:
            logger.error(f"Failed to delete user: {e}")
            return False

    def update_user(
        self,
        username: str,
        email: str | None = None,
        display_name: str | None = None,
    ) -> bool:
        """Update user profile information.

        Args:
            username: The username to update
            email: New email (or None to keep current)
            display_name: New display name (or None to keep current)

        Returns:
            True if successful
        """
        try:
            session = self._get_session()

            user = session.query(LocalUser).filter(LocalUser.username == username).first()

            if not user:
                session.close()
                return False

            if email is not None:
                user.email = email
            if display_name is not None:
                user.display_name = display_name

            user.updated_at = datetime.now(UTC)

            session.commit()
            session.close()

            logger.info(f"Updated profile for user '{username}'")
            return True

        except Exception as e:
            logger.error(f"Failed to update user: {e}")
            return False


# Singleton instance
_user_storage: UserStorageService | None = None


def get_user_storage() -> UserStorageService:
    """Get the user storage service singleton."""
    global _user_storage
    if _user_storage is None:
        _user_storage = UserStorageService()
    return _user_storage


def reset_user_storage() -> None:
    """Reset the user storage singleton (useful for testing)."""
    global _user_storage
    _user_storage = None
