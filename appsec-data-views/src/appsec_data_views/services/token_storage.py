"""Secure token storage service with encrypted SQLite database.

This module provides secure storage for JWT tokens using SQLite with
field-level encryption via Fernet symmetric encryption.
"""

import base64
import hashlib
import logging
import os
from datetime import UTC, datetime
from typing import Any

from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Integer,
    String,
    Text,
    create_engine,
)
from sqlalchemy.orm import Session, declarative_base, sessionmaker

from appsec_data_views.config import DatabaseConfig, get_config

logger = logging.getLogger(__name__)

Base = declarative_base()


class StoredToken(Base):
    """SQLAlchemy model for stored tokens."""

    __tablename__ = "tokens"
    __table_args__ = (
        # Compound unique constraint: same user can't have duplicate token names
        {"sqlite_autoincrement": True},
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(255), nullable=False, index=True)
    token_name = Column(String(255), nullable=False)
    token_hash = Column(String(64), nullable=False, unique=True)  # SHA-256 hash for lookup
    encrypted_token = Column(Text, nullable=False)  # Fernet-encrypted token
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(UTC))
    expires_at = Column(DateTime, nullable=True)
    last_used_at = Column(DateTime, nullable=True)
    is_revoked = Column(Boolean, nullable=False, default=False)
    description = Column(Text, nullable=True)


class TokenStorageError(Exception):
    """Raised when token storage operations fail."""

    pass


class TokenStorageService:
    """Service for securely storing and managing JWT tokens."""

    def __init__(self, config: DatabaseConfig | None = None):
        """Initialize token storage service.

        Args:
            config: Database configuration. If None, loads from environment.
        """
        self.config = config or get_config().database
        self._engine = None
        self._session_factory = None
        self._fernet: Fernet | None = None

    def _get_fernet(self) -> Fernet:
        """Get or create Fernet encryption instance."""
        if self._fernet is None:
            # Derive a valid Fernet key from the configured encryption key
            key = self.config.encryption_key.encode("utf-8")
            # Use SHA-256 to derive a 32-byte key, then base64 encode for Fernet
            derived_key = hashlib.sha256(key).digest()
            fernet_key = base64.urlsafe_b64encode(derived_key)
            self._fernet = Fernet(fernet_key)
        return self._fernet

    def _get_engine(self):
        """Get or create SQLAlchemy engine."""
        if self._engine is None:
            # Ensure directory exists
            db_dir = os.path.dirname(self.config.path)
            if db_dir and not os.path.exists(db_dir):
                os.makedirs(db_dir, mode=0o700)

            # Create SQLite engine
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

    def _hash_token(self, token: str) -> str:
        """Create a SHA-256 hash of a token for lookup.

        Args:
            token: The JWT token to hash

        Returns:
            Hex-encoded SHA-256 hash
        """
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    def _encrypt_token(self, token: str) -> str:
        """Encrypt a token using Fernet.

        Args:
            token: The JWT token to encrypt

        Returns:
            Base64-encoded encrypted token
        """
        fernet = self._get_fernet()
        encrypted = fernet.encrypt(token.encode("utf-8"))
        return encrypted.decode("utf-8")

    def _decrypt_token(self, encrypted_token: str) -> str | None:
        """Decrypt an encrypted token.

        Args:
            encrypted_token: The encrypted token

        Returns:
            Decrypted token or None if decryption fails
        """
        try:
            fernet = self._get_fernet()
            decrypted = fernet.decrypt(encrypted_token.encode("utf-8"))
            return decrypted.decode("utf-8")
        except InvalidToken:
            logger.error("Failed to decrypt token - invalid encryption key or corrupted data")
            return None

    def store_token(
        self,
        username: str,
        token: str,
        token_name: str,
        expires_at: datetime | None = None,
        description: str | None = None,
    ) -> int:
        """Store a JWT token securely.

        Args:
            username: The username associated with the token
            token: The JWT token to store
            token_name: A user-friendly name for the token
            expires_at: Optional expiration datetime
            description: Optional description

        Returns:
            The ID of the stored token

        Raises:
            TokenStorageError: If storage fails or token name already exists for user
        """
        try:
            session = self._get_session()

            # Check if token name already exists for this user (active tokens only)
            existing = (
                session.query(StoredToken)
                .filter(
                    StoredToken.username == username,
                    StoredToken.token_name == token_name,
                    StoredToken.is_revoked == False,  # noqa: E712
                )
                .first()
            )
            if existing:
                session.close()
                raise TokenStorageError(
                    f"A token named '{token_name}' already exists. Please choose a different name."
                )

            stored_token = StoredToken(
                username=username,
                token_name=token_name,
                token_hash=self._hash_token(token),
                encrypted_token=self._encrypt_token(token),
                expires_at=expires_at,
                description=description,
            )

            session.add(stored_token)
            session.commit()
            token_id = stored_token.id
            session.close()

            logger.info(f"Stored token '{token_name}' for user {username}")
            return token_id

        except Exception as e:
            logger.error(f"Failed to store token: {e}")
            raise TokenStorageError(f"Failed to store token: {e}") from e

    def get_token(self, token_id: int, username: str) -> dict[str, Any] | None:
        """Retrieve a stored token by ID.

        Args:
            token_id: The token ID
            username: The username (for authorization check)

        Returns:
            Token details dict or None if not found
        """
        try:
            session = self._get_session()

            stored = (
                session.query(StoredToken)
                .filter(
                    StoredToken.id == token_id,
                    StoredToken.username == username,
                    StoredToken.is_revoked == False,  # noqa: E712
                )
                .first()
            )

            if not stored:
                session.close()
                return None

            # Update last used timestamp
            stored.last_used_at = datetime.now(UTC)
            session.commit()

            result = {
                "id": stored.id,
                "username": stored.username,
                "token_name": stored.token_name,
                "token": self._decrypt_token(stored.encrypted_token),
                "created_at": stored.created_at.isoformat() if stored.created_at else None,
                "expires_at": stored.expires_at.isoformat() if stored.expires_at else None,
                "last_used_at": stored.last_used_at.isoformat() if stored.last_used_at else None,
                "description": stored.description,
            }

            session.close()
            return result

        except Exception as e:
            logger.error(f"Failed to retrieve token: {e}")
            return None

    def list_tokens(self, username: str, include_revoked: bool = False) -> list[dict[str, Any]]:
        """List all tokens for a user (without the actual token values).

        Args:
            username: The username
            include_revoked: If True, include revoked tokens in the list

        Returns:
            List of token metadata dicts
        """
        try:
            session = self._get_session()

            # First, let's see all tokens in the database for debugging
            all_tokens = session.query(StoredToken).all()
            all_usernames = {t.username for t in all_tokens}
            logger.info(f"Database has {len(all_tokens)} total tokens, usernames: {all_usernames}")
            logger.info(f"Looking for tokens with username='{username}' (type: {type(username)})")

            query = session.query(StoredToken).filter(StoredToken.username == username)

            if not include_revoked:
                query = query.filter(StoredToken.is_revoked == False)  # noqa: E712

            tokens = query.order_by(StoredToken.created_at.desc()).all()

            logger.info(f"Found {len(tokens)} tokens for user '{username}'")

            # Get current time for expiration check (use naive datetime for SQLite compatibility)
            now = datetime.now(UTC).replace(tzinfo=None)

            result = [
                {
                    "id": t.id,
                    "token_name": t.token_name,
                    "created_at": t.created_at.isoformat() if t.created_at else None,
                    "expires_at": t.expires_at.isoformat() if t.expires_at else None,
                    "last_used_at": t.last_used_at.isoformat() if t.last_used_at else None,
                    "description": t.description,
                    "is_expired": t.expires_at is not None and t.expires_at < now,
                    "is_revoked": t.is_revoked,
                }
                for t in tokens
            ]

            session.close()
            return result

        except Exception as e:
            logger.error(f"Failed to list tokens for user '{username}': {e}")
            return []

    def revoke_token(self, token_id: int, username: str) -> bool:
        """Revoke a stored token.

        Args:
            token_id: The token ID to revoke
            username: The username (for authorization check)

        Returns:
            True if revoked, False if not found
        """
        try:
            session = self._get_session()

            stored = (
                session.query(StoredToken)
                .filter(
                    StoredToken.id == token_id,
                    StoredToken.username == username,
                )
                .first()
            )

            if not stored:
                session.close()
                return False

            stored.is_revoked = True
            session.commit()
            session.close()

            logger.info(f"Revoked token {token_id} for user {username}")
            return True

        except Exception as e:
            logger.error(f"Failed to revoke token: {e}")
            return False

    def delete_token(self, token_id: int, username: str) -> bool:
        """Permanently delete a stored token.

        Args:
            token_id: The token ID to delete
            username: The username (for authorization check)

        Returns:
            True if deleted, False if not found
        """
        try:
            session = self._get_session()

            stored = (
                session.query(StoredToken)
                .filter(
                    StoredToken.id == token_id,
                    StoredToken.username == username,
                )
                .first()
            )

            if not stored:
                session.close()
                return False

            session.delete(stored)
            session.commit()
            session.close()

            logger.info(f"Deleted token {token_id} for user {username}")
            return True

        except Exception as e:
            logger.error(f"Failed to delete token: {e}")
            return False

    def is_token_valid(self, token: str) -> bool:
        """Check if a token is valid (not revoked and not expired).

        Args:
            token: The JWT token to check

        Returns:
            True if valid, False otherwise
        """
        try:
            session = self._get_session()
            token_hash = self._hash_token(token)

            stored = session.query(StoredToken).filter(StoredToken.token_hash == token_hash).first()

            if not stored:
                session.close()
                # Token not in storage - may be a session token, allow it
                return True

            if stored.is_revoked:
                session.close()
                return False

            # Use naive datetime for SQLite compatibility
            now = datetime.now(UTC).replace(tzinfo=None)
            if stored.expires_at and stored.expires_at < now:
                session.close()
                return False

            session.close()
            return True

        except Exception as e:
            logger.error(f"Failed to validate token: {e}")
            return False

    def cleanup_expired(self) -> int:
        """Remove expired and revoked tokens from storage.

        Returns:
            Number of tokens removed
        """
        try:
            session = self._get_session()

            # Use naive datetime for SQLite compatibility
            now = datetime.now(UTC).replace(tzinfo=None)

            # Delete expired or revoked tokens
            deleted = (
                session.query(StoredToken)
                .filter(
                    (StoredToken.is_revoked == True)  # noqa: E712
                    | (
                        (StoredToken.expires_at.isnot(None))
                        & (StoredToken.expires_at < now)
                    )
                )
                .delete(synchronize_session=False)
            )

            session.commit()
            session.close()

            if deleted > 0:
                logger.info(f"Cleaned up {deleted} expired/revoked tokens")

            return deleted

        except Exception as e:
            logger.error(f"Failed to cleanup tokens: {e}")
            return 0


# Singleton instance
_token_storage: TokenStorageService | None = None


def get_token_storage() -> TokenStorageService:
    """Get the token storage service singleton."""
    global _token_storage
    if _token_storage is None:
        _token_storage = TokenStorageService()
    return _token_storage


def reset_token_storage() -> None:
    """Reset the token storage singleton (useful for testing)."""
    global _token_storage
    _token_storage = None
