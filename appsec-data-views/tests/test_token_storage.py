"""Tests for token storage service with encrypted SQLite database."""

from datetime import UTC, datetime, timedelta

import pytest

from appsec_data_views.config import DatabaseConfig
from appsec_data_views.services.token_storage import (
    TokenStorageError,
    TokenStorageService,
    get_token_storage,
    reset_token_storage,
)


@pytest.fixture
def db_config(tmp_path):
    """Create a database config pointing to a temp directory."""
    return DatabaseConfig(
        path=str(tmp_path / "test-tokens.db"),
        encryption_key="test-encryption-key-for-testing-purposes",
    )


@pytest.fixture
def token_service(db_config):
    """Create a fresh TokenStorageService for each test."""
    service = TokenStorageService(config=db_config)
    yield service
    reset_token_storage()


class TestTokenEncryption:
    """Tests for token encryption and decryption round-trip."""

    def test_encrypt_decrypt_round_trip(self, token_service):
        """Token can be encrypted and decrypted back to original."""
        original = "eyJhbGciOiJIUzI1NiJ9.test-payload.signature"
        encrypted = token_service._encrypt_token(original)
        decrypted = token_service._decrypt_token(encrypted)
        assert decrypted == original

    def test_encrypted_differs_from_original(self, token_service):
        encrypted = token_service._encrypt_token("my-secret-token")
        assert encrypted != "my-secret-token"

    def test_decrypt_invalid_data_returns_none(self, token_service):
        assert token_service._decrypt_token("not-valid-fernet-data") is None

    def test_hash_is_deterministic(self, token_service):
        token = "test-token-value"
        hash1 = token_service._hash_token(token)
        hash2 = token_service._hash_token(token)
        assert hash1 == hash2

    def test_different_tokens_produce_different_hashes(self, token_service):
        hash1 = token_service._hash_token("token-a")
        hash2 = token_service._hash_token("token-b")
        assert hash1 != hash2


class TestStoreToken:
    """Tests for storing tokens."""

    # Positive tests

    def test_store_returns_id(self, token_service):
        token_id = token_service.store_token(
            username="alice",
            token="jwt-token-value",
            token_name="My API Token",
        )
        assert isinstance(token_id, int)
        assert token_id > 0

    def test_store_with_all_fields(self, token_service):
        expires = datetime.now(UTC).replace(tzinfo=None) + timedelta(days=30)
        token_id = token_service.store_token(
            username="alice",
            token="jwt-token",
            token_name="Full Token",
            expires_at=expires,
            description="A test token with all fields",
        )
        assert token_id > 0

    def test_store_multiple_tokens_different_names(self, token_service):
        id1 = token_service.store_token("alice", "token-1", "Token A")
        id2 = token_service.store_token("alice", "token-2", "Token B")
        assert id1 != id2

    def test_same_name_different_users(self, token_service):
        """Different users can use the same token name."""
        id1 = token_service.store_token("alice", "token-1", "My Token")
        id2 = token_service.store_token("bob", "token-2", "My Token")
        assert id1 != id2

    # Negative tests

    def test_duplicate_name_same_user_raises(self, token_service):
        token_service.store_token("alice", "token-1", "My Token")
        with pytest.raises(TokenStorageError, match="already exists"):
            token_service.store_token("alice", "token-2", "My Token")

    def test_revoked_name_can_be_reused(self, token_service):
        """A revoked token's name can be reused by the same user."""
        token_id = token_service.store_token("alice", "token-1", "Reusable Name")
        token_service.revoke_token(token_id, "alice")
        new_id = token_service.store_token("alice", "token-2", "Reusable Name")
        assert new_id > token_id


class TestGetToken:
    """Tests for retrieving tokens."""

    # Positive tests

    def test_get_stored_token(self, token_service):
        token_id = token_service.store_token("alice", "my-jwt-token", "Test Token")
        result = token_service.get_token(token_id, "alice")
        assert result is not None
        assert result["id"] == token_id
        assert result["username"] == "alice"
        assert result["token_name"] == "Test Token"
        assert result["token"] == "my-jwt-token"

    def test_get_updates_last_used(self, token_service):
        token_id = token_service.store_token("alice", "token", "Test")
        result = token_service.get_token(token_id, "alice")
        assert result["last_used_at"] is not None

    # Negative tests

    def test_wrong_user_returns_none(self, token_service):
        token_id = token_service.store_token("alice", "token", "Test")
        assert token_service.get_token(token_id, "bob") is None

    def test_revoked_returns_none(self, token_service):
        token_id = token_service.store_token("alice", "token", "Test")
        token_service.revoke_token(token_id, "alice")
        assert token_service.get_token(token_id, "alice") is None

    def test_nonexistent_id_returns_none(self, token_service):
        assert token_service.get_token(99999, "alice") is None


class TestListTokens:
    """Tests for listing user tokens."""

    def test_empty_list(self, token_service):
        tokens = token_service.list_tokens("alice")
        assert tokens == []

    def test_lists_own_tokens(self, token_service):
        token_service.store_token("alice", "t1", "Token A")
        token_service.store_token("alice", "t2", "Token B")
        token_service.store_token("bob", "t3", "Token C")

        tokens = token_service.list_tokens("alice")
        assert len(tokens) == 2
        names = {t["token_name"] for t in tokens}
        assert names == {"Token A", "Token B"}

    def test_excludes_revoked_by_default(self, token_service):
        id1 = token_service.store_token("alice", "t1", "Active")
        id2 = token_service.store_token("alice", "t2", "Revoked")
        token_service.revoke_token(id2, "alice")

        tokens = token_service.list_tokens("alice")
        assert len(tokens) == 1
        assert tokens[0]["token_name"] == "Active"

    def test_includes_revoked_when_requested(self, token_service):
        id1 = token_service.store_token("alice", "t1", "Active")
        id2 = token_service.store_token("alice", "t2", "Revoked")
        token_service.revoke_token(id2, "alice")

        tokens = token_service.list_tokens("alice", include_revoked=True)
        assert len(tokens) == 2

    def test_expired_flag(self, token_service):
        past = datetime.now(UTC).replace(tzinfo=None) - timedelta(days=1)
        token_service.store_token("alice", "t1", "Expired", expires_at=past)

        tokens = token_service.list_tokens("alice")
        assert len(tokens) == 1
        assert tokens[0]["is_expired"] is True

    def test_token_value_not_in_list(self, token_service):
        """List should not include actual token values."""
        token_service.store_token("alice", "secret-jwt", "Test")
        tokens = token_service.list_tokens("alice")
        assert "token" not in tokens[0]


class TestRevokeToken:
    """Tests for token revocation."""

    def test_revoke_success(self, token_service):
        token_id = token_service.store_token("alice", "token", "Test")
        assert token_service.revoke_token(token_id, "alice") is True

    def test_revoke_wrong_user(self, token_service):
        token_id = token_service.store_token("alice", "token", "Test")
        assert token_service.revoke_token(token_id, "bob") is False

    def test_revoke_nonexistent(self, token_service):
        assert token_service.revoke_token(99999, "alice") is False


class TestDeleteToken:
    """Tests for token deletion."""

    def test_delete_success(self, token_service):
        token_id = token_service.store_token("alice", "token", "Test")
        assert token_service.delete_token(token_id, "alice") is True
        assert token_service.get_token(token_id, "alice") is None

    def test_delete_wrong_user(self, token_service):
        token_id = token_service.store_token("alice", "token", "Test")
        assert token_service.delete_token(token_id, "bob") is False

    def test_delete_nonexistent(self, token_service):
        assert token_service.delete_token(99999, "alice") is False


class TestIsTokenValid:
    """Tests for token validity checking."""

    def test_unknown_token_is_valid(self, token_service):
        """Tokens not in storage (session tokens) are considered valid."""
        assert token_service.is_token_valid("not-stored-anywhere") is True

    def test_stored_active_token_is_valid(self, token_service):
        token = "my-stored-jwt"
        token_service.store_token("alice", token, "Test")
        assert token_service.is_token_valid(token) is True

    def test_revoked_token_is_invalid(self, token_service):
        token = "revoked-jwt"
        token_id = token_service.store_token("alice", token, "Test")
        token_service.revoke_token(token_id, "alice")
        assert token_service.is_token_valid(token) is False

    def test_expired_token_is_invalid(self, token_service):
        token = "expired-jwt"
        past = datetime.now(UTC).replace(tzinfo=None) - timedelta(days=1)
        token_service.store_token("alice", token, "Expired", expires_at=past)
        assert token_service.is_token_valid(token) is False


class TestCleanupExpired:
    """Tests for expired token cleanup."""

    def test_cleanup_removes_expired(self, token_service):
        past = datetime.now(UTC).replace(tzinfo=None) - timedelta(days=1)
        token_service.store_token("alice", "t1", "Expired", expires_at=past)
        token_service.store_token("alice", "t2", "Active")

        deleted = token_service.cleanup_expired()
        assert deleted == 1

        tokens = token_service.list_tokens("alice")
        assert len(tokens) == 1
        assert tokens[0]["token_name"] == "Active"

    def test_cleanup_removes_revoked(self, token_service):
        token_id = token_service.store_token("alice", "t1", "Revoked")
        token_service.revoke_token(token_id, "alice")

        deleted = token_service.cleanup_expired()
        assert deleted == 1

    def test_cleanup_nothing_to_remove(self, token_service):
        token_service.store_token("alice", "t1", "Active")
        deleted = token_service.cleanup_expired()
        assert deleted == 0


class TestSingletonFunctions:
    """Tests for module-level singleton functions."""

    def test_reset_clears_singleton(self, db_config):
        reset_token_storage()
        service1 = get_token_storage()
        reset_token_storage()
        service2 = get_token_storage()
        assert service1 is not service2

    def test_get_returns_same_instance(self):
        reset_token_storage()
        service1 = get_token_storage()
        service2 = get_token_storage()
        assert service1 is service2
        reset_token_storage()
