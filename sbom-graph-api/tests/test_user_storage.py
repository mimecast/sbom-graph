"""Tests for local user storage service with password hashing."""

import pytest

from sbom_graph_api.config import DatabaseConfig
from sbom_graph_api.services.user_storage import (
    UserStorageError,
    UserStorageService,
    get_user_storage,
    reset_user_storage,
)


@pytest.fixture
def db_config(tmp_path):
    """Create a database config pointing to a temp directory."""
    return DatabaseConfig(
        path=str(tmp_path / "test-users.db"),
        encryption_key="test-encryption-key",
    )


@pytest.fixture
def user_service(db_config):
    """Create a fresh UserStorageService for each test."""
    service = UserStorageService(config=db_config)
    yield service
    reset_user_storage()


class TestPasswordHashing:
    """Tests for password hashing and verification."""

    def test_hash_produces_salt_colon_hash_format(self, user_service):
        combined, _salt = user_service._hash_password("mypassword")
        assert ":" in combined
        parts = combined.split(":")
        assert len(parts) == 2
        assert len(parts[0]) == 64  # 32 bytes hex = 64 chars
        assert len(parts[1]) > 0

    def test_verify_correct_password(self, user_service):
        combined, _ = user_service._hash_password("correct-password")
        assert user_service._verify_password("correct-password", combined) is True

    def test_verify_wrong_password(self, user_service):
        combined, _ = user_service._hash_password("correct-password")
        assert user_service._verify_password("wrong-password", combined) is False

    def test_different_passwords_produce_different_hashes(self, user_service):
        hash1, _ = user_service._hash_password("password1")
        hash2, _ = user_service._hash_password("password2")
        assert hash1 != hash2

    def test_same_password_different_salt(self, user_service):
        """Same password with different salts produces different hashes."""
        hash1, _ = user_service._hash_password("same-password")
        hash2, _ = user_service._hash_password("same-password")
        assert hash1 != hash2

    def test_verify_malformed_hash_returns_false(self, user_service):
        assert user_service._verify_password("password", "not-a-valid-hash") is False

    def test_verify_empty_hash_returns_false(self, user_service):
        assert user_service._verify_password("password", "") is False


class TestTempPasswordGeneration:
    """Tests for temporary password generation."""

    def test_generates_string_of_correct_length(self, user_service):
        password = user_service._generate_temp_password()
        assert len(password) == 16

    def test_custom_length(self, user_service):
        password = user_service._generate_temp_password(length=32)
        assert len(password) == 32

    def test_passwords_are_unique(self, user_service):
        passwords = {user_service._generate_temp_password() for _ in range(50)}
        assert len(passwords) == 50


class TestHasAnyUsers:
    """Tests for has_any_users method."""

    def test_empty_database(self, user_service):
        assert user_service.has_any_users() is False

    def test_after_creating_user(self, user_service):
        user_service.create_user("alice", "password123")
        assert user_service.has_any_users() is True


class TestCreateUser:
    """Tests for user creation."""

    # Positive tests

    def test_create_with_password(self, user_service):
        user, temp = user_service.create_user("alice", "my-password")
        assert user is not None
        assert user.username == "alice"
        assert temp is None  # No temp password when explicit password given

    def test_create_without_password_generates_temp(self, user_service):
        user, temp = user_service.create_user("alice")
        assert user is not None
        assert temp is not None
        assert len(temp) == 16

    def test_create_with_all_fields(self, user_service):
        user, _ = user_service.create_user(
            username="alice",
            password="pass123",
            email="alice@example.com",
            display_name="Alice Smith",
            is_admin=True,
            must_change_password=False,
            created_by="system",
        )
        assert user.email == "alice@example.com"
        assert user.display_name == "Alice Smith"
        assert user.is_admin is True
        assert user.must_change_password is False

    def test_default_must_change_password(self, user_service):
        user, _ = user_service.create_user("alice", "password")
        assert user.must_change_password is True

    def test_default_not_admin(self, user_service):
        user, _ = user_service.create_user("alice", "password")
        assert user.is_admin is False

    def test_display_name_defaults_to_username(self, user_service):
        user, _ = user_service.create_user("alice", "password")
        assert user.display_name == "alice"

    # Negative tests

    def test_duplicate_username_raises(self, user_service):
        user_service.create_user("alice", "password")
        with pytest.raises(UserStorageError, match="already exists"):
            user_service.create_user("alice", "different-password")


class TestCreateFirstUser:
    """Tests for first user bootstrap."""

    def test_first_user_is_admin(self, user_service):
        user = user_service.create_first_user("admin", "admin-pass")
        assert user is not None
        assert user.is_admin is True
        assert user.must_change_password is False

    def test_returns_none_if_users_exist(self, user_service):
        user_service.create_user("existing", "password")
        result = user_service.create_first_user("admin", "admin-pass")
        assert result is None


class TestAuthenticate:
    """Tests for user authentication."""

    # Positive tests

    def test_valid_credentials(self, user_service):
        user_service.create_user("alice", "correct-password", must_change_password=False)
        user = user_service.authenticate("alice", "correct-password")
        assert user is not None
        assert user.username == "alice"

    def test_updates_last_login(self, user_service):
        user_service.create_user("alice", "password", must_change_password=False)
        user = user_service.authenticate("alice", "password")
        assert user.last_login_at is not None

    # Negative tests

    def test_wrong_password(self, user_service):
        user_service.create_user("alice", "correct-password")
        assert user_service.authenticate("alice", "wrong-password") is None

    def test_nonexistent_user(self, user_service):
        assert user_service.authenticate("nobody", "password") is None

    def test_inactive_user_rejected(self, user_service):
        user_service.create_user("alice", "password")
        user_service.set_active("alice", False, "admin")
        assert user_service.authenticate("alice", "password") is None


class TestGetUser:
    """Tests for user retrieval."""

    def test_get_by_id(self, user_service):
        created, _ = user_service.create_user("alice", "password")
        found = user_service.get_user_by_id(created.id)
        assert found is not None
        assert found.username == "alice"

    def test_get_by_username(self, user_service):
        user_service.create_user("alice", "password")
        found = user_service.get_user_by_username("alice")
        assert found is not None
        assert found.username == "alice"

    def test_get_nonexistent_by_id(self, user_service):
        assert user_service.get_user_by_id(99999) is None

    def test_get_nonexistent_by_username(self, user_service):
        assert user_service.get_user_by_username("nobody") is None


class TestListUsers:
    """Tests for listing users."""

    def test_empty_list(self, user_service):
        assert user_service.list_users() == []

    def test_returns_all_users_ordered(self, user_service):
        user_service.create_user("charlie", "p1")
        user_service.create_user("alice", "p2")
        user_service.create_user("bob", "p3")

        users = user_service.list_users()
        assert len(users) == 3
        assert [u.username for u in users] == ["alice", "bob", "charlie"]


class TestChangePassword:
    """Tests for password change."""

    def test_successful_change(self, user_service):
        user_service.create_user("alice", "old-pass")
        result = user_service.change_password("alice", "old-pass", "new-pass")
        assert result is True

    def test_can_authenticate_with_new_password(self, user_service):
        user_service.create_user("alice", "old-pass", must_change_password=False)
        user_service.change_password("alice", "old-pass", "new-pass")
        assert user_service.authenticate("alice", "new-pass") is not None

    def test_old_password_no_longer_works(self, user_service):
        user_service.create_user("alice", "old-pass", must_change_password=False)
        user_service.change_password("alice", "old-pass", "new-pass")
        assert user_service.authenticate("alice", "old-pass") is None

    def test_clears_must_change_flag(self, user_service):
        user_service.create_user("alice", "temp-pass", must_change_password=True)
        user_service.change_password("alice", "temp-pass", "new-pass")
        user = user_service.get_user_by_username("alice")
        assert user.must_change_password is False

    def test_wrong_old_password_fails(self, user_service):
        user_service.create_user("alice", "real-pass")
        result = user_service.change_password("alice", "wrong-pass", "new-pass")
        assert result is False

    def test_nonexistent_user_fails(self, user_service):
        result = user_service.change_password("nobody", "old", "new")
        assert result is False


class TestResetPassword:
    """Tests for admin password reset."""

    def test_returns_temp_password(self, user_service):
        user_service.create_user("alice", "original")
        temp = user_service.reset_password("alice", "admin")
        assert temp is not None
        assert len(temp) == 16

    def test_sets_must_change_flag(self, user_service):
        user_service.create_user("alice", "original", must_change_password=False)
        user_service.reset_password("alice", "admin")
        user = user_service.get_user_by_username("alice")
        assert user.must_change_password is True

    def test_can_authenticate_with_temp_password(self, user_service):
        user_service.create_user("alice", "original", must_change_password=False)
        temp = user_service.reset_password("alice", "admin")
        user = user_service.authenticate("alice", temp)
        assert user is not None

    def test_nonexistent_user_returns_none(self, user_service):
        assert user_service.reset_password("nobody", "admin") is None


class TestAdminOperations:
    """Tests for admin user management operations."""

    def test_set_admin_true(self, user_service):
        user_service.create_user("alice", "pass", is_admin=False)
        assert user_service.set_admin("alice", True, "superadmin") is True
        user = user_service.get_user_by_username("alice")
        assert user.is_admin is True

    def test_set_admin_false(self, user_service):
        user_service.create_user("alice", "pass", is_admin=True)
        assert user_service.set_admin("alice", False, "superadmin") is True
        user = user_service.get_user_by_username("alice")
        assert user.is_admin is False

    def test_set_admin_nonexistent_user(self, user_service):
        assert user_service.set_admin("nobody", True, "admin") is False

    def test_set_active_false(self, user_service):
        user_service.create_user("alice", "pass")
        assert user_service.set_active("alice", False, "admin") is True
        user = user_service.get_user_by_username("alice")
        assert user.is_active is False

    def test_set_active_true(self, user_service):
        user_service.create_user("alice", "pass")
        user_service.set_active("alice", False, "admin")
        assert user_service.set_active("alice", True, "admin") is True
        user = user_service.get_user_by_username("alice")
        assert user.is_active is True

    def test_set_active_nonexistent_user(self, user_service):
        assert user_service.set_active("nobody", False, "admin") is False

    def test_delete_user(self, user_service):
        user_service.create_user("alice", "pass")
        assert user_service.delete_user("alice", "admin") is True
        assert user_service.get_user_by_username("alice") is None

    def test_delete_nonexistent_user(self, user_service):
        assert user_service.delete_user("nobody", "admin") is False


class TestUpdateUser:
    """Tests for updating user profile."""

    def test_update_email(self, user_service):
        user_service.create_user("alice", "pass")
        assert user_service.update_user("alice", email="new@example.com") is True
        user = user_service.get_user_by_username("alice")
        assert user.email == "new@example.com"

    def test_update_display_name(self, user_service):
        user_service.create_user("alice", "pass")
        assert user_service.update_user("alice", display_name="Alice S.") is True
        user = user_service.get_user_by_username("alice")
        assert user.display_name == "Alice S."

    def test_update_both(self, user_service):
        user_service.create_user("alice", "pass")
        result = user_service.update_user("alice", email="a@b.com", display_name="A")
        assert result is True

    def test_update_nonexistent_user(self, user_service):
        assert user_service.update_user("nobody", email="x@y.com") is False

    def test_none_values_keep_current(self, user_service):
        user_service.create_user("alice", "pass", email="orig@example.com")
        user_service.update_user("alice", display_name="New Name")
        user = user_service.get_user_by_username("alice")
        assert user.email == "orig@example.com"
        assert user.display_name == "New Name"


class TestSingletonFunctions:
    """Tests for module-level singleton functions."""

    def test_reset_clears_singleton(self):
        reset_user_storage()
        s1 = get_user_storage()
        reset_user_storage()
        s2 = get_user_storage()
        assert s1 is not s2

    def test_get_returns_same_instance(self):
        reset_user_storage()
        s1 = get_user_storage()
        s2 = get_user_storage()
        assert s1 is s2
        reset_user_storage()
