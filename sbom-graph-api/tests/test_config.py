"""Tests for configuration module."""

import os
from unittest.mock import patch

import pytest

from sbom_graph_api.config import (
    AppConfig,
    FalkorDBConfig,
    get_config,
    reset_config,
)


class TestFalkorDBConfig:
    """Tests for FalkorDBConfig class."""

    # Positive tests

    def test_from_env_with_defaults(self, monkeypatch):
        """Test loading config with default values."""
        # Delete any existing environment variables to test defaults
        for var in [
            "FALKORDB_HOST",
            "FALKORDB_PORT",
            "FALKORDB_PASSWORD",
            "FALKORDB_GRAPH_NAME",
            "FALKORDB_SOCKET_TIMEOUT",
            "FALKORDB_CONNECT_TIMEOUT",
            "FALKORDB_INTERNAL_LABEL",
        ]:
            monkeypatch.delenv(var, raising=False)

        config = FalkorDBConfig.from_env()

        assert config.host == "localhost"
        assert config.port == 6379
        assert config.password is None
        assert config.graph_name == "acme_corp"
        assert config.internal_label == "INTERNAL"

    def test_from_env_with_custom_values(self):
        """Test loading config with custom environment values."""
        env_vars = {
            "FALKORDB_HOST": "custom-host",
            "FALKORDB_PORT": "6380",
            "FALKORDB_PASSWORD": "secret123",
            "FALKORDB_GRAPH_NAME": "custom-graph",
        }
        with patch.dict(os.environ, env_vars, clear=True):
            config = FalkorDBConfig.from_env()

        assert config.host == "custom-host"
        assert config.port == 6380
        assert config.password == "secret123"
        assert config.graph_name == "custom-graph"

    def test_from_env_with_partial_values(self):
        """Test loading config with some custom values."""
        env_vars = {
            "FALKORDB_HOST": "partial-host",
        }
        with patch.dict(os.environ, env_vars, clear=True):
            config = FalkorDBConfig.from_env()

        assert config.host == "partial-host"
        assert config.port == 6379  # default
        assert config.password is None  # default
        assert config.graph_name == "acme_corp"  # default

    # Negative tests

    def test_from_env_with_invalid_port(self):
        """Test that invalid port value raises ValueError."""
        env_vars = {
            "FALKORDB_PORT": "not-a-number",
        }
        with patch.dict(os.environ, env_vars, clear=True):
            with pytest.raises(ValueError):
                FalkorDBConfig.from_env()

    def test_from_env_with_empty_port(self):
        """Test that empty port falls back to default."""
        env_vars = {
            "FALKORDB_PORT": "",
        }
        with patch.dict(os.environ, env_vars, clear=True):
            with pytest.raises(ValueError):
                FalkorDBConfig.from_env()


class TestAppConfig:
    """Tests for AppConfig class."""

    # Positive tests

    def test_from_env_with_defaults(self):
        """Test loading app config with defaults."""
        with patch.dict(os.environ, {}, clear=True):
            config = AppConfig.from_env()

        assert config.debug is False
        assert config.host == "0.0.0.0"
        assert config.port == 8080
        assert config.secret_key == "dev-secret-key-change-in-production"
        assert config.falkordb is not None

    def test_from_env_with_debug_true(self):
        """Test debug mode enabled."""
        env_vars = {"FLASK_DEBUG": "true"}
        with patch.dict(os.environ, env_vars, clear=True):
            config = AppConfig.from_env()

        assert config.debug is True

    def test_from_env_with_debug_false(self):
        """Test debug mode disabled explicitly."""
        env_vars = {"FLASK_DEBUG": "false"}
        with patch.dict(os.environ, env_vars, clear=True):
            config = AppConfig.from_env()

        assert config.debug is False

    def test_from_env_with_custom_values(self):
        """Test loading app config with custom values."""
        env_vars = {
            "FLASK_DEBUG": "TRUE",  # case insensitive
            "FLASK_HOST": "127.0.0.1",
            "FLASK_PORT": "5000",
            "FLASK_SECRET_KEY": "my-secret",
        }
        with patch.dict(os.environ, env_vars, clear=True):
            config = AppConfig.from_env()

        assert config.debug is True
        assert config.host == "127.0.0.1"
        assert config.port == 5000
        assert config.secret_key == "my-secret"

    # Negative tests

    def test_from_env_with_invalid_flask_port(self):
        """Test invalid Flask port raises error."""
        env_vars = {"FLASK_PORT": "invalid"}
        with patch.dict(os.environ, env_vars, clear=True):
            with pytest.raises(ValueError):
                AppConfig.from_env()


class TestGetConfig:
    """Tests for get_config singleton function."""

    def setup_method(self):
        """Reset config before each test."""
        reset_config()

    def teardown_method(self):
        """Reset config after each test."""
        reset_config()

    def test_get_config_returns_singleton(self):
        """Test that get_config returns the same instance."""
        with patch.dict(os.environ, {}, clear=True):
            config1 = get_config()
            config2 = get_config()

        assert config1 is config2

    def test_reset_config_clears_singleton(self):
        """Test that reset_config clears the singleton."""
        with patch.dict(os.environ, {"FLASK_HOST": "first"}, clear=True):
            config1 = get_config()
            assert config1.host == "first"

        reset_config()

        with patch.dict(os.environ, {"FLASK_HOST": "second"}, clear=True):
            config2 = get_config()
            assert config2.host == "second"

        assert config1 is not config2
