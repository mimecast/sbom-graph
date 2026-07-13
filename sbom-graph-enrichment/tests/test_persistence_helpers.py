"""Unit tests for the persistence_helpers module."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import httpx
import pytest

import sbom_graph_enrichment.persistence_helpers as ph
from sbom_graph_enrichment.persistence_helpers import (
    _on_worker_process_init,
    _on_worker_process_shutdown,
    _reset_persistence,
    create_persistence,
    get_http_client,
    get_persistence,
)


class TestGetPersistence:
    """Tests for the per-process cached get_persistence."""

    def setup_method(self) -> None:
        _reset_persistence()

    def teardown_method(self) -> None:
        _reset_persistence()

    @patch("sbom_graph_enrichment.persistence_helpers.create_persistence")
    def test_creates_once_then_caches(self, mock_create: MagicMock) -> None:
        sentinel = MagicMock(name="persistence-singleton")
        mock_create.return_value = sentinel

        first = get_persistence()
        second = get_persistence()

        assert first is sentinel
        assert second is sentinel
        mock_create.assert_called_once()

    @patch("sbom_graph_enrichment.persistence_helpers.create_persistence")
    def test_reset_clears_cache(self, mock_create: MagicMock) -> None:
        mock_create.return_value = MagicMock()

        get_persistence()
        _reset_persistence()
        get_persistence()

        assert mock_create.call_count == 2


class TestGetHttpClient:
    """Tests for the per-process cached get_http_client."""

    def setup_method(self) -> None:
        _reset_persistence()

    def teardown_method(self) -> None:
        _reset_persistence()

    def test_creates_once_then_caches(self) -> None:
        first = get_http_client()
        second = get_http_client()

        assert first is second
        assert isinstance(first, httpx.Client)

    def test_reset_clears_http_client(self) -> None:
        first = get_http_client()
        _reset_persistence()
        second = get_http_client()

        assert first is not second


class TestWorkerProcessInitSignal:
    """Tests for the worker_process_init signal handler."""

    def setup_method(self) -> None:
        _reset_persistence()

    def teardown_method(self) -> None:
        _reset_persistence()

    @patch("sbom_graph_enrichment.persistence_helpers.create_persistence")
    def test_signal_populates_cache(self, mock_create: MagicMock) -> None:
        sentinel = MagicMock(name="signal-persistence")
        mock_create.return_value = sentinel

        _on_worker_process_init()

        assert get_persistence() is sentinel
        mock_create.assert_called_once()

    @patch("sbom_graph_enrichment.persistence_helpers.create_persistence")
    def test_signal_creates_http_client(self, mock_create: MagicMock) -> None:
        mock_create.return_value = MagicMock()

        _on_worker_process_init()

        client = get_http_client()
        assert isinstance(client, httpx.Client)

    @patch("sbom_graph_enrichment.persistence_helpers.create_persistence")
    def test_get_persistence_uses_signal_instance(self, mock_create: MagicMock) -> None:
        """After the signal fires, get_persistence must not create a new one."""
        sentinel = MagicMock(name="signal-persistence")
        mock_create.return_value = sentinel

        _on_worker_process_init()
        result = get_persistence()

        assert result is sentinel
        mock_create.assert_called_once()

    def test_worker_process_shutdown_closes_and_resets(self) -> None:
        """The shutdown handler must close the per-process httpx client and
        FalkorDB connection (no leak on worker recycle) and clear the globals."""
        mock_client = MagicMock(name="http-client")
        mock_pers = MagicMock(name="persistence")
        ph._process_http_client = mock_client
        ph._process_persistence = mock_pers

        _on_worker_process_shutdown()

        mock_client.close.assert_called_once()
        mock_pers.close.assert_called_once()
        assert ph._process_http_client is None
        assert ph._process_persistence is None


class TestCreatePersistence:
    """Tests for the non-cached create_persistence factory."""

    @patch("sbom_graph_enrichment.persistence_helpers.Persistence")
    def test_reads_env_vars(self, mock_cls: MagicMock, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        monkeypatch.setenv("FALKORDB_HOST", "redis.example.com")
        monkeypatch.setenv("FALKORDB_PORT", "6380")
        monkeypatch.setenv("FALKORDB_GRAPH_NAME", "test-graph")
        monkeypatch.setenv("FALKORDB_PASSWORD", "s3cret")
        monkeypatch.setenv("FALKORDB_SSL", "true")
        monkeypatch.setenv("FALKORDB_CACERTS", "/tls/ca.crt")
        monkeypatch.setenv("INTERNAL_PREFIXES", "group:com.acme")

        mock_cls.parse_internal_prefixes.return_value = ["group:com.acme"]

        create_persistence()

        mock_cls.assert_called_once_with(
            host="redis.example.com",
            port=6380,
            graph_name="test-graph",
            password="s3cret",
            ssl=True,
            ssl_ca_certs="/tls/ca.crt",
            ssl_certfile=None,
            ssl_keyfile=None,
            internal_prefixes=["group:com.acme"],
        )

    @patch("sbom_graph_enrichment.persistence_helpers.Persistence")
    def test_ssl_ca_certs_from_env(
        self, mock_cls: MagicMock, monkeypatch
    ) -> None:  # type: ignore[no-untyped-def]
        monkeypatch.setenv("FALKORDB_PASSWORD", "s3cret")
        monkeypatch.setenv("FALKORDB_CACERTS", "/custom/ca.pem")

        create_persistence()

        mock_cls.assert_called_once()
        call_kwargs = mock_cls.call_args.kwargs
        assert call_kwargs["ssl_ca_certs"] == "/custom/ca.pem"

    @patch("sbom_graph_enrichment.persistence_helpers.Persistence")
    def test_empty_password_fails_closed(
        self, mock_cls: MagicMock, monkeypatch
    ) -> None:  # type: ignore[no-untyped-def]
        """SECURITY (CWE-306): an empty FALKORDB_PASSWORD means the Helm-provisioned
        secret was removed; refuse to connect to an unauthenticated DB."""
        monkeypatch.delenv("FALKORDB_PASSWORD", raising=False)
        monkeypatch.delenv("FALKORDB_ALLOW_NO_AUTH", raising=False)

        with pytest.raises(RuntimeError, match="refusing to connect"):
            create_persistence()
        mock_cls.assert_not_called()

    @patch("sbom_graph_enrichment.persistence_helpers.Persistence")
    def test_empty_password_allowed_with_opt_in(
        self, mock_cls: MagicMock, monkeypatch
    ) -> None:  # type: ignore[no-untyped-def]
        """Local development against an auth-less FalkorDB requires an explicit
        FALKORDB_ALLOW_NO_AUTH=true opt-in."""
        monkeypatch.delenv("FALKORDB_PASSWORD", raising=False)
        monkeypatch.setenv("FALKORDB_ALLOW_NO_AUTH", "true")

        create_persistence()

        mock_cls.assert_called_once()
        assert mock_cls.call_args.kwargs["password"] == ""
