"""Unit tests for the persistence_helpers module."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import httpx

from sbom_graph_enrichment.persistence_helpers import (
    _on_worker_process_init,
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
            internal_prefixes=["group:com.acme"],
        )
