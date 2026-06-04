"""Tests for Kubernetes service-link host resolution.

The resolver returns the input host unchanged by default; service-link ClusterIP
fallback is only consulted when ``FALKORDB_USE_SERVICE_LINK=true`` is set.
This avoids silently breaking TLS hostname verification in the common case.
"""

import os

import pytest

from sbom_graph_model.k8s_service_host import resolve_k8s_service_link_host


@pytest.fixture
def clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Remove all *_SERVICE_HOST env vars and the opt-in flag for a clean slate."""
    for key in list(os.environ):
        if key.endswith("_SERVICE_HOST"):
            monkeypatch.delenv(key, raising=False)
    monkeypatch.delenv("FALKORDB_USE_SERVICE_LINK", raising=False)


@pytest.fixture
def opt_in(monkeypatch: pytest.MonkeyPatch, clean_env: None) -> None:
    """Enable opt-in service-link resolution."""
    monkeypatch.setenv("FALKORDB_USE_SERVICE_LINK", "true")


# ---------------------------------------------------------------------------
# Default behaviour: opt-in disabled, host returned unchanged
# ---------------------------------------------------------------------------


def test_empty_uses_localhost(clean_env: None) -> None:
    assert resolve_k8s_service_link_host("") == "localhost"
    assert resolve_k8s_service_link_host("  ") == "localhost"


def test_ipv4_unchanged_default(clean_env: None) -> None:
    assert resolve_k8s_service_link_host("10.96.0.1") == "10.96.0.1"


def test_default_returns_host_unchanged_even_when_link_set(
    monkeypatch: pytest.MonkeyPatch, clean_env: None
) -> None:
    """Without opt-in, service-link env var must be ignored to preserve TLS validation."""
    monkeypatch.setenv("SBOM_GRAPH_FALKORDB_SERVICE_HOST", "10.96.12.34")
    assert (
        resolve_k8s_service_link_host(
            "sbom-graph-falkordb.sbom-graph.svc.cluster.local"
        )
        == "sbom-graph-falkordb.sbom-graph.svc.cluster.local"
    )


def test_default_strips_whitespace(clean_env: None) -> None:
    assert resolve_k8s_service_link_host("  example.com  ") == "example.com"


# ---------------------------------------------------------------------------
# Opt-in behaviour: FALKORDB_USE_SERVICE_LINK=true
# ---------------------------------------------------------------------------


def test_optin_fqdn_uses_service_link(
    monkeypatch: pytest.MonkeyPatch, opt_in: None
) -> None:
    monkeypatch.setenv("SBOM_GRAPH_FALKORDB_SERVICE_HOST", "10.96.12.34")
    assert (
        resolve_k8s_service_link_host(
            "sbom-graph-falkordb.sbom-graph.svc.cluster.local"
        )
        == "10.96.12.34"
    )


def test_optin_short_name_uses_service_link(
    monkeypatch: pytest.MonkeyPatch, opt_in: None
) -> None:
    monkeypatch.setenv("MYREL_FALKORDB_SERVICE_HOST", "10.0.0.5")
    assert resolve_k8s_service_link_host("myrel-falkordb") == "10.0.0.5"


def test_optin_no_link_returns_original(opt_in: None) -> None:
    h = "sbom-graph-falkordb.sbom-graph.svc.cluster.local"
    assert resolve_k8s_service_link_host(h) == h


def test_optin_ipv4_unchanged(monkeypatch: pytest.MonkeyPatch, opt_in: None) -> None:
    """An IPv4 input is never replaced (we already have the address)."""
    monkeypatch.setenv("SBOM_GRAPH_FALKORDB_SERVICE_HOST", "10.96.12.34")
    assert resolve_k8s_service_link_host("10.96.0.1") == "10.96.0.1"


# ---------------------------------------------------------------------------
# Opt-in flag parsing: accept multiple truthy values, reject everything else
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("value", ["true", "TRUE", "True", "1", "yes", "YES"])
def test_optin_truthy_values(
    monkeypatch: pytest.MonkeyPatch, clean_env: None, value: str
) -> None:
    monkeypatch.setenv("FALKORDB_USE_SERVICE_LINK", value)
    monkeypatch.setenv("SBOM_GRAPH_FALKORDB_SERVICE_HOST", "10.96.12.34")
    assert (
        resolve_k8s_service_link_host(
            "sbom-graph-falkordb.sbom-graph.svc.cluster.local"
        )
        == "10.96.12.34"
    )


@pytest.mark.parametrize("value", ["false", "0", "no", "off", "", "  "])
def test_optin_falsy_values(
    monkeypatch: pytest.MonkeyPatch, clean_env: None, value: str
) -> None:
    monkeypatch.setenv("FALKORDB_USE_SERVICE_LINK", value)
    monkeypatch.setenv("SBOM_GRAPH_FALKORDB_SERVICE_HOST", "10.96.12.34")
    h = "sbom-graph-falkordb.sbom-graph.svc.cluster.local"
    assert resolve_k8s_service_link_host(h) == h
