"""Kubernetes-friendly FalkorDB / Redis host resolution.

When Cluster DNS in a pod cannot resolve a Service name (misconfigured CoreDNS,
search-path quirks, etc.), kubelet-injected `service link`_ environment variables
still expose the Service ClusterIP. Those variables are enabled by default
(``enableServiceLinks`` on the Pod spec).

This resolver lets callers fall back to the service-link ClusterIP when DNS is
unavailable, but the behaviour is **opt-in** to avoid silently breaking TLS.

Why opt-in?
    The Python redis client validates the TLS certificate against the host in
    the connection URL.  Replacing a DNS name with a ClusterIP causes the
    ``CERTIFICATE_VERIFY_FAILED: IP address mismatch`` error because the cert
    SAN is the cluster DNS name, not the ClusterIP.  Since this failure mode
    is silent and easy to misdiagnose, the resolver only consults service-link
    env vars when ``FALKORDB_USE_SERVICE_LINK=true`` is set.

When is it safe to enable?
    Only when **TLS to FalkorDB is disabled** AND cluster DNS resolution is
    unavailable in the pod.  Otherwise leave it off (the default) and either
    rely on cluster DNS or set ``FALKORDB_HOST`` explicitly to a hostname that
    matches the cert SAN.

The Helm chart ``wait-for-falkordb`` init container handles the same fallback
in shell, but it pairs the IP-based connection with ``--sni`` so TLS still
validates against the DNS SAN.  Python redis has no equivalent escape hatch.

.. _service link:
   https://kubernetes.io/docs/concepts/services-networking/connect-applications-service/#accessing-the-service
"""

from __future__ import annotations

import os
import re

_IPV4 = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")
_OPT_IN_ENV = "FALKORDB_USE_SERVICE_LINK"


def _is_opt_in_enabled() -> bool:
    """Return True when the caller has explicitly enabled service-link fallback."""
    return os.environ.get(_OPT_IN_ENV, "").strip().lower() in {"true", "1", "yes"}


def resolve_k8s_service_link_host(host: str) -> str:
    """Return the host to use for the FalkorDB / Redis connection.

    By default this returns ``host`` unchanged (apart from stripping whitespace
    and substituting ``"localhost"`` for empty input).  The kubelet-injected
    service-link ClusterIP is only consulted when the opt-in environment
    variable ``FALKORDB_USE_SERVICE_LINK=true`` is set.

    Opt-in service-link behaviour:
        For Service ``metadata.name`` ``sbom-graph-falkordb``, kubelet adds
        ``SBOM_GRAPH_FALKORDB_SERVICE_HOST`` in the same namespace.  The key
        is the service name uppercased with ``-`` replaced by ``_``, suffixed
        with ``_SERVICE_HOST``.  When opted in and a matching key is set, the
        ClusterIP is returned.  IPv4 inputs and missing link keys still
        return ``host`` unchanged.

    Args:
        host: Value of ``FALKORDB_HOST`` (short name, FQDN, or IPv4 literal).

    Returns:
        - ``"localhost"`` when ``host`` is empty / whitespace.
        - ``host`` (stripped) when:
            - ``FALKORDB_USE_SERVICE_LINK`` is not enabled (default), OR
            - ``host`` is already an IPv4 literal, OR
            - the matching ``*_SERVICE_HOST`` env var is unset.
        - The ClusterIP from ``*_SERVICE_HOST`` when opted in and present.
    """
    raw = (host or "").strip()
    if not raw:
        return "localhost"

    if not _is_opt_in_enabled():
        return raw

    m = _IPV4.fullmatch(raw)
    if m is not None and all(0 <= int(g) <= 255 for g in m.groups()):
        return raw

    short = raw.split(".", 1)[0]
    if not short:
        return raw

    link_key = short.upper().replace("-", "_") + "_SERVICE_HOST"
    linked = os.environ.get(link_key, "").strip()
    return linked if linked else raw
