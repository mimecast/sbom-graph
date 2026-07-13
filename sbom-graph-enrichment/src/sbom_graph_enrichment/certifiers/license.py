"""ClearlyDefined certifier -- discovers license information for packages.

Queries the ClearlyDefined API to resolve declared and discovered licenses.

Security note (SSRF):
    :func:`_purl_to_coordinates` constructs a URL *path* from PURL
    components that ultimately originate from user-uploaded SBOMs.  SSRF is
    mitigated by the following layered controls:

    1. **Hardcoded host** -- the request always targets
       ``api.clearlydefined.io``; the purl only populates the path portion.
    2. **Allowlisted package types** -- ``_purl_to_coordinates`` rejects any
       purl whose type is not in the ``provider_map``, returning ``None``.
    3. **Connection-pooled httpx.Client** -- the shared client is configured
       with a 30 s timeout, preventing slow-loris style resource exhaustion.
    4. **NetworkPolicy** -- when enabled, the Helm chart restricts worker
       egress to port 443 on public IPs and the FalkorDB pod on port 6379,
       blocking any lateral movement inside the cluster.

    No additional action is needed unless the certifier is extended to accept
    a user-controllable base URL.
"""

from __future__ import annotations

import logging
import re
from typing import Any
from urllib.parse import quote, unquote

import httpx

from sbom_graph_model import LicenseRiskCategory

from .base import Certifier, Finding, FindingKind


def _cd_segment(segment: str) -> str:
    """Normalise a PURL-derived ClearlyDefined path segment.

    Decode-then-encode (``quote(unquote(...), safe="")``) so that ``/`` and
    ``..`` cannot introduce path separators / traversal into the fixed
    ClearlyDefined host (CWE-22), while avoiding double-encoding of PURL fields
    that are already percent-encoded (e.g. npm ``%40`` scopes).
    """
    return quote(unquote(segment), safe="")



logger = logging.getLogger(__name__)

CLEARLY_DEFINED_API = "https://api.clearlydefined.io/definitions"

_PURL_RE = re.compile(
    r"^pkg:(?P<type>[^/]+)/(?:(?P<ns>[^/]+)/)?(?P<name>[^@]+)@(?P<version>.+)$"
)

_GOLANG_PURL_RE = re.compile(
    r"^pkg:golang/(?P<path>.+)@(?P<version>.+)$"
)

_RISK_CATEGORIES: dict[str, str] = {
    "MIT": LicenseRiskCategory.PERMISSIVE,
    "Apache-2.0": LicenseRiskCategory.PERMISSIVE,
    "BSD-2-Clause": LicenseRiskCategory.PERMISSIVE,
    "BSD-3-Clause": LicenseRiskCategory.PERMISSIVE,
    "ISC": LicenseRiskCategory.PERMISSIVE,
    "0BSD": LicenseRiskCategory.PERMISSIVE,
    "Unlicense": LicenseRiskCategory.PERMISSIVE,
    "CC0-1.0": LicenseRiskCategory.PERMISSIVE,
    "WTFPL": LicenseRiskCategory.PERMISSIVE,
    "Zlib": LicenseRiskCategory.PERMISSIVE,
    "LGPL-2.0-only": LicenseRiskCategory.WEAK_COPYLEFT,
    "LGPL-2.1-only": LicenseRiskCategory.WEAK_COPYLEFT,
    "LGPL-3.0-only": LicenseRiskCategory.WEAK_COPYLEFT,
    "LGPL-2.0-or-later": LicenseRiskCategory.WEAK_COPYLEFT,
    "LGPL-2.1-or-later": LicenseRiskCategory.WEAK_COPYLEFT,
    "LGPL-3.0-or-later": LicenseRiskCategory.WEAK_COPYLEFT,
    "MPL-2.0": LicenseRiskCategory.WEAK_COPYLEFT,
    "EPL-1.0": LicenseRiskCategory.WEAK_COPYLEFT,
    "EPL-2.0": LicenseRiskCategory.WEAK_COPYLEFT,
    "CDDL-1.0": LicenseRiskCategory.WEAK_COPYLEFT,
    "GPL-2.0-only": LicenseRiskCategory.STRONG_COPYLEFT,
    "GPL-2.0-or-later": LicenseRiskCategory.STRONG_COPYLEFT,
    "GPL-3.0-only": LicenseRiskCategory.STRONG_COPYLEFT,
    "GPL-3.0-or-later": LicenseRiskCategory.STRONG_COPYLEFT,
    "AGPL-3.0-only": LicenseRiskCategory.STRONG_COPYLEFT,
    "AGPL-3.0-or-later": LicenseRiskCategory.STRONG_COPYLEFT,
    "SSPL-1.0": LicenseRiskCategory.STRONG_COPYLEFT,
    "EUPL-1.2": LicenseRiskCategory.STRONG_COPYLEFT,
}


def classify_license(spdx_id: str) -> str:
    """Return the risk category for a given SPDX identifier."""
    return _RISK_CATEGORIES.get(spdx_id, LicenseRiskCategory.UNKNOWN)


class LicenseCertifier(Certifier):
    """Fetches license data from the ClearlyDefined API."""

    @property
    def name(self) -> str:
        return "clearlydefined"

    def enrich(self, purl: str, *, client: httpx.Client) -> list[Finding]:
        coord = _purl_to_coordinates(purl)
        if coord is None:
            logger.warning(
                "Cannot convert purl to ClearlyDefined coordinates: %s", purl
            )
            return []

        url = f"{CLEARLY_DEFINED_API}/{coord}"
        resp = client.get(url)
        if resp.status_code == 404:
            logger.debug("ClearlyDefined has no data for %s", purl)
            return []
        resp.raise_for_status()
        if not resp.content:
            logger.debug("ClearlyDefined has no data for %s", purl)
            return []
        body = resp.json()

        return _parse_response(purl, body)


def _golang_purl_to_coordinates(purl: str) -> str | None:
    """Convert a golang purl to ClearlyDefined coordinates.

    ClearlyDefined uses coordinate type ``go`` and splits the import path at
    the last ``/``: everything before is the namespace (with ``/`` encoded
    as ``%2F``), the final segment is the package name.

    Example: ``pkg:golang/github.com/gorilla/context@v1.0.0``
    becomes ``go/golang/github.com%2Fgorilla/context/v1.0.0``.
    """
    m = _GOLANG_PURL_RE.match(purl)
    if not m:
        return None

    path = m.group("path")
    version = m.group("version")
    if "/" in path:
        namespace, name = path.rsplit("/", 1)
    else:
        namespace = "-"
        name = path

    return f"go/golang/{_cd_segment(namespace)}/{_cd_segment(name)}/{_cd_segment(version)}"


def _purl_to_coordinates(purl: str) -> str | None:
    """Convert a purl to ClearlyDefined coordinate path.

    Example: ``pkg:maven/org.apache/commons-lang3@3.12.0``
    becomes ``maven/mavencentral/org.apache/commons-lang3/3.12.0``.
    """
    if purl.startswith("pkg:golang/"):
        return _golang_purl_to_coordinates(purl)

    m = _PURL_RE.match(purl)
    if not m:
        return None

    ptype = m.group("type")
    ns = m.group("ns") or "-"
    name = m.group("name")
    version = m.group("version")

    provider_map = {
        "maven": "mavencentral",
        "npm": "npmjs",
        "pypi": "pypi",
        "nuget": "nuget",
        "gem": "rubygems",
        "cargo": "cratesio",
    }
    provider = provider_map.get(ptype)
    if provider is None:
        return None

    return f"{ptype}/{provider}/{_cd_segment(ns)}/{_cd_segment(name)}/{_cd_segment(version)}"


def _parse_response(purl: str, body: dict[str, Any]) -> list[Finding]:
    """Extract license findings from the ClearlyDefined response."""
    licensed = body.get("licensed", {})
    declared = licensed.get("declared")
    discovered = licensed.get("discovered", {}).get("expressions", [])

    spdx_ids: set[str] = set()
    if declared and declared != "NOASSERTION":
        spdx_ids.add(declared)
    for expr in discovered:
        if expr and expr != "NOASSERTION":
            spdx_ids.add(expr)

    findings: list[Finding] = []
    for spdx_id in sorted(spdx_ids):
        findings.append(
            Finding(
                kind=FindingKind.LICENSE,
                source="clearlydefined",
                package_url=purl,
                data={
                    "spdx_id": spdx_id,
                    "name": spdx_id,
                    "risk_category": classify_license(spdx_id),
                },
            )
        )

    if findings:
        logger.info("ClearlyDefined returned %d licenses for %s", len(findings), purl)
    return findings
