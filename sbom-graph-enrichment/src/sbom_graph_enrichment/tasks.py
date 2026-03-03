"""Celery tasks for the enrichment pipeline.

Tasks run synchronously -- Celery's prefork pool provides concurrency
and each certifier makes at most one HTTP request per invocation, so
async I/O adds complexity without benefit.  A shared :class:`httpx.Client`
is cached per worker process alongside the :class:`Persistence` instance
to enable TCP/TLS connection pooling.
"""

from __future__ import annotations

import logging
from typing import Any

from celery import shared_task

from sbom_graph_model import Defect, VersionDefect, Version, Project

from .certifiers.base import Finding, FindingKind
from .certifiers.osv import OSVCertifier
from .certifiers.license import LicenseCertifier
from .persistence_helpers import create_persistence, get_persistence, get_http_client

logger = logging.getLogger(__name__)

_CERTIFIERS = {
    "osv": OSVCertifier,
    "clearlydefined": LicenseCertifier,
}


@shared_task(bind=True, max_retries=3, default_retry_delay=60)
def enrich_package(self: Any, purl: str, sources: list[str] | None = None) -> dict[str, Any]:
    """Enrich a single package identified by *purl*.

    Args:
        purl: The package URL to enrich.
        sources: Optional list of certifier names to run.
            Defaults to all registered certifiers.

    Returns:
        Summary dict with counts per finding kind.
    """
    if sources is None:
        sources = list(_CERTIFIERS.keys())

    http_client = get_http_client()
    all_findings: list[Finding] = []
    for source_name in sources:
        cls = _CERTIFIERS.get(source_name)
        if cls is None:
            logger.warning("Unknown certifier: %s", source_name)
            continue
        certifier = cls()
        try:
            findings = certifier.enrich(purl, client=http_client)
            all_findings.extend(findings)
        except Exception as exc:
            logger.exception("Certifier %s failed for %s", source_name, purl)
            raise self.retry(exc=exc)

    persistence = get_persistence()
    vuln_count = 0
    license_count = 0

    for finding in all_findings:
        if finding.kind == FindingKind.VULNERABILITY:
            _persist_vulnerability(persistence, finding)
            vuln_count += 1
        elif finding.kind == FindingKind.LICENSE:
            _persist_license(persistence, finding)
            license_count += 1

    return {
        "purl": purl,
        "vulnerabilities": vuln_count,
        "licenses": license_count,
    }


_DISPATCH_BATCH_SIZE = 500


@shared_task
def enrich_all_packages(sources: list[str] | None = None) -> dict[str, int]:
    """Fan-out enrichment for every package in the graph.

    Queries the graph for all distinct purls and dispatches
    :func:`enrich_package` tasks in batches to avoid overwhelming
    the broker with very large SBOM graphs.
    """
    persistence = create_persistence()
    result = persistence.run_query(
        query="MATCH (v:Version) WHERE v.package_url IS NOT NULL RETURN DISTINCT v.package_url AS purl"
    )
    purls: list[str] = [row["purl"] for row in result.result_set if row.get("purl")]

    logger.info("Dispatching enrichment for %d packages in batches of %d", len(purls), _DISPATCH_BATCH_SIZE)
    for i in range(0, len(purls), _DISPATCH_BATCH_SIZE):
        batch = purls[i : i + _DISPATCH_BATCH_SIZE]
        for purl in batch:
            enrich_package.delay(purl, sources)
        logger.debug("Dispatched batch %d-%d of %d", i, i + len(batch), len(purls))

    return {"dispatched": len(purls)}


def _persist_vulnerability(persistence: Any, finding: Finding) -> None:
    """Create or update a Defect node from a vulnerability finding."""
    data = finding.data
    defect = Defect()
    defect.id = data.get("id", "")
    defect.severity = data.get("severity")
    defect.source = (finding.source, "")
    defect.cvss_string = data.get("cvss_vector")
    defect.description = data.get("summary")
    defect.aliases = data.get("aliases", [])
    defect.enrichment_source = finding.source
    defect.last_enriched_at = finding.timestamp.isoformat()

    persistence.create_defect(defect=defect)

    purl = finding.package_url
    for row in persistence.get_versions_by_purl(purl):
        version = Version()
        version.version = row.get("name")
        project = Project()
        project.name = row.get("project_name")
        project.group = row.get("project_group")
        project.purl = purl
        version.project = project

        vd = VersionDefect()
        vd.defect = defect
        vd.project_version = version
        persistence.create_version_defect(version_defect=vd)


def _persist_license(persistence: Any, finding: Finding) -> None:
    """Create or update a License node and HAS_LICENSE edge."""
    data = finding.data
    spdx_id = data.get("spdx_id", "")
    name = data.get("name", spdx_id)
    risk_category = data.get("risk_category", "unknown")

    persistence.create_license(
        spdx_id=spdx_id,
        name=name,
        risk_category=risk_category,
    )

    purl = finding.package_url
    persistence.create_version_license(purl=purl, spdx_id=spdx_id)
