"""Celery tasks for the enrichment pipeline.

Tasks run synchronously -- Celery's prefork pool provides concurrency
and each certifier makes at most one HTTP request per invocation, so
async I/O adds complexity without benefit.  A shared :class:`httpx.Client`
is cached per worker process alongside the :class:`Persistence` instance
to enable TCP/TLS connection pooling.
"""

from __future__ import annotations

import json
import logging
import os
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any

import redis
from celery import shared_task

from sbom_graph_model import Defect, VersionDefect, Version, Project

from .celery_app import BROKER_URL
from .certifiers.base import Finding, FindingKind
from .certifiers.osv import OSVCertifier
from .certifiers.license import LicenseCertifier
from .certifiers.scorecard import ScorecardCertifier
from .certifiers.ossindex import OSSIndexCertifier
from .certifiers.depsdev import DepsDevCertifier
from .certifiers.eol import EOLCertifier
from .certifiers.source_repo import SourceRepoCertifier
from .certifiers.trust_score import TrustScoreCalculator
from .persistence_helpers import get_http_client, get_persistence

logger = logging.getLogger(__name__)

_CERTIFIERS: dict[str, type] = {
    "osv": OSVCertifier,
    "clearlydefined": LicenseCertifier,
    "scorecard": ScorecardCertifier,
    "ossindex": OSSIndexCertifier,
    "depsdev": DepsDevCertifier,
    "eol": EOLCertifier,
    "source_repo": SourceRepoCertifier,
}


@shared_task(bind=True, max_retries=3, default_retry_delay=60)
def enrich_package(
    self: Any, purl: str, sources: list[str] | None = None
) -> dict[str, Any]:
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
    eol_count = 0
    source_repo_count = 0
    depsdev_count = 0

    for finding in all_findings:
        if finding.kind == FindingKind.VULNERABILITY:
            _persist_vulnerability(persistence, finding)
            vuln_count += 1
        elif finding.kind == FindingKind.LICENSE:
            _persist_license(persistence, finding)
            license_count += 1
        elif finding.kind == FindingKind.EOL:
            _persist_eol(persistence, finding)
            eol_count += 1
        elif finding.kind == FindingKind.SOURCE_REPO:
            _persist_source_repo(persistence, finding)
            source_repo_count += 1
        elif finding.kind == FindingKind.DEPSDEV:
            _persist_depsdev(persistence, finding)
            depsdev_count += 1

    # Stamp the canonical "package was fully enriched" timestamp.  Only
    # written when every certifier in `sources` succeeded -- a transient
    # failure raises self.retry above and never reaches this point, so
    # the freshness filter in `enrich_all_packages` will pick the purl
    # up again on the next beat tick.
    persistence.run_query(
        query=("MATCH (v:Version {package_url: $purl}) SET v.last_enriched_at = $ts"),
        params={
            "purl": purl,
            "ts": datetime.now(timezone.utc).isoformat(),
        },
    )

    if _TRUST_SCORE_ENABLED and all_findings:
        compute_trust_score.delay(purl, _serialise_findings(all_findings))

    return {
        "purl": purl,
        "vulnerabilities": vuln_count,
        "licenses": license_count,
        "eol": eol_count,
        "source_repo": source_repo_count,
        "depsdev": depsdev_count,
    }


_DISPATCH_BATCH_SIZE = 500

# Use 90% of the configured interval as the freshness cutoff so a beat tick
# that runs slightly slow does not lag the previous one and accidentally
# re-enqueue work that was just completed.
_ENRICHMENT_INTERVAL_SECONDS = int(os.environ.get("ENRICHMENT_INTERVAL", "3600"))
_FRESHNESS_CUTOFF_SECONDS = max(int(_ENRICHMENT_INTERVAL_SECONDS * 0.9), 1)

# ``last_enriched_at`` only advances when a dispatched task actually
# *completes*.  If the worker pool falls behind (or stalls entirely -- e.g.
# an OOM-restart loop), purls dispatched on one beat tick are still sitting
# in the queue, unprocessed, on the next tick.  The freshness filter alone
# can't see that: it re-queries the same "not yet enriched" purls and
# re-dispatches a full duplicate batch on top of the one still stuck,
# compounding every cycle.  ``enrichment_queued_at`` closes that gap: a
# purl dispatched within the last ``_QUEUED_STALE_SECONDS`` is skipped on
# the next tick even though it hasn't completed yet.  Set generously above
# a single interval so a task that's merely slow (not lost) isn't
# re-dispatched out from under itself; a task whose worker genuinely lost
# the message becomes eligible again once this window elapses.
_QUEUED_STALE_SECONDS = max(int(_ENRICHMENT_INTERVAL_SECONDS * 2), 1)

# Hard backpressure ceiling on the `enrichment` broker queue depth. Even with
# the dispatch-time guard above, a sustained worker outage should stop this
# task from adding more work rather than trusting the guard alone -- this is
# the belt to the guard's suspenders. Checked via a direct LLEN against the
# broker (the same Redis instance FalkorDB and the graph share), not via
# Celery's inspect API, which talks to live workers rather than the broker
# and would report nothing useful when the worker pool is down -- exactly
# the scenario this exists to catch.
_QUEUE_BACKPRESSURE_THRESHOLD = int(
    os.environ.get("ENRICHMENT_QUEUE_BACKPRESSURE_THRESHOLD", "5000")
)


def _enrichment_queue_depth() -> int | None:
    """Return the current length of the ``enrichment`` broker queue.

    Returns ``None`` if the depth can't be determined (broker unreachable,
    etc.) -- callers should treat that as "unknown" and proceed rather than
    blocking dispatch on a diagnostic that itself just failed.
    """
    try:
        client = redis.Redis.from_url(BROKER_URL)
        try:
            # redis-py's stubs type `llen` to cover both the sync and async
            # client via a shared generic base, so it reports a union
            # including Awaitable[int] even though `redis.Redis` (as
            # opposed to `redis.asyncio.Redis`) always returns plain int.
            return int(client.llen("enrichment"))  # type: ignore[arg-type]
        finally:
            client.close()
    except Exception:  # pylint: disable=broad-exception-caught
        logger.warning("Unable to determine enrichment queue depth", exc_info=True)
        return None


@shared_task
def enrich_all_packages(
    sources: list[str] | None = None,
    force: bool = False,
) -> dict[str, Any]:
    """Fan-out enrichment for every package in the graph.

    Only dispatches :func:`enrich_package` tasks for purls whose
    ``last_enriched_at`` is older than ``_FRESHNESS_CUTOFF_SECONDS``
    (or has never been enriched) *and* whose ``enrichment_queued_at``
    (if any) is older than ``_QUEUED_STALE_SECONDS``. In steady state
    this means each beat tick dispatches a small number of tasks
    (newly-ingested packages, or packages whose certifier set changed)
    rather than the entire graph -- without the freshness filter a
    single missed beat tick caused the queue to grow by tens of
    thousands of tasks that could not be drained fast enough, eventually
    OOM-killing FalkorDB; without the queued-at guard, a worker pool that
    stalls entirely (rather than merely falling behind) causes the same
    purls to be re-dispatched on every subsequent tick since none of them
    ever reach ``last_enriched_at``, growing the backlog without bound.

    A queue-depth backpressure check runs before dispatch: if the
    ``enrichment`` broker queue is already past
    ``ENRICHMENT_QUEUE_BACKPRESSURE_THRESHOLD`` (default 5000), this task
    skips dispatching entirely rather than adding to a backlog the worker
    pool has already demonstrably fallen behind on.

    Args:
        sources: Optional list of certifier names to run for each
            dispatched task.  ``None`` (the default) runs every
            registered certifier.
        force: When ``True``, bypass the freshness filter and
            re-enrich every package in the graph.  Intended for
            manual / on-demand use (e.g. after a schema change or
            certifier addition); never set this from the periodic
            beat schedule.
    """
    # Reuse the per-process cached Persistence (one FalkorDB connection per
    # worker) instead of opening a fresh connection pool on every beat tick,
    # which would leak connections/sockets over the worker's lifetime.
    persistence = get_persistence()

    if force:
        query = (
            "MATCH (v:Version) WHERE v.package_url IS NOT NULL "
            "RETURN DISTINCT v.package_url AS purl"
        )
        params: dict[str, Any] = {}
    else:
        now = datetime.now(timezone.utc)
        cutoff_iso = (now - timedelta(seconds=_FRESHNESS_CUTOFF_SECONDS)).isoformat()
        queued_cutoff_iso = (
            now - timedelta(seconds=_QUEUED_STALE_SECONDS)
        ).isoformat()
        query = (
            "MATCH (v:Version) "
            "WHERE v.package_url IS NOT NULL "
            "AND (v.last_enriched_at IS NULL OR v.last_enriched_at < $cutoff) "
            "AND (v.enrichment_queued_at IS NULL OR v.enrichment_queued_at < $queued_cutoff) "
            "RETURN DISTINCT v.package_url AS purl"
        )
        params = {"cutoff": cutoff_iso, "queued_cutoff": queued_cutoff_iso}

    result = persistence.run_query(query=query, params=params)
    purls: list[str] = [row["purl"] for row in result.result_set if row.get("purl")]

    if not force and purls:
        queue_depth = _enrichment_queue_depth()
        if queue_depth is not None and queue_depth > _QUEUE_BACKPRESSURE_THRESHOLD:
            logger.warning(
                "Skipping enrichment dispatch: enrichment queue depth %d exceeds "
                "backpressure threshold %d (%d packages were eligible)",
                queue_depth,
                _QUEUE_BACKPRESSURE_THRESHOLD,
                len(purls),
            )
            return {
                "dispatched": 0,
                "force": force,
                "skipped_backpressure": True,
                "queue_depth": queue_depth,
            }

    logger.info(
        "Dispatching enrichment for %d packages (force=%s) in batches of %d",
        len(purls),
        force,
        _DISPATCH_BATCH_SIZE,
    )
    now_iso = datetime.now(timezone.utc).isoformat()
    for i in range(0, len(purls), _DISPATCH_BATCH_SIZE):
        batch = purls[i : i + _DISPATCH_BATCH_SIZE]
        if not force:
            persistence.run_query(
                query=(
                    "UNWIND $purls AS purl "
                    "MATCH (v:Version {package_url: purl}) "
                    "SET v.enrichment_queued_at = $ts"
                ),
                params={"purls": batch, "ts": now_iso},
            )
        for purl in batch:
            enrich_package.delay(purl, sources)
        logger.debug("Dispatched batch %d-%d of %d", i, i + len(batch), len(purls))

    return {"dispatched": len(purls), "force": force}


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


def _persist_eol(persistence: Any, finding: Finding) -> None:
    """Store EOL data on the Version node."""
    data = finding.data
    purl = finding.package_url
    eol = data.get("eol")
    eol_date = data.get("eol_date")

    persistence.run_query(
        query=(
            "MATCH (v:Version {package_url: $purl}) "
            "SET v.eol = $eol, v.eol_date = $eol_date, "
            "v.eol_product = $product, v.eol_cycle = $cycle, "
            "v.eol_last_enriched = $ts"
        ),
        params={
            "purl": purl,
            "eol": eol is True or (isinstance(eol, str) and eol != "false"),
            "eol_date": eol_date or "",
            "product": data.get("product", ""),
            "cycle": data.get("cycle", ""),
            "ts": finding.timestamp.isoformat(),
        },
    )


def _persist_source_repo(persistence: Any, finding: Finding) -> None:
    """Create or link a SourceRepository node."""
    data = finding.data
    repo_url = data.get("repo_url")
    if not repo_url:
        return

    purl = finding.package_url
    persistence.run_query(
        query=(
            "MERGE (r:SourceRepository {url: $repo_url}) "
            "ON CREATE SET r.host = $host "
            "WITH r "
            "MATCH (v:Version {package_url: $purl}) "
            "MERGE (v)-[:FROM_REPO]->(r)"
        ),
        params={
            "repo_url": repo_url,
            "host": data.get("repo_host", ""),
            "purl": purl,
        },
    )


def _persist_depsdev(persistence: Any, finding: Finding) -> None:
    """Persist deps.dev metadata on the Version node and optionally a Scorecard node.

    Stores advisory count, publication date, default-version flag, and
    deps.dev license data directly on the Version node.  If OpenSSF
    Scorecard data is present, creates (or merges) a ``Scorecard`` node
    linked to the version.
    """
    data = finding.data
    purl = finding.package_url

    licenses_json = json.dumps(data.get("licenses", []))

    persistence.run_query(
        query=(
            "MATCH (v:Version {package_url: $purl}) "
            "SET v.depsdev_advisory_count = $advisory_count, "
            "    v.depsdev_published_at   = $published_at, "
            "    v.depsdev_is_default     = $is_default, "
            "    v.depsdev_licenses       = $licenses, "
            "    v.depsdev_last_enriched  = $ts"
        ),
        params={
            "purl": purl,
            "advisory_count": data.get("advisory_count", 0),
            "published_at": data.get("published_at") or "",
            "is_default": data.get("is_default", False),
            "licenses": licenses_json,
            "ts": finding.timestamp.isoformat(),
        },
    )

    scorecard_overall = data.get("scorecard_overall")
    if scorecard_overall is not None:
        checks_json = json.dumps(data.get("scorecard_checks", {}))
        persistence.run_query(
            query=(
                "MATCH (v:Version {package_url: $purl}) "
                "MERGE (sc:Scorecard {purl: $purl}) "
                "ON CREATE SET sc.overall_score = $overall, "
                "             sc.checks         = $checks, "
                "             sc.source          = 'depsdev', "
                "             sc.scored_at       = $ts "
                "ON MATCH SET  sc.overall_score = $overall, "
                "             sc.checks         = $checks, "
                "             sc.scored_at       = $ts "
                "MERGE (v)-[:HAS_SCORECARD]->(sc)"
            ),
            params={
                "purl": purl,
                "overall": scorecard_overall,
                "checks": checks_json,
                "ts": finding.timestamp.isoformat(),
            },
        )

    oss_fuzz = data.get("oss_fuzz")
    if oss_fuzz:
        persistence.run_query(
            query=(
                "MATCH (v:Version {package_url: $purl}) SET v.oss_fuzz = $oss_fuzz_json"
            ),
            params={
                "purl": purl,
                "oss_fuzz_json": json.dumps(oss_fuzz),
            },
        )

    project_key = data.get("project_key")
    if project_key:
        persistence.run_query(
            query=(
                "MATCH (v:Version {package_url: $purl}) "
                "SET v.depsdev_project_key = $project_key"
            ),
            params={
                "purl": purl,
                "project_key": project_key,
            },
        )

    logger.debug(
        "Persisted deps.dev metadata for %s (advisory_count=%d, scorecard=%s)",
        purl,
        data.get("advisory_count", 0),
        scorecard_overall,
    )


# ---------------------------------------------------------------------------
# Trust score tasks
# ---------------------------------------------------------------------------

_TRUST_SCORE_ENABLED = os.environ.get("TRUST_SCORE_ENABLED", "true").lower() == "true"


@shared_task(bind=True, max_retries=2, default_retry_delay=120)
def compute_trust_score(  # pylint: disable=unused-argument
    self: Any, purl: str, findings_data: list[dict[str, Any]]
) -> dict[str, Any]:
    """Compute and persist the direct trust score for a single PURL.

    Called after :func:`enrich_package` completes.  Receives serialised
    findings (dicts) and reconstructs them before passing to the calculator.

    Args:
        purl: The package URL being scored.
        findings_data: List of serialised Finding dicts.

    Returns:
        Summary dict with the direct_score and confidence.
    """
    if not _TRUST_SCORE_ENABLED:
        return {"purl": purl, "skipped": True}

    findings = _deserialise_findings(findings_data)
    calculator = TrustScoreCalculator()
    result = calculator.compute(purl, findings)

    persistence = get_persistence()
    persistence.create_trust_score(
        purl=purl,
        direct_score=result.direct_score,
        confidence=result.confidence,
        security_practices_score=result.security_practices_score,
        vulnerability_profile_score=result.vulnerability_profile_score,
        maintenance_health_score=result.maintenance_health_score,
        supply_chain_hygiene_score=result.supply_chain_hygiene_score,
        sources_used=result.sources_used,
        scored_at=datetime.now(timezone.utc).isoformat(),
        scorecard_raw=result.scorecard_raw,
        depsdev_raw=result.depsdev_raw,
    )
    persistence.link_version_to_trust_score(purl)

    logger.info(
        "Trust score computed for %s: direct=%.2f confidence=%.2f",
        purl,
        result.direct_score,
        result.confidence,
    )
    return {
        "purl": purl,
        "direct_score": result.direct_score,
        "confidence": result.confidence,
    }


@shared_task
def propagate_effective_scores() -> dict[str, Any]:
    """Propagate inherited risk through the dependency graph.

    Performs a bottom-up traversal using reverse topological order to compute
    ``effective_score``, ``inherited_score``, and ``min_path_score`` for
    every package that has a TrustScore node.

    Configurable via environment variables:
    - ``TRUST_SCORE_ALPHA``: blend weight for own vs inherited (default 0.4).
    - ``TRUST_SCORE_DECAY``: depth attenuation factor (default 0.8).
    - ``TRUST_SCORE_MAX_DEPTH``: maximum traversal depth (default 20).
    """
    if not _TRUST_SCORE_ENABLED:
        return {"skipped": True}

    alpha = float(os.environ.get("TRUST_SCORE_ALPHA", "0.4"))
    decay = float(os.environ.get("TRUST_SCORE_DECAY", "0.8"))
    max_depth = int(os.environ.get("TRUST_SCORE_MAX_DEPTH", "20"))

    # Reuse the per-process cached Persistence (see enrich_all_packages) rather
    # than opening a new FalkorDB connection pool on each scheduled run.
    persistence = get_persistence()

    scores_rows = persistence.get_all_trust_scores()
    direct_scores: dict[str, float] = {}
    for row in scores_rows:
        p = row.get("purl")
        ds = row.get("direct_score")
        if p and ds is not None:
            direct_scores[p] = float(ds)

    edges = persistence.get_dependency_graph_for_propagation()
    children: dict[str, list[str]] = defaultdict(list)
    for edge in edges:
        parent = edge.get("parent_purl")
        child = edge.get("child_purl")
        if parent and child:
            children[parent].append(child)

    effective, inherited, min_path, dep_counts = _propagate(
        direct_scores,
        children,
        alpha,
        decay,
        max_depth,
    )

    alert_threshold = float(os.environ.get("TRUST_SCORE_ALERT_THRESHOLD", "4.0"))

    updated = 0
    alerts: list[dict[str, Any]] = []
    for purl in effective:
        eff_score = effective[purl]
        persistence.update_trust_score_propagation(
            purl=purl,
            effective_score=eff_score,
            inherited_score=inherited.get(purl, 0.0),
            min_path_score=min_path.get(purl, direct_scores.get(purl, 5.0)),
            dep_count=dep_counts.get(purl, 0),
        )
        updated += 1

        if eff_score < alert_threshold:
            alerts.append(
                {
                    "purl": purl,
                    "effective_score": eff_score,
                    "direct_score": direct_scores.get(purl, 5.0),
                    "dep_count": dep_counts.get(purl, 0),
                }
            )

    if alerts:
        alerts.sort(key=lambda a: a["effective_score"])
        top_alerts = alerts[:20]
        logger.warning(
            "Trust score alert: %d packages below threshold %.1f. Top concerns: %s",
            len(alerts),
            alert_threshold,
            ", ".join(f"{a['purl']} ({a['effective_score']:.1f})" for a in top_alerts),
        )

    logger.info("Propagated effective scores for %d packages", updated)
    return {"updated": updated, "alerts": len(alerts)}


def _propagate(
    direct_scores: dict[str, float],
    children: dict[str, list[str]],
    alpha: float,
    decay: float,
    max_depth: int,  # noqa: ARG001  # pylint: disable=unused-argument
) -> tuple[dict[str, float], dict[str, float], dict[str, float], dict[str, int]]:
    """Bottom-up propagation of inherited risk.

    Returns four dicts keyed by purl:
    - effective_score
    - inherited_score
    - min_path_score
    - dep_count
    """
    all_purls = set(direct_scores.keys())
    effective: dict[str, float] = {}
    inherited: dict[str, float] = {}
    min_path: dict[str, float] = {}
    dep_counts: dict[str, int] = {}

    topo_order = _reverse_topological_sort(all_purls, children)

    for purl in topo_order:
        ds = direct_scores.get(purl, 5.0)
        deps = children.get(purl, [])
        scored_deps = [d for d in deps if d in direct_scores]

        if not scored_deps:
            effective[purl] = ds
            inherited[purl] = 0.0
            min_path[purl] = ds
            dep_counts[purl] = 0
            continue

        weighted_sum = 0.0
        weight_total = 0.0
        local_min = ds
        total_dep_count = 0

        for dep_purl in scored_deps:
            dep_eff = effective.get(dep_purl, direct_scores.get(dep_purl, 5.0))
            dep_min = min_path.get(dep_purl, direct_scores.get(dep_purl, 5.0))
            dep_dep_count = dep_counts.get(dep_purl, 0)

            w = decay
            weighted_sum += w * dep_eff
            weight_total += w
            local_min = min(local_min, dep_min)
            total_dep_count += 1 + dep_dep_count

        inh = weighted_sum / weight_total if weight_total > 0 else 0.0
        eff = alpha * ds + (1 - alpha) * inh

        effective[purl] = round(eff, 2)
        inherited[purl] = round(inh, 2)
        min_path[purl] = round(local_min, 2)
        dep_counts[purl] = total_dep_count

    return effective, inherited, min_path, dep_counts


def _reverse_topological_sort(
    nodes: set[str],
    children: dict[str, list[str]],
) -> list[str]:
    """Compute reverse topological order (leaves first) using Kahn's algorithm.

    Handles cycles gracefully by processing remaining nodes in arbitrary
    order after all acyclic nodes are exhausted.
    """
    in_degree: dict[str, int] = {n: 0 for n in nodes}
    for parent, deps in children.items():
        if parent not in nodes:
            continue
        for dep in deps:
            if dep in nodes:
                in_degree.setdefault(dep, 0)
                in_degree[parent] = in_degree.get(parent, 0)

    reverse_children: dict[str, list[str]] = defaultdict(list)
    for parent, deps in children.items():
        for dep in deps:
            if dep in nodes and parent in nodes:
                reverse_children[dep].append(parent)

    in_degree_fwd: dict[str, int] = {n: 0 for n in nodes}
    for parent in nodes:
        for dep in children.get(parent, []):
            if dep in nodes:
                in_degree_fwd[parent] = in_degree_fwd.get(parent, 0) + 0
                in_degree_fwd[dep] = in_degree_fwd.get(dep, 0)

    out_degree: dict[str, int] = {n: 0 for n in nodes}
    for parent in nodes:
        for dep in children.get(parent, []):
            if dep in nodes:
                out_degree[parent] = out_degree.get(parent, 0) + 1

    in_deg: dict[str, int] = {n: 0 for n in nodes}
    for parent in nodes:
        for dep in children.get(parent, []):
            if dep in nodes:
                in_deg[dep] = in_deg.get(dep, 0) + 1

    queue: list[str] = [n for n in nodes if out_degree.get(n, 0) == 0]
    result: list[str] = []
    visited: set[str] = set()

    while queue:
        node = queue.pop(0)
        if node in visited:
            continue
        visited.add(node)
        result.append(node)

        for parent in reverse_children.get(node, []):
            if parent in visited:
                continue
            out_degree[parent] = out_degree.get(parent, 1) - 1
            if out_degree[parent] <= 0:
                queue.append(parent)

    for n in nodes:
        if n not in visited:
            result.append(n)

    return result


def _deserialise_findings(data_list: list[dict[str, Any]]) -> list[Finding]:
    """Reconstruct Finding objects from serialised dicts."""
    findings: list[Finding] = []
    for item in data_list:
        try:
            kind = FindingKind(item["kind"])
        except KeyError, ValueError:
            continue
        findings.append(
            Finding(
                kind=kind,
                source=item.get("source", ""),
                package_url=item.get("package_url", ""),
                data=item.get("data", {}),
            )
        )
    return findings


def _serialise_findings(findings: list[Finding]) -> list[dict[str, Any]]:
    """Serialise Finding objects to JSON-safe dicts for task dispatch."""
    return [
        {
            "kind": f.kind.value,
            "source": f.source,
            "package_url": f.package_url,
            "data": f.data,
        }
        for f in findings
    ]


@shared_task
def refresh_internal_centrality() -> dict[str, Any]:
    """Recompute and store ``inDegree`` / ``outDegree`` on internal Version nodes.

    Aligns with the internal-centrality report: only nodes carrying the
    configured internal secondary label (``FALKORDB_INTERNAL_LABEL``, default
    ``INTERNAL``) are updated. Scheduled by Celery beat (see ``celery_app``).
    """
    internal_label = os.environ.get("FALKORDB_INTERNAL_LABEL", "INTERNAL") or "INTERNAL"
    persistence = get_persistence()
    persistence.refresh_internal_degree_centrality(internal_label=internal_label)
    logger.info(
        "Refreshed internal degree centrality for label %s",
        internal_label,
    )
    return {"internal_label": internal_label, "status": "ok"}
