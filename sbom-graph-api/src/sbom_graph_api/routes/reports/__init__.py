"""Reports blueprint — split into sub-modules by report category.

Sub-modules:
    inventory       Projects, applications, centrality, source repos
    dependencies    Snapshot, self-dep, multi-version, version-dep,
                    dependants, PURL redirects
    vulnerabilities Vulnerability lists, dependants, freshness, VEX
    compliance      Licenses, license summary/conflicts, policy
    trust_scores    Trust scores, trust score gaps
    sbom_provenance SBOM inventory, coverage
"""

from flask import Blueprint

bp = Blueprint("reports", __name__, url_prefix="/reports")

from sbom_graph_api.routes.reports import (  # noqa: E402, F401  # pylint: disable=wrong-import-position
    compliance,
    dependencies,
    inventory,
    sbom_provenance,
    trust_scores,
    vulnerabilities,
)
