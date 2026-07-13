"""JSON export formatters for report endpoints.

Each public function accepts pre-fetched data from a report route,
assembles the canonical JSON envelope (``report_type``, ``generated_at``,
``stats``, ``data``), and returns a ``(payload, filename)`` tuple so the
caller can pass the result straight to :func:`_build_json_response`.
"""

from typing import Any

from sbom_graph_api.utils.api_helpers import get_utc_timestamp


def _ts() -> str:
    """Return the current UTC time in ISO-8601 format.

    Thin alias over the canonical :func:`get_utc_timestamp`.
    """
    return get_utc_timestamp()


def _safe_name(raw: str) -> str:
    """Sanitise a string for use in a filename."""
    return raw.replace("/", "_").replace(":", "_")


# -- report formatters ------------------------------------------------


def multi_version_deps_json(
    library_info: dict[str, Any],
    total_dependants: int,
    versions: list[dict[str, Any]],
    project_name: str,
) -> tuple[dict[str, Any], str]:
    """Build the JSON payload for the *multi-version-deps* report."""
    safe = _safe_name(project_name)
    payload = {
        "report_type": "multi-version-deps",
        "generated_at": _ts(),
        "library": library_info,
        "stats": {
            "total_versions": library_info.get(
                "total_versions",
                0,
            ),
            "total_dependants": total_dependants,
        },
        "versions": versions,
    }
    return payload, f"version_usage_{safe}.json"


def multi_version_sources_json(
    target: dict[str, Any],
    multi_deps: list[dict[str, Any]],
    total_versions: int,
    contributing_app_count: int,
    project_name: str,
    version_name: str,
) -> tuple[dict[str, Any], str]:
    """Build the JSON payload for *multi-version-sources*."""
    safe_name = _safe_name(project_name)
    safe_ver = _safe_name(version_name)
    payload = {
        "report_type": "multi-version-sources",
        "generated_at": _ts(),
        "target": target,
        "stats": {
            "dependencies_with_multiple_versions": len(
                multi_deps,
            ),
            "total_conflicting_versions": total_versions,
            "contributing_applications": contributing_app_count,
        },
        "multi_version_dependencies": multi_deps,
    }
    filename = f"multi_version_deps_{safe_name}_{safe_ver}.json"
    return payload, filename


def non_semver_json(
    data: list[dict[str, Any]],
    internal_only: bool,
    unique_projects: int,
    reason_counts: dict[str, int],
) -> tuple[dict[str, Any], str]:
    """Build the JSON payload for *non-semver-versions*."""
    filename = "non_semver_internal.json" if internal_only else "non_semver_versions.json"
    payload = {
        "report_type": "non-semver-versions",
        "generated_at": _ts(),
        "filter": "internal_only" if internal_only else "all",
        "stats": {
            "total_non_semver_versions": len(data),
            "affected_projects": unique_projects,
            "reason_breakdown": reason_counts,
        },
        "data": data,
    }
    return payload, filename


def version_dependencies_json(
    dependencies: list[dict[str, Any]],
    project_name: str,
    resolved_version: str,
    internal_only: bool,
    max_depth: int,
    is_semver_compliant: bool,
    latest_version: str | None,
    non_compliant_count: int,
    unique_dependencies: int,
    direct_deps: int,
    max_depth_reached: int,
) -> tuple[dict[str, Any], str]:
    """Build the JSON payload for *version-dependencies*."""
    safe_name = _safe_name(project_name)
    safe_ver = _safe_name(resolved_version)
    filename = f"{safe_name}_{safe_ver}_dependencies.json"

    data_rows: list[dict[str, Any]] = []
    if dependencies:
        for dep in dependencies:
            data_rows.append(
                {
                    "depth": dep["depth"],
                    "dependency_project": dep["dependency_project"],
                    "dependency_version": dep["dependency_version"],
                    "is_internal": dep.get(
                        "is_internal",
                        False,
                    ),
                },
            )
    else:
        data_rows.append(
            {
                "depth": 0,
                "dependency_project": "(no dependencies)",
                "dependency_version": "-",
                "is_internal": False,
            },
        )

    payload = {
        "report_type": "version-dependencies",
        "generated_at": _ts(),
        "project_name": project_name,
        "version": resolved_version,
        "filter": "internal_only" if internal_only else "all",
        "max_depth": max_depth,
        "semver_compliance": {
            "is_compliant": is_semver_compliant,
            "latest_version": latest_version,
            "non_compliant_count": (non_compliant_count if not is_semver_compliant else 0),
        },
        "summary": {
            "total_dependencies": len(dependencies),
            "unique_dependencies": unique_dependencies,
            "direct_dependencies": direct_deps,
            "max_depth_reached": max_depth_reached,
        },
        "data": data_rows,
    }
    return payload, filename


def dependants_json(
    report_data: dict[str, Any],
    internal_only: bool,
    longest_only: bool,
    project_name: str,
    version_name: str,
) -> tuple[dict[str, Any], str]:
    """Build the JSON payload for the *dependants* report."""
    safe_name = _safe_name(project_name)
    safe_ver = _safe_name(version_name)
    suffix = "_longest" if longest_only else "_all_paths"
    filename = f"dependants_{safe_name}_{safe_ver}{suffix}.json"

    payload = {
        "report_type": "dependants",
        "generated_at": _ts(),
        "filter": "internal_only" if internal_only else "all",
        "longest_only": longest_only,
        "target": report_data.get("target", {}),
        "stats": report_data.get("stats", {}),
        "dependants": report_data.get("dependants", []),
    }
    return payload, filename


def vulnerability_dependants_json(
    vuln: dict[str, Any],
    dependants: list[dict[str, Any]],
    internal_only: bool,
    defect_id: str,
    max_partition: int,
    unique_projects: int,
    partition_counts: dict[int, int],
) -> tuple[dict[str, Any], str]:
    """Build the JSON payload for *vulnerability-dependants*."""
    payload = {
        "report_type": "vulnerability-dependants",
        "generated_at": _ts(),
        "filter": "internal_only" if internal_only else "all",
        "vulnerability": vuln,
        "stats": {
            "total_dependants": len(dependants),
            "max_partition": max_partition,
            "unique_projects": unique_projects,
            "by_partition": partition_counts,
        },
        "dependants": dependants,
    }
    filename = f"vulnerability_dependants_{defect_id}.json"
    return payload, filename


def incident_response_json(
    defect_id: str,
    blast_radius: dict[str, Any],
    patch_plan: list[dict[str, Any]],
    internal_only: bool,
) -> tuple[dict[str, Any], str]:
    """Build the JSON payload for *incident-response* report."""
    payload = {
        "report_type": "incident-response",
        "generated_at": _ts(),
        "filter": "internal_only" if internal_only else "all",
        "defect_id": defect_id,
        "blast_radius": blast_radius,
        "patch_plan": patch_plan,
        "stats": {
            "affected_versions": len(blast_radius.get("affected_versions", [])),
            "affected_applications": len(blast_radius.get("affected_applications", [])),
            "patch_plan_items": len(patch_plan),
        },
    }
    filename = f"incident_response_{_safe_name(defect_id)}.json"
    return payload, filename


def centrality_json(
    centrality_data: list[dict[str, Any]],
    total_libs: int,
    total_in_degree: int,
    total_out_degree: int,
    max_in_degree: int,
    max_out_degree: int,
) -> tuple[dict[str, Any], str]:
    """Build the JSON payload for the *centrality* report."""
    payload = {
        "report_type": "centrality",
        "generated_at": _ts(),
        "stats": {
            "total_libraries": total_libs,
            "total_in_degree": total_in_degree,
            "total_out_degree": total_out_degree,
            "max_in_degree": max_in_degree,
            "max_out_degree": max_out_degree,
        },
        "data": centrality_data,
    }
    return payload, "internal_centrality.json"


def licenses_json(
    licenses: list[dict[str, Any]],
    internal_only: bool,
) -> tuple[dict[str, Any], str]:
    """Build the JSON payload for the *licenses* report."""
    payload = {
        "report_type": "licenses",
        "generated_at": _ts(),
        "filter": "internal_only" if internal_only else "all",
        "total": len(licenses),
        "licenses": licenses,
    }
    return payload, "licenses.json"


def license_summary_json(
    summary: list[dict[str, Any]],
    project_name: str,
    version_name: str,
) -> tuple[dict[str, Any], str]:
    """Build the JSON payload for *license-summary*."""
    payload = {
        "report_type": "license-summary",
        "generated_at": _ts(),
        "project_name": project_name,
        "version_name": version_name,
        "total": len(summary),
        "licenses": summary,
    }
    return payload, "license-summary.json"


def vulnerability_freshness_json(
    data: list[dict[str, Any]],
    internal_only: bool,
) -> tuple[dict[str, Any], str]:
    """Build the JSON payload for *vulnerability-freshness*."""
    never_enriched = sum(1 for d in data if not d.get("last_enriched_at"))
    payload = {
        "report_type": "vulnerability-freshness",
        "generated_at": _ts(),
        "filter": "internal_only" if internal_only else "all",
        "stats": {
            "total_packages": len(data),
            "never_enriched": never_enriched,
        },
        "data": data,
    }
    return payload, "vulnerability_freshness.json"


def policy_violations_json(
    data: list[dict[str, Any]],
    internal_only: bool,
) -> tuple[dict[str, Any], str]:
    """Build the JSON payload for *policy-violations*."""
    total_affected = sum(v.get("dependant_count", 0) for v in data)
    payload = {
        "report_type": "policy-violations",
        "generated_at": _ts(),
        "filter": "internal_only" if internal_only else "all",
        "stats": {
            "total_violations": len(data),
            "total_affected_dependants": total_affected,
        },
        "data": data,
    }
    return payload, "policy_violations.json"


def enrichment_coverage_json(
    data: dict[str, Any],
    internal_only: bool,
) -> tuple[dict[str, Any], str]:
    """Build the JSON payload for *enrichment-coverage*."""
    filename = "enrichment_coverage_internal.json" if internal_only else "enrichment_coverage.json"
    payload = {
        "report_type": "enrichment-coverage",
        "generated_at": _ts(),
        "filter": "internal_only" if internal_only else "all",
        "stats": {
            "total": data["total"],
            "recent": data["recent"],
            "stale": data["stale"],
            "never": data["never"],
            "recent_pct": data["recent_pct"],
            "stale_pct": data["stale_pct"],
            "never_pct": data["never_pct"],
        },
        "packages": data["packages"],
    }
    return payload, filename


def vex_coverage_json(
    coverage: dict[str, Any],
    vulns: list[dict[str, Any]],
    internal_only: bool,
) -> tuple[dict[str, Any], str]:
    """Build the JSON payload for *vex-coverage*."""
    payload = {
        "report_type": "vex-coverage",
        "generated_at": _ts(),
        "filter": "internal_only" if internal_only else "all",
        "stats": coverage,
        "data": vulns,
    }
    return payload, "vex_coverage.json"


def license_conflicts_json(
    conflicts: list[dict[str, Any]],
    internal_only: bool,
) -> tuple[dict[str, Any], str]:
    """Build the JSON payload for *license-conflicts*."""
    payload = {
        "report_type": "license-conflicts",
        "generated_at": _ts(),
        "filter": "internal_only" if internal_only else "all",
        "total": len(conflicts),
        "conflicts": conflicts,
    }
    return payload, "license-conflicts.json"


def source_repos_json(
    repos: list[dict[str, Any]],
    internal_only: bool,
) -> tuple[dict[str, Any], str]:
    """Build the JSON payload for *source-repos*."""
    payload = {
        "report_type": "source-repos",
        "generated_at": _ts(),
        "filter": "internal_only" if internal_only else "all",
        "data": repos,
        "total": len(repos),
    }
    return payload, "source_repos.json"


def source_impact_json(
    impact: dict[str, Any],
    repo_url: str,
) -> tuple[dict[str, Any], str]:
    """Build the JSON payload for *source-impact* report."""
    filename = _safe_name(repo_url) + "_source_impact.json"
    payload = {
        "report_type": "source-impact",
        "generated_at": _ts(),
        "repo_url": repo_url,
        "stats": impact.get("stats", {}),
        "packages": impact.get("packages", []),
        "dependants": impact.get("dependants", []),
        "affected_applications": impact.get("affected_applications", []),
        "graph_nodes": impact.get("graph_nodes", []),
        "graph_edges": impact.get("graph_edges", []),
    }
    return payload, filename
