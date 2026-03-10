"""JSON export formatters for report endpoints.

Each public function accepts pre-fetched data from a report route,
assembles the canonical JSON envelope (``report_type``, ``generated_at``,
``stats``, ``data``), and returns a ``(payload, filename)`` tuple so the
caller can pass the result straight to :func:`_build_json_response`.
"""

from datetime import UTC, datetime
from typing import Any


def _ts() -> str:
    """Return the current UTC time in ISO-8601 format."""
    return datetime.now(UTC).isoformat()


def _safe_name(raw: str) -> str:
    """Sanitise a string for use in a filename."""
    return raw.replace("/", "_").replace(":", "_")


# -- report formatters ------------------------------------------------


def projects_json(
    projects: list[dict[str, Any]],
    unique_projects: int,
    internal_only: bool,
) -> tuple[dict[str, Any], str]:
    """Build the JSON payload for the *projects* report."""
    filename = "internal_projects.json" if internal_only else "all_projects.json"
    payload = {
        "report_type": "projects",
        "generated_at": _ts(),
        "filter": "internal_only" if internal_only else "all",
        "stats": {
            "total_project_versions": len(projects),
            "unique_projects": unique_projects,
        },
        "data": projects,
    }
    return payload, filename


def applications_json(
    applications: list[dict[str, Any]],
    unique_apps: int,
    internal_only: bool,
    latest_only: bool,
) -> tuple[dict[str, Any], str]:
    """Build the JSON payload for the *applications* report."""
    parts: list[str] = []
    if internal_only:
        parts.append("internal")
    if latest_only:
        parts.append("latest")
    parts.append("applications.json")
    filename = "_".join(parts) if len(parts) > 1 else "applications.json"
    payload = {
        "report_type": "applications",
        "generated_at": _ts(),
        "filter": "internal_only" if internal_only else "all",
        "version_mode": ("latest_only" if latest_only else "all_versions"),
        "stats": {
            "total_application_versions": len(applications),
            "unique_applications": unique_apps,
        },
        "data": applications,
    }
    return payload, filename


def snapshots_json(
    data: list[dict[str, Any]],
    internal_only: bool,
    unique_apps: int,
    unique_deps: int,
) -> tuple[dict[str, Any], str]:
    """Build the JSON payload for the *snapshots* report."""
    payload = {
        "report_type": "snapshots",
        "generated_at": _ts(),
        "filter": "internal_only" if internal_only else "all",
        "stats": {
            "total_snapshot_dependencies": len(data),
            "affected_applications": unique_apps,
            "unique_snapshot_dependencies": unique_deps,
        },
        "data": data,
    }
    return payload, "snapshot_dependencies.json"


def self_dependencies_json(
    data: list[dict[str, Any]],
    internal_only: bool,
    unique_projects: int,
) -> tuple[dict[str, Any], str]:
    """Build the JSON payload for the *self-dependencies* report."""
    payload = {
        "report_type": "self-dependencies",
        "generated_at": _ts(),
        "filter": "internal_only" if internal_only else "all",
        "stats": {
            "total_self_dependencies": len(data),
            "affected_projects": unique_projects,
        },
        "data": data,
    }
    return payload, "self_dependencies.json"


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


def vulnerabilities_json(
    vulnerabilities: list[dict[str, Any]],
    internal_only: bool,
    severity_counts: dict[str, int],
    total_affected: int,
) -> tuple[dict[str, Any], str]:
    """Build the JSON payload for *vulnerabilities*."""
    filename = "vulnerabilities_internal.json" if internal_only else "vulnerabilities.json"
    payload = {
        "report_type": "vulnerabilities",
        "generated_at": _ts(),
        "filter": "internal_only" if internal_only else "all",
        "stats": {
            "total_vulnerabilities": len(vulnerabilities),
            "total_affected_versions": total_affected,
            "by_severity": severity_counts,
        },
        "data": vulnerabilities,
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
