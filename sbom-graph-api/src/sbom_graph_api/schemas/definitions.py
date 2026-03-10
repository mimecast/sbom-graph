"""JSON Schema definitions for all reports and exports.

Each schema follows JSON Schema Draft-07 specification.
"""

from typing import Any

# Base schema metadata
SCHEMA_VERSION = "http://json-schema.org/draft-07/schema#"

# ============================================================================
# Projects Report Schema
# ============================================================================
PROJECTS_SCHEMA: dict[str, Any] = {
    "$schema": SCHEMA_VERSION,
    "$id": "/schemas/projects",
    "title": "Projects Report",
    "description": "List of all projects with their versions",
    "type": "object",
    "required": ["report_type", "generated_at", "stats", "data"],
    "properties": {
        "report_type": {
            "type": "string",
            "const": "projects",
            "description": "Type identifier for this report",
        },
        "generated_at": {
            "type": "string",
            "format": "date-time",
            "description": "ISO 8601 timestamp when report was generated",
        },
        "filter": {
            "type": "string",
            "enum": ["all", "internal_only"],
            "description": "Filter applied to the data",
        },
        "stats": {
            "type": "object",
            "properties": {
                "total_project_versions": {
                    "type": "integer",
                    "minimum": 0,
                    "description": "Total count of project-version pairs",
                },
                "unique_projects": {
                    "type": "integer",
                    "minimum": 0,
                    "description": "Count of unique project names",
                },
            },
            "required": ["total_project_versions", "unique_projects"],
        },
        "data": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["project_name", "version"],
                "properties": {
                    "project_name": {
                        "type": "string",
                        "description": "Name of the project",
                    },
                    "version": {
                        "type": "string",
                        "description": "Version string of the project",
                    },
                },
            },
        },
    },
}

# ============================================================================
# Applications Report Schema
# ============================================================================
APPLICATIONS_SCHEMA: dict[str, Any] = {
    "$schema": SCHEMA_VERSION,
    "$id": "/schemas/applications",
    "title": "Applications Report",
    "description": "List of all applications with their versions and metadata",
    "type": "object",
    "required": ["report_type", "generated_at", "stats", "data"],
    "properties": {
        "report_type": {
            "type": "string",
            "const": "applications",
            "description": "Type identifier for this report",
        },
        "generated_at": {
            "type": "string",
            "format": "date-time",
            "description": "ISO 8601 timestamp when report was generated",
        },
        "filter": {
            "type": "string",
            "enum": ["all", "internal_only"],
            "description": "Filter applied to the data",
        },
        "version_mode": {
            "type": "string",
            "enum": ["all_versions", "latest_only"],
            "description": "Version filter applied to the data",
        },
        "stats": {
            "type": "object",
            "properties": {
                "total_application_versions": {
                    "type": "integer",
                    "minimum": 0,
                    "description": "Total count of application-version pairs",
                },
                "unique_applications": {
                    "type": "integer",
                    "minimum": 0,
                    "description": "Count of unique application names",
                },
            },
            "required": ["total_application_versions", "unique_applications"],
        },
        "data": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["project_name", "version"],
                "properties": {
                    "project_name": {
                        "type": "string",
                        "description": "Name of the application",
                    },
                    "version": {
                        "type": "string",
                        "description": "Version string of the application",
                    },
                    "scan_id": {
                        "type": ["string", "null"],
                        "description": "SCA scan ID from CycloneDX",
                    },
                    "app_id": {
                        "type": ["string", "null"],
                        "description": "App ID within the SCA platform",
                    },
                    "public_id": {
                        "type": ["string", "null"],
                        "description": "Human-readable identifier in the SCA platform",
                    },
                    "repo_url": {
                        "type": ["string", "null"],
                        "description": "VCS repository URL for the project",
                    },
                    "labels": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Node labels (e.g., Application, internal label)",
                    },
                    "is_internal": {
                        "type": "boolean",
                        "description": "Whether this is an internal application",
                    },
                },
            },
        },
    },
}

# ============================================================================
# SNAPSHOT Dependencies Report Schema
# ============================================================================
SNAPSHOTS_SCHEMA: dict[str, Any] = {
    "$schema": SCHEMA_VERSION,
    "$id": "/schemas/snapshots",
    "title": "SNAPSHOT Dependencies Report",
    "description": "Applications with SNAPSHOT dependencies",
    "type": "object",
    "required": ["report_type", "generated_at", "stats", "data"],
    "properties": {
        "report_type": {
            "type": "string",
            "const": "snapshots",
            "description": "Type identifier for this report",
        },
        "generated_at": {
            "type": "string",
            "format": "date-time",
            "description": "ISO 8601 timestamp when report was generated",
        },
        "stats": {
            "type": "object",
            "properties": {
                "total_snapshot_dependencies": {
                    "type": "integer",
                    "minimum": 0,
                    "description": "Total count of SNAPSHOT dependencies",
                },
                "affected_applications": {
                    "type": "integer",
                    "minimum": 0,
                    "description": "Count of applications with SNAPSHOT dependencies",
                },
                "unique_snapshot_dependencies": {
                    "type": "integer",
                    "minimum": 0,
                    "description": "Count of unique SNAPSHOT dependency projects",
                },
            },
            "required": [
                "total_snapshot_dependencies",
                "affected_applications",
                "unique_snapshot_dependencies",
            ],
        },
        "data": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["application", "app_version", "dependency", "dep_version"],
                "properties": {
                    "application": {
                        "type": "string",
                        "description": "Name of the application",
                    },
                    "app_version": {
                        "type": "string",
                        "description": "Version of the application",
                    },
                    "dependency": {
                        "type": "string",
                        "description": "Name of the SNAPSHOT dependency",
                    },
                    "dep_version": {
                        "type": "string",
                        "description": "Version of the SNAPSHOT dependency",
                    },
                },
            },
        },
    },
}

# ============================================================================
# Self Dependencies Report Schema
# ============================================================================
SELF_DEPENDENCIES_SCHEMA: dict[str, Any] = {
    "$schema": SCHEMA_VERSION,
    "$id": "/schemas/self-dependencies",
    "title": "Self Dependencies Report",
    "description": "Nodes that depend on themselves",
    "type": "object",
    "required": ["report_type", "generated_at", "stats", "data"],
    "properties": {
        "report_type": {
            "type": "string",
            "const": "self-dependencies",
            "description": "Type identifier for this report",
        },
        "generated_at": {
            "type": "string",
            "format": "date-time",
            "description": "ISO 8601 timestamp when report was generated",
        },
        "stats": {
            "type": "object",
            "properties": {
                "total_self_dependencies": {
                    "type": "integer",
                    "minimum": 0,
                    "description": "Total count of self-dependency relationships",
                },
                "affected_projects": {
                    "type": "integer",
                    "minimum": 0,
                    "description": "Count of unique projects with self-dependencies",
                },
            },
            "required": ["total_self_dependencies", "affected_projects"],
        },
        "data": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["project_name", "version", "relationship_type"],
                "properties": {
                    "project_name": {
                        "type": "string",
                        "description": "Name of the project",
                    },
                    "version": {
                        "type": "string",
                        "description": "Version of the project",
                    },
                    "relationship_type": {
                        "type": "string",
                        "description": "Type of the self-dependency relationship",
                    },
                },
            },
        },
    },
}

# ============================================================================
# Multi-Version Dependency Sources Report Schema
# ============================================================================
MULTI_VERSION_SOURCES_SCHEMA: dict[str, Any] = {
    "$schema": SCHEMA_VERSION,
    "$id": "/schemas/multi-version-sources",
    "title": "Multi-Version Dependency Sources Report",
    "description": (
        "Report showing dependencies with multiple versions and their contributing applications"
    ),
    "type": "object",
    "required": ["report_type", "generated_at", "target", "stats", "multi_version_dependencies"],
    "properties": {
        "report_type": {
            "type": "string",
            "const": "multi-version-sources",
            "description": "Type identifier for this report",
        },
        "generated_at": {
            "type": "string",
            "format": "date-time",
            "description": "ISO 8601 timestamp when report was generated",
        },
        "target": {
            "type": ["object", "null"],
            "description": "The target project being analyzed",
            "properties": {
                "project_name": {
                    "type": "string",
                    "description": "Name of the target project",
                },
                "version": {
                    "type": "string",
                    "description": "Version of the target project",
                },
                "scan_ids_count": {
                    "type": "integer",
                    "minimum": 0,
                    "description": "Number of scan IDs associated with this version",
                },
            },
        },
        "stats": {
            "type": "object",
            "properties": {
                "dependencies_with_multiple_versions": {
                    "type": "integer",
                    "minimum": 0,
                    "description": "Count of dependencies that have multiple versions",
                },
                "total_conflicting_versions": {
                    "type": "integer",
                    "minimum": 0,
                    "description": "Total count of version conflicts",
                },
                "contributing_applications": {
                    "type": "integer",
                    "minimum": 0,
                    "description": "Count of unique applications contributing versions",
                },
            },
            "required": [
                "dependencies_with_multiple_versions",
                "total_conflicting_versions",
                "contributing_applications",
            ],
        },
        "multi_version_dependencies": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["dependency_project", "version_count", "versions"],
                "properties": {
                    "dependency_project": {
                        "type": "string",
                        "description": "Name of the dependency project",
                    },
                    "version_count": {
                        "type": "integer",
                        "minimum": 2,
                        "description": "Number of different versions of this dependency",
                    },
                    "versions": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "required": [
                                "version",
                                "scan_ids_intersection",
                                "contributing_applications",
                            ],
                            "properties": {
                                "version": {
                                    "type": "string",
                                    "description": "The dependency version",
                                },
                                "scan_ids_intersection": {
                                    "type": "array",
                                    "items": {"type": "string"},
                                    "description": "Scan IDs where this version appears",
                                },
                                "contributing_applications": {
                                    "type": "array",
                                    "items": {
                                        "type": "object",
                                        "required": ["project_name", "version"],
                                        "properties": {
                                            "project_name": {
                                                "type": "string",
                                                "description": "Application project name",
                                            },
                                            "version": {
                                                "type": "string",
                                                "description": "Application version",
                                            },
                                            "scan_id": {
                                                "type": "string",
                                                "description": "Scan ID of the application",
                                            },
                                        },
                                    },
                                    "description": "Applications that contribute this version",
                                },
                            },
                        },
                    },
                },
            },
        },
    },
}

# ============================================================================
# Multi-Version Dependencies Report Schema (Library Version Usage)
# ============================================================================
MULTI_VERSION_DEPS_SCHEMA: dict[str, Any] = {
    "$schema": SCHEMA_VERSION,
    "$id": "/schemas/multi-version-deps",
    "title": "Multi-Version Dependencies Report",
    "description": "Report showing all versions of a library and who uses each version",
    "type": "object",
    "required": ["report_type", "generated_at", "library", "stats", "versions"],
    "properties": {
        "report_type": {
            "type": "string",
            "const": "multi-version-deps",
            "description": "Type identifier for this report",
        },
        "generated_at": {
            "type": "string",
            "format": "date-time",
            "description": "ISO 8601 timestamp when report was generated",
        },
        "library": {
            "type": "object",
            "description": "The library being analyzed",
            "properties": {
                "project_name": {
                    "type": "string",
                    "description": "Name of the library",
                },
                "total_versions": {
                    "type": "integer",
                    "minimum": 0,
                    "description": "Total count of versions found",
                },
            },
            "required": ["project_name", "total_versions"],
        },
        "stats": {
            "type": "object",
            "properties": {
                "total_versions": {
                    "type": "integer",
                    "minimum": 0,
                    "description": "Number of distinct versions",
                },
                "total_dependants": {
                    "type": "integer",
                    "minimum": 0,
                    "description": "Total count of direct dependants across all versions",
                },
            },
            "required": ["total_versions", "total_dependants"],
        },
        "versions": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["version", "dependant_count", "dependants"],
                "properties": {
                    "version": {
                        "type": "string",
                        "description": "The version string",
                    },
                    "project_group": {
                        "type": ["string", "null"],
                        "description": "Maven-style project group",
                    },
                    "is_internal": {
                        "type": "boolean",
                        "description": "Whether this version is internal",
                    },
                    "dependant_count": {
                        "type": "integer",
                        "minimum": 0,
                        "description": "Number of direct dependants",
                    },
                    "dependants": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "required": ["project_name", "version"],
                            "properties": {
                                "project_name": {
                                    "type": "string",
                                    "description": "Dependant project name",
                                },
                                "version": {
                                    "type": "string",
                                    "description": "Dependant version",
                                },
                                "project_group": {
                                    "type": ["string", "null"],
                                    "description": "Dependant project group",
                                },
                                "is_internal": {
                                    "type": "boolean",
                                    "description": "Whether dependant is internal",
                                },
                            },
                        },
                        "description": "List of projects that depend on this version",
                    },
                },
            },
        },
    },
}

# ============================================================================
# Non-SemVer Versions Report Schema
# ============================================================================
NON_SEMVER_VERSIONS_SCHEMA: dict[str, Any] = {
    "$schema": SCHEMA_VERSION,
    "$id": "/schemas/non-semver-versions",
    "title": "Non-SemVer Versions Report",
    "description": "Report of versions not following SemVer naming convention",
    "type": "object",
    "required": ["report_type", "generated_at", "stats", "data"],
    "properties": {
        "report_type": {
            "type": "string",
            "const": "non-semver-versions",
            "description": "Type identifier for this report",
        },
        "generated_at": {
            "type": "string",
            "format": "date-time",
            "description": "ISO 8601 timestamp when report was generated",
        },
        "filter": {
            "type": "string",
            "enum": ["all", "internal_only"],
            "description": "Filter applied to the data",
        },
        "stats": {
            "type": "object",
            "properties": {
                "total_non_semver_versions": {
                    "type": "integer",
                    "minimum": 0,
                    "description": "Total count of non-SemVer versions",
                },
                "affected_projects": {
                    "type": "integer",
                    "minimum": 0,
                    "description": "Count of unique projects with non-SemVer versions",
                },
                "reason_breakdown": {
                    "type": "object",
                    "additionalProperties": {
                        "type": "integer",
                        "minimum": 0,
                    },
                    "description": "Count of versions by reason category",
                },
            },
            "required": ["total_non_semver_versions", "affected_projects"],
        },
        "data": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["project_name", "version", "reason"],
                "properties": {
                    "project_name": {
                        "type": "string",
                        "description": "Name of the project",
                    },
                    "version": {
                        "type": "string",
                        "description": "The non-SemVer version string",
                    },
                    "reason": {
                        "type": "string",
                        "description": "Category/reason for non-SemVer classification",
                    },
                    "labels": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Node labels (e.g., internal organization label)",
                    },
                },
            },
        },
    },
}

# ============================================================================
# Version Dependencies Export Schema
# ============================================================================
VERSION_DEPENDENCIES_SCHEMA: dict[str, Any] = {
    "$schema": SCHEMA_VERSION,
    "$id": "/schemas/version-dependencies",
    "title": "Version Dependencies Report",
    "description": (
        "Report of transitive dependencies for a project version,"
        " showing what the version depends ON at all depths"
    ),
    "type": "object",
    "required": ["report_type", "generated_at", "project_name", "version", "summary", "data"],
    "properties": {
        "report_type": {
            "type": "string",
            "const": "version-dependencies",
            "description": "Type identifier for this report",
        },
        "generated_at": {
            "type": "string",
            "format": "date-time",
            "description": "ISO 8601 timestamp when report was generated",
        },
        "project_name": {
            "type": "string",
            "description": "The project being analyzed",
        },
        "version": {
            "type": "string",
            "description": "The version being analyzed",
        },
        "filter": {
            "type": "string",
            "enum": ["all", "internal_only"],
            "description": "Filter mode applied to the data",
        },
        "max_depth": {
            "type": "integer",
            "minimum": 1,
            "description": "Maximum depth used for traversal",
        },
        "semver_compliance": {
            "type": "object",
            "description": "SemVer compliance information for the project",
            "properties": {
                "is_compliant": {
                    "type": "boolean",
                    "description": "Whether all versions follow SemVer naming convention",
                },
                "latest_version": {
                    "type": ["string", "null"],
                    "description": "Latest SemVer version if compliant, null otherwise",
                },
                "non_compliant_count": {
                    "type": "integer",
                    "minimum": 0,
                    "description": "Number of non-SemVer compliant versions",
                },
            },
            "required": ["is_compliant", "latest_version", "non_compliant_count"],
        },
        "summary": {
            "type": "object",
            "properties": {
                "total_dependencies": {
                    "type": "integer",
                    "minimum": 0,
                    "description": "Total number of transitive dependencies found",
                },
                "unique_dependencies": {
                    "type": "integer",
                    "minimum": 0,
                    "description": "Number of unique dependency project versions",
                },
                "direct_dependencies": {
                    "type": "integer",
                    "minimum": 0,
                    "description": "Number of direct (depth 1) dependencies",
                },
                "max_depth_reached": {
                    "type": "integer",
                    "minimum": 0,
                    "description": "Maximum depth level reached in the traversal",
                },
            },
            "required": [
                "total_dependencies",
                "unique_dependencies",
                "direct_dependencies",
                "max_depth_reached",
            ],
        },
        "data": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["depth", "dependency_project", "dependency_version"],
                "properties": {
                    "depth": {
                        "type": "integer",
                        "minimum": 1,
                        "description": "Depth level of this dependency (1 = direct)",
                    },
                    "dependency_project": {
                        "type": "string",
                        "description": "Name of the dependency project",
                    },
                    "dependency_version": {
                        "type": "string",
                        "description": "Version of the dependency project",
                    },
                    "is_internal": {
                        "type": "boolean",
                        "description": "Whether this is an internal-labeled library",
                    },
                },
            },
        },
    },
}

# ============================================================================
# Dependants Report Schema
# ============================================================================
DEPENDANTS_SCHEMA: dict[str, Any] = {
    "$schema": SCHEMA_VERSION,
    "$id": "/schemas/dependants",
    "title": "Dependants Report",
    "description": "Report of all dependants with partition levels and dependency paths",
    "type": "object",
    "required": ["report_type", "generated_at", "target", "stats", "dependants"],
    "properties": {
        "report_type": {
            "type": "string",
            "const": "dependants",
            "description": "Type identifier for this report",
        },
        "generated_at": {
            "type": "string",
            "format": "date-time",
            "description": "ISO 8601 timestamp when report was generated",
        },
        "filter": {
            "type": "string",
            "enum": ["all", "internal_only"],
            "description": "Filter applied to the data",
        },
        "longest_only": {
            "type": "boolean",
            "description": (
                "If true, only longest paths are included"
                " (default for vulnerability prioritization)"
            ),
        },
        "target": {
            "type": "object",
            "description": "The target project being analyzed",
            "properties": {
                "project_name": {
                    "type": "string",
                    "description": "Name of the target project",
                },
                "version": {
                    "type": "string",
                    "description": "Version of the target project",
                },
                "labels": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Node labels",
                },
            },
            "required": ["project_name", "version"],
        },
        "stats": {
            "type": "object",
            "properties": {
                "total_dependants": {
                    "type": "integer",
                    "minimum": 0,
                    "description": "Total count of dependant nodes",
                },
                "max_partition": {
                    "type": "integer",
                    "minimum": 0,
                    "description": "Maximum partition level (longest path from target)",
                },
                "unique_projects": {
                    "type": "integer",
                    "minimum": 0,
                    "description": "Count of unique dependant projects",
                },
            },
            "required": ["total_dependants", "max_partition", "unique_projects"],
        },
        "dependants": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["id", "project_name", "version", "partition"],
                "properties": {
                    "id": {
                        "type": "string",
                        "description": "Unique node identifier (project:version)",
                    },
                    "project_name": {
                        "type": "string",
                        "description": "Name of the dependant project",
                    },
                    "version": {
                        "type": "string",
                        "description": "Version of the dependant project",
                    },
                    "partition": {
                        "type": "integer",
                        "minimum": 0,
                        "description": "Longest path from target (number of edges)",
                    },
                    "max_path_edges": {
                        "type": "integer",
                        "minimum": 0,
                        "description": "Edges in longest path from dependant to target",
                    },
                    "labels": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Node labels (e.g., internal organization label)",
                    },
                    "paths": {
                        "type": "array",
                        "items": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Path from dependant to target",
                        },
                        "description": "Alternative dependency paths (up to 50, longest first)",
                    },
                    "path_count": {
                        "type": "integer",
                        "minimum": 0,
                        "description": "Number of alternative paths found",
                    },
                },
            },
        },
    },
}

# ============================================================================
# Vulnerabilities Report Schema
# ============================================================================
VULNERABILITIES_SCHEMA: dict[str, Any] = {
    "$schema": SCHEMA_VERSION,
    "$id": "/schemas/vulnerabilities",
    "title": "Vulnerabilities Report",
    "description": "List of all vulnerabilities with affected versions",
    "type": "object",
    "required": ["report_type", "generated_at", "stats", "data"],
    "properties": {
        "report_type": {
            "type": "string",
            "const": "vulnerabilities",
            "description": "Type identifier for this report",
        },
        "generated_at": {
            "type": "string",
            "format": "date-time",
            "description": "ISO 8601 timestamp when report was generated",
        },
        "filter": {
            "type": "string",
            "enum": ["all", "internal_only"],
            "description": "Filter applied to the data",
        },
        "stats": {
            "type": "object",
            "properties": {
                "total_vulnerabilities": {
                    "type": "integer",
                    "minimum": 0,
                    "description": "Total count of vulnerabilities",
                },
                "total_affected_versions": {
                    "type": "integer",
                    "minimum": 0,
                    "description": "Total count of affected version entries",
                },
                "by_severity": {
                    "type": "object",
                    "additionalProperties": {"type": "integer"},
                    "description": "Count of vulnerabilities by severity",
                },
            },
            "required": ["total_vulnerabilities", "total_affected_versions"],
        },
        "data": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["defect_id", "severity"],
                "properties": {
                    "defect_id": {
                        "type": "string",
                        "description": "Vulnerability identifier (e.g., CVE-2021-44228)",
                    },
                    "title": {
                        "type": "string",
                        "description": "Short description of the vulnerability",
                    },
                    "description": {
                        "type": "string",
                        "description": "Detailed description",
                    },
                    "severity": {
                        "type": "string",
                        "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                        "description": "Vulnerability severity level",
                    },
                    "cvss_score": {
                        "type": "number",
                        "minimum": 0,
                        "maximum": 10,
                        "description": "CVSS v3 score",
                    },
                    "cwe_id": {
                        "type": "string",
                        "description": "CWE identifier (e.g., CWE-79)",
                    },
                    "published_date": {
                        "type": "string",
                        "description": "Date vulnerability was published",
                    },
                    "affected_versions": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "project_name": {"type": "string"},
                                "version": {"type": "string"},
                                "project_group": {"type": ["string", "null"]},
                            },
                        },
                        "description": "List of directly affected library versions",
                    },
                },
            },
        },
    },
}

# ============================================================================
# Vulnerability Dependants Report Schema
# ============================================================================
VULNERABILITY_DEPENDANTS_SCHEMA: dict[str, Any] = {
    "$schema": SCHEMA_VERSION,
    "$id": "/schemas/vulnerability-dependants",
    "title": "Vulnerability Dependants Report",
    "description": "All dependants affected by a specific vulnerability",
    "type": "object",
    "required": ["report_type", "generated_at", "vulnerability", "stats", "dependants"],
    "properties": {
        "report_type": {
            "type": "string",
            "const": "vulnerability-dependants",
            "description": "Type identifier for this report",
        },
        "generated_at": {
            "type": "string",
            "format": "date-time",
            "description": "ISO 8601 timestamp when report was generated",
        },
        "filter": {
            "type": "string",
            "enum": ["all", "internal_only"],
            "description": "Filter applied to the data",
        },
        "vulnerability": {
            "type": "object",
            "properties": {
                "defect_id": {"type": "string"},
                "title": {"type": "string"},
                "description": {"type": "string"},
                "severity": {"type": "string"},
                "cvss_score": {"type": "number"},
                "cwe_id": {"type": "string"},
                "published_date": {"type": "string"},
                "affected_versions": {"type": "array"},
            },
            "description": "The vulnerability details",
        },
        "stats": {
            "type": "object",
            "properties": {
                "total_dependants": {
                    "type": "integer",
                    "minimum": 0,
                    "description": "Total count of affected dependants",
                },
                "max_partition": {
                    "type": "integer",
                    "minimum": 0,
                    "description": "Maximum partition depth",
                },
                "unique_projects": {
                    "type": "integer",
                    "minimum": 0,
                    "description": "Count of unique project names",
                },
                "by_partition": {
                    "type": "object",
                    "additionalProperties": {"type": "integer"},
                    "description": "Count of dependants by partition",
                },
            },
            "required": ["total_dependants", "max_partition", "unique_projects"],
        },
        "dependants": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["project_name", "version", "partition"],
                "properties": {
                    "project_name": {
                        "type": "string",
                        "description": "Name of the dependant project",
                    },
                    "version": {
                        "type": "string",
                        "description": "Version of the dependant project",
                    },
                    "partition": {
                        "type": "integer",
                        "minimum": 0,
                        "description": "Distance from vulnerable library (1 = direct dependency)",
                    },
                    "is_internal": {
                        "type": "boolean",
                        "description": "Whether this is an internal project",
                    },
                    "affected_by": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "project_name": {"type": "string"},
                                "version": {"type": "string"},
                            },
                        },
                        "description": "Which vulnerable versions this dependant uses",
                    },
                },
            },
        },
    },
}

# ============================================================================
# Centrality Schema
# ============================================================================
CENTRALITY_SCHEMA: dict[str, Any] = {
    "$schema": SCHEMA_VERSION,
    "$id": "/schemas/centrality",
    "title": "Internal Library Centrality Report",
    "description": "Centrality metrics (inDegree/outDegree) for internal libraries",
    "type": "object",
    "required": ["report_type", "generated_at", "stats", "data"],
    "properties": {
        "report_type": {
            "type": "string",
            "const": "centrality",
            "description": "Report type identifier",
        },
        "generated_at": {
            "type": "string",
            "format": "date-time",
            "description": "Timestamp when the report was generated",
        },
        "stats": {
            "type": "object",
            "properties": {
                "total_libraries": {
                    "type": "integer",
                    "minimum": 0,
                    "description": "Total number of internal libraries",
                },
                "total_in_degree": {
                    "type": "integer",
                    "minimum": 0,
                    "description": "Sum of all inDegree values",
                },
                "total_out_degree": {
                    "type": "integer",
                    "minimum": 0,
                    "description": "Sum of all outDegree values",
                },
                "max_in_degree": {
                    "type": "integer",
                    "minimum": 0,
                    "description": "Maximum inDegree value in the dataset",
                },
                "max_out_degree": {
                    "type": "integer",
                    "minimum": 0,
                    "description": "Maximum outDegree value in the dataset",
                },
            },
            "required": ["total_libraries", "max_in_degree", "max_out_degree"],
        },
        "data": {
            "type": "array",
            "items": {
                "type": "object",
                "required": [
                    "project_group",
                    "project_name",
                    "version_name",
                    "inDegree",
                    "outDegree",
                ],
                "properties": {
                    "project_group": {
                        "type": "string",
                        "description": "Maven/Gradle group identifier",
                    },
                    "project_name": {
                        "type": "string",
                        "description": "Name of the project/artifact",
                    },
                    "version_name": {
                        "type": "string",
                        "description": "Version string",
                    },
                    "inDegree": {
                        "type": "integer",
                        "minimum": 0,
                        "description": "Number of projects depending on this library",
                    },
                    "outDegree": {
                        "type": "integer",
                        "minimum": 0,
                        "description": "Number of dependencies this library has",
                    },
                },
            },
        },
    },
}


# ============================================================================
# Licenses Report Schema
# ============================================================================
LICENSES_SCHEMA: dict[str, Any] = {
    "$schema": SCHEMA_VERSION,
    "$id": "/schemas/licenses",
    "title": "Licenses Report",
    "description": "All licenses grouped by risk category with usage counts",
    "type": "object",
    "required": ["report_type", "generated_at", "total", "licenses"],
    "properties": {
        "report_type": {
            "type": "string",
            "const": "licenses",
            "description": "Type identifier for this report",
        },
        "generated_at": {
            "type": "string",
            "format": "date-time",
            "description": "ISO 8601 timestamp when report was generated",
        },
        "filter": {
            "type": "string",
            "enum": ["all", "internal_only"],
            "description": "Filter applied to the data",
        },
        "total": {
            "type": "integer",
            "minimum": 0,
            "description": "Total count of licenses",
        },
        "licenses": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["spdx_id", "name", "risk_category"],
                "properties": {
                    "spdx_id": {
                        "type": "string",
                        "description": "SPDX license identifier",
                    },
                    "name": {
                        "type": "string",
                        "description": "Full license name",
                    },
                    "risk_category": {
                        "type": "string",
                        "description": (
                            "Risk category (Copyleft, Weak Copyleft, Permissive, Unknown)"
                        ),
                    },
                    "usage_count": {
                        "type": "integer",
                        "minimum": 0,
                        "description": "Number of packages using this license",
                    },
                },
            },
        },
    },
}

# ============================================================================
# License Summary Report Schema
# ============================================================================
LICENSE_SUMMARY_SCHEMA: dict[str, Any] = {
    "$schema": SCHEMA_VERSION,
    "$id": "/schemas/license-summary",
    "title": "License Summary Report",
    "description": "License BOM for a specific project version including transitive dependencies",
    "type": "object",
    "required": [
        "report_type",
        "generated_at",
        "project_name",
        "version_name",
        "total",
        "licenses",
    ],
    "properties": {
        "report_type": {
            "type": "string",
            "const": "license-summary",
            "description": "Type identifier for this report",
        },
        "generated_at": {
            "type": "string",
            "format": "date-time",
            "description": "ISO 8601 timestamp when report was generated",
        },
        "project_name": {
            "type": "string",
            "description": "The project being analyzed",
        },
        "version_name": {
            "type": "string",
            "description": "The version being analyzed",
        },
        "total": {
            "type": "integer",
            "minimum": 0,
            "description": "Total count of license entries",
        },
        "licenses": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["project_name", "version"],
                "properties": {
                    "project_group": {
                        "type": ["string", "null"],
                        "description": "Maven-style project group",
                    },
                    "project_name": {
                        "type": "string",
                        "description": "Dependency project name",
                    },
                    "version": {
                        "type": "string",
                        "description": "Dependency version",
                    },
                    "purl": {
                        "type": ["string", "null"],
                        "description": "Package URL",
                    },
                    "spdx_id": {
                        "type": ["string", "null"],
                        "description": "SPDX license identifier",
                    },
                    "license_name": {
                        "type": ["string", "null"],
                        "description": "Full license name",
                    },
                    "risk_category": {
                        "type": ["string", "null"],
                        "description": (
                            "Risk category (Copyleft, Weak Copyleft, Permissive, Unknown)"
                        ),
                    },
                },
            },
        },
    },
}

# ============================================================================
# License Conflicts Report Schema
# ============================================================================
LICENSE_CONFLICTS_SCHEMA: dict[str, Any] = {
    "$schema": SCHEMA_VERSION,
    "$id": "/schemas/license-conflicts",
    "title": "License Conflicts Report",
    "description": "Projects mixing incompatible license categories in their dependency tree",
    "type": "object",
    "required": ["report_type", "generated_at", "total", "conflicts"],
    "properties": {
        "report_type": {
            "type": "string",
            "const": "license-conflicts",
            "description": "Type identifier for this report",
        },
        "generated_at": {
            "type": "string",
            "format": "date-time",
            "description": "ISO 8601 timestamp when report was generated",
        },
        "filter": {
            "type": "string",
            "enum": ["all", "internal_only"],
            "description": "Filter applied to the data",
        },
        "total": {
            "type": "integer",
            "minimum": 0,
            "description": "Total count of conflicting projects",
        },
        "conflicts": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "project_name": {
                        "type": "string",
                        "description": "Project with license conflicts",
                    },
                    "version": {
                        "type": "string",
                        "description": "Project version",
                    },
                    "categories": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "License categories found in the dependency tree",
                    },
                    "conflicting_licenses": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "spdx_id": {"type": "string"},
                                "risk_category": {"type": "string"},
                                "package": {"type": "string"},
                            },
                        },
                        "description": "Specific license conflicts",
                    },
                },
            },
        },
    },
}

# ============================================================================
# Vulnerability Freshness Report Schema
# ============================================================================
VULNERABILITY_FRESHNESS_SCHEMA: dict[str, Any] = {
    "$schema": SCHEMA_VERSION,
    "$id": "/schemas/vulnerability-freshness",
    "title": "Vulnerability Freshness Report",
    "description": (
        "Enrichment freshness showing when each package was last scanned for vulnerabilities"
    ),
    "type": "object",
    "required": ["report_type", "generated_at", "stats", "data"],
    "properties": {
        "report_type": {
            "type": "string",
            "const": "vulnerability-freshness",
            "description": "Type identifier for this report",
        },
        "generated_at": {
            "type": "string",
            "format": "date-time",
            "description": "ISO 8601 timestamp when report was generated",
        },
        "filter": {
            "type": "string",
            "enum": ["all", "internal_only"],
            "description": "Filter applied to the data",
        },
        "stats": {
            "type": "object",
            "properties": {
                "total_packages": {
                    "type": "integer",
                    "minimum": 0,
                    "description": "Total count of packages",
                },
                "never_enriched": {
                    "type": "integer",
                    "minimum": 0,
                    "description": "Count of packages never enriched",
                },
            },
            "required": ["total_packages", "never_enriched"],
        },
        "data": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["project_name", "version_name"],
                "properties": {
                    "project_group": {
                        "type": ["string", "null"],
                        "description": "Maven-style project group",
                    },
                    "project_name": {
                        "type": "string",
                        "description": "Package name",
                    },
                    "version_name": {
                        "type": "string",
                        "description": "Package version",
                    },
                    "purl": {
                        "type": ["string", "null"],
                        "description": "Package URL",
                    },
                    "last_enriched_at": {
                        "type": ["string", "null"],
                        "format": "date-time",
                        "description": "ISO 8601 timestamp of last enrichment, null if never",
                    },
                },
            },
        },
    },
}

# ============================================================================
# Policy Violations Report Schema
# ============================================================================
POLICY_VIOLATIONS_SCHEMA: dict[str, Any] = {
    "$schema": SCHEMA_VERSION,
    "$id": "/schemas/policy-violations",
    "title": "Policy Violations Report",
    "description": "Packages with 'bad' policy annotations that are still in use",
    "type": "object",
    "required": ["report_type", "generated_at", "stats", "data"],
    "properties": {
        "report_type": {
            "type": "string",
            "const": "policy-violations",
            "description": "Type identifier for this report",
        },
        "generated_at": {
            "type": "string",
            "format": "date-time",
            "description": "ISO 8601 timestamp when report was generated",
        },
        "filter": {
            "type": "string",
            "enum": ["all", "internal_only"],
            "description": "Filter applied to the data",
        },
        "stats": {
            "type": "object",
            "properties": {
                "total_violations": {
                    "type": "integer",
                    "minimum": 0,
                    "description": "Total count of policy violations",
                },
                "total_affected_dependants": {
                    "type": "integer",
                    "minimum": 0,
                    "description": "Total count of dependants affected by violations",
                },
            },
            "required": ["total_violations", "total_affected_dependants"],
        },
        "data": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["project_name", "version_name"],
                "properties": {
                    "purl": {
                        "type": ["string", "null"],
                        "description": "Package URL",
                    },
                    "project_name": {
                        "type": "string",
                        "description": "Package name",
                    },
                    "version_name": {
                        "type": "string",
                        "description": "Package version",
                    },
                    "justification": {
                        "type": ["string", "null"],
                        "description": "Reason for the policy annotation",
                    },
                    "created_by": {
                        "type": ["string", "null"],
                        "description": "User who created the annotation",
                    },
                    "created_at": {
                        "type": ["string", "null"],
                        "format": "date-time",
                        "description": "When the annotation was created",
                    },
                    "dependant_count": {
                        "type": "integer",
                        "minimum": 0,
                        "description": "Number of dependants using this package",
                    },
                },
            },
        },
    },
}

# ============================================================================
# VEX Coverage Report Schema
# ============================================================================
VEX_COVERAGE_SCHEMA: dict[str, Any] = {
    "$schema": SCHEMA_VERSION,
    "$id": "/schemas/vex-coverage",
    "title": "VEX Coverage Report",
    "description": "VEX coverage statistics across all vulnerabilities",
    "type": "object",
    "required": ["report_type", "generated_at", "stats", "data"],
    "properties": {
        "report_type": {
            "type": "string",
            "const": "vex-coverage",
            "description": "Type identifier for this report",
        },
        "generated_at": {
            "type": "string",
            "format": "date-time",
            "description": "ISO 8601 timestamp when report was generated",
        },
        "filter": {
            "type": "string",
            "enum": ["all", "internal_only"],
            "description": "Filter applied to the data",
        },
        "stats": {
            "type": "object",
            "properties": {
                "total_vulnerabilities": {
                    "type": "integer",
                    "minimum": 0,
                    "description": "Total count of vulnerabilities",
                },
                "with_vex": {
                    "type": "integer",
                    "minimum": 0,
                    "description": "Vulnerabilities with VEX statements",
                },
                "without_vex": {
                    "type": "integer",
                    "minimum": 0,
                    "description": "Vulnerabilities without VEX statements",
                },
                "coverage_percent": {
                    "type": "number",
                    "minimum": 0,
                    "maximum": 100,
                    "description": "Percentage of vulnerabilities with VEX statements",
                },
            },
            "required": ["total_vulnerabilities", "with_vex", "without_vex"],
        },
        "data": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["defect_id", "severity"],
                "properties": {
                    "defect_id": {
                        "type": "string",
                        "description": "Vulnerability identifier (e.g., CVE-2021-44228)",
                    },
                    "severity": {
                        "type": "string",
                        "description": "Vulnerability severity level",
                    },
                    "description": {
                        "type": ["string", "null"],
                        "description": "Description of the vulnerability",
                    },
                    "vex_status": {
                        "type": ["string", "null"],
                        "description": "VEX status (e.g., not_affected, affected)",
                    },
                    "vex_count": {
                        "type": "integer",
                        "minimum": 0,
                        "description": "Number of VEX statements for this vulnerability",
                    },
                },
            },
        },
    },
}

# ============================================================================
# Source Repositories Report Schema
# ============================================================================
SOURCE_REPOS_SCHEMA: dict[str, Any] = {
    "$schema": SCHEMA_VERSION,
    "$id": "/schemas/source-repos",
    "title": "Source Repositories Report",
    "description": "All tracked source repositories with linked package counts",
    "type": "object",
    "required": ["report_type", "generated_at", "total", "data"],
    "properties": {
        "report_type": {
            "type": "string",
            "const": "source-repos",
            "description": "Type identifier for this report",
        },
        "generated_at": {
            "type": "string",
            "format": "date-time",
            "description": "ISO 8601 timestamp when report was generated",
        },
        "filter": {
            "type": "string",
            "enum": ["all", "internal_only"],
            "description": "Filter applied to the data",
        },
        "total": {
            "type": "integer",
            "minimum": 0,
            "description": "Total count of repositories",
        },
        "data": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["url"],
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "Repository URL",
                    },
                    "vcs_type": {
                        "type": ["string", "null"],
                        "description": "Version control system type (e.g., git)",
                    },
                    "namespace": {
                        "type": ["string", "null"],
                        "description": "Repository namespace or organization",
                    },
                    "name": {
                        "type": ["string", "null"],
                        "description": "Repository name",
                    },
                    "package_count": {
                        "type": "integer",
                        "minimum": 0,
                        "description": "Number of packages sourced from this repository",
                    },
                },
            },
        },
    },
}


# ============================================================================
# Schema Index - list of all available schemas
# ============================================================================
SCHEMA_INDEX: dict[str, dict[str, Any]] = {
    "projects": {
        "schema": PROJECTS_SCHEMA,
        "endpoint": "/reports/projects",
        "description": "All projects with their versions",
    },
    "applications": {
        "schema": APPLICATIONS_SCHEMA,
        "endpoint": "/reports/applications",
        "description": "All applications with their versions and metadata",
    },
    "snapshots": {
        "schema": SNAPSHOTS_SCHEMA,
        "endpoint": "/reports/snapshots",
        "description": "Applications with SNAPSHOT dependencies",
    },
    "self-dependencies": {
        "schema": SELF_DEPENDENCIES_SCHEMA,
        "endpoint": "/reports/self-dependencies",
        "description": "Nodes that depend on themselves",
    },
    "multi-version-sources": {
        "schema": MULTI_VERSION_SOURCES_SCHEMA,
        "endpoint": "/reports/multi-version-sources/{project_name}/{version_name}",
        "description": "Dependencies with multiple versions and their sources (diamond deps)",
    },
    "multi-version-deps": {
        "schema": MULTI_VERSION_DEPS_SCHEMA,
        "endpoint": "/reports/multi-version-deps/{project_name}",
        "description": "All versions of a library and who uses each version",
    },
    "non-semver-versions": {
        "schema": NON_SEMVER_VERSIONS_SCHEMA,
        "endpoint": "/reports/non-semver-versions",
        "description": "Versions not following SemVer naming",
    },
    "version-dependencies": {
        "schema": VERSION_DEPENDENCIES_SCHEMA,
        "endpoint": "/reports/version-dependencies/{project_name}/{version_name}",
        "description": (
            "Version-to-dependant relationships with SemVer compliance and 'latest' support"
        ),
    },
    "dependants": {
        "schema": DEPENDANTS_SCHEMA,
        "endpoint": "/reports/dependants/{project_name}/{version_name}",
        "description": "Dependants with partition levels and paths",
    },
    "vulnerabilities": {
        "schema": VULNERABILITIES_SCHEMA,
        "endpoint": "/reports/vulnerabilities",
        "description": "All vulnerabilities with affected versions",
    },
    "vulnerability-dependants": {
        "schema": VULNERABILITY_DEPENDANTS_SCHEMA,
        "endpoint": "/reports/vulnerability-dependants/{defect_id}",
        "description": "Dependants affected by a specific vulnerability",
    },
    "centrality": {
        "schema": CENTRALITY_SCHEMA,
        "endpoint": "/reports/centrality",
        "description": "Centrality metrics for internal libraries",
    },
    "licenses": {
        "schema": LICENSES_SCHEMA,
        "endpoint": "/reports/licenses",
        "description": "All licenses grouped by risk category",
    },
    "license-summary": {
        "schema": LICENSE_SUMMARY_SCHEMA,
        "endpoint": "/reports/license-summary",
        "description": "License BOM for a specific project version",
    },
    "license-conflicts": {
        "schema": LICENSE_CONFLICTS_SCHEMA,
        "endpoint": "/reports/license-conflicts",
        "description": "Projects mixing incompatible license categories",
    },
    "vulnerability-freshness": {
        "schema": VULNERABILITY_FRESHNESS_SCHEMA,
        "endpoint": "/reports/vulnerability-freshness",
        "description": "Enrichment freshness for vulnerability data",
    },
    "policy-violations": {
        "schema": POLICY_VIOLATIONS_SCHEMA,
        "endpoint": "/reports/policy-violations",
        "description": "Packages with bad policy annotations still in use",
    },
    "vex-coverage": {
        "schema": VEX_COVERAGE_SCHEMA,
        "endpoint": "/reports/vex-coverage",
        "description": "VEX coverage statistics across vulnerabilities",
    },
    "source-repos": {
        "schema": SOURCE_REPOS_SCHEMA,
        "endpoint": "/reports/source-repos",
        "description": "Tracked source repositories with package counts",
    },
}


def _register_inbound_schemas() -> None:
    """Register inbound request schemas into SCHEMA_INDEX at import time.

    Kept as a function to avoid circular-import issues with inbound.py
    importing SCHEMA_VERSION from this module.
    """
    from sbom_graph_api.schemas.inbound import INBOUND_SCHEMA_INDEX

    SCHEMA_INDEX.update(INBOUND_SCHEMA_INDEX)


_register_inbound_schemas()


def get_schema(schema_name: str) -> dict[str, Any] | None:
    """Get a schema by name.

    Args:
        schema_name: The schema identifier (e.g., 'projects', 'snapshots')

    Returns:
        The schema dict or None if not found
    """
    entry = SCHEMA_INDEX.get(schema_name)
    return entry["schema"] if entry else None


def get_schema_list() -> list[dict[str, str]]:
    """Get a list of all available schemas.

    Returns:
        List of schema metadata dicts with name, endpoint, and description
    """
    return [
        {
            "name": name,
            "schema_url": f"/schemas/{name}",
            "endpoint": entry["endpoint"],
            "description": entry["description"],
        }
        for name, entry in SCHEMA_INDEX.items()
    ]
