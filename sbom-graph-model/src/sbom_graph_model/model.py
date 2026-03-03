"""
Data models for AppSec data ingestion.

This module contains Pydantic-style data classes representing nodes and edges
in the dependency graph, including Projects, Versions, Defects, and their relationships.
"""

from enum import IntEnum
from typing import Optional
from datetime import datetime


class RiskStatus(IntEnum):
    """Risk status for defects."""
    ACCEPTED = 2
    MITIGATED = 1
    UNKNOWN = 0


class DefectType(IntEnum):
    """Type of security defect."""
    SAST = 0
    SCA = 1


class ProjectType(IntEnum):
    """Type of project."""
    Application = 0
    Library = 1


# Nodes

class Version:
    """Represents a specific version of a project."""

    def __init__(self):
        self.version: Optional[str] = None
        self.project: Optional["Project"] = None
        self.scan_id: Optional[str] = None
        self.sbom_format: Optional[str] = None  # "cyclonedx" or "spdx"

    def __str__(self):
        return_value = 'Version {'
        for key, value in self.__dict__.items():
            return_value += f"'{key}': '{value}', "
        return_value += '}'
        return return_value


class Project:
    """Represents a software project (application or library)."""

    def __init__(self):
        self.application_id: Optional[str] = None
        self.public_app_id: Optional[str] = None
        self.name: Optional[str] = None
        self.group: Optional[str] = None

        self.type: Optional[ProjectType] = None

        self.purl: Optional[str] = None
        self.modified: Optional[bool] = None

        self.licenses: list["License"] = []

        self.repo: Optional[str] = None
        self.team: Optional[str] = None

        self.gitlab_project_url: Optional[str] = None
        self.scan_id: Optional[str] = None

    def __str__(self):
        return_value = 'Project {'
        for key, value in self.__dict__.items():
            return_value += f"'{key}': '{value}', "
        return_value += '}'
        return return_value


class Defect:
    """Represents a security defect/vulnerability."""

    def __init__(self):
        self.id: Optional[str] = None
        self.type: Optional[DefectType] = None
        self.discovered: Optional[datetime] = None
        self.description: Optional[str] = None
        self.cwes: list[int] = []
        self.severity: Optional[str] = None
        self.cvss: Optional[int] = None
        self.cvss_string: Optional[str] = None
        self.source: Optional[tuple[str, str]] = None
        self.last_enriched_at: Optional[str] = None  # ISO timestamp
        self.enrichment_source: Optional[str] = None  # "osv", "nvd", "sbom"
        self.aliases: list[str] = []  # CVE/GHSA/OSV cross-references


class PolicyType(str):
    """Policy annotation type for packages."""
    BAD = "bad"
    GOOD = "good"
    HOLD = "hold"

    _VALID: frozenset[str] = frozenset({BAD, GOOD, HOLD})

    @classmethod
    def from_str(cls, value: str | None) -> str:
        if value and value in cls._VALID:
            return value
        raise ValueError(f"Invalid policy type {value!r}: must be one of {sorted(cls._VALID)}")


class PolicyAnnotation:
    """Represents a policy annotation (CertifyBad/CertifyGood/Hold).

    Attributes:
        annotation_id: Unique identifier (auto-generated UUID).
        type: One of "bad", "good", "hold".
        justification: Reason for the annotation.
        created_by: Username of creator.
        created_at: ISO timestamp of creation.
        expires_at: Optional ISO timestamp of expiration.
    """

    def __init__(self):
        self.annotation_id: Optional[str] = None
        self.type: Optional[str] = None  # PolicyType value
        self.justification: Optional[str] = None
        self.created_by: Optional[str] = None
        self.created_at: Optional[str] = None
        self.expires_at: Optional[str] = None


class VersionPolicy:
    """Edge linking a Version to a PolicyAnnotation (HAS_POLICY)."""

    def __init__(self):
        self.version: Optional[Version] = None
        self.annotation: Optional[PolicyAnnotation] = None


class PointOfContact:
    """Represents a team or individual responsible for a package.

    Attributes:
        email: Contact email address.
        team: Team name responsible for the package.
        slack_channel: Slack channel for notifications.
    """

    def __init__(self):
        self.email: Optional[str] = None
        self.team: Optional[str] = None
        self.slack_channel: Optional[str] = None


class ContactFor:
    """Edge linking a PointOfContact to a Version (CONTACT_FOR)."""

    def __init__(self):
        self.contact: Optional[PointOfContact] = None
        self.version: Optional[Version] = None


class VexStatus(str):
    """VEX statement status values."""
    NOT_AFFECTED = "not_affected"
    AFFECTED = "affected"
    FIXED = "fixed"
    UNDER_INVESTIGATION = "under_investigation"

    _VALID: frozenset[str] = frozenset({
        NOT_AFFECTED, AFFECTED, FIXED, UNDER_INVESTIGATION,
    })

    @classmethod
    def from_str(cls, value: str | None) -> str:
        if value and value in cls._VALID:
            return value
        raise ValueError(
            f"Invalid VEX status {value!r}: must be one of {sorted(cls._VALID)}"
        )


class VexStatement:
    """Represents a VEX (Vulnerability Exploitability eXchange) statement.

    Attributes:
        statement_id: Unique identifier (auto-generated UUID).
        status: One of not_affected, affected, fixed, under_investigation.
        justification: Reason for the status determination.
        impact_statement: Description of the impact.
        action_statement: Recommended action.
        source_document: URI or identifier of the source VEX document.
        timestamp: ISO timestamp of the statement.
    """

    def __init__(self):
        self.statement_id: Optional[str] = None
        self.status: Optional[str] = None  # VexStatus value
        self.justification: Optional[str] = None
        self.impact_statement: Optional[str] = None
        self.action_statement: Optional[str] = None
        self.source_document: Optional[str] = None
        self.timestamp: Optional[str] = None


class VersionVex:
    """Edge linking a Version to a VexStatement (HAS_VEX)."""

    def __init__(self):
        self.version: Optional[Version] = None
        self.statement: Optional[VexStatement] = None


class VexRefersTo:
    """Edge linking a VexStatement to a Defect (REFERS_TO)."""

    def __init__(self):
        self.statement: Optional[VexStatement] = None
        self.defect: Optional[Defect] = None


class LicenseRiskCategory(str):
    """Risk category for software licenses.

    Values are the canonical strings stored in the graph database.
    Use :meth:`from_str` to safely convert an arbitrary string to a
    known category (falling back to :attr:`UNKNOWN`).
    """

    PERMISSIVE = "permissive"
    WEAK_COPYLEFT = "weak_copyleft"
    STRONG_COPYLEFT = "strong_copyleft"
    PROPRIETARY = "proprietary"
    UNKNOWN = "unknown"

    _VALID: frozenset[str] = frozenset({
        PERMISSIVE,
        WEAK_COPYLEFT,
        STRONG_COPYLEFT,
        PROPRIETARY,
        UNKNOWN,
    })

    @classmethod
    def from_str(cls, value: str | None) -> str:
        """Convert an arbitrary string to a valid risk category.

        Returns :attr:`UNKNOWN` for ``None`` or unrecognised values.
        """
        if value and value in cls._VALID:
            return value
        return cls.UNKNOWN


class License:
    """Represents a software license.

    Attributes:
        spdx_id: SPDX identifier (e.g. ``"MIT"``, ``"Apache-2.0"``).
            Used as the MERGE key in the graph.
        name: Human-readable license name.
        url: URL to the license text.
        risk_category: Copyleft risk classification -- must be a value
            from :class:`LicenseRiskCategory`.
    """

    def __init__(self):
        self.spdx_id: Optional[str] = None
        self.name: Optional[str] = None
        self.url: Optional[str] = None
        self.risk_category: str = LicenseRiskCategory.UNKNOWN


class TrustScore:
    """Composite supply-chain trust score for a package version.

    Combines signals from OpenSSF Scorecard, OSV, Sonatype OSS Index,
    and deps.dev into a single 0--10 score per package, then propagates
    inherited risk through the dependency graph to produce an effective
    score that reflects the aggregate health of a package and all of
    its transitive dependencies.

    Attributes:
        purl: Package URL (MERGE key -- one score per package version).
        direct_score: Per-package composite from the 4-category formula.
        effective_score: Blended own + inherited risk.
        inherited_score: Weighted aggregate from dependency scores.
        min_path_score: Lowest direct_score on any dependency path.
        confidence: Data source coverage (0--1).
        dep_count: Number of direct + transitive deps in the calculation.
        security_practices_score: Category breakdown (0--10).
        vulnerability_profile_score: Category breakdown (0--10).
        maintenance_health_score: Category breakdown (0--10).
        supply_chain_hygiene_score: Category breakdown (0--10).
        sources_used: List of source names that contributed data.
        scored_at: ISO timestamp of last scoring run.
        scorecard_raw: Raw Scorecard JSON response (nullable).
        depsdev_raw: Raw deps.dev JSON response (nullable).
    """

    def __init__(self):
        self.purl: Optional[str] = None
        self.direct_score: Optional[float] = None
        self.effective_score: Optional[float] = None
        self.inherited_score: Optional[float] = None
        self.min_path_score: Optional[float] = None
        self.confidence: Optional[float] = None
        self.dep_count: Optional[int] = None
        self.security_practices_score: Optional[float] = None
        self.vulnerability_profile_score: Optional[float] = None
        self.maintenance_health_score: Optional[float] = None
        self.supply_chain_hygiene_score: Optional[float] = None
        self.sources_used: list[str] = []
        self.scored_at: Optional[str] = None
        self.scorecard_raw: Optional[str] = None
        self.depsdev_raw: Optional[str] = None


class HasTrustScore:
    """Edge linking a Version to its TrustScore (HAS_TRUST_SCORE)."""

    def __init__(self):
        self.version: Optional[Version] = None
        self.trust_score: Optional[TrustScore] = None


class SourceRepository:
    """Represents a source code repository linked to a package.

    Attributes:
        url: Canonical repository URL (used as the MERGE key).
        vcs_type: Version control system type (e.g. "git", "svn").
        namespace: Hosting platform (e.g. "github.com", "gitlab.com").
        name: Repository path within the namespace (e.g. "org/repo").
        tag: Tag associated with the linked version.
        commit: Commit hash associated with the linked version.
    """

    def __init__(self):
        self.url: Optional[str] = None
        self.vcs_type: Optional[str] = None
        self.namespace: Optional[str] = None
        self.name: Optional[str] = None
        self.tag: Optional[str] = None
        self.commit: Optional[str] = None


class VersionSource:
    """Edge linking a Version to a SourceRepository (HAS_SOURCE)."""

    def __init__(self):
        self.version: Optional[Version] = None
        self.repository: Optional[SourceRepository] = None


# Edges

class VersionDefect:
    """Edge linking a Version to a Defect it contains."""

    def __init__(self):
        self.project_version: Optional[Version] = None
        self.defect: Optional[Defect] = None
        self.description: Optional[str] = None
        self.risk_status: Optional[RiskStatus] = None
        self.justification: Optional[str] = None
        self.review_date: Optional[datetime] = None


class DependencyVersion:
    """Edge representing a dependency relationship between versions."""

    def __init__(self):
        self.parent_version: Optional[Version] = None
        self.child_version: Optional[Version] = None
        self.chosen_license: Optional[License] = None
        self.vex_information: Optional[dict] = None


class VersionLicense:
    """Edge linking a Version to a License it uses (HAS_LICENSE)."""

    def __init__(self):
        self.version: Optional[Version] = None
        self.license: Optional[License] = None


class HasVersion:
    """Edge linking a Project to its Version."""

    def __init__(self):
        self.project: Optional[Project] = None
        self.version: Optional[Version] = None
