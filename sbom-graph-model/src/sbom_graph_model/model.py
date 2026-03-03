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
