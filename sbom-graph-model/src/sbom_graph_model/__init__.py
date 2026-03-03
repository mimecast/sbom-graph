"""
Core package for AppSec data models, persistence, and CycloneDX processing.

This package is designed to be extractable as a standalone library for reuse
by other projects such as webhooks that process SonaType release scans.
"""

from .model import (
    RiskStatus,
    DefectType,
    ProjectType,
    LicenseRiskCategory,
    PolicyType,
    VexStatus,
    Version,
    Project,
    Defect,
    License,
    PolicyAnnotation,
    PointOfContact,
    VexStatement,
    TrustScore,
    SourceRepository,
    VersionDefect,
    VersionLicense,
    VersionPolicy,
    VersionSource,
    HasTrustScore,
    ContactFor,
    VersionVex,
    VexRefersTo,
    DependencyVersion,
    HasVersion,
)
from .persistence import Persistence

__all__ = [
    # Enums
    "RiskStatus",
    "DefectType",
    "ProjectType",
    "LicenseRiskCategory",
    "PolicyType",
    "VexStatus",
    # Nodes
    "Version",
    "Project",
    "Defect",
    "License",
    "PolicyAnnotation",
    "PointOfContact",
    "VexStatement",
    "TrustScore",
    "SourceRepository",
    # Edges
    "VersionDefect",
    "VersionLicense",
    "VersionPolicy",
    "VersionSource",
    "HasTrustScore",
    "ContactFor",
    "VersionVex",
    "VexRefersTo",
    "DependencyVersion",
    "HasVersion",
    # Persistence
    "Persistence",
]
