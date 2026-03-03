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
    Version,
    Project,
    Defect,
    License,
    PolicyAnnotation,
    VersionDefect,
    VersionLicense,
    VersionPolicy,
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
    # Nodes
    "Version",
    "Project",
    "Defect",
    "License",
    "PolicyAnnotation",
    # Edges
    "VersionDefect",
    "VersionLicense",
    "VersionPolicy",
    "DependencyVersion",
    "HasVersion",
    # Persistence
    "Persistence",
]
