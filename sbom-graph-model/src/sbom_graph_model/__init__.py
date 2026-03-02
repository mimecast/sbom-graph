"""
Core package for AppSec data models, persistence, and CycloneDX processing.

This package is designed to be extractable as a standalone library for reuse
by other projects such as webhooks that process SonaType release scans.
"""

from .model import (
    RiskStatus,
    DefectType,
    ProjectType,
    Version,
    Project,
    Defect,
    License,
    VersionDefect,
    DependencyVersion,
    HasVersion,
)
from .persistence import Persistence

__all__ = [
    # Enums
    "RiskStatus",
    "DefectType",
    "ProjectType",
    # Nodes
    "Version",
    "Project",
    "Defect",
    "License",
    # Edges
    "VersionDefect",
    "DependencyVersion",
    "HasVersion",
    # Persistence
    "Persistence",
]
