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


class License:
    """Represents a software license."""

    def __init__(self):
        self.id: Optional[str] = None


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


class HasVersion:
    """Edge linking a Project to its Version."""

    def __init__(self):
        self.project: Optional[Project] = None
        self.version: Optional[Version] = None
