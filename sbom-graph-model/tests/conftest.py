"""Shared fixtures for AppSec SBOM Model test suite."""

import json
import pathlib
from unittest.mock import MagicMock, patch

import pytest

from sbom_graph_model.model import (
    Defect,
    DefectType,
    Project,
    ProjectType,
    RiskStatus,
    Version,
    VersionDefect,
)
from sbom_graph_model.persistence import Persistence
from sbom_graph_model.cyclonedx.processor import CycloneDXProcessor

RESOURCES_DIR = pathlib.Path(__file__).parent / "resources"


@pytest.fixture
def admin_console_sbom() -> dict:
    """Load the customer_portal CycloneDX SBOM fixture (acme_corp demo data)."""
    sbom_path = RESOURCES_DIR / "customer_portal__acme-bom.json"
    with open(sbom_path, encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture
def mock_graph() -> MagicMock:
    """Create a mock FalkorDB Graph object."""
    graph = MagicMock()
    graph.query.return_value = MagicMock(result_set=[])
    return graph


@pytest.fixture
def mock_persistence(mock_graph: MagicMock) -> Persistence:
    """Create a Persistence instance with a mocked database connection."""
    with patch("sbom_graph_model.persistence.FalkorDB") as mock_fdb:
        mock_fdb_instance = MagicMock()
        mock_fdb_instance.select_graph.return_value = mock_graph
        mock_fdb.return_value = mock_fdb_instance

        persistence = Persistence(
            host="localhost",
            port=6379,
            graph_name="test_graph",
            password="test_password",
            ssl=False,
        )
    return persistence


@pytest.fixture
def processor(mock_persistence: Persistence) -> CycloneDXProcessor:
    """Create a CycloneDXProcessor backed by mock persistence."""
    return CycloneDXProcessor(persistence=mock_persistence)


@pytest.fixture
def sample_project() -> Project:
    """Create a sample Project with all fields populated."""
    project = Project()
    project.application_id = "app-123"
    project.public_app_id = "pub-123"
    project.name = "test-project"
    project.group = "com.example"
    project.type = ProjectType.Application
    project.purl = "pkg:maven/com.example/test-project@1.0.0"
    project.repo = "https://gitlab.example.com/test-project"
    project.team = "security-team"
    project.scan_id = "scan-001"
    return project


@pytest.fixture
def sample_library_project() -> Project:
    """Create a sample library Project."""
    project = Project()
    project.name = "test-library"
    project.group = "org.example"
    project.type = ProjectType.Library
    project.purl = "pkg:maven/org.example/test-library@2.0.0"
    return project


@pytest.fixture
def sample_version(sample_project: Project) -> Version:
    """Create a sample Version linked to the sample project."""
    version = Version()
    version.version = "1.0.0"
    version.project = sample_project
    version.scan_id = "scan-001"
    return version


@pytest.fixture
def sample_library_version(sample_library_project: Project) -> Version:
    """Create a sample Version linked to the library project."""
    version = Version()
    version.version = "2.0.0"
    version.project = sample_library_project
    version.scan_id = "scan-001"
    return version


@pytest.fixture
def sample_defect() -> Defect:
    """Create a sample Defect with all fields populated."""
    defect = Defect()
    defect.id = "CVE-2024-12345"
    defect.type = DefectType.SCA
    defect.severity = "high"
    defect.cwes = [79, 89]
    defect.cvss = 8.5
    defect.cvss_string = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
    defect.source = ("NVD", "https://nvd.nist.gov")
    return defect


@pytest.fixture
def sample_version_defect(
    sample_version: Version,
    sample_defect: Defect,
) -> VersionDefect:
    """Create a sample VersionDefect edge."""
    vd = VersionDefect()
    vd.project_version = sample_version
    vd.defect = sample_defect
    vd.risk_status = RiskStatus.UNKNOWN
    return vd


@pytest.fixture
def minimal_cyclonedx() -> dict:
    """Create a minimal valid CycloneDX JSON structure."""
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "metadata": {
            "component": {
                "bom-ref": "root-ref",
                "name": "test-app",
                "group": "com.test",
                "version": "1.0.0",
                "type": "application",
            },
            "properties": [
                {"name": "Scan ID", "value": "scan-123"},
            ],
        },
        "components": [
            {
                "bom-ref": "comp-1",
                "name": "lib-a",
                "group": "org.example",
                "version": "1.0.0",
                "type": "library",
                "purl": "pkg:maven/org.example/lib-a@1.0.0",
            },
            {
                "bom-ref": "comp-2",
                "name": "lib-b",
                "group": "org.example",
                "version": "2.0.0",
                "type": "library",
                "purl": "pkg:maven/org.example/lib-b@2.0.0",
            },
        ],
        "dependencies": [
            {
                "ref": "root-ref",
                "dependsOn": ["comp-1"],
            },
            {
                "ref": "comp-1",
                "dependsOn": ["comp-2"],
            },
        ],
        "vulnerabilities": [
            {
                "id": "CVE-2024-00001",
                "source": {"name": "NVD", "url": "https://nvd.nist.gov"},
                "ratings": [
                    {
                        "severity": "high",
                        "score": 7.5,
                        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    }
                ],
                "cwes": [79],
                "affects": [{"ref": "comp-1"}],
            },
        ],
    }
