"""Tests for package-level exports.

Verifies that the public API exposed by __init__.py of both the root
package, the cyclonedx sub-package, and the spdx sub-package are
correct and importable.
"""

import sbom_graph_model
from sbom_graph_model.cyclonedx import CycloneDXProcessor, CycloneDXValidationError
from sbom_graph_model.spdx import SPDXProcessor, SPDXValidationError


class TestRootPackageExports:
    """Verify all symbols declared in sbom_graph_model.__all__."""

    def test_all_symbols_importable(self):
        for name in sbom_graph_model.__all__:
            assert hasattr(sbom_graph_model, name), f"{name} not found in package"

    def test_exports_enums(self):
        assert sbom_graph_model.RiskStatus is not None
        assert sbom_graph_model.DefectType is not None
        assert sbom_graph_model.ProjectType is not None

    def test_exports_node_classes(self):
        assert sbom_graph_model.Version is not None
        assert sbom_graph_model.Project is not None
        assert sbom_graph_model.Defect is not None
        assert sbom_graph_model.License is not None
        assert sbom_graph_model.PolicyAnnotation is not None
        assert sbom_graph_model.TrustScore is not None
        assert sbom_graph_model.SourceRepository is not None

    def test_exports_edge_classes(self):
        assert sbom_graph_model.VersionDefect is not None
        assert sbom_graph_model.VersionPolicy is not None
        assert sbom_graph_model.VersionSource is not None
        assert sbom_graph_model.HasTrustScore is not None
        assert sbom_graph_model.DependencyVersion is not None
        assert sbom_graph_model.HasVersion is not None

    def test_exports_persistence(self):
        assert sbom_graph_model.Persistence is not None

    def test_all_list_complete(self):
        expected = {
            "RiskStatus", "DefectType", "ProjectType", "LicenseRiskCategory",
            "PolicyType", "VexStatus",
            "Version", "Project", "Defect", "License", "PolicyAnnotation",
            "PointOfContact", "VexStatement", "TrustScore", "SourceRepository",
            "VersionDefect", "VersionLicense", "VersionPolicy", "VersionSource",
            "HasTrustScore", "ContactFor", "VersionVex", "VexRefersTo",
            "DependencyVersion", "HasVersion",
            "Persistence",
        }
        assert set(sbom_graph_model.__all__) == expected


class TestCycloneDXSubpackageExports:
    """Verify cyclonedx sub-package exports."""

    def test_processor_importable(self):
        assert CycloneDXProcessor is not None

    def test_validation_error_importable(self):
        assert CycloneDXValidationError is not None

    def test_validation_error_is_value_error(self):
        assert issubclass(CycloneDXValidationError, ValueError)


class TestSPDXSubpackageExports:
    """Verify spdx sub-package exports."""

    def test_processor_importable(self):
        assert SPDXProcessor is not None

    def test_validation_error_importable(self):
        assert SPDXValidationError is not None

    def test_validation_error_is_value_error(self):
        assert issubclass(SPDXValidationError, ValueError)
