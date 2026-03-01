"""Tests for package-level exports.

Verifies that the public API exposed by __init__.py of both the root
package and the cyclonedx sub-package are correct and importable.
"""

import appsec_sbom_model
from appsec_sbom_model.cyclonedx import CycloneDXProcessor, CycloneDXValidationError


class TestRootPackageExports:
    """Verify all symbols declared in appsec_sbom_model.__all__."""

    def test_all_symbols_importable(self):
        for name in appsec_sbom_model.__all__:
            assert hasattr(appsec_sbom_model, name), f"{name} not found in package"

    def test_exports_enums(self):
        assert appsec_sbom_model.RiskStatus is not None
        assert appsec_sbom_model.DefectType is not None
        assert appsec_sbom_model.ProjectType is not None

    def test_exports_node_classes(self):
        assert appsec_sbom_model.Version is not None
        assert appsec_sbom_model.Project is not None
        assert appsec_sbom_model.Defect is not None
        assert appsec_sbom_model.License is not None

    def test_exports_edge_classes(self):
        assert appsec_sbom_model.VersionDefect is not None
        assert appsec_sbom_model.DependencyVersion is not None
        assert appsec_sbom_model.HasVersion is not None

    def test_exports_persistence(self):
        assert appsec_sbom_model.Persistence is not None

    def test_all_list_complete(self):
        expected = {
            "RiskStatus", "DefectType", "ProjectType",
            "Version", "Project", "Defect", "License",
            "VersionDefect", "DependencyVersion", "HasVersion",
            "Persistence",
        }
        assert set(appsec_sbom_model.__all__) == expected


class TestCycloneDXSubpackageExports:
    """Verify cyclonedx sub-package exports."""

    def test_processor_importable(self):
        assert CycloneDXProcessor is not None

    def test_validation_error_importable(self):
        assert CycloneDXValidationError is not None

    def test_validation_error_is_value_error(self):
        assert issubclass(CycloneDXValidationError, ValueError)
