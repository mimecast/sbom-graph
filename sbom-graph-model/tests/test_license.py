"""Unit tests for license model and CycloneDX license extraction."""

from sbom_graph_model.model import License, LicenseRiskCategory, VersionLicense
from sbom_graph_model.cyclonedx.processor import CycloneDXProcessor


class TestLicenseModel:
    """Tests for the License data class."""

    def test_license_defaults(self) -> None:
        lic = License()
        assert lic.spdx_id is None
        assert lic.name is None
        assert lic.url is None
        assert lic.risk_category == LicenseRiskCategory.UNKNOWN

    def test_license_risk_category_values(self) -> None:
        assert LicenseRiskCategory.PERMISSIVE == "permissive"
        assert LicenseRiskCategory.WEAK_COPYLEFT == "weak_copyleft"
        assert LicenseRiskCategory.STRONG_COPYLEFT == "strong_copyleft"
        assert LicenseRiskCategory.PROPRIETARY == "proprietary"
        assert LicenseRiskCategory.UNKNOWN == "unknown"

    def test_license_risk_category_from_str(self) -> None:
        assert LicenseRiskCategory.from_str("permissive") == "permissive"
        assert LicenseRiskCategory.from_str("strong_copyleft") == "strong_copyleft"
        assert LicenseRiskCategory.from_str("bogus") == "unknown"
        assert LicenseRiskCategory.from_str(None) == "unknown"
        assert LicenseRiskCategory.from_str("") == "unknown"

    def test_version_license_edge(self) -> None:
        edge = VersionLicense()
        assert edge.version is None
        assert edge.license is None


class TestParseLicensesFromComponent:
    """Tests for CycloneDX license extraction."""

    def test_spdx_license(self) -> None:
        component = {
            "name": "my-lib",
            "licenses": [
                {"license": {"id": "MIT", "url": "https://opensource.org/licenses/MIT"}}
            ],
        }
        licenses = CycloneDXProcessor.parse_licenses_from_component(component)
        assert len(licenses) == 1
        assert licenses[0].spdx_id == "MIT"
        assert licenses[0].url == "https://opensource.org/licenses/MIT"

    def test_freetext_license(self) -> None:
        component = {
            "name": "my-lib",
            "licenses": [
                {"license": {"name": "Custom License v2"}}
            ],
        }
        licenses = CycloneDXProcessor.parse_licenses_from_component(component)
        assert len(licenses) == 1
        assert licenses[0].spdx_id == "Custom License v2"
        assert licenses[0].name == "Custom License v2"

    def test_multiple_licenses(self) -> None:
        component = {
            "name": "dual-licensed-lib",
            "licenses": [
                {"license": {"id": "MIT"}},
                {"license": {"id": "Apache-2.0"}},
            ],
        }
        licenses = CycloneDXProcessor.parse_licenses_from_component(component)
        assert len(licenses) == 2
        ids = {lic.spdx_id for lic in licenses}
        assert ids == {"MIT", "Apache-2.0"}

    def test_no_licenses_field(self) -> None:
        component = {"name": "no-license-lib"}
        licenses = CycloneDXProcessor.parse_licenses_from_component(component)
        assert licenses == []

    def test_empty_licenses_list(self) -> None:
        component = {"name": "empty-lic", "licenses": []}
        licenses = CycloneDXProcessor.parse_licenses_from_component(component)
        assert licenses == []

    def test_invalid_license_entry(self) -> None:
        component = {
            "name": "bad-lic",
            "licenses": [
                {"expression": "MIT OR Apache-2.0"},
                {"license": {"id": "BSD-3-Clause"}},
            ],
        }
        licenses = CycloneDXProcessor.parse_licenses_from_component(component)
        assert len(licenses) == 1
        assert licenses[0].spdx_id == "BSD-3-Clause"

    def test_empty_name_and_no_id(self) -> None:
        component = {
            "name": "lib",
            "licenses": [
                {"license": {"url": "https://example.com/lic"}}
            ],
        }
        licenses = CycloneDXProcessor.parse_licenses_from_component(component)
        assert licenses == []

    def test_licenses_not_a_list(self) -> None:
        component = {"name": "lib", "licenses": "MIT"}
        licenses = CycloneDXProcessor.parse_licenses_from_component(component)
        assert licenses == []
