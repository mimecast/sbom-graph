"""Tests for the data model module.

Covers enums (RiskStatus, DefectType, ProjectType), node classes
(Project, Version, Defect, License), and edge classes (VersionDefect,
DependencyVersion, HasVersion).
"""

from datetime import datetime

import pytest

from sbom_graph_model.model import (
    Defect,
    DefectType,
    DependencyVersion,
    HasVersion,
    License,
    PolicyAnnotation,
    PolicyType,
    Project,
    ProjectType,
    RiskStatus,
    Version,
    VersionDefect,
    VersionPolicy,
)


class TestRiskStatus:
    """Tests for the RiskStatus enum."""

    def test_accepted_value(self):
        assert RiskStatus.ACCEPTED == 2

    def test_mitigated_value(self):
        assert RiskStatus.MITIGATED == 1

    def test_unknown_value(self):
        assert RiskStatus.UNKNOWN == 0

    def test_ordering(self):
        assert RiskStatus.UNKNOWN < RiskStatus.MITIGATED < RiskStatus.ACCEPTED

    def test_is_int_subclass(self):
        assert isinstance(RiskStatus.ACCEPTED, int)

    def test_invalid_value_raises(self):
        with pytest.raises(ValueError):
            RiskStatus(99)


class TestDefectType:
    """Tests for the DefectType enum."""

    def test_sast_value(self):
        assert DefectType.SAST == 0

    def test_sca_value(self):
        assert DefectType.SCA == 1

    def test_is_int_subclass(self):
        assert isinstance(DefectType.SAST, int)

    def test_invalid_value_raises(self):
        with pytest.raises(ValueError):
            DefectType(42)


class TestProjectType:
    """Tests for the ProjectType enum."""

    def test_application_value(self):
        assert ProjectType.Application == 0

    def test_library_value(self):
        assert ProjectType.Library == 1

    def test_invalid_value_raises(self):
        with pytest.raises(ValueError):
            ProjectType(10)


class TestVersion:
    """Tests for the Version node class."""

    def test_default_init(self):
        v = Version()
        assert v.version is None
        assert v.project is None
        assert v.scan_id is None

    def test_set_attributes(self):
        v = Version()
        v.version = "2.3.1"
        v.scan_id = "scan-abc"
        assert v.version == "2.3.1"
        assert v.scan_id == "scan-abc"

    def test_str_contains_fields(self):
        v = Version()
        v.version = "1.0.0"
        result = str(v)
        assert "Version {" in result
        assert "'version': '1.0.0'" in result

    def test_str_with_none_fields(self):
        v = Version()
        result = str(v)
        assert "Version {" in result
        assert "None" in result

    def test_project_association(self, sample_project):
        v = Version()
        v.project = sample_project
        assert v.project.name == "test-project"


class TestProject:
    """Tests for the Project node class."""

    def test_default_init(self):
        p = Project()
        assert p.application_id is None
        assert p.public_app_id is None
        assert p.name is None
        assert p.group is None
        assert p.type is None
        assert p.purl is None
        assert p.modified is None
        assert p.licenses == []
        assert p.repo is None
        assert p.team is None
        assert p.gitlab_project_url is None
        assert p.scan_id is None

    def test_set_all_attributes(self, sample_project):
        assert sample_project.application_id == "app-123"
        assert sample_project.public_app_id == "pub-123"
        assert sample_project.name == "test-project"
        assert sample_project.group == "com.example"
        assert sample_project.type == "application"
        assert sample_project.purl == "pkg:maven/com.example/test-project@1.0.0"
        assert sample_project.repo == "https://gitlab.example.com/test-project"
        assert sample_project.team == "security-team"

    def test_str_contains_fields(self, sample_project):
        result = str(sample_project)
        assert "Project {" in result
        assert "test-project" in result

    def test_str_with_none_fields(self):
        p = Project()
        result = str(p)
        assert "Project {" in result

    def test_licenses_list(self):
        p = Project()
        lic = License()
        lic.id = "MIT"
        p.licenses.append(lic)
        assert len(p.licenses) == 1
        assert p.licenses[0].id == "MIT"

    def test_licenses_not_shared_across_instances(self):
        """Verify that default mutable list is per-instance."""
        p1 = Project()
        p2 = Project()
        p1.licenses.append(License())
        assert len(p2.licenses) == 0


class TestDefect:
    """Tests for the Defect node class."""

    def test_default_init(self):
        d = Defect()
        assert d.id is None
        assert d.type is None
        assert d.discovered is None
        assert d.description is None
        assert d.cwes == []
        assert d.severity is None
        assert d.cvss is None
        assert d.cvss_string is None
        assert d.source is None

    def test_set_all_attributes(self, sample_defect):
        assert sample_defect.id == "CVE-2024-12345"
        assert sample_defect.type == DefectType.SCA
        assert sample_defect.severity == "high"
        assert sample_defect.cwes == [79, 89]
        assert sample_defect.cvss == 8.5
        assert sample_defect.source == ("NVD", "https://nvd.nist.gov")

    def test_cwes_not_shared_across_instances(self):
        d1 = Defect()
        d2 = Defect()
        d1.cwes.append(79)
        assert len(d2.cwes) == 0

    def test_discovered_datetime(self):
        d = Defect()
        d.discovered = datetime(2024, 1, 15, 12, 0, 0)
        assert d.discovered.year == 2024


class TestPolicyType:
    """Tests for the PolicyType string enum."""

    def test_from_str_bad(self):
        assert PolicyType.from_str("bad") == "bad"

    def test_from_str_good(self):
        assert PolicyType.from_str("good") == "good"

    def test_from_str_hold(self):
        assert PolicyType.from_str("hold") == "hold"

    def test_from_str_invalid_raises(self):
        with pytest.raises(ValueError):
            PolicyType.from_str("invalid")

    def test_from_str_none_raises(self):
        with pytest.raises(ValueError):
            PolicyType.from_str(None)


class TestPolicyAnnotation:
    """Tests for the PolicyAnnotation node class."""

    def test_default_init(self):
        pa = PolicyAnnotation()
        assert pa.annotation_id is None
        assert pa.type is None
        assert pa.justification is None
        assert pa.created_by is None
        assert pa.created_at is None
        assert pa.expires_at is None

    def test_set_fields(self):
        pa = PolicyAnnotation()
        pa.annotation_id = "uuid-123"
        pa.type = PolicyType.BAD
        pa.justification = "reason"
        pa.created_by = "admin"
        pa.created_at = "2024-06-01T00:00:00Z"
        pa.expires_at = "2025-01-01T00:00:00Z"
        assert pa.annotation_id == "uuid-123"
        assert pa.type == "bad"


class TestVersionPolicy:
    """Tests for the VersionPolicy edge class."""

    def test_default_init(self):
        vp = VersionPolicy()
        assert vp.version is None
        assert vp.annotation is None


class TestDefectEnrichmentFields:
    """Tests for Defect enrichment metadata fields."""

    def test_new_fields_default(self):
        d = Defect()
        assert d.last_enriched_at is None
        assert d.enrichment_source is None
        assert d.aliases == []

    def test_set_enrichment_fields(self):
        d = Defect()
        d.last_enriched_at = "2024-06-01T00:00:00Z"
        d.enrichment_source = "osv"
        d.aliases = ["CVE-2024-1", "GHSA-xxx"]
        assert d.last_enriched_at == "2024-06-01T00:00:00Z"
        assert len(d.aliases) == 2


class TestLicense:
    """Tests for the License node class."""

    def test_default_init(self):
        lic = License()
        assert lic.spdx_id is None
        assert lic.name is None
        assert lic.url is None
        assert lic.risk_category == "unknown"

    def test_set_spdx_id(self):
        lic = License()
        lic.spdx_id = "Apache-2.0"
        assert lic.spdx_id == "Apache-2.0"


class TestVersionDefect:
    """Tests for the VersionDefect edge class."""

    def test_default_init(self):
        vd = VersionDefect()
        assert vd.project_version is None
        assert vd.defect is None
        assert vd.description is None
        assert vd.risk_status is None
        assert vd.justification is None
        assert vd.review_date is None

    def test_set_all_attributes(self, sample_version, sample_defect):
        vd = VersionDefect()
        vd.project_version = sample_version
        vd.defect = sample_defect
        vd.description = "Needs patching"
        vd.risk_status = RiskStatus.ACCEPTED
        vd.justification = "Mitigated by WAF"
        vd.review_date = datetime(2024, 6, 1)

        assert vd.project_version.version == "1.0.0"
        assert vd.defect.id == "CVE-2024-12345"
        assert vd.risk_status == RiskStatus.ACCEPTED
        assert vd.review_date.month == 6


class TestDependencyVersion:
    """Tests for the DependencyVersion edge class."""

    def test_default_init(self):
        dv = DependencyVersion()
        assert dv.parent_version is None
        assert dv.child_version is None
        assert dv.chosen_license is None
        assert dv.vex_information is None

    def test_set_all_attributes(self, sample_version, sample_library_version):
        dv = DependencyVersion()
        dv.parent_version = sample_version
        dv.child_version = sample_library_version
        lic = License()
        lic.id = "MIT"
        dv.chosen_license = lic
        dv.vex_information = {"status": "not_affected"}

        assert dv.parent_version.version == "1.0.0"
        assert dv.child_version.version == "2.0.0"
        assert dv.chosen_license.id == "MIT"
        assert dv.vex_information["status"] == "not_affected"


class TestHasVersion:
    """Tests for the HasVersion edge class."""

    def test_default_init(self):
        hv = HasVersion()
        assert hv.project is None
        assert hv.version is None

    def test_set_all_attributes(self, sample_project, sample_version):
        hv = HasVersion()
        hv.project = sample_project
        hv.version = sample_version
        assert hv.project.name == "test-project"
        assert hv.version.version == "1.0.0"
