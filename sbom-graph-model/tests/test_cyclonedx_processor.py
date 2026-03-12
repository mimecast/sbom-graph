"""Tests for the CycloneDX processor module.

Covers CycloneDXProcessor and CycloneDXValidationError including validation,
parsing, and full processing of CycloneDX SBOM data. Exercises both synthetic
minimal fixtures and the customer_portal SBOM resource (acme_corp demo data).
"""

import pytest

from sbom_graph_model.cyclonedx.processor import (
    CycloneDXProcessor,
    CycloneDXValidationError,
)
from sbom_graph_model.model import Defect, Project, ProjectType, Version


# ---------------------------------------------------------------------------
# CycloneDXValidationError
# ---------------------------------------------------------------------------


class TestCycloneDXValidationError:
    """Tests for the CycloneDXValidationError exception."""

    def test_is_value_error(self):
        assert issubclass(CycloneDXValidationError, ValueError)

    def test_message_preserved(self):
        err = CycloneDXValidationError("bad data")
        assert str(err) == "bad data"


# ---------------------------------------------------------------------------
# _validate_cyclonedx_structure
# ---------------------------------------------------------------------------


class TestValidateCycloneDXStructure:
    """Tests for CycloneDXProcessor._validate_cyclonedx_structure."""

    def test_valid_minimal_structure(self, minimal_cyclonedx):
        CycloneDXProcessor._validate_cyclonedx_structure(minimal_cyclonedx)

    def test_valid_admin_console_structure(self, admin_console_sbom):
        CycloneDXProcessor._validate_cyclonedx_structure(admin_console_sbom)

    def test_rejects_non_dict(self):
        with pytest.raises(CycloneDXValidationError, match="must be a JSON object"):
            CycloneDXProcessor._validate_cyclonedx_structure([])

    def test_rejects_none(self):
        with pytest.raises(CycloneDXValidationError, match="must be a JSON object"):
            CycloneDXProcessor._validate_cyclonedx_structure(None)

    def test_rejects_missing_metadata(self):
        with pytest.raises(CycloneDXValidationError, match="metadata"):
            CycloneDXProcessor._validate_cyclonedx_structure({})

    def test_rejects_non_dict_metadata(self):
        with pytest.raises(
            CycloneDXValidationError, match="metadata.*must be a JSON object"
        ):
            CycloneDXProcessor._validate_cyclonedx_structure({"metadata": "bad"})

    def test_rejects_missing_component_in_metadata(self):
        with pytest.raises(CycloneDXValidationError, match="metadata.component"):
            CycloneDXProcessor._validate_cyclonedx_structure({"metadata": {}})

    def test_rejects_non_dict_component(self):
        with pytest.raises(
            CycloneDXValidationError, match="metadata.component.*must be"
        ):
            CycloneDXProcessor._validate_cyclonedx_structure(
                {"metadata": {"component": "bad"}}
            )

    def test_rejects_missing_bom_ref(self):
        with pytest.raises(CycloneDXValidationError, match="bom-ref"):
            CycloneDXProcessor._validate_cyclonedx_structure(
                {"metadata": {"component": {"name": "test"}}}
            )

    def test_rejects_missing_name(self):
        with pytest.raises(CycloneDXValidationError, match="name"):
            CycloneDXProcessor._validate_cyclonedx_structure(
                {"metadata": {"component": {"bom-ref": "ref-1"}}}
            )

    def test_rejects_components_wrong_type(self, minimal_cyclonedx):
        minimal_cyclonedx["components"] = "not-a-list"
        with pytest.raises(
            CycloneDXValidationError, match="components.*must be a list"
        ):
            CycloneDXProcessor._validate_cyclonedx_structure(minimal_cyclonedx)

    def test_rejects_dependencies_wrong_type(self, minimal_cyclonedx):
        minimal_cyclonedx["dependencies"] = {"bad": "type"}
        with pytest.raises(
            CycloneDXValidationError, match="dependencies.*must be a list"
        ):
            CycloneDXProcessor._validate_cyclonedx_structure(minimal_cyclonedx)

    def test_rejects_vulnerabilities_wrong_type(self, minimal_cyclonedx):
        minimal_cyclonedx["vulnerabilities"] = "bad"
        with pytest.raises(
            CycloneDXValidationError, match="vulnerabilities.*must be a list"
        ):
            CycloneDXProcessor._validate_cyclonedx_structure(minimal_cyclonedx)

    def test_rejects_component_non_dict(self, minimal_cyclonedx):
        minimal_cyclonedx["components"] = ["not-a-dict"]
        with pytest.raises(
            CycloneDXValidationError, match="components\\[0\\].*must be"
        ):
            CycloneDXProcessor._validate_cyclonedx_structure(minimal_cyclonedx)

    def test_rejects_component_missing_bom_ref(self, minimal_cyclonedx):
        minimal_cyclonedx["components"] = [{"name": "lib", "version": "1.0"}]
        with pytest.raises(
            CycloneDXValidationError, match="components\\[0\\].*bom-ref"
        ):
            CycloneDXProcessor._validate_cyclonedx_structure(minimal_cyclonedx)

    def test_accepts_without_optional_sections(self):
        data = {
            "metadata": {
                "component": {
                    "bom-ref": "root",
                    "name": "app",
                },
            },
        }
        CycloneDXProcessor._validate_cyclonedx_structure(data)


# ---------------------------------------------------------------------------
# _get_property_value
# ---------------------------------------------------------------------------


class TestGetPropertyValue:
    """Tests for CycloneDXProcessor._get_property_value."""

    def test_finds_existing_property(self):
        props = [
            {"name": "Scan ID", "value": "abc-123"},
            {"name": "Match State", "value": "exact"},
        ]
        assert CycloneDXProcessor._get_property_value(props, "Scan ID") == "abc-123"

    def test_returns_empty_for_missing_property(self):
        props = [{"name": "Other", "value": "val"}]
        assert CycloneDXProcessor._get_property_value(props, "Missing") == ""

    def test_returns_empty_for_empty_list(self):
        assert CycloneDXProcessor._get_property_value([], "Any") == ""

    def test_returns_first_match(self):
        props = [
            {"name": "key", "value": "first"},
            {"name": "key", "value": "second"},
        ]
        assert CycloneDXProcessor._get_property_value(props, "key") == "first"


# ---------------------------------------------------------------------------
# parse_application_from_cyclone_dx
# ---------------------------------------------------------------------------


class TestParseApplicationFromCycloneDx:
    """Tests for CycloneDXProcessor.parse_application_from_cyclone_dx."""

    def test_parses_full_metadata(self):
        metadata = {
            "component": {
                "bom-ref": "ref-123",
                "name": "my-app",
                "group": "com.example",
                "version": "3.0.0",
                "type": "application",
                "purl": "pkg:maven/com.example/my-app@3.0.0",
            },
        }
        bom_ref, (project, version) = (
            CycloneDXProcessor.parse_application_from_cyclone_dx(
                app_id="app-1",
                public_app_id="pub-1",
                scan_id="scan-1",
                metadata_json=metadata,
                gitlab_project_url="https://gitlab.example.com/app",
            )
        )
        assert bom_ref == "ref-123"
        assert project.name == "my-app"
        assert project.group == "com.example"
        assert project.application_id == "app-1"
        assert project.public_app_id == "pub-1"
        assert project.repo == "https://gitlab.example.com/app"
        assert version.version == "3.0.0"
        assert version.scan_id == "scan-1"

    def test_missing_version_defaults_to_unknown(self):
        metadata = {
            "component": {
                "bom-ref": "ref-1",
                "name": "app-no-version",
            },
        }
        _, (_, version) = CycloneDXProcessor.parse_application_from_cyclone_dx(
            app_id="a", public_app_id="b", scan_id="s", metadata_json=metadata,
        )
        assert version.version == "UNKNOWN"

    def test_missing_optional_fields(self):
        metadata = {
            "component": {
                "bom-ref": "ref-1",
                "name": "minimal-app",
            },
        }
        _, (project, _) = CycloneDXProcessor.parse_application_from_cyclone_dx(
            app_id="a", public_app_id="b", scan_id="s", metadata_json=metadata,
        )
        assert project.group is None
        assert project.type is None
        assert project.purl is None

    def test_no_gitlab_url(self):
        metadata = {
            "component": {
                "bom-ref": "ref-1",
                "name": "app",
            },
        }
        _, (project, _) = CycloneDXProcessor.parse_application_from_cyclone_dx(
            app_id="a", public_app_id="b", scan_id="s", metadata_json=metadata,
        )
        assert project.repo is None


# ---------------------------------------------------------------------------
# parse_component_from_cyclone_dx
# ---------------------------------------------------------------------------


class TestParseComponentFromCycloneDx:
    """Tests for CycloneDXProcessor.parse_component_from_cyclone_dx."""

    def test_parses_full_component(self):
        comp = {
            "name": "library-x",
            "group": "org.test",
            "version": "1.2.3",
            "type": "library",
            "purl": "pkg:maven/org.test/library-x@1.2.3",
        }
        project, version = CycloneDXProcessor.parse_component_from_cyclone_dx(
            comp, "scan-1"
        )
        assert project.name == "library-x"
        assert project.group == "org.test"
        assert project.type == ProjectType.Library
        assert version.version == "1.2.3"
        assert version.scan_id == "scan-1"

    def test_missing_optional_fields(self):
        comp = {"name": "bare-lib"}
        project, version = CycloneDXProcessor.parse_component_from_cyclone_dx(
            comp, "scan-x"
        )
        assert project.name == "bare-lib"
        assert project.group is None
        assert project.purl is None
        assert version.version is None


# ---------------------------------------------------------------------------
# parse_defect_from_cyclone_dx
# ---------------------------------------------------------------------------


class TestParseDefectFromCycloneDx:
    """Tests for CycloneDXProcessor.parse_defect_from_cyclone_dx."""

    def test_parses_standard_vulnerability(self):
        vuln = {
            "id": "CVE-2024-99999",
            "source": {"name": "NVD", "url": "https://nvd.nist.gov"},
            "ratings": [
                {
                    "severity": "critical",
                    "score": 9.8,
                    "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                }
            ],
            "cwes": [89, 79],
        }
        defect = CycloneDXProcessor.parse_defect_from_cyclone_dx(vuln)
        assert defect.id == "CVE-2024-99999"
        assert defect.severity == "critical"
        assert defect.cvss == 9.8
        assert defect.cwes == [89, 79]
        assert defect.source == ("NVD", "https://nvd.nist.gov")

    def test_no_cwes(self):
        vuln = {
            "id": "CVE-2024-00001",
            "source": {"name": "NVD", "url": ""},
            "ratings": [{"severity": "low", "score": 2.0}],
        }
        defect = CycloneDXProcessor.parse_defect_from_cyclone_dx(vuln)
        assert defect.cwes == []
        assert defect.cvss_string is None

    def test_source_without_url(self):
        vuln = {
            "id": "CVE-1",
            "source": {"name": "Internal"},
            "ratings": [{"severity": "medium", "score": 5.0}],
        }
        defect = CycloneDXProcessor.parse_defect_from_cyclone_dx(vuln)
        assert defect.source == ("Internal", "")

    def test_multiple_ratings_raises(self):
        vuln = {
            "id": "CVE-multi",
            "source": {"name": "NVD"},
            "ratings": [
                {"severity": "high", "score": 7.5},
                {"severity": "medium", "score": 5.0},
            ],
        }
        with pytest.raises(ValueError, match="multiple ratings"):
            CycloneDXProcessor.parse_defect_from_cyclone_dx(vuln)


# ---------------------------------------------------------------------------
# _get_affects_list
# ---------------------------------------------------------------------------


class TestGetAffectsList:
    """Tests for CycloneDXProcessor._get_affects_list."""

    def test_returns_matching_versions(self):
        project = Project()
        version = Version()
        version.version = "1.0"
        version.project = project
        projects = {"ref-1": (project, version)}

        result = CycloneDXProcessor._get_affects_list(
            [{"ref": "ref-1"}], projects
        )
        assert len(result) == 1
        assert result[0].version == "1.0"

    def test_skips_unknown_refs(self):
        projects = {}
        result = CycloneDXProcessor._get_affects_list(
            [{"ref": "unknown-ref"}], projects
        )
        assert result == []

    def test_empty_affects_list(self):
        result = CycloneDXProcessor._get_affects_list([], {})
        assert result == []

    def test_mixed_known_and_unknown_refs(self):
        p = Project()
        v = Version()
        v.project = p
        projects = {"known": (p, v)}

        result = CycloneDXProcessor._get_affects_list(
            [{"ref": "known"}, {"ref": "unknown"}], projects
        )
        assert len(result) == 1

    def test_missing_ref_key(self):
        projects = {"ref-1": (Project(), Version())}
        result = CycloneDXProcessor._get_affects_list(
            [{"not-ref": "value"}], projects
        )
        assert result == []


# ---------------------------------------------------------------------------
# process_cyclone_dx_json (integration with mocked persistence)
# ---------------------------------------------------------------------------


class TestProcessCycloneDxJson:
    """Tests for CycloneDXProcessor.process_cyclone_dx_json."""

    def test_processes_minimal_sbom(self, processor, minimal_cyclonedx):
        projects, deps, defects = processor.process_cyclone_dx_json(
            app_id="app-1",
            public_app_id="pub-1",
            gitlab_project_url="https://gitlab.example.com",
            json_data=minimal_cyclonedx,
        )
        assert "root-ref" in projects
        assert "comp-1" in projects
        assert "comp-2" in projects
        assert len(defects) == 1
        assert "CVE-2024-00001" in defects

    def test_processes_admin_console_sbom(self, processor, admin_console_sbom):
        projects, deps, defects = processor.process_cyclone_dx_json(
            app_id="portal-app-id",
            public_app_id="customer-portal",
            gitlab_project_url=None,
            json_data=admin_console_sbom,
        )
        assert len(projects) > 50
        assert len(defects) > 0
        root_ref = "11e74f9d-9d27-4741-98ed-c1b96a08041c"
        assert root_ref in projects
        root_project, root_version = projects[root_ref]
        assert root_project.name == "customer-portal"
        assert root_version.version == "2.1.0"

    def test_invalid_structure_raises(self, processor):
        with pytest.raises(CycloneDXValidationError):
            processor.process_cyclone_dx_json(
                app_id="a",
                public_app_id="b",
                gitlab_project_url=None,
                json_data={},
            )

    def test_no_components_section(self, processor, minimal_cyclonedx):
        del minimal_cyclonedx["components"]
        del minimal_cyclonedx["dependencies"]
        del minimal_cyclonedx["vulnerabilities"]
        projects, deps, defects = processor.process_cyclone_dx_json(
            app_id="a",
            public_app_id="b",
            gitlab_project_url=None,
            json_data=minimal_cyclonedx,
        )
        assert "root-ref" in projects
        assert len(defects) == 0

    def test_no_dependencies_section(self, processor, minimal_cyclonedx):
        del minimal_cyclonedx["dependencies"]
        projects, deps, defects = processor.process_cyclone_dx_json(
            app_id="a",
            public_app_id="b",
            gitlab_project_url=None,
            json_data=minimal_cyclonedx,
        )
        assert len(projects) > 0

    def test_no_vulnerabilities_section(self, processor, minimal_cyclonedx):
        del minimal_cyclonedx["vulnerabilities"]
        projects, deps, defects = processor.process_cyclone_dx_json(
            app_id="a",
            public_app_id="b",
            gitlab_project_url=None,
            json_data=minimal_cyclonedx,
        )
        assert len(defects) == 0

    def test_unlinked_libraries_assigned_to_root(self, processor, minimal_cyclonedx):
        """Components not in the dependency tree are linked to the root."""
        minimal_cyclonedx["components"].append({
            "bom-ref": "orphan-1",
            "name": "orphan-lib",
            "group": "org.orphan",
            "version": "0.1.0",
            "type": "library",
        })
        projects, deps, defects = processor.process_cyclone_dx_json(
            app_id="a",
            public_app_id="b",
            gitlab_project_url=None,
            json_data=minimal_cyclonedx,
        )
        assert "orphan-1" in deps.get("root-ref", set())

    def test_persistence_called_for_projects(
        self, processor, mock_graph, minimal_cyclonedx
    ):
        processor.process_cyclone_dx_json(
            app_id="a",
            public_app_id="b",
            gitlab_project_url=None,
            json_data=minimal_cyclonedx,
        )
        assert mock_graph.query.called

    def test_scan_id_extracted_from_properties(self, processor, minimal_cyclonedx):
        projects, _, _ = processor.process_cyclone_dx_json(
            app_id="a",
            public_app_id="b",
            gitlab_project_url=None,
            json_data=minimal_cyclonedx,
        )
        _, root_version = projects["root-ref"]
        assert root_version.scan_id == "scan-123"

    def test_scan_id_empty_when_no_properties(self, processor, minimal_cyclonedx):
        del minimal_cyclonedx["metadata"]["properties"]
        projects, _, _ = processor.process_cyclone_dx_json(
            app_id="a",
            public_app_id="b",
            gitlab_project_url=None,
            json_data=minimal_cyclonedx,
        )
        _, comp_version = projects["comp-1"]
        assert comp_version.scan_id == ""

    def test_empty_components_list(self, processor, minimal_cyclonedx):
        minimal_cyclonedx["components"] = []
        minimal_cyclonedx["dependencies"] = []
        minimal_cyclonedx["vulnerabilities"] = []
        projects, deps, defects = processor.process_cyclone_dx_json(
            app_id="a", public_app_id="b",
            gitlab_project_url=None, json_data=minimal_cyclonedx,
        )
        assert "root-ref" in projects
        assert len(defects) == 0


# ---------------------------------------------------------------------------
# _persist_projects
# ---------------------------------------------------------------------------


class TestPersistProjects:
    """Tests for CycloneDXProcessor._persist_projects."""

    def test_skips_none_version(self, processor):
        p = Project()
        p.name = "test"
        projects = {"ref-1": (p, None)}
        processor._persist_projects(projects)

    def test_creates_versions(self, processor, mock_graph):
        p = Project()
        p.name = "test"
        p.group = "com.test"
        p.type = "library"
        v = Version()
        v.version = "1.0"
        v.project = p

        projects = {"ref-1": (p, v)}
        processor._persist_projects(projects)
        assert mock_graph.query.called


# ---------------------------------------------------------------------------
# _persist_dependencies
# ---------------------------------------------------------------------------


class TestPersistDependencies:
    """Tests for CycloneDXProcessor._persist_dependencies."""

    def test_skips_unknown_parent_ref(self, processor, mock_graph):
        deps = {"unknown-ref": {"comp-1"}}
        projects = {}
        processor._persist_dependencies(deps, projects)
        mock_graph.query.assert_not_called()

    def test_skips_unknown_child_ref(self, processor, mock_graph):
        p = Project()
        p.name = "parent"
        p.group = "com.test"
        v = Version()
        v.version = "1.0"
        v.project = p
        projects = {"parent-ref": (p, v)}
        deps = {"parent-ref": {"unknown-child"}}
        processor._persist_dependencies(deps, projects)
        mock_graph.query.assert_not_called()

    def test_skips_none_parent_version(self, processor, mock_graph):
        p = Project()
        projects = {"parent-ref": (p, None)}
        deps = {"parent-ref": set()}
        processor._persist_dependencies(deps, projects)
        mock_graph.query.assert_not_called()

    def test_skips_none_child_version(self, processor, mock_graph):
        pp = Project()
        pp.name = "parent"
        pp.group = "com.test"
        pv = Version()
        pv.version = "1.0"
        pv.project = pp

        cp = Project()
        projects = {"parent-ref": (pp, pv), "child-ref": (cp, None)}
        deps = {"parent-ref": {"child-ref"}}
        processor._persist_dependencies(deps, projects)
        mock_graph.query.assert_not_called()


# ---------------------------------------------------------------------------
# _persist_defects
# ---------------------------------------------------------------------------


class TestPersistDefects:
    """Tests for CycloneDXProcessor._persist_defects."""

    def test_persists_defects_and_edges(self, processor, mock_graph, minimal_cyclonedx):
        defects = {"CVE-1": Defect()}
        defects["CVE-1"].id = "CVE-1"
        defects["CVE-1"].source = ("NVD", "")
        defects["CVE-1"].severity = "high"

        p = Project()
        p.name = "lib"
        p.group = "com.test"
        v = Version()
        v.version = "1.0"
        v.project = p
        projects = {"comp-1": (p, v)}

        json_data = {
            "vulnerabilities": [
                {
                    "id": "CVE-1",
                    "affects": [{"ref": "comp-1"}],
                }
            ]
        }
        processor._persist_defects(json_data, defects, projects)
        assert mock_graph.query.called

    def test_skips_none_defect_in_dict(self, processor, mock_graph):
        json_data = {"vulnerabilities": []}
        defects = {"CVE-1": None}
        processor._persist_defects(json_data, defects, {})

    def test_skips_none_version_in_affected(self, processor, mock_graph):
        d = Defect()
        d.id = "CVE-1"
        d.source = ("NVD", "")
        d.severity = "low"
        defects = {"CVE-1": d}

        p = Project()
        p.name = "lib"
        p.group = "com.test"
        projects = {"comp-1": (p, None)}

        json_data = {
            "vulnerabilities": [
                {
                    "id": "CVE-1",
                    "affects": [{"ref": "comp-1"}],
                }
            ]
        }
        processor._persist_defects(json_data, defects, projects)

    def test_handles_vulnerability_not_in_defects(self, processor, mock_graph):
        json_data = {
            "vulnerabilities": [
                {"id": "CVE-UNKNOWN", "affects": []},
            ]
        }
        processor._persist_defects(json_data, {}, {})

    def test_handles_empty_affects(self, processor, mock_graph):
        d = Defect()
        d.id = "CVE-1"
        d.source = ("NVD", "")
        d.severity = "low"
        defects = {"CVE-1": d}

        json_data = {
            "vulnerabilities": [
                {"id": "CVE-1", "affects": []},
            ]
        }
        processor._persist_defects(json_data, defects, {})
        assert mock_graph.query.called


# ---------------------------------------------------------------------------
# Customer portal SBOM integration assertions
# ---------------------------------------------------------------------------


class TestAdminConsoleSBOMIntegration:
    """Integration tests using customer_portal SBOM fixture (acme_corp demo)."""

    def test_component_count(self, admin_console_sbom):
        assert len(admin_console_sbom["components"]) > 50

    def test_vulnerability_count(self, admin_console_sbom):
        assert len(admin_console_sbom["vulnerabilities"]) > 5

    def test_dependency_count(self, admin_console_sbom):
        assert len(admin_console_sbom["dependencies"]) > 10

    def test_metadata_scan_id(self, admin_console_sbom):
        props = admin_console_sbom["metadata"]["properties"]
        scan_id = CycloneDXProcessor._get_property_value(props, "Scan ID")
        assert scan_id == "6dfd3c6f3170de9aa8eb0a87845ae3c9"

    def test_all_components_have_bom_ref(self, admin_console_sbom):
        for i, comp in enumerate(admin_console_sbom["components"]):
            assert "bom-ref" in comp, f"Component {i} missing bom-ref"

    def test_all_vulnerabilities_parsed(self, processor, admin_console_sbom):
        projects, deps, defects = processor.process_cyclone_dx_json(
            app_id="test-id",
            public_app_id="customer-portal",
            gitlab_project_url=None,
            json_data=admin_console_sbom,
        )
        vuln_ids = {v["id"] for v in admin_console_sbom["vulnerabilities"]}
        assert set(defects.keys()) == vuln_ids

    def test_root_application_parsed(self, processor, admin_console_sbom):
        projects, _, _ = processor.process_cyclone_dx_json(
            app_id="test-id",
            public_app_id="customer-portal",
            gitlab_project_url="https://bitbucket.acme-corp.internal/customer-portal",
            json_data=admin_console_sbom,
        )
        root_ref = "11e74f9d-9d27-4741-98ed-c1b96a08041c"
        root_project, root_version = projects[root_ref]
        assert root_project.name == "customer-portal"
        assert root_project.group == "com.acme.apps"
        assert root_project.type == ProjectType.Application
        assert root_project.repo == "https://bitbucket.acme-corp.internal/customer-portal"
        assert root_version.version == "2.1.0"
