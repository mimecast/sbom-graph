"""Tests for the SPDX processor module.

Covers SPDXProcessor and SPDXValidationError including validation,
parsing, and full processing of SPDX 2.3 JSON SBOM data.
"""

from unittest.mock import MagicMock

import pytest

from sbom_graph_model.model import License, Project, Version
from sbom_graph_model.persistence import Persistence
from sbom_graph_model.spdx.processor import (
    SPDXProcessor,
    SPDXValidationError,
    _extract_group_from_purl,
    _split_spdx_expression,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def spdx_processor(mock_persistence: Persistence) -> SPDXProcessor:
    """Create an SPDXProcessor backed by mock persistence."""
    return SPDXProcessor(persistence=mock_persistence)


@pytest.fixture
def minimal_spdx() -> dict:
    """Create a minimal valid SPDX JSON document."""
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "test-app",
        "documentNamespace": "https://example.com/test-app",
        "packages": [
            {
                "SPDXID": "SPDXRef-RootPackage",
                "name": "test-app",
                "versionInfo": "1.0.0",
                "supplier": "Organization: com.test",
                "downloadLocation": "https://github.com/test/app",
                "licenseConcluded": "MIT",
                "licenseDeclared": "MIT",
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": "pkg:maven/com.test/test-app@1.0.0",
                    }
                ],
            },
            {
                "SPDXID": "SPDXRef-LibA",
                "name": "lib-a",
                "versionInfo": "2.0.0",
                "supplier": "Organization: org.example",
                "downloadLocation": "NOASSERTION",
                "licenseConcluded": "Apache-2.0",
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": "pkg:maven/org.example/lib-a@2.0.0",
                    }
                ],
            },
        ],
        "relationships": [
            {
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relationshipType": "DESCRIBES",
                "relatedSpdxElement": "SPDXRef-RootPackage",
            },
            {
                "spdxElementId": "SPDXRef-RootPackage",
                "relationshipType": "DEPENDS_ON",
                "relatedSpdxElement": "SPDXRef-LibA",
            },
        ],
    }


# ---------------------------------------------------------------------------
# TestSPDXValidationError
# ---------------------------------------------------------------------------


class TestSPDXValidationError:
    """Tests for the SPDXValidationError exception."""

    def test_is_value_error(self):
        assert issubclass(SPDXValidationError, ValueError)

    def test_message_preserved(self):
        err = SPDXValidationError("invalid structure")
        assert str(err) == "invalid structure"

    def test_can_be_caught_as_value_error(self):
        with pytest.raises(ValueError):
            raise SPDXValidationError("test")

    def test_raises_with_match(self):
        with pytest.raises(SPDXValidationError, match="validation failed"):
            raise SPDXValidationError("validation failed")


# ---------------------------------------------------------------------------
# TestValidateSPDXStructure
# ---------------------------------------------------------------------------


class TestValidateSPDXStructure:
    """Tests for SPDXProcessor._validate_spdx_structure."""

    def test_valid_minimal_structure(self, minimal_spdx: dict):
        SPDXProcessor._validate_spdx_structure(minimal_spdx)

    def test_valid_without_packages(self):
        data = {
            "spdxVersion": "SPDX-2.3",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "empty-doc",
        }
        SPDXProcessor._validate_spdx_structure(data)

    def test_rejects_non_dict(self):
        with pytest.raises(SPDXValidationError, match="must be a JSON object"):
            SPDXProcessor._validate_spdx_structure([])

    def test_rejects_none(self):
        with pytest.raises(SPDXValidationError, match="must be a JSON object"):
            SPDXProcessor._validate_spdx_structure(None)

    def test_rejects_missing_spdx_version(self):
        with pytest.raises(SPDXValidationError, match="spdxVersion"):
            SPDXProcessor._validate_spdx_structure(
                {"SPDXID": "SPDXRef-DOCUMENT", "name": "test"}
            )

    def test_rejects_invalid_spdx_version_prefix(self):
        with pytest.raises(SPDXValidationError, match="Invalid spdxVersion"):
            SPDXProcessor._validate_spdx_structure(
                {
                    "spdxVersion": "2.3",
                    "SPDXID": "SPDXRef-DOCUMENT",
                    "name": "test",
                }
            )

    def test_rejects_missing_spdxid(self):
        with pytest.raises(SPDXValidationError, match="SPDXID"):
            SPDXProcessor._validate_spdx_structure(
                {"spdxVersion": "SPDX-2.3", "name": "test"}
            )

    def test_rejects_missing_name(self):
        with pytest.raises(SPDXValidationError, match="'name'"):
            SPDXProcessor._validate_spdx_structure(
                {"spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT"}
            )

    def test_rejects_packages_wrong_type(self, minimal_spdx: dict):
        minimal_spdx["packages"] = "not-a-list"
        with pytest.raises(SPDXValidationError, match="packages.*list"):
            SPDXProcessor._validate_spdx_structure(minimal_spdx)

    def test_rejects_relationships_wrong_type(self, minimal_spdx: dict):
        minimal_spdx["relationships"] = {}
        with pytest.raises(SPDXValidationError, match="relationships.*list"):
            SPDXProcessor._validate_spdx_structure(minimal_spdx)

    def test_rejects_package_non_dict(self, minimal_spdx: dict):
        minimal_spdx["packages"] = ["not-a-dict"]
        with pytest.raises(SPDXValidationError, match="packages\\[0\\].*JSON object"):
            SPDXProcessor._validate_spdx_structure(minimal_spdx)

    def test_rejects_package_missing_spdxid(self, minimal_spdx: dict):
        minimal_spdx["packages"][0] = {"name": "pkg", "versionInfo": "1.0"}
        with pytest.raises(SPDXValidationError, match="packages\\[0\\].*SPDXID"):
            SPDXProcessor._validate_spdx_structure(minimal_spdx)

    def test_rejects_package_missing_name(self, minimal_spdx: dict):
        minimal_spdx["packages"][0] = {"SPDXID": "SPDXRef-Pkg", "versionInfo": "1.0"}
        with pytest.raises(SPDXValidationError, match="packages\\[0\\].*name"):
            SPDXProcessor._validate_spdx_structure(minimal_spdx)


# ---------------------------------------------------------------------------
# TestExtractPurlFromPackage
# ---------------------------------------------------------------------------


class TestExtractPurlFromPackage:
    """Tests for SPDXProcessor._extract_purl_from_package."""

    def test_extracts_from_external_refs_purl(self):
        package = {
            "externalRefs": [
                {"referenceType": "other", "referenceLocator": "x"},
                {
                    "referenceType": "purl",
                    "referenceLocator": "pkg:maven/com.example/foo@1.0",
                },
            ]
        }
        assert SPDXProcessor._extract_purl_from_package(package) == (
            "pkg:maven/com.example/foo@1.0"
        )

    def test_extracts_from_external_references_purl_type(self):
        package = {
            "externalReferences": [
                {"referenceType": "purl-type", "referenceLocator": "pkg:npm/foo@2.0"},
            ]
        }
        assert SPDXProcessor._extract_purl_from_package(package) == "pkg:npm/foo@2.0"

    def test_falls_back_to_package_url(self):
        package = {"packageUrl": "pkg:maven/org/art@3.0"}
        assert SPDXProcessor._extract_purl_from_package(package) == (
            "pkg:maven/org/art@3.0"
        )

    def test_returns_none_when_no_purl(self):
        package = {"name": "foo", "SPDXID": "SPDXRef-Foo"}
        assert SPDXProcessor._extract_purl_from_package(package) is None

    def test_skips_empty_locator(self):
        package = {
            "externalRefs": [{"referenceType": "purl", "referenceLocator": ""}],
        }
        assert SPDXProcessor._extract_purl_from_package(package) is None

    def test_prefers_external_refs_over_package_url(self):
        package = {
            "packageUrl": "pkg:fallback/old@1.0",
            "externalRefs": [
                {"referenceType": "purl", "referenceLocator": "pkg:maven/com/x@2.0"},
            ],
        }
        assert SPDXProcessor._extract_purl_from_package(package) == (
            "pkg:maven/com/x@2.0"
        )


# ---------------------------------------------------------------------------
# TestExtractVcsUrl
# ---------------------------------------------------------------------------


class TestExtractVcsUrl:
    """Tests for SPDXProcessor._extract_vcs_url_from_package."""

    def test_extracts_github_from_external_refs(self):
        package = {
            "externalRefs": [
                {
                    "referenceCategory": "PERSISTENT_ID",
                    "referenceLocator": "https://github.com/org/repo",
                },
            ]
        }
        assert SPDXProcessor._extract_vcs_url_from_package(package) == (
            "https://github.com/org/repo"
        )

    def test_extracts_gitlab_from_external_refs(self):
        package = {
            "externalRefs": [
                {"referenceCategory": "OTHER", "referenceLocator": "https://gitlab.com/g/rep"},
            ]
        }
        assert SPDXProcessor._extract_vcs_url_from_package(package) == (
            "https://gitlab.com/g/rep"
        )

    def test_extracts_from_download_location(self):
        package = {"downloadLocation": "https://github.com/vendor/package"}
        assert SPDXProcessor._extract_vcs_url_from_package(package) == (
            "https://github.com/vendor/package"
        )

    def test_skips_noassertion_download_location(self):
        package = {"downloadLocation": "NOASSERTION"}
        assert SPDXProcessor._extract_vcs_url_from_package(package) is None

    def test_skips_none_download_location(self):
        package = {"downloadLocation": "NONE"}
        assert SPDXProcessor._extract_vcs_url_from_package(package) is None

    def test_skips_empty_download_location(self):
        package = {"downloadLocation": ""}
        assert SPDXProcessor._extract_vcs_url_from_package(package) is None

    def test_returns_none_when_no_vcs(self):
        package = {"name": "foo", "downloadLocation": "NOASSERTION"}
        assert SPDXProcessor._extract_vcs_url_from_package(package) is None


# ---------------------------------------------------------------------------
# TestExtractLicenses
# ---------------------------------------------------------------------------


class TestExtractLicenses:
    """Tests for SPDXProcessor._extract_licenses_from_package."""

    def test_extracts_single_license_concluded(self):
        package = {"licenseConcluded": "MIT"}
        result = SPDXProcessor._extract_licenses_from_package(package)
        assert len(result) == 1
        assert result[0].spdx_id == "MIT"
        assert result[0].name == "MIT"

    def test_extracts_license_declared(self):
        package = {"licenseDeclared": "Apache-2.0"}
        result = SPDXProcessor._extract_licenses_from_package(package)
        assert len(result) == 1
        assert result[0].spdx_id == "Apache-2.0"

    def test_merges_and_deduplicates_concluded_and_declared(self):
        package = {"licenseConcluded": "MIT", "licenseDeclared": "MIT"}
        result = SPDXProcessor._extract_licenses_from_package(package)
        assert len(result) == 1
        assert result[0].spdx_id == "MIT"

    def test_extracts_multiple_from_expression(self):
        package = {"licenseConcluded": "Apache-2.0 OR MIT"}
        result = SPDXProcessor._extract_licenses_from_package(package)
        assert len(result) == 2
        spdx_ids = {lic.spdx_id for lic in result}
        assert spdx_ids == {"Apache-2.0", "MIT"}

    def test_skips_noassertion(self):
        package = {"licenseConcluded": "NOASSERTION"}
        result = SPDXProcessor._extract_licenses_from_package(package)
        assert result == []

    def test_skips_none_value(self):
        package = {"licenseConcluded": "NONE"}
        result = SPDXProcessor._extract_licenses_from_package(package)
        assert result == []

    def test_returns_empty_for_empty_package(self):
        result = SPDXProcessor._extract_licenses_from_package({})
        assert result == []


# ---------------------------------------------------------------------------
# TestParseRepoUrl
# ---------------------------------------------------------------------------


class TestParseRepoUrl:
    """Tests for SPDXProcessor._parse_repo_url."""

    def test_parses_github_url(self):
        result = SPDXProcessor._parse_repo_url("https://github.com/org/repo")
        assert result["namespace"] == "github.com"
        assert result["name"] == "org/repo"
        assert result["vcs_type"] == "git"

    def test_parses_gitlab_url(self):
        result = SPDXProcessor._parse_repo_url("https://gitlab.com/group/sub/repo")
        assert result["namespace"] == "gitlab.com"
        assert result["name"] == "group/sub/repo"
        assert result["vcs_type"] == "git"

    def test_strips_dot_git_suffix(self):
        result = SPDXProcessor._parse_repo_url(
            "https://github.com/org/repo.git/"
        )
        assert result["name"] == "org/repo"
        assert result["vcs_type"] == "git"

    def test_parses_bitbucket(self):
        result = SPDXProcessor._parse_repo_url("https://bitbucket.org/user/repo")
        assert result["namespace"] == "bitbucket.org"
        assert result["name"] == "user/repo"
        assert result["vcs_type"] == "git"

    def test_non_vcs_url_returns_none_vcs_type(self):
        result = SPDXProcessor._parse_repo_url("https://example.com/path")
        assert result["namespace"] == "example.com"
        assert result["name"] == "path"
        assert result["vcs_type"] is None


# ---------------------------------------------------------------------------
# TestSplitSpdxExpression
# ---------------------------------------------------------------------------


class TestSplitSpdxExpression:
    """Tests for _split_spdx_expression module helper."""

    def test_single_license(self):
        assert _split_spdx_expression("MIT") == ["MIT"]

    def test_or_expression(self):
        assert _split_spdx_expression("Apache-2.0 OR MIT") == [
            "Apache-2.0",
            "MIT",
        ]

    def test_and_expression(self):
        assert _split_spdx_expression("MIT AND BSD-3-Clause") == [
            "MIT",
            "BSD-3-Clause",
        ]

    def test_parenthesized_expression(self):
        assert _split_spdx_expression("(MIT AND BSD-3-Clause)") == [
            "MIT",
            "BSD-3-Clause",
        ]

    def test_with_operator(self):
        result = _split_spdx_expression("GPL-2.0-only WITH Classpath-exception-2.0")
        assert "GPL-2.0-only" in result
        assert "Classpath-exception-2.0" in result


# ---------------------------------------------------------------------------
# TestExtractGroupFromPurl
# ---------------------------------------------------------------------------


class TestExtractGroupFromPurl:
    """Tests for _extract_group_from_purl module helper."""

    def test_maven_group(self):
        assert _extract_group_from_purl("pkg:maven/com.example/artifact@1.0") == (
            "com.example"
        )

    def test_npm_scope(self):
        assert _extract_group_from_purl("pkg:npm/@scope/pkg@1.0") == "@scope"

    def test_npm_package_without_scope(self):
        purl = "pkg:npm/package-name@2.0.0"
        result = _extract_group_from_purl(purl)
        assert result is None

    def test_returns_none_for_invalid_purl(self):
        assert _extract_group_from_purl("not-a-purl") is None

    def test_pypi_type_returns_none(self):
        purl = "pkg:pypi/requests@2.28.0"
        result = _extract_group_from_purl(purl)
        assert result is None


# ---------------------------------------------------------------------------
# TestFindRootSpdxId
# ---------------------------------------------------------------------------


class TestFindRootSpdxId:
    """Tests for SPDXProcessor._find_root_spdx_id."""

    def test_finds_root_via_describes_relationship(
        self, spdx_processor: SPDXProcessor, minimal_spdx: dict
    ):
        packages = {p["SPDXID"]: p for p in minimal_spdx["packages"]}
        root_id = spdx_processor._find_root_spdx_id(minimal_spdx, packages)
        assert root_id == "SPDXRef-RootPackage"

    def test_returns_none_when_no_describes(
        self, spdx_processor: SPDXProcessor, minimal_spdx: dict
    ):
        minimal_spdx["relationships"] = [
            {
                "spdxElementId": "SPDXRef-RootPackage",
                "relationshipType": "DEPENDS_ON",
                "relatedSpdxElement": "SPDXRef-LibA",
            },
        ]
        packages = {p["SPDXID"]: p for p in minimal_spdx["packages"]}
        root_id = spdx_processor._find_root_spdx_id(minimal_spdx, packages)
        assert root_id is None

    def test_returns_none_when_target_not_in_packages(
        self, spdx_processor: SPDXProcessor, minimal_spdx: dict
    ):
        minimal_spdx["relationships"] = [
            {
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relationshipType": "DESCRIBES",
                "relatedSpdxElement": "SPDXRef-NonExistent",
            },
        ]
        packages = {p["SPDXID"]: p for p in minimal_spdx["packages"]}
        root_id = spdx_processor._find_root_spdx_id(minimal_spdx, packages)
        assert root_id is None

    def test_returns_none_when_no_relationships(
        self, spdx_processor: SPDXProcessor
    ):
        json_data = {
            "SPDXID": "SPDXRef-DOCUMENT",
            "spdxVersion": "SPDX-2.3",
            "name": "doc",
            "relationships": [],
        }
        root_id = spdx_processor._find_root_spdx_id(json_data, {})
        assert root_id is None

    def test_skips_non_dict_relationships(
        self, spdx_processor: SPDXProcessor, minimal_spdx: dict
    ):
        minimal_spdx["relationships"] = ["invalid", 123]
        packages = {p["SPDXID"]: p for p in minimal_spdx["packages"]}
        root_id = spdx_processor._find_root_spdx_id(minimal_spdx, packages)
        assert root_id is None


# ---------------------------------------------------------------------------
# TestParsePackage
# ---------------------------------------------------------------------------


class TestParsePackage:
    """Tests for SPDXProcessor.parse_package."""

    def test_parses_root_package_full(
        self, spdx_processor: SPDXProcessor, minimal_spdx: dict
    ):
        pkg = minimal_spdx["packages"][0]
        project, version = spdx_processor.parse_package(
            package=pkg,
            scan_id="scan-1",
            is_root=True,
            app_id="app-1",
            public_app_id="pub-1",
            project_url="https://gitlab.com/test/app",
        )
        assert project.name == "test-app"
        assert project.group == "com.test"
        assert project.purl == "pkg:maven/com.test/test-app@1.0.0"
        assert project.type == "application"
        assert project.application_id == "app-1"
        assert project.public_app_id == "pub-1"
        assert project.repo == "https://gitlab.com/test/app"
        assert len(project.licenses) == 1
        assert project.licenses[0].spdx_id == "MIT"

        assert version.version == "1.0.0"
        assert version.scan_id == "scan-1"
        assert version.sbom_format == "spdx"

    def test_parses_library_package(
        self, spdx_processor: SPDXProcessor, minimal_spdx: dict
    ):
        pkg = minimal_spdx["packages"][1]
        project, version = spdx_processor.parse_package(
            package=pkg,
            scan_id="scan-1",
            is_root=False,
        )
        assert project.name == "lib-a"
        assert project.group == "org.example"
        assert project.type == "library"
        assert project.application_id is None
        assert project.public_app_id is None
        assert version.version == "2.0.0"

    def test_extracts_group_from_supplier(self, spdx_processor: SPDXProcessor):
        pkg = {
            "SPDXID": "SPDXRef-Pkg",
            "name": "foo",
            "versionInfo": "1.0",
            "supplier": "Organization: com.myorg",
        }
        project, _ = spdx_processor.parse_package(pkg, "scan-x")
        assert project.group == "com.myorg"

    def test_extracts_group_from_purl_when_no_supplier(
        self, spdx_processor: SPDXProcessor
    ):
        pkg = {
            "SPDXID": "SPDXRef-Pkg",
            "name": "foo",
            "versionInfo": "1.0",
            "externalRefs": [
                {"referenceType": "purl", "referenceLocator": "pkg:maven/org.lib/foo@1.0"},
            ],
        }
        project, _ = spdx_processor.parse_package(pkg, "scan-x")
        assert project.group == "org.lib"

    def test_version_defaults_to_unknown(self, spdx_processor: SPDXProcessor):
        pkg = {"SPDXID": "SPDXRef-Pkg", "name": "bare"}
        _, version = spdx_processor.parse_package(pkg, "scan-x")
        assert version.version == "UNKNOWN"


# ---------------------------------------------------------------------------
# TestProcessSpdxJson (integration)
# ---------------------------------------------------------------------------


class TestProcessSpdxJson:
    """Tests for SPDXProcessor.process_spdx_json integration."""

    def test_processes_minimal_sbom(self, spdx_processor: SPDXProcessor, minimal_spdx: dict):
        packages, deps, defects = spdx_processor.process_spdx_json(
            app_id="app-1",
            public_app_id="pub-1",
            project_url="https://example.com/project",
            json_data=minimal_spdx,
        )
        assert "SPDXRef-RootPackage" in packages
        assert "SPDXRef-LibA" in packages
        root_project, root_version = packages["SPDXRef-RootPackage"]
        assert root_project.name == "test-app"
        assert root_version.version == "1.0.0"
        assert len(defects) == 0
        assert "SPDXRef-RootPackage" in deps
        assert "SPDXRef-LibA" in deps["SPDXRef-RootPackage"]

    def test_invalid_structure_raises(self, spdx_processor: SPDXProcessor):
        with pytest.raises(SPDXValidationError):
            spdx_processor.process_spdx_json(
                app_id="a",
                public_app_id="b",
                project_url=None,
                json_data={},
            )

    def test_persistence_called(self, spdx_processor: SPDXProcessor, mock_graph: MagicMock, minimal_spdx: dict):
        spdx_processor.process_spdx_json(
            app_id="a",
            public_app_id="b",
            project_url=None,
            json_data=minimal_spdx,
        )
        assert mock_graph.query.called

    def test_scan_id_from_document_namespace(
        self, spdx_processor: SPDXProcessor, minimal_spdx: dict
    ):
        packages, _, _ = spdx_processor.process_spdx_json(
            app_id="a",
            public_app_id="b",
            project_url=None,
            json_data=minimal_spdx,
        )
        _, root_version = packages["SPDXRef-RootPackage"]
        assert root_version.scan_id == "https://example.com/test-app"

    def test_empty_packages_list(self, spdx_processor: SPDXProcessor):
        data = {
            "spdxVersion": "SPDX-2.3",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "empty",
            "documentNamespace": "urn:example:empty",
            "packages": [],
            "relationships": [],
        }
        packages, deps, defects = spdx_processor.process_spdx_json(
            app_id="a", public_app_id="b", project_url=None, json_data=data,
        )
        assert len(packages) == 0
        assert len(deps) == 0
        assert len(defects) == 0


# ---------------------------------------------------------------------------
# TestProcessSpdxJsonWithVulnerabilities
# ---------------------------------------------------------------------------


class TestProcessSpdxJsonWithVulnerabilities:
    """Tests for vulnerability handling in SPDX processing."""

    def test_parses_vulnerabilities_with_affects(
        self, spdx_processor: SPDXProcessor, minimal_spdx: dict
    ):
        minimal_spdx["vulnerabilities"] = [
            {
                "id": "CVE-2024-12345",
                "description": "Test vulnerability",
                "ratings": [
                    {"severity": "high", "score": 7.5, "vector": "CVSS:3.1/..."},
                ],
                "source": {"name": "NVD", "url": "https://nvd.nist.gov"},
                "cwes": [79],
                "affects": [{"ref": "SPDXRef-LibA"}],
            },
        ]
        packages, _, defects = spdx_processor.process_spdx_json(
            app_id="a",
            public_app_id="b",
            project_url=None,
            json_data=minimal_spdx,
        )
        assert "CVE-2024-12345" in defects
        defect = defects["CVE-2024-12345"]
        assert defect.id == "CVE-2024-12345"
        assert defect.severity == "high"
        assert defect.cvss == 7.5
        assert defect.cwes == [79]
        assert defect.source == ("NVD", "https://nvd.nist.gov")

    def test_skips_vulnerability_without_id(
        self, spdx_processor: SPDXProcessor, minimal_spdx: dict
    ):
        minimal_spdx["vulnerabilities"] = [
            {"description": "No ID", "affects": []},
        ]
        _, _, defects = spdx_processor.process_spdx_json(
            app_id="a", public_app_id="b", project_url=None, json_data=minimal_spdx,
        )
        assert len(defects) == 0

    def test_skips_non_dict_vulnerability(
        self, spdx_processor: SPDXProcessor, minimal_spdx: dict
    ):
        minimal_spdx["vulnerabilities"] = ["invalid", {"id": "CVE-2"}]
        _, _, defects = spdx_processor.process_spdx_json(
            app_id="a", public_app_id="b", project_url=None, json_data=minimal_spdx,
        )
        assert "CVE-2" in defects
        assert len(defects) == 1

    def test_persists_defects_and_version_defect_edges(
        self, spdx_processor: SPDXProcessor, mock_graph: MagicMock, minimal_spdx: dict
    ):
        minimal_spdx["vulnerabilities"] = [
            {
                "id": "CVE-2024-99999",
                "ratings": [{"severity": "critical", "score": 9.0}],
                "affects": [{"ref": "SPDXRef-LibA"}],
            },
        ]
        spdx_processor.process_spdx_json(
            app_id="a",
            public_app_id="b",
            project_url=None,
            json_data=minimal_spdx,
        )
        assert mock_graph.query.called

    def test_affects_with_unknown_ref_skipped(
        self, spdx_processor: SPDXProcessor, minimal_spdx: dict
    ):
        minimal_spdx["vulnerabilities"] = [
            {
                "id": "CVE-2024-X",
                "affects": [{"ref": "SPDXRef-NonExistent"}],
            },
        ]
        packages, _, defects = spdx_processor.process_spdx_json(
            app_id="a", public_app_id="b", project_url=None, json_data=minimal_spdx,
        )
        assert "CVE-2024-X" in defects
        assert len(defects) == 1
