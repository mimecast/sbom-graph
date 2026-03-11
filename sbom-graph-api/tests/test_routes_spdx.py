"""Tests for SPDX ingest and unified SBOM ingest routes."""

from unittest.mock import MagicMock, patch

from sbom_graph_model.cyclonedx import CycloneDXValidationError
from sbom_graph_model.spdx import SPDXValidationError


def _minimal_spdx(name: str = "my-spdx-doc") -> dict:
    """Return a minimal valid SPDX 2.3 structure for testing."""
    return {
        "spdxVersion": "SPDX-2.3",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": name,
        "packages": [
            {"SPDXID": "SPDXRef-1", "name": "pkg1"},
            {"SPDXID": "SPDXRef-2", "name": "pkg2"},
        ],
        "relationships": [],
    }


def _minimal_cyclonedx(name: str = "my-app", version: str = "1.0.0") -> dict:
    """Return a minimal valid CycloneDX SBOM structure for testing."""
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "metadata": {
            "component": {
                "bom-ref": "app-ref",
                "name": name,
                "version": version,
                "type": "application",
            }
        },
        "components": [
            {"bom-ref": "comp-1", "name": "lib-a", "version": "2.0.0", "type": "library"},
        ],
        "dependencies": [
            {"ref": "app-ref", "dependsOn": ["comp-1"]},
            {"ref": "comp-1", "dependsOn": []},
        ],
    }


def _mock_spdx_result():
    """Return a representative result from SPDXProcessor.process_spdx_json."""
    proj1, ver1 = MagicMock(), MagicMock()
    proj1.purl = "pkg:npm/pkg1@1.0.0"
    proj1.name = "pkg1"
    proj1.group = None
    ver1.version = "1.0.0"
    proj2, ver2 = MagicMock(), MagicMock()
    proj2.purl = None
    proj2.name = "pkg2"
    proj2.group = None
    ver2.version = "2.0.0"
    packages = {"SPDXRef-1": (proj1, ver1), "SPDXRef-2": (proj2, ver2)}
    dependency_versions = {"SPDXRef-1": {"SPDXRef-2"}}
    defects: dict = {}
    return packages, dependency_versions, defects


def _mock_cyclonedx_result():
    """Return a representative result from CycloneDXProcessor.process_cyclone_dx_json."""
    proj1, ver1 = MagicMock(), MagicMock()
    proj1.purl = "pkg:maven/com.example/app@1.0.0"
    proj1.name = "app"
    proj1.group = "com.example"
    ver1.version = "1.0.0"
    proj2, ver2 = MagicMock(), MagicMock()
    proj2.purl = "pkg:maven/com.example/lib@2.0.0"
    proj2.name = "lib"
    proj2.group = "com.example"
    ver2.version = "2.0.0"
    projects = {"app-ref": (proj1, ver1), "comp-1": (proj2, ver2)}
    dependency_versions = {"app-ref": {"comp-1"}}
    defects: dict = {}
    return projects, dependency_versions, defects


class TestUploadSPDX:
    """Tests for POST /ingest/spdx."""

    def test_415_when_not_json(self, client):
        """Request without application/json Content-Type returns 415."""
        response = client.post(
            "/ingest/spdx",
            data="not json",
            content_type="text/plain",
        )
        assert response.status_code == 415
        data = response.get_json()
        assert "application/json" in data["error"]

    def test_400_when_body_not_dict(self, client):
        """Request with body not a JSON object returns 400."""
        response = client.post(
            "/ingest/spdx",
            json=["array", "not", "dict"],
            content_type="application/json",
        )
        assert response.status_code == 400
        data = response.get_json()
        assert "object" in data["error"].lower()

    def test_400_when_sbom_missing(self, client):
        """Request without 'sbom' key returns 400."""
        response = client.post(
            "/ingest/spdx",
            json={"not_sbom": {}},
            content_type="application/json",
        )
        assert response.status_code == 400
        data = response.get_json()
        assert "error" in data

    def test_400_when_sbom_not_a_dict(self, client):
        """Request with 'sbom' as a non-dict returns 400."""
        response = client.post(
            "/ingest/spdx",
            json={"sbom": "not-a-dict"},
            content_type="application/json",
        )
        assert response.status_code == 400
        data = response.get_json()
        assert "error" in data

    def test_422_when_spdx_validation_fails(self, client):
        """SPDXValidationError from the processor returns 422."""
        sbom = {"name": "incomplete"}  # Missing spdxVersion, SPDXID

        with (
            patch("sbom_graph_api.routes.ingest._create_persistence"),
            patch("sbom_graph_api.routes.ingest.SPDXProcessor") as mock_processor_cls,
        ):
            mock_processor = MagicMock()
            mock_processor.process_spdx_json.side_effect = SPDXValidationError(
                "Missing required field: 'spdxVersion'"
            )
            mock_processor_cls.return_value = mock_processor

            response = client.post(
                "/ingest/spdx",
                json={"sbom": sbom},
                content_type="application/json",
            )

        assert response.status_code == 422
        data = response.get_json()
        assert "validation" in data["error"].lower()

    def test_201_on_successful_processing(self, client):
        """Valid SPDX SBOM is processed and returns 201 with summary."""
        sbom = _minimal_spdx()
        packages, dep_versions, defects = _mock_spdx_result()

        with (
            patch("sbom_graph_api.routes.ingest._create_persistence"),
            patch("sbom_graph_api.routes.ingest.SPDXProcessor") as mock_processor_cls,
        ):
            mock_processor = MagicMock()
            mock_processor.process_spdx_json.return_value = (
                packages,
                dep_versions,
                defects,
            )
            mock_processor_cls.return_value = mock_processor

            response = client.post(
                "/ingest/spdx",
                json={"sbom": sbom},
                content_type="application/json",
            )

        assert response.status_code == 201
        data = response.get_json()
        assert data["status"] == "ok"
        assert "record_id" in data
        assert len(data["record_id"]) == 36
        assert data["format"] == "spdx"
        assert data["projects_count"] == 2
        assert data["dependencies_count"] == 1
        assert data["defects_count"] == 0
        assert data["public_app_id"] == "my-spdx-doc"

    def test_spdx_stores_provenance(self, client):
        """SPDX route stores provenance: create_sbom_record and link_version called."""
        sbom = _minimal_spdx()
        proj, ver = MagicMock(), MagicMock()
        proj.purl = "pkg:npm/pkg1@1.0.0"
        proj.name = "pkg1"
        proj.group = None
        ver.version = "1.0.0"
        packages = {"SPDXRef-1": (proj, ver)}
        dep_versions = {"SPDXRef-1": set()}
        defects = {}

        with (
            patch("sbom_graph_api.routes.ingest._create_persistence") as mock_persist,
            patch("sbom_graph_api.routes.ingest.SPDXProcessor") as mock_processor_cls,
        ):
            mock_processor = MagicMock()
            mock_processor.process_spdx_json.return_value = (
                packages,
                dep_versions,
                defects,
            )
            mock_processor_cls.return_value = mock_processor
            mock_persistence = MagicMock()
            mock_persist.return_value = mock_persistence

            response = client.post(
                "/ingest/spdx",
                json={"sbom": sbom},
                content_type="application/json",
            )

        assert response.status_code == 201
        mock_persistence.create_sbom_record.assert_called_once()
        call_kwargs = mock_persistence.create_sbom_record.call_args.kwargs
        assert call_kwargs["sbom_format"] == "spdx"
        assert call_kwargs["source"] == "api_upload"
        mock_persistence.link_version_to_sbom_record.assert_called_once_with(
            "pkg:npm/pkg1@1.0.0",
            call_kwargs["record_id"],
        )

    def test_500_on_unexpected_error(self, client):
        """Unexpected exception from the processor returns 500."""
        sbom = _minimal_spdx()

        with (
            patch("sbom_graph_api.routes.ingest._create_persistence"),
            patch("sbom_graph_api.routes.ingest.SPDXProcessor") as mock_processor_cls,
        ):
            mock_processor = MagicMock()
            mock_processor.process_spdx_json.side_effect = RuntimeError("Connection refused")
            mock_processor_cls.return_value = mock_processor

            response = client.post(
                "/ingest/spdx",
                json={"sbom": sbom},
                content_type="application/json",
            )

        assert response.status_code == 500
        data = response.get_json()
        assert "unexpected" in data["error"].lower()
        assert "Connection refused" not in data["error"]


class TestUploadUnifiedSBOM:
    """Tests for POST /ingest/sbom (unified format auto-detect)."""

    def test_415_when_not_json(self, client):
        """Request without application/json Content-Type returns 415."""
        response = client.post(
            "/ingest/sbom",
            data="not json",
            content_type="text/plain",
        )
        assert response.status_code == 415
        data = response.get_json()
        assert "application/json" in data["error"]

    def test_400_when_body_missing_sbom(self, client):
        """Request without 'sbom' key returns 400."""
        response = client.post(
            "/ingest/sbom",
            json={"other": {}},
            content_type="application/json",
        )
        assert response.status_code == 400
        data = response.get_json()
        assert "error" in data

    def test_400_when_format_undetectable(self, client):
        """Empty sbom dict has no format markers; returns 400."""
        response = client.post(
            "/ingest/sbom",
            json={"sbom": {}},
            content_type="application/json",
        )
        assert response.status_code == 400
        data = response.get_json()
        assert "detect" in data["error"].lower() or "format" in data["error"].lower()

    def test_201_with_cyclonedx_format_autodetected(self, client):
        """CycloneDX format auto-detected via bomFormat; returns 201."""
        sbom = _minimal_cyclonedx()
        projects, dep_versions, defects = _mock_cyclonedx_result()

        with (
            patch("sbom_graph_api.routes.ingest._create_persistence"),
            patch("sbom_graph_api.routes.ingest.CycloneDXProcessor") as mock_processor_cls,
        ):
            mock_processor = MagicMock()
            mock_processor.process_cyclone_dx_json.return_value = (
                projects,
                dep_versions,
                defects,
            )
            mock_processor_cls.return_value = mock_processor

            response = client.post(
                "/ingest/sbom",
                json={"sbom": sbom},
                content_type="application/json",
            )

        assert response.status_code == 201
        data = response.get_json()
        assert data["status"] == "ok"
        assert "record_id" in data
        assert data["format"] == "cyclonedx"
        assert data["public_app_id"] == "my-app"

    def test_201_with_spdx_format_autodetected(self, client):
        """SPDX format auto-detected via spdxVersion; returns 201."""
        sbom = _minimal_spdx()
        packages, dep_versions, defects = _mock_spdx_result()

        with (
            patch("sbom_graph_api.routes.ingest._create_persistence"),
            patch("sbom_graph_api.routes.ingest.SPDXProcessor") as mock_processor_cls,
        ):
            mock_processor = MagicMock()
            mock_processor.process_spdx_json.return_value = (
                packages,
                dep_versions,
                defects,
            )
            mock_processor_cls.return_value = mock_processor

            response = client.post(
                "/ingest/sbom",
                json={"sbom": sbom},
                content_type="application/json",
            )

        assert response.status_code == 201
        data = response.get_json()
        assert data["status"] == "ok"
        assert "record_id" in data
        assert data["format"] == "spdx"
        assert data["public_app_id"] == "my-spdx-doc"

    def test_422_on_validation_error(self, client):
        """Validation error from processor returns 422."""
        sbom = _minimal_cyclonedx()

        with (
            patch("sbom_graph_api.routes.ingest._create_persistence"),
            patch("sbom_graph_api.routes.ingest.CycloneDXProcessor") as mock_processor_cls,
        ):
            mock_processor = MagicMock()
            mock_processor.process_cyclone_dx_json.side_effect = CycloneDXValidationError(
                "Missing metadata.component"
            )
            mock_processor_cls.return_value = mock_processor

            response = client.post(
                "/ingest/sbom",
                json={"sbom": sbom},
                content_type="application/json",
            )

        assert response.status_code == 422
        data = response.get_json()
        assert "validation" in data["error"].lower()

    def test_500_on_unexpected_error(self, client):
        """Unexpected exception returns 500."""
        sbom = _minimal_cyclonedx()

        with (
            patch("sbom_graph_api.routes.ingest._create_persistence"),
            patch("sbom_graph_api.routes.ingest.CycloneDXProcessor") as mock_processor_cls,
        ):
            mock_processor = MagicMock()
            mock_processor.process_cyclone_dx_json.side_effect = RuntimeError("Unexpected failure")
            mock_processor_cls.return_value = mock_processor

            response = client.post(
                "/ingest/sbom",
                json={"sbom": sbom},
                content_type="application/json",
            )

        assert response.status_code == 500
        data = response.get_json()
        assert "unexpected" in data["error"].lower()
