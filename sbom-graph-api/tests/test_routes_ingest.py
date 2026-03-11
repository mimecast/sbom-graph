"""Tests for the SBOM ingest route."""

import hashlib
from unittest.mock import MagicMock, patch

from sbom_graph_model.cyclonedx import CycloneDXValidationError
from sbom_graph_model.spdx import SPDXValidationError


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
            {
                "bom-ref": "comp-1",
                "name": "lib-a",
                "version": "2.0.0",
                "type": "library",
            }
        ],
        "dependencies": [
            {"ref": "app-ref", "dependsOn": ["comp-1"]},
            {"ref": "comp-1", "dependsOn": []},
        ],
    }


def _mock_processor_result():
    """Return a representative result from CycloneDXProcessor.process_cyclone_dx_json."""
    projects = {
        "app-ref": (MagicMock(), MagicMock()),
        "comp-1": (MagicMock(), MagicMock()),
    }
    dependency_versions = {
        "app-ref": {"comp-1"},
    }
    defects: dict = {}
    return projects, dependency_versions, defects


class TestUploadCycloneDX:
    """Tests for POST /ingest/cyclonedx."""

    def test_happy_path(self, client):
        """Valid SBOM is processed and returns 201 with summary."""
        sbom = _minimal_cyclonedx()
        projects, dep_versions, defects = _mock_processor_result()

        with (
            patch("sbom_graph_api.routes.ingest._create_persistence") as mock_persist,
            patch("sbom_graph_api.routes.ingest.CycloneDXProcessor") as mock_processor_cls,
        ):
            mock_processor = MagicMock()
            mock_processor.process_cyclone_dx_json.return_value = (
                projects,
                dep_versions,
                defects,
            )
            mock_processor_cls.return_value = mock_processor
            mock_persist.return_value = MagicMock()

            response = client.post(
                "/ingest/cyclonedx",
                json={"sbom": sbom},
                content_type="application/json",
            )

        assert response.status_code == 201
        data = response.get_json()
        assert data["status"] == "ok"
        assert "record_id" in data
        assert len(data["record_id"]) == 36  # UUID format
        assert data["projects_count"] == 2
        assert data["dependencies_count"] == 1
        assert data["defects_count"] == 0
        assert data["public_app_id"] == "my-app"

    def test_cyclonedx_stores_provenance(self, client):
        """Provenance metadata is stored: create_sbom_record and link_version called."""
        sbom = _minimal_cyclonedx()
        proj, ver = MagicMock(), MagicMock()
        proj.purl = "pkg:maven/com.example/app@1.0.0"
        proj.name = "app"
        proj.group = "com.example"
        ver.version = "1.0.0"
        projects = {"app-ref": (proj, ver)}
        dep_versions = {"app-ref": set()}
        defects = {}

        with (
            patch("sbom_graph_api.routes.ingest._create_persistence") as mock_persist,
            patch("sbom_graph_api.routes.ingest.CycloneDXProcessor") as mock_processor_cls,
        ):
            mock_processor = MagicMock()
            mock_processor.process_cyclone_dx_json.return_value = (
                projects,
                dep_versions,
                defects,
            )
            mock_processor_cls.return_value = mock_processor
            mock_persistence = MagicMock()
            mock_persist.return_value = mock_persistence

            response = client.post(
                "/ingest/cyclonedx",
                json={"sbom": sbom},
                content_type="application/json",
            )

        assert response.status_code == 201
        mock_persistence.create_sbom_record.assert_called_once()
        call_kwargs = mock_persistence.create_sbom_record.call_args.kwargs
        assert call_kwargs["sbom_format"] == "cyclonedx"
        assert call_kwargs["source"] == "api_upload"
        assert "record_id" in call_kwargs
        assert call_kwargs["document_hash"]
        mock_persistence.link_version_to_sbom_record.assert_called_once_with(
            "pkg:maven/com.example/app@1.0.0",
            call_kwargs["record_id"],
        )

    def test_with_optional_params(self, client):
        """Custom app_id, public_app_id, and project_url are forwarded to the processor."""
        sbom = _minimal_cyclonedx()
        projects, dep_versions, defects = _mock_processor_result()

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
                "/ingest/cyclonedx",
                json={
                    "sbom": sbom,
                    "app_id": "custom-id",
                    "public_app_id": "custom-public",
                    "project_url": "https://github.com/org/repo",
                },
                content_type="application/json",
            )

        assert response.status_code == 201
        data = response.get_json()
        assert data["app_id"] == "custom-id"
        assert data["public_app_id"] == "custom-public"

        call_kwargs = mock_processor.process_cyclone_dx_json.call_args
        assert call_kwargs.kwargs["app_id"] == "custom-id"
        assert call_kwargs.kwargs["public_app_id"] == "custom-public"
        assert call_kwargs.kwargs["gitlab_project_url"] == "https://github.com/org/repo"

    def test_auto_derived_ids(self, client):
        """When optional params are omitted, IDs are derived from SBOM metadata."""
        sbom = _minimal_cyclonedx(name="acme-service")
        projects, dep_versions, defects = _mock_processor_result()
        expected_app_id = hashlib.sha1(b"acme-service").hexdigest()  # noqa: S324

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
                "/ingest/cyclonedx",
                json={"sbom": sbom},
                content_type="application/json",
            )

        assert response.status_code == 201
        data = response.get_json()
        assert data["app_id"] == expected_app_id
        assert data["public_app_id"] == "acme-service"

    def test_missing_sbom_field(self, client):
        """Request without 'sbom' key returns 400."""
        response = client.post(
            "/ingest/cyclonedx",
            json={"not_sbom": {}},
            content_type="application/json",
        )

        assert response.status_code == 400
        data = response.get_json()
        assert "error" in data

    def test_sbom_not_a_dict(self, client):
        """Request with 'sbom' as a non-dict returns 400."""
        response = client.post(
            "/ingest/cyclonedx",
            json={"sbom": "not-a-dict"},
            content_type="application/json",
        )

        assert response.status_code == 400
        data = response.get_json()
        assert "error" in data

    def test_non_json_content_type(self, client):
        """Request without application/json Content-Type returns 415."""
        response = client.post(
            "/ingest/cyclonedx",
            data="not json",
            content_type="text/plain",
        )

        assert response.status_code == 415
        data = response.get_json()
        assert "application/json" in data["error"]

    def test_invalid_cyclonedx_structure(self, client):
        """CycloneDXValidationError from the processor returns 422."""
        sbom = {"metadata": {}}  # Missing required fields

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
                "/ingest/cyclonedx",
                json={"sbom": sbom},
                content_type="application/json",
            )

        assert response.status_code == 422
        data = response.get_json()
        assert "validation" in data["error"].lower()

    def test_processor_unexpected_error(self, client):
        """Unexpected exception from the processor returns 500 with generic message."""
        sbom = _minimal_cyclonedx()

        with (
            patch("sbom_graph_api.routes.ingest._create_persistence"),
            patch("sbom_graph_api.routes.ingest.CycloneDXProcessor") as mock_processor_cls,
        ):
            mock_processor = MagicMock()
            mock_processor.process_cyclone_dx_json.side_effect = RuntimeError("Connection refused")
            mock_processor_cls.return_value = mock_processor

            response = client.post(
                "/ingest/cyclonedx",
                json={"sbom": sbom},
                content_type="application/json",
            )

        assert response.status_code == 500
        data = response.get_json()
        assert "unexpected" in data["error"].lower()
        assert "Connection refused" not in data["error"]

    def test_empty_request_body(self, client):
        """Empty request body returns 400."""
        response = client.post(
            "/ingest/cyclonedx",
            data="",
            content_type="application/json",
        )

        assert response.status_code == 400


def _minimal_spdx(name: str = "my-spdx-app") -> dict:
    """Return a minimal valid SPDX 2.3 SBOM structure for testing."""
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": name,
        "packages": [
            {
                "SPDXID": "SPDXRef-Package-app",
                "name": "my-app",
                "versionInfo": "1.0.0",
            },
        ],
        "relationships": [],
    }


class TestUploadSPDX:
    """Tests for POST /ingest/spdx."""

    def test_happy_path(self, client):
        """Valid SPDX SBOM is processed and returns 201 with summary."""
        sbom = _minimal_spdx()
        packages = {"pkg-1": (MagicMock(), MagicMock())}
        dep_versions = {"pkg-1": set()}
        defects = []

        with (
            patch("sbom_graph_api.routes.ingest._create_persistence") as mock_persist,
            patch("sbom_graph_api.routes.ingest.SPDXProcessor") as mock_proc_cls,
        ):
            mock_processor = MagicMock()
            mock_processor.process_spdx_json.return_value = (
                packages,
                dep_versions,
                defects,
            )
            mock_proc_cls.return_value = mock_processor
            mock_persist.return_value = MagicMock()

            response = client.post(
                "/ingest/spdx",
                json={"sbom": sbom},
                content_type="application/json",
            )

        assert response.status_code == 201
        data = response.get_json()
        assert data["status"] == "ok"
        assert "record_id" in data
        assert data["format"] == "spdx"
        assert data["public_app_id"] == "my-spdx-app"

    def test_spdx_stores_provenance_with_tool_info(self, client):
        """SPDX metadata extraction: creationInfo.creators Tool: syft-1.2.3."""
        sbom = _minimal_spdx()
        sbom["creationInfo"] = {
            "creators": ["Tool: syft-1.2.3", "Organization: acme"],
        }
        packages = {"pkg-1": (MagicMock(), MagicMock())}
        dep_versions = {"pkg-1": set()}
        defects = []

        with (
            patch("sbom_graph_api.routes.ingest._create_persistence") as mock_persist,
            patch("sbom_graph_api.routes.ingest.SPDXProcessor") as mock_proc_cls,
        ):
            mock_processor = MagicMock()
            mock_processor.process_spdx_json.return_value = (
                packages,
                dep_versions,
                defects,
            )
            mock_proc_cls.return_value = mock_processor
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
        assert call_kwargs["tool_name"] == "syft"
        assert call_kwargs["tool_version"] == "1.2.3"

    def test_spdx_tool_info_no_version(self, client):
        """SPDX creator Tool: trivy (no version) returns tool_name only."""
        sbom = _minimal_spdx()
        sbom["creationInfo"] = {"creators": ["Tool: trivy"]}
        packages = {"pkg-1": (MagicMock(), MagicMock())}
        dep_versions = {"pkg-1": set()}
        defects = []

        with (
            patch("sbom_graph_api.routes.ingest._create_persistence") as mock_persist,
            patch("sbom_graph_api.routes.ingest.SPDXProcessor") as mock_proc_cls,
        ):
            mock_processor = MagicMock()
            mock_processor.process_spdx_json.return_value = (
                packages,
                dep_versions,
                defects,
            )
            mock_proc_cls.return_value = mock_processor
            mock_persistence = MagicMock()
            mock_persist.return_value = mock_persistence

            response = client.post(
                "/ingest/spdx",
                json={"sbom": sbom},
                content_type="application/json",
            )

        assert response.status_code == 201
        call_kwargs = mock_persistence.create_sbom_record.call_args.kwargs
        assert call_kwargs["tool_name"] == "trivy"
        assert call_kwargs["tool_version"] is None

    def test_spdx_non_json_content_type(self, client):
        """Request without application/json Content-Type returns 415."""
        response = client.post(
            "/ingest/spdx",
            data="not json",
            content_type="text/plain",
        )
        assert response.status_code == 415

    def test_spdx_validation_error(self, client):
        """SPDXValidationError from processor returns 422."""
        sbom = {"metadata": {}}  # Missing spdxVersion, SPDXID, etc.

        with (
            patch("sbom_graph_api.routes.ingest._create_persistence"),
            patch("sbom_graph_api.routes.ingest.SPDXProcessor") as mock_proc_cls,
        ):
            mock_processor = MagicMock()
            mock_processor.process_spdx_json.side_effect = SPDXValidationError(
                "Missing required field: spdxVersion"
            )
            mock_proc_cls.return_value = mock_processor

            response = client.post(
                "/ingest/spdx",
                json={"sbom": sbom},
                content_type="application/json",
            )

        assert response.status_code == 422
        data = response.get_json()
        assert "validation" in data["error"].lower() or "spdx" in data["error"].lower()

    def test_spdx_unexpected_error(self, client):
        """Unexpected exception returns 500 with generic message."""
        sbom = _minimal_spdx()

        with (
            patch("sbom_graph_api.routes.ingest._create_persistence"),
            patch("sbom_graph_api.routes.ingest.SPDXProcessor") as mock_proc_cls,
        ):
            mock_processor = MagicMock()
            mock_processor.process_spdx_json.side_effect = RuntimeError("DB error")
            mock_proc_cls.return_value = mock_processor

            response = client.post(
                "/ingest/spdx",
                json={"sbom": sbom},
                content_type="application/json",
            )

        assert response.status_code == 500
        data = response.get_json()
        assert "unexpected" in data["error"].lower()
        assert "DB error" not in data["error"]


class TestUploadSbomAutoDetect:
    """Tests for POST /ingest/sbom (format auto-detection)."""

    def test_detects_cyclonedx(self, client):
        """SBOM with bomFormat is detected as CycloneDX."""
        sbom = _minimal_cyclonedx()
        projects, dep_versions, defects = _mock_processor_result()

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
        assert data["format"] == "cyclonedx"

    def test_detects_spdx(self, client):
        """SBOM with spdxVersion is detected as SPDX."""
        sbom = _minimal_spdx()
        packages = {"pkg-1": (MagicMock(), MagicMock())}
        dep_versions = {"pkg-1": set()}
        defects = []

        with (
            patch("sbom_graph_api.routes.ingest._create_persistence"),
            patch("sbom_graph_api.routes.ingest.SPDXProcessor") as mock_proc_cls,
        ):
            mock_processor = MagicMock()
            mock_processor.process_spdx_json.return_value = (
                packages,
                dep_versions,
                defects,
            )
            mock_proc_cls.return_value = mock_processor

            response = client.post(
                "/ingest/sbom",
                json={"sbom": sbom},
                content_type="application/json",
            )

        assert response.status_code == 201
        data = response.get_json()
        assert data["format"] == "spdx"

    def test_unrecognised_format_returns_400(self, client):
        """SBOM with unrecognised format returns 400."""
        response = client.post(
            "/ingest/sbom",
            json={"sbom": {"unknown": "format"}},
            content_type="application/json",
        )
        assert response.status_code == 400
        data = response.get_json()
        assert "detect" in data["error"].lower() or "format" in data["error"].lower()
