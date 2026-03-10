"""Tests for the SBOM ingest route."""

import hashlib
from unittest.mock import MagicMock, patch

from sbom_graph_model.cyclonedx import CycloneDXValidationError


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
        assert data["projects_count"] == 2
        assert data["dependencies_count"] == 1
        assert data["defects_count"] == 0
        assert data["public_app_id"] == "my-app"

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
        assert "metadata.component" in data["detail"]

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
