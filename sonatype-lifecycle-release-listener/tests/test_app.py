"""
Test cases for the release listener Flask application.
"""

import hashlib
import hmac
import json
import uuid
import pytest
import requests as requests_lib
from unittest.mock import patch, MagicMock, ANY
from pathlib import Path

from flask.testing import FlaskClient
from werkzeug.exceptions import NotFound
from redis.exceptions import RedisError

from sonatype_lifecycle_release_listener.app import (
    create_app,
    process_release_scan,
    CycloneDXHelper,
    SonaTypeClient,
    VexHelper,
    _verify_hmac,
    _extract_cyclonedx_tool_info,
)


RESOURCES_DIR = Path(__file__).parent / "resources"


def test_logging_conf_uses_streams_not_files():
    """M12 (CWE-532): logging.conf must stream to stdout/stderr only. FileHandlers
    wrote to the CWD, which fails under readOnlyRootFilesystem and silently degraded
    logging to a DEBUG fallback."""
    conf = (Path(__file__).parent / ".." / "logging.conf").resolve()
    content = conf.read_text()
    assert "FileHandler" not in content
    assert "StreamHandler" in content


def _nexus_webhook_signature(secret: str, body: bytes) -> str:
    """Compute Sonatype Lifecycle X-Nexus-Webhook-Signature value."""
    return hmac.new(secret.encode(), body, hashlib.sha1).hexdigest()


class _SigningClient(FlaskClient):
    """Test client that auto-signs POSTs to /webhook.

    The webhook now fails closed (rejects unauthenticated requests), so the test
    suite must present a valid HMAC. This signs the request body with the app's
    configured WEBHOOK_SECRET unless the test already set a signature header
    (so the explicit invalid/valid-signature tests still control their own header).
    """

    def post(self, *args, **kwargs):
        path = args[0] if args else kwargs.get("path", "")
        headers = dict(kwargs.get("headers") or {})
        secret = self.application.config.get("WEBHOOK_SECRET", "")
        if secret and "/webhook" in str(path) and "X-Nexus-Webhook-Signature" not in headers:
            data = kwargs.get("data", b"")
            body = data.encode() if isinstance(data, str) else (data or b"")
            headers["X-Nexus-Webhook-Signature"] = _nexus_webhook_signature(secret, body)
            kwargs["headers"] = headers
        return super().post(*args, **kwargs)


@pytest.fixture
def example_message():
    """Load the example message from test resources."""
    with open(RESOURCES_DIR / "example-message.json", "r") as f:
        return json.load(f)


@pytest.fixture
def example_cyclonedx():
    """Load the example CycloneDX SBOM from test resources (acme_corp demo data)."""
    with open(RESOURCES_DIR / "acme_notification_service_sbom.json", "r") as f:
        return json.load(f)


@pytest.fixture
def example_vex():
    """Load the example VEX document from test resources."""
    with open(RESOURCES_DIR / "example_vex.json", "r") as f:
        return json.load(f)


@pytest.fixture
def app():
    """Create a test Flask application."""
    test_config = {
        "TESTING": True,
        "SONATYPE_HOST": "sonatype.example.com",
        "SONATYPE_USERNAME": "test_user",
        "SONATYPE_PASSWORD": "test_pass",
        "SONATYPE_CACERTS": "certs/ca_bundle.pem",
        "FALKORDB_HOST": "localhost",
        "FALKORDB_PORT": 6379,
        "FALKORDB_GRAPH_NAME": "test-graph",
        "FALKORDB_PASSWORD": "",
        "FALKORDB_CACERTS": "certs/ca_bundle.pem",
        # Webhook now fails closed; tests run with a configured secret and the
        # signing test client (below) signs /webhook POSTs automatically.
        "WEBHOOK_SECRET": "test-webhook-secret",
    }
    app = create_app(test_config)
    app.test_client_class = _SigningClient
    return app


@pytest.fixture
def client(app):
    """Create a test client for the Flask application."""
    return app.test_client()


class TestHealthEndpoint:
    """Tests for the health check endpoint."""

    def test_health_check_returns_200(self, client):
        """Test that health check returns 200 status."""
        response = client.get("/health")
        assert response.status_code == 200

    def test_health_check_returns_healthy_status(self, client):
        """Test that health check returns healthy status in JSON."""
        response = client.get("/health")
        data = json.loads(response.data)
        assert data["status"] == "healthy"


class TestWebhookEndpoint:
    """Tests for the webhook endpoint."""

    def test_empty_payload_returns_400(self, client):
        """Test that empty payload returns 400 error."""
        response = client.post("/webhook", data="", content_type="application/json")
        assert response.status_code == 400

    def test_missing_secret_fails_closed(self):
        """SECURITY (CWE-306): with no WEBHOOK_SECRET the endpoint rejects (503),
        never processing a webhook unauthenticated — protects against the secret
        being removed from the deployment."""
        app_no_secret = create_app({"TESTING": True, "WEBHOOK_SECRET": ""})
        resp = app_no_secret.test_client().post(
            "/webhook",
            data=json.dumps({"id": "x"}),
            content_type="application/json",
        )
        assert resp.status_code == 503

    def test_invalid_json_returns_400(self, client):
        """Test that invalid JSON returns 400 error."""
        response = client.post(
            "/webhook", data="not json", content_type="application/json"
        )
        assert response.status_code == 400

    def test_message_without_application_evaluation_is_ignored(self, client):
        """Test that messages without applicationEvaluation are ignored."""
        message = {"id": "test123", "timestamp": "2020-04-22T18:30:04.673+0000"}
        response = client.post(
            "/webhook", data=json.dumps(message), content_type="application/json"
        )
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data["status"] == "ignored"
        assert "No applicationEvaluation" in data["reason"]

    def test_non_release_stage_is_ignored(self, client, example_message):
        """Test that non-release stages are ignored."""
        example_message["applicationEvaluation"]["stage"] = "build"

        response = client.post(
            "/webhook",
            data=json.dumps(example_message),
            content_type="application/json",
        )
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data["status"] == "ignored"
        assert "not release" in data["reason"]

    def test_missing_app_id_returns_400(self, client, example_message):
        """Test that missing application ID returns 400 error."""
        del example_message["applicationEvaluation"]["application"]["id"]

        response = client.post(
            "/webhook",
            data=json.dumps(example_message),
            content_type="application/json",
        )
        assert response.status_code == 400
        data = json.loads(response.data)
        assert "Missing application id" in data["error"]

    def test_missing_public_id_returns_400(self, client, example_message):
        """Test that missing publicId returns 400 error."""
        del example_message["applicationEvaluation"]["application"]["publicId"]

        response = client.post(
            "/webhook",
            data=json.dumps(example_message),
            content_type="application/json",
        )
        assert response.status_code == 400
        data = json.loads(response.data)
        assert "Missing application id" in data["error"]

    def test_null_json_payload_returns_400(self, client):
        """Test that a JSON null body returns 400 error."""
        response = client.post("/webhook", data="null", content_type="application/json")
        assert response.status_code == 400
        data = json.loads(response.data)
        assert "Invalid JSON payload" in data["error"]

    @patch("sonatype_lifecycle_release_listener.app.process_release_scan")
    def test_unhandled_not_found_returns_500(
        self, mock_process, client, example_message
    ):
        """Test that an unhandled NotFound from processing returns 500."""
        mock_process.side_effect = NotFound("Unexpected error")

        response = client.post(
            "/webhook",
            data=json.dumps(example_message),
            content_type="application/json",
        )
        assert response.status_code == 500
        data = json.loads(response.data)
        assert data["status"] == "error"

    @patch("sonatype_lifecycle_release_listener.app.process_release_scan")
    def test_unhandled_redis_error_returns_500(
        self, mock_process, client, example_message
    ):
        """Test that an unhandled RedisError from processing returns 500."""
        mock_process.side_effect = RedisError("Connection lost")

        response = client.post(
            "/webhook",
            data=json.dumps(example_message),
            content_type="application/json",
        )
        assert response.status_code == 500
        data = json.loads(response.data)
        assert data["status"] == "error"

    @patch("sonatype_lifecycle_release_listener.app.process_release_scan")
    def test_release_scan_is_processed(self, mock_process, client, example_message):
        """Test that release scans are processed correctly."""
        mock_process.return_value = {"success": True}

        response = client.post(
            "/webhook",
            data=json.dumps(example_message),
            content_type="application/json",
        )

        assert response.status_code == 200
        data = json.loads(response.data)
        assert data["status"] == "processed"
        assert data["application"] == "My-Application-ID"

        mock_process.assert_called_once_with(
            app_id="0f256982c80b4e13abef4917b93ac343",
            public_id="My-Application-ID",
            config=ANY,
        )

    @patch("sonatype_lifecycle_release_listener.app.process_release_scan")
    def test_process_failure_returns_500(self, mock_process, client, example_message):
        """Test that processing failures return 500 error with opaque message."""
        mock_process.return_value = {"success": False, "error": "Connection failed"}

        response = client.post(
            "/webhook",
            data=json.dumps(example_message),
            content_type="application/json",
        )

        assert response.status_code == 500
        data = json.loads(response.data)
        assert data["status"] == "error"
        assert "message" in data
        assert "reference" in data

    def test_hmac_invalid_signature_returns_403(self, app, example_message):
        """Test that invalid HMAC signature returns 403 when WEBHOOK_SECRET set."""
        app.config["WEBHOOK_SECRET"] = "my-secret"
        test_client = app.test_client()
        body = json.dumps(example_message).encode()

        response = test_client.post(
            "/webhook",
            data=body,
            content_type="application/json",
            headers={"X-Nexus-Webhook-Signature": "invalid"},
        )

        assert response.status_code == 403
        data = json.loads(response.data)
        assert "Invalid signature" in data["error"]

    def test_hmac_valid_signature_is_accepted(self, app, example_message):
        """Test that a valid Sonatype HMAC signature passes verification."""
        secret = "my-secret"
        app.config["WEBHOOK_SECRET"] = secret
        test_client = app.test_client()
        example_message["applicationEvaluation"]["stage"] = "build"
        body = json.dumps(example_message).encode()

        response = test_client.post(
            "/webhook",
            data=body,
            content_type="application/json",
            headers={
                "X-Nexus-Webhook-Signature": _nexus_webhook_signature(secret, body),
                "X-Nexus-Webhook-Signature-Algorithm": "HmacSHA1",
            },
        )

        assert response.status_code == 200
        data = json.loads(response.data)
        assert data["status"] == "ignored"


class TestProcessReleaseScan:
    """Tests for the process_release_scan function."""

    TEST_CONFIG = {
        "SONATYPE_HOST": "sonatype.example.com",
        "SONATYPE_USERNAME": "test_user",
        "SONATYPE_PASSWORD": "test_pass",
        "SONATYPE_CACERTS": "certs/ca_bundle.pem",
        "FALKORDB_HOST": "localhost",
        "FALKORDB_PORT": 6379,
        "FALKORDB_GRAPH_NAME": "test-graph",
        "FALKORDB_PASSWORD": "",
        "FALKORDB_CACERTS": "certs/ca_bundle.pem",
    }

    @patch("sonatype_lifecycle_release_listener.app.CycloneDXHelper")
    def test_creates_cyclone_helper_with_config(self, mock_helper_class):
        """Test that CycloneDXHelper is created with the provided config."""
        mock_helper = MagicMock()
        mock_helper_class.return_value = mock_helper

        process_release_scan(
            app_id="test_app_id",
            public_id="test_public_id",
            config=self.TEST_CONFIG,
        )

        mock_helper_class.assert_called_once_with(self.TEST_CONFIG)

    @patch("sonatype_lifecycle_release_listener.app.CycloneDXHelper")
    def test_calls_process_cyclonedx_sbom_correctly(self, mock_helper_class):
        """Test that process_cyclonedx_sbom is called with correct parameters."""
        mock_helper = MagicMock()
        mock_helper_class.return_value = mock_helper

        process_release_scan(
            app_id="test_app_id",
            public_id="test_public_id",
            config=self.TEST_CONFIG,
        )

        mock_helper.process_cyclonedx_sbom.assert_called_once_with(
            app_id="test_app_id",
            public_app_id="test_public_id",
        )

    @patch("sonatype_lifecycle_release_listener.app.CycloneDXHelper")
    def test_returns_success_on_successful_processing(self, mock_helper_class):
        """Test that function returns success on successful processing."""
        mock_helper = MagicMock()
        mock_helper_class.return_value = mock_helper

        result = process_release_scan(
            app_id="test_app_id",
            public_id="test_public_id",
            config=self.TEST_CONFIG,
        )

        assert result["success"] is True

    @patch("sonatype_lifecycle_release_listener.app.CycloneDXHelper")
    def test_returns_failure_on_not_found(self, mock_helper_class):
        """Test that function returns failure when SBOM is not found."""
        mock_helper = MagicMock()
        mock_helper_class.return_value = mock_helper
        mock_helper.process_cyclonedx_sbom.side_effect = NotFound("SBOM not found")

        result = process_release_scan(
            app_id="test_app_id",
            public_id="test_public_id",
            config=self.TEST_CONFIG,
        )

        assert result["success"] is False
        assert result["error"] == "SBOM processing failed"

    @patch("sonatype_lifecycle_release_listener.app.CycloneDXHelper")
    def test_returns_failure_on_redis_error(self, mock_helper_class):
        """Test that function returns failure on FalkorDB connection error."""
        mock_helper_class.side_effect = RedisError("Connection refused")

        result = process_release_scan(
            app_id="test_app_id",
            public_id="test_public_id",
            config=self.TEST_CONFIG,
        )

        assert result["success"] is False
        assert result["error"] == "SBOM processing failed"

    @patch("sonatype_lifecycle_release_listener.app.VexHelper")
    @patch("sonatype_lifecycle_release_listener.app.CycloneDXHelper")
    def test_webhook_processes_both_sbom_and_vex(
        self, mock_cyclone_class, mock_vex_class
    ):
        """Test that process_release_scan attempts both SBOM and VEX processing."""
        mock_cyclone = MagicMock()
        mock_cyclone_class.return_value = mock_cyclone

        mock_vex = MagicMock()
        mock_vex.process_vex_for_application.return_value = {
            "statements_processed": 2,
            "linked_vulnerabilities": 2,
        }
        mock_vex_class.return_value = mock_vex

        result = process_release_scan(
            app_id="test_app_id",
            public_id="test_public_id",
            config=self.TEST_CONFIG,
        )

        assert result["success"] is True
        mock_cyclone.process_cyclonedx_sbom.assert_called_once_with(
            app_id="test_app_id",
            public_app_id="test_public_id",
        )
        mock_vex.process_vex_for_application.assert_called_once_with("test_app_id")

    @patch("sonatype_lifecycle_release_listener.app.VexHelper")
    @patch("sonatype_lifecycle_release_listener.app.CycloneDXHelper")
    def test_vex_failure_does_not_block_webhook_success(
        self, mock_cyclone_class, mock_vex_class
    ):
        """Test that VEX processing failure is non-fatal; webhook still succeeds."""
        mock_cyclone = MagicMock()
        mock_cyclone_class.return_value = mock_cyclone

        mock_vex = MagicMock()
        mock_vex.process_vex_for_application.side_effect = Exception("VEX API error")

        mock_vex_class.return_value = mock_vex

        result = process_release_scan(
            app_id="test_app_id",
            public_id="test_public_id",
            config=self.TEST_CONFIG,
        )

        assert result["success"] is True
        mock_cyclone.process_cyclonedx_sbom.assert_called_once()
        mock_vex.process_vex_for_application.assert_called_once()


class TestIntegrationWithMockedSonatype:
    """Integration tests using mocked SonaType responses."""

    @patch("sonatype_lifecycle_release_listener.app.CycloneDXHelper")
    def test_full_webhook_flow(self, mock_helper_class, client, example_message):
        """Test full webhook flow with mocked CycloneDXHelper."""
        mock_helper = MagicMock()
        mock_helper_class.return_value = mock_helper

        response = client.post(
            "/webhook",
            data=json.dumps(example_message),
            content_type="application/json",
        )

        assert response.status_code == 200
        data = json.loads(response.data)
        assert data["status"] == "processed"

        mock_helper.process_cyclonedx_sbom.assert_called_once_with(
            app_id="0f256982c80b4e13abef4917b93ac343",
            public_app_id="My-Application-ID",
        )

    @patch("sonatype_lifecycle_release_listener.app.CycloneDXHelper")
    def test_multiple_webhook_messages_processed_sequentially(
        self, mock_helper_class, client, example_message
    ):
        """Test that multiple webhook messages are processed sequentially."""
        mock_helper = MagicMock()
        mock_helper_class.return_value = mock_helper

        response1 = client.post(
            "/webhook",
            data=json.dumps(example_message),
            content_type="application/json",
        )
        assert response1.status_code == 200

        example_message["applicationEvaluation"]["application"]["id"] = (
            "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"
        )
        example_message["applicationEvaluation"]["application"]["publicId"] = (
            "Second-Application"
        )

        response2 = client.post(
            "/webhook",
            data=json.dumps(example_message),
            content_type="application/json",
        )
        assert response2.status_code == 200

        assert mock_helper.process_cyclonedx_sbom.call_count == 2


@pytest.mark.integration
class TestFalkorDBIntegration:
    """
    Integration tests that verify FalkorDB content.

    These tests require FalkorDB to be running at localhost:6379.
    They test the actual database insertion behavior by mocking the SonaType
    API call and using the real FalkorDB instance.

    Skipped by default in CI/CD. Run locally with:
        uv run pytest -m integration
    """

    FALKORDB_CONFIG = {
        "SONATYPE_HOST": "sonatype.example.com",
        "SONATYPE_USERNAME": "test_user",
        "SONATYPE_PASSWORD": "test_pass",
        "SONATYPE_CACERTS": "certs/ca_bundle.pem",
        "FALKORDB_HOST": "localhost",
        "FALKORDB_PORT": 6379,
        "FALKORDB_GRAPH_NAME": "acme_corp",
        "FALKORDB_PASSWORD": "",
        "FALKORDB_CACERTS": "",
    }

    @pytest.fixture
    def falkordb_connection(self):
        """Create a FalkorDB connection for verification."""
        try:
            from falkordb import FalkorDB

            db = FalkorDB(host="localhost", port=6379)
            graph = db.select_graph("acme_corp")
            yield graph
        except (OSError, ConnectionError, TimeoutError) as e:
            pytest.skip(f"FalkorDB not available: {e}")

    @patch("sonatype_lifecycle_release_listener.app.SonaTypeClient.get_cyclonedx_sbom")
    def test_dependency_tree_inserted_into_falkordb(
        self, mock_get_sbom, example_cyclonedx, falkordb_connection
    ):
        """
        Test that dependency tree is correctly inserted into FalkorDB.

        This test mocks the SonaType API but uses the real FalkorDB.
        """
        mock_get_sbom.return_value = example_cyclonedx

        try:
            helper = CycloneDXHelper(self.FALKORDB_CONFIG)
        except (OSError, ConnectionError, RedisError) as e:
            pytest.skip(f"FalkorDB not available: {e}")

        helper.process_cyclonedx_sbom(
            app_id="test_app_id",
            public_app_id="test_public_id",
        )

        mock_get_sbom.assert_called_once()

        result = falkordb_connection.query(
            "MATCH (v:Version {project_name: 'notification-service'}) "
            "RETURN count(v) as count"
        )
        count = result.result_set[0][0] if result.result_set else 0
        assert count > 0, "Expected the application Version node to exist in FalkorDB"

    @patch("sonatype_lifecycle_release_listener.app.SonaTypeClient.get_cyclonedx_sbom")
    def test_defects_inserted_into_falkordb(
        self, mock_get_sbom, example_cyclonedx, falkordb_connection
    ):
        """
        Test that defects are correctly inserted into FalkorDB.
        """
        mock_get_sbom.return_value = example_cyclonedx

        try:
            helper = CycloneDXHelper(self.FALKORDB_CONFIG)
        except (OSError, ConnectionError, RedisError) as e:
            pytest.skip(f"FalkorDB not available: {e}")

        helper.process_cyclonedx_sbom(
            app_id="test_app_id",
            public_app_id="test_public_id",
        )

        mock_get_sbom.assert_called_once()

        result = falkordb_connection.query("MATCH (d:Defect) RETURN count(d) as count")
        defect_count = result.result_set[0][0] if result.result_set else 0
        assert defect_count > 0, "Expected Defect nodes to exist in FalkorDB"


class TestSbomRecordIdempotency:
    """SAST L2: a re-delivered webhook must converge to the same SBOMRecord
    instead of accumulating duplicates. record_id is derived deterministically
    from the SBOM content + public app id (uuid5), so re-ingesting identical
    content is an idempotent MERGE rather than a fresh node per replay."""

    CONFIG = {"FALKORDB_HOST": "localhost"}

    SBOM = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": "urn:uuid:1111",
        "components": [
            {"name": "lib", "version": "1.0", "purl": "pkg:pypi/lib@1.0"}
        ],
    }

    def _make_helper(self, sbom):
        with patch(
            "sonatype_lifecycle_release_listener.app._listener_ingestion_persistence"
        ), patch(
            "sonatype_lifecycle_release_listener.app.SonaTypeClient"
        ) as mock_client_cls, patch(
            "sonatype_lifecycle_release_listener.app.CycloneDXProcessor"
        ) as mock_proc_cls:
            mock_client_cls.return_value.get_cyclonedx_sbom.return_value = sbom
            mock_proc_cls.return_value.process_cyclone_dx_json.return_value = (
                {},
                {},
                [],
            )
            return CycloneDXHelper(self.CONFIG)

    @staticmethod
    def _expected_id(public_app_id, sbom):
        doc_hash = hashlib.sha256(
            json.dumps(sbom, sort_keys=True).encode("utf-8")
        ).hexdigest()
        return str(
            uuid.uuid5(uuid.NAMESPACE_URL, f"sbom:{public_app_id}:{doc_hash}")
        )

    def test_same_content_yields_same_record_id(self):
        helper = self._make_helper(self.SBOM)
        rid1 = helper.process_cyclonedx_sbom(app_id="a1", public_app_id="pub")
        rid2 = helper.process_cyclonedx_sbom(app_id="a1", public_app_id="pub")
        assert rid1 == rid2 == self._expected_id("pub", self.SBOM)
        # Both ingests MERGE the same SBOMRecord identity (no duplicate node).
        ids = [
            c.kwargs["record_id"]
            for c in helper.persistence.create_sbom_record.call_args_list
        ]
        assert ids == [rid1, rid1]

    def test_different_app_yields_different_record_id(self):
        helper = self._make_helper(self.SBOM)
        rid_a = helper.process_cyclonedx_sbom(app_id="a1", public_app_id="pubA")
        rid_b = helper.process_cyclonedx_sbom(app_id="a1", public_app_id="pubB")
        assert rid_a != rid_b

    def test_changed_content_yields_different_record_id(self):
        helper = self._make_helper(self.SBOM)
        rid1 = helper.process_cyclonedx_sbom(app_id="a1", public_app_id="pub")
        helper.sonatype_client.get_cyclonedx_sbom.return_value = {
            **self.SBOM,
            "components": [{"name": "lib", "version": "2.0"}],
        }
        rid2 = helper.process_cyclonedx_sbom(app_id="a1", public_app_id="pub")
        assert rid1 != rid2


class TestResourceCleanup:
    """Leak fix: a per-webhook helper must release its FalkorDB connection and
    Sonatype HTTP session on every path (success and error)."""

    _APP = "sonatype_lifecycle_release_listener.app"

    def test_helper_close_releases_resources(self):
        with patch(f"{self._APP}._listener_ingestion_persistence"), patch(
            f"{self._APP}.SonaTypeClient"
        ), patch(f"{self._APP}.CycloneDXProcessor"):
            helper = CycloneDXHelper({"FALKORDB_HOST": "localhost"})
        helper.close()
        helper.persistence.close.assert_called_once()
        helper.sonatype_client.close.assert_called_once()

    def test_process_release_scan_closes_helpers_on_success(self):
        with patch(f"{self._APP}.CycloneDXHelper") as mock_cyc, patch(
            f"{self._APP}.VexHelper"
        ) as mock_vex:
            mock_vex.return_value.process_vex_for_application.return_value = None
            result = process_release_scan("app", "pub", {})
        assert result["success"] is True
        mock_cyc.return_value.close.assert_called_once()
        mock_vex.return_value.close.assert_called_once()

    def test_process_release_scan_closes_helper_on_error(self):
        with patch(f"{self._APP}.CycloneDXHelper") as mock_cyc:
            mock_cyc.return_value.process_cyclonedx_sbom.side_effect = NotFound("x")
            result = process_release_scan("app", "pub", {})
        assert result["success"] is False
        # cyclone helper still closed via finally on the error path
        mock_cyc.return_value.close.assert_called_once()


class TestSonaTypeClient:
    """Tests for the SonaTypeClient class."""

    TEST_CONFIG = {
        "SONATYPE_HOST": "sonatype.example.com",
        "SONATYPE_USERNAME": "test_user",
        "SONATYPE_PASSWORD": "test_pass",
        "SONATYPE_CACERTS": "certs/ca_bundle.pem",
    }

    def test_init_sets_attributes_from_config(self):
        """Test that SonaTypeClient reads config values correctly."""
        client = SonaTypeClient(self.TEST_CONFIG)
        assert client.sonatype_host == "sonatype.example.com"
        assert client.sonatype_username == "test_user"
        assert client.sonatype_password == "test_pass"
        assert client.cacerts == "certs/ca_bundle.pem"
        assert client.api_url == "https://sonatype.example.com/api/v2/"

    def test_init_uses_defaults_for_missing_config(self):
        """Test that SonaTypeClient falls back to defaults for missing keys."""
        client = SonaTypeClient({})
        assert client.sonatype_host == ""
        assert client.sonatype_username == ""
        assert client.cacerts == "certs/ca_bundle.pem"

    def test_get_cyclonedx_sbom_success(self):
        """Test successful SBOM retrieval."""
        client = SonaTypeClient(self.TEST_CONFIG)
        mock_response = MagicMock()
        mock_response.json.return_value = {"bomFormat": "CycloneDX"}
        client.session = MagicMock()
        client.session.get.return_value = mock_response

        result = client.get_cyclonedx_sbom("app123")

        assert result == {"bomFormat": "CycloneDX"}
        mock_response.raise_for_status.assert_called_once()
        url_arg = client.session.get.call_args[0][0]
        assert "cycloneDx/1.5/app123/stages/release/" in url_arg

    def test_get_cyclonedx_sbom_with_custom_headers(self):
        """Test that custom headers are merged with the accept header."""
        client = SonaTypeClient(self.TEST_CONFIG)
        mock_response = MagicMock()
        mock_response.json.return_value = {}
        client.session = MagicMock()
        client.session.get.return_value = mock_response

        client.get_cyclonedx_sbom("app123", headers={"X-Custom": "value"})

        call_kwargs = client.session.get.call_args
        headers = call_kwargs.kwargs.get("headers", call_kwargs[1].get("headers"))
        assert headers["accept"] == "application/json"
        assert headers["X-Custom"] == "value"

    def test_get_cyclonedx_sbom_custom_version_and_stage(self):
        """Test SBOM retrieval with non-default version and stage."""
        client = SonaTypeClient(self.TEST_CONFIG)
        mock_response = MagicMock()
        mock_response.json.return_value = {}
        client.session = MagicMock()
        client.session.get.return_value = mock_response

        client.get_cyclonedx_sbom("app123", version="1.4", stage_id="build")

        url_arg = client.session.get.call_args[0][0]
        assert "cycloneDx/1.4/app123/stages/build/" in url_arg

    def test_get_cyclonedx_sbom_raises_not_found_on_request_error(self):
        """Test that a request error is wrapped in NotFound."""
        client = SonaTypeClient(self.TEST_CONFIG)
        client.session = MagicMock()
        client.session.get.side_effect = requests_lib.exceptions.ConnectionError(
            "timeout"
        )

        with pytest.raises(NotFound):
            client.get_cyclonedx_sbom("app123")

    def test_get_cyclonedx_sbom_raises_not_found_on_http_error(self):
        """Test that an HTTP error status is wrapped in NotFound."""
        client = SonaTypeClient(self.TEST_CONFIG)
        client.session = MagicMock()
        mock_response = MagicMock()
        mock_response.raise_for_status.side_effect = requests_lib.exceptions.HTTPError(
            "404"
        )
        client.session.get.return_value = mock_response

        with pytest.raises(NotFound):
            client.get_cyclonedx_sbom("app123")

    def test_get_vex_document_success(self):
        """Test successful VEX document retrieval."""
        client = SonaTypeClient(self.TEST_CONFIG)
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "@context": "https://openvex.dev/ns",
            "@id": "vex-doc-1",
            "statements": [
                {"status": "not_affected", "vulnerability": {"@id": "CVE-1"}}
            ],
        }
        client.session = MagicMock()
        client.session.get.return_value = mock_response

        result = client.get_vex_document("app123")

        assert result is not None
        assert result["@id"] == "vex-doc-1"
        assert len(result["statements"]) == 1
        mock_response.raise_for_status.assert_called_once()
        url_arg = client.session.get.call_args[0][0]
        assert "vulnerabilities/vex/app123/stages/release" in url_arg

    def test_get_vex_document_returns_none_on_404(self):
        """Test that 404 returns None."""
        client = SonaTypeClient(self.TEST_CONFIG)
        mock_response = MagicMock()
        mock_response.status_code = 404
        client.session = MagicMock()
        client.session.get.return_value = mock_response

        result = client.get_vex_document("app123")

        assert result is None


class TestVexHelper:
    """Tests for the VexHelper class."""

    TEST_CONFIG = {
        "SONATYPE_HOST": "sonatype.example.com",
        "SONATYPE_USERNAME": "test_user",
        "SONATYPE_PASSWORD": "test_pass",
        "SONATYPE_CACERTS": "certs/ca_bundle.pem",
        "FALKORDB_HOST": "localhost",
        "FALKORDB_PORT": 6379,
        "FALKORDB_GRAPH_NAME": "test-graph",
        "FALKORDB_PASSWORD": "",
        "FALKORDB_CACERTS": "certs/ca_bundle.pem",
    }

    @patch("sonatype_lifecycle_release_listener.app.VexProcessor")
    @patch("sonatype_lifecycle_release_listener.app.SonaTypeClient")
    @patch("sonatype_lifecycle_release_listener.app.Persistence")
    def test_init_creates_dependencies(
        self, mock_persistence, mock_client, mock_processor
    ):
        """Test VexHelper wires Persistence, SonaTypeClient, VexProcessor."""
        helper = VexHelper(self.TEST_CONFIG)

        mock_persistence.assert_called_once()
        mock_client.assert_called_once_with(self.TEST_CONFIG)
        mock_processor.assert_called_once_with(
            persistence=mock_persistence.return_value
        )
        assert helper.persistence is mock_persistence.return_value
        assert helper.sonatype_client is mock_client.return_value
        assert helper.vex_processor is mock_processor.return_value

    @patch("sonatype_lifecycle_release_listener.app.VexProcessor")
    @patch("sonatype_lifecycle_release_listener.app.SonaTypeClient")
    @patch("sonatype_lifecycle_release_listener.app.Persistence")
    def test_process_vex_for_application_success(
        self, mock_persistence, mock_client_cls, mock_proc_cls, example_vex
    ):
        """Test successful VEX processing with valid document."""
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        mock_client.get_vex_document.return_value = example_vex

        mock_proc = MagicMock()
        mock_proc.process_vex_document.return_value = {
            "statements_processed": 1,
            "linked_vulnerabilities": 1,
        }
        mock_proc_cls.return_value = mock_proc

        helper = VexHelper(self.TEST_CONFIG)
        result = helper.process_vex_for_application(app_id="app123")

        assert result is not None
        assert result["statements_processed"] == 1
        assert result["linked_vulnerabilities"] == 1
        mock_client.get_vex_document.assert_called_once_with(
            app_id="app123",
            stage_id="release",
        )
        mock_proc.process_vex_document.assert_called_once_with(example_vex)

    @patch("sonatype_lifecycle_release_listener.app.VexProcessor")
    @patch("sonatype_lifecycle_release_listener.app.SonaTypeClient")
    @patch("sonatype_lifecycle_release_listener.app.Persistence")
    def test_process_vex_for_application_returns_none_when_no_vex(
        self, mock_persistence, mock_client_cls, mock_proc_cls
    ):
        """Test that None is returned when no VEX document is available."""
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        mock_client.get_vex_document.return_value = None

        helper = VexHelper(self.TEST_CONFIG)
        result = helper.process_vex_for_application(app_id="app123")

        assert result is None
        mock_client.get_vex_document.assert_called_once_with(
            app_id="app123",
            stage_id="release",
        )
        mock_proc_cls.return_value.process_vex_document.assert_not_called()

    @patch("sonatype_lifecycle_release_listener.app.VexProcessor")
    @patch("sonatype_lifecycle_release_listener.app.SonaTypeClient")
    @patch("sonatype_lifecycle_release_listener.app.Persistence")
    def test_process_vex_for_application_with_custom_stage(
        self, mock_persistence, mock_client_cls, mock_proc_cls, example_vex
    ):
        """Test VEX processing with custom stage_id."""
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        mock_client.get_vex_document.return_value = example_vex

        mock_proc = MagicMock()
        mock_proc.process_vex_document.return_value = {
            "statements_processed": 1,
            "linked_vulnerabilities": 1,
        }
        mock_proc_cls.return_value = mock_proc

        helper = VexHelper(self.TEST_CONFIG)
        helper.process_vex_for_application(app_id="app123", stage_id="build")

        mock_client.get_vex_document.assert_called_once_with(
            app_id="app123",
            stage_id="build",
        )


class TestCycloneDXHelper:
    """Tests for the CycloneDXHelper class."""

    TEST_CONFIG = {
        "SONATYPE_HOST": "sonatype.example.com",
        "SONATYPE_USERNAME": "test_user",
        "SONATYPE_PASSWORD": "test_pass",
        "SONATYPE_CACERTS": "certs/ca_bundle.pem",
        "FALKORDB_HOST": "localhost",
        "FALKORDB_PORT": 6379,
        "FALKORDB_GRAPH_NAME": "test-graph",
        "FALKORDB_PASSWORD": "",
        "FALKORDB_CACERTS": "certs/ca_bundle.pem",
    }

    @patch("sonatype_lifecycle_release_listener.app.CycloneDXProcessor")
    @patch("sonatype_lifecycle_release_listener.app.SonaTypeClient")
    @patch("sonatype_lifecycle_release_listener.app.Persistence")
    def test_init_creates_dependencies(
        self, mock_persistence, mock_client, mock_processor
    ):
        """Test CycloneDXHelper wires Persistence, SonaTypeClient, Processor."""
        helper = CycloneDXHelper(self.TEST_CONFIG)

        mock_persistence.assert_called_once_with(
            host="localhost",
            port=6379,
            graph_name="test-graph",
            password="",
            ssl=False,
            ssl_ca_certs="certs/ca_bundle.pem",
            ssl_certfile=None,
            ssl_keyfile=None,
            internal_prefixes=mock_persistence.parse_internal_prefixes.return_value,
        )
        mock_client.assert_called_once_with(self.TEST_CONFIG)
        mock_processor.assert_called_once_with(
            persistence=mock_persistence.return_value
        )
        assert helper.persistence is mock_persistence.return_value
        assert helper.sonatype_client is mock_client.return_value
        assert helper.cyclonedx_processor is mock_processor.return_value

    @patch("sonatype_lifecycle_release_listener.app.CycloneDXProcessor")
    @patch("sonatype_lifecycle_release_listener.app.SonaTypeClient")
    @patch("sonatype_lifecycle_release_listener.app.Persistence")
    def test_init_creates_persistence_with_tls_and_mtls(
        self, mock_persistence, mock_client, mock_processor
    ) -> None:
        """FALKORDB_SSL and optional client cert paths are passed to Persistence."""
        config = {
            **self.TEST_CONFIG,
            "FALKORDB_SSL": "true",
            "FALKORDB_CLIENT_CERT": "/tls/client.crt",
            "FALKORDB_CLIENT_KEY": "/tls/client.key",
        }
        CycloneDXHelper(config)

        mock_persistence.assert_called_once_with(
            host="localhost",
            port=6379,
            graph_name="test-graph",
            password="",
            ssl=True,
            ssl_ca_certs="certs/ca_bundle.pem",
            ssl_certfile="/tls/client.crt",
            ssl_keyfile="/tls/client.key",
            internal_prefixes=mock_persistence.parse_internal_prefixes.return_value,
        )

    @patch("sonatype_lifecycle_release_listener.app.CycloneDXProcessor")
    @patch("sonatype_lifecycle_release_listener.app.SonaTypeClient")
    @patch("sonatype_lifecycle_release_listener.app.Persistence")
    def test_process_cyclonedx_sbom_success(
        self, mock_persistence, mock_client_cls, mock_proc_cls
    ):
        """Test successful end-to-end SBOM processing."""
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        mock_client.get_cyclonedx_sbom.return_value = {"bomFormat": "CycloneDX"}

        proj, ver = MagicMock(), MagicMock()
        proj.purl = "pkg:maven/com.example/app@1.0.0"
        proj.name = "app"
        proj.group = "com.example"
        ver.version = "1.0.0"
        projects = {"app-ref": (proj, ver)}
        mock_proc = MagicMock()
        mock_proc.process_cyclone_dx_json.return_value = (projects, {}, {})
        mock_proc_cls.return_value = mock_proc

        helper = CycloneDXHelper(self.TEST_CONFIG)
        result = helper.process_cyclonedx_sbom(app_id="app123", public_app_id="MyApp")

        mock_client.get_cyclonedx_sbom.assert_called_once_with(
            "app123", "1.5", "release"
        )
        mock_proc.process_cyclone_dx_json.assert_called_once_with(
            app_id="app123",
            public_app_id="MyApp",
            gitlab_project_url="",
            json_data={"bomFormat": "CycloneDX"},
        )
        assert isinstance(result, str)
        assert len(result) == 36  # UUID format

        # Provenance stored
        mock_persistence.return_value.create_sbom_record.assert_called_once()
        call_kwargs = mock_persistence.return_value.create_sbom_record.call_args.kwargs
        assert call_kwargs["sbom_format"] == "cyclonedx"
        assert call_kwargs["source"] == "webhook"
        assert call_kwargs["record_id"] == result
        mock_persistence.return_value.link_version_to_sbom_record.assert_called_once_with(
            "pkg:maven/com.example/app@1.0.0",
            result,
        )

    @patch("sonatype_lifecycle_release_listener.app.CycloneDXProcessor")
    @patch("sonatype_lifecycle_release_listener.app.SonaTypeClient")
    @patch("sonatype_lifecycle_release_listener.app.Persistence")
    def test_process_cyclonedx_sbom_raises_not_found_when_sbom_is_none(
        self, mock_persistence, mock_client_cls, mock_proc_cls
    ):
        """Test that a None SBOM response raises NotFound."""
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        mock_client.get_cyclonedx_sbom.return_value = None

        helper = CycloneDXHelper(self.TEST_CONFIG)

        with pytest.raises(NotFound):
            helper.process_cyclonedx_sbom(app_id="app123", public_app_id="MyApp")

    @patch("sonatype_lifecycle_release_listener.app.CycloneDXProcessor")
    @patch("sonatype_lifecycle_release_listener.app.SonaTypeClient")
    @patch("sonatype_lifecycle_release_listener.app.Persistence")
    def test_process_cyclonedx_sbom_propagates_not_found_from_client(
        self, mock_persistence, mock_client_cls, mock_proc_cls
    ):
        """Test that NotFound from the SonaType client is re-raised."""
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        mock_client.get_cyclonedx_sbom.side_effect = NotFound("API error")

        helper = CycloneDXHelper(self.TEST_CONFIG)

        with pytest.raises(NotFound):
            helper.process_cyclonedx_sbom(app_id="app123", public_app_id="MyApp")

    @patch("sonatype_lifecycle_release_listener.app.CycloneDXProcessor")
    @patch("sonatype_lifecycle_release_listener.app.SonaTypeClient")
    @patch("sonatype_lifecycle_release_listener.app.Persistence")
    def test_process_cyclonedx_sbom_propagates_redis_error(
        self, mock_persistence, mock_client_cls, mock_proc_cls
    ):
        """Test that RedisError from the processor is re-raised."""
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        mock_client.get_cyclonedx_sbom.return_value = {"bomFormat": "CycloneDX"}

        mock_proc = MagicMock()
        mock_proc_cls.return_value = mock_proc
        mock_proc.process_cyclone_dx_json.side_effect = RedisError("Connection lost")

        helper = CycloneDXHelper(self.TEST_CONFIG)

        with pytest.raises(RedisError):
            helper.process_cyclonedx_sbom(app_id="app123", public_app_id="MyApp")


class TestEdgeCases:
    """Tests for edge cases and error handling."""

    def test_case_insensitive_stage_matching(self, client, example_message):
        """Test that stage matching is case-insensitive."""
        with patch(
            "sonatype_lifecycle_release_listener.app.process_release_scan"
        ) as mock_process:
            mock_process.return_value = {"success": True}

            example_message["applicationEvaluation"]["stage"] = "RELEASE"
            response = client.post(
                "/webhook",
                data=json.dumps(example_message),
                content_type="application/json",
            )
            assert response.status_code == 200
            data = json.loads(response.data)
            assert data["status"] == "processed"

    def test_stage_with_different_values(self, client, example_message):
        """Test that various non-release stages are properly ignored."""
        non_release_stages = [
            "build",
            "stage-release",
            "develop",
            "test",
            "ci",
            "DEVELOP",
        ]

        for stage in non_release_stages:
            example_message["applicationEvaluation"]["stage"] = stage

            response = client.post(
                "/webhook",
                data=json.dumps(example_message),
                content_type="application/json",
            )

            assert response.status_code == 200
            data = json.loads(response.data)
            assert data["status"] == "ignored", f"Stage '{stage}' should be ignored"

    def test_empty_application_object(self, client, example_message):
        """Test handling of empty application object."""
        example_message["applicationEvaluation"]["application"] = {}

        response = client.post(
            "/webhook",
            data=json.dumps(example_message),
            content_type="application/json",
        )

        assert response.status_code == 400

    def test_null_values_in_application(self, client, example_message):
        """Test handling of null values in application object."""
        example_message["applicationEvaluation"]["application"]["id"] = None

        response = client.post(
            "/webhook",
            data=json.dumps(example_message),
            content_type="application/json",
        )

        assert response.status_code == 400

    def test_invalid_app_id_format_returns_400(self, client, example_message):
        """Test that invalid app_id format (not 32 hex chars) returns 400."""
        example_message["applicationEvaluation"]["application"]["id"] = "short"

        response = client.post(
            "/webhook",
            data=json.dumps(example_message),
            content_type="application/json",
        )

        assert response.status_code == 400
        data = json.loads(response.data)
        assert "Invalid application id format" in data["error"]

    def test_invalid_public_id_format_returns_400(self, client, example_message):
        """Test that invalid publicId format returns 400."""
        example_message["applicationEvaluation"]["application"]["publicId"] = (
            "x" * 300
        )

        response = client.post(
            "/webhook",
            data=json.dumps(example_message),
            content_type="application/json",
        )

        assert response.status_code == 400
        data = json.loads(response.data)
        assert "Invalid publicId format" in data["error"]


class TestVerifyHmac:
    """Tests for _verify_hmac helper."""

    def test_returns_false_when_signature_header_empty(self):
        """Missing or blank signature header returns False."""
        assert _verify_hmac("secret", b"body", "") is False
        assert _verify_hmac("secret", b"body", "   ") is False

    def test_returns_false_when_signature_mismatch(self):
        """Wrong signature returns False."""
        assert _verify_hmac("secret", b"body", "deadbeef") is False

    def test_returns_true_when_signature_valid(self):
        """Valid HMAC-SHA1 returns True."""
        sig = _nexus_webhook_signature("secret", b"body")
        assert _verify_hmac("secret", b"body", sig) is True


class TestExtractCycloneDXToolInfo:
    """Tests for _extract_cyclonedx_tool_info helper."""

    def test_returns_none_when_no_metadata(self):
        """No metadata returns None, None."""
        assert _extract_cyclonedx_tool_info({}) == (None, None)

    def test_returns_none_when_metadata_not_dict(self):
        """Metadata that is not a dict returns None, None."""
        assert _extract_cyclonedx_tool_info({"metadata": "x"}) == (None, None)

    def test_returns_none_when_no_tools(self):
        """No tools key returns None, None."""
        assert _extract_cyclonedx_tool_info({"metadata": {}}) == (None, None)

    def test_extracts_from_tools_array_cyclonedx_14(self):
        """Extract from tools array (CycloneDX 1.4+)."""
        sbom = {
            "metadata": {
                "tools": [
                    {"name": "Sonatype", "version": "1.2.3"},
                ],
            },
        }
        assert _extract_cyclonedx_tool_info(sbom) == ("Sonatype", "1.2.3")

    def test_extracts_from_tools_components_cyclonedx_15(self):
        """Extract from tools.components (CycloneDX 1.5+)."""
        sbom = {
            "metadata": {
                "tools": {
                    "components": [
                        {"name": "IQ", "version": "4.0"},
                    ],
                },
            },
        }
        assert _extract_cyclonedx_tool_info(sbom) == ("IQ", "4.0")

    def test_returns_none_for_non_string_name_version(self):
        """Non-string name/version returns None."""
        sbom = {
            "metadata": {
                "tools": [{"name": 123, "version": 4.5}],
            },
        }
        assert _extract_cyclonedx_tool_info(sbom) == (None, None)


class TestProcessCycloneSbom:
    """Tests for process_cyclone_sbom backwards-compat wrapper."""

    TEST_CONFIG = {
        "SONATYPE_HOST": "sonatype.example.com",
        "SONATYPE_USERNAME": "test_user",
        "SONATYPE_PASSWORD": "test_pass",
        "SONATYPE_CACERTS": "certs/ca_bundle.pem",
        "FALKORDB_HOST": "localhost",
        "FALKORDB_PORT": 6379,
        "FALKORDB_GRAPH_NAME": "test-graph",
        "FALKORDB_PASSWORD": "",
        "FALKORDB_CACERTS": "certs/ca_bundle.pem",
    }

    @patch("sonatype_lifecycle_release_listener.app.CycloneDXProcessor")
    @patch("sonatype_lifecycle_release_listener.app.SonaTypeClient")
    @patch("sonatype_lifecycle_release_listener.app.Persistence")
    def test_process_cyclone_sbom_calls_cyclonedx(
        self, mock_persistence, mock_client_cls, mock_proc_cls
    ):
        """process_cyclone_sbom delegates to process_cyclonedx_sbom."""
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        mock_client.get_cyclonedx_sbom.return_value = {"bomFormat": "CycloneDX"}

        proj, ver = MagicMock(), MagicMock()
        proj.purl = "pkg:maven/com.example/app@1.0"
        proj.name = "app"
        proj.group = "com.example"
        ver.version = "1.0.0"
        mock_proc = MagicMock()
        mock_proc.process_cyclone_dx_json.return_value = (
            {"ref": (proj, ver)}, {}, {}
        )
        mock_proc_cls.return_value = mock_proc

        helper = CycloneDXHelper(self.TEST_CONFIG)
        result = helper.process_cyclone_sbom(
            app_id="app123", public_app_id="MyApp"
        )

        assert isinstance(result, str)
        mock_client.get_cyclonedx_sbom.assert_called_once_with(
            "app123", "1.5", "release"
        )
