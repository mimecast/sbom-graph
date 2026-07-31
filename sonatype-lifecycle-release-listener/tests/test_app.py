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

from sonatype_lifecycle_release_listener.app import (
    create_app,
    process_release_scan,
    CycloneDXHelper,
    SonaTypeClient,
    VexHelper,
    _verify_hmac,
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
    def test_unhandled_runtime_error_returns_500(
        self, mock_process, client, example_message
    ):
        """Test that an unhandled RuntimeError (enqueue failure) from processing returns 500."""
        mock_process.side_effect = RuntimeError("Ingest pipeline not available")

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
        """Test that release scans are enqueued and accepted correctly."""
        mock_process.return_value = {"success": True}

        response = client.post(
            "/webhook",
            data=json.dumps(example_message),
            content_type="application/json",
        )

        assert response.status_code == 202
        data = json.loads(response.data)
        assert data["status"] == "accepted"
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
    def test_returns_failure_on_runtime_error(self, mock_helper_class):
        """Test that function returns failure when the ingest queue is unavailable."""
        mock_helper_class.side_effect = RuntimeError("Ingest pipeline not available")

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

        assert response.status_code == 202
        data = json.loads(response.data)
        assert data["status"] == "accepted"

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
        assert response1.status_code == 202

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
        assert response2.status_code == 202

        assert mock_helper.process_cyclonedx_sbom.call_count == 2


class TestSbomRecordIdempotency:
    """SAST L2: a re-delivered webhook must converge to the same SBOMRecord
    instead of accumulating duplicates. record_id is derived deterministically
    from the SBOM content + public app id (uuid5), so re-ingesting identical
    content enqueues the same record_id -- an idempotent MERGE downstream in
    the ``ingest`` worker -- rather than a fresh node per replay."""

    CONFIG = {"SONATYPE_HOST": "sonatype.example.com"}

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
            "sonatype_lifecycle_release_listener.app.SonaTypeClient"
        ) as mock_client_cls:
            mock_client_cls.return_value.get_cyclonedx_sbom.return_value = sbom
            return CycloneDXHelper(self.CONFIG)

    @staticmethod
    def _expected_id(public_app_id, sbom):
        doc_hash = hashlib.sha256(
            json.dumps(sbom, sort_keys=True).encode("utf-8")
        ).hexdigest()
        return str(
            uuid.uuid5(uuid.NAMESPACE_URL, f"sbom:{public_app_id}:{doc_hash}")
        )

    @patch("sonatype_lifecycle_release_listener.app.get_celery_client")
    def test_same_content_yields_same_record_id(self, mock_get_celery):
        mock_get_celery.return_value.send_task.return_value = MagicMock(id="job-1")
        helper = self._make_helper(self.SBOM)
        result1 = helper.process_cyclonedx_sbom(app_id="a1", public_app_id="pub")
        result2 = helper.process_cyclonedx_sbom(app_id="a1", public_app_id="pub")

        expected = self._expected_id("pub", self.SBOM)
        assert result1["record_id"] == result2["record_id"] == expected
        # Both ingests enqueue the same record_id (worker-side MERGE is a
        # no-op for the second one, no duplicate SBOMRecord node).
        enqueued_ids = [
            c.kwargs["args"][0]
            for c in mock_get_celery.return_value.send_task.call_args_list
        ]
        assert enqueued_ids == [expected, expected]

    @patch("sonatype_lifecycle_release_listener.app.get_celery_client")
    def test_different_app_yields_different_record_id(self, mock_get_celery):
        mock_get_celery.return_value.send_task.return_value = MagicMock(id="job-1")
        helper = self._make_helper(self.SBOM)
        result_a = helper.process_cyclonedx_sbom(app_id="a1", public_app_id="pubA")
        result_b = helper.process_cyclonedx_sbom(app_id="a1", public_app_id="pubB")
        assert result_a["record_id"] != result_b["record_id"]

    @patch("sonatype_lifecycle_release_listener.app.get_celery_client")
    def test_changed_content_yields_different_record_id(self, mock_get_celery):
        mock_get_celery.return_value.send_task.return_value = MagicMock(id="job-1")
        helper = self._make_helper(self.SBOM)
        result1 = helper.process_cyclonedx_sbom(app_id="a1", public_app_id="pub")
        helper.sonatype_client.get_cyclonedx_sbom.return_value = {
            **self.SBOM,
            "components": [{"name": "lib", "version": "2.0"}],
        }
        result2 = helper.process_cyclonedx_sbom(app_id="a1", public_app_id="pub")
        assert result1["record_id"] != result2["record_id"]


class TestResourceCleanup:
    """Leak fix: a per-webhook helper must release its Sonatype HTTP session
    on every path (success and error)."""

    _APP = "sonatype_lifecycle_release_listener.app"

    def test_helper_close_releases_resources(self):
        with patch(f"{self._APP}.SonaTypeClient"):
            helper = CycloneDXHelper({"SONATYPE_HOST": "sonatype.example.com"})
        helper.close()
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
    }

    @patch("sonatype_lifecycle_release_listener.app.SonaTypeClient")
    def test_init_creates_dependencies(self, mock_client):
        """Test VexHelper wires SonaTypeClient."""
        helper = VexHelper(self.TEST_CONFIG)

        mock_client.assert_called_once_with(self.TEST_CONFIG)
        assert helper.sonatype_client is mock_client.return_value

    @patch("sonatype_lifecycle_release_listener.app.get_celery_client")
    @patch("sonatype_lifecycle_release_listener.app.SonaTypeClient")
    def test_process_vex_for_application_success(
        self, mock_client_cls, mock_get_celery, example_vex
    ):
        """Test successful VEX processing enqueues onto the ingest queue."""
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        mock_client.get_vex_document.return_value = example_vex

        mock_send_task = mock_get_celery.return_value.send_task
        mock_send_task.return_value = MagicMock(id="vex-job-1")

        helper = VexHelper(self.TEST_CONFIG)
        result = helper.process_vex_for_application(app_id="app123")

        assert result == {"job_id": "vex-job-1"}
        mock_client.get_vex_document.assert_called_once_with(
            app_id="app123",
            stage_id="release",
        )
        mock_send_task.assert_called_once_with(
            "sbom_graph_enrichment.ingest_tasks.ingest_vex",
            args=[example_vex],
            queue="ingest",
        )

    @patch("sonatype_lifecycle_release_listener.app.get_celery_client")
    @patch("sonatype_lifecycle_release_listener.app.SonaTypeClient")
    def test_process_vex_for_application_returns_none_when_no_vex(
        self, mock_client_cls, mock_get_celery
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
        mock_get_celery.return_value.send_task.assert_not_called()

    @patch("sonatype_lifecycle_release_listener.app.get_celery_client")
    @patch("sonatype_lifecycle_release_listener.app.SonaTypeClient")
    def test_process_vex_for_application_with_custom_stage(
        self, mock_client_cls, mock_get_celery, example_vex
    ):
        """Test VEX processing with custom stage_id."""
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        mock_client.get_vex_document.return_value = example_vex
        mock_get_celery.return_value.send_task.return_value = MagicMock(id="vex-job-1")

        helper = VexHelper(self.TEST_CONFIG)
        helper.process_vex_for_application(app_id="app123", stage_id="build")

        mock_client.get_vex_document.assert_called_once_with(
            app_id="app123",
            stage_id="build",
        )

    @patch("sonatype_lifecycle_release_listener.app.get_celery_client")
    @patch("sonatype_lifecycle_release_listener.app.SonaTypeClient")
    def test_process_vex_for_application_raises_runtime_error_on_enqueue_failure(
        self, mock_client_cls, mock_get_celery, example_vex
    ):
        """Test that a broker/enqueue failure is wrapped in RuntimeError (CWE-209)."""
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        mock_client.get_vex_document.return_value = example_vex
        mock_get_celery.return_value.send_task.side_effect = ConnectionError("refused")

        helper = VexHelper(self.TEST_CONFIG)

        with pytest.raises(RuntimeError):
            helper.process_vex_for_application(app_id="app123")


class TestCycloneDXHelper:
    """Tests for the CycloneDXHelper class."""

    TEST_CONFIG = {
        "SONATYPE_HOST": "sonatype.example.com",
        "SONATYPE_USERNAME": "test_user",
        "SONATYPE_PASSWORD": "test_pass",
        "SONATYPE_CACERTS": "certs/ca_bundle.pem",
    }

    @patch("sonatype_lifecycle_release_listener.app.SonaTypeClient")
    def test_init_creates_dependencies(self, mock_client):
        """Test CycloneDXHelper wires SonaTypeClient."""
        helper = CycloneDXHelper(self.TEST_CONFIG)

        mock_client.assert_called_once_with(self.TEST_CONFIG)
        assert helper.sonatype_client is mock_client.return_value

    @patch("sonatype_lifecycle_release_listener.app.get_celery_client")
    @patch("sonatype_lifecycle_release_listener.app.SonaTypeClient")
    def test_process_cyclonedx_sbom_success(self, mock_client_cls, mock_get_celery):
        """Test successful SBOM fetch + enqueue onto the ingest queue."""
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        mock_client.get_cyclonedx_sbom.return_value = {"bomFormat": "CycloneDX"}

        mock_send_task = mock_get_celery.return_value.send_task
        mock_send_task.return_value = MagicMock(id="cdx-job-1")

        helper = CycloneDXHelper(self.TEST_CONFIG)
        result = helper.process_cyclonedx_sbom(app_id="app123", public_app_id="MyApp")

        mock_client.get_cyclonedx_sbom.assert_called_once_with(
            "app123", "1.5", "release"
        )
        assert isinstance(result["record_id"], str)
        assert len(result["record_id"]) == 36  # UUID format
        assert result["job_id"] == "cdx-job-1"

        mock_send_task.assert_called_once_with(
            "sbom_graph_enrichment.ingest_tasks.ingest_cyclonedx",
            args=[
                result["record_id"],
                {"bomFormat": "CycloneDX"},
                "app123",
                "MyApp",
                None,
                "webhook",
            ],
            queue="ingest",
        )

    @patch("sonatype_lifecycle_release_listener.app.get_celery_client")
    @patch("sonatype_lifecycle_release_listener.app.SonaTypeClient")
    def test_process_cyclonedx_sbom_raises_not_found_when_sbom_is_none(
        self, mock_client_cls, mock_get_celery
    ):
        """Test that a None SBOM response raises NotFound."""
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        mock_client.get_cyclonedx_sbom.return_value = None

        helper = CycloneDXHelper(self.TEST_CONFIG)

        with pytest.raises(NotFound):
            helper.process_cyclonedx_sbom(app_id="app123", public_app_id="MyApp")
        mock_get_celery.return_value.send_task.assert_not_called()

    @patch("sonatype_lifecycle_release_listener.app.get_celery_client")
    @patch("sonatype_lifecycle_release_listener.app.SonaTypeClient")
    def test_process_cyclonedx_sbom_propagates_not_found_from_client(
        self, mock_client_cls, mock_get_celery
    ):
        """Test that NotFound from the SonaType client is re-raised."""
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        mock_client.get_cyclonedx_sbom.side_effect = NotFound("API error")

        helper = CycloneDXHelper(self.TEST_CONFIG)

        with pytest.raises(NotFound):
            helper.process_cyclonedx_sbom(app_id="app123", public_app_id="MyApp")

    @patch("sonatype_lifecycle_release_listener.app.get_celery_client")
    @patch("sonatype_lifecycle_release_listener.app.SonaTypeClient")
    def test_process_cyclonedx_sbom_raises_runtime_error_on_enqueue_failure(
        self, mock_client_cls, mock_get_celery
    ):
        """Test that a broker/enqueue failure is wrapped in RuntimeError (CWE-209)."""
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        mock_client.get_cyclonedx_sbom.return_value = {"bomFormat": "CycloneDX"}
        mock_get_celery.return_value.send_task.side_effect = ConnectionError("refused")

        helper = CycloneDXHelper(self.TEST_CONFIG)

        with pytest.raises(RuntimeError):
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
            assert response.status_code == 202
            data = json.loads(response.data)
            assert data["status"] == "accepted"

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


class TestProcessCycloneSbom:
    """Tests for process_cyclone_sbom backwards-compat wrapper."""

    TEST_CONFIG = {
        "SONATYPE_HOST": "sonatype.example.com",
        "SONATYPE_USERNAME": "test_user",
        "SONATYPE_PASSWORD": "test_pass",
        "SONATYPE_CACERTS": "certs/ca_bundle.pem",
    }

    @patch("sonatype_lifecycle_release_listener.app.get_celery_client")
    @patch("sonatype_lifecycle_release_listener.app.SonaTypeClient")
    def test_process_cyclone_sbom_calls_cyclonedx(
        self, mock_client_cls, mock_get_celery
    ):
        """process_cyclone_sbom delegates to process_cyclonedx_sbom."""
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        mock_client.get_cyclonedx_sbom.return_value = {"bomFormat": "CycloneDX"}
        mock_get_celery.return_value.send_task.return_value = MagicMock(id="job-1")

        helper = CycloneDXHelper(self.TEST_CONFIG)
        result = helper.process_cyclone_sbom(
            app_id="app123", public_app_id="MyApp"
        )

        assert isinstance(result["record_id"], str)
        assert result["job_id"] == "job-1"
        mock_client.get_cyclonedx_sbom.assert_called_once_with(
            "app123", "1.5", "release"
        )
