"""
Test cases for the release listener Flask application.
"""
import json
import pytest
import requests as requests_lib
from unittest.mock import patch, MagicMock, ANY
from pathlib import Path

from werkzeug.exceptions import NotFound
from redis.exceptions import RedisError

from sonatype_lifecycle_release_listener.app import (
    create_app, process_release_scan, CycloneDXHelper, SonaTypeClient,
)


RESOURCES_DIR = Path(__file__).parent / 'resources'


@pytest.fixture
def example_message():
    """Load the example message from test resources."""
    with open(RESOURCES_DIR / 'example-message.json', 'r') as f:
        return json.load(f)


@pytest.fixture
def example_cyclonedx():
    """Load the example CycloneDX SBOM from test resources (acme_corp demo data)."""
    with open(RESOURCES_DIR / 'acme_notification_service_sbom.json', 'r') as f:
        return json.load(f)


@pytest.fixture
def app():
    """Create a test Flask application."""
    test_config = {
        'TESTING': True,
        'SONATYPE_HOST': 'sonatype.example.com',
        'SONATYPE_USERNAME': 'test_user',
        'SONATYPE_PASSWORD': 'test_pass',
        'SONATYPE_CACERTS': 'certs/ca_bundle.pem',
        'FALKORDB_HOST': 'localhost',
        'FALKORDB_PORT': 6379,
        'FALKORDB_GRAPH_NAME': 'test-graph',
        'FALKORDB_PASSWORD': '',
        'FALKORDB_CACERTS': 'certs/ca_bundle.pem',
    }
    return create_app(test_config)


@pytest.fixture
def client(app):
    """Create a test client for the Flask application."""
    return app.test_client()


class TestHealthEndpoint:
    """Tests for the health check endpoint."""

    def test_health_check_returns_200(self, client):
        """Test that health check returns 200 status."""
        response = client.get('/health')
        assert response.status_code == 200

    def test_health_check_returns_healthy_status(self, client):
        """Test that health check returns healthy status in JSON."""
        response = client.get('/health')
        data = json.loads(response.data)
        assert data['status'] == 'healthy'


class TestWebhookEndpoint:
    """Tests for the webhook endpoint."""

    def test_empty_payload_returns_400(self, client):
        """Test that empty payload returns 400 error."""
        response = client.post(
            '/webhook',
            data='',
            content_type='application/json'
        )
        assert response.status_code == 400

    def test_invalid_json_returns_400(self, client):
        """Test that invalid JSON returns 400 error."""
        response = client.post(
            '/webhook',
            data='not json',
            content_type='application/json'
        )
        assert response.status_code == 400

    def test_message_without_application_evaluation_is_ignored(self, client):
        """Test that messages without applicationEvaluation are ignored."""
        message = {'id': 'test123', 'timestamp': '2020-04-22T18:30:04.673+0000'}
        response = client.post(
            '/webhook',
            data=json.dumps(message),
            content_type='application/json'
        )
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['status'] == 'ignored'
        assert 'No applicationEvaluation' in data['reason']

    def test_non_release_stage_is_ignored(self, client, example_message):
        """Test that non-release stages are ignored."""
        example_message['applicationEvaluation']['stage'] = 'build'

        response = client.post(
            '/webhook',
            data=json.dumps(example_message),
            content_type='application/json'
        )
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['status'] == 'ignored'
        assert 'not release' in data['reason']

    def test_missing_app_id_returns_400(self, client, example_message):
        """Test that missing application ID returns 400 error."""
        del example_message['applicationEvaluation']['application']['id']

        response = client.post(
            '/webhook',
            data=json.dumps(example_message),
            content_type='application/json'
        )
        assert response.status_code == 400
        data = json.loads(response.data)
        assert 'Missing application id' in data['error']

    def test_missing_public_id_returns_400(self, client, example_message):
        """Test that missing publicId returns 400 error."""
        del example_message['applicationEvaluation']['application']['publicId']

        response = client.post(
            '/webhook',
            data=json.dumps(example_message),
            content_type='application/json'
        )
        assert response.status_code == 400
        data = json.loads(response.data)
        assert 'Missing application id' in data['error']

    def test_null_json_payload_returns_400(self, client):
        """Test that a JSON null body returns 400 error."""
        response = client.post(
            '/webhook',
            data='null',
            content_type='application/json'
        )
        assert response.status_code == 400
        data = json.loads(response.data)
        assert 'Invalid JSON payload' in data['error']

    @patch('sonatype_lifecycle_release_listener.app.process_release_scan')
    def test_unhandled_not_found_returns_500(self, mock_process, client, example_message):
        """Test that an unhandled NotFound from processing returns 500."""
        mock_process.side_effect = NotFound('Unexpected error')

        response = client.post(
            '/webhook',
            data=json.dumps(example_message),
            content_type='application/json'
        )
        assert response.status_code == 500
        data = json.loads(response.data)
        assert data['status'] == 'error'

    @patch('sonatype_lifecycle_release_listener.app.process_release_scan')
    def test_unhandled_redis_error_returns_500(self, mock_process, client, example_message):
        """Test that an unhandled RedisError from processing returns 500."""
        mock_process.side_effect = RedisError('Connection lost')

        response = client.post(
            '/webhook',
            data=json.dumps(example_message),
            content_type='application/json'
        )
        assert response.status_code == 500
        data = json.loads(response.data)
        assert data['status'] == 'error'

    @patch('sonatype_lifecycle_release_listener.app.process_release_scan')
    def test_release_scan_is_processed(self, mock_process, client, example_message):
        """Test that release scans are processed correctly."""
        mock_process.return_value = {'success': True}

        response = client.post(
            '/webhook',
            data=json.dumps(example_message),
            content_type='application/json'
        )

        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['status'] == 'processed'
        assert data['application'] == 'My-Application-ID'

        mock_process.assert_called_once_with(
            app_id='0f256982c80b4e13abef4917b93ac343',
            public_id='My-Application-ID',
            config=ANY,
        )

    @patch('sonatype_lifecycle_release_listener.app.process_release_scan')
    def test_process_failure_returns_500(self, mock_process, client, example_message):
        """Test that processing failures return 500 error with opaque message."""
        mock_process.return_value = {'success': False, 'error': 'Connection failed'}

        response = client.post(
            '/webhook',
            data=json.dumps(example_message),
            content_type='application/json'
        )

        assert response.status_code == 500
        data = json.loads(response.data)
        assert data['status'] == 'error'
        assert 'message' in data
        assert 'reference' in data


class TestProcessReleaseScan:
    """Tests for the process_release_scan function."""

    TEST_CONFIG = {
        'SONATYPE_HOST': 'sonatype.example.com',
        'SONATYPE_USERNAME': 'test_user',
        'SONATYPE_PASSWORD': 'test_pass',
        'SONATYPE_CACERTS': 'certs/ca_bundle.pem',
        'FALKORDB_HOST': 'localhost',
        'FALKORDB_PORT': 6379,
        'FALKORDB_GRAPH_NAME': 'test-graph',
        'FALKORDB_PASSWORD': '',
        'FALKORDB_CACERTS': 'certs/ca_bundle.pem',
    }

    @patch('sonatype_lifecycle_release_listener.app.CycloneDXHelper')
    def test_creates_cyclone_helper_with_config(self, mock_helper_class):
        """Test that CycloneDXHelper is created with the provided config."""
        mock_helper = MagicMock()
        mock_helper_class.return_value = mock_helper

        process_release_scan(
            app_id='test_app_id',
            public_id='test_public_id',
            config=self.TEST_CONFIG,
        )

        mock_helper_class.assert_called_once_with(self.TEST_CONFIG)

    @patch('sonatype_lifecycle_release_listener.app.CycloneDXHelper')
    def test_calls_process_cyclonedx_sbom_correctly(self, mock_helper_class):
        """Test that process_cyclonedx_sbom is called with correct parameters."""
        mock_helper = MagicMock()
        mock_helper_class.return_value = mock_helper

        process_release_scan(
            app_id='test_app_id',
            public_id='test_public_id',
            config=self.TEST_CONFIG,
        )

        mock_helper.process_cyclonedx_sbom.assert_called_once_with(
            app_id='test_app_id',
            public_app_id='test_public_id',
        )

    @patch('sonatype_lifecycle_release_listener.app.CycloneDXHelper')
    def test_returns_success_on_successful_processing(self, mock_helper_class):
        """Test that function returns success on successful processing."""
        mock_helper = MagicMock()
        mock_helper_class.return_value = mock_helper

        result = process_release_scan(
            app_id='test_app_id',
            public_id='test_public_id',
            config=self.TEST_CONFIG,
        )

        assert result['success'] is True

    @patch('sonatype_lifecycle_release_listener.app.CycloneDXHelper')
    def test_returns_failure_on_not_found(self, mock_helper_class):
        """Test that function returns failure when SBOM is not found."""
        mock_helper = MagicMock()
        mock_helper_class.return_value = mock_helper
        mock_helper.process_cyclonedx_sbom.side_effect = NotFound('SBOM not found')

        result = process_release_scan(
            app_id='test_app_id',
            public_id='test_public_id',
            config=self.TEST_CONFIG,
        )

        assert result['success'] is False
        assert result['error'] == 'SBOM processing failed'

    @patch('sonatype_lifecycle_release_listener.app.CycloneDXHelper')
    def test_returns_failure_on_redis_error(self, mock_helper_class):
        """Test that function returns failure on FalkorDB connection error."""
        mock_helper_class.side_effect = RedisError('Connection refused')

        result = process_release_scan(
            app_id='test_app_id',
            public_id='test_public_id',
            config=self.TEST_CONFIG,
        )

        assert result['success'] is False
        assert result['error'] == 'SBOM processing failed'


class TestIntegrationWithMockedSonatype:
    """Integration tests using mocked SonaType responses."""

    @patch('sonatype_lifecycle_release_listener.app.CycloneDXHelper')
    def test_full_webhook_flow(self, mock_helper_class, client, example_message):
        """Test full webhook flow with mocked CycloneDXHelper."""
        mock_helper = MagicMock()
        mock_helper_class.return_value = mock_helper

        response = client.post(
            '/webhook',
            data=json.dumps(example_message),
            content_type='application/json'
        )

        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['status'] == 'processed'

        mock_helper.process_cyclonedx_sbom.assert_called_once_with(
            app_id='0f256982c80b4e13abef4917b93ac343',
            public_app_id='My-Application-ID',
        )

    @patch('sonatype_lifecycle_release_listener.app.CycloneDXHelper')
    def test_multiple_webhook_messages_processed_sequentially(
        self, mock_helper_class, client, example_message
    ):
        """Test that multiple webhook messages are processed sequentially."""
        mock_helper = MagicMock()
        mock_helper_class.return_value = mock_helper

        response1 = client.post(
            '/webhook',
            data=json.dumps(example_message),
            content_type='application/json'
        )
        assert response1.status_code == 200

        example_message['applicationEvaluation']['application']['id'] = 'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6'
        example_message['applicationEvaluation']['application']['publicId'] = 'Second-Application'

        response2 = client.post(
            '/webhook',
            data=json.dumps(example_message),
            content_type='application/json'
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
        'SONATYPE_HOST': 'sonatype.example.com',
        'SONATYPE_USERNAME': 'test_user',
        'SONATYPE_PASSWORD': 'test_pass',
        'SONATYPE_CACERTS': 'certs/ca_bundle.pem',
        'FALKORDB_HOST': 'localhost',
        'FALKORDB_PORT': 6379,
        'FALKORDB_GRAPH_NAME': 'acme_corp',
        'FALKORDB_PASSWORD': '',
        'FALKORDB_CACERTS': '',
    }

    @pytest.fixture
    def falkordb_connection(self):
        """Create a FalkorDB connection for verification."""
        try:
            from falkordb import FalkorDB
            db = FalkorDB(host='localhost', port=6379)
            graph = db.select_graph('acme_corp')
            yield graph
        except (OSError, ConnectionError, TimeoutError) as e:
            pytest.skip(f"FalkorDB not available: {e}")

    @patch('sonatype_lifecycle_release_listener.app.SonaTypeClient.get_cyclonedx_sbom')
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
            app_id='test_app_id',
            public_app_id='test_public_id',
        )

        mock_get_sbom.assert_called_once()

        result = falkordb_connection.query(
            "MATCH (v:Version {project_name: 'notification-service'}) RETURN count(v) as count"
        )
        count = result.result_set[0][0] if result.result_set else 0
        assert count > 0, "Expected the application Version node to exist in FalkorDB"

    @patch('sonatype_lifecycle_release_listener.app.SonaTypeClient.get_cyclonedx_sbom')
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
            app_id='test_app_id',
            public_app_id='test_public_id',
        )

        mock_get_sbom.assert_called_once()

        result = falkordb_connection.query("MATCH (d:Defect) RETURN count(d) as count")
        defect_count = result.result_set[0][0] if result.result_set else 0
        assert defect_count > 0, "Expected Defect nodes to exist in FalkorDB"


class TestSonaTypeClient:
    """Tests for the SonaTypeClient class."""

    TEST_CONFIG = {
        'SONATYPE_HOST': 'sonatype.example.com',
        'SONATYPE_USERNAME': 'test_user',
        'SONATYPE_PASSWORD': 'test_pass',
        'SONATYPE_CACERTS': 'certs/ca_bundle.pem',
    }

    def test_init_sets_attributes_from_config(self):
        """Test that SonaTypeClient reads config values correctly."""
        client = SonaTypeClient(self.TEST_CONFIG)
        assert client.sonatype_host == 'sonatype.example.com'
        assert client.sonatype_username == 'test_user'
        assert client.sonatype_password == 'test_pass'
        assert client.cacerts == 'certs/ca_bundle.pem'
        assert client.api_url == 'https://sonatype.example.com/api/v2/'

    def test_init_uses_defaults_for_missing_config(self):
        """Test that SonaTypeClient falls back to defaults for missing keys."""
        client = SonaTypeClient({})
        assert client.sonatype_host == ''
        assert client.sonatype_username == ''
        assert client.cacerts == 'certs/ca_bundle.pem'

    def test_get_cyclonedx_sbom_success(self):
        """Test successful SBOM retrieval."""
        client = SonaTypeClient(self.TEST_CONFIG)
        mock_response = MagicMock()
        mock_response.json.return_value = {'bomFormat': 'CycloneDX'}
        client.session = MagicMock()
        client.session.get.return_value = mock_response

        result = client.get_cyclonedx_sbom('app123')

        assert result == {'bomFormat': 'CycloneDX'}
        mock_response.raise_for_status.assert_called_once()
        url_arg = client.session.get.call_args[0][0]
        assert 'cycloneDx/1.5/app123/stages/release/' in url_arg

    def test_get_cyclonedx_sbom_with_custom_headers(self):
        """Test that custom headers are merged with the accept header."""
        client = SonaTypeClient(self.TEST_CONFIG)
        mock_response = MagicMock()
        mock_response.json.return_value = {}
        client.session = MagicMock()
        client.session.get.return_value = mock_response

        client.get_cyclonedx_sbom('app123', headers={'X-Custom': 'value'})

        call_kwargs = client.session.get.call_args
        headers = call_kwargs.kwargs.get('headers', call_kwargs[1].get('headers'))
        assert headers['accept'] == 'application/json'
        assert headers['X-Custom'] == 'value'

    def test_get_cyclonedx_sbom_custom_version_and_stage(self):
        """Test SBOM retrieval with non-default version and stage."""
        client = SonaTypeClient(self.TEST_CONFIG)
        mock_response = MagicMock()
        mock_response.json.return_value = {}
        client.session = MagicMock()
        client.session.get.return_value = mock_response

        client.get_cyclonedx_sbom('app123', version='1.4', stage_id='build')

        url_arg = client.session.get.call_args[0][0]
        assert 'cycloneDx/1.4/app123/stages/build/' in url_arg

    def test_get_cyclonedx_sbom_raises_not_found_on_request_error(self):
        """Test that a request error is wrapped in NotFound."""
        client = SonaTypeClient(self.TEST_CONFIG)
        client.session = MagicMock()
        client.session.get.side_effect = requests_lib.exceptions.ConnectionError('timeout')

        with pytest.raises(NotFound):
            client.get_cyclonedx_sbom('app123')

    def test_get_cyclonedx_sbom_raises_not_found_on_http_error(self):
        """Test that an HTTP error status is wrapped in NotFound."""
        client = SonaTypeClient(self.TEST_CONFIG)
        client.session = MagicMock()
        mock_response = MagicMock()
        mock_response.raise_for_status.side_effect = requests_lib.exceptions.HTTPError('404')
        client.session.get.return_value = mock_response

        with pytest.raises(NotFound):
            client.get_cyclonedx_sbom('app123')


class TestCycloneDXHelper:
    """Tests for the CycloneDXHelper class."""

    TEST_CONFIG = {
        'SONATYPE_HOST': 'sonatype.example.com',
        'SONATYPE_USERNAME': 'test_user',
        'SONATYPE_PASSWORD': 'test_pass',
        'SONATYPE_CACERTS': 'certs/ca_bundle.pem',
        'FALKORDB_HOST': 'localhost',
        'FALKORDB_PORT': 6379,
        'FALKORDB_GRAPH_NAME': 'test-graph',
        'FALKORDB_PASSWORD': '',
        'FALKORDB_CACERTS': 'certs/ca_bundle.pem',
    }

    @patch('sonatype_lifecycle_release_listener.app.CycloneDXProcessor')
    @patch('sonatype_lifecycle_release_listener.app.SonaTypeClient')
    @patch('sonatype_lifecycle_release_listener.app.Persistence')
    def test_init_creates_dependencies(self, mock_persistence, mock_client, mock_processor):
        """Test that CycloneDXHelper wires up Persistence, SonaTypeClient, and CycloneDXProcessor."""
        helper = CycloneDXHelper(self.TEST_CONFIG)

        mock_persistence.assert_called_once_with(
            host='localhost',
            port=6379,
            graph_name='test-graph',
            password='',
            ssl=True,
            ssl_ca_certs='certs/ca_bundle.pem',
            internal_prefixes=mock_persistence.parse_internal_prefixes.return_value,
        )
        mock_client.assert_called_once_with(self.TEST_CONFIG)
        mock_processor.assert_called_once_with(persistence=mock_persistence.return_value)
        assert helper.persistence is mock_persistence.return_value
        assert helper.sonatype_client is mock_client.return_value
        assert helper.cyclonedx_processor is mock_processor.return_value

    @patch('sonatype_lifecycle_release_listener.app.CycloneDXProcessor')
    @patch('sonatype_lifecycle_release_listener.app.SonaTypeClient')
    @patch('sonatype_lifecycle_release_listener.app.Persistence')
    def test_process_cyclonedx_sbom_success(self, mock_persistence, mock_client_cls, mock_proc_cls):
        """Test successful end-to-end SBOM processing."""
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        mock_client.get_cyclonedx_sbom.return_value = {'bomFormat': 'CycloneDX'}

        mock_proc = MagicMock()
        mock_proc_cls.return_value = mock_proc

        helper = CycloneDXHelper(self.TEST_CONFIG)
        helper.process_cyclonedx_sbom(app_id='app123', public_app_id='MyApp')

        mock_client.get_cyclonedx_sbom.assert_called_once_with('app123', '1.5', 'release')
        mock_proc.process_cyclone_dx_json.assert_called_once_with(
            app_id='app123',
            public_app_id='MyApp',
            gitlab_project_url="",
            json_data={'bomFormat': 'CycloneDX'},
        )

    @patch('sonatype_lifecycle_release_listener.app.CycloneDXProcessor')
    @patch('sonatype_lifecycle_release_listener.app.SonaTypeClient')
    @patch('sonatype_lifecycle_release_listener.app.Persistence')
    def test_process_cyclonedx_sbom_raises_not_found_when_sbom_is_none(
        self, mock_persistence, mock_client_cls, mock_proc_cls
    ):
        """Test that a None SBOM response raises NotFound."""
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        mock_client.get_cyclonedx_sbom.return_value = None

        helper = CycloneDXHelper(self.TEST_CONFIG)

        with pytest.raises(NotFound):
            helper.process_cyclonedx_sbom(app_id='app123', public_app_id='MyApp')

    @patch('sonatype_lifecycle_release_listener.app.CycloneDXProcessor')
    @patch('sonatype_lifecycle_release_listener.app.SonaTypeClient')
    @patch('sonatype_lifecycle_release_listener.app.Persistence')
    def test_process_cyclonedx_sbom_propagates_not_found_from_client(
        self, mock_persistence, mock_client_cls, mock_proc_cls
    ):
        """Test that NotFound from the SonaType client is re-raised."""
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        mock_client.get_cyclonedx_sbom.side_effect = NotFound('API error')

        helper = CycloneDXHelper(self.TEST_CONFIG)

        with pytest.raises(NotFound):
            helper.process_cyclonedx_sbom(app_id='app123', public_app_id='MyApp')

    @patch('sonatype_lifecycle_release_listener.app.CycloneDXProcessor')
    @patch('sonatype_lifecycle_release_listener.app.SonaTypeClient')
    @patch('sonatype_lifecycle_release_listener.app.Persistence')
    def test_process_cyclonedx_sbom_propagates_redis_error(
        self, mock_persistence, mock_client_cls, mock_proc_cls
    ):
        """Test that RedisError from the processor is re-raised."""
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        mock_client.get_cyclonedx_sbom.return_value = {'bomFormat': 'CycloneDX'}

        mock_proc = MagicMock()
        mock_proc_cls.return_value = mock_proc
        mock_proc.process_cyclone_dx_json.side_effect = RedisError('Connection lost')

        helper = CycloneDXHelper(self.TEST_CONFIG)

        with pytest.raises(RedisError):
            helper.process_cyclonedx_sbom(app_id='app123', public_app_id='MyApp')


class TestEdgeCases:
    """Tests for edge cases and error handling."""

    def test_case_insensitive_stage_matching(self, client, example_message):
        """Test that stage matching is case-insensitive."""
        with patch('sonatype_lifecycle_release_listener.app.process_release_scan') as mock_process:
            mock_process.return_value = {'success': True}

            example_message['applicationEvaluation']['stage'] = 'RELEASE'
            response = client.post(
                '/webhook',
                data=json.dumps(example_message),
                content_type='application/json'
            )
            assert response.status_code == 200
            data = json.loads(response.data)
            assert data['status'] == 'processed'

    def test_stage_with_different_values(self, client, example_message):
        """Test that various non-release stages are properly ignored."""
        non_release_stages = ['build', 'stage-release', 'develop', 'test', 'ci', 'DEVELOP']

        for stage in non_release_stages:
            example_message['applicationEvaluation']['stage'] = stage

            response = client.post(
                '/webhook',
                data=json.dumps(example_message),
                content_type='application/json'
            )

            assert response.status_code == 200
            data = json.loads(response.data)
            assert data['status'] == 'ignored', f"Stage '{stage}' should be ignored"

    def test_empty_application_object(self, client, example_message):
        """Test handling of empty application object."""
        example_message['applicationEvaluation']['application'] = {}

        response = client.post(
            '/webhook',
            data=json.dumps(example_message),
            content_type='application/json'
        )

        assert response.status_code == 400

    def test_null_values_in_application(self, client, example_message):
        """Test handling of null values in application object."""
        example_message['applicationEvaluation']['application']['id'] = None

        response = client.post(
            '/webhook',
            data=json.dumps(example_message),
            content_type='application/json'
        )

        assert response.status_code == 400
