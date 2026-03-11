"""
Flask microservice to listen for SonaType webhook messages and process release scans.
"""
import hashlib
import hmac
import os
import logging
import logging.config
import re
import uuid
from typing import Optional
from urllib.parse import quote as urlquote
from flask import Flask, request, jsonify
from werkzeug.exceptions import BadRequest, NotFound
import requests
from requests.auth import HTTPBasicAuth
from sbom_graph_model.cyclonedx.processor import CycloneDXProcessor
from sbom_graph_model.persistence import Persistence
from redis.exceptions import RedisError

_SONATYPE_ID_RE = re.compile(r"^[a-fA-F0-9]{32}$")
_PUBLIC_ID_RE = re.compile(r"^[a-zA-Z0-9._-]{1,256}$")


# Configure logging
def _configure_logging():
    """Configure logging from file or fall back to basic config."""
    logging_conf_paths = [
        os.path.join(os.path.dirname(__file__), '..', '..', 'logging.conf'),
        os.path.join(os.getcwd(), 'logging.conf'),
        'logging.conf'
    ]

    for conf_path in logging_conf_paths:
        if os.path.exists(conf_path):
            try:
                logging.config.fileConfig(conf_path, disable_existing_loggers=False)
                return
            except (OSError, ValueError):
                continue

    # Fall back to basic configuration
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s - %(name)s - %(funcName)s - %(levelname)s - %(message)s'
    )


_configure_logging()
logger = logging.getLogger(__name__)


def create_app(config: Optional[dict] = None) -> Flask:
    """
    Application factory for creating the Flask app.
    
    :param config: Optional configuration dictionary
    :return: Configured Flask application
    """
    app = Flask(__name__)

    # Apply configuration
    if config is not None:
        app.config.update(config)

    # Default configuration from environment variables
    app.config.setdefault('SONATYPE_HOST', os.environ.get('SONATYPE_HOST', ''))
    app.config.setdefault('SONATYPE_USERNAME', os.environ.get('SONATYPE_USERNAME', ''))
    app.config.setdefault('SONATYPE_PASSWORD', os.environ.get('SONATYPE_PASSWORD', ''))
    app.config.setdefault(
        'SONATYPE_CACERTS', os.environ.get('SONATYPE_CACERTS', 'certs/ca_bundle.pem'))
    app.config.setdefault('FALKORDB_HOST', os.environ.get('FALKORDB_HOST', ''))
    app.config.setdefault('FALKORDB_PORT', int(os.environ.get('FALKORDB_PORT', '6379')))
    app.config.setdefault('FALKORDB_GRAPH_NAME', os.environ.get('FALKORDB_GRAPH_NAME', 'acme-corp'))
    app.config.setdefault('FALKORDB_PASSWORD', os.environ.get('FALKORDB_PASSWORD', ''))
    app.config.setdefault(
        'FALKORDB_CACERTS', os.environ.get('FALKORDB_CACERTS', 'certs/ca_bundle.pem'))
    app.config.setdefault(
        'INTERNAL_PREFIXES', os.environ.get('INTERNAL_PREFIXES', ''))
    app.config.setdefault(
        'WEBHOOK_SECRET', os.environ.get('WEBHOOK_SECRET', ''))
    app.config['MAX_CONTENT_LENGTH'] = 1 * 1024 * 1024  # 1 MB

    if not app.config['WEBHOOK_SECRET']:
        logger.warning(
            "WEBHOOK_SECRET is not set -- webhook endpoint is unauthenticated. "
            "Set WEBHOOK_SECRET to enable HMAC signature verification."
        )

    @app.route('/health', methods=['GET'])
    def health_check():
        """Health check endpoint for load balancers and orchestration."""
        return jsonify({'status': 'healthy'}), 200

    @app.route('/webhook', methods=['POST'])
    def handle_webhook():
        """
        Handle incoming webhook messages from SonaType.

        Processes release scan events and ingests dependency trees into FalkorDB.
        When WEBHOOK_SECRET is configured, the request must include an
        ``X-Webhook-Signature`` header with the value ``sha256=<hex_digest>``
        where the digest is HMAC-SHA256 of the raw request body.
        """
        request_id = uuid.uuid4().hex[:12]

        try:
            webhook_secret = app.config.get('WEBHOOK_SECRET', '')
            if webhook_secret:
                sig_header = request.headers.get('X-Webhook-Signature', '')
                if not _verify_hmac(webhook_secret, request.get_data(), sig_header):
                    logger.warning("Webhook signature verification failed",
                                   extra={'request_id': request_id})
                    return jsonify({'error': 'Invalid signature'}), 403

            try:
                message = request.get_json()
            except BadRequest:
                logger.warning("Received invalid JSON payload",
                               extra={'request_id': request_id})
                return jsonify({'error': 'Invalid JSON payload'}), 400

            if not message:
                logger.warning("Received empty or invalid JSON payload",
                               extra={'request_id': request_id})
                return jsonify({'error': 'Invalid JSON payload'}), 400

            logger.info("Received webhook message",
                        extra={'request_id': request_id,
                               'webhook_id': message.get('id', 'unknown')})

            application_evaluation = message.get('applicationEvaluation')
            if not application_evaluation:
                logger.debug("Message does not contain applicationEvaluation, ignoring")
                return jsonify({'status': 'ignored', 'reason': 'No applicationEvaluation'}), 200

            stage = application_evaluation.get('stage', '').lower()
            if stage != 'release':
                logger.debug("Stage '%s' is not 'release', ignoring", stage)
                return jsonify(
                    {'status': 'ignored', 'reason': f"Stage '{stage}' is not release"}), 200

            application = application_evaluation.get('application', {})
            app_id = application.get('id', '')
            public_id = application.get('publicId', '')

            if not app_id or not public_id:
                logger.warning("Missing application id or publicId in message")
                return jsonify({'error': 'Missing application id or publicId'}), 400

            if not _SONATYPE_ID_RE.match(app_id):
                logger.warning("Invalid app_id format rejected",
                               extra={'request_id': request_id})
                return jsonify({'error': 'Invalid application id format'}), 400

            if not _PUBLIC_ID_RE.match(public_id):
                logger.warning("Invalid publicId format rejected",
                               extra={'request_id': request_id})
                return jsonify({'error': 'Invalid publicId format'}), 400

            logger.info("Processing release scan",
                        extra={'request_id': request_id,
                               'public_id': public_id})

            result = process_release_scan(
                app_id=app_id,
                public_id=public_id,
                config=app.config,
            )

            if result['success']:
                logger.info("Successfully processed release scan",
                            extra={'request_id': request_id,
                                   'public_id': public_id})
                return jsonify({'status': 'processed', 'application': public_id}), 200
            else:
                logger.error("Failed to process release scan",
                             extra={'request_id': request_id,
                                    'public_id': public_id,
                                    'error': result['error']})
                return jsonify({
                    'status': 'error',
                    'message': 'Failed to process release scan',
                    'reference': request_id,
                }), 500

        except (NotFound, RedisError):
            logger.exception("Error processing webhook",
                             extra={'request_id': request_id})
            return jsonify({
                'status': 'error',
                'message': 'Internal processing error',
                'reference': request_id,
            }), 500

    return app


def _verify_hmac(secret: str, body: bytes, signature_header: str) -> bool:
    """Verify HMAC-SHA256 signature of the request body."""
    if not signature_header.startswith('sha256='):
        return False
    received_sig = signature_header[7:]
    expected_sig = hmac.new(
        secret.encode('utf-8'), body, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected_sig, received_sig)


class CycloneDXHelper:
    """Helper class to process CycloneDX SBOMs."""

    def __init__(self, config: dict):
        internal_prefixes = Persistence.parse_internal_prefixes(
            config.get('INTERNAL_PREFIXES', '')
        )
        self.persistence = Persistence(
            host=config.get('FALKORDB_HOST', ''),
            port=int(config.get('FALKORDB_PORT', 6379)),
            graph_name=config.get('FALKORDB_GRAPH_NAME', 'acme-corp'),
            password=config.get('FALKORDB_PASSWORD', ''),
            ssl=True,
            ssl_ca_certs=config.get('FALKORDB_CACERTS', 'certs/ca_bundle.pem'),
            internal_prefixes=internal_prefixes,
        )
        self.sonatype_client = SonaTypeClient(config)
        self.cyclonedx_processor = CycloneDXProcessor(persistence=self.persistence)

    def process_cyclonedx_sbom(
        self,
        app_id: str,
        public_app_id: str,
        version: str = '1.5',
        stage_id: str = 'release'):
        """
        Process the CycloneDX SBOM.
        """
        try:
            sbom = self.sonatype_client.get_cyclonedx_sbom(app_id, version, stage_id)
            if sbom is None:
                error_message = (
                    f"Error: Unable to retrieve CycloneDX {version} data for app ID {app_id} on {stage_id}"
                )
                logger.error(error_message)
                raise NotFound(error_message)
        except NotFound as e:
            logger.exception("Error processing CycloneDX SBOM")
            raise

        try:
            self.cyclonedx_processor.process_cyclone_dx_json(
                app_id=app_id,
                public_app_id=public_app_id,
                gitlab_project_url="",
                json_data=sbom)
        except RedisError as e:
            logger.exception("Error processing CycloneDX SBOM")
            raise


    def process_cyclone_sbom(
        self,
        app_id: str,
        public_app_id: str,
        version: str = '1.5',
        stage_id: str = 'release'):
        """
        Backwards-compatible wrapper for :meth:`process_cyclonedx_sbom`.
        """
        return self.process_cyclonedx_sbom(
            app_id=app_id,
            public_app_id=public_app_id,
            version=version,
            stage_id=stage_id,
        )


class SonaTypeClient:
    """Client class to interact with SonaType API."""
    def __init__(self, config: dict):
        self.sonatype_host = config.get('SONATYPE_HOST', '')
        self.sonatype_username = config.get('SONATYPE_USERNAME', '')
        self.sonatype_password = config.get('SONATYPE_PASSWORD', '')
        self.cacerts = config.get('SONATYPE_CACERTS', 'certs/ca_bundle.pem')
        self.session = requests.Session()
        self.session.verify = self.cacerts
        self.session.auth = HTTPBasicAuth(
            username=self.sonatype_username,
            password=self.sonatype_password
        )
        self.api_url = f'https://{self.sonatype_host}/api/v2/'

    def get_cyclonedx_sbom(
        self,
        app_id: str,
        version: str = '1.5',
        stage_id: str = 'release',
        headers: Optional[dict] = None) -> Optional[dict]:
        """
        Get the CycloneDX SBOM for the given application ID and public ID.
        """
        try:
            if headers is None:
                headers = {'accept': 'application/json'}
            else:
                headers['accept'] = 'application/json'

            url = (
                f"{self.api_url}cycloneDx/{urlquote(version, safe='')}"
                f"/{urlquote(app_id, safe='')}"
                f"/stages/{urlquote(stage_id, safe='')}/"
            )

            response = self.session.get(url, params=None, headers=headers)
            response.raise_for_status()  # Raise exception for non-200 response codes
            return response.json()
        except requests.exceptions.RequestException as e:
            error_message = (
                    f"Error: Unable to retrieve CycloneDX {version} data for app ID {app_id} on {stage_id}"
                )
            logger.error(error_message)
            raise NotFound(error_message) from e


def process_release_scan(
    app_id: str,
    public_id: str,
    config: dict,
) -> dict:
    """
    Process a release scan by fetching and ingesting the CycloneDX SBOM.

    :param app_id: The SonaType application ID
    :param public_id: The SonaType public application ID
    :param config: Application configuration dictionary
    :return: Dictionary with success status and any error message
    """
    try:
        helper = CycloneDXHelper(config)
        helper.process_cyclonedx_sbom(app_id=app_id, public_app_id=public_id)
        return {'success': True}
    except (NotFound, RedisError):
        logger.exception("Error processing release scan for %s", public_id)
        return {'success': False, 'error': 'SBOM processing failed'}


# Create the default application instance
app = create_app()


if __name__ == '__main__':
    debug_mode = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
    app.run(debug=debug_mode, host='0.0.0.0', port=5000)
