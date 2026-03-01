"""
Flask microservice to listen for SonaType webhook messages and process release scans.
"""
import os
import logging
import logging.config
from typing import Optional
from flask import Flask, request, jsonify
from werkzeug.exceptions import BadRequest, NotFound
import requests
from requests.auth import HTTPBasicAuth
from appsec_sbom_model.cyclonedx.processor import CycloneDXProcessor
from appsec_sbom_model.persistence import Persistence
from redis.exceptions import RedisError


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
    app.config.setdefault('FALKORDB_PORT', os.environ.get('FALKORDB_PORT', 6379))
    app.config.setdefault('FALKORDB_GRAPH_NAME', os.environ.get('FALKORDB_GRAPH_NAME', 'acme-corp'))
    app.config.setdefault('FALKORDB_PASSWORD', os.environ.get('FALKORDB_PASSWORD', ''))
    app.config.setdefault(
        'FALKORDB_CACERTS', os.environ.get('FALKORDB_CACERTS', 'certs/ca_bundle.pem'))

    @app.route('/health', methods=['GET'])
    def health_check():
        """Health check endpoint for load balancers and orchestration."""
        return jsonify({'status': 'healthy'}), 200

    @app.route('/webhook', methods=['POST'])
    def handle_webhook():
        """
        Handle incoming webhook messages from SonaType.
        
        Processes release scan events and ingests dependency trees into FalkorDB.
        """
        try:
            try:
                message = request.get_json()
            except BadRequest as e:
                logger.warning(f"Received invalid JSON payload: {str(e)}")
                return jsonify({'error': 'Invalid JSON payload'}), 400

            if not message:
                logger.warning("Received empty or invalid JSON payload")
                return jsonify({'error': 'Invalid JSON payload'}), 400

            logger.info(f"Received webhook message with id: {message.get('id', 'unknown')}")

            # Check if this is an application evaluation message
            application_evaluation = message.get('applicationEvaluation')
            if not application_evaluation:
                logger.debug("Message does not contain applicationEvaluation, ignoring")
                return jsonify({'status': 'ignored', 'reason': 'No applicationEvaluation'}), 200

            # Check if this is a release scan
            stage = application_evaluation.get('stage', '').lower()
            if stage != 'release':
                logger.debug(f"Stage '{stage}' is not 'release', ignoring")
                return jsonify(
                    {'status': 'ignored', 'reason': f"Stage '{stage}' is not release"}), 200

            # Extract application details
            application = application_evaluation.get('application', {})
            app_id = application.get('id')
            public_id = application.get('publicId')

            if not app_id or not public_id:
                logger.warning("Missing application id or publicId in message")
                return jsonify({'error': 'Missing application id or publicId'}), 400

            logger.info(f"Processing release scan for application: {public_id} (id: {app_id})")

            # Process the release scan
            result = process_release_scan(
                app_id=app_id,
                public_id=public_id,
                config=app.config,
            )

            if result['success']:
                logger.info(f"Successfully processed release scan for {public_id}")
                return jsonify({'status': 'processed', 'application': public_id}), 200
            else:
                logger.error(f"Failed to process release scan for {public_id}")
                return jsonify({
                    'status': 'error',
                    'error': 'An internal error occurred while processing the release scan.'
                }), 500

        except (NotFound, RedisError) as e:
            logger.exception(f"Error processing webhook: {str(e)}")
            return jsonify({
                'status': 'error',
                'error': 'An internal error occurred while processing the request.'
            }), 500

    return app


class CycloneHelper:
    """Helper class to process CycloneDX SBOMs."""

    def __init__(self, config: dict):
        self.persistence = Persistence(
            host=config.get('FALKORDB_HOST', ''),
            port=config.get('FALKORDB_PORT', 6379),
            graph_name=config.get('FALKORDB_GRAPH_NAME', 'acme-corp'),
            password=config.get('FALKORDB_PASSWORD', ''),
            ssl=True,
            ssl_ca_certs=config.get('FALKORDB_CACERTS', 'certs/ca_bundle.pem'),
        )
        self.sonatype_client = SonaTypeClient(config)
        self.cyclonedx_processor = CycloneDXProcessor(persistence=self.persistence)

    def process_cyclone_sbom(
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
                logger.error(f"Failed to get CycloneDX SBOM for app ID {app_id} on {stage_id}")
                raise NotFound(f"Failed to get CycloneDX SBOM for app ID {app_id} on {stage_id}")
        except NotFound as e:
            logger.exception(f"Error processing CycloneDX SBOM: {str(e)}")
            raise e

        try:
            self.cyclonedx_processor.process_cyclone_dx_json(
                app_id=app_id,
                public_app_id=public_app_id,
                gitlab_project_url="",
                json_data=sbom)
        except RedisError as e:
            logger.exception(f"Error processing CycloneDX SBOM: {str(e)}")
            raise e


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
        headers: dict|None = None) -> dict|None:
        """
        Get the CycloneDX SBOM for the given application ID and public ID.
        """
        try:
            if headers is None:
                headers = {'accept': 'application/json'}
            else:
                headers['accept'] = 'application/json'

            url=f"{self.api_url}cycloneDx/{version}/{app_id}/stages/{stage_id}/"

            response = self.session.get(url, params=None, headers=headers)
            response.raise_for_status()  # Raise exception for non-200 response codes
            return response.json()
        except requests.exceptions.RequestException as e:
            error_message = (
                f"Error: Unable to retrieve CycloneDX {version} data for app ID "
                f"{app_id} on {stage_id}: {e}"
            )
            logger.error(error_message)
            raise NotFound(error_message)
        return None


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
        helper = CycloneHelper(config)
        helper.process_cyclone_sbom(app_id=app_id, public_app_id=public_id)
        return {'success': True}
    except (NotFound, RedisError) as e:
        logger.exception(f"Error processing release scan: {str(e)}")
        return {'success': False}


# Create the default application instance
app = create_app()


if __name__ == '__main__':
    debug_mode = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
    app.run(debug=debug_mode, host='0.0.0.0', port=5000)
