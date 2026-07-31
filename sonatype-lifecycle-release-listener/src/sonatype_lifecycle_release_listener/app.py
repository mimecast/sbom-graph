"""
Flask microservice to listen for SonaType webhook messages and process release scans.
"""

import hashlib
import hmac
import json
import logging
import logging.config
import os
import re
import uuid
from typing import Optional
from urllib.parse import quote as urlquote
from flask import Flask, request, jsonify
from werkzeug.exceptions import BadRequest, NotFound
import requests
from requests.auth import HTTPBasicAuth

from sonatype_lifecycle_release_listener.celery_client import get_celery_client

_SONATYPE_ID_RE = re.compile(r"^[a-fA-F0-9]{32}$")
_PUBLIC_ID_RE = re.compile(r"^[a-zA-Z0-9._-]{1,256}$")


# Configure logging
def _configure_logging():
    """Configure logging from file or fall back to basic config."""
    logging_conf_paths = [
        os.path.join(os.path.dirname(__file__), "..", "..", "logging.conf"),
        os.path.join(os.getcwd(), "logging.conf"),
        "logging.conf",
    ]

    for conf_path in logging_conf_paths:
        if os.path.exists(conf_path):
            try:
                logging.config.fileConfig(conf_path, disable_existing_loggers=False)
                return
            except (OSError, ValueError):
                continue

    # Fall back to basic configuration (INFO, not DEBUG — a DEBUG fallback in
    # production would leak request/exception detail to logs).
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(funcName)s - %(levelname)s - %(message)s",
    )


_configure_logging()
logger = logging.getLogger(__name__)


def create_app(config: Optional[dict] = None) -> Flask:
    """
    Application factory for creating the Flask app.

    :param config: Optional configuration dictionary
    :return: Configured Flask application
    """
    app = Flask(__name__)  # pylint: disable=redefined-outer-name

    # Apply configuration
    if config is not None:
        app.config.update(config)

    # Default configuration from environment variables
    app.config.setdefault("SONATYPE_HOST", os.environ.get("SONATYPE_HOST", ""))
    app.config.setdefault("SONATYPE_USERNAME", os.environ.get("SONATYPE_USERNAME", ""))
    app.config.setdefault("SONATYPE_PASSWORD", os.environ.get("SONATYPE_PASSWORD", ""))
    app.config.setdefault(
        "SONATYPE_CACERTS", os.environ.get("SONATYPE_CACERTS", "certs/ca_bundle.pem")
    )
    # FalkorDB connection details are no longer read here -- SBOM/VEX
    # ingestion is enqueued onto the ``ingest`` Celery queue (see
    # ``celery_client.py``), which reads its own broker connection
    # material directly from the environment rather than Flask config.
    app.config.setdefault("WEBHOOK_SECRET", os.environ.get("WEBHOOK_SECRET", ""))
    app.config["MAX_CONTENT_LENGTH"] = 1 * 1024 * 1024  # 1 MB

    if not app.config["WEBHOOK_SECRET"]:
        logger.error(
            "WEBHOOK_SECRET is not set -- the /webhook endpoint will REJECT all "
            "requests (fail-closed). Set WEBHOOK_SECRET to enable HMAC verification."
        )

    @app.route("/health", methods=["GET"])
    def health_check():
        """Health check endpoint for load balancers and orchestration."""
        return jsonify({"status": "healthy"}), 200

    @app.route("/webhook", methods=["POST"])
    def handle_webhook():
        """
        Handle incoming webhook messages from SonaType.

        Processes release scan events and enqueues dependency trees for
        asynchronous ingestion into FalkorDB via the ``ingest`` Celery queue.
        When WEBHOOK_SECRET is configured, the request must include Sonatype's
        ``X-Nexus-Webhook-Signature`` header containing the plain hex digest
        of HMAC-SHA1 over the raw request body (see Lifecycle Webhooks docs).
        """
        request_id = uuid.uuid4().hex[:12]

        try:
            webhook_secret = app.config.get("WEBHOOK_SECRET", "")
            if not webhook_secret:
                # Fail closed (CWE-306): never process webhooks unauthenticated. The
                # umbrella Helm chart auto-provisions WEBHOOK_SECRET, so a missing
                # secret means a misconfigured/standalone deploy — reject, don't skip.
                logger.error(
                    "WEBHOOK_SECRET not configured; rejecting webhook (fail-closed)",
                    extra={"request_id": request_id},
                )
                return jsonify({"error": "Webhook authentication is not configured"}), 503
            sig_header = request.headers.get("X-Nexus-Webhook-Signature", "")
            if not _verify_hmac(webhook_secret, request.get_data(), sig_header):
                logger.warning(
                    "Webhook signature verification failed",
                    extra={"request_id": request_id},
                )
                return jsonify({"error": "Invalid signature"}), 403

            try:
                message = request.get_json()
            except BadRequest:
                logger.warning(
                    "Received invalid JSON payload", extra={"request_id": request_id}
                )
                return jsonify({"error": "Invalid JSON payload"}), 400

            if not message:
                logger.warning(
                    "Received empty or invalid JSON payload",
                    extra={"request_id": request_id},
                )
                return jsonify({"error": "Invalid JSON payload"}), 400

            logger.info(
                "Received webhook message",
                extra={
                    "request_id": request_id,
                    "webhook_id": message.get("id", "unknown"),
                },
            )

            application_evaluation = message.get("applicationEvaluation")
            if not application_evaluation:
                logger.debug("Message does not contain applicationEvaluation, ignoring")
                return jsonify(
                    {"status": "ignored", "reason": "No applicationEvaluation"}
                ), 200

            stage = application_evaluation.get("stage", "").lower()
            if stage != "release":
                logger.debug("Stage '%s' is not 'release', ignoring", stage)
                return jsonify(
                    {"status": "ignored", "reason": f"Stage '{stage}' is not release"}
                ), 200

            application = application_evaluation.get("application", {})
            app_id = application.get("id", "")
            public_id = application.get("publicId", "")

            if not app_id or not public_id:
                logger.warning("Missing application id or publicId in message")
                return jsonify({"error": "Missing application id or publicId"}), 400

            if not _SONATYPE_ID_RE.match(app_id):
                logger.warning(
                    "Invalid app_id format rejected", extra={"request_id": request_id}
                )
                return jsonify({"error": "Invalid application id format"}), 400

            if not _PUBLIC_ID_RE.match(public_id):
                logger.warning(
                    "Invalid publicId format rejected", extra={"request_id": request_id}
                )
                return jsonify({"error": "Invalid publicId format"}), 400

            logger.info(
                "Processing release scan",
                extra={"request_id": request_id, "public_id": public_id},
            )

            result = process_release_scan(
                app_id=app_id,
                public_id=public_id,
                config=app.config,
            )

            if result["success"]:
                logger.info(
                    "Release scan enqueued for ingestion",
                    extra={"request_id": request_id, "public_id": public_id},
                )
                return jsonify({"status": "accepted", "application": public_id}), 202
            else:
                logger.error(
                    "Failed to process release scan",
                    extra={
                        "request_id": request_id,
                        "public_id": public_id,
                        "error": result["error"],
                    },
                )
                return jsonify(
                    {
                        "status": "error",
                        "message": "Failed to process release scan",
                        "reference": request_id,
                    }
                ), 500

        except (NotFound, RuntimeError):
            logger.exception(
                "Error processing webhook", extra={"request_id": request_id}
            )
            return jsonify(
                {
                    "status": "error",
                    "message": "Internal processing error",
                    "reference": request_id,
                }
            ), 500

    return app


def _verify_hmac(secret: str, body: bytes, signature_header: str) -> bool:
    """Verify Sonatype Lifecycle HMAC-SHA1 webhook signature of the request body."""
    received_sig = signature_header.strip()
    if not received_sig:
        return False
    expected_sig = hmac.new(
        secret.encode("utf-8"), body, hashlib.sha1  # noqa: S324  # nosec B324
    ).hexdigest()
    return hmac.compare_digest(expected_sig, received_sig)


class CycloneDXHelper:
    """Helper class to fetch a CycloneDX SBOM from Sonatype and enqueue it for ingest.

    The actual parse-and-persist work (including tool-info extraction and
    SBOM-record/version linking) happens in the ``ingest`` worker pool --
    see ``sbom_graph_enrichment.ingest_tasks.ingest_cyclonedx``.
    """

    def __init__(self, config: dict):
        self.sonatype_client = SonaTypeClient(config)

    def close(self) -> None:
        """Release the Sonatype HTTP session."""
        self.sonatype_client.close()

    def process_cyclonedx_sbom(
        self,
        app_id: str,
        public_app_id: str,
        version: str = "1.5",
        stage_id: str = "release",
    ) -> dict[str, str]:
        """Fetch the CycloneDX SBOM and enqueue it on the ``ingest`` queue.

        Returns:
            Dict with ``record_id`` and ``job_id``.
        """
        try:
            sbom = self.sonatype_client.get_cyclonedx_sbom(app_id, version, stage_id)
            if sbom is None:
                error_message = (
                    f"Error: Unable to retrieve CycloneDX {version} data "
                    f"for app ID {app_id} on {stage_id}"
                )
                logger.error(error_message)
                raise NotFound(error_message)
        except NotFound:
            logger.exception("Error processing CycloneDX SBOM")
            raise

        # Derive a *deterministic* record id from the SBOM content (and the
        # app it belongs to) so a re-delivered webhook converges to the same
        # SBOMRecord node + PRODUCED_BY_SBOM edges instead of accumulating a
        # fresh duplicate on every replay (idempotent ingest — SAST L2).
        # Identical content for the same app => identical record_id => the
        # worker's MERGE is a no-op.
        document_hash = hashlib.sha256(
            json.dumps(sbom, sort_keys=True).encode("utf-8")
        ).hexdigest()
        record_id = str(
            uuid.uuid5(uuid.NAMESPACE_URL, f"sbom:{public_app_id}:{document_hash}")
        )

        try:
            celery_app = get_celery_client()
            async_result = celery_app.send_task(
                "sbom_graph_enrichment.ingest_tasks.ingest_cyclonedx",
                args=[record_id, sbom, app_id, public_app_id, None, "webhook"],
                queue="ingest",
            )
        except Exception as exc:  # pylint: disable=broad-exception-caught
            # CWE-209: never propagate the underlying broker/celery exception.
            logger.error(
                "Failed to enqueue CycloneDX ingest for record_id=%s: %s",
                record_id,
                exc.__class__.__name__,
            )
            raise RuntimeError("Ingest pipeline not available") from exc

        logger.info(
            "CycloneDX SBOM ingest enqueued: record_id=%s job_id=%s app_id=%s",
            record_id,
            async_result.id,
            app_id,
        )
        return {"record_id": record_id, "job_id": async_result.id}

    def process_cyclone_sbom(
        self,
        app_id: str,
        public_app_id: str,
        version: str = "1.5",
        stage_id: str = "release",
    ):
        """
        Backwards-compatible wrapper for :meth:`process_cyclonedx_sbom`.
        """
        return self.process_cyclonedx_sbom(
            app_id=app_id,
            public_app_id=public_app_id,
            version=version,
            stage_id=stage_id,
        )


class VexHelper:
    """Helper class to fetch a VEX document from Sonatype and enqueue it for ingest.

    The actual parsing/persistence happens in the ``ingest`` worker pool --
    see ``sbom_graph_enrichment.ingest_tasks.ingest_vex``.
    """

    def __init__(self, config: dict):
        """Initialize with a Sonatype client."""
        self.sonatype_client = SonaTypeClient(config)

    def close(self) -> None:
        """Release the Sonatype HTTP session."""
        self.sonatype_client.close()

    def process_vex_for_application(
        self,
        app_id: str,
        stage_id: str = "release",
    ) -> Optional[dict[str, str]]:
        """Fetch VEX data for an application and enqueue it on the ``ingest`` queue.

        Args:
            app_id: The Sonatype application ID.
            stage_id: The stage to fetch VEX for.

        Returns:
            Dict with ``job_id``, or None if no VEX data available.
        """
        document = self.sonatype_client.get_vex_document(
            app_id=app_id,
            stage_id=stage_id,
        )
        if document is None:
            return None

        try:
            celery_app = get_celery_client()
            async_result = celery_app.send_task(
                "sbom_graph_enrichment.ingest_tasks.ingest_vex",
                args=[document],
                queue="ingest",
            )
        except Exception as exc:  # pylint: disable=broad-exception-caught
            # CWE-209: never propagate the underlying broker/celery exception.
            logger.error(
                "Failed to enqueue VEX ingest for app_id=%s: %s",
                app_id,
                exc.__class__.__name__,
            )
            raise RuntimeError("Ingest pipeline not available") from exc

        return {"job_id": async_result.id}


class SonaTypeClient:
    """Client class to interact with SonaType API."""

    def __init__(self, config: dict):
        self.sonatype_host = config.get("SONATYPE_HOST", "")
        self.sonatype_username = config.get("SONATYPE_USERNAME", "")
        self.sonatype_password = config.get("SONATYPE_PASSWORD", "")
        self.cacerts = config.get("SONATYPE_CACERTS", "certs/ca_bundle.pem")
        self.session = requests.Session()
        self.session.verify = self.cacerts
        self.session.auth = HTTPBasicAuth(
            username=self.sonatype_username, password=self.sonatype_password
        )
        self.api_url = f"https://{self.sonatype_host}/api/v2/"

    def close(self) -> None:
        """Close the underlying requests session (releases pooled sockets)."""
        self.session.close()

    def get_cyclonedx_sbom(
        self,
        app_id: str,
        version: str = "1.5",
        stage_id: str = "release",
        headers: Optional[dict] = None,
    ) -> Optional[dict]:
        """
        Get the CycloneDX SBOM for the given application ID and public ID.
        """
        try:
            if headers is None:
                headers = {"accept": "application/json"}
            else:
                headers["accept"] = "application/json"

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
                f"Error: Unable to retrieve CycloneDX {version} data "
                f"for app ID {app_id} on {stage_id}"
            )
            logger.error(error_message)
            raise NotFound(error_message) from e

    def get_vex_document(
        self,
        app_id: str,
        stage_id: str = "release",
        headers: Optional[dict] = None,
    ) -> Optional[dict]:
        """Fetch a VEX document from Sonatype IQ for the given application.

        Args:
            app_id: The Sonatype application ID.
            stage_id: The stage to fetch VEX for.
            headers: Optional HTTP headers.

        Returns:
            The parsed VEX JSON document, or None if not available.
        """
        try:
            if headers is None:
                headers = {"accept": "application/json"}
            else:
                headers = dict(headers)
                headers["accept"] = "application/json"

            url = (
                f"{self.api_url}vulnerabilities/vex/{urlquote(app_id, safe='')}"
                f"/stages/{urlquote(stage_id, safe='')}"
            )

            response = self.session.get(url, params=None, headers=headers)
            if response.status_code == 404:
                return None
            response.raise_for_status()

            data = response.json()
            if not isinstance(data, dict):
                return None
            return data
        except requests.exceptions.RequestException:
            logger.debug(
                "VEX document not available for app_id=%s stage_id=%s",
                app_id,
                stage_id,
            )
            return None
        except (ValueError, TypeError):
            logger.debug(
                "Invalid VEX response for app_id=%s stage_id=%s",
                app_id,
                stage_id,
            )
            return None


def process_release_scan(
    app_id: str,
    public_id: str,
    config: dict,
) -> dict:
    """
    Process a release scan by fetching the CycloneDX SBOM and enqueueing it
    for ingestion on the ``ingest`` Celery queue (see
    ``sbom_graph_enrichment.ingest_tasks``).

    Optionally fetches and enqueues VEX data (best-effort; failures are
    non-fatal).

    :param app_id: The SonaType application ID
    :param public_id: The SonaType public application ID
    :param config: Application configuration dictionary
    :return: Dictionary with success status and any error message
    """
    cyclone_helper = None
    try:
        cyclone_helper = CycloneDXHelper(config)
        cyclone_helper.process_cyclonedx_sbom(app_id=app_id, public_app_id=public_id)

        # Attempt VEX processing (non-blocking)
        vex_helper = None
        try:
            vex_helper = VexHelper(config)
            vex_result = vex_helper.process_vex_for_application(app_id)
            if vex_result:
                logger.info(
                    "VEX ingest enqueued: job_id=%s",
                    vex_result.get("job_id"),
                )
        except Exception:  # pylint: disable=broad-exception-caught
            logger.warning("VEX processing failed for %s (non-fatal)", public_id)
        finally:
            # Release the VEX helper's HTTP session so a per-webhook instance
            # does not leak it (these are created fresh per request, not
            # process singletons).
            if vex_helper is not None:
                vex_helper.close()

        return {"success": True}
    except (NotFound, RuntimeError):
        logger.exception("Error processing release scan for %s", public_id)
        return {"success": False, "error": "SBOM processing failed"}
    finally:
        if cyclone_helper is not None:
            cyclone_helper.close()


# Create the default application instance
app = create_app()


if __name__ == "__main__":
    debug_mode = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    app.run(debug=debug_mode, host="0.0.0.0", port=5000)
