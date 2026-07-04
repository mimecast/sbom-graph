"""OpenVEX document parser.

Parses OpenVEX JSON documents and maps statements to graph model objects
for persistence. See https://openvex.dev/ for the specification.
"""

from __future__ import annotations

import logging
import re
import uuid
from typing import Any

from .model import VexStatus
from .persistence import Persistence

logger = logging.getLogger(__name__)

# A VEX statement's `vulnerability.@id` / `name` becomes a Defect link, so an
# unvalidated value could forge a VEX->Defect edge (e.g. a bogus "not_affected")
# against an arbitrary identifier. Require a recognised vulnerability-id scheme
# (CVE or GHSA) before linking; anything else is skipped and logged (CWE-20/290).
_VULN_ID_RE = re.compile(
    r"^(?:CVE-\d{4}-\d{4,}|GHSA-[0-9a-z]+(?:-[0-9a-z]+)*)$",
    re.IGNORECASE,
)


class VexProcessingError(ValueError):
    """Raised when a VEX document fails validation."""


class VexProcessor:
    """Processes OpenVEX JSON documents and persists them to the graph.

    Args:
        persistence: The persistence layer for graph operations.
    """

    def __init__(self, persistence: Persistence):
        self.persistence = persistence

    def process_vex_document(self, document: dict[str, Any]) -> dict[str, int]:
        """Parse and persist an OpenVEX document.

        Args:
            document: Parsed OpenVEX JSON.

        Returns:
            Summary dict with ``statements_processed`` and
            ``linked_vulnerabilities`` counts.

        Raises:
            VexProcessingError: If the document is malformed.
        """
        self._validate_document(document)

        source_document = document.get("@id", str(uuid.uuid4()))
        doc_timestamp = document.get("timestamp", "")
        statements = document.get("statements", [])

        statements_processed = 0
        linked_vulns = 0

        for stmt in statements:
            result = self._process_statement(stmt, source_document, doc_timestamp)
            statements_processed += 1
            linked_vulns += result.get("linked_vulns", 0)

        logger.info(
            "Processed VEX document: %d statements, %d linked vulns",
            statements_processed, linked_vulns,
        )
        return {
            "statements_processed": statements_processed,
            "linked_vulnerabilities": linked_vulns,
        }

    def _validate_document(self, document: dict[str, Any]) -> None:
        """Validate basic OpenVEX document structure."""
        if not isinstance(document, dict):
            raise VexProcessingError("VEX document must be a JSON object")

        context = document.get("@context")
        if context and "openvex" not in str(context).lower():
            logger.warning("VEX document @context does not reference openvex")

        statements = document.get("statements")
        if not statements or not isinstance(statements, list):
            raise VexProcessingError(
                "VEX document must contain a non-empty 'statements' array"
            )

    def _process_statement(
        self,
        stmt: dict[str, Any],
        source_document: str,
        doc_timestamp: str,
    ) -> dict[str, int]:
        """Process a single VEX statement."""
        raw_status = stmt.get("status", "")
        try:
            status = VexStatus.from_str(raw_status)
        except ValueError:
            logger.warning("Skipping VEX statement with invalid status: %s", raw_status)
            return {"linked_vulns": 0}

        statement_id = str(uuid.uuid4())
        justification = stmt.get("justification")
        impact_statement = stmt.get("impact_statement")
        action_statement = stmt.get("action_statement")
        timestamp = stmt.get("timestamp", doc_timestamp)

        self.persistence.create_vex_statement(
            statement_id=statement_id,
            status=status,
            justification=justification,
            impact_statement=impact_statement,
            action_statement=action_statement,
            source_document=source_document,
            timestamp=timestamp,
        )

        linked_vulns = 0

        vulnerability = stmt.get("vulnerability") or {}
        vuln_id = vulnerability.get("@id") or vulnerability.get("name", "")
        if vuln_id and (not isinstance(vuln_id, str) or not _VULN_ID_RE.match(vuln_id)):
            logger.warning(
                "Skipping VEX->Defect link: unrecognised vulnerability id %r "
                "(expected CVE-… or GHSA-…)",
                vuln_id,
            )
            vuln_id = ""
        if vuln_id:
            self.persistence.link_vex_to_defect(
                statement_id=statement_id, defect_id=vuln_id,
            )
            linked_vulns += 1

        products = stmt.get("products", [])
        for product in products:
            purl = self._extract_purl(product)
            if purl:
                self.persistence.link_vex_to_version(
                    statement_id=statement_id, purl=purl,
                )

        return {"linked_vulns": linked_vulns}

    @staticmethod
    def _extract_purl(product: dict[str, Any] | str) -> str | None:
        """Extract a purl from an OpenVEX product entry."""
        if isinstance(product, str):
            return product if product.startswith("pkg:") else None

        if isinstance(product, dict):
            identifiers = product.get("identifiers") or {}
            purl = identifiers.get("purl")
            if purl and isinstance(purl, str):
                return purl

            product_id = product.get("@id", "")
            if isinstance(product_id, str) and product_id.startswith("pkg:"):
                return product_id

        return None
