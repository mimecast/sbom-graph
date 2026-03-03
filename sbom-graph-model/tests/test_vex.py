"""Tests for the OpenVEX parser module."""

from unittest.mock import MagicMock

import pytest

from sbom_graph_model.vex import VexProcessingError, VexProcessor


class TestProcessValidDocument:
    """Tests for VexProcessor.process_vex_document with valid input."""

    def test_process_valid_document(self):
        """Valid OpenVEX doc with 2 statements checks calls to persistence."""
        persistence = MagicMock()
        processor = VexProcessor(persistence)

        document = {
            "@context": "https://openvex.dev/ns",
            "@id": "https://example.com/vex/doc-1",
            "timestamp": "2024-06-01T00:00:00Z",
            "statements": [
                {
                    "status": "not_affected",
                    "vulnerability": {"@id": "CVE-2024-12345"},
                    "products": [{"identifiers": {"purl": "pkg:maven/com.example/lib@1.0"}}],
                },
                {
                    "status": "affected",
                    "justification": "In use",
                    "vulnerability": {"name": "GHSA-xxxx"},
                    "products": ["pkg:npm/-/dep@2.0"],
                },
            ],
        }

        result = processor.process_vex_document(document)

        assert result["statements_processed"] == 2
        assert result["linked_vulnerabilities"] == 2
        assert persistence.create_vex_statement.call_count == 2
        assert persistence.link_vex_to_defect.call_count == 2
        assert persistence.link_vex_to_version.call_count == 2


class TestMissingStatementsRaises:
    """Tests for document validation."""

    def test_missing_statements_raises(self):
        """Document without statements raises VexProcessingError."""
        persistence = MagicMock()
        processor = VexProcessor(persistence)

        document = {"@context": "https://openvex.dev/ns", "@id": "doc-1"}

        with pytest.raises(VexProcessingError, match="statements"):
            processor.process_vex_document(document)

        document_empty = {"statements": []}
        with pytest.raises(VexProcessingError, match="statements"):
            processor.process_vex_document(document_empty)


class TestInvalidStatusSkipped:
    """Tests for statement validation."""

    def test_invalid_status_skipped(self):
        """Statement with bad status is skipped."""
        persistence = MagicMock()
        processor = VexProcessor(persistence)

        document = {
            "@id": "doc-1",
            "statements": [
                {"status": "invalid_status", "vulnerability": {"@id": "CVE-1"}},
            ],
        }

        result = processor.process_vex_document(document)

        assert result["statements_processed"] == 1
        assert result["linked_vulnerabilities"] == 0
        persistence.create_vex_statement.assert_not_called()


class TestExtractPurl:
    """Tests for VexProcessor._extract_purl."""

    def test_extract_purl_from_string(self):
        """Purl string extraction."""
        purl = VexProcessor._extract_purl("pkg:maven/com.example/lib@1.0")
        assert purl == "pkg:maven/com.example/lib@1.0"

    def test_extract_purl_from_dict_identifiers(self):
        """Purl dict extraction via identifiers.purl."""
        product = {"identifiers": {"purl": "pkg:npm/-/foo@2.0"}}
        purl = VexProcessor._extract_purl(product)
        assert purl == "pkg:npm/-/foo@2.0"

    def test_extract_purl_from_dict_at_id(self):
        """Purl dict extraction via @id."""
        product = {"@id": "pkg:maven/org/bar@3.0"}
        purl = VexProcessor._extract_purl(product)
        assert purl == "pkg:maven/org/bar@3.0"

    def test_extract_purl_returns_none(self):
        """Non-purl string returns None."""
        assert VexProcessor._extract_purl("https://example.com/not-a-purl") is None
        assert VexProcessor._extract_purl("plain-string") is None
        assert VexProcessor._extract_purl({}) is None
        assert VexProcessor._extract_purl({"identifiers": {}}) is None
