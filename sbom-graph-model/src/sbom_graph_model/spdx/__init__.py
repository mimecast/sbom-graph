"""
SPDX SBOM processing module for parsing and processing SPDX 2.3 JSON documents.
"""

from .processor import SPDXProcessor, SPDXValidationError

__all__ = ["SPDXProcessor", "SPDXValidationError"]
