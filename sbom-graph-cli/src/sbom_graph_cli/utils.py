"""Shared utilities: output formatting, error handling."""

from __future__ import annotations


class APIError(Exception):
    """Raised when the sbom-graph API returns an error.

    Attributes:
        message: Human-readable error message.
        status_code: HTTP status code (e.g. 400, 404, 500).
    """

    def __init__(self, message: str, status_code: int | None = None) -> None:
        """Initialise the error.

        Args:
            message: Error message from the API or client.
            status_code: Optional HTTP status code.
        """
        super().__init__(message)
        self.message = message
        self.status_code = status_code


# Exit codes for CI/CD integration
EXIT_SUCCESS = 0
EXIT_POLICY_VIOLATIONS = 1
EXIT_ERROR = 2
