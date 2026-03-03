"""Abstract base class for enrichment certifiers.

Every certifier queries an external data source for a given package URL
and returns a list of findings that the task layer persists to the graph.

Certifiers are synchronous -- Celery already provides concurrency via the
worker pool, and each certifier makes at most one HTTP request per task
invocation, so async I/O adds complexity without benefit.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

import httpx


class FindingKind(str, Enum):
    """Discriminator for the type of enrichment finding."""

    VULNERABILITY = "vulnerability"
    LICENSE = "license"
    SCORECARD = "scorecard"
    OSSINDEX = "ossindex"
    DEPSDEV = "depsdev"
    TRUST_SCORE = "trust_score"


@dataclass(slots=True)
class Finding:
    """A single piece of enrichment data produced by a certifier."""

    kind: FindingKind
    source: str
    package_url: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    data: dict[str, Any] = field(default_factory=dict)


class Certifier(abc.ABC):
    """Interface that every enrichment certifier must implement."""

    @property
    @abc.abstractmethod
    def name(self) -> str:
        """Short identifier used in logs and enrichment records."""

    @abc.abstractmethod
    def enrich(self, purl: str, *, client: httpx.Client) -> list[Finding]:
        """Query the external source and return findings for *purl*.

        A shared :class:`httpx.Client` is passed in by the task layer to
        enable TCP/TLS connection pooling across calls.

        Implementations must handle rate-limiting internally and raise
        ``httpx.HTTPStatusError`` or subclass on transient failures so the
        task layer can retry.
        """
