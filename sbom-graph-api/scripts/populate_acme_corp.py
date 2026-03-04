#!/usr/bin/env python3
"""Script to populate the acme_corp FalkorDB graph with fictional dependency data.

=============================================================================
DEMONSTRATION GRAPH - FOR EXPERIMENTATION AND TESTING ONLY
=============================================================================

This script creates a fictional software dependency graph for ACME Corporation
to demonstrate and test the SBOM Graph API application. The data is entirely
fictional and does not represent any real organization or vulnerabilities.

=============================================================================
GRAPH SCHEMA SPECIFICATION
=============================================================================

NODE TYPES
----------

1. Version
   Represents a specific version of a software project (application or library).

   Labels (can have multiple):
   - Version          : All version nodes have this label
   - Application      : Root nodes that are scanned applications
   - Library          : Nodes that are dependencies (can also be Applications)
   - INTERNAL        : Internal ACME Corporation projects

   Properties (all Version nodes):
   - name             : String - The version string (e.g., "1.0.0", "2.1.0-SNAPSHOT")
   - project_name     : String - The project/artifact name (e.g., "acme-auth")
   - project_group    : String - The group/organization (e.g., "com.acme.security")
   - type             : String - "application" or "library"
   - package_url      : String - Package URL (purl) format identifier
   - scan_ids         : List[String] - SCA scan IDs that surfaced this dependency

   Additional properties for Application nodes:
   - scan_id          : String - The SCA scan ID from CycloneDX
   - app_id           : String - Application ID in the SCA platform
   - public_id        : String - Human-readable identifier in SCA platform
   - repo_url         : String - VCS repository URL

   Additional properties for internal (INTERNAL) nodes:
   - inDegree         : Integer - Number of inbound DEPENDENCY_VERSION edges
   - outDegree        : Integer - Number of outbound DEPENDENCY_VERSION edges

2. Defect
   Represents a security vulnerability or defect.

   Properties:
   - defect_id        : String - Unique identifier (e.g., "CVE-2023-12345")
   - title            : String - Short description
   - description      : String - Detailed description
   - severity         : String - "CRITICAL", "HIGH", "MEDIUM", "LOW"
   - cvss_score       : Float - CVSS v3 score (0.0 - 10.0)
   - cwe_id           : String - CWE identifier (e.g., "CWE-79")
   - published_date   : String - ISO date when published
   - affected_versions: List[String] - Version ranges affected

EDGE TYPES
----------

1. DEPENDENCY_VERSION
   Connects a Version node to its dependency Version node.
   Direction: (dependent)-[:DEPENDENCY_VERSION]->(dependency)

2. VERSION_DEFECT
   Connects a Version node to a Defect that affects it.
   Direction: (version)-[:VERSION_DEFECT]->(defect)

GRAPH CHARACTERISTICS
---------------------

- DAG Structure: The dependency graph is primarily a Directed Acyclic Graph
- Scan ID Propagation: Application scan_ids propagate to all transitive dependencies
- Centrality Variation:
  - High inward centrality: Common libraries many projects depend on
  - High outward centrality: Applications with many dependencies
  - Some nodes have both (framework libraries that are also scanned as apps)
- Library Connectivity: All libraries have at least one inbound connection
  (they are not start/root nodes)

SPECIAL CASES
-------------

1. SNAPSHOT Versions:
   - Some internal libraries have SNAPSHOT versions (e.g., "3.0.0-SNAPSHOT")
   - Some applications have SNAPSHOT versions
   - Some release versions depend on SNAPSHOT libraries (bad practice scenario)

2. Non-Semver Versions:
   - Legacy projects use non-standard version formats:
     - Calendar-based: "2024.01", "2024.02", "2024.03-hotfix"
     - Prefix-based: "v1", "v2", "v2.1", "v3-beta", "v5.0", "v6-preview"
     - Build-based: "build-123", "build-456", "release-2024.01"
     - Phase-based: "alpha", "beta", "rc1", "GA", "prototype-1", "mvp"

3. Self-Referential Libraries (Simple Cycles):
   - acme-plugin-loader: Plugin system that can load itself as a plugin
   - acme-module-registry: Registry that references itself for nested modules
   - These are intentional self-dependencies used to test cycle detection

   DEMO APPLICATIONS for cyclic dependency visualization:

   The /visualizations/dependencies endpoint uses spring layout (force-directed)
   which naturally handles cyclic graphs. Cycle edges are shown in red dashed lines
   and nodes involved in cycles have red borders.

   - extensible-platform 1.0.0: Uses BOTH cyclic libraries (best comprehensive demo)
     URL: /visualizations/dependencies?project_name=extensible-platform&version_name=1.0.0
     Shows: Both acme-plugin-loader and acme-module-registry cycles

   - plugin-manager 1.0.0: Uses acme-plugin-loader (self-referential)
     URL: /visualizations/dependencies?project_name=plugin-manager&version_name=1.0.0
     Shows: acme-plugin-loader:1.0.0 -> acme-plugin-loader:1.0.0 cycle

   - module-loader 1.0.0: Uses acme-module-registry (self-referential)
     URL: /visualizations/dependencies?project_name=module-loader&version_name=1.0.0
     Shows: acme-module-registry:1.0.0 -> acme-module-registry:1.0.0 cycle

   Self-Dependencies Report: /reports/self-dependencies
     Lists all self-referential dependencies in the graph

4. Multi-Version Dependencies (Library Adoption Demonstration):
   Multiple applications explicitly use different versions of the same library.
   This demonstrates the Multi-Version Dependencies Report - useful for
   understanding library adoption patterns and vulnerability remediation planning.

   DEMO LIBRARIES for /reports/multi-version-deps:

   - jackson-databind: /reports/multi-version-deps/jackson-databind
     5 different versions pinned across apps (2.13.0, 2.14.0, 2.14.2, 2.15.2, 2.16.1)
     Use case: Identify teams on vulnerable versions

   - slf4j-api: /reports/multi-version-deps/slf4j-api
     SLF4J 1.x vs 2.x compatibility scenarios (1.7.36, 2.0.9)
     Use case: Track migration progress from 1.x to 2.x

   - guava: /reports/multi-version-deps/guava
     Multiple Guava versions (31.1-jre, 32.0.0-jre, 33.0.0-jre)
     Use case: Identify version fragmentation

5. Multi-Version Sources (Diamond Dependencies Demonstration):
   These scenarios demonstrate when a library's transitive dependency tree
   contains multiple versions of the same package due to upstream version
   pinning. This is a common source of runtime issues (NoSuchMethodError,
   ClassNotFoundException) in Java applications.

   DEMO LIBRARIES for /reports/multi-version-sources:

   - acme-kafka 2.0.0: Query with project_name=acme-kafka&version_name=2.0.0
     Diamond on acme-events:
     * acme-kafka -> acme-serialization 2.0.0 -> acme-events 1.1.0 (pinned)
     * acme-kafka -> acme-schema-registry 2.0.0 -> acme-events 2.0.0 (latest)
     Runtime risk: Event serialization format incompatibilities

   - acme-data-pipeline 2.0.0: Query with project_name=acme-data-pipeline&version_name=2.0.0
     Diamond on acme-connection-pool:
     * acme-data-pipeline -> acme-db-common 2.1.0 -> acme-connection-pool 1.1.0 (pinned)
     * acme-data-pipeline -> acme-cache 1.1.0 -> acme-connection-pool 2.0.0 (latest)
     Runtime risk: Connection pool API changes causing pool exhaustion

   - acme-web-common 2.0.0: Query with project_name=acme-web-common&version_name=2.0.0
     Diamond on acme-logging:
     * acme-web-common -> acme-auth 3.0.0 -> acme-logging 2.0.0-SNAPSHOT (latest)
     * acme-web-common -> acme-metrics 1.1.0 -> acme-logging 1.2.0 (pinned)
     Runtime risk: Log format inconsistencies, missing log correlation

=============================================================================
"""

import os
import random
import ssl
import sys
import traceback
import uuid
from dataclasses import dataclass, field

from falkordb import FalkorDB


@dataclass
class Version:
    """Represents a Version node in the graph."""

    project_group: str
    project_name: str
    name: str  # version string
    is_internal: bool = True  # True = INTERNAL label
    is_application: bool = False  # True = Application label
    is_library: bool = True  # True = Library label
    scan_id: str | None = None  # Only for applications
    app_id: str | None = None
    public_id: str | None = None
    repo_url: str | None = None
    scan_ids: list[str] = field(default_factory=list)
    in_degree: int = 0
    out_degree: int = 0

    @property
    def full_name(self) -> str:
        """Return full project identifier."""
        return f"{self.project_group}:{self.project_name}"

    @property
    def package_url(self) -> str:
        """Generate package URL (purl) for this version."""
        return f"pkg:maven/{self.project_group}/{self.project_name}@{self.name}?type=jar"
        

    @property
    def node_type(self) -> str:
        """Return the type property value."""
        return "application" if self.is_application else "library"


@dataclass
class Defect:
    """Represents a Defect (vulnerability) node in the graph."""

    defect_id: str
    title: str
    description: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    cvss_score: float
    cwe_id: str
    published_date: str
    affected_versions: list[str] = field(default_factory=list)


# =============================================================================
# Define the fictional ACME Corp dependency graph - EXPANDED DATASET
# =============================================================================

# Third-party libraries (high inward centrality - many things depend on these)
THIRD_PARTY_LIBS = [
    # Logging
    ("org.slf4j", "slf4j-api", ["1.7.32", "1.7.36", "2.0.0", "2.0.7", "2.0.9", "2.0.11"]),
    ("ch.qos.logback", "logback-classic", ["1.2.9", "1.2.11", "1.4.5", "1.4.11", "1.4.14"]),
    ("org.apache.logging.log4j", "log4j-core", ["2.17.0", "2.17.1", "2.19.0", "2.20.0", "2.21.0"]),
    ("org.apache.logging.log4j", "log4j-api", ["2.17.0", "2.17.1", "2.19.0", "2.20.0", "2.21.0"]),
    # JSON
    ("com.fasterxml.jackson.core", "jackson-databind", ["2.13.0", "2.14.0", "2.14.2", "2.15.2", "2.16.0", "2.16.1"]),
    ("com.fasterxml.jackson.core", "jackson-core", ["2.13.0", "2.14.0", "2.14.2", "2.15.2", "2.16.0", "2.16.1"]),
    ("com.fasterxml.jackson.core", "jackson-annotations", ["2.13.0", "2.14.0", "2.14.2", "2.15.2", "2.16.0", "2.16.1"]),
    ("com.google.code.gson", "gson", ["2.8.9", "2.9.0", "2.9.1", "2.10.0", "2.10.1"]),
    # HTTP
    ("org.apache.httpcomponents", "httpclient", ["4.5.13", "4.5.14"]),
    ("org.apache.httpcomponents.client5", "httpclient5", ["5.2.0", "5.2.1", "5.3.0"]),
    ("com.squareup.okhttp3", "okhttp", ["4.9.3", "4.10.0", "4.11.0", "4.12.0"]),
    # Database
    ("org.postgresql", "postgresql", ["42.5.0", "42.5.4", "42.6.0", "42.7.0", "42.7.1"]),
    ("mysql", "mysql-connector-java", ["8.0.30", "8.0.32", "8.0.33"]),
    ("com.zaxxer", "HikariCP", ["5.0.0", "5.0.1", "5.1.0"]),
    ("redis.clients", "jedis", ["4.3.0", "4.4.0", "4.4.3", "5.0.0", "5.1.0"]),
    ("org.mongodb", "mongodb-driver-sync", ["4.9.0", "4.10.0", "4.11.0"]),
    # Security
    ("org.bouncycastle", "bcprov-jdk18on", ["1.72", "1.74", "1.76", "1.77"]),
    ("org.bouncycastle", "bcpkix-jdk18on", ["1.72", "1.74", "1.76", "1.77"]),
    ("com.auth0", "java-jwt", ["4.0.0", "4.2.0", "4.3.0", "4.4.0"]),
    ("io.jsonwebtoken", "jjwt-api", ["0.11.5", "0.12.0", "0.12.3"]),
    # Testing
    ("org.junit.jupiter", "junit-jupiter", ["5.8.2", "5.9.0", "5.9.3", "5.10.0", "5.10.1"]),
    ("org.junit.jupiter", "junit-jupiter-api", ["5.8.2", "5.9.0", "5.9.3", "5.10.0", "5.10.1"]),
    ("org.mockito", "mockito-core", ["4.8.0", "5.3.0", "5.5.0", "5.7.0"]),
    ("org.assertj", "assertj-core", ["3.23.0", "3.24.0", "3.24.2", "3.25.0"]),
    # Spring Framework
    ("org.springframework", "spring-core", ["5.3.25", "5.3.30", "6.0.11", "6.1.0", "6.1.2"]),
    ("org.springframework", "spring-beans", ["5.3.25", "5.3.30", "6.0.11", "6.1.0", "6.1.2"]),
    ("org.springframework", "spring-context", ["5.3.25", "5.3.30", "6.0.11", "6.1.0", "6.1.2"]),
    ("org.springframework", "spring-web", ["5.3.25", "5.3.30", "6.0.11", "6.1.0", "6.1.2"]),
    ("org.springframework", "spring-webmvc", ["5.3.25", "5.3.30", "6.0.11", "6.1.0", "6.1.2"]),
    ("org.springframework.boot", "spring-boot", ["2.7.12", "2.7.15", "3.1.5", "3.2.0", "3.2.1"]),
    ("org.springframework.boot", "spring-boot-autoconfigure", ["2.7.12", "2.7.15", "3.1.5", "3.2.0", "3.2.1"]),
    ("org.springframework.boot", "spring-boot-starter-web", ["2.7.12", "2.7.15", "3.1.5", "3.2.0", "3.2.1"]),
    ("org.springframework.boot", "spring-boot-starter-data-jpa", ["2.7.12", "2.7.15", "3.1.5", "3.2.0", "3.2.1"]),
    ("org.springframework.security", "spring-security-core", ["5.8.0", "6.1.0", "6.2.0"]),
    ("org.springframework.security", "spring-security-web", ["5.8.0", "6.1.0", "6.2.0"]),
    # Utils
    ("com.google.guava", "guava", ["31.0-jre", "31.1-jre", "32.0.0-jre", "32.1.2-jre", "33.0.0-jre"]),
    ("org.apache.commons", "commons-lang3", ["3.12.0", "3.13.0", "3.14.0"]),
    ("commons-io", "commons-io", ["2.11.0", "2.13.0", "2.15.0", "2.15.1"]),
    ("org.apache.commons", "commons-collections4", ["4.4"]),
    ("org.apache.commons", "commons-text", ["1.10.0", "1.11.0"]),
    ("commons-codec", "commons-codec", ["1.15", "1.16.0"]),
    # Serialization
    ("com.esotericsoftware", "kryo", ["5.4.0", "5.5.0"]),
    ("org.xerial.snappy", "snappy-java", ["1.1.10.0", "1.1.10.4", "1.1.10.5"]),
    # AWS SDK
    ("software.amazon.awssdk", "aws-core", ["2.20.0", "2.21.0", "2.25.0"]),
    ("software.amazon.awssdk", "s3", ["2.20.0", "2.21.0", "2.25.0"]),
    ("software.amazon.awssdk", "sqs", ["2.20.0", "2.21.0", "2.25.0"]),
    ("software.amazon.awssdk", "dynamodb", ["2.20.0", "2.21.0", "2.25.0"]),
    # Kafka
    ("org.apache.kafka", "kafka-clients", ["3.4.0", "3.5.0", "3.6.0"]),
    # gRPC
    ("io.grpc", "grpc-core", ["1.54.0", "1.58.0", "1.60.0"]),
    ("io.grpc", "grpc-netty", ["1.54.0", "1.58.0", "1.60.0"]),
    ("io.grpc", "grpc-protobuf", ["1.54.0", "1.58.0", "1.60.0"]),
    # Netty
    ("io.netty", "netty-all", ["4.1.90.Final", "4.1.100.Final", "4.1.104.Final"]),
    ("io.netty", "netty-handler", ["4.1.90.Final", "4.1.100.Final", "4.1.104.Final"]),
    # Metrics/Monitoring
    ("io.micrometer", "micrometer-core", ["1.10.0", "1.11.0", "1.12.0"]),
    ("io.prometheus", "simpleclient", ["0.16.0"]),
    # Validation
    ("org.hibernate.validator", "hibernate-validator", ["8.0.0.Final", "8.0.1.Final"]),
    ("jakarta.validation", "jakarta.validation-api", ["3.0.0", "3.0.2"]),
]

# Internal shared libraries (medium-high inward centrality)
INTERNAL_LIBS = [
    # ==========================================================================
    # LAYER 0: Foundational wrappers (wrap third-party directly)
    # These ensure ALL third-party libraries have at least one incoming connection
    # ==========================================================================
    # Testing wrappers (wrap junit, mockito, assertj)
    ("com.acme.foundation", "acme-testing-core", ["1.0.0", "1.1.0", "2.0.0"]),
    # Validation wrappers (wrap hibernate-validator, jakarta.validation)
    ("com.acme.foundation", "acme-validation-core", ["1.0.0", "1.1.0"]),
    # Serialization wrappers (wrap kryo, snappy-java, additional gson usage)
    ("com.acme.foundation", "acme-serialization-core", ["1.0.0", "1.1.0", "2.0.0"]),
    # HTTP client wrappers (wrap httpclient, okhttp)
    ("com.acme.foundation", "acme-http-core", ["1.0.0", "1.1.0", "2.0.0"]),
    # Monitoring wrappers (wrap prometheus, additional micrometer)
    ("com.acme.foundation", "acme-monitoring-core", ["1.0.0", "1.1.0"]),
    # Netty wrappers (wrap netty-all, netty-handler)
    ("com.acme.foundation", "acme-netty-core", ["1.0.0", "1.1.0"]),
    # Spring core wrappers (additional spring framework abstractions)
    ("com.acme.foundation", "acme-spring-core", ["1.0.0", "1.1.0", "2.0.0"]),
    # Collections wrappers (wrap commons-collections, commons-text, commons-codec)
    ("com.acme.foundation", "acme-collections", ["1.0.0", "1.1.0"]),
    # MySQL/MongoDB wrappers
    ("com.acme.foundation", "acme-nosql-core", ["1.0.0", "1.1.0"]),
    ("com.acme.foundation", "acme-mysql-core", ["1.0.0"]),

    # ==========================================================================
    # LAYER 1: Core framework (depends on Layer 0)
    # ==========================================================================
    ("com.acme.core", "acme-common", ["1.0.0", "1.1.0", "1.2.0", "2.0.0", "2.1.0", "3.0.0-SNAPSHOT"]),
    ("com.acme.core", "acme-logging", ["1.0.0", "1.1.0", "1.2.0", "2.0.0-SNAPSHOT"]),
    ("com.acme.core", "acme-config", ["1.0.0", "1.1.0", "1.2.0", "2.0.0", "2.1.0-SNAPSHOT"]),
    ("com.acme.core", "acme-utils", ["1.0.0", "1.1.0", "1.2.0"]),
    ("com.acme.core", "acme-metrics", ["1.0.0", "1.1.0"]),

    # ==========================================================================
    # LAYER 2: Security (depends on Layer 1)
    # ==========================================================================
    ("com.acme.security", "acme-auth", ["1.0.0", "1.1.0", "2.0.0", "2.1.0", "3.0.0", "4.0.0-SNAPSHOT"]),
    ("com.acme.security", "acme-crypto", ["1.0.0", "1.1.0", "1.2.0"]),
    ("com.acme.security", "acme-jwt", ["1.0.0", "1.0.1", "1.1.0"]),
    ("com.acme.security", "acme-oauth", ["1.0.0", "1.1.0"]),
    ("com.acme.security", "acme-rbac", ["1.0.0", "1.1.0"]),

    # ==========================================================================
    # LAYER 2: Data (depends on Layer 1)
    # ==========================================================================
    ("com.acme.data", "acme-db-common", ["1.0.0", "1.1.0", "2.0.0", "2.1.0", "3.0.0-SNAPSHOT"]),
    ("com.acme.data", "acme-cache", ["1.0.0", "1.0.1", "1.1.0", "2.0.0-SNAPSHOT"]),
    ("com.acme.data", "acme-models", ["1.0.0", "2.0.0", "3.0.0", "4.0.0", "5.0.0-SNAPSHOT"]),
    ("com.acme.data", "acme-repository", ["1.0.0", "1.1.0", "2.0.0", "3.0.0-SNAPSHOT"]),
    ("com.acme.data", "acme-migration", ["1.0.0", "1.1.0"]),
    ("com.acme.data", "acme-connection-pool", ["1.0.0", "1.1.0", "2.0.0"]),
    ("com.acme.data", "acme-data-pipeline", ["1.0.0", "2.0.0"]),

    # ==========================================================================
    # LAYER 2: Messaging (depends on Layer 1)
    # ==========================================================================
    ("com.acme.messaging", "acme-events", ["1.0.0", "1.1.0", "2.0.0", "3.0.0-SNAPSHOT"]),
    ("com.acme.messaging", "acme-kafka", ["1.0.0", "1.1.0", "2.0.0", "3.0.0-SNAPSHOT"]),
    ("com.acme.messaging", "acme-sqs", ["1.0.0", "1.1.0"]),
    ("com.acme.messaging", "acme-pubsub", ["1.0.0"]),
    ("com.acme.messaging", "acme-serialization", ["1.0.0", "2.0.0"]),
    ("com.acme.messaging", "acme-schema-registry", ["1.0.0", "2.0.0"]),

    # ==========================================================================
    # LAYER 2: HTTP/API (depends on Layer 1 and Layer 0)
    # ==========================================================================
    ("com.acme.http", "acme-rest-client", ["1.0.0", "1.1.0", "2.0.0", "2.1.0", "3.0.0-SNAPSHOT"]),
    ("com.acme.http", "acme-web-common", ["1.0.0", "1.1.0", "2.0.0", "3.0.0-SNAPSHOT"]),
    ("com.acme.http", "acme-grpc-common", ["1.0.0", "1.1.0"]),
    ("com.acme.http", "acme-api-gateway-sdk", ["1.0.0", "1.1.0"]),

    # ==========================================================================
    # LAYER 2: Testing (depends on Layer 0 and Layer 1)
    # ==========================================================================
    ("com.acme.testing", "acme-test-utils", ["1.0.0", "1.1.0", "1.2.0"]),
    ("com.acme.testing", "acme-mock-services", ["1.0.0", "1.1.0"]),
    ("com.acme.testing", "acme-test-containers", ["1.0.0"]),

    # ==========================================================================
    # LAYER 2: Cloud (depends on Layer 1)
    # ==========================================================================
    ("com.acme.cloud", "acme-aws-common", ["1.0.0", "1.1.0"]),
    ("com.acme.cloud", "acme-s3-client", ["1.0.0", "1.1.0"]),
    ("com.acme.cloud", "acme-secrets-manager", ["1.0.0"]),

    # ==========================================================================
    # LAYER 3: Domain-specific (depends on Layer 2)
    # ==========================================================================
    ("com.acme.domain", "acme-customer-model", ["1.0.0", "1.1.0", "2.0.0"]),
    ("com.acme.domain", "acme-order-model", ["1.0.0", "1.1.0", "2.0.0"]),
    ("com.acme.domain", "acme-product-model", ["1.0.0", "1.1.0"]),
    ("com.acme.domain", "acme-payment-model", ["1.0.0", "1.1.0"]),
    ("com.acme.domain", "acme-billing-model", ["1.0.0", "1.1.0"]),

    # ==========================================================================
    # Legacy and experimental (various layers)
    # ==========================================================================
    ("com.acme.legacy", "acme-legacy-utils", ["v1", "v2", "v2.1", "v3-beta"]),
    ("com.acme.legacy", "acme-legacy-connector", ["build-123", "build-456", "release-2024.01"]),
    ("com.acme.experimental", "acme-ml-pipeline", ["alpha", "beta", "rc1", "GA"]),
    # Self-referential libraries (simple cycles - depends on itself)
    ("com.acme.recursive", "acme-plugin-loader", ["1.0.0", "1.1.0"]),  # Plugin system that can load itself
    ("com.acme.recursive", "acme-module-registry", ["1.0.0"]),  # Registry that references itself
]

# Internal applications (roots - high outward centrality)
APPLICATIONS = [
    # Customer-facing
    ("com.acme.apps", "customer-portal", ["1.0.0", "1.1.0", "1.2.0", "2.0.0", "2.1.0", "3.0.0-SNAPSHOT"]),
    ("com.acme.apps", "customer-mobile-api", ["1.0.0", "1.1.0", "2.0.0", "2.1.0-SNAPSHOT"]),
    ("com.acme.apps", "customer-support-portal", ["1.0.0", "1.1.0"]),
    # Admin/Internal
    ("com.acme.apps", "admin-dashboard", ["1.0.0", "1.1.0", "1.2.0", "2.0.0", "3.0.0-SNAPSHOT"]),
    ("com.acme.apps", "ops-console", ["1.0.0", "1.1.0"]),
    ("com.acme.apps", "internal-tools", ["1.0.0"]),
    # API/Gateway
    ("com.acme.apps", "api-gateway", ["1.0.0", "2.0.0", "3.0.0", "3.1.0", "4.0.0-SNAPSHOT"]),
    ("com.acme.apps", "graphql-gateway", ["1.0.0", "1.1.0"]),
    ("com.acme.apps", "public-api", ["1.0.0", "1.1.0", "2.0.0"]),
    # Core Services
    ("com.acme.services", "billing-service", ["1.0.0", "1.1.0", "2.0.0", "3.0.0-SNAPSHOT"]),
    ("com.acme.services", "payment-service", ["1.0.0", "1.1.0", "2.0.0"]),
    ("com.acme.services", "notification-service", ["1.0.0", "1.1.0", "2.0.0", "2.1.0"]),
    ("com.acme.services", "email-service", ["1.0.0", "1.1.0"]),
    ("com.acme.services", "sms-service", ["1.0.0"]),
    ("com.acme.services", "push-notification-service", ["1.0.0", "1.1.0"]),
    # Analytics
    ("com.acme.services", "analytics-engine", ["1.0.0", "1.0.1", "1.1.0"]),
    ("com.acme.services", "reporting-service", ["1.0.0", "1.1.0"]),
    ("com.acme.services", "metrics-aggregator", ["1.0.0"]),
    # Order/Inventory
    ("com.acme.services", "inventory-manager", ["1.0.0", "1.1.0", "1.2.0", "2.0.0"]),
    ("com.acme.services", "order-processor", ["1.0.0", "1.1.0", "2.0.0", "3.0.0-SNAPSHOT"]),
    ("com.acme.services", "fulfillment-service", ["1.0.0", "1.1.0"]),
    ("com.acme.services", "shipping-service", ["1.0.0"]),
    # User/Auth
    ("com.acme.services", "user-service", ["1.0.0", "1.1.0", "2.0.0"]),
    ("com.acme.services", "auth-service", ["1.0.0", "1.1.0", "2.0.0", "3.0.0", "4.0.0-SNAPSHOT"]),
    ("com.acme.services", "identity-provider", ["1.0.0", "1.1.0"]),
    # Infrastructure
    ("com.acme.services", "scheduler-service", ["1.0.0", "1.1.0"]),
    ("com.acme.services", "job-runner", ["1.0.0", "1.1.0"]),
    ("com.acme.services", "config-server", ["1.0.0"]),
    ("com.acme.services", "service-registry", ["1.0.0"]),
    # Data Pipeline
    ("com.acme.services", "data-ingestion", ["1.0.0", "1.1.0"]),
    ("com.acme.services", "etl-processor", ["1.0.0"]),
    ("com.acme.services", "data-exporter", ["1.0.0"]),
    # Search
    ("com.acme.services", "search-service", ["1.0.0", "1.1.0"]),
    ("com.acme.services", "indexer-service", ["1.0.0"]),
    # Integration
    ("com.acme.services", "webhook-service", ["1.0.0", "1.1.0"]),
    ("com.acme.services", "integration-hub", ["1.0.0"]),
    # Applications with non-semver versions
    ("com.acme.legacy", "legacy-crm", ["2024.01", "2024.02", "2024.03-hotfix"]),
    ("com.acme.legacy", "legacy-erp", ["v5.0", "v5.1", "v6-preview"]),
    ("com.acme.experimental", "ai-recommendation-engine", ["prototype-1", "prototype-2", "mvp"]),
    # Release versions that use SNAPSHOT dependencies (bad practice scenarios)
    ("com.acme.apps", "quick-prototype", ["1.0.0"]),  # Release using SNAPSHOT deps
    ("com.acme.apps", "demo-app", ["1.0.0", "1.1.0"]),  # Release using SNAPSHOT deps
    # Version pinning demonstration applications (Multi-Version Sources)
    ("com.acme.services", "data-platform-core", ["1.0.0"]),  # Pins jackson-databind 2.14.2
    ("com.acme.services", "realtime-processor", ["1.0.0"]),  # Pins jackson-databind 2.13.0
    ("com.acme.services", "api-v2-service", ["1.0.0"]),  # Uses jackson-databind 2.16.1
    ("com.acme.services", "batch-processor", ["1.0.0"]),  # Pins jackson-databind 2.15.2
    ("com.acme.services", "compliance-service", ["1.0.0"]),  # Pins jackson-databind 2.14.0
    ("com.acme.services", "legacy-adapter", ["1.0.0"]),  # Pins slf4j-api 1.7.36
    ("com.acme.services", "modern-gateway", ["1.0.0"]),  # Uses slf4j-api 2.0.9
    ("com.acme.services", "cache-service", ["1.0.0"]),  # Pins guava 31.1-jre
    ("com.acme.services", "search-indexer", ["1.0.0"]),  # Pins guava 32.0.0-jre
    ("com.acme.services", "ml-inference", ["1.0.0"]),  # Uses guava 33.0.0-jre
    # Cyclic dependency demonstration applications
    ("com.acme.apps", "plugin-manager", ["1.0.0", "2.0.0"]),  # Uses self-referential acme-plugin-loader
    ("com.acme.apps", "module-loader", ["1.0.0"]),  # Uses self-referential acme-module-registry
    ("com.acme.apps", "extensible-platform", ["1.0.0"]),  # Uses both cyclic libraries
]

# Fictional vulnerabilities for third-party libraries
DEFECTS = [
    Defect(
        defect_id="CVE-2021-44228",
        title="Log4Shell RCE Vulnerability",
        description="Apache Log4j2 JNDI features do not protect against attacker controlled LDAP and other JNDI related endpoints.",
        severity="CRITICAL",
        cvss_score=10.0,
        cwe_id="CWE-502",
        published_date="2021-12-10",
        affected_versions=["log4j-core:2.17.0"],
    ),
    Defect(
        defect_id="CVE-2022-42889",
        title="Apache Commons Text RCE",
        description="Apache Commons Text performs variable interpolation, allowing properties to be dynamically evaluated and expanded.",
        severity="CRITICAL",
        cvss_score=9.8,
        cwe_id="CWE-94",
        published_date="2022-10-13",
        affected_versions=["commons-text:1.10.0"],
    ),
    Defect(
        defect_id="CVE-2023-34035",
        title="Spring Security Authorization Bypass",
        description="Spring Security authorization rules can be bypassed in certain conditions.",
        severity="HIGH",
        cvss_score=8.1,
        cwe_id="CWE-863",
        published_date="2023-07-18",
        affected_versions=["spring-security-core:5.8.0", "spring-security-web:5.8.0"],
    ),
    Defect(
        defect_id="CVE-2023-20861",
        title="Spring Expression DoS",
        description="Spring Expression Language vulnerability can lead to denial of service.",
        severity="MEDIUM",
        cvss_score=6.5,
        cwe_id="CWE-400",
        published_date="2023-03-21",
        affected_versions=["spring-core:5.3.25", "spring-beans:5.3.25"],
    ),
    Defect(
        defect_id="CVE-2023-1370",
        title="json-smart Uncontrolled Recursion",
        description="Uncontrolled recursion in JSON parser leads to stack overflow.",
        severity="HIGH",
        cvss_score=7.5,
        cwe_id="CWE-674",
        published_date="2023-03-22",
        affected_versions=["gson:2.8.9"],
    ),
    Defect(
        defect_id="CVE-2022-45688",
        title="Snappy Java Buffer Overflow",
        description="Buffer overflow vulnerability in snappy-java compression library.",
        severity="HIGH",
        cvss_score=7.5,
        cwe_id="CWE-787",
        published_date="2022-12-14",
        affected_versions=["snappy-java:1.1.10.0", "snappy-java:1.1.10.4"],
    ),
    Defect(
        defect_id="CVE-2023-44487",
        title="HTTP/2 Rapid Reset Attack",
        description="HTTP/2 protocol allows denial of service via rapid stream resets.",
        severity="HIGH",
        cvss_score=7.5,
        cwe_id="CWE-400",
        published_date="2023-10-10",
        affected_versions=["netty-all:4.1.90.Final", "netty-handler:4.1.90.Final", "grpc-core:1.54.0", "grpc-netty:1.54.0"],
    ),
    Defect(
        defect_id="CVE-2023-2976",
        title="Guava Insecure Temp File Creation",
        description="Guava creates temporary files with insecure permissions.",
        severity="MEDIUM",
        cvss_score=5.5,
        cwe_id="CWE-732",
        published_date="2023-06-14",
        affected_versions=["guava:31.0-jre", "guava:31.1-jre"],
    ),
    Defect(
        defect_id="CVE-2022-25857",
        title="SnakeYAML DoS Vulnerability",
        description="SnakeYAML allows crafted YAML input to cause denial of service.",
        severity="HIGH",
        cvss_score=7.5,
        cwe_id="CWE-400",
        published_date="2022-08-30",
        affected_versions=["spring-boot:2.7.12"],
    ),
    Defect(
        defect_id="CVE-2023-33201",
        title="Bouncy Castle Certificate Validation",
        description="Bouncy Castle fails to properly validate certificates in certain cases.",
        severity="MEDIUM",
        cvss_score=5.3,
        cwe_id="CWE-295",
        published_date="2023-07-05",
        affected_versions=["bcprov-jdk18on:1.72", "bcpkix-jdk18on:1.72"],
    ),
    Defect(
        defect_id="CVE-2023-4586",
        title="PostgreSQL JDBC Injection",
        description="PostgreSQL JDBC driver vulnerable to SQL injection in certain configurations.",
        severity="HIGH",
        cvss_score=8.1,
        cwe_id="CWE-89",
        published_date="2023-08-10",
        affected_versions=["postgresql:42.5.0", "postgresql:42.5.4"],
    ),
    Defect(
        defect_id="CVE-2023-34462",
        title="Netty HTTP Header Smuggling",
        description="Netty allows HTTP request smuggling via malformed headers.",
        severity="MEDIUM",
        cvss_score=6.1,
        cwe_id="CWE-444",
        published_date="2023-06-22",
        affected_versions=["netty-all:4.1.90.Final", "netty-handler:4.1.90.Final"],
    ),
    Defect(
        defect_id="CVE-2022-41881",
        title="Jackson Databind Polymorphic Deserialization",
        description="Jackson Databind vulnerable to polymorphic deserialization attacks.",
        severity="HIGH",
        cvss_score=7.5,
        cwe_id="CWE-502",
        published_date="2022-11-11",
        affected_versions=["jackson-databind:2.13.0"],
    ),
    Defect(
        defect_id="CVE-2023-35116",
        title="Jackson Databind DoS",
        description="Jackson Databind denial of service via deeply nested objects.",
        severity="MEDIUM",
        cvss_score=5.9,
        cwe_id="CWE-400",
        published_date="2023-06-14",
        affected_versions=["jackson-databind:2.14.0", "jackson-databind:2.14.2"],
    ),
    Defect(
        defect_id="CVE-2023-52428",
        title="Jedis Connection Pool Leak",
        description="Jedis connection pool leak under certain error conditions.",
        severity="MEDIUM",
        cvss_score=5.3,
        cwe_id="CWE-404",
        published_date="2023-12-01",
        affected_versions=["jedis:4.3.0", "jedis:4.4.0"],
    ),
]


def create_versions() -> list[Version]:
    """Create all Version objects for the graph."""
    versions: list[Version] = []

    # Third-party libraries
    for group, name, vers in THIRD_PARTY_LIBS:
        for v in vers:
            versions.append(Version(
                project_group=group,
                project_name=name,
                name=v,
                is_internal=False,
                is_application=False,
                is_library=True,
            ))

    # Internal libraries (can also be applications if they have scans)
    scan_counter = 1000
    for group, name, vers in INTERNAL_LIBS:
        for v in vers:
            # Some internal libraries are also scanned as applications
            is_also_app = random.random() < 0.2  # 20% chance
            scan_id = None
            app_id = None
            public_id = None
            repo_url = None

            if is_also_app:
                scan_id = f"scan-{scan_counter:05d}"
                app_id = f"app-{uuid.uuid4().hex[:8]}"
                public_id = f"ACME-LIB-{name.upper().replace('-', '')[:8]}-{v.replace('.', '')}"
                repo_url = f"https://github.com/acme-corp/{name}.git"
                scan_counter += 1

            versions.append(Version(
                project_group=group,
                project_name=name,
                name=v,
                is_internal=True,
                is_application=is_also_app,
                is_library=True,
                scan_id=scan_id,
                app_id=app_id,
                public_id=public_id,
                repo_url=repo_url,
            ))

    # Applications
    for group, name, vers in APPLICATIONS:
        for v in vers:
            scan_id = f"scan-{scan_counter:05d}"
            app_id = f"app-{uuid.uuid4().hex[:8]}"
            public_id = f"ACME-{name.upper().replace('-', '')[:10]}-{v.replace('.', '')}"
            repo_url = f"https://github.com/acme-corp/{name}.git"
            scan_counter += 1

            versions.append(Version(
                project_group=group,
                project_name=name,
                name=v,
                is_internal=True,
                is_application=True,
                is_library=False,  # Pure applications are not libraries
                scan_id=scan_id,
                app_id=app_id,
                public_id=public_id,
                repo_url=repo_url,
            ))

    return versions


def define_dependencies() -> list[tuple[str, str, str, str, str, str]]:
    """Define dependency relationships.

    Returns list of (from_group, from_name, from_version, to_group, to_name, to_version) tuples.
    """
    deps: list[tuple[str, str, str, str, str, str]] = []

    # Helper to add dependency
    def add_dep(from_g, from_n, from_v, to_g, to_n, to_v):
        deps.append((from_g, from_n, from_v, to_g, to_n, to_v))

    # ==========================================================================
    # Third-party inter-dependencies
    # ==========================================================================

    # logback depends on slf4j
    add_dep("ch.qos.logback", "logback-classic", "1.2.9", "org.slf4j", "slf4j-api", "1.7.32")
    add_dep("ch.qos.logback", "logback-classic", "1.2.11", "org.slf4j", "slf4j-api", "1.7.36")
    add_dep("ch.qos.logback", "logback-classic", "1.4.5", "org.slf4j", "slf4j-api", "2.0.0")
    add_dep("ch.qos.logback", "logback-classic", "1.4.11", "org.slf4j", "slf4j-api", "2.0.9")
    add_dep("ch.qos.logback", "logback-classic", "1.4.14", "org.slf4j", "slf4j-api", "2.0.11")

    # log4j-core depends on log4j-api
    add_dep("org.apache.logging.log4j", "log4j-core", "2.17.0", "org.apache.logging.log4j", "log4j-api", "2.17.0")
    add_dep("org.apache.logging.log4j", "log4j-core", "2.17.1", "org.apache.logging.log4j", "log4j-api", "2.17.1")
    add_dep("org.apache.logging.log4j", "log4j-core", "2.19.0", "org.apache.logging.log4j", "log4j-api", "2.19.0")
    add_dep("org.apache.logging.log4j", "log4j-core", "2.20.0", "org.apache.logging.log4j", "log4j-api", "2.20.0")
    add_dep("org.apache.logging.log4j", "log4j-core", "2.21.0", "org.apache.logging.log4j", "log4j-api", "2.21.0")

    # jackson-databind depends on jackson-core and jackson-annotations
    for v in ["2.13.0", "2.14.0", "2.14.2", "2.15.2", "2.16.0", "2.16.1"]:
        add_dep("com.fasterxml.jackson.core", "jackson-databind", v, "com.fasterxml.jackson.core", "jackson-core", v)
        add_dep("com.fasterxml.jackson.core", "jackson-databind", v, "com.fasterxml.jackson.core", "jackson-annotations", v)

    # Spring dependencies
    for v in ["5.3.25", "5.3.30", "6.0.11", "6.1.0", "6.1.2"]:
        add_dep("org.springframework", "spring-beans", v, "org.springframework", "spring-core", v)
        add_dep("org.springframework", "spring-context", v, "org.springframework", "spring-beans", v)
        add_dep("org.springframework", "spring-context", v, "org.springframework", "spring-core", v)
        add_dep("org.springframework", "spring-web", v, "org.springframework", "spring-core", v)
        add_dep("org.springframework", "spring-web", v, "org.springframework", "spring-beans", v)
        add_dep("org.springframework", "spring-webmvc", v, "org.springframework", "spring-web", v)
        add_dep("org.springframework", "spring-webmvc", v, "org.springframework", "spring-context", v)

    # Spring Boot dependencies
    spring_boot_versions = {
        "2.7.12": "5.3.25", "2.7.15": "5.3.30",
        "3.1.5": "6.0.11", "3.2.0": "6.1.0", "3.2.1": "6.1.2"
    }
    for boot_v, spring_v in spring_boot_versions.items():
        add_dep("org.springframework.boot", "spring-boot", boot_v, "org.springframework", "spring-core", spring_v)
        add_dep("org.springframework.boot", "spring-boot", boot_v, "org.springframework", "spring-context", spring_v)
        add_dep("org.springframework.boot", "spring-boot-autoconfigure", boot_v, "org.springframework.boot", "spring-boot", boot_v)
        add_dep("org.springframework.boot", "spring-boot-starter-web", boot_v, "org.springframework.boot", "spring-boot-autoconfigure", boot_v)
        add_dep("org.springframework.boot", "spring-boot-starter-web", boot_v, "org.springframework", "spring-webmvc", spring_v)
        add_dep("org.springframework.boot", "spring-boot-starter-data-jpa", boot_v, "org.springframework.boot", "spring-boot-autoconfigure", boot_v)

    # Spring Security
    add_dep("org.springframework.security", "spring-security-web", "5.8.0", "org.springframework.security", "spring-security-core", "5.8.0")
    add_dep("org.springframework.security", "spring-security-web", "6.1.0", "org.springframework.security", "spring-security-core", "6.1.0")
    add_dep("org.springframework.security", "spring-security-web", "6.2.0", "org.springframework.security", "spring-security-core", "6.2.0")

    # java-jwt depends on jackson
    add_dep("com.auth0", "java-jwt", "4.0.0", "com.fasterxml.jackson.core", "jackson-databind", "2.13.0")
    add_dep("com.auth0", "java-jwt", "4.2.0", "com.fasterxml.jackson.core", "jackson-databind", "2.14.0")
    add_dep("com.auth0", "java-jwt", "4.3.0", "com.fasterxml.jackson.core", "jackson-databind", "2.15.2")
    add_dep("com.auth0", "java-jwt", "4.4.0", "com.fasterxml.jackson.core", "jackson-databind", "2.16.0")

    # gRPC dependencies
    for v in ["1.54.0", "1.58.0", "1.60.0"]:
        add_dep("io.grpc", "grpc-netty", v, "io.grpc", "grpc-core", v)
        add_dep("io.grpc", "grpc-protobuf", v, "io.grpc", "grpc-core", v)

    # AWS SDK dependencies
    for v in ["2.20.0", "2.21.0", "2.25.0"]:
        add_dep("software.amazon.awssdk", "s3", v, "software.amazon.awssdk", "aws-core", v)
        add_dep("software.amazon.awssdk", "sqs", v, "software.amazon.awssdk", "aws-core", v)
        add_dep("software.amazon.awssdk", "dynamodb", v, "software.amazon.awssdk", "aws-core", v)

    # Bouncy Castle
    for v in ["1.72", "1.74", "1.76", "1.77"]:
        add_dep("org.bouncycastle", "bcpkix-jdk18on", v, "org.bouncycastle", "bcprov-jdk18on", v)

    # JUnit
    for v in ["5.8.2", "5.9.0", "5.9.3", "5.10.0", "5.10.1"]:
        add_dep("org.junit.jupiter", "junit-jupiter", v, "org.junit.jupiter", "junit-jupiter-api", v)

    # ==========================================================================
    # LAYER 0: Foundation libraries - wrap third-party to ensure all have
    # incoming connections and add depth to the graph
    # ==========================================================================

    # acme-testing-core wraps junit, mockito, assertj
    add_dep("com.acme.foundation", "acme-testing-core", "1.0.0", "org.junit.jupiter", "junit-jupiter", "5.9.0")
    add_dep("com.acme.foundation", "acme-testing-core", "1.0.0", "org.junit.jupiter", "junit-jupiter-api", "5.9.0")
    add_dep("com.acme.foundation", "acme-testing-core", "1.0.0", "org.mockito", "mockito-core", "4.8.0")
    add_dep("com.acme.foundation", "acme-testing-core", "1.0.0", "org.assertj", "assertj-core", "3.23.0")
    add_dep("com.acme.foundation", "acme-testing-core", "1.1.0", "org.junit.jupiter", "junit-jupiter", "5.9.3")
    add_dep("com.acme.foundation", "acme-testing-core", "1.1.0", "org.junit.jupiter", "junit-jupiter-api", "5.9.3")
    add_dep("com.acme.foundation", "acme-testing-core", "1.1.0", "org.mockito", "mockito-core", "5.3.0")
    add_dep("com.acme.foundation", "acme-testing-core", "1.1.0", "org.assertj", "assertj-core", "3.24.0")
    add_dep("com.acme.foundation", "acme-testing-core", "2.0.0", "org.junit.jupiter", "junit-jupiter", "5.10.1")
    add_dep("com.acme.foundation", "acme-testing-core", "2.0.0", "org.junit.jupiter", "junit-jupiter-api", "5.10.1")
    add_dep("com.acme.foundation", "acme-testing-core", "2.0.0", "org.mockito", "mockito-core", "5.7.0")
    add_dep("com.acme.foundation", "acme-testing-core", "2.0.0", "org.assertj", "assertj-core", "3.25.0")

    # acme-validation-core wraps hibernate-validator, jakarta.validation
    add_dep("com.acme.foundation", "acme-validation-core", "1.0.0", "org.hibernate.validator", "hibernate-validator", "8.0.0.Final")
    add_dep("com.acme.foundation", "acme-validation-core", "1.0.0", "jakarta.validation", "jakarta.validation-api", "3.0.0")
    add_dep("com.acme.foundation", "acme-validation-core", "1.1.0", "org.hibernate.validator", "hibernate-validator", "8.0.1.Final")
    add_dep("com.acme.foundation", "acme-validation-core", "1.1.0", "jakarta.validation", "jakarta.validation-api", "3.0.2")

    # acme-serialization-core wraps kryo, snappy-java, gson
    add_dep("com.acme.foundation", "acme-serialization-core", "1.0.0", "com.esotericsoftware", "kryo", "5.4.0")
    add_dep("com.acme.foundation", "acme-serialization-core", "1.0.0", "org.xerial.snappy", "snappy-java", "1.1.10.0")
    add_dep("com.acme.foundation", "acme-serialization-core", "1.0.0", "com.google.code.gson", "gson", "2.9.1")
    add_dep("com.acme.foundation", "acme-serialization-core", "1.1.0", "com.esotericsoftware", "kryo", "5.5.0")
    add_dep("com.acme.foundation", "acme-serialization-core", "1.1.0", "org.xerial.snappy", "snappy-java", "1.1.10.4")
    add_dep("com.acme.foundation", "acme-serialization-core", "1.1.0", "com.google.code.gson", "gson", "2.10.0")
    add_dep("com.acme.foundation", "acme-serialization-core", "2.0.0", "com.esotericsoftware", "kryo", "5.5.0")
    add_dep("com.acme.foundation", "acme-serialization-core", "2.0.0", "org.xerial.snappy", "snappy-java", "1.1.10.5")
    add_dep("com.acme.foundation", "acme-serialization-core", "2.0.0", "com.google.code.gson", "gson", "2.10.1")

    # acme-http-core wraps httpclient variants and okhttp
    add_dep("com.acme.foundation", "acme-http-core", "1.0.0", "org.apache.httpcomponents", "httpclient", "4.5.13")
    add_dep("com.acme.foundation", "acme-http-core", "1.0.0", "com.squareup.okhttp3", "okhttp", "4.9.3")
    add_dep("com.acme.foundation", "acme-http-core", "1.1.0", "org.apache.httpcomponents", "httpclient", "4.5.14")
    add_dep("com.acme.foundation", "acme-http-core", "1.1.0", "org.apache.httpcomponents.client5", "httpclient5", "5.2.0")
    add_dep("com.acme.foundation", "acme-http-core", "1.1.0", "com.squareup.okhttp3", "okhttp", "4.10.0")
    add_dep("com.acme.foundation", "acme-http-core", "2.0.0", "org.apache.httpcomponents.client5", "httpclient5", "5.3.0")
    add_dep("com.acme.foundation", "acme-http-core", "2.0.0", "com.squareup.okhttp3", "okhttp", "4.12.0")

    # acme-monitoring-core wraps prometheus and additional micrometer
    add_dep("com.acme.foundation", "acme-monitoring-core", "1.0.0", "io.prometheus", "simpleclient", "0.16.0")
    add_dep("com.acme.foundation", "acme-monitoring-core", "1.0.0", "io.micrometer", "micrometer-core", "1.10.0")
    add_dep("com.acme.foundation", "acme-monitoring-core", "1.1.0", "io.prometheus", "simpleclient", "0.16.0")
    add_dep("com.acme.foundation", "acme-monitoring-core", "1.1.0", "io.micrometer", "micrometer-core", "1.12.0")

    # acme-netty-core wraps netty
    add_dep("com.acme.foundation", "acme-netty-core", "1.0.0", "io.netty", "netty-all", "4.1.90.Final")
    add_dep("com.acme.foundation", "acme-netty-core", "1.0.0", "io.netty", "netty-handler", "4.1.90.Final")
    add_dep("com.acme.foundation", "acme-netty-core", "1.1.0", "io.netty", "netty-all", "4.1.104.Final")
    add_dep("com.acme.foundation", "acme-netty-core", "1.1.0", "io.netty", "netty-handler", "4.1.104.Final")

    # acme-spring-core wraps spring framework core components
    add_dep("com.acme.foundation", "acme-spring-core", "1.0.0", "org.springframework", "spring-core", "5.3.25")
    add_dep("com.acme.foundation", "acme-spring-core", "1.0.0", "org.springframework", "spring-beans", "5.3.25")
    add_dep("com.acme.foundation", "acme-spring-core", "1.0.0", "org.springframework", "spring-context", "5.3.25")
    add_dep("com.acme.foundation", "acme-spring-core", "1.1.0", "org.springframework", "spring-core", "6.0.11")
    add_dep("com.acme.foundation", "acme-spring-core", "1.1.0", "org.springframework", "spring-beans", "6.0.11")
    add_dep("com.acme.foundation", "acme-spring-core", "1.1.0", "org.springframework", "spring-context", "6.0.11")
    add_dep("com.acme.foundation", "acme-spring-core", "2.0.0", "org.springframework", "spring-core", "6.1.2")
    add_dep("com.acme.foundation", "acme-spring-core", "2.0.0", "org.springframework", "spring-beans", "6.1.2")
    add_dep("com.acme.foundation", "acme-spring-core", "2.0.0", "org.springframework", "spring-context", "6.1.2")

    # acme-collections wraps commons-collections, commons-text, commons-codec
    add_dep("com.acme.foundation", "acme-collections", "1.0.0", "org.apache.commons", "commons-collections4", "4.4")
    add_dep("com.acme.foundation", "acme-collections", "1.0.0", "org.apache.commons", "commons-text", "1.10.0")
    add_dep("com.acme.foundation", "acme-collections", "1.0.0", "commons-codec", "commons-codec", "1.15")
    add_dep("com.acme.foundation", "acme-collections", "1.1.0", "org.apache.commons", "commons-collections4", "4.4")
    add_dep("com.acme.foundation", "acme-collections", "1.1.0", "org.apache.commons", "commons-text", "1.11.0")
    add_dep("com.acme.foundation", "acme-collections", "1.1.0", "commons-codec", "commons-codec", "1.16.0")

    # acme-nosql-core wraps MongoDB and DynamoDB
    add_dep("com.acme.foundation", "acme-nosql-core", "1.0.0", "org.mongodb", "mongodb-driver-sync", "4.9.0")
    add_dep("com.acme.foundation", "acme-nosql-core", "1.0.0", "software.amazon.awssdk", "dynamodb", "2.20.0")
    add_dep("com.acme.foundation", "acme-nosql-core", "1.1.0", "org.mongodb", "mongodb-driver-sync", "4.11.0")
    add_dep("com.acme.foundation", "acme-nosql-core", "1.1.0", "software.amazon.awssdk", "dynamodb", "2.25.0")

    # acme-mysql-core wraps MySQL
    add_dep("com.acme.foundation", "acme-mysql-core", "1.0.0", "mysql", "mysql-connector-java", "8.0.33")

    # ==========================================================================
    # Layer 0 -> Layer 1 connections (foundation -> core)
    # ==========================================================================

    # acme-common now depends on acme-collections for extended utilities
    add_dep("com.acme.core", "acme-common", "1.0.0", "com.acme.foundation", "acme-collections", "1.0.0")
    add_dep("com.acme.core", "acme-common", "1.1.0", "com.acme.foundation", "acme-collections", "1.0.0")
    add_dep("com.acme.core", "acme-common", "1.2.0", "com.acme.foundation", "acme-collections", "1.1.0")
    add_dep("com.acme.core", "acme-common", "2.0.0", "com.acme.foundation", "acme-collections", "1.1.0")
    add_dep("com.acme.core", "acme-common", "2.1.0", "com.acme.foundation", "acme-collections", "1.1.0")

    # acme-config depends on acme-validation-core for config validation
    add_dep("com.acme.core", "acme-config", "1.0.0", "com.acme.foundation", "acme-validation-core", "1.0.0")
    add_dep("com.acme.core", "acme-config", "1.1.0", "com.acme.foundation", "acme-validation-core", "1.0.0")
    add_dep("com.acme.core", "acme-config", "1.2.0", "com.acme.foundation", "acme-validation-core", "1.1.0")
    add_dep("com.acme.core", "acme-config", "2.0.0", "com.acme.foundation", "acme-validation-core", "1.1.0")

    # acme-utils depends on acme-serialization-core
    add_dep("com.acme.core", "acme-utils", "1.0.0", "com.acme.foundation", "acme-serialization-core", "1.0.0")
    add_dep("com.acme.core", "acme-utils", "1.1.0", "com.acme.foundation", "acme-serialization-core", "1.1.0")
    add_dep("com.acme.core", "acme-utils", "1.2.0", "com.acme.foundation", "acme-serialization-core", "2.0.0")

    # acme-metrics depends on acme-monitoring-core
    add_dep("com.acme.core", "acme-metrics", "1.0.0", "com.acme.foundation", "acme-monitoring-core", "1.0.0")
    add_dep("com.acme.core", "acme-metrics", "1.1.0", "com.acme.foundation", "acme-monitoring-core", "1.1.0")

    # ==========================================================================
    # Internal library dependencies on third-party
    # ==========================================================================

    # acme-logging
    add_dep("com.acme.core", "acme-logging", "1.0.0", "org.slf4j", "slf4j-api", "1.7.36")
    add_dep("com.acme.core", "acme-logging", "1.0.0", "ch.qos.logback", "logback-classic", "1.2.11")
    add_dep("com.acme.core", "acme-logging", "1.1.0", "org.slf4j", "slf4j-api", "2.0.7")
    add_dep("com.acme.core", "acme-logging", "1.1.0", "ch.qos.logback", "logback-classic", "1.4.5")
    add_dep("com.acme.core", "acme-logging", "1.2.0", "org.slf4j", "slf4j-api", "2.0.11")
    add_dep("com.acme.core", "acme-logging", "1.2.0", "ch.qos.logback", "logback-classic", "1.4.14")

    # acme-common
    add_dep("com.acme.core", "acme-common", "1.0.0", "com.google.guava", "guava", "31.1-jre")
    add_dep("com.acme.core", "acme-common", "1.0.0", "org.apache.commons", "commons-lang3", "3.12.0")
    add_dep("com.acme.core", "acme-common", "1.1.0", "com.google.guava", "guava", "32.0.0-jre")
    add_dep("com.acme.core", "acme-common", "1.1.0", "org.apache.commons", "commons-lang3", "3.13.0")
    add_dep("com.acme.core", "acme-common", "1.1.0", "com.acme.core", "acme-logging", "1.0.0")
    add_dep("com.acme.core", "acme-common", "1.2.0", "com.google.guava", "guava", "32.1.2-jre")
    add_dep("com.acme.core", "acme-common", "1.2.0", "org.apache.commons", "commons-lang3", "3.13.0")
    add_dep("com.acme.core", "acme-common", "1.2.0", "com.acme.core", "acme-logging", "1.1.0")
    add_dep("com.acme.core", "acme-common", "2.0.0", "com.google.guava", "guava", "33.0.0-jre")
    add_dep("com.acme.core", "acme-common", "2.0.0", "org.apache.commons", "commons-lang3", "3.14.0")
    add_dep("com.acme.core", "acme-common", "2.0.0", "com.acme.core", "acme-logging", "1.2.0")
    add_dep("com.acme.core", "acme-common", "2.1.0", "com.google.guava", "guava", "33.0.0-jre")
    add_dep("com.acme.core", "acme-common", "2.1.0", "org.apache.commons", "commons-lang3", "3.14.0")
    add_dep("com.acme.core", "acme-common", "2.1.0", "com.acme.core", "acme-logging", "1.2.0")

    # acme-config
    add_dep("com.acme.core", "acme-config", "1.0.0", "com.acme.core", "acme-common", "1.0.0")
    add_dep("com.acme.core", "acme-config", "1.0.0", "com.fasterxml.jackson.core", "jackson-databind", "2.14.0")
    add_dep("com.acme.core", "acme-config", "1.1.0", "com.acme.core", "acme-common", "1.1.0")
    add_dep("com.acme.core", "acme-config", "1.1.0", "com.fasterxml.jackson.core", "jackson-databind", "2.15.2")
    add_dep("com.acme.core", "acme-config", "1.2.0", "com.acme.core", "acme-common", "1.2.0")
    add_dep("com.acme.core", "acme-config", "1.2.0", "com.fasterxml.jackson.core", "jackson-databind", "2.16.0")
    add_dep("com.acme.core", "acme-config", "2.0.0", "com.acme.core", "acme-common", "2.0.0")
    add_dep("com.acme.core", "acme-config", "2.0.0", "com.fasterxml.jackson.core", "jackson-databind", "2.16.1")

    # acme-utils
    add_dep("com.acme.core", "acme-utils", "1.0.0", "com.acme.core", "acme-common", "1.0.0")
    add_dep("com.acme.core", "acme-utils", "1.0.0", "commons-io", "commons-io", "2.11.0")
    add_dep("com.acme.core", "acme-utils", "1.1.0", "com.acme.core", "acme-common", "1.1.0")
    add_dep("com.acme.core", "acme-utils", "1.1.0", "commons-io", "commons-io", "2.13.0")
    add_dep("com.acme.core", "acme-utils", "1.2.0", "com.acme.core", "acme-common", "2.0.0")
    add_dep("com.acme.core", "acme-utils", "1.2.0", "commons-io", "commons-io", "2.15.1")

    # acme-metrics
    add_dep("com.acme.core", "acme-metrics", "1.0.0", "io.micrometer", "micrometer-core", "1.10.0")
    add_dep("com.acme.core", "acme-metrics", "1.0.0", "com.acme.core", "acme-common", "1.1.0")
    add_dep("com.acme.core", "acme-metrics", "1.0.0", "com.acme.core", "acme-logging", "1.0.0")
    add_dep("com.acme.core", "acme-metrics", "1.1.0", "io.micrometer", "micrometer-core", "1.12.0")
    add_dep("com.acme.core", "acme-metrics", "1.1.0", "com.acme.core", "acme-common", "2.0.0")
    add_dep("com.acme.core", "acme-metrics", "1.1.0", "com.acme.core", "acme-logging", "1.2.0")  # Pinned for metric format compat

    # acme-crypto
    add_dep("com.acme.security", "acme-crypto", "1.0.0", "org.bouncycastle", "bcprov-jdk18on", "1.72")
    add_dep("com.acme.security", "acme-crypto", "1.0.0", "com.acme.core", "acme-common", "1.0.0")
    add_dep("com.acme.security", "acme-crypto", "1.1.0", "org.bouncycastle", "bcprov-jdk18on", "1.76")
    add_dep("com.acme.security", "acme-crypto", "1.1.0", "com.acme.core", "acme-common", "1.1.0")
    add_dep("com.acme.security", "acme-crypto", "1.2.0", "org.bouncycastle", "bcprov-jdk18on", "1.77")
    add_dep("com.acme.security", "acme-crypto", "1.2.0", "com.acme.core", "acme-common", "2.0.0")

    # acme-jwt (supports both java-jwt and jjwt libraries)
    add_dep("com.acme.security", "acme-jwt", "1.0.0", "com.auth0", "java-jwt", "4.2.0")
    add_dep("com.acme.security", "acme-jwt", "1.0.0", "io.jsonwebtoken", "jjwt-api", "0.11.5")  # Alternative JWT lib
    add_dep("com.acme.security", "acme-jwt", "1.0.0", "com.acme.security", "acme-crypto", "1.0.0")
    add_dep("com.acme.security", "acme-jwt", "1.0.1", "com.auth0", "java-jwt", "4.3.0")
    add_dep("com.acme.security", "acme-jwt", "1.0.1", "io.jsonwebtoken", "jjwt-api", "0.12.0")  # Alternative JWT lib
    add_dep("com.acme.security", "acme-jwt", "1.0.1", "com.acme.security", "acme-crypto", "1.1.0")
    add_dep("com.acme.security", "acme-jwt", "1.1.0", "com.auth0", "java-jwt", "4.4.0")
    add_dep("com.acme.security", "acme-jwt", "1.1.0", "io.jsonwebtoken", "jjwt-api", "0.12.3")  # Alternative JWT lib
    add_dep("com.acme.security", "acme-jwt", "1.1.0", "com.acme.security", "acme-crypto", "1.2.0")

    # acme-auth
    add_dep("com.acme.security", "acme-auth", "1.0.0", "com.acme.core", "acme-config", "1.0.0")
    add_dep("com.acme.security", "acme-auth", "1.1.0", "com.acme.security", "acme-jwt", "1.0.0")
    add_dep("com.acme.security", "acme-auth", "1.1.0", "com.acme.core", "acme-config", "1.1.0")
    add_dep("com.acme.security", "acme-auth", "2.0.0", "com.acme.security", "acme-jwt", "1.0.1")
    add_dep("com.acme.security", "acme-auth", "2.0.0", "com.acme.core", "acme-config", "1.2.0")
    add_dep("com.acme.security", "acme-auth", "2.1.0", "com.acme.security", "acme-jwt", "1.0.1")
    add_dep("com.acme.security", "acme-auth", "2.1.0", "com.acme.core", "acme-config", "2.0.0")
    add_dep("com.acme.security", "acme-auth", "3.0.0", "com.acme.security", "acme-jwt", "1.1.0")
    add_dep("com.acme.security", "acme-auth", "3.0.0", "com.acme.core", "acme-config", "2.0.0")
    add_dep("com.acme.security", "acme-auth", "3.0.0", "org.springframework.security", "spring-security-core", "6.2.0")
    add_dep("com.acme.security", "acme-auth", "3.0.0", "com.acme.core", "acme-logging", "2.0.0-SNAPSHOT")  # Uses latest logging

    # acme-oauth
    add_dep("com.acme.security", "acme-oauth", "1.0.0", "com.acme.security", "acme-auth", "2.0.0")
    add_dep("com.acme.security", "acme-oauth", "1.1.0", "com.acme.security", "acme-auth", "3.0.0")

    # acme-rbac
    add_dep("com.acme.security", "acme-rbac", "1.0.0", "com.acme.security", "acme-auth", "2.0.0")
    add_dep("com.acme.security", "acme-rbac", "1.0.0", "com.acme.data", "acme-models", "2.0.0")
    add_dep("com.acme.security", "acme-rbac", "1.1.0", "com.acme.security", "acme-auth", "3.0.0")
    add_dep("com.acme.security", "acme-rbac", "1.1.0", "com.acme.data", "acme-models", "4.0.0")

    # acme-db-common (uses foundation layers for additional DB support and depth)
    add_dep("com.acme.data", "acme-db-common", "1.0.0", "org.postgresql", "postgresql", "42.5.0")
    add_dep("com.acme.data", "acme-db-common", "1.0.0", "com.zaxxer", "HikariCP", "5.0.0")
    add_dep("com.acme.data", "acme-db-common", "1.0.0", "com.acme.core", "acme-config", "1.0.0")
    add_dep("com.acme.data", "acme-db-common", "1.1.0", "org.postgresql", "postgresql", "42.6.0")
    add_dep("com.acme.data", "acme-db-common", "1.1.0", "com.zaxxer", "HikariCP", "5.0.1")
    add_dep("com.acme.data", "acme-db-common", "1.1.0", "com.acme.core", "acme-config", "1.1.0")
    add_dep("com.acme.data", "acme-db-common", "1.1.0", "com.acme.foundation", "acme-mysql-core", "1.0.0")  # MySQL support added
    add_dep("com.acme.data", "acme-db-common", "2.0.0", "org.postgresql", "postgresql", "42.7.0")
    add_dep("com.acme.data", "acme-db-common", "2.0.0", "com.zaxxer", "HikariCP", "5.1.0")
    add_dep("com.acme.data", "acme-db-common", "2.0.0", "com.acme.core", "acme-config", "1.2.0")
    add_dep("com.acme.data", "acme-db-common", "2.0.0", "com.acme.foundation", "acme-mysql-core", "1.0.0")
    add_dep("com.acme.data", "acme-db-common", "2.0.0", "com.acme.foundation", "acme-nosql-core", "1.0.0")  # NoSQL support added
    add_dep("com.acme.data", "acme-db-common", "2.1.0", "org.postgresql", "postgresql", "42.7.1")
    add_dep("com.acme.data", "acme-db-common", "2.1.0", "com.zaxxer", "HikariCP", "5.1.0")
    add_dep("com.acme.data", "acme-db-common", "2.1.0", "com.acme.core", "acme-config", "2.0.0")
    add_dep("com.acme.data", "acme-db-common", "2.1.0", "com.acme.foundation", "acme-mysql-core", "1.0.0")
    add_dep("com.acme.data", "acme-db-common", "2.1.0", "com.acme.foundation", "acme-nosql-core", "1.1.0")
    add_dep("com.acme.data", "acme-db-common", "2.1.0", "com.acme.data", "acme-connection-pool", "1.1.0")  # Pinned older version!

    # acme-data-pipeline 2.0.0 - MULTI-VERSION-SOURCES DEMO #2
    # This version creates a diamond dependency on acme-connection-pool:
    #   acme-data-pipeline 2.0.0 -> acme-db-common 2.1.0 -> acme-connection-pool 1.1.0 (pinned)
    #   acme-data-pipeline 2.0.0 -> acme-cache 1.1.0 -> acme-connection-pool 2.0.0 (uses latest)
    # Query: /reports/multi-version-sources?project_name=acme-data-pipeline&version_name=2.0.0
    add_dep("com.acme.data", "acme-data-pipeline", "1.0.0", "com.acme.data", "acme-db-common", "2.0.0")
    add_dep("com.acme.data", "acme-data-pipeline", "1.0.0", "com.acme.data", "acme-cache", "1.0.1")
    add_dep("com.acme.data", "acme-data-pipeline", "1.0.0", "com.acme.messaging", "acme-kafka", "1.1.0")
    add_dep("com.acme.data", "acme-data-pipeline", "2.0.0", "com.acme.data", "acme-db-common", "2.1.0")  # Has conn-pool 1.1.0
    add_dep("com.acme.data", "acme-data-pipeline", "2.0.0", "com.acme.data", "acme-cache", "1.1.0")  # Has conn-pool 2.0.0
    add_dep("com.acme.data", "acme-data-pipeline", "2.0.0", "com.acme.messaging", "acme-kafka", "2.0.0")

    # acme-cache
    add_dep("com.acme.data", "acme-cache", "1.0.0", "redis.clients", "jedis", "4.4.0")
    add_dep("com.acme.data", "acme-cache", "1.0.0", "com.acme.core", "acme-config", "1.0.0")
    add_dep("com.acme.data", "acme-cache", "1.0.1", "redis.clients", "jedis", "4.4.3")
    add_dep("com.acme.data", "acme-cache", "1.0.1", "com.acme.core", "acme-config", "1.1.0")
    add_dep("com.acme.data", "acme-cache", "1.1.0", "redis.clients", "jedis", "5.1.0")
    add_dep("com.acme.data", "acme-cache", "1.1.0", "com.acme.core", "acme-config", "2.0.0")
    add_dep("com.acme.data", "acme-cache", "1.1.0", "com.acme.data", "acme-connection-pool", "2.0.0")  # Uses latest

    # acme-connection-pool - used in MULTI-VERSION-SOURCES DEMO #2
    add_dep("com.acme.data", "acme-connection-pool", "1.0.0", "com.zaxxer", "HikariCP", "5.0.1")
    add_dep("com.acme.data", "acme-connection-pool", "1.0.0", "com.acme.core", "acme-config", "1.0.0")
    add_dep("com.acme.data", "acme-connection-pool", "1.1.0", "com.zaxxer", "HikariCP", "5.0.1")
    add_dep("com.acme.data", "acme-connection-pool", "1.1.0", "com.acme.core", "acme-config", "1.1.0")
    add_dep("com.acme.data", "acme-connection-pool", "2.0.0", "com.zaxxer", "HikariCP", "5.1.0")
    add_dep("com.acme.data", "acme-connection-pool", "2.0.0", "com.acme.core", "acme-config", "2.0.0")

    # acme-db-common 2.1.0 uses older connection-pool for stability
    # (This creates part of diamond in acme-data-pipeline 2.0.0)

    # acme-models
    add_dep("com.acme.data", "acme-models", "1.0.0", "com.fasterxml.jackson.core", "jackson-databind", "2.14.0")
    add_dep("com.acme.data", "acme-models", "1.0.0", "com.acme.core", "acme-common", "1.0.0")
    add_dep("com.acme.data", "acme-models", "2.0.0", "com.fasterxml.jackson.core", "jackson-databind", "2.15.2")
    add_dep("com.acme.data", "acme-models", "2.0.0", "com.acme.core", "acme-common", "1.1.0")
    add_dep("com.acme.data", "acme-models", "3.0.0", "com.fasterxml.jackson.core", "jackson-databind", "2.16.0")
    add_dep("com.acme.data", "acme-models", "3.0.0", "com.acme.core", "acme-common", "2.0.0")
    add_dep("com.acme.data", "acme-models", "4.0.0", "com.fasterxml.jackson.core", "jackson-databind", "2.16.1")
    add_dep("com.acme.data", "acme-models", "4.0.0", "com.acme.core", "acme-common", "2.1.0")

    # acme-repository
    add_dep("com.acme.data", "acme-repository", "1.0.0", "com.acme.data", "acme-db-common", "1.0.0")
    add_dep("com.acme.data", "acme-repository", "1.0.0", "com.acme.data", "acme-models", "1.0.0")
    add_dep("com.acme.data", "acme-repository", "1.1.0", "com.acme.data", "acme-db-common", "1.1.0")
    add_dep("com.acme.data", "acme-repository", "1.1.0", "com.acme.data", "acme-models", "2.0.0")
    add_dep("com.acme.data", "acme-repository", "2.0.0", "com.acme.data", "acme-db-common", "2.0.0")
    add_dep("com.acme.data", "acme-repository", "2.0.0", "com.acme.data", "acme-models", "3.0.0")

    # acme-migration
    add_dep("com.acme.data", "acme-migration", "1.0.0", "com.acme.data", "acme-db-common", "1.0.0")
    add_dep("com.acme.data", "acme-migration", "1.1.0", "com.acme.data", "acme-db-common", "2.0.0")

    # acme-events
    add_dep("com.acme.messaging", "acme-events", "1.0.0", "com.acme.data", "acme-models", "2.0.0")
    add_dep("com.acme.messaging", "acme-events", "1.0.0", "com.acme.core", "acme-common", "1.1.0")
    add_dep("com.acme.messaging", "acme-events", "1.1.0", "com.acme.data", "acme-models", "3.0.0")
    add_dep("com.acme.messaging", "acme-events", "1.1.0", "com.acme.core", "acme-common", "2.0.0")
    add_dep("com.acme.messaging", "acme-events", "2.0.0", "com.acme.data", "acme-models", "4.0.0")
    add_dep("com.acme.messaging", "acme-events", "2.0.0", "com.acme.core", "acme-common", "2.1.0")

    # acme-kafka
    add_dep("com.acme.messaging", "acme-kafka", "1.0.0", "org.apache.kafka", "kafka-clients", "3.4.0")
    add_dep("com.acme.messaging", "acme-kafka", "1.0.0", "com.acme.messaging", "acme-events", "1.0.0")
    add_dep("com.acme.messaging", "acme-kafka", "1.0.0", "com.acme.core", "acme-config", "1.0.0")
    add_dep("com.acme.messaging", "acme-kafka", "1.1.0", "org.apache.kafka", "kafka-clients", "3.5.0")
    add_dep("com.acme.messaging", "acme-kafka", "1.1.0", "com.acme.messaging", "acme-events", "1.1.0")
    add_dep("com.acme.messaging", "acme-kafka", "1.1.0", "com.acme.core", "acme-config", "1.2.0")
    # acme-kafka 2.0.0 - MULTI-VERSION-SOURCES DEMO #1
    # This version creates a diamond dependency on acme-events:
    #   acme-kafka 2.0.0 -> acme-serialization 2.0.0 -> acme-events 1.1.0 (pinned for stability)
    #   acme-kafka 2.0.0 -> acme-schema-registry 2.0.0 -> acme-events 2.0.0 (uses latest)
    # Query: /reports/multi-version-sources?project_name=acme-kafka&version_name=2.0.0
    add_dep("com.acme.messaging", "acme-kafka", "2.0.0", "org.apache.kafka", "kafka-clients", "3.6.0")
    add_dep("com.acme.messaging", "acme-kafka", "2.0.0", "com.acme.core", "acme-config", "2.0.0")
    add_dep("com.acme.messaging", "acme-kafka", "2.0.0", "com.acme.messaging", "acme-serialization", "2.0.0")
    add_dep("com.acme.messaging", "acme-kafka", "2.0.0", "com.acme.messaging", "acme-schema-registry", "2.0.0")

    # ==========================================================================
    # MULTI-VERSION-SOURCES DEMO LIBRARIES
    # These create diamond dependency scenarios for the multi-version-sources report
    # ==========================================================================

    # acme-serialization: Uses foundation serialization-core, pins acme-events for stability
    add_dep("com.acme.messaging", "acme-serialization", "1.0.0", "com.acme.foundation", "acme-serialization-core", "1.0.0")
    add_dep("com.acme.messaging", "acme-serialization", "1.0.0", "com.acme.messaging", "acme-events", "1.0.0")
    add_dep("com.acme.messaging", "acme-serialization", "2.0.0", "com.acme.foundation", "acme-serialization-core", "2.0.0")
    add_dep("com.acme.messaging", "acme-serialization", "2.0.0", "com.acme.messaging", "acme-events", "1.1.0")  # Pinned old version!
    add_dep("com.acme.messaging", "acme-serialization", "2.0.0", "com.acme.core", "acme-common", "2.0.0")

    # acme-schema-registry: Uses latest acme-events for new schema features
    add_dep("com.acme.messaging", "acme-schema-registry", "1.0.0", "com.acme.messaging", "acme-events", "1.1.0")
    add_dep("com.acme.messaging", "acme-schema-registry", "1.0.0", "com.acme.data", "acme-cache", "1.0.0")
    add_dep("com.acme.messaging", "acme-schema-registry", "2.0.0", "com.acme.messaging", "acme-events", "2.0.0")  # Uses latest!
    add_dep("com.acme.messaging", "acme-schema-registry", "2.0.0", "com.acme.data", "acme-cache", "1.1.0")
    add_dep("com.acme.messaging", "acme-schema-registry", "2.0.0", "com.acme.core", "acme-common", "2.1.0")

    # acme-sqs (depends on aws-common for cloud connectivity)
    add_dep("com.acme.messaging", "acme-sqs", "1.0.0", "com.acme.cloud", "acme-aws-common", "1.0.0")
    add_dep("com.acme.messaging", "acme-sqs", "1.0.0", "software.amazon.awssdk", "sqs", "2.20.0")
    add_dep("com.acme.messaging", "acme-sqs", "1.0.0", "com.acme.messaging", "acme-events", "1.0.0")
    add_dep("com.acme.messaging", "acme-sqs", "1.1.0", "com.acme.cloud", "acme-aws-common", "1.1.0")
    add_dep("com.acme.messaging", "acme-sqs", "1.1.0", "software.amazon.awssdk", "sqs", "2.25.0")
    add_dep("com.acme.messaging", "acme-sqs", "1.1.0", "com.acme.messaging", "acme-events", "2.0.0")

    # acme-pubsub (Google Cloud Pub/Sub adapter using http-core)
    add_dep("com.acme.messaging", "acme-pubsub", "1.0.0", "com.acme.foundation", "acme-http-core", "2.0.0")
    add_dep("com.acme.messaging", "acme-pubsub", "1.0.0", "com.acme.messaging", "acme-events", "2.0.0")
    add_dep("com.acme.messaging", "acme-pubsub", "1.0.0", "com.acme.core", "acme-config", "2.0.0")

    # acme-rest-client (depends on foundation http-core for HTTP abstraction)
    add_dep("com.acme.http", "acme-rest-client", "1.0.0", "com.acme.foundation", "acme-http-core", "1.0.0")
    add_dep("com.acme.http", "acme-rest-client", "1.0.0", "com.fasterxml.jackson.core", "jackson-databind", "2.14.0")
    add_dep("com.acme.http", "acme-rest-client", "1.0.0", "com.acme.core", "acme-config", "1.0.0")
    add_dep("com.acme.http", "acme-rest-client", "1.1.0", "com.acme.foundation", "acme-http-core", "1.1.0")
    add_dep("com.acme.http", "acme-rest-client", "1.1.0", "com.fasterxml.jackson.core", "jackson-databind", "2.15.2")
    add_dep("com.acme.http", "acme-rest-client", "1.1.0", "com.acme.core", "acme-config", "1.1.0")
    add_dep("com.acme.http", "acme-rest-client", "2.0.0", "com.acme.foundation", "acme-http-core", "2.0.0")
    add_dep("com.acme.http", "acme-rest-client", "2.0.0", "com.fasterxml.jackson.core", "jackson-databind", "2.16.0")
    add_dep("com.acme.http", "acme-rest-client", "2.0.0", "com.acme.core", "acme-config", "1.2.0")
    add_dep("com.acme.http", "acme-rest-client", "2.1.0", "com.acme.foundation", "acme-http-core", "2.0.0")
    add_dep("com.acme.http", "acme-rest-client", "2.1.0", "com.fasterxml.jackson.core", "jackson-databind", "2.16.1")
    add_dep("com.acme.http", "acme-rest-client", "2.1.0", "com.acme.core", "acme-config", "2.0.0")

    # acme-web-common (depends on spring-core for foundational Spring support)
    add_dep("com.acme.http", "acme-web-common", "1.0.0", "com.acme.foundation", "acme-spring-core", "1.0.0")
    add_dep("com.acme.http", "acme-web-common", "1.0.0", "org.springframework.boot", "spring-boot-starter-web", "2.7.15")
    add_dep("com.acme.http", "acme-web-common", "1.0.0", "com.acme.security", "acme-auth", "1.1.0")
    add_dep("com.acme.http", "acme-web-common", "1.0.0", "com.acme.core", "acme-metrics", "1.0.0")
    add_dep("com.acme.http", "acme-web-common", "1.1.0", "com.acme.foundation", "acme-spring-core", "1.1.0")
    add_dep("com.acme.http", "acme-web-common", "1.1.0", "org.springframework.boot", "spring-boot-starter-web", "3.1.5")
    add_dep("com.acme.http", "acme-web-common", "1.1.0", "com.acme.security", "acme-auth", "2.1.0")
    add_dep("com.acme.http", "acme-web-common", "1.1.0", "com.acme.core", "acme-metrics", "1.1.0")
    # acme-web-common 2.0.0 - MULTI-VERSION-SOURCES DEMO #3
    # This version creates a diamond dependency on acme-logging:
    #   acme-web-common 2.0.0 -> acme-auth 3.0.0 -> acme-logging 2.0.0-SNAPSHOT (uses latest)
    #   acme-web-common 2.0.0 -> acme-metrics 1.1.0 -> acme-logging 1.2.0 (pinned for format compat)
    # Query: /reports/multi-version-sources?project_name=acme-web-common&version_name=2.0.0
    add_dep("com.acme.http", "acme-web-common", "2.0.0", "org.springframework.boot", "spring-boot-starter-web", "3.2.1")
    add_dep("com.acme.http", "acme-web-common", "2.0.0", "com.acme.security", "acme-auth", "3.0.0")  # Has logging 2.0.0-SNAPSHOT
    add_dep("com.acme.http", "acme-web-common", "2.0.0", "com.acme.core", "acme-metrics", "1.1.0")  # Has logging 1.2.0

    # acme-grpc-common (depends on netty-core for network transport)
    add_dep("com.acme.http", "acme-grpc-common", "1.0.0", "com.acme.foundation", "acme-netty-core", "1.0.0")
    add_dep("com.acme.http", "acme-grpc-common", "1.0.0", "io.grpc", "grpc-netty", "1.54.0")
    add_dep("com.acme.http", "acme-grpc-common", "1.0.0", "io.grpc", "grpc-protobuf", "1.54.0")
    add_dep("com.acme.http", "acme-grpc-common", "1.0.0", "com.acme.core", "acme-config", "1.1.0")
    add_dep("com.acme.http", "acme-grpc-common", "1.1.0", "com.acme.foundation", "acme-netty-core", "1.1.0")
    add_dep("com.acme.http", "acme-grpc-common", "1.1.0", "io.grpc", "grpc-netty", "1.60.0")
    add_dep("com.acme.http", "acme-grpc-common", "1.1.0", "io.grpc", "grpc-protobuf", "1.60.0")
    add_dep("com.acme.http", "acme-grpc-common", "1.1.0", "com.acme.core", "acme-config", "2.0.0")

    # acme-api-gateway-sdk
    add_dep("com.acme.http", "acme-api-gateway-sdk", "1.0.0", "com.acme.http", "acme-rest-client", "1.1.0")
    add_dep("com.acme.http", "acme-api-gateway-sdk", "1.0.0", "com.acme.security", "acme-auth", "2.0.0")
    add_dep("com.acme.http", "acme-api-gateway-sdk", "1.1.0", "com.acme.http", "acme-rest-client", "2.0.0")
    add_dep("com.acme.http", "acme-api-gateway-sdk", "1.1.0", "com.acme.security", "acme-auth", "3.0.0")

    # acme-test-utils (depends on foundation testing-core instead of directly on junit/mockito)
    add_dep("com.acme.testing", "acme-test-utils", "1.0.0", "com.acme.foundation", "acme-testing-core", "1.0.0")
    add_dep("com.acme.testing", "acme-test-utils", "1.0.0", "com.acme.core", "acme-common", "1.0.0")
    add_dep("com.acme.testing", "acme-test-utils", "1.1.0", "com.acme.foundation", "acme-testing-core", "1.1.0")
    add_dep("com.acme.testing", "acme-test-utils", "1.1.0", "com.acme.core", "acme-common", "1.1.0")
    add_dep("com.acme.testing", "acme-test-utils", "1.2.0", "com.acme.foundation", "acme-testing-core", "2.0.0")
    add_dep("com.acme.testing", "acme-test-utils", "1.2.0", "com.acme.core", "acme-common", "2.0.0")

    # acme-mock-services (depends on testing layer)
    add_dep("com.acme.testing", "acme-mock-services", "1.0.0", "com.acme.testing", "acme-test-utils", "1.0.0")
    add_dep("com.acme.testing", "acme-mock-services", "1.0.0", "com.acme.http", "acme-web-common", "1.0.0")
    add_dep("com.acme.testing", "acme-mock-services", "1.1.0", "com.acme.testing", "acme-test-utils", "1.1.0")
    add_dep("com.acme.testing", "acme-mock-services", "1.1.0", "com.acme.http", "acme-web-common", "2.0.0")

    # acme-test-containers (depends on testing layer)
    add_dep("com.acme.testing", "acme-test-containers", "1.0.0", "com.acme.testing", "acme-test-utils", "1.2.0")
    add_dep("com.acme.testing", "acme-test-containers", "1.0.0", "com.acme.data", "acme-db-common", "2.0.0")

    # Cloud libraries
    add_dep("com.acme.cloud", "acme-aws-common", "1.0.0", "software.amazon.awssdk", "aws-core", "2.20.0")
    add_dep("com.acme.cloud", "acme-aws-common", "1.0.0", "com.acme.core", "acme-config", "1.1.0")
    add_dep("com.acme.cloud", "acme-aws-common", "1.1.0", "software.amazon.awssdk", "aws-core", "2.25.0")
    add_dep("com.acme.cloud", "acme-aws-common", "1.1.0", "com.acme.core", "acme-config", "2.0.0")

    add_dep("com.acme.cloud", "acme-s3-client", "1.0.0", "software.amazon.awssdk", "s3", "2.20.0")
    add_dep("com.acme.cloud", "acme-s3-client", "1.0.0", "com.acme.cloud", "acme-aws-common", "1.0.0")
    add_dep("com.acme.cloud", "acme-s3-client", "1.1.0", "software.amazon.awssdk", "s3", "2.25.0")
    add_dep("com.acme.cloud", "acme-s3-client", "1.1.0", "com.acme.cloud", "acme-aws-common", "1.1.0")

    add_dep("com.acme.cloud", "acme-secrets-manager", "1.0.0", "com.acme.cloud", "acme-aws-common", "1.1.0")
    add_dep("com.acme.cloud", "acme-secrets-manager", "1.0.0", "com.acme.security", "acme-crypto", "1.2.0")

    # Domain models (use validation-core for entity validation, add depth)
    add_dep("com.acme.domain", "acme-customer-model", "1.0.0", "com.acme.foundation", "acme-validation-core", "1.0.0")
    add_dep("com.acme.domain", "acme-customer-model", "1.0.0", "com.acme.data", "acme-models", "2.0.0")
    add_dep("com.acme.domain", "acme-customer-model", "1.1.0", "com.acme.foundation", "acme-validation-core", "1.0.0")
    add_dep("com.acme.domain", "acme-customer-model", "1.1.0", "com.acme.data", "acme-models", "3.0.0")
    add_dep("com.acme.domain", "acme-customer-model", "2.0.0", "com.acme.foundation", "acme-validation-core", "1.1.0")
    add_dep("com.acme.domain", "acme-customer-model", "2.0.0", "com.acme.data", "acme-models", "4.0.0")

    add_dep("com.acme.domain", "acme-order-model", "1.0.0", "com.acme.foundation", "acme-validation-core", "1.0.0")
    add_dep("com.acme.domain", "acme-order-model", "1.0.0", "com.acme.data", "acme-models", "2.0.0")
    add_dep("com.acme.domain", "acme-order-model", "1.0.0", "com.acme.domain", "acme-customer-model", "1.0.0")
    add_dep("com.acme.domain", "acme-order-model", "1.1.0", "com.acme.foundation", "acme-validation-core", "1.0.0")
    add_dep("com.acme.domain", "acme-order-model", "1.1.0", "com.acme.data", "acme-models", "3.0.0")
    add_dep("com.acme.domain", "acme-order-model", "1.1.0", "com.acme.domain", "acme-customer-model", "1.1.0")
    add_dep("com.acme.domain", "acme-order-model", "2.0.0", "com.acme.foundation", "acme-validation-core", "1.1.0")
    add_dep("com.acme.domain", "acme-order-model", "2.0.0", "com.acme.data", "acme-models", "4.0.0")
    add_dep("com.acme.domain", "acme-order-model", "2.0.0", "com.acme.domain", "acme-customer-model", "2.0.0")

    add_dep("com.acme.domain", "acme-product-model", "1.0.0", "com.acme.foundation", "acme-validation-core", "1.0.0")
    add_dep("com.acme.domain", "acme-product-model", "1.0.0", "com.acme.data", "acme-models", "3.0.0")
    add_dep("com.acme.domain", "acme-product-model", "1.1.0", "com.acme.foundation", "acme-validation-core", "1.1.0")
    add_dep("com.acme.domain", "acme-product-model", "1.1.0", "com.acme.data", "acme-models", "4.0.0")

    add_dep("com.acme.domain", "acme-payment-model", "1.0.0", "com.acme.foundation", "acme-validation-core", "1.0.0")
    add_dep("com.acme.domain", "acme-payment-model", "1.0.0", "com.acme.data", "acme-models", "3.0.0")
    add_dep("com.acme.domain", "acme-payment-model", "1.1.0", "com.acme.foundation", "acme-validation-core", "1.1.0")
    add_dep("com.acme.domain", "acme-payment-model", "1.1.0", "com.acme.data", "acme-models", "4.0.0")

    add_dep("com.acme.domain", "acme-billing-model", "1.0.0", "com.acme.foundation", "acme-validation-core", "1.0.0")
    add_dep("com.acme.domain", "acme-billing-model", "1.0.0", "com.acme.domain", "acme-customer-model", "1.1.0")
    add_dep("com.acme.domain", "acme-billing-model", "1.0.0", "com.acme.domain", "acme-payment-model", "1.0.0")
    add_dep("com.acme.domain", "acme-billing-model", "1.1.0", "com.acme.foundation", "acme-validation-core", "1.1.0")
    add_dep("com.acme.domain", "acme-billing-model", "1.1.0", "com.acme.domain", "acme-customer-model", "2.0.0")
    add_dep("com.acme.domain", "acme-billing-model", "1.1.0", "com.acme.domain", "acme-payment-model", "1.1.0")

    # ==========================================================================
    # Application dependencies
    # ==========================================================================

    # Helper to add common app dependencies
    def add_app_deps(app_group, app_name, app_ver, web_ver, db_ver, model_ver, kafka_ver=None, cache_ver=None):
        add_dep(app_group, app_name, app_ver, "com.acme.http", "acme-web-common", web_ver)
        if db_ver:
            add_dep(app_group, app_name, app_ver, "com.acme.data", "acme-repository", db_ver)
        if model_ver:
            add_dep(app_group, app_name, app_ver, "com.acme.data", "acme-models", model_ver)
        if kafka_ver:
            add_dep(app_group, app_name, app_ver, "com.acme.messaging", "acme-kafka", kafka_ver)
        if cache_ver:
            add_dep(app_group, app_name, app_ver, "com.acme.data", "acme-cache", cache_ver)

    # Customer-facing apps
    add_app_deps("com.acme.apps", "customer-portal", "1.0.0", "1.0.0", "1.0.0", "2.0.0")
    add_app_deps("com.acme.apps", "customer-portal", "1.1.0", "1.0.0", "1.1.0", "2.0.0", cache_ver="1.0.0")
    add_app_deps("com.acme.apps", "customer-portal", "1.2.0", "1.1.0", "1.1.0", "3.0.0", cache_ver="1.0.1")
    add_app_deps("com.acme.apps", "customer-portal", "2.0.0", "1.1.0", "2.0.0", "3.0.0", kafka_ver="1.1.0", cache_ver="1.0.1")
    add_app_deps("com.acme.apps", "customer-portal", "2.1.0", "2.0.0", "2.0.0", "4.0.0", kafka_ver="2.0.0", cache_ver="1.1.0")
    add_dep("com.acme.apps", "customer-portal", "2.0.0", "com.acme.domain", "acme-customer-model", "1.1.0")
    add_dep("com.acme.apps", "customer-portal", "2.1.0", "com.acme.domain", "acme-customer-model", "2.0.0")

    add_app_deps("com.acme.apps", "customer-mobile-api", "1.0.0", "1.0.0", "1.0.0", "2.0.0")
    add_app_deps("com.acme.apps", "customer-mobile-api", "1.1.0", "1.1.0", "1.1.0", "3.0.0", cache_ver="1.0.1")
    add_app_deps("com.acme.apps", "customer-mobile-api", "2.0.0", "2.0.0", "2.0.0", "4.0.0", cache_ver="1.1.0")

    add_app_deps("com.acme.apps", "customer-support-portal", "1.0.0", "1.0.0", "1.0.0", "2.0.0")
    add_app_deps("com.acme.apps", "customer-support-portal", "1.1.0", "1.1.0", "2.0.0", "3.0.0")

    # Admin apps
    add_app_deps("com.acme.apps", "admin-dashboard", "1.0.0", "1.0.0", "1.0.0", "2.0.0")
    add_app_deps("com.acme.apps", "admin-dashboard", "1.1.0", "1.0.0", "1.1.0", "2.0.0")
    add_app_deps("com.acme.apps", "admin-dashboard", "1.2.0", "1.1.0", "2.0.0", "3.0.0")
    add_app_deps("com.acme.apps", "admin-dashboard", "2.0.0", "2.0.0", "2.0.0", "4.0.0")
    add_dep("com.acme.apps", "admin-dashboard", "1.2.0", "com.acme.security", "acme-rbac", "1.0.0")
    add_dep("com.acme.apps", "admin-dashboard", "2.0.0", "com.acme.security", "acme-rbac", "1.1.0")

    add_app_deps("com.acme.apps", "ops-console", "1.0.0", "1.0.0", "1.0.0", "2.0.0")
    add_app_deps("com.acme.apps", "ops-console", "1.1.0", "1.1.0", "2.0.0", "3.0.0")
    add_dep("com.acme.apps", "ops-console", "1.0.0", "com.acme.core", "acme-metrics", "1.0.0")
    add_dep("com.acme.apps", "ops-console", "1.1.0", "com.acme.core", "acme-metrics", "1.1.0")

    add_dep("com.acme.apps", "internal-tools", "1.0.0", "com.acme.http", "acme-web-common", "1.1.0")
    add_dep("com.acme.apps", "internal-tools", "1.0.0", "com.acme.data", "acme-db-common", "2.0.0")
    add_dep("com.acme.apps", "internal-tools", "1.0.0", "com.acme.data", "acme-migration", "1.1.0")

    # API Gateway
    add_dep("com.acme.apps", "api-gateway", "1.0.0", "com.acme.http", "acme-web-common", "1.0.0")
    add_dep("com.acme.apps", "api-gateway", "1.0.0", "com.acme.data", "acme-cache", "1.0.0")
    add_dep("com.acme.apps", "api-gateway", "1.0.0", "com.acme.security", "acme-auth", "1.1.0")
    add_dep("com.acme.apps", "api-gateway", "2.0.0", "com.acme.http", "acme-web-common", "1.0.0")
    add_dep("com.acme.apps", "api-gateway", "2.0.0", "com.acme.data", "acme-cache", "1.0.1")
    add_dep("com.acme.apps", "api-gateway", "2.0.0", "com.acme.security", "acme-auth", "2.0.0")
    add_dep("com.acme.apps", "api-gateway", "2.0.0", "com.acme.security", "acme-rbac", "1.0.0")
    add_dep("com.acme.apps", "api-gateway", "3.0.0", "com.acme.http", "acme-web-common", "1.1.0")
    add_dep("com.acme.apps", "api-gateway", "3.0.0", "com.acme.data", "acme-cache", "1.0.1")
    add_dep("com.acme.apps", "api-gateway", "3.0.0", "com.acme.security", "acme-auth", "2.1.0")
    add_dep("com.acme.apps", "api-gateway", "3.0.0", "com.acme.security", "acme-rbac", "1.0.0")
    add_dep("com.acme.apps", "api-gateway", "3.1.0", "com.acme.http", "acme-web-common", "2.0.0")
    add_dep("com.acme.apps", "api-gateway", "3.1.0", "com.acme.data", "acme-cache", "1.1.0")
    add_dep("com.acme.apps", "api-gateway", "3.1.0", "com.acme.security", "acme-auth", "3.0.0")
    add_dep("com.acme.apps", "api-gateway", "3.1.0", "com.acme.security", "acme-rbac", "1.1.0")

    # GraphQL gateway
    add_dep("com.acme.apps", "graphql-gateway", "1.0.0", "com.acme.http", "acme-web-common", "1.1.0")
    add_dep("com.acme.apps", "graphql-gateway", "1.0.0", "com.acme.http", "acme-api-gateway-sdk", "1.0.0")
    add_dep("com.acme.apps", "graphql-gateway", "1.1.0", "com.acme.http", "acme-web-common", "2.0.0")
    add_dep("com.acme.apps", "graphql-gateway", "1.1.0", "com.acme.http", "acme-api-gateway-sdk", "1.1.0")

    # Public API
    add_dep("com.acme.apps", "public-api", "1.0.0", "com.acme.http", "acme-web-common", "1.0.0")
    add_dep("com.acme.apps", "public-api", "1.0.0", "com.acme.security", "acme-oauth", "1.0.0")
    add_dep("com.acme.apps", "public-api", "1.1.0", "com.acme.http", "acme-web-common", "1.1.0")
    add_dep("com.acme.apps", "public-api", "1.1.0", "com.acme.security", "acme-oauth", "1.0.0")
    add_dep("com.acme.apps", "public-api", "2.0.0", "com.acme.http", "acme-web-common", "2.0.0")
    add_dep("com.acme.apps", "public-api", "2.0.0", "com.acme.security", "acme-oauth", "1.1.0")

    # Services - Billing and Payment
    add_app_deps("com.acme.services", "billing-service", "1.0.0", "1.0.0", "1.0.0", "2.0.0", kafka_ver="1.0.0")
    add_app_deps("com.acme.services", "billing-service", "1.1.0", "1.1.0", "1.1.0", "3.0.0", kafka_ver="1.1.0")
    add_app_deps("com.acme.services", "billing-service", "2.0.0", "2.0.0", "2.0.0", "4.0.0", kafka_ver="2.0.0")
    add_dep("com.acme.services", "billing-service", "1.1.0", "com.acme.domain", "acme-billing-model", "1.0.0")
    add_dep("com.acme.services", "billing-service", "2.0.0", "com.acme.domain", "acme-billing-model", "1.1.0")

    add_app_deps("com.acme.services", "payment-service", "1.0.0", "1.0.0", "1.0.0", "2.0.0", kafka_ver="1.0.0")
    add_app_deps("com.acme.services", "payment-service", "1.1.0", "1.1.0", "1.1.0", "3.0.0", kafka_ver="1.1.0")
    add_app_deps("com.acme.services", "payment-service", "2.0.0", "2.0.0", "2.0.0", "4.0.0", kafka_ver="2.0.0")
    add_dep("com.acme.services", "payment-service", "1.0.0", "com.acme.domain", "acme-payment-model", "1.0.0")
    add_dep("com.acme.services", "payment-service", "1.1.0", "com.acme.domain", "acme-payment-model", "1.0.0")
    add_dep("com.acme.services", "payment-service", "2.0.0", "com.acme.domain", "acme-payment-model", "1.1.0")
    add_dep("com.acme.services", "payment-service", "2.0.0", "com.acme.security", "acme-crypto", "1.2.0")

    # Notification services
    add_dep("com.acme.services", "notification-service", "1.0.0", "com.acme.messaging", "acme-kafka", "1.0.0")
    add_dep("com.acme.services", "notification-service", "1.0.0", "com.acme.http", "acme-rest-client", "1.0.0")
    add_dep("com.acme.services", "notification-service", "1.0.0", "com.acme.core", "acme-config", "1.0.0")
    add_dep("com.acme.services", "notification-service", "1.1.0", "com.acme.messaging", "acme-kafka", "1.1.0")
    add_dep("com.acme.services", "notification-service", "1.1.0", "com.acme.http", "acme-rest-client", "1.1.0")
    add_dep("com.acme.services", "notification-service", "1.1.0", "com.acme.core", "acme-config", "1.2.0")
    add_dep("com.acme.services", "notification-service", "2.0.0", "com.acme.messaging", "acme-kafka", "2.0.0")
    add_dep("com.acme.services", "notification-service", "2.0.0", "com.acme.http", "acme-rest-client", "2.0.0")
    add_dep("com.acme.services", "notification-service", "2.0.0", "com.acme.core", "acme-config", "2.0.0")
    add_dep("com.acme.services", "notification-service", "2.1.0", "com.acme.messaging", "acme-kafka", "2.0.0")
    add_dep("com.acme.services", "notification-service", "2.1.0", "com.acme.http", "acme-rest-client", "2.1.0")
    add_dep("com.acme.services", "notification-service", "2.1.0", "com.acme.core", "acme-config", "2.0.0")
    add_dep("com.acme.services", "notification-service", "2.1.0", "com.acme.messaging", "acme-sqs", "1.1.0")

    add_dep("com.acme.services", "email-service", "1.0.0", "com.acme.messaging", "acme-kafka", "1.0.0")
    add_dep("com.acme.services", "email-service", "1.0.0", "com.acme.core", "acme-config", "1.1.0")
    add_dep("com.acme.services", "email-service", "1.1.0", "com.acme.messaging", "acme-kafka", "2.0.0")
    add_dep("com.acme.services", "email-service", "1.1.0", "com.acme.core", "acme-config", "2.0.0")

    add_dep("com.acme.services", "sms-service", "1.0.0", "com.acme.messaging", "acme-kafka", "2.0.0")
    add_dep("com.acme.services", "sms-service", "1.0.0", "com.acme.http", "acme-rest-client", "2.0.0")
    add_dep("com.acme.services", "sms-service", "1.0.0", "com.acme.core", "acme-config", "2.0.0")

    add_dep("com.acme.services", "push-notification-service", "1.0.0", "com.acme.messaging", "acme-kafka", "1.1.0")
    add_dep("com.acme.services", "push-notification-service", "1.0.0", "com.acme.http", "acme-rest-client", "1.1.0")
    add_dep("com.acme.services", "push-notification-service", "1.1.0", "com.acme.messaging", "acme-kafka", "2.0.0")
    add_dep("com.acme.services", "push-notification-service", "1.1.0", "com.acme.http", "acme-rest-client", "2.1.0")

    # Analytics services
    add_dep("com.acme.services", "analytics-engine", "1.0.0", "com.acme.data", "acme-repository", "1.1.0")
    add_dep("com.acme.services", "analytics-engine", "1.0.0", "com.acme.data", "acme-cache", "1.0.0")
    add_dep("com.acme.services", "analytics-engine", "1.0.0", "com.acme.core", "acme-config", "1.1.0")
    add_dep("com.acme.services", "analytics-engine", "1.0.1", "com.acme.data", "acme-repository", "2.0.0")
    add_dep("com.acme.services", "analytics-engine", "1.0.1", "com.acme.data", "acme-cache", "1.0.1")
    add_dep("com.acme.services", "analytics-engine", "1.0.1", "com.acme.core", "acme-config", "1.2.0")
    add_dep("com.acme.services", "analytics-engine", "1.1.0", "com.acme.data", "acme-repository", "2.0.0")
    add_dep("com.acme.services", "analytics-engine", "1.1.0", "com.acme.data", "acme-cache", "1.1.0")
    add_dep("com.acme.services", "analytics-engine", "1.1.0", "com.acme.core", "acme-config", "2.0.0")

    add_dep("com.acme.services", "reporting-service", "1.0.0", "com.acme.data", "acme-repository", "1.1.0")
    add_dep("com.acme.services", "reporting-service", "1.0.0", "com.acme.core", "acme-config", "1.1.0")
    add_dep("com.acme.services", "reporting-service", "1.0.0", "commons-io", "commons-io", "2.13.0")
    add_dep("com.acme.services", "reporting-service", "1.1.0", "com.acme.data", "acme-repository", "2.0.0")
    add_dep("com.acme.services", "reporting-service", "1.1.0", "com.acme.core", "acme-config", "2.0.0")
    add_dep("com.acme.services", "reporting-service", "1.1.0", "commons-io", "commons-io", "2.15.1")

    add_dep("com.acme.services", "metrics-aggregator", "1.0.0", "com.acme.messaging", "acme-kafka", "2.0.0")
    add_dep("com.acme.services", "metrics-aggregator", "1.0.0", "com.acme.core", "acme-metrics", "1.1.0")
    add_dep("com.acme.services", "metrics-aggregator", "1.0.0", "com.acme.data", "acme-cache", "1.1.0")

    # Order/Inventory services
    add_app_deps("com.acme.services", "inventory-manager", "1.0.0", "1.0.0", "1.0.0", "2.0.0")
    add_app_deps("com.acme.services", "inventory-manager", "1.1.0", "1.0.0", "1.1.0", "2.0.0", kafka_ver="1.0.0")
    add_app_deps("com.acme.services", "inventory-manager", "1.2.0", "1.1.0", "2.0.0", "3.0.0", kafka_ver="1.1.0")
    add_app_deps("com.acme.services", "inventory-manager", "2.0.0", "2.0.0", "2.0.0", "4.0.0", kafka_ver="2.0.0")
    add_dep("com.acme.services", "inventory-manager", "1.2.0", "com.acme.domain", "acme-product-model", "1.0.0")
    add_dep("com.acme.services", "inventory-manager", "2.0.0", "com.acme.domain", "acme-product-model", "1.1.0")

    add_app_deps("com.acme.services", "order-processor", "1.0.0", "1.0.0", "1.0.0", "2.0.0", kafka_ver="1.0.0")
    add_app_deps("com.acme.services", "order-processor", "1.1.0", "1.1.0", "1.1.0", "3.0.0", kafka_ver="1.1.0")
    add_app_deps("com.acme.services", "order-processor", "2.0.0", "2.0.0", "2.0.0", "4.0.0", kafka_ver="2.0.0")
    add_dep("com.acme.services", "order-processor", "1.0.0", "com.acme.domain", "acme-order-model", "1.0.0")
    add_dep("com.acme.services", "order-processor", "1.1.0", "com.acme.domain", "acme-order-model", "1.1.0")
    add_dep("com.acme.services", "order-processor", "2.0.0", "com.acme.domain", "acme-order-model", "2.0.0")
    add_dep("com.acme.services", "order-processor", "2.0.0", "com.acme.http", "acme-api-gateway-sdk", "1.1.0")

    add_dep("com.acme.services", "fulfillment-service", "1.0.0", "com.acme.messaging", "acme-kafka", "1.1.0")
    add_dep("com.acme.services", "fulfillment-service", "1.0.0", "com.acme.data", "acme-repository", "1.1.0")
    add_dep("com.acme.services", "fulfillment-service", "1.0.0", "com.acme.domain", "acme-order-model", "1.1.0")
    add_dep("com.acme.services", "fulfillment-service", "1.1.0", "com.acme.messaging", "acme-kafka", "2.0.0")
    add_dep("com.acme.services", "fulfillment-service", "1.1.0", "com.acme.data", "acme-repository", "2.0.0")
    add_dep("com.acme.services", "fulfillment-service", "1.1.0", "com.acme.domain", "acme-order-model", "2.0.0")

    add_dep("com.acme.services", "shipping-service", "1.0.0", "com.acme.messaging", "acme-kafka", "2.0.0")
    add_dep("com.acme.services", "shipping-service", "1.0.0", "com.acme.http", "acme-rest-client", "2.1.0")
    add_dep("com.acme.services", "shipping-service", "1.0.0", "com.acme.domain", "acme-order-model", "2.0.0")

    # User/Auth services
    add_app_deps("com.acme.services", "user-service", "1.0.0", "1.0.0", "1.0.0", "2.0.0")
    add_app_deps("com.acme.services", "user-service", "1.1.0", "1.1.0", "1.1.0", "3.0.0", cache_ver="1.0.1")
    add_app_deps("com.acme.services", "user-service", "2.0.0", "2.0.0", "2.0.0", "4.0.0", cache_ver="1.1.0")
    add_dep("com.acme.services", "user-service", "1.0.0", "com.acme.domain", "acme-customer-model", "1.0.0")
    add_dep("com.acme.services", "user-service", "1.1.0", "com.acme.domain", "acme-customer-model", "1.1.0")
    add_dep("com.acme.services", "user-service", "2.0.0", "com.acme.domain", "acme-customer-model", "2.0.0")

    add_dep("com.acme.services", "auth-service", "1.0.0", "com.acme.http", "acme-web-common", "1.0.0")
    add_dep("com.acme.services", "auth-service", "1.0.0", "com.acme.data", "acme-cache", "1.0.0")
    add_dep("com.acme.services", "auth-service", "1.0.0", "com.acme.security", "acme-auth", "1.1.0")
    add_dep("com.acme.services", "auth-service", "1.1.0", "com.acme.http", "acme-web-common", "1.0.0")
    add_dep("com.acme.services", "auth-service", "1.1.0", "com.acme.data", "acme-cache", "1.0.1")
    add_dep("com.acme.services", "auth-service", "1.1.0", "com.acme.security", "acme-auth", "2.0.0")
    add_dep("com.acme.services", "auth-service", "2.0.0", "com.acme.http", "acme-web-common", "1.1.0")
    add_dep("com.acme.services", "auth-service", "2.0.0", "com.acme.data", "acme-cache", "1.0.1")
    add_dep("com.acme.services", "auth-service", "2.0.0", "com.acme.security", "acme-auth", "2.1.0")
    add_dep("com.acme.services", "auth-service", "3.0.0", "com.acme.http", "acme-web-common", "2.0.0")
    add_dep("com.acme.services", "auth-service", "3.0.0", "com.acme.data", "acme-cache", "1.1.0")
    add_dep("com.acme.services", "auth-service", "3.0.0", "com.acme.security", "acme-auth", "3.0.0")

    add_dep("com.acme.services", "identity-provider", "1.0.0", "com.acme.services", "auth-service", "2.0.0")
    add_dep("com.acme.services", "identity-provider", "1.0.0", "com.acme.security", "acme-oauth", "1.0.0")
    add_dep("com.acme.services", "identity-provider", "1.1.0", "com.acme.services", "auth-service", "3.0.0")
    add_dep("com.acme.services", "identity-provider", "1.1.0", "com.acme.security", "acme-oauth", "1.1.0")

    # Infrastructure services
    add_dep("com.acme.services", "scheduler-service", "1.0.0", "com.acme.messaging", "acme-kafka", "1.0.0")
    add_dep("com.acme.services", "scheduler-service", "1.0.0", "com.acme.data", "acme-db-common", "1.0.0")
    add_dep("com.acme.services", "scheduler-service", "1.0.0", "com.acme.core", "acme-config", "1.0.0")
    add_dep("com.acme.services", "scheduler-service", "1.1.0", "com.acme.messaging", "acme-kafka", "2.0.0")
    add_dep("com.acme.services", "scheduler-service", "1.1.0", "com.acme.data", "acme-db-common", "2.0.0")
    add_dep("com.acme.services", "scheduler-service", "1.1.0", "com.acme.core", "acme-config", "2.0.0")

    add_dep("com.acme.services", "job-runner", "1.0.0", "com.acme.messaging", "acme-kafka", "1.1.0")
    add_dep("com.acme.services", "job-runner", "1.0.0", "com.acme.core", "acme-config", "1.2.0")
    add_dep("com.acme.services", "job-runner", "1.1.0", "com.acme.messaging", "acme-kafka", "2.0.0")
    add_dep("com.acme.services", "job-runner", "1.1.0", "com.acme.core", "acme-config", "2.0.0")

    add_dep("com.acme.services", "config-server", "1.0.0", "com.acme.http", "acme-web-common", "2.0.0")
    add_dep("com.acme.services", "config-server", "1.0.0", "com.acme.cloud", "acme-secrets-manager", "1.0.0")

    add_dep("com.acme.services", "service-registry", "1.0.0", "com.acme.http", "acme-web-common", "2.0.0")
    add_dep("com.acme.services", "service-registry", "1.0.0", "com.acme.data", "acme-cache", "1.1.0")

    # Data pipeline services
    add_dep("com.acme.services", "data-ingestion", "1.0.0", "com.acme.messaging", "acme-kafka", "1.1.0")
    add_dep("com.acme.services", "data-ingestion", "1.0.0", "com.acme.data", "acme-db-common", "1.1.0")
    add_dep("com.acme.services", "data-ingestion", "1.0.0", "com.acme.cloud", "acme-s3-client", "1.0.0")
    add_dep("com.acme.services", "data-ingestion", "1.1.0", "com.acme.messaging", "acme-kafka", "2.0.0")
    add_dep("com.acme.services", "data-ingestion", "1.1.0", "com.acme.data", "acme-db-common", "2.1.0")
    add_dep("com.acme.services", "data-ingestion", "1.1.0", "com.acme.cloud", "acme-s3-client", "1.1.0")

    add_dep("com.acme.services", "etl-processor", "1.0.0", "com.acme.messaging", "acme-kafka", "2.0.0")
    add_dep("com.acme.services", "etl-processor", "1.0.0", "com.acme.data", "acme-db-common", "2.1.0")
    add_dep("com.acme.services", "etl-processor", "1.0.0", "com.acme.core", "acme-config", "2.0.0")

    add_dep("com.acme.services", "data-exporter", "1.0.0", "com.acme.data", "acme-repository", "2.0.0")
    add_dep("com.acme.services", "data-exporter", "1.0.0", "com.acme.cloud", "acme-s3-client", "1.1.0")
    add_dep("com.acme.services", "data-exporter", "1.0.0", "commons-io", "commons-io", "2.15.1")

    # Search services
    add_dep("com.acme.services", "search-service", "1.0.0", "com.acme.http", "acme-web-common", "1.1.0")
    add_dep("com.acme.services", "search-service", "1.0.0", "com.acme.data", "acme-cache", "1.0.1")
    add_dep("com.acme.services", "search-service", "1.0.0", "com.acme.core", "acme-config", "1.2.0")
    add_dep("com.acme.services", "search-service", "1.1.0", "com.acme.http", "acme-web-common", "2.0.0")
    add_dep("com.acme.services", "search-service", "1.1.0", "com.acme.data", "acme-cache", "1.1.0")
    add_dep("com.acme.services", "search-service", "1.1.0", "com.acme.core", "acme-config", "2.0.0")

    add_dep("com.acme.services", "indexer-service", "1.0.0", "com.acme.messaging", "acme-kafka", "2.0.0")
    add_dep("com.acme.services", "indexer-service", "1.0.0", "com.acme.data", "acme-repository", "2.0.0")
    add_dep("com.acme.services", "indexer-service", "1.0.0", "com.acme.core", "acme-config", "2.0.0")

    # Integration services
    add_dep("com.acme.services", "webhook-service", "1.0.0", "com.acme.messaging", "acme-kafka", "1.1.0")
    add_dep("com.acme.services", "webhook-service", "1.0.0", "com.acme.http", "acme-rest-client", "1.1.0")
    add_dep("com.acme.services", "webhook-service", "1.0.0", "com.acme.data", "acme-db-common", "1.1.0")
    add_dep("com.acme.services", "webhook-service", "1.1.0", "com.acme.messaging", "acme-kafka", "2.0.0")
    add_dep("com.acme.services", "webhook-service", "1.1.0", "com.acme.http", "acme-rest-client", "2.1.0")
    add_dep("com.acme.services", "webhook-service", "1.1.0", "com.acme.data", "acme-db-common", "2.1.0")

    add_dep("com.acme.services", "integration-hub", "1.0.0", "com.acme.http", "acme-web-common", "2.0.0")
    add_dep("com.acme.services", "integration-hub", "1.0.0", "com.acme.http", "acme-rest-client", "2.1.0")
    add_dep("com.acme.services", "integration-hub", "1.0.0", "com.acme.messaging", "acme-kafka", "2.0.0")
    add_dep("com.acme.services", "integration-hub", "1.0.0", "com.acme.security", "acme-oauth", "1.1.0")

    # ==========================================================================
    # SNAPSHOT library dependencies (depend on stable versions)
    # ==========================================================================

    # SNAPSHOT libs depend on stable versions of other libs
    add_dep("com.acme.core", "acme-common", "3.0.0-SNAPSHOT", "com.google.guava", "guava", "33.0.0-jre")
    add_dep("com.acme.core", "acme-common", "3.0.0-SNAPSHOT", "org.apache.commons", "commons-lang3", "3.14.0")
    add_dep("com.acme.core", "acme-common", "3.0.0-SNAPSHOT", "com.acme.core", "acme-logging", "1.2.0")

    add_dep("com.acme.core", "acme-logging", "2.0.0-SNAPSHOT", "org.slf4j", "slf4j-api", "2.0.11")
    add_dep("com.acme.core", "acme-logging", "2.0.0-SNAPSHOT", "ch.qos.logback", "logback-classic", "1.4.14")

    add_dep("com.acme.core", "acme-config", "2.1.0-SNAPSHOT", "com.acme.core", "acme-common", "2.1.0")
    add_dep("com.acme.core", "acme-config", "2.1.0-SNAPSHOT", "com.fasterxml.jackson.core", "jackson-databind", "2.16.1")

    add_dep("com.acme.security", "acme-auth", "4.0.0-SNAPSHOT", "com.acme.security", "acme-jwt", "1.1.0")
    add_dep("com.acme.security", "acme-auth", "4.0.0-SNAPSHOT", "com.acme.core", "acme-config", "2.0.0")
    add_dep("com.acme.security", "acme-auth", "4.0.0-SNAPSHOT", "org.springframework.security", "spring-security-core", "6.2.0")

    add_dep("com.acme.data", "acme-db-common", "3.0.0-SNAPSHOT", "org.postgresql", "postgresql", "42.7.1")
    add_dep("com.acme.data", "acme-db-common", "3.0.0-SNAPSHOT", "com.zaxxer", "HikariCP", "5.1.0")
    add_dep("com.acme.data", "acme-db-common", "3.0.0-SNAPSHOT", "com.acme.core", "acme-config", "2.0.0")
    add_dep("com.acme.data", "acme-db-common", "3.0.0-SNAPSHOT", "com.acme.foundation", "acme-mysql-core", "1.0.0")
    add_dep("com.acme.data", "acme-db-common", "3.0.0-SNAPSHOT", "com.acme.foundation", "acme-nosql-core", "1.1.0")

    add_dep("com.acme.data", "acme-cache", "2.0.0-SNAPSHOT", "redis.clients", "jedis", "5.1.0")
    add_dep("com.acme.data", "acme-cache", "2.0.0-SNAPSHOT", "com.acme.core", "acme-config", "2.0.0")
    add_dep("com.acme.data", "acme-cache", "2.0.0-SNAPSHOT", "com.acme.foundation", "acme-serialization-core", "2.0.0")

    add_dep("com.acme.data", "acme-models", "5.0.0-SNAPSHOT", "com.fasterxml.jackson.core", "jackson-databind", "2.16.1")
    add_dep("com.acme.data", "acme-models", "5.0.0-SNAPSHOT", "com.acme.core", "acme-common", "2.1.0")

    add_dep("com.acme.data", "acme-repository", "3.0.0-SNAPSHOT", "com.acme.data", "acme-db-common", "2.1.0")
    add_dep("com.acme.data", "acme-repository", "3.0.0-SNAPSHOT", "com.acme.data", "acme-models", "4.0.0")

    add_dep("com.acme.messaging", "acme-events", "3.0.0-SNAPSHOT", "com.acme.data", "acme-models", "5.0.0-SNAPSHOT")
    add_dep("com.acme.messaging", "acme-events", "3.0.0-SNAPSHOT", "com.acme.core", "acme-common", "3.0.0-SNAPSHOT")

    add_dep("com.acme.messaging", "acme-kafka", "3.0.0-SNAPSHOT", "org.apache.kafka", "kafka-clients", "3.6.0")
    add_dep("com.acme.messaging", "acme-kafka", "3.0.0-SNAPSHOT", "com.acme.messaging", "acme-events", "3.0.0-SNAPSHOT")
    add_dep("com.acme.messaging", "acme-kafka", "3.0.0-SNAPSHOT", "com.acme.core", "acme-config", "2.1.0-SNAPSHOT")

    add_dep("com.acme.http", "acme-rest-client", "3.0.0-SNAPSHOT", "com.acme.foundation", "acme-http-core", "2.0.0")
    add_dep("com.acme.http", "acme-rest-client", "3.0.0-SNAPSHOT", "com.fasterxml.jackson.core", "jackson-databind", "2.16.1")
    add_dep("com.acme.http", "acme-rest-client", "3.0.0-SNAPSHOT", "com.acme.core", "acme-config", "2.1.0-SNAPSHOT")

    add_dep("com.acme.http", "acme-web-common", "3.0.0-SNAPSHOT", "com.acme.foundation", "acme-spring-core", "2.0.0")
    add_dep("com.acme.http", "acme-web-common", "3.0.0-SNAPSHOT", "org.springframework.boot", "spring-boot-starter-web", "3.2.1")
    add_dep("com.acme.http", "acme-web-common", "3.0.0-SNAPSHOT", "com.acme.security", "acme-auth", "4.0.0-SNAPSHOT")
    add_dep("com.acme.http", "acme-web-common", "3.0.0-SNAPSHOT", "com.acme.core", "acme-metrics", "1.1.0")

    # ==========================================================================
    # SNAPSHOT applications using SNAPSHOT libraries
    # ==========================================================================

    add_dep("com.acme.apps", "customer-portal", "3.0.0-SNAPSHOT", "com.acme.http", "acme-web-common", "3.0.0-SNAPSHOT")
    add_dep("com.acme.apps", "customer-portal", "3.0.0-SNAPSHOT", "com.acme.data", "acme-repository", "3.0.0-SNAPSHOT")
    add_dep("com.acme.apps", "customer-portal", "3.0.0-SNAPSHOT", "com.acme.data", "acme-models", "5.0.0-SNAPSHOT")
    add_dep("com.acme.apps", "customer-portal", "3.0.0-SNAPSHOT", "com.acme.messaging", "acme-kafka", "3.0.0-SNAPSHOT")
    add_dep("com.acme.apps", "customer-portal", "3.0.0-SNAPSHOT", "com.acme.data", "acme-cache", "2.0.0-SNAPSHOT")

    add_dep("com.acme.apps", "customer-mobile-api", "2.1.0-SNAPSHOT", "com.acme.http", "acme-web-common", "2.0.0")
    add_dep("com.acme.apps", "customer-mobile-api", "2.1.0-SNAPSHOT", "com.acme.data", "acme-repository", "2.0.0")
    add_dep("com.acme.apps", "customer-mobile-api", "2.1.0-SNAPSHOT", "com.acme.data", "acme-models", "5.0.0-SNAPSHOT")
    add_dep("com.acme.apps", "customer-mobile-api", "2.1.0-SNAPSHOT", "com.acme.data", "acme-cache", "2.0.0-SNAPSHOT")

    add_dep("com.acme.apps", "admin-dashboard", "3.0.0-SNAPSHOT", "com.acme.http", "acme-web-common", "3.0.0-SNAPSHOT")
    add_dep("com.acme.apps", "admin-dashboard", "3.0.0-SNAPSHOT", "com.acme.data", "acme-repository", "3.0.0-SNAPSHOT")
    add_dep("com.acme.apps", "admin-dashboard", "3.0.0-SNAPSHOT", "com.acme.data", "acme-models", "5.0.0-SNAPSHOT")
    add_dep("com.acme.apps", "admin-dashboard", "3.0.0-SNAPSHOT", "com.acme.security", "acme-rbac", "1.1.0")

    add_dep("com.acme.apps", "api-gateway", "4.0.0-SNAPSHOT", "com.acme.http", "acme-web-common", "3.0.0-SNAPSHOT")
    add_dep("com.acme.apps", "api-gateway", "4.0.0-SNAPSHOT", "com.acme.data", "acme-cache", "2.0.0-SNAPSHOT")
    add_dep("com.acme.apps", "api-gateway", "4.0.0-SNAPSHOT", "com.acme.security", "acme-auth", "4.0.0-SNAPSHOT")
    add_dep("com.acme.apps", "api-gateway", "4.0.0-SNAPSHOT", "com.acme.security", "acme-rbac", "1.1.0")

    add_dep("com.acme.services", "billing-service", "3.0.0-SNAPSHOT", "com.acme.http", "acme-web-common", "3.0.0-SNAPSHOT")
    add_dep("com.acme.services", "billing-service", "3.0.0-SNAPSHOT", "com.acme.data", "acme-repository", "3.0.0-SNAPSHOT")
    add_dep("com.acme.services", "billing-service", "3.0.0-SNAPSHOT", "com.acme.data", "acme-models", "5.0.0-SNAPSHOT")
    add_dep("com.acme.services", "billing-service", "3.0.0-SNAPSHOT", "com.acme.messaging", "acme-kafka", "3.0.0-SNAPSHOT")
    add_dep("com.acme.services", "billing-service", "3.0.0-SNAPSHOT", "com.acme.domain", "acme-billing-model", "1.1.0")

    add_dep("com.acme.services", "order-processor", "3.0.0-SNAPSHOT", "com.acme.http", "acme-web-common", "3.0.0-SNAPSHOT")
    add_dep("com.acme.services", "order-processor", "3.0.0-SNAPSHOT", "com.acme.data", "acme-repository", "3.0.0-SNAPSHOT")
    add_dep("com.acme.services", "order-processor", "3.0.0-SNAPSHOT", "com.acme.data", "acme-models", "5.0.0-SNAPSHOT")
    add_dep("com.acme.services", "order-processor", "3.0.0-SNAPSHOT", "com.acme.messaging", "acme-kafka", "3.0.0-SNAPSHOT")
    add_dep("com.acme.services", "order-processor", "3.0.0-SNAPSHOT", "com.acme.domain", "acme-order-model", "2.0.0")
    add_dep("com.acme.services", "order-processor", "3.0.0-SNAPSHOT", "com.acme.http", "acme-api-gateway-sdk", "1.1.0")

    add_dep("com.acme.services", "auth-service", "4.0.0-SNAPSHOT", "com.acme.http", "acme-web-common", "3.0.0-SNAPSHOT")
    add_dep("com.acme.services", "auth-service", "4.0.0-SNAPSHOT", "com.acme.data", "acme-cache", "2.0.0-SNAPSHOT")
    add_dep("com.acme.services", "auth-service", "4.0.0-SNAPSHOT", "com.acme.security", "acme-auth", "4.0.0-SNAPSHOT")

    # ==========================================================================
    # Release versions using SNAPSHOT dependencies (bad practice)
    # ==========================================================================

    add_dep("com.acme.apps", "quick-prototype", "1.0.0", "com.acme.http", "acme-web-common", "3.0.0-SNAPSHOT")
    add_dep("com.acme.apps", "quick-prototype", "1.0.0", "com.acme.data", "acme-models", "5.0.0-SNAPSHOT")
    add_dep("com.acme.apps", "quick-prototype", "1.0.0", "com.acme.core", "acme-config", "2.1.0-SNAPSHOT")

    add_dep("com.acme.apps", "demo-app", "1.0.0", "com.acme.http", "acme-web-common", "2.0.0")
    add_dep("com.acme.apps", "demo-app", "1.0.0", "com.acme.data", "acme-models", "5.0.0-SNAPSHOT")
    add_dep("com.acme.apps", "demo-app", "1.1.0", "com.acme.http", "acme-web-common", "3.0.0-SNAPSHOT")
    add_dep("com.acme.apps", "demo-app", "1.1.0", "com.acme.data", "acme-models", "5.0.0-SNAPSHOT")
    add_dep("com.acme.apps", "demo-app", "1.1.0", "com.acme.messaging", "acme-kafka", "3.0.0-SNAPSHOT")

    # ==========================================================================
    # Non-semver / legacy library dependencies
    # ==========================================================================

    # Legacy utils library (uses foundation collections layer for additional depth)
    add_dep("com.acme.legacy", "acme-legacy-utils", "v1", "com.acme.foundation", "acme-collections", "1.0.0")
    add_dep("com.acme.legacy", "acme-legacy-utils", "v1", "com.google.guava", "guava", "31.1-jre")
    add_dep("com.acme.legacy", "acme-legacy-utils", "v1", "org.apache.commons", "commons-lang3", "3.12.0")
    add_dep("com.acme.legacy", "acme-legacy-utils", "v2", "com.acme.foundation", "acme-collections", "1.0.0")
    add_dep("com.acme.legacy", "acme-legacy-utils", "v2", "com.google.guava", "guava", "32.1.2-jre")
    add_dep("com.acme.legacy", "acme-legacy-utils", "v2", "org.apache.commons", "commons-lang3", "3.13.0")
    add_dep("com.acme.legacy", "acme-legacy-utils", "v2.1", "com.acme.legacy", "acme-legacy-utils", "v2")  # Depends on itself (previous version)
    add_dep("com.acme.legacy", "acme-legacy-utils", "v2.1", "org.apache.commons", "commons-lang3", "3.14.0")
    add_dep("com.acme.legacy", "acme-legacy-utils", "v3-beta", "com.acme.foundation", "acme-collections", "1.1.0")
    add_dep("com.acme.legacy", "acme-legacy-utils", "v3-beta", "com.google.guava", "guava", "33.0.0-jre")
    add_dep("com.acme.legacy", "acme-legacy-utils", "v3-beta", "org.apache.commons", "commons-lang3", "3.14.0")
    add_dep("com.acme.legacy", "acme-legacy-utils", "v3-beta", "com.acme.core", "acme-common", "2.1.0")

    # Legacy connector library (uses foundation http-core for HTTP abstractions)
    add_dep("com.acme.legacy", "acme-legacy-connector", "build-123", "com.acme.foundation", "acme-http-core", "1.0.0")
    add_dep("com.acme.legacy", "acme-legacy-connector", "build-123", "com.fasterxml.jackson.core", "jackson-databind", "2.14.0")
    add_dep("com.acme.legacy", "acme-legacy-connector", "build-456", "com.acme.foundation", "acme-http-core", "1.1.0")
    add_dep("com.acme.legacy", "acme-legacy-connector", "build-456", "com.fasterxml.jackson.core", "jackson-databind", "2.15.2")
    add_dep("com.acme.legacy", "acme-legacy-connector", "release-2024.01", "com.acme.foundation", "acme-http-core", "2.0.0")
    add_dep("com.acme.legacy", "acme-legacy-connector", "release-2024.01", "com.fasterxml.jackson.core", "jackson-databind", "2.16.1")
    add_dep("com.acme.legacy", "acme-legacy-connector", "release-2024.01", "com.acme.core", "acme-config", "2.0.0")

    # ML Pipeline experimental library (uses foundation layers)
    add_dep("com.acme.experimental", "acme-ml-pipeline", "alpha", "com.acme.foundation", "acme-serialization-core", "1.0.0")
    add_dep("com.acme.experimental", "acme-ml-pipeline", "alpha", "com.google.guava", "guava", "32.1.2-jre")
    add_dep("com.acme.experimental", "acme-ml-pipeline", "alpha", "com.fasterxml.jackson.core", "jackson-databind", "2.15.2")
    add_dep("com.acme.experimental", "acme-ml-pipeline", "beta", "com.acme.experimental", "acme-ml-pipeline", "alpha")
    add_dep("com.acme.experimental", "acme-ml-pipeline", "beta", "com.acme.data", "acme-models", "3.0.0")
    add_dep("com.acme.experimental", "acme-ml-pipeline", "rc1", "com.acme.experimental", "acme-ml-pipeline", "beta")
    add_dep("com.acme.experimental", "acme-ml-pipeline", "rc1", "com.acme.data", "acme-models", "4.0.0")
    add_dep("com.acme.experimental", "acme-ml-pipeline", "GA", "com.acme.foundation", "acme-serialization-core", "2.0.0")
    add_dep("com.acme.experimental", "acme-ml-pipeline", "GA", "com.google.guava", "guava", "33.0.0-jre")
    add_dep("com.acme.experimental", "acme-ml-pipeline", "GA", "com.fasterxml.jackson.core", "jackson-databind", "2.16.1")
    add_dep("com.acme.experimental", "acme-ml-pipeline", "GA", "com.acme.data", "acme-models", "4.0.0")
    add_dep("com.acme.experimental", "acme-ml-pipeline", "GA", "com.acme.messaging", "acme-kafka", "2.0.0")

    # Non-semver applications
    add_dep("com.acme.legacy", "legacy-crm", "2024.01", "com.acme.http", "acme-web-common", "1.0.0")
    add_dep("com.acme.legacy", "legacy-crm", "2024.01", "com.acme.data", "acme-repository", "1.0.0")
    add_dep("com.acme.legacy", "legacy-crm", "2024.01", "com.acme.legacy", "acme-legacy-utils", "v2")
    add_dep("com.acme.legacy", "legacy-crm", "2024.02", "com.acme.http", "acme-web-common", "1.1.0")
    add_dep("com.acme.legacy", "legacy-crm", "2024.02", "com.acme.data", "acme-repository", "1.1.0")
    add_dep("com.acme.legacy", "legacy-crm", "2024.02", "com.acme.legacy", "acme-legacy-utils", "v2.1")
    add_dep("com.acme.legacy", "legacy-crm", "2024.03-hotfix", "com.acme.http", "acme-web-common", "1.1.0")
    add_dep("com.acme.legacy", "legacy-crm", "2024.03-hotfix", "com.acme.data", "acme-repository", "2.0.0")
    add_dep("com.acme.legacy", "legacy-crm", "2024.03-hotfix", "com.acme.legacy", "acme-legacy-utils", "v3-beta")

    add_dep("com.acme.legacy", "legacy-erp", "v5.0", "com.acme.http", "acme-web-common", "1.0.0")
    add_dep("com.acme.legacy", "legacy-erp", "v5.0", "com.acme.data", "acme-db-common", "1.0.0")
    add_dep("com.acme.legacy", "legacy-erp", "v5.0", "com.acme.legacy", "acme-legacy-connector", "build-123")
    add_dep("com.acme.legacy", "legacy-erp", "v5.1", "com.acme.http", "acme-web-common", "1.1.0")
    add_dep("com.acme.legacy", "legacy-erp", "v5.1", "com.acme.data", "acme-db-common", "1.1.0")
    add_dep("com.acme.legacy", "legacy-erp", "v5.1", "com.acme.legacy", "acme-legacy-connector", "build-456")
    add_dep("com.acme.legacy", "legacy-erp", "v6-preview", "com.acme.http", "acme-web-common", "2.0.0")
    add_dep("com.acme.legacy", "legacy-erp", "v6-preview", "com.acme.data", "acme-db-common", "2.0.0")
    add_dep("com.acme.legacy", "legacy-erp", "v6-preview", "com.acme.legacy", "acme-legacy-connector", "release-2024.01")

    add_dep("com.acme.experimental", "ai-recommendation-engine", "prototype-1", "com.acme.experimental", "acme-ml-pipeline", "alpha")
    add_dep("com.acme.experimental", "ai-recommendation-engine", "prototype-1", "com.acme.data", "acme-repository", "1.1.0")
    add_dep("com.acme.experimental", "ai-recommendation-engine", "prototype-2", "com.acme.experimental", "acme-ml-pipeline", "beta")
    add_dep("com.acme.experimental", "ai-recommendation-engine", "prototype-2", "com.acme.data", "acme-repository", "2.0.0")
    add_dep("com.acme.experimental", "ai-recommendation-engine", "mvp", "com.acme.experimental", "acme-ml-pipeline", "GA")
    add_dep("com.acme.experimental", "ai-recommendation-engine", "mvp", "com.acme.data", "acme-repository", "2.0.0")
    add_dep("com.acme.experimental", "ai-recommendation-engine", "mvp", "com.acme.http", "acme-web-common", "2.0.0")

    # ==========================================================================
    # VERSION PINNING EXAMPLES (Multi-Version Dependencies Demonstration)
    # ==========================================================================
    # These examples create multiple versions of third-party libraries in the graph.
    # This data supports TWO different reports:
    #
    # 1. /reports/multi-version-deps/{library}
    #    Shows who uses what version of a library (e.g., jackson-databind)
    #    Use: Vulnerability remediation planning, adoption tracking
    #
    # 2. /reports/multi-version-sources/{project}/{version}
    #    Shows version conflicts within a specific project's dependency tree
    #    Use: Diamond dependency detection, runtime conflict risk analysis
    # ==========================================================================

    # Application: data-platform-core - pins jackson-databind to 2.14.2 for stability
    # (overrides the 2.15.2 that would come transitively from acme-models)
    add_dep("com.acme.services", "data-platform-core", "1.0.0", "com.acme.data", "acme-models", "3.0.0")
    add_dep("com.acme.services", "data-platform-core", "1.0.0", "com.fasterxml.jackson.core", "jackson-databind", "2.14.2")  # Pinned!
    add_dep("com.acme.services", "data-platform-core", "1.0.0", "com.acme.core", "acme-config", "1.2.0")

    # Application: realtime-processor - pins jackson-databind to 2.13.0 for legacy compat
    add_dep("com.acme.services", "realtime-processor", "1.0.0", "com.acme.messaging", "acme-kafka", "1.1.0")
    add_dep("com.acme.services", "realtime-processor", "1.0.0", "com.fasterxml.jackson.core", "jackson-databind", "2.13.0")  # Pinned!
    add_dep("com.acme.services", "realtime-processor", "1.0.0", "com.acme.data", "acme-models", "2.0.0")

    # Application: api-v2-service - uses latest jackson-databind 2.16.1
    add_dep("com.acme.services", "api-v2-service", "1.0.0", "com.acme.http", "acme-web-common", "2.0.0")
    add_dep("com.acme.services", "api-v2-service", "1.0.0", "com.fasterxml.jackson.core", "jackson-databind", "2.16.1")  # Latest
    add_dep("com.acme.services", "api-v2-service", "1.0.0", "com.acme.data", "acme-repository", "2.0.0")

    # Application: batch-processor - pins to 2.15.2 for performance fixes
    add_dep("com.acme.services", "batch-processor", "1.0.0", "com.acme.messaging", "acme-kafka", "2.0.0")
    add_dep("com.acme.services", "batch-processor", "1.0.0", "com.fasterxml.jackson.core", "jackson-databind", "2.15.2")  # Pinned!
    add_dep("com.acme.services", "batch-processor", "1.0.0", "com.acme.data", "acme-db-common", "2.0.0")

    # Application: compliance-service - pins to 2.14.0 for audit certification
    add_dep("com.acme.services", "compliance-service", "1.0.0", "com.acme.http", "acme-rest-client", "2.0.0")
    add_dep("com.acme.services", "compliance-service", "1.0.0", "com.fasterxml.jackson.core", "jackson-databind", "2.14.0")  # Pinned for audit!
    add_dep("com.acme.services", "compliance-service", "1.0.0", "com.acme.security", "acme-auth", "2.1.0")

    # ==========================================================================
    # ADDITIONAL VERSION PINNING: slf4j-api
    # Apps pin slf4j to specific versions for logging framework compatibility
    # ==========================================================================

    # Some apps pin slf4j to specific versions for logging framework compatibility
    add_dep("com.acme.services", "legacy-adapter", "1.0.0", "org.slf4j", "slf4j-api", "1.7.36")  # Pinned for logback 1.2.x compat
    add_dep("com.acme.services", "legacy-adapter", "1.0.0", "ch.qos.logback", "logback-classic", "1.2.11")
    add_dep("com.acme.services", "legacy-adapter", "1.0.0", "com.acme.core", "acme-common", "1.2.0")

    add_dep("com.acme.services", "modern-gateway", "1.0.0", "org.slf4j", "slf4j-api", "2.0.9")  # Latest SLF4J 2.x
    add_dep("com.acme.services", "modern-gateway", "1.0.0", "ch.qos.logback", "logback-classic", "1.4.11")
    add_dep("com.acme.services", "modern-gateway", "1.0.0", "com.acme.http", "acme-web-common", "2.0.0")

    # ==========================================================================
    # ADDITIONAL VERSION PINNING: guava
    # Different teams have pinned guava to different versions
    # ==========================================================================

    # Different teams have pinned guava to different versions
    add_dep("com.acme.services", "cache-service", "1.0.0", "com.google.guava", "guava", "31.1-jre")  # Stable LTS
    add_dep("com.acme.services", "cache-service", "1.0.0", "com.acme.data", "acme-cache", "1.1.0")

    add_dep("com.acme.services", "search-indexer", "1.0.0", "com.google.guava", "guava", "32.0.0-jre")  # For specific feature
    add_dep("com.acme.services", "search-indexer", "1.0.0", "com.acme.data", "acme-repository", "2.0.0")

    add_dep("com.acme.services", "ml-inference", "1.0.0", "com.google.guava", "guava", "33.0.0-jre")  # Latest for perf
    add_dep("com.acme.services", "ml-inference", "1.0.0", "com.acme.experimental", "acme-ml-pipeline", "GA")

    # ==========================================================================
    # Self-referential libraries (simple cycles - depends on itself)
    # These represent plugin systems or module registries that can reference themselves
    # ==========================================================================

    # Plugin loader that can load itself as a plugin
    add_dep("com.acme.recursive", "acme-plugin-loader", "1.0.0", "com.acme.core", "acme-common", "1.1.0")
    add_dep("com.acme.recursive", "acme-plugin-loader", "1.0.0", "com.acme.recursive", "acme-plugin-loader", "1.0.0")  # Self-reference
    add_dep("com.acme.recursive", "acme-plugin-loader", "1.1.0", "com.acme.core", "acme-common", "2.0.0")
    add_dep("com.acme.recursive", "acme-plugin-loader", "1.1.0", "com.acme.recursive", "acme-plugin-loader", "1.1.0")  # Self-reference

    # Module registry that references itself for nested modules
    add_dep("com.acme.recursive", "acme-module-registry", "1.0.0", "com.acme.core", "acme-config", "2.0.0")
    add_dep("com.acme.recursive", "acme-module-registry", "1.0.0", "com.acme.recursive", "acme-module-registry", "1.0.0")  # Self-reference

    # ==========================================================================
    # CYCLIC DEPENDENCY DEMO APPLICATIONS
    # These applications use the self-referential libraries for demo purposes
    #
    # Visualization endpoint (spring layout, shows cycles in red):
    #   /visualizations/dependencies?project_name=<name>&version_name=<version>
    #
    # Self-dependencies report (lists all cycles):
    #   /reports/self-dependencies
    # ==========================================================================

    # plugin-manager: Application that manages plugins using the self-referential plugin-loader
    # Visualization: /visualizations/dependencies?project_name=plugin-manager&version_name=1.0.0
    # Shows: acme-plugin-loader:1.0.0 self-loop cycle (red dashed edge)
    add_dep("com.acme.apps", "plugin-manager", "1.0.0", "com.acme.recursive", "acme-plugin-loader", "1.0.0")
    add_dep("com.acme.apps", "plugin-manager", "1.0.0", "com.acme.http", "acme-web-common", "1.1.0")
    add_dep("com.acme.apps", "plugin-manager", "1.0.0", "com.acme.data", "acme-repository", "1.1.0")
    add_dep("com.acme.apps", "plugin-manager", "2.0.0", "com.acme.recursive", "acme-plugin-loader", "1.1.0")
    add_dep("com.acme.apps", "plugin-manager", "2.0.0", "com.acme.http", "acme-web-common", "2.0.0")
    add_dep("com.acme.apps", "plugin-manager", "2.0.0", "com.acme.data", "acme-repository", "2.0.0")

    # module-loader: Application that uses the self-referential module-registry
    # Visualization: /visualizations/dependencies?project_name=module-loader&version_name=1.0.0
    # Shows: acme-module-registry:1.0.0 self-loop cycle (red dashed edge)
    add_dep("com.acme.apps", "module-loader", "1.0.0", "com.acme.recursive", "acme-module-registry", "1.0.0")
    add_dep("com.acme.apps", "module-loader", "1.0.0", "com.acme.http", "acme-web-common", "2.0.0")
    add_dep("com.acme.apps", "module-loader", "1.0.0", "com.acme.core", "acme-config", "2.0.0")

    # extensible-platform: Uses BOTH cyclic libraries - BEST comprehensive cycle demo
    # Visualization: /visualizations/dependencies?project_name=extensible-platform&version_name=1.0.0
    # Shows: Both acme-plugin-loader:1.1.0 and acme-module-registry:1.0.0 self-loops
    add_dep("com.acme.apps", "extensible-platform", "1.0.0", "com.acme.recursive", "acme-plugin-loader", "1.1.0")
    add_dep("com.acme.apps", "extensible-platform", "1.0.0", "com.acme.recursive", "acme-module-registry", "1.0.0")
    add_dep("com.acme.apps", "extensible-platform", "1.0.0", "com.acme.http", "acme-web-common", "2.0.0")
    add_dep("com.acme.apps", "extensible-platform", "1.0.0", "com.acme.messaging", "acme-kafka", "2.0.0")

    return deps


def propagate_scan_ids(
    versions: list[Version],
    dependencies: list[tuple[str, str, str, str, str, str]]
) -> None:
    """Propagate scan_ids from applications to all their transitive dependencies."""
    # Build lookup maps
    version_map: dict[tuple[str, str, str], Version] = {
        (v.project_group, v.project_name, v.name): v for v in versions
    }

    # Build adjacency list (from -> list of to)
    adj: dict[tuple[str, str, str], list[tuple[str, str, str]]] = {}
    for from_g, from_n, from_v, to_g, to_n, to_v in dependencies:
        key = (from_g, from_n, from_v)
        if key not in adj:
            adj[key] = []
        adj[key].append((to_g, to_n, to_v))

    # For each application, BFS to propagate scan_id
    for version in versions:
        if version.is_application and version.scan_id:
            # BFS from this application
            visited: set[tuple[str, str, str]] = set()
            queue = [(version.project_group, version.project_name, version.name)]
            visited.add((version.project_group, version.project_name, version.name))

            while queue:
                current = queue.pop(0)
                current_version = version_map.get(current)
                if current_version and version.scan_id not in current_version.scan_ids:
                    current_version.scan_ids.append(version.scan_id)

                # Add dependencies to queue
                for dep in adj.get(current, []):
                    if dep not in visited:
                        visited.add(dep)
                        queue.append(dep)


def calculate_degrees(
    versions: list[Version],
    dependencies: list[tuple[str, str, str, str, str, str]]
) -> None:
    """Calculate inDegree and outDegree for all internal nodes."""
    # Reset degrees
    for v in versions:
        v.in_degree = 0
        v.out_degree = 0

    # Build lookup map
    version_map: dict[tuple[str, str, str], Version] = {
        (v.project_group, v.project_name, v.name): v for v in versions
    }

    # Count degrees
    for from_g, from_n, from_v, to_g, to_n, to_v in dependencies:
        from_key = (from_g, from_n, from_v)
        to_key = (to_g, to_n, to_v)

        from_version = version_map.get(from_key)
        to_version = version_map.get(to_key)

        if from_version:
            from_version.out_degree += 1
        if to_version:
            to_version.in_degree += 1


def _log(msg: str) -> None:
    """Print and flush immediately so output appears before potential crash."""
    print(msg, flush=True)


def create_graph(
    host: str,
    port: int,
    password: str | None = None,
    graph_name: str = "acme_corp",
    ssl_enabled: bool = False,
    ssl_ca_certs: str | None = None,
) -> None:
    """Create and populate the FalkorDB graph with acme-corp demo data."""
    _log(f"Connecting to FalkorDB at {host}:{port} (ssl={ssl_enabled}, ca={ssl_ca_certs})...")

    socket_timeout = float(os.environ.get("FALKORDB_SOCKET_TIMEOUT", "60.0"))
    connect_timeout = float(os.environ.get("FALKORDB_CONNECT_TIMEOUT", "30.0"))

    connection_kwargs: dict[str, object] = {
        "host": host,
        "port": port,
        "socket_timeout": socket_timeout,
        "socket_connect_timeout": connect_timeout,
    }
    if password:
        connection_kwargs["password"] = password
    if ssl_enabled:
        connection_kwargs["ssl"] = True
        connection_kwargs["ssl_cert_reqs"] = ssl.CERT_REQUIRED
        if ssl_ca_certs:
            connection_kwargs["ssl_ca_certs"] = ssl_ca_certs

    _log("Creating FalkorDB client...")
    db = FalkorDB(**connection_kwargs)
    _log("Selecting graph...")
    graph = db.select_graph(graph_name)

    _log(f"Creating {graph_name} graph...")

    # Clear existing data if any (first query triggers actual connection)
    try:
        _log("Testing connection (MATCH/DETACH DELETE)...")
        graph.query("MATCH (n) DETACH DELETE n")
        _log("Cleared existing data")
    except Exception as e:
        _log(f"Note: {e}")

    # Create versions and dependencies
    versions = create_versions()
    dependencies = define_dependencies()

    # Propagate scan_ids
    propagate_scan_ids(versions, dependencies)

    # Calculate degrees
    calculate_degrees(versions, dependencies)

    _log(f"Creating {len(versions)} version nodes...")

    # Create nodes
    for v in versions:
        # Build labels
        labels = ["Version"]
        if v.is_application:
            labels.append("Application")
        if v.is_library:
            labels.append("Library")
        if v.is_internal:
            labels.append("INTERNAL")

        label_str = ":".join(labels)

        # Create node with basic properties
        query = f"""
            CREATE (v:{label_str} {{
                project_group: $project_group,
                project_name: $project_name,
                name: $name,
                type: $type,
                package_url: $package_url
            }})
            RETURN v
        """
        graph.query(query, {
            "project_group": v.project_group,
            "project_name": v.project_name,
            "name": v.name,
            "type": v.node_type,
            "package_url": v.package_url,
        })

        # Set scan_ids if present
        if v.scan_ids:
            query = """
                MATCH (v:Version {project_group: $project_group, project_name: $project_name, name: $name})
                SET v.scan_ids = $scan_ids
            """
            graph.query(query, {
                "project_group": v.project_group,
                "project_name": v.project_name,
                "name": v.name,
                "scan_ids": v.scan_ids,
            })

        # Set application-specific properties
        if v.is_application and v.scan_id:
            query = """
                MATCH (v:Version {project_group: $project_group, project_name: $project_name, name: $name})
                SET v.scan_id = $scan_id,
                    v.app_id = $app_id,
                    v.public_id = $public_id,
                    v.repo_url = $repo_url
            """
            graph.query(query, {
                "project_group": v.project_group,
                "project_name": v.project_name,
                "name": v.name,
                "scan_id": v.scan_id,
                "app_id": v.app_id,
                "public_id": v.public_id,
                "repo_url": v.repo_url,
            })

        # Set internal node properties (inDegree, outDegree)
        if v.is_internal:
            query = """
                MATCH (v:Version {project_group: $project_group, project_name: $project_name, name: $name})
                SET v.inDegree = $in_degree,
                    v.outDegree = $out_degree
            """
            graph.query(query, {
                "project_group": v.project_group,
                "project_name": v.project_name,
                "name": v.name,
                "in_degree": v.in_degree,
                "out_degree": v.out_degree,
            })

    _log(f"Creating {len(dependencies)} DEPENDENCY_VERSION relationships...")

    # Create relationships
    for from_g, from_n, from_v, to_g, to_n, to_v in dependencies:
        query = """
            MATCH (from:Version {project_group: $from_g, project_name: $from_n, name: $from_v})
            MATCH (to:Version {project_group: $to_g, project_name: $to_n, name: $to_v})
            CREATE (from)-[:DEPENDENCY_VERSION]->(to)
        """
        try:
            graph.query(query, {
                "from_g": from_g, "from_n": from_n, "from_v": from_v,
                "to_g": to_g, "to_n": to_n, "to_v": to_v,
            })
        except Exception as e:
            _log(f"Warning: Failed to create edge {from_g}:{from_n}:{from_v} -> {to_g}:{to_n}:{to_v}: {e}")

    # Create Defect nodes and VERSION_DEFECT relationships
    _log(f"Creating {len(DEFECTS)} defect nodes and relationships...")

    for defect in DEFECTS:
        # Create defect node
        query = """
            CREATE (d:Defect {
                defect_id: $defect_id,
                title: $title,
                description: $description,
                severity: $severity,
                cvss_score: $cvss_score,
                cwe_id: $cwe_id,
                published_date: $published_date
            })
        """
        graph.query(query, {
            "defect_id": defect.defect_id,
            "title": defect.title,
            "description": defect.description,
            "severity": defect.severity,
            "cvss_score": defect.cvss_score,
            "cwe_id": defect.cwe_id,
            "published_date": defect.published_date,
        })

        # Set affected_versions
        if defect.affected_versions:
            query = """
                MATCH (d:Defect {defect_id: $defect_id})
                SET d.affected_versions = $affected_versions
            """
            graph.query(query, {
                "defect_id": defect.defect_id,
                "affected_versions": defect.affected_versions,
            })

        # Create VERSION_DEFECT relationships
        for affected in defect.affected_versions:
            # Parse "name:version" format
            if ":" in affected:
                name, ver = affected.rsplit(":", 1)
                # Find matching third-party library
                for v in versions:
                    if v.project_name == name and v.name == ver and not v.is_internal:
                        query = """
                            MATCH (v:Version {project_group: $group, project_name: $name, name: $version})
                            MATCH (d:Defect {defect_id: $defect_id})
                            CREATE (v)-[:VERSION_DEFECT]->(d)
                        """
                        try:
                            graph.query(query, {
                                "group": v.project_group,
                                "name": v.project_name,
                                "version": v.name,
                                "defect_id": defect.defect_id,
                            })
                        except Exception:
                            pass  # Ignore if relationship already exists

    # Create indexes for performance
    _log("Creating indexes...")
    try:
        graph.query("CREATE INDEX FOR (v:Version) ON (v.project_name)")
    except Exception:
        pass
    try:
        graph.query("CREATE INDEX FOR (v:Version) ON (v.project_group)")
    except Exception:
        pass
    try:
        graph.query("CREATE INDEX FOR (v:Version) ON (v.name)")
    except Exception:
        pass
    try:
        graph.query("CREATE INDEX FOR (d:Defect) ON (d.defect_id)")
    except Exception:
        pass

    # Print summary statistics
    _log("\n" + "=" * 60)
    _log("GRAPH STATISTICS")
    _log("=" * 60)

    result = graph.query("MATCH (n:Version) RETURN count(n) as count")
    _log(f"Total Version nodes: {result.result_set[0][0]}")

    result = graph.query("MATCH (n:Version:INTERNAL) RETURN count(n) as count")
    _log(f"Internal (INTERNAL) nodes: {result.result_set[0][0]}")

    result = graph.query("MATCH (n:Version) WHERE NOT n:INTERNAL RETURN count(n) as count")
    _log(f"Third-party nodes: {result.result_set[0][0]}")

    result = graph.query("MATCH (n:Version:Application) RETURN count(n) as count")
    _log(f"Application nodes: {result.result_set[0][0]}")

    result = graph.query("MATCH (n:Version:Library) RETURN count(n) as count")
    _log(f"Library nodes: {result.result_set[0][0]}")

    result = graph.query("MATCH (n:Defect) RETURN count(n) as count")
    _log(f"Defect nodes: {result.result_set[0][0]}")

    result = graph.query("MATCH ()-[r:DEPENDENCY_VERSION]->() RETURN count(r) as count")
    _log(f"DEPENDENCY_VERSION relationships: {result.result_set[0][0]}")

    result = graph.query("MATCH ()-[r:VERSION_DEFECT]->() RETURN count(r) as count")
    _log(f"VERSION_DEFECT relationships: {result.result_set[0][0]}")

    # Show high centrality nodes
    _log("\n--- High Inward Centrality (most depended upon) ---")
    result = graph.query("""
        MATCH (v:Version:INTERNAL)
        WHERE v.inDegree > 0
        RETURN v.project_group, v.project_name, v.name, v.inDegree
        ORDER BY v.inDegree DESC
        LIMIT 10
    """)
    for row in result.result_set:
        _log(f"  {row[0]}:{row[1]}:{row[2]} - {row[3]} dependants")

    _log("\n--- High Outward Centrality (most dependencies) ---")
    result = graph.query("""
        MATCH (v:Version:INTERNAL)
        WHERE v.outDegree > 0
        RETURN v.project_group, v.project_name, v.name, v.outDegree
        ORDER BY v.outDegree DESC
        LIMIT 10
    """)
    for row in result.result_set:
        _log(f"  {row[0]}:{row[1]}:{row[2]} - {row[3]} dependencies")

    _log("\n--- Vulnerabilities by Severity ---")
    result = graph.query("""
        MATCH (d:Defect)
        RETURN d.severity, count(d) as count
        ORDER BY count DESC
    """)
    for row in result.result_set:
        _log(f"  {row[0]}: {row[1]}")

    _log("\n" + "=" * 60)
    _log(f"Graph '{graph_name}' created successfully!")
    _log("=" * 60)


def main():
    """Main entry point."""
    try:
        host = os.environ.get("FALKORDB_HOST", "localhost")
        port = int(os.environ.get("FALKORDB_PORT", "6379"))
        password = os.environ.get("FALKORDB_PASSWORD")
        graph_name = os.environ.get("FALKORDB_GRAPH_NAME", "acme_corp")
        ssl_enabled = os.environ.get("FALKORDB_SSL", "false").lower() == "true"
        ssl_ca_certs = os.environ.get("FALKORDB_CA_FILE") or os.environ.get("FALKORDB_CACERTS")

        create_graph(
            host=host,
            port=port,
            password=password,
            graph_name=graph_name,
            ssl_enabled=ssl_enabled,
            ssl_ca_certs=ssl_ca_certs,
        )
    except Exception as e:
        _log(f"FATAL: {e}")
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
