"""
Persistence layer for FalkorDB graph database operations.

This module provides the Persistence class for storing and retrieving
AppSec data from a FalkorDB graph database.
"""

import logging
import re
from typing import Any, LiteralString, Optional, cast
from falkordb import FalkorDB, Graph

from .model import LicenseRiskCategory, Project, Version, Defect, VersionDefect

logger = logging.getLogger(__name__)

INTERNAL_PREFIX_FIELDS: frozenset[str] = frozenset({"group", "name", "purl"})

# CycloneDX 1.6 component type taxonomy (used as Cypher node labels).
# Values are validated against this set before interpolation into queries
# to prevent Cypher injection via externally-supplied type strings.
ALLOWED_PROJECT_TYPES: frozenset[str] = frozenset({
    "Application",
    "Library",
    "Framework",
    "Container",
    "Platform",
    "Device",
    "Firmware",
    "File",
    "Machine-Learning-Model",
    "Data",
})

_SAFE_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]*$")


class Persistence:
    """Persistence class for FalkorDB database operations.

    Provides methods for creating and querying nodes and edges in the
    dependency graph, including Projects, Versions, Defects, and their
    relationships.

    Args:
        host: The host for the FalkorDB database.
        port: The port for the FalkorDB database.
        graph_name: The name of the graph to use.
        password: The password for the FalkorDB database.
        ssl: Whether to use SSL for the FalkorDB database.
        ssl_ca_certs: The CA certificates for the FalkorDB database.
        internal_prefixes: List of (field, prefix) tuples for INTERNAL
            label assignment. See :meth:`parse_internal_prefixes`.
    """

    def __init__(
        self,
        host: str,
        port: int,
        graph_name: str,
        password: str,
        ssl: bool = True,
        ssl_ca_certs: Optional[str] = None,
        internal_prefixes: Optional[list[tuple[str, str]]] = None,
    ):
        """Initialize the Persistence class with database connection.

        Args:
            host: The host for the FalkorDB database.
            port: The port for the FalkorDB database.
            graph_name: The name of the graph to use.
            password: The password for the FalkorDB database.
            ssl: Whether to use SSL for the FalkorDB database.
            ssl_ca_certs: The CA certificates for the FalkorDB database.
            internal_prefixes: List of (field, prefix) tuples used to decide
                whether a project should receive the INTERNAL label. Supported
                fields: ``"group"``, ``"name"``, ``"purl"``.
                Example: ``[("group", "com.acme"), ("name", "acme-")]``.
        """
        self.db = FalkorDB(
            host=host,
            port=port,
            password=password,
            ssl=ssl,
            ssl_ca_certs=ssl_ca_certs,
        )
        self.graph: Graph = self.db.select_graph(graph_name)
        self.internal_prefixes: list[tuple[str, str]] = internal_prefixes or []
        for field, _ in self.internal_prefixes:
            if field not in INTERNAL_PREFIX_FIELDS:
                raise ValueError(
                    f"Invalid internal prefix field {field!r}: "
                    f"must be one of {sorted(INTERNAL_PREFIX_FIELDS)}"
                )

    def is_internal(self, project: Project) -> bool:
        """Check whether a project matches any configured internal prefix.

        Args:
            project: The project to check.

        Returns:
            True if any (field, prefix) pair matches the project's attribute.
        """
        for field, prefix in self.internal_prefixes:
            value = getattr(project, field, None) or ""
            if value.startswith(prefix):
                return True
        return False

    @staticmethod
    def parse_internal_prefixes(env_value: str) -> list[tuple[str, str]]:
        """Parse an ``INTERNAL_PREFIXES`` environment variable string.

        Format: ``"field:prefix,field:prefix,..."``
        Example: ``"group:com.acme,name:acme-"``

        Args:
            env_value: The raw environment variable value.

        Returns:
            List of validated (field, prefix) tuples.

        Raises:
            ValueError: If a field name is not in INTERNAL_PREFIX_FIELDS or
                a token is malformed.
        """
        if not env_value or not env_value.strip():
            return []

        prefixes: list[tuple[str, str]] = []
        for token in env_value.split(","):
            token = token.strip()
            if not token:
                continue
            if ":" not in token:
                raise ValueError(
                    f"Malformed INTERNAL_PREFIXES token {token!r}: "
                    "expected 'field:prefix'"
                )
            field, prefix = token.split(":", maxsplit=1)
            field = field.strip()
            if field not in INTERNAL_PREFIX_FIELDS:
                raise ValueError(
                    f"Invalid internal prefix field {field!r}: "
                    f"must be one of {sorted(INTERNAL_PREFIX_FIELDS)}"
                )
            prefixes.append((field, prefix))
        return prefixes

    @staticmethod
    def _validate_label(label: str, allowed: frozenset[str]) -> str:
        """Validate a Cypher node label against an allowlist.

        Prevents Cypher injection by ensuring only pre-approved, safe
        identifiers are interpolated into query strings.

        Args:
            label: The candidate label string.
            allowed: Set of permitted label values.

        Returns:
            The validated label.

        Raises:
            ValueError: If the label is not in the allowlist or contains
                unsafe characters.
        """
        if label not in allowed:
            raise ValueError(
                f"Invalid node label {label!r}: must be one of {sorted(allowed)}"
            )
        if not _SAFE_IDENTIFIER_RE.match(label):
            raise ValueError(
                f"Node label {label!r} contains unsafe characters"
            )
        return label

    def run_query(
        self,
        query: LiteralString,
        params: Optional[dict[str, Any]] = None,
    ):
        """Execute a query on the graph.

        Args:
            query: The Cypher query to run.
            params: Optional parameters for the query.

        Returns:
            The result of the query.
        """
        return self.graph.query(q=query, params=params, timeout=60000)

    # Query building utilities

    @staticmethod
    def _append_to_main_fields(
        field_name: str,
        value: Optional[Any],
        params: dict[str, Any],
        main_fields: str,
    ) -> tuple[str, dict[str, Any]]:
        """Build main fields for Neo4j MERGE query.

        Ensures values are not None because MERGE doesn't like null values.

        Args:
            field_name: The name of the field to add.
            value: The value to add to parameters.
            params: The parameter dictionary to update.
            main_fields: The main fields string to append to.

        Returns:
            Tuple of (updated main_fields string, updated params dict).
        """
        if value is not None:
            params[field_name] = value
            if len(main_fields) > 0:
                main_fields += ','
            main_fields += f'{field_name}: ${field_name}'
        return main_fields, params

    @staticmethod
    def _append_to_additional_fields(
        field_name: str,
        value: Any,
        params: dict[str, Any],
        additional_fields: str,
    ) -> tuple[str, dict[str, Any]]:
        """Build additional fields for Neo4j ON MATCH/ON CREATE.

        Args:
            field_name: The name of the field to add.
            value: The value to add to parameters.
            params: The parameter dictionary to update.
            additional_fields: The additional fields string to append to.

        Returns:
            Tuple of (updated additional_fields string, updated params dict).
        """
        if value is not None:
            if len(additional_fields) == 0:
                additional_fields += 'SET\n\t'
            else:
                additional_fields += ',\n\t'
            params[field_name] = value
            additional_fields += f'n.{field_name} = ${field_name}'
        return additional_fields, params

    @staticmethod
    def _create_extended_query(
        name_value_pairs: list[tuple[str, Any]],
        params: dict[str, Any],
    ) -> tuple[str, dict[str, Any]]:
        """Create ON MATCH and ON CREATE sections for MERGE queries.

        Due to a limitation of the MERGE feature in Cypher, this utility
        function simplifies creation of the ON MATCH and ON CREATE sections
        that update property values of a Node or Edge.

        Args:
            name_value_pairs: List of (property_name, property_value) tuples.
            params: The parameter dictionary for the parameterized query.

        Returns:
            Tuple of (query section string, updated params dict).
        """
        additional_fields = ""
        for name, value in name_value_pairs:
            additional_fields, params = Persistence._append_to_additional_fields(
                field_name=name,
                value=value,
                params=params,
                additional_fields=additional_fields,
            )

        if len(additional_fields) > 0:
            extended_query = f"""
            ON MATCH
                {additional_fields}
            ON CREATE 
                {additional_fields}
            """
        else:
            extended_query = ''
        return extended_query, params

    @staticmethod
    def _get_purl_prefix(purl: str) -> str:
        """Extract project part of purl without version info.

        Args:
            purl: The package URL to extract prefix from.

        Returns:
            The purl prefix (everything before the version).
        """
        return purl.rsplit('@')[0] + '@'

    # Node creation methods

    def create_project_version(self, version: Version) -> None:
        """Persist a Version node and associate it with its project.

        Creates a Version node in the database and associates it with
        a HAS_VERSION edge if the project is an application.

        Args:
            version: The Version to persist.

        Raises:
            ValueError: If version or version.project is None.
        """
        if version is None:
            logger.warning("Cannot create project version: version is None")
            return

        if version.project is None:
            logger.warning(f"Cannot create project version: project is None for version {version.version}")
            return

        if version.project.purl is None or len(version.project.purl) == 0:
            logger.debug(f"Version has no purl: {version}")

        params: dict[str, Any] = {}
        main_fields = ""

        main_fields, params = self._append_to_main_fields(
            field_name='name',
            value=version.version,
            params=params,
            main_fields=main_fields,
        )
        main_fields, params = self._append_to_main_fields(
            field_name='project_name',
            value=version.project.name if version.project else None,
            params=params,
            main_fields=main_fields,
        )
        main_fields, params = self._append_to_main_fields(
            field_name='project_group',
            value=version.project.group if version.project else None,
            params=params,
            main_fields=main_fields,
        )

        name_value_pairs: list[tuple[str, Any]] = [
            ('app_id', version.project.application_id if version.project else None),
            ('public_id', version.project.public_app_id if version.project else None),
            ('type', version.project.type if version.project else None),
            ('package_url', version.project.purl if version.project else None),
            ('repo', version.project.repo if version.project else None),
            ('sbom_format', version.sbom_format),
        ]

        if version.project and version.project.type == 'application':
            name_value_pairs.append(('scan_id', version.scan_id))

        extended_query, params = self._create_extended_query(
            name_value_pairs=name_value_pairs,
            params=params,
        )

        raw_type = str(version.project.type).title() if version.project and version.project.type else "Library"
        project_type = self._validate_label(raw_type, ALLOWED_PROJECT_TYPES)

        internal = version.project is not None and self.is_internal(version.project)
        internal_label = ":INTERNAL" if internal else ""

        # Safety: project_type is validated against ALLOWED_PROJECT_TYPES;
        # internal_label is a hardcoded literal chosen by a boolean;
        # main_fields/extended_query use only hardcoded field names with
        # parameterized values — cast(LiteralString, ...) is acceptable.
        query = f"""
            MERGE (
                n:Version:{project_type}{internal_label} {{
                    {main_fields}
                }}
            )
            {extended_query}
        """

        logger.info(
            "Creating Version node for project=%s version=%s type=%s internal=%s",
            version.project.name if version.project else "unknown",
            version.version,
            project_type,
            internal,
        )
        logger.debug("Version MERGE query: %s | params: %s", query, params)
        self.run_query(query=cast(LiteralString, query), params=params)

        # Add scan_id to the version's scan_ids list
        if version.version and version.project and version.project.name:
            logger.debug(
                "Adding scan ID %s to version %s of project %s",
                version.scan_id,
                version.version,
                version.project.name,
            )
            self.run_query(
                query="""
                    MATCH (p:Version {name: $version_name, project_name: $project_name, project_group: $project_group})
                    WHERE NOT $scan_id IN coalesce(p.scan_ids, [])
                    SET p.scan_ids = coalesce(p.scan_ids, []) + [$scan_id]
                """,
                params={
                    'version_name': version.version,
                    'project_name': version.project.name,
                    'project_group': version.project.group,
                    'scan_id': version.scan_id,
                },
            )

    def create_defect(self, defect: Defect) -> None:
        """Persist a Defect node to the database.

        Args:
            defect: The Defect to persist.
        """
        if defect is None:
            logger.warning("Cannot create defect: defect is None")
            return

        if defect.id is None:
            logger.warning("Cannot create defect: defect.id is None")
            return

        params = {'id': defect.id}

        name_value_pairs: list[tuple[str, Any]] = [
            ('source', defect.source),
            ('severity', defect.severity),
            ('cwes', defect.cwes),
            ('cvss', defect.cvss),
            ('cvss_string', defect.cvss_string),
            ('description', defect.description),
            ('last_enriched_at', defect.last_enriched_at),
            ('enrichment_source', defect.enrichment_source),
            ('aliases', defect.aliases if defect.aliases else None),
        ]

        extended_query, params = self._create_extended_query(
            name_value_pairs=name_value_pairs,
            params=params,
        )

        # Safety: the only dynamic part is extended_query which is built from
        # hardcoded field names with parameterized values — no external
        # identifiers are interpolated.
        query = f"""
            MERGE (
                n:Defect {{
                    id: $id
                }}
            )
            {extended_query}
        """
        logger.info("Creating Defect node id=%s severity=%s", defect.id, defect.severity)
        logger.debug("Defect MERGE query: %s | params: %s", query, params)
        self.run_query(query=cast(LiteralString, query), params=params)

    def update_defect_enrichment(
        self,
        defect_id: str,
        source: str,
        aliases: list[str] | None = None,
        timestamp: str | None = None,
    ) -> None:
        """Update enrichment metadata on an existing Defect node.

        Args:
            defect_id: The defect identifier.
            source: The enrichment source (e.g. "osv").
            aliases: List of cross-reference IDs.
            timestamp: ISO timestamp of enrichment.
        """
        if not defect_id:
            return

        params: dict[str, Any] = {
            "defect_id": defect_id,
            "enrichment_source": source,
            "last_enriched_at": timestamp,
        }
        alias_clause = ""
        if aliases:
            params["aliases"] = aliases
            alias_clause = ",\n                d.aliases = $aliases"

        query = f"""
            MATCH (d:Defect {{id: $defect_id}})
            SET d.enrichment_source = $enrichment_source,
                d.last_enriched_at = $last_enriched_at
                {alias_clause}
        """
        logger.info("Updating enrichment on defect %s source=%s", defect_id, source)
        self.run_query(query=cast(LiteralString, query), params=params)

    def get_packages_needing_enrichment(self, older_than_hours: int = 24) -> list[str]:
        """Return purls that have never been enriched or are stale.

        A package needs enrichment if either:
        - No Defect linked to it has ``last_enriched_at`` set, or
        - All linked Defects have ``last_enriched_at`` older than the threshold.

        For packages with no linked defects, they are always included
        (they may have undiscovered vulnerabilities).

        Args:
            older_than_hours: Hours after which enrichment is considered stale.

        Returns:
            List of package URL strings.
        """
        result = self.run_query(
            query=(
                "MATCH (v:Version) WHERE v.package_url IS NOT NULL "
                "RETURN DISTINCT v.package_url AS purl"
            ),
        )
        return [row["purl"] for row in result.result_set if row.get("purl")]

    def create_policy_annotation(
        self,
        annotation_id: str,
        policy_type: str,
        justification: str,
        created_by: str,
        created_at: str,
        expires_at: str | None = None,
    ) -> None:
        """Create a PolicyAnnotation node.

        Args:
            annotation_id: Unique ID (UUID).
            policy_type: One of "bad", "good", "hold".
            justification: Reason for the annotation.
            created_by: Username of the creator.
            created_at: ISO timestamp.
            expires_at: Optional expiry ISO timestamp.
        """
        if not annotation_id:
            logger.warning("Cannot create policy annotation: annotation_id is empty")
            return

        from .model import PolicyType
        safe_type = PolicyType.from_str(policy_type)

        params: dict[str, Any] = {
            "annotation_id": annotation_id,
            "policy_type": safe_type,
            "justification": justification,
            "created_by": created_by,
            "created_at": created_at,
        }

        expires_clause = ""
        if expires_at:
            params["expires_at"] = expires_at
            expires_clause = ", n.expires_at = $expires_at"

        query = f"""
            MERGE (n:PolicyAnnotation {{annotation_id: $annotation_id}})
            ON CREATE SET
                n.type = $policy_type,
                n.justification = $justification,
                n.created_by = $created_by,
                n.created_at = $created_at
                {expires_clause}
            ON MATCH SET
                n.type = $policy_type,
                n.justification = $justification
                {expires_clause}
        """
        logger.info("Creating PolicyAnnotation id=%s type=%s", annotation_id, safe_type)
        self.run_query(query=cast(LiteralString, query), params=params)

    def link_policy_to_version(self, purl: str, annotation_id: str) -> None:
        """Create a HAS_POLICY edge between a Version and a PolicyAnnotation.

        Args:
            purl: The package URL of the version.
            annotation_id: The annotation ID.
        """
        if not purl or not annotation_id:
            logger.warning(
                "Cannot create HAS_POLICY edge: purl=%s annotation_id=%s",
                purl, annotation_id,
            )
            return

        query = """
            MATCH (v:Version {package_url: $purl})
            MATCH (a:PolicyAnnotation {annotation_id: $annotation_id})
            MERGE (v)-[:HAS_POLICY]->(a)
        """
        logger.info("Creating HAS_POLICY edge purl=%s -> annotation=%s", purl, annotation_id)
        self.run_query(query=query, params={"purl": purl, "annotation_id": annotation_id})

    def delete_policy_annotation(self, annotation_id: str) -> bool:
        """Delete a PolicyAnnotation and its edges.

        Args:
            annotation_id: The annotation ID to delete.

        Returns:
            True if a node was deleted, False if not found.
        """
        if not annotation_id:
            return False

        result = self.run_query(
            query="""
                MATCH (a:PolicyAnnotation {annotation_id: $annotation_id})
                DETACH DELETE a
                RETURN 1 AS deleted
            """,
            params={"annotation_id": annotation_id},
        )
        deleted = bool(result.result_set)
        if deleted:
            logger.info("Deleted PolicyAnnotation id=%s", annotation_id)
        return deleted

    def create_point_of_contact(
        self,
        email: str,
        team: str | None = None,
        slack_channel: str | None = None,
    ) -> None:
        """Create or update a PointOfContact node.

        Uses ``email`` as the MERGE key.

        Args:
            email: Contact email address.
            team: Team name.
            slack_channel: Slack channel.
        """
        if not email:
            logger.warning("Cannot create point of contact: email is empty")
            return

        params: dict[str, Any] = {"email": email}
        name_value_pairs: list[tuple[str, Any]] = [
            ("team", team),
            ("slack_channel", slack_channel),
        ]

        extended_query, params = self._create_extended_query(
            name_value_pairs=name_value_pairs,
            params=params,
        )

        query = f"""
            MERGE (n:PointOfContact {{email: $email}})
            {extended_query}
        """
        logger.info("Creating PointOfContact email=%s", email)
        self.run_query(query=cast(LiteralString, query), params=params)

    def link_contact_to_version(self, email: str, purl: str) -> None:
        """Create a CONTACT_FOR edge between a PointOfContact and a Version.

        Args:
            email: The contact email.
            purl: The package URL of the version.
        """
        if not email or not purl:
            logger.warning(
                "Cannot create CONTACT_FOR edge: email=%s purl=%s", email, purl,
            )
            return

        query = """
            MATCH (c:PointOfContact {email: $email})
            MATCH (v:Version {package_url: $purl})
            MERGE (c)-[:CONTACT_FOR]->(v)
        """
        logger.info("Creating CONTACT_FOR edge email=%s -> purl=%s", email, purl)
        self.run_query(query=query, params={"email": email, "purl": purl})

    def create_vex_statement(
        self,
        statement_id: str,
        status: str,
        justification: str | None = None,
        impact_statement: str | None = None,
        action_statement: str | None = None,
        source_document: str | None = None,
        timestamp: str | None = None,
    ) -> None:
        """Create or update a VexStatement node.

        Args:
            statement_id: Unique ID (UUID).
            status: One of not_affected, affected, fixed, under_investigation.
            justification: Reason for the status.
            impact_statement: Impact description.
            action_statement: Recommended action.
            source_document: Source document URI.
            timestamp: ISO timestamp.
        """
        if not statement_id:
            logger.warning("Cannot create VEX statement: statement_id is empty")
            return

        from .model import VexStatus
        safe_status = VexStatus.from_str(status)

        params: dict[str, Any] = {"statement_id": statement_id}
        name_value_pairs: list[tuple[str, Any]] = [
            ("status", safe_status),
            ("justification", justification),
            ("impact_statement", impact_statement),
            ("action_statement", action_statement),
            ("source_document", source_document),
            ("timestamp", timestamp),
        ]

        extended_query, params = self._create_extended_query(
            name_value_pairs=name_value_pairs,
            params=params,
        )

        query = f"""
            MERGE (n:VexStatement {{statement_id: $statement_id}})
            {extended_query}
        """
        logger.info("Creating VexStatement id=%s status=%s", statement_id, safe_status)
        self.run_query(query=cast(LiteralString, query), params=params)

    def link_vex_to_version(self, statement_id: str, purl: str) -> None:
        """Create a HAS_VEX edge between a Version and a VexStatement.

        Args:
            statement_id: The VEX statement ID.
            purl: The package URL of the version.
        """
        if not statement_id or not purl:
            return

        query = """
            MATCH (v:Version {package_url: $purl})
            MATCH (s:VexStatement {statement_id: $statement_id})
            MERGE (v)-[:HAS_VEX]->(s)
        """
        logger.info("Creating HAS_VEX edge purl=%s -> statement=%s", purl, statement_id)
        self.run_query(query=query, params={"purl": purl, "statement_id": statement_id})

    def link_vex_to_defect(self, statement_id: str, defect_id: str) -> None:
        """Create a REFERS_TO edge between a VexStatement and a Defect.

        Args:
            statement_id: The VEX statement ID.
            defect_id: The defect/vulnerability ID.
        """
        if not statement_id or not defect_id:
            return

        query = """
            MATCH (s:VexStatement {statement_id: $statement_id})
            MATCH (d:Defect {id: $defect_id})
            MERGE (s)-[:REFERS_TO]->(d)
        """
        logger.info("Creating REFERS_TO edge statement=%s -> defect=%s", statement_id, defect_id)
        self.run_query(
            query=query,
            params={"statement_id": statement_id, "defect_id": defect_id},
        )

    # Source repository methods

    def create_source_repository(
        self,
        url: str,
        vcs_type: str | None = None,
        namespace: str | None = None,
        name: str | None = None,
        tag: str | None = None,
        commit: str | None = None,
    ) -> None:
        """Create or update a SourceRepository node.

        Uses ``url`` as the MERGE key.

        Args:
            url: Canonical repository URL.
            vcs_type: Version control type (e.g. "git", "svn").
            namespace: Hosting platform (e.g. "github.com").
            name: Repository path (e.g. "org/repo").
            tag: Tag for the linked version.
            commit: Commit hash for the linked version.
        """
        if not url:
            logger.warning("Cannot create source repository: url is empty")
            return

        params: dict[str, Any] = {"url": url}
        name_value_pairs: list[tuple[str, Any]] = [
            ("vcs_type", vcs_type),
            ("namespace", namespace),
            ("name", name),
            ("tag", tag),
            ("commit_hash", commit),
        ]

        extended_query, params = self._create_extended_query(
            name_value_pairs=name_value_pairs,
            params=params,
        )

        query = f"""
            MERGE (n:SourceRepository {{url: $url}})
            {extended_query}
        """
        logger.info("Creating SourceRepository url=%s", url)
        self.run_query(query=cast(LiteralString, query), params=params)

    def link_version_to_source(self, purl: str, repo_url: str) -> None:
        """Create a HAS_SOURCE edge between a Version and a SourceRepository.

        Args:
            purl: The package URL of the version.
            repo_url: The repository URL.
        """
        if not purl or not repo_url:
            logger.warning(
                "Cannot create HAS_SOURCE edge: purl=%s repo_url=%s",
                purl, repo_url,
            )
            return

        query = """
            MATCH (v:Version {package_url: $purl})
            MATCH (r:SourceRepository {url: $repo_url})
            MERGE (v)-[:HAS_SOURCE]->(r)
        """
        logger.info("Creating HAS_SOURCE edge purl=%s -> repo=%s", purl, repo_url)
        self.run_query(query=query, params={"purl": purl, "repo_url": repo_url})

    def link_version_to_source_by_name(
        self,
        project_name: str,
        project_group: str | None,
        version_name: str,
        repo_url: str,
    ) -> None:
        """Create a HAS_SOURCE edge using version identity fields.

        Useful during SBOM ingestion when the purl may not yet be set.

        Args:
            project_name: The project name.
            project_group: The project group (may be None).
            version_name: The version string.
            repo_url: The repository URL.
        """
        if not repo_url:
            return

        params: dict[str, Any] = {
            "project_name": project_name,
            "version_name": version_name,
            "repo_url": repo_url,
        }

        if project_group is not None:
            query = """
                MATCH (v:Version {name: $version_name, project_name: $project_name, project_group: $project_group})
                MATCH (r:SourceRepository {url: $repo_url})
                MERGE (v)-[:HAS_SOURCE]->(r)
            """
            params["project_group"] = project_group
        else:
            query = """
                MATCH (v:Version {name: $version_name, project_name: $project_name})
                MATCH (r:SourceRepository {url: $repo_url})
                MERGE (v)-[:HAS_SOURCE]->(r)
            """

        logger.info(
            "Creating HAS_SOURCE edge %s/%s -> %s",
            project_name, version_name, repo_url,
        )
        self.run_query(query=query, params=params)

    # Edge creation methods

    def create_dependency(self, parent: Version, child: Version) -> None:
        """Connect a dependency version to its parent version.

        Args:
            parent: The parent version.
            child: The dependency version.
        """
        if parent is None or child is None:
            logger.warning("Cannot create dependency: parent or child is None")
            return

        if parent.project is None or child.project is None:
            logger.warning("Cannot create dependency: parent.project or child.project is None")
            return

        params = {
            'child_version': child.version,
            'child_project_name': child.project.name if child.project else None,
            'parent_version': parent.version,
            'parent_project_name': parent.project.name if parent.project else None,
        }

        if parent.project.group is None:
            if parent.project.purl is None:
                logger.warning("Cannot create dependency: parent has no group or purl")
                return
            params['parent_purl_prefix'] = self._get_purl_prefix(parent.project.purl)
            pv = "pv:Version {name: $parent_version, project_name: $parent_project_name}"
            pv_where_clause = "WHERE pv.package_url STARTS WITH $parent_purl_prefix"
        else:
            params['parent_project_group'] = parent.project.group
            pv = """
            pv:Version {
                name: $parent_version, 
                project_name: $parent_project_name, 
                project_group: $parent_project_group
            }"""
            pv_where_clause = ""

        if child.project.group is None:
            if child.project.purl is None:
                logger.warning("Cannot create dependency: child has no group or purl")
                return
            params['child_purl_prefix'] = self._get_purl_prefix(child.project.purl)
            cv = "cv:Version {name: $child_version, project_name: $child_project_name}"
            cv_where_clause = "WHERE cv.package_url STARTS WITH $child_purl_prefix"
        else:
            params['child_project_group'] = child.project.group
            cv = """
            cv:Version {
                name: $child_version, 
                project_name: $child_project_name, 
                project_group: $child_project_group
            }"""
            cv_where_clause = ""

        # Safety: pv/cv/where clauses are built from hardcoded Cypher
        # fragments with parameterized values — no external identifiers.
        query = f"""
            MATCH 
            (
                {pv}
            )
            {pv_where_clause} 
            CALL {{ 
                MATCH (
                    {cv}
                )
                {cv_where_clause}
                RETURN cv
            }}
            MERGE (pv)-[:DEPENDENCY_VERSION]->(cv)
        """
        logger.info(
            "Creating dependency edge %s/%s -> %s/%s",
            parent.project.name if parent.project else "?",
            parent.version,
            child.project.name if child.project else "?",
            child.version,
        )
        logger.debug("Dependency MERGE query: %s | params: %s", query, params)
        self.run_query(query=cast(LiteralString, query), params=params)

    def create_version_defect(self, version_defect: VersionDefect) -> None:
        """Connect a project version to a Defect.

        Args:
            version_defect: The VersionDefect relationship to create.
        """
        if version_defect is None:
            logger.warning("Cannot create version_defect: version_defect is None")
            return

        if version_defect.project_version is None:
            logger.warning("Cannot create version_defect: project_version is None")
            return

        if version_defect.project_version.project is None:
            logger.warning("Cannot create version_defect: project_version.project is None")
            return

        if version_defect.defect is None:
            logger.warning("Cannot create version_defect: defect is None")
            return

        project = version_defect.project_version.project

        if project.group is None:
            pv = "pv:Version {name: $version_name, project_name: $project_name}"
            pv_where_clause = "WHERE pv.package_url STARTS WITH $purl_prefix"
        else:
            pv = "pv:Version {name: $version_name, project_name: $project_name, project_group: $project_group}"
            pv_where_clause = ""

        params = {
            'version_name': version_defect.project_version.version,
            'project_name': project.name,
            'id': version_defect.defect.id,
        }

        if project.group is None:
            if project.purl is None:
                logger.warning("Cannot create version_defect: project has no group or purl")
                return
            params['purl_prefix'] = self._get_purl_prefix(project.purl)
        else:
            params['project_group'] = project.group

        # Safety: pv/where clause are built from hardcoded Cypher fragments
        # with parameterized values — no external identifiers.
        query = f"""
                MATCH
                (
                    {pv}
                )
                {pv_where_clause}
                CALL {{
                    MATCH (defect:Defect {{id: $id}})
                    RETURN defect
                }}
                MERGE (pv)-[:VERSION_DEFECT]->(defect)
            """

        logger.info(
            "Creating version-defect edge version=%s project=%s defect=%s",
            version_defect.project_version.version,
            project.name,
            version_defect.defect.id,
        )
        logger.debug("VersionDefect MERGE query: %s | params: %s", query, params)
        self.run_query(query=cast(LiteralString, query), params=params)

    # License methods

    def create_license(
        self,
        spdx_id: str,
        name: str | None = None,
        url: str | None = None,
        risk_category: str | None = None,
    ) -> None:
        """Create or update a License node.

        Uses ``spdx_id`` as the MERGE key so duplicate licenses are
        deduplicated automatically.

        Args:
            spdx_id: The SPDX identifier (e.g. ``"MIT"``).
            name: Human-readable license name. Defaults to *spdx_id*.
            url: URL to the license text.
            risk_category: A :class:`LicenseRiskCategory` value.
                Unrecognised strings are normalised to ``"unknown"``.
        """
        if not spdx_id:
            logger.warning("Cannot create license: spdx_id is empty")
            return

        safe_category = LicenseRiskCategory.from_str(risk_category)

        params: dict[str, Any] = {"spdx_id": spdx_id}
        name_value_pairs: list[tuple[str, Any]] = [
            ("name", name or spdx_id),
            ("url", url),
            ("risk_category", safe_category),
        ]

        extended_query, params = self._create_extended_query(
            name_value_pairs=name_value_pairs,
            params=params,
        )

        query = f"""
            MERGE (n:License {{spdx_id: $spdx_id}})
            {extended_query}
        """
        logger.info("Creating License node spdx_id=%s", spdx_id)
        self.run_query(query=cast(LiteralString, query), params=params)

    def create_version_license(self, purl: str, spdx_id: str) -> None:
        """Create a HAS_LICENSE edge between a Version and a License.

        Matches the Version by ``package_url`` and the License by
        ``spdx_id``.

        Args:
            purl: The package URL of the version.
            spdx_id: The SPDX identifier of the license.
        """
        if not purl or not spdx_id:
            logger.warning(
                "Cannot create version-license edge: purl=%s spdx_id=%s",
                purl, spdx_id,
            )
            return

        query = """
            MATCH (v:Version {package_url: $purl})
            MATCH (l:License {spdx_id: $spdx_id})
            MERGE (v)-[:HAS_LICENSE]->(l)
        """
        params = {"purl": purl, "spdx_id": spdx_id}
        logger.info("Creating HAS_LICENSE edge purl=%s -> spdx_id=%s", purl, spdx_id)
        self.run_query(query=query, params=params)

    def create_version_license_by_name(
        self,
        project_name: str,
        project_group: str | None,
        version_name: str,
        spdx_id: str,
    ) -> None:
        """Create a HAS_LICENSE edge using version identity fields.

        Useful during CycloneDX ingestion when the purl may not yet be
        set on the Version node.

        Args:
            project_name: The project name.
            project_group: The project group (may be None).
            version_name: The version string.
            spdx_id: The SPDX identifier of the license.
        """
        if not spdx_id:
            return

        params: dict[str, Any] = {
            "project_name": project_name,
            "version_name": version_name,
            "spdx_id": spdx_id,
        }

        if project_group is not None:
            query = """
                MATCH (v:Version {name: $version_name, project_name: $project_name, project_group: $project_group})
                MATCH (l:License {spdx_id: $spdx_id})
                MERGE (v)-[:HAS_LICENSE]->(l)
            """
            params["project_group"] = project_group
        else:
            query = """
                MATCH (v:Version {name: $version_name, project_name: $project_name})
                MATCH (l:License {spdx_id: $spdx_id})
                MERGE (v)-[:HAS_LICENSE]->(l)
            """

        logger.info(
            "Creating HAS_LICENSE edge %s/%s -> %s",
            project_name, version_name, spdx_id,
        )
        self.run_query(query=query, params=params)

    # Labeling methods

    def label_projects_with_type_information(self) -> None:
        """Add type labels to all Version nodes."""
        self.run_query(
            query="""
                MATCH (p:Version {type: 'library'})
                SET p:Library
                RETURN p
            """
        )
        self.run_query(
            query="""
                MATCH (p:Version {type: 'application'})
                SET p:Application
                RETURN p
            """
        )

    def label_projects_with_renovate_usage(self, projects: list[dict[str, Any]]) -> None:
        """Add Renovate label to projects that use Renovate.

        Args:
            projects: List of project dicts with 'project_name' and 'name' keys.
        """
        for project in projects:
            self.run_query(
                query="""
                    MATCH (p:Version {name: $version, project_name: $project_name})
                    SET p:Renovate
                    YIELD node
                    RETURN node
                """,
                params={
                    "project_name": project['project_name'],
                    "version": project['name'],
                },
            )

    # Query methods

    def get_versions_by_purl(self, purl: str) -> list[dict[str, str | None]]:
        """Return lightweight version/project info for a given package URL.

        Used by the enrichment pipeline to link newly discovered defects
        or licenses to the correct Version nodes without leaking raw
        Cypher into task code.

        Args:
            purl: The package URL to look up.

        Returns:
            List of dicts with keys ``name``, ``project_name``, and
            ``project_group`` (any of which may be ``None``).
        """
        result = self.run_query(
            query=(
                "MATCH (v:Version) WHERE v.package_url = $purl "
                "RETURN v.name AS name, v.project_name AS project_name, "
                "v.project_group AS project_group"
            ),
            params={"purl": purl},
        )
        return [
            {
                "name": row.get("name"),
                "project_name": row.get("project_name"),
                "project_group": row.get("project_group"),
            }
            for row in result.result_set
        ]

    def retrieve_all_project_nodes_with_repo_url(self, project_repo: str) -> list[dict[str, Any]]:
        """Retrieve all project nodes with a specific repo URL.

        Args:
            project_repo: The repository URL to search for.

        Returns:
            List of project node dictionaries.
        """
        data = self.run_query(
            query="""
                MATCH (n:Version {repo: $project_repo})
                RETURN n
            """,
            params={'project_repo': project_repo},
        ).result_set
        return [elem.get('n') for elem in data]

    # Centrality methods

    def add_inward_centrality_scores(self) -> None:
        """Add inward centrality scores to INTERNAL nodes."""
        self.run_query(
            query="""
                MATCH (n:INTERNAL)
                SET n.inDegree = SIZE((n)<--())
            """
        )

    def add_outward_centrality_scores(self) -> None:
        """Add outward centrality scores to INTERNAL nodes."""
        self.run_query(
            query="""
                MATCH (n:INTERNAL)
                SET n.outDegree = SIZE((n)-->())
            """
        )

    # Trust Score methods

    def create_trust_score(
        self,
        purl: str,
        direct_score: float,
        confidence: float,
        security_practices_score: float,
        vulnerability_profile_score: float,
        maintenance_health_score: float,
        supply_chain_hygiene_score: float,
        sources_used: list[str],
        scored_at: str,
        scorecard_raw: str | None = None,
        depsdev_raw: str | None = None,
    ) -> None:
        """Create or update a TrustScore node and link it to Version nodes.

        Uses ``purl`` as the MERGE key so each package version has at most
        one TrustScore.

        Args:
            purl: Package URL identifying the package version.
            direct_score: Composite direct score (0--10).
            confidence: Data source coverage (0--1).
            security_practices_score: Category score (0--10).
            vulnerability_profile_score: Category score (0--10).
            maintenance_health_score: Category score (0--10).
            supply_chain_hygiene_score: Category score (0--10).
            sources_used: List of data source names.
            scored_at: ISO timestamp of scoring.
            scorecard_raw: Optional raw Scorecard JSON.
            depsdev_raw: Optional raw deps.dev JSON.
        """
        if not purl:
            logger.warning("Cannot create TrustScore: purl is empty")
            return

        params: dict[str, Any] = {
            "purl": purl,
            "direct_score": direct_score,
            "confidence": confidence,
            "security_practices_score": security_practices_score,
            "vulnerability_profile_score": vulnerability_profile_score,
            "maintenance_health_score": maintenance_health_score,
            "supply_chain_hygiene_score": supply_chain_hygiene_score,
            "sources_used": sources_used,
            "scored_at": scored_at,
        }

        optional_sets: list[str] = []
        if scorecard_raw is not None:
            params["scorecard_raw"] = scorecard_raw
            optional_sets.append("n.scorecard_raw = $scorecard_raw")
        if depsdev_raw is not None:
            params["depsdev_raw"] = depsdev_raw
            optional_sets.append("n.depsdev_raw = $depsdev_raw")

        extra_set = ", " + ", ".join(optional_sets) if optional_sets else ""

        query = f"""
            MERGE (n:TrustScore {{purl: $purl}})
            ON CREATE SET
                n.direct_score = $direct_score,
                n.confidence = $confidence,
                n.security_practices_score = $security_practices_score,
                n.vulnerability_profile_score = $vulnerability_profile_score,
                n.maintenance_health_score = $maintenance_health_score,
                n.supply_chain_hygiene_score = $supply_chain_hygiene_score,
                n.sources_used = $sources_used,
                n.scored_at = $scored_at{extra_set}
            ON MATCH SET
                n.direct_score = $direct_score,
                n.confidence = $confidence,
                n.security_practices_score = $security_practices_score,
                n.vulnerability_profile_score = $vulnerability_profile_score,
                n.maintenance_health_score = $maintenance_health_score,
                n.supply_chain_hygiene_score = $supply_chain_hygiene_score,
                n.sources_used = $sources_used,
                n.scored_at = $scored_at{extra_set}
        """
        logger.info("Creating TrustScore purl=%s direct_score=%.2f", purl, direct_score)
        self.run_query(query=cast(LiteralString, query), params=params)

    def link_version_to_trust_score(self, purl: str) -> None:
        """Create a HAS_TRUST_SCORE edge between matching Version nodes and the TrustScore.

        Args:
            purl: The package URL shared by the Version and TrustScore nodes.
        """
        if not purl:
            return

        query = """
            MATCH (v:Version {package_url: $purl})
            MATCH (t:TrustScore {purl: $purl})
            MERGE (v)-[:HAS_TRUST_SCORE]->(t)
        """
        logger.info("Creating HAS_TRUST_SCORE edge for purl=%s", purl)
        self.run_query(query=query, params={"purl": purl})

    def update_trust_score_propagation(
        self,
        purl: str,
        effective_score: float,
        inherited_score: float,
        min_path_score: float,
        dep_count: int,
    ) -> None:
        """Update propagation fields on an existing TrustScore node.

        Called by the periodic propagation task after computing inherited
        risk through the dependency graph.

        Args:
            purl: Package URL identifying the TrustScore.
            effective_score: Blended own + inherited score (0--10).
            inherited_score: Weighted aggregate from deps (0--10).
            min_path_score: Weakest direct_score on any dependency path (0--10).
            dep_count: Number of deps used in the calculation.
        """
        if not purl:
            return

        query = """
            MATCH (n:TrustScore {purl: $purl})
            SET n.effective_score = $effective_score,
                n.inherited_score = $inherited_score,
                n.min_path_score = $min_path_score,
                n.dep_count = $dep_count
        """
        self.run_query(
            query=query,
            params={
                "purl": purl,
                "effective_score": effective_score,
                "inherited_score": inherited_score,
                "min_path_score": min_path_score,
                "dep_count": dep_count,
            },
        )

    def get_all_trust_scores(self) -> list[dict[str, Any]]:
        """Return all TrustScore nodes as dictionaries.

        Used by the propagation task to read current direct_scores.

        Returns:
            List of dictionaries with purl, direct_score, effective_score,
            inherited_score, min_path_score, confidence, and dep_count.
        """
        result = self.run_query(
            query=(
                "MATCH (t:TrustScore) "
                "RETURN t.purl AS purl, t.direct_score AS direct_score, "
                "t.effective_score AS effective_score, "
                "t.inherited_score AS inherited_score, "
                "t.min_path_score AS min_path_score, "
                "t.confidence AS confidence, "
                "t.dep_count AS dep_count"
            ),
        )
        return [
            {
                "purl": row.get("purl"),
                "direct_score": row.get("direct_score"),
                "effective_score": row.get("effective_score"),
                "inherited_score": row.get("inherited_score"),
                "min_path_score": row.get("min_path_score"),
                "confidence": row.get("confidence"),
                "dep_count": row.get("dep_count"),
            }
            for row in result.result_set
        ]

    def get_dependency_graph_for_propagation(self) -> list[dict[str, str]]:
        """Return the dependency adjacency list for trust score propagation.

        Returns pairs of (parent_purl, child_purl) from the
        DEPENDENCY_VERSION edges, only for versions that have package_url set.

        Returns:
            List of dicts with ``parent_purl`` and ``child_purl`` keys.
        """
        result = self.run_query(
            query=(
                "MATCH (parent:Version)-[:DEPENDENCY_VERSION]->(child:Version) "
                "WHERE parent.package_url IS NOT NULL "
                "AND child.package_url IS NOT NULL "
                "RETURN DISTINCT parent.package_url AS parent_purl, "
                "child.package_url AS child_purl"
            ),
        )
        return [
            {
                "parent_purl": row.get("parent_purl"),
                "child_purl": row.get("child_purl"),
            }
            for row in result.result_set
        ]

    # Index management

    def create_indexes(self) -> None:
        """Create indexes for query performance.

        Creates indexes on commonly queried fields. Logs warnings for
        indexes that already exist rather than silently catching exceptions.
        """
        logger.info("Creating indexes...")

        index_definitions = [
            ("Version", "project_name"),
            ("Version", "project_group"),
            ("Version", "name"),
            ("Defect", "id"),
            ("License", "spdx_id"),
            ("PolicyAnnotation", "annotation_id"),
            ("PolicyAnnotation", "type"),
            ("PointOfContact", "email"),
            ("VexStatement", "statement_id"),
            ("SourceRepository", "url"),
            ("TrustScore", "purl"),
            ("TrustScore", "effective_score"),
            ("TrustScore", "min_path_score"),
        ]

        for label, property_name in index_definitions:
            # Safety: label and property_name come from the hardcoded
            # index_definitions list above — no external input.
            query = f"CREATE INDEX FOR (n:{label}) ON (n.{property_name})"
            try:
                self.run_query(cast(LiteralString, query))
                logger.info(f"Created index on {label}.{property_name}")
            except Exception as e:
                error_msg = str(e).lower()
                if "already exists" in error_msg or "equivalent index" in error_msg:
                    logger.debug(f"Index on {label}.{property_name} already exists")
                else:
                    logger.warning(f"Failed to create index on {label}.{property_name}: {e}")
