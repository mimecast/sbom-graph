"""
Persistence layer for FalkorDB graph database operations.

This module provides the Persistence class for storing and retrieving
AppSec data from a FalkorDB graph database.
"""

import logging
import re
from typing import Any, LiteralString, Optional, cast
from falkordb import FalkorDB, Graph

from .model import Project, Version, Defect, VersionDefect

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
