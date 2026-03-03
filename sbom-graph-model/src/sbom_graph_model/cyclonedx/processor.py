"""
CycloneDX SBOM processing module.

This module provides functionality for parsing and processing CycloneDX
Software Bill of Materials (SBOM) files, extracting projects, versions,
dependencies, and vulnerabilities.
"""

import logging
import operator
from functools import reduce
from typing import Optional
from urllib.parse import urlparse

from ..model import Project, Version, Defect, License, VersionDefect
from ..persistence import Persistence

logger = logging.getLogger(__name__)


class CycloneDXValidationError(ValueError):
    """Raised when CycloneDX JSON data fails structural validation."""


class CycloneDXProcessor:
    """Processor for CycloneDX SBOM files.

    Parses CycloneDX JSON data and persists the extracted information
    (projects, versions, dependencies, defects) to the graph database.

    Args:
        persistence: The Persistence instance for database operations.
    """

    def __init__(self, persistence: Persistence):
        """Initialize the CycloneDX processor.

        Args:
            persistence: The Persistence instance to use for database operations.
        """
        self.persistence = persistence

    @staticmethod
    def _validate_cyclonedx_structure(json_data: dict) -> None:
        """Validate the top-level structure of a CycloneDX JSON document.

        Ensures required fields are present and have the expected types
        before deeper processing begins. This catches malformed input
        early and provides clear error messages.

        Args:
            json_data: The complete CycloneDX JSON data.

        Raises:
            CycloneDXValidationError: If required fields are missing or
                have incorrect types.
        """
        if not isinstance(json_data, dict):
            raise CycloneDXValidationError("CycloneDX data must be a JSON object")

        if "metadata" not in json_data:
            raise CycloneDXValidationError("Missing required field: 'metadata'")

        metadata = json_data["metadata"]
        if not isinstance(metadata, dict):
            raise CycloneDXValidationError("'metadata' must be a JSON object")

        if "component" not in metadata:
            raise CycloneDXValidationError("Missing required field: 'metadata.component'")

        component = metadata["component"]
        if not isinstance(component, dict):
            raise CycloneDXValidationError("'metadata.component' must be a JSON object")

        if "bom-ref" not in component:
            raise CycloneDXValidationError("Missing required field: 'metadata.component.bom-ref'")

        if "name" not in component:
            raise CycloneDXValidationError("Missing required field: 'metadata.component.name'")

        for section, expected_type in [
            ("components", list),
            ("dependencies", list),
            ("vulnerabilities", list),
        ]:
            if section in json_data and not isinstance(json_data[section], expected_type):
                raise CycloneDXValidationError(
                    f"'{section}' must be a {expected_type.__name__}"
                )

        if "components" in json_data:
            for i, comp in enumerate(json_data["components"]):
                if not isinstance(comp, dict):
                    raise CycloneDXValidationError(
                        f"components[{i}] must be a JSON object"
                    )
                if "bom-ref" not in comp:
                    raise CycloneDXValidationError(
                        f"components[{i}] missing required field: 'bom-ref'"
                    )

    @staticmethod
    def _get_property_value(properties: list[dict], property_name: str) -> str:
        """Extract a property value from a CycloneDX properties list.

        Args:
            properties: List of property dictionaries with 'name' and 'value' keys.
            property_name: The name of the property to find.

        Returns:
            The property value, or empty string if not found.
        """
        logger.debug(f"Looking for property {property_name} in {properties}")
        for prop in properties:
            if prop['name'] == property_name:
                return prop['value']
        return ''

    @staticmethod
    def parse_application_from_cyclone_dx(
        app_id: str,
        public_app_id: str,
        scan_id: str,
        metadata_json: dict,
        gitlab_project_url: Optional[str] = None,
    ) -> tuple[str, tuple[Project, Version]]:
        """Parse CycloneDX data for the scanned application.

        Creates a Project and Version object from the CycloneDX metadata.

        Args:
            app_id: Lifecycle hash representing the application.
            public_app_id: The identifier of the scanned application.
            scan_id: The unique identifier for the scan.
            metadata_json: The metadata section of the CycloneDX file.
            gitlab_project_url: Optional GitLab URL for the application.

        Returns:
            Tuple of (bom-ref, (Project, Version)).
        """
        component = metadata_json['component']

        application = Project()
        application.application_id = app_id
        application.public_app_id = public_app_id
        application.name = component.get('name')
        application.group = component.get('group')
        application.type = component.get('type')
        application.purl = component.get('purl')
        application.repo = gitlab_project_url
        application.licenses = CycloneDXProcessor.parse_licenses_from_component(component)

        version = Version()
        version.scan_id = scan_id
        version.project = application
        version.version = component.get('version', "UNKNOWN")
        version.sbom_format = "cyclonedx"
        ref = component.get('bom-ref')

        return ref, (application, version)

    @staticmethod
    def parse_component_from_cyclone_dx(
        json_component: dict,
        scan_id: str,
    ) -> tuple[Project, Version]:
        """Parse CycloneDX data for a component.

        Creates a Project and Version object from component data.

        Args:
            json_component: The component section of the CycloneDX file.
            scan_id: The unique identifier for the scan.

        Returns:
            Tuple of (Project, Version).
        """
        project = Project()
        project.name = json_component.get('name')
        project.group = json_component.get('group')
        project.type = json_component.get('type')
        project.purl = json_component.get('purl')
        project.licenses = CycloneDXProcessor.parse_licenses_from_component(json_component)

        version = Version()
        version.project = project
        version.version = json_component.get('version')
        version.scan_id = scan_id
        version.sbom_format = "cyclonedx"

        return project, version

    @staticmethod
    def parse_licenses_from_component(component: dict) -> list[License]:
        """Extract license information from a CycloneDX component.

        Handles both SPDX-identified licenses (``license.id``) and
        freetext license names (``license.name``).

        Args:
            component: A CycloneDX component dictionary.

        Returns:
            List of License objects extracted from the component.
        """
        licenses: list[License] = []
        license_entries = component.get("licenses", [])
        if not isinstance(license_entries, list):
            return licenses

        for entry in license_entries:
            if not isinstance(entry, dict):
                continue
            lic_obj = entry.get("license")
            if not isinstance(lic_obj, dict):
                continue

            lic = License()
            spdx_id = lic_obj.get("id")
            if spdx_id:
                lic.spdx_id = spdx_id
                lic.name = spdx_id
            else:
                name = lic_obj.get("name", "")
                if name:
                    lic.spdx_id = name
                    lic.name = name
                else:
                    continue

            lic.url = lic_obj.get("url")
            licenses.append(lic)

        return licenses

    @staticmethod
    def extract_vcs_url_from_component(component: dict) -> Optional[str]:
        """Extract a VCS repository URL from CycloneDX externalReferences.

        Looks for ``externalReferences`` entries with ``type`` equal to
        ``"vcs"`` and returns the first URL found.

        Args:
            component: A CycloneDX component dictionary.

        Returns:
            The VCS URL or None if not found.
        """
        refs = component.get("externalReferences", [])
        if not isinstance(refs, list):
            return None
        for ref in refs:
            if not isinstance(ref, dict):
                continue
            if ref.get("type") == "vcs":
                url = ref.get("url", "")
                if url:
                    return url
        return None

    @staticmethod
    def _parse_repo_url(url: str) -> dict[str, Optional[str]]:
        """Parse a repository URL into namespace, name, and vcs_type."""
        parsed = urlparse(url.rstrip("/"))
        namespace = parsed.netloc or None
        path = parsed.path.lstrip("/")
        if path.endswith(".git"):
            path = path[:-4]
        return {
            "namespace": namespace,
            "name": path or None,
            "vcs_type": "git" if (
                url.endswith(".git") or "github.com" in url
                or "gitlab.com" in url or "bitbucket.org" in url
            ) else None,
        }

    @staticmethod
    def parse_defect_from_cyclone_dx(cyclone_dx_json: dict) -> Defect:
        """Parse CycloneDX vulnerability data into a Defect.

        Args:
            cyclone_dx_json: The vulnerability section of the CycloneDX file.

        Returns:
            A Defect object.

        Raises:
            ValueError: If the vulnerability has multiple ratings.
        """
        defect = Defect()
        defect.id = cyclone_dx_json['id']
        defect.source = (
            cyclone_dx_json['source']['name'],
            cyclone_dx_json['source'].get('url', ''),
        )

        if len(cyclone_dx_json['ratings']) > 1:
            raise ValueError('Vulnerability has multiple ratings - this is not currently handled')

        defect.severity = cyclone_dx_json['ratings'][0]['severity']
        defect.cwes = cyclone_dx_json.get('cwes', [])
        defect.cvss = cyclone_dx_json['ratings'][0]['score']
        defect.cvss_string = cyclone_dx_json['ratings'][0].get('vector')

        return defect

    @staticmethod
    def _get_affects_list(
        cyclone_dx_json: list[dict[str, str]],
        projects: dict[str, tuple[Project, Version]],
    ) -> list[Version]:
        """Extract affected versions from vulnerability data.

        Args:
            cyclone_dx_json: The 'affects' section of a vulnerability.
            projects: Dictionary mapping bom-ref to (Project, Version) tuples.

        Returns:
            List of affected Version objects.
        """
        result = []
        for entry in cyclone_dx_json:
            ref = entry.get('ref')
            if ref and ref in projects:
                result.append(projects[ref][1])
            else:
                logger.warning(f"Reference {ref} not found in projects")
        return result

    def process_cyclone_dx_json(
        self,
        app_id: str,
        public_app_id: str,
        gitlab_project_url: Optional[str],
        json_data: dict,
    ) -> tuple[
        dict[str, tuple[Project, Version]],
        dict[str, set[str]],
        dict[str, Defect],
    ]:
        """Process CycloneDX JSON data and persist to database.

        Parses the CycloneDX SBOM, extracts all projects, versions,
        dependencies, and defects, and persists them to the graph database.

        Args:
            app_id: The application ID in SonaType.
            public_app_id: The public application identifier.
            gitlab_project_url: Optional GitLab URL for the project.
            json_data: The complete CycloneDX JSON data.

        Returns:
            Tuple of (projects dict, dependency_versions dict, defects dict).

        Raises:
            CycloneDXValidationError: If the JSON structure is invalid.
        """
        self._validate_cyclonedx_structure(json_data)

        scan_id = self._get_property_value(
            json_data.get('metadata', {}).get('properties', []),
            'Scan ID',
        )

        projects: dict[str, tuple[Project, Version]] = {}
        dependency_versions: dict[str, set[str]] = {}
        defects: dict[str, Defect] = {}

        # Parse components
        if 'components' in json_data:
            projects.update({
                component['bom-ref']: self.parse_component_from_cyclone_dx(component, scan_id)
                for component in json_data['components']
            })

        # Parse dependencies
        if 'dependencies' in json_data:
            dependency_versions.update({
                project_deps['ref']: set(project_deps['dependsOn'])
                for project_deps in json_data['dependencies']
            })

        # Parse vulnerabilities
        if 'vulnerabilities' in json_data:
            defects.update({
                vuln['id']: self.parse_defect_from_cyclone_dx(vuln)
                for vuln in json_data['vulnerabilities']
            })

        # Parse application metadata
        bom_ref, app_version_pair = self.parse_application_from_cyclone_dx(
            app_id=app_id,
            public_app_id=public_app_id,
            scan_id=scan_id,
            metadata_json=json_data['metadata'],
            gitlab_project_url=gitlab_project_url,
        )

        # Handle unlinked libraries
        dependency_versions_ref_set = set(dependency_versions.keys())
        dependency_versions_ref_set.update(
            reduce(operator.iconcat, dependency_versions.values(), [])
        )
        unlinked_libraries = set(projects.keys()).difference(dependency_versions_ref_set)

        if len(unlinked_libraries) > 0:
            if bom_ref not in dependency_versions:
                dependency_versions[bom_ref] = unlinked_libraries
            else:
                dependency_versions[bom_ref].update(unlinked_libraries)

        projects[bom_ref] = app_version_pair

        # Persist to database
        self._persist_projects(projects)
        self._persist_source_repos(json_data, projects)
        self._persist_dependencies(dependency_versions, projects)
        self._persist_defects(json_data, defects, projects)

        return projects, dependency_versions, defects

    def _persist_projects(
        self,
        projects: dict[str, tuple[Project, Version]],
    ) -> None:
        """Persist all projects and their versions to the database.

        Also persists license nodes and HAS_LICENSE edges extracted
        from CycloneDX component data.

        Args:
            projects: Dictionary mapping bom-ref to (Project, Version) tuples.
        """
        logger.info("Persisting %d project versions", len(projects))
        for project, version in projects.values():
            if version is None:
                logger.warning(f"Skipping project {project}: version is None")
                continue
            self.persistence.create_project_version(version=version)

            for lic in getattr(project, "licenses", []):
                if not lic or not lic.spdx_id:
                    continue
                self.persistence.create_license(
                    spdx_id=lic.spdx_id,
                    name=lic.name,
                    url=lic.url,
                    risk_category=lic.risk_category,
                )
                self.persistence.create_version_license_by_name(
                    project_name=project.name or "",
                    project_group=project.group,
                    version_name=version.version or "",
                    spdx_id=lic.spdx_id,
                )

    def _persist_source_repos(
        self,
        json_data: dict,
        projects: dict[str, tuple[Project, Version]],
    ) -> None:
        """Create SourceRepository nodes and HAS_SOURCE edges from VCS data.

        Extracts VCS URLs from CycloneDX ``externalReferences`` on each
        component, as well as from the ``gitlab_project_url`` on the root.
        """
        components_by_ref: dict[str, dict] = {}
        for comp in json_data.get("components", []):
            if isinstance(comp, dict) and "bom-ref" in comp:
                components_by_ref[comp["bom-ref"]] = comp

        root_comp = json_data.get("metadata", {}).get("component", {})
        if isinstance(root_comp, dict) and "bom-ref" in root_comp:
            components_by_ref[root_comp["bom-ref"]] = root_comp

        for ref, (project, version) in projects.items():
            if version is None:
                continue

            repo_url = getattr(project, "repo", None)

            comp = components_by_ref.get(ref, {})
            vcs_url = self.extract_vcs_url_from_component(comp)
            url = vcs_url or repo_url
            if not url:
                continue

            parsed = self._parse_repo_url(url)
            self.persistence.create_source_repository(
                url=url,
                vcs_type=parsed["vcs_type"],
                namespace=parsed["namespace"],
                name=parsed["name"],
            )
            self.persistence.link_version_to_source_by_name(
                project_name=project.name or "",
                project_group=project.group,
                version_name=version.version or "",
                repo_url=url,
            )

    def _persist_dependencies(
        self,
        dependency_versions: dict[str, set[str]],
        projects: dict[str, tuple[Project, Version]],
    ) -> None:
        """Persist dependency relationships to the database.

        Args:
            dependency_versions: Dictionary mapping parent ref to set of child refs.
            projects: Dictionary mapping bom-ref to (Project, Version) tuples.
        """
        logger.info("Persisting dependency edges for %d parent refs", len(dependency_versions))
        for ref, dependency_refs in dependency_versions.items():
            if ref not in projects:
                logger.warning(f"Parent reference {ref} not found in projects")
                continue

            parent = projects[ref][1]
            if parent is None:
                logger.warning(f"Parent version is None for ref {ref}")
                continue

            for dep_ref in dependency_refs:
                if dep_ref not in projects:
                    logger.warning(f"Child reference {dep_ref} not found in projects")
                    continue

                child = projects[dep_ref][1]
                if child is None:
                    logger.warning(f"Child version is None for ref {dep_ref}")
                    continue

                self.persistence.create_dependency(parent=parent, child=child)

    def _persist_defects(
        self,
        json_data: dict,
        defects: dict[str, Defect],
        projects: dict[str, tuple[Project, Version]],
    ) -> None:
        """Persist defects and their version associations to the database.

        Args:
            json_data: The original CycloneDX JSON data.
            defects: Dictionary mapping defect ID to Defect objects.
            projects: Dictionary mapping bom-ref to (Project, Version) tuples.
        """
        # Build version_defects mapping
        version_defects: dict[Defect, list[Version]] = {}

        for vuln in json_data.get('vulnerabilities', []):
            defect_id = vuln.get('id')
            if defect_id and defect_id in defects:
                defect = defects[defect_id]
                affected_versions = self._get_affects_list(
                    vuln.get('affects', []),
                    projects,
                )
                version_defects[defect] = affected_versions

        logger.info(
            "Persisting %d defects and %d version-defect associations",
            len(defects),
            sum(len(v) for v in version_defects.values()),
        )
        for defect in defects.values():
            if defect is None:
                continue
            self.persistence.create_defect(defect=defect)

        # Persist version-defect edges
        for defect, versions in version_defects.items():
            if defect is None:
                continue

            for version in versions:
                if version is None:
                    logger.warning(f"Skipping None version for defect {defect.id}")
                    continue

                version_defect = VersionDefect()
                version_defect.defect = defect
                version_defect.project_version = version
                self.persistence.create_version_defect(version_defect=version_defect)
