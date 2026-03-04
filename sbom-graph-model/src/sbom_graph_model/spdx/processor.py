"""
SPDX 2.3 SBOM processing module.

Parses SPDX JSON documents and persists the extracted information
(projects, versions, dependencies, licenses, source repositories, defects)
to the graph database using the same persistence layer as CycloneDX.
"""

import logging
from typing import Optional
from urllib.parse import urlparse

from ..model import Defect, License, Project, Version, VersionDefect
from ..persistence import Persistence

logger = logging.getLogger(__name__)


class SPDXValidationError(ValueError):
    """Raised when SPDX JSON data fails structural validation."""


class SPDXProcessor:
    """Processor for SPDX 2.3 JSON SBOM documents.

    Parses SPDX JSON data and persists the extracted information
    to the graph database via the shared :class:`Persistence` layer.

    Args:
        persistence: The Persistence instance for database operations.
    """

    SPDX_FORMAT = "spdx"
    DEPENDENCY_RELATIONSHIPS = frozenset({
        "DEPENDS_ON",
        "HAS_PREREQUISITE",
        "CONTAINS",
    })
    INVERSE_DEPENDENCY_RELATIONSHIPS = frozenset({
        "DEPENDENCY_OF",
        "PREREQUISITE_FOR",
        "CONTAINED_BY",
    })

    def __init__(self, persistence: Persistence):
        self.persistence = persistence

    @staticmethod
    def _validate_spdx_structure(json_data: dict) -> None:
        """Validate the top-level structure of an SPDX 2.3 JSON document.

        Args:
            json_data: The complete SPDX JSON data.

        Raises:
            SPDXValidationError: If required fields are missing or invalid.
        """
        if not isinstance(json_data, dict):
            raise SPDXValidationError("SPDX data must be a JSON object")

        if "spdxVersion" not in json_data:
            raise SPDXValidationError("Missing required field: 'spdxVersion'")

        version = json_data["spdxVersion"]
        if not isinstance(version, str) or not version.startswith("SPDX-"):
            raise SPDXValidationError(
                f"Invalid spdxVersion: {version!r}; expected 'SPDX-2.x'"
            )

        if "SPDXID" not in json_data:
            raise SPDXValidationError("Missing required field: 'SPDXID'")

        if "name" not in json_data:
            raise SPDXValidationError("Missing required field: 'name'")

        for section, expected_type in [
            ("packages", list),
            ("relationships", list),
        ]:
            if section in json_data and not isinstance(json_data[section], expected_type):
                raise SPDXValidationError(
                    f"'{section}' must be a {expected_type.__name__}"
                )

        if "packages" in json_data:
            for i, pkg in enumerate(json_data["packages"]):
                if not isinstance(pkg, dict):
                    raise SPDXValidationError(
                        f"packages[{i}] must be a JSON object"
                    )
                if "SPDXID" not in pkg:
                    raise SPDXValidationError(
                        f"packages[{i}] missing required field: 'SPDXID'"
                    )
                if "name" not in pkg:
                    raise SPDXValidationError(
                        f"packages[{i}] missing required field: 'name'"
                    )

    @staticmethod
    def _extract_purl_from_package(package: dict) -> Optional[str]:
        """Extract a purl from an SPDX package via externalRefs or externalReferences.

        Checks both ``externalRefs`` (SPDX 2.2+) and ``externalReferences``
        (SPDX 2.3 alternative key).
        """
        for key in ("externalRefs", "externalReferences"):
            refs = package.get(key, [])
            if not isinstance(refs, list):
                continue
            for ref in refs:
                if not isinstance(ref, dict):
                    continue
                ref_type = ref.get("referenceType", "")
                if ref_type == "purl" or ref_type == "purl-type":
                    locator = ref.get("referenceLocator", "")
                    if locator:
                        return locator
        return package.get("packageUrl")

    @staticmethod
    def _extract_vcs_url_from_package(package: dict) -> Optional[str]:
        """Extract a VCS repository URL from SPDX externalRefs."""
        for key in ("externalRefs", "externalReferences"):
            refs = package.get(key, [])
            if not isinstance(refs, list):
                continue
            for ref in refs:
                if not isinstance(ref, dict):
                    continue
                cat = ref.get("referenceCategory", "")
                if cat in ("PERSISTENT_ID", "SECURITY", "OTHER"):
                    locator = ref.get("referenceLocator", "")
                    if not locator or not isinstance(locator, str):
                        continue
                    parsed = urlparse(locator)
                    host = parsed.hostname.lower() if parsed.hostname else ""
                    # Accept well-known VCS hosts (including their subdomains).
                    if host and (
                        host == "github.com"
                        or host.endswith(".github.com")
                        or host == "gitlab.com"
                        or host.endswith(".gitlab.com")
                        or host == "bitbucket.org"
                        or host.endswith(".bitbucket.org")
                    ):
                        return locator
                    # As a fallback, treat URLs whose path ends with ".git" as VCS URLs,
                    # but only if they have a valid scheme and host.
                    if parsed.scheme and host and parsed.path.endswith(".git"):
                        return locator

        download = package.get("downloadLocation", "")
        if isinstance(download, str) and download not in ("NOASSERTION", "NONE", ""):
            parsed = urlparse(download)
            if parsed.scheme in ("https", "http", "git") and parsed.netloc:
                return download
        return None

    @staticmethod
    def _extract_licenses_from_package(package: dict) -> list[License]:
        """Extract license information from SPDX package fields."""
        licenses: list[License] = []
        seen: set[str] = set()

        for field in ("licenseConcluded", "licenseDeclared"):
            value = package.get(field, "")
            if not value or not isinstance(value, str):
                continue
            if value in ("NOASSERTION", "NONE"):
                continue
            for spdx_id in _split_spdx_expression(value):
                if spdx_id not in seen:
                    seen.add(spdx_id)
                    lic = License()
                    lic.spdx_id = spdx_id
                    lic.name = spdx_id
                    licenses.append(lic)

        return licenses

    @staticmethod
    def _parse_repo_url(url: str) -> dict[str, Optional[str]]:
        """Parse a repository URL into namespace, name, and vcs_type."""
        parsed = urlparse(url.rstrip("/"))
        namespace = parsed.netloc or None
        path = parsed.path.lstrip("/")
        if path.endswith(".git"):
            path = path[:-4]
        host = parsed.hostname.lower() if parsed.hostname else ""
        is_git_host = bool(
            host
            and (
                host == "github.com"
                or host.endswith(".github.com")
                or host == "gitlab.com"
                or host.endswith(".gitlab.com")
                or host == "bitbucket.org"
                or host.endswith(".bitbucket.org")
            )
        )
        vcs_type: Optional[str] = "git" if (
            url.endswith(".git") or path.endswith(".git") or is_git_host
        ) else None
        return {
            "namespace": namespace,
            "name": path or None,
            "vcs_type": vcs_type,
        }

    def _find_root_spdx_id(
        self,
        json_data: dict,
        packages_by_spdx_id: dict[str, dict],
    ) -> Optional[str]:
        """Find the SPDXID of the root/described package.

        The root package is the one linked via a ``DESCRIBES``
        relationship from the document element.
        """
        doc_spdx_id = json_data.get("SPDXID", "SPDXRef-DOCUMENT")
        for rel in json_data.get("relationships", []):
            if not isinstance(rel, dict):
                continue
            if (
                rel.get("spdxElementId") == doc_spdx_id
                and rel.get("relationshipType") == "DESCRIBES"
            ):
                target = rel.get("relatedSpdxElement")
                if target in packages_by_spdx_id:
                    return target
        return None

    def parse_package(
        self,
        package: dict,
        scan_id: str,
        is_root: bool = False,
        app_id: Optional[str] = None,
        public_app_id: Optional[str] = None,
        project_url: Optional[str] = None,
    ) -> tuple[Project, Version]:
        """Parse an SPDX package into a Project and Version.

        Args:
            package: An SPDX package dict.
            scan_id: Scan identifier.
            is_root: Whether this is the root/application package.
            app_id: Application ID (for root packages).
            public_app_id: Public application ID (for root packages).
            project_url: Repository URL override (for root packages).

        Returns:
            Tuple of (Project, Version).
        """
        project = Project()
        project.name = package.get("name")
        project.purl = self._extract_purl_from_package(package)

        supplier = package.get("supplier", "")
        if isinstance(supplier, str) and supplier.startswith("Organization: "):
            project.group = supplier.replace("Organization: ", "")

        if project.purl and not project.group:
            group = _extract_group_from_purl(project.purl)
            if group:
                project.group = group

        project.type = "application" if is_root else "library"
        project.licenses = self._extract_licenses_from_package(package)

        vcs_url = self._extract_vcs_url_from_package(package)
        if project_url and is_root:
            project.repo = project_url
        elif vcs_url:
            project.repo = vcs_url

        if is_root:
            project.application_id = app_id
            project.public_app_id = public_app_id

        version = Version()
        version.project = project
        version.version = package.get("versionInfo", "UNKNOWN")
        version.scan_id = scan_id
        version.sbom_format = self.SPDX_FORMAT

        return project, version

    def process_spdx_json(
        self,
        app_id: str,
        public_app_id: str,
        project_url: Optional[str],
        json_data: dict,
    ) -> tuple[
        dict[str, tuple[Project, Version]],
        dict[str, set[str]],
        dict[str, Defect],
    ]:
        """Process an SPDX JSON document and persist to the database.

        Args:
            app_id: The application ID.
            public_app_id: The public application identifier.
            project_url: Optional repository URL for the root project.
            json_data: The complete SPDX JSON data.

        Returns:
            Tuple of (packages dict, dependency_versions dict, defects dict).

        Raises:
            SPDXValidationError: If the JSON structure is invalid.
        """
        self._validate_spdx_structure(json_data)

        scan_id = json_data.get("documentNamespace", "")

        packages_raw = {
            pkg["SPDXID"]: pkg
            for pkg in json_data.get("packages", [])
            if isinstance(pkg, dict)
        }

        root_spdx_id = self._find_root_spdx_id(json_data, packages_raw)

        packages: dict[str, tuple[Project, Version]] = {}
        for spdx_id, pkg in packages_raw.items():
            is_root = spdx_id == root_spdx_id
            project, version = self.parse_package(
                package=pkg,
                scan_id=scan_id,
                is_root=is_root,
                app_id=app_id if is_root else None,
                public_app_id=public_app_id if is_root else None,
                project_url=project_url if is_root else None,
            )
            packages[spdx_id] = (project, version)

        dependency_versions = self._build_dependency_map(json_data, packages)
        defects = self._parse_vulnerabilities(json_data)

        self._persist_projects(packages)
        self._persist_source_repos(packages)
        self._persist_dependencies(dependency_versions, packages)
        self._persist_defects(json_data, defects, packages)

        return packages, dependency_versions, defects

    def _build_dependency_map(
        self,
        json_data: dict,
        packages: dict[str, tuple[Project, Version]],
    ) -> dict[str, set[str]]:
        """Build parent→children dependency map from SPDX relationships."""
        deps: dict[str, set[str]] = {}
        for rel in json_data.get("relationships", []):
            if not isinstance(rel, dict):
                continue
            rel_type = rel.get("relationshipType", "")
            source = rel.get("spdxElementId", "")
            target = rel.get("relatedSpdxElement", "")

            if rel_type in self.DEPENDENCY_RELATIONSHIPS:
                parent, child = source, target
            elif rel_type in self.INVERSE_DEPENDENCY_RELATIONSHIPS:
                parent, child = target, source
            else:
                continue

            if parent in packages and child in packages:
                deps.setdefault(parent, set()).add(child)

        return deps

    def _parse_vulnerabilities(
        self,
        json_data: dict,
    ) -> dict[str, Defect]:
        """Parse SPDX vulnerabilities section (SPDX 2.3+) into Defect objects."""
        defects: dict[str, Defect] = {}
        for vuln in json_data.get("vulnerabilities", []):
            if not isinstance(vuln, dict):
                continue
            vuln_id = vuln.get("id")
            if not vuln_id:
                continue

            defect = Defect()
            defect.id = vuln_id
            defect.description = vuln.get("description")

            ratings = vuln.get("ratings", [])
            if isinstance(ratings, list) and ratings:
                first = ratings[0] if isinstance(ratings[0], dict) else {}
                defect.severity = first.get("severity")
                defect.cvss = first.get("score")
                defect.cvss_string = first.get("vector")

            source = vuln.get("source")
            if isinstance(source, dict):
                defect.source = (source.get("name", ""), source.get("url", ""))

            defect.cwes = vuln.get("cwes", [])
            defects[vuln_id] = defect

        return defects

    def _persist_projects(
        self,
        packages: dict[str, tuple[Project, Version]],
    ) -> None:
        """Persist all packages as Version nodes and their licenses."""
        logger.info("Persisting %d SPDX packages", len(packages))
        for project, version in packages.values():
            if version is None:
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
        packages: dict[str, tuple[Project, Version]],
    ) -> None:
        """Create SourceRepository nodes and HAS_SOURCE edges from VCS data."""
        for project, version in packages.values():
            repo_url = getattr(project, "repo", None)
            if not repo_url or version is None:
                continue

            parsed = self._parse_repo_url(repo_url)
            self.persistence.create_source_repository(
                url=repo_url,
                vcs_type=parsed["vcs_type"],
                namespace=parsed["namespace"],
                name=parsed["name"],
            )
            self.persistence.link_version_to_source_by_name(
                project_name=project.name or "",
                project_group=project.group,
                version_name=version.version or "",
                repo_url=repo_url,
            )

    def _persist_dependencies(
        self,
        dependency_versions: dict[str, set[str]],
        packages: dict[str, tuple[Project, Version]],
    ) -> None:
        """Persist DEPENDENCY_VERSION edges."""
        logger.info("Persisting dependency edges for %d parent refs", len(dependency_versions))
        for ref, dep_refs in dependency_versions.items():
            if ref not in packages:
                continue
            parent = packages[ref][1]
            if parent is None:
                continue
            for dep_ref in dep_refs:
                if dep_ref not in packages:
                    continue
                child = packages[dep_ref][1]
                if child is None:
                    continue
                self.persistence.create_dependency(parent=parent, child=child)

    def _persist_defects(
        self,
        json_data: dict,
        defects: dict[str, Defect],
        packages: dict[str, tuple[Project, Version]],
    ) -> None:
        """Persist Defect nodes and VERSION_DEFECT edges."""
        spdx_id_to_pkg = {
            spdx_id: (project, version)
            for spdx_id, (project, version) in packages.items()
        }

        version_defects: dict[str, list[Version]] = {}
        for vuln in json_data.get("vulnerabilities", []):
            if not isinstance(vuln, dict):
                continue
            vuln_id = vuln.get("id")
            if not vuln_id or vuln_id not in defects:
                continue
            affected: list[Version] = []
            for affect in vuln.get("affects", []):
                if not isinstance(affect, dict):
                    continue
                ref = affect.get("ref", "")
                if ref in spdx_id_to_pkg:
                    affected.append(spdx_id_to_pkg[ref][1])
            version_defects[vuln_id] = affected

        logger.info(
            "Persisting %d defects and %d version-defect associations",
            len(defects),
            sum(len(v) for v in version_defects.values()),
        )
        for defect in defects.values():
            self.persistence.create_defect(defect=defect)

        for vuln_id, versions in version_defects.items():
            defect = defects[vuln_id]
            for version in versions:
                if version is None:
                    continue
                vd = VersionDefect()
                vd.defect = defect
                vd.project_version = version
                self.persistence.create_version_defect(version_defect=vd)


def _split_spdx_expression(expression: str) -> list[str]:
    """Split an SPDX license expression into individual license IDs.

    Handles simple expressions like ``MIT``, ``Apache-2.0 OR MIT``,
    and ``(MIT AND BSD-3-Clause)``. Does not attempt full expression
    parsing -- operators and parentheses are stripped.
    """
    cleaned = expression.replace("(", " ").replace(")", " ")
    tokens = cleaned.split()
    return [
        t for t in tokens
        if t.upper() not in ("AND", "OR", "WITH")
        and t not in ("NOASSERTION", "NONE")
    ]


def _extract_group_from_purl(purl: str) -> Optional[str]:
    """Extract the namespace/group from a purl string.

    For ``pkg:maven/com.example/artifact@1.0``, returns ``com.example``.
    For ``pkg:npm/@scope/pkg@1.0``, returns ``@scope``.
    """
    try:
        without_scheme = purl.split("pkg:", 1)[1] if "pkg:" in purl else purl
        parts = without_scheme.split("/", 2)
        if len(parts) >= 3:
            return parts[1]
    except (IndexError, ValueError):
        # Malformed purl; return None to indicate that no group could be extracted.
        logger.debug("Failed to extract group from purl %r", purl, exc_info=True)
    return None
