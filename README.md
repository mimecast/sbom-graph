# sbom-graph

# Comming Soon

## Tool Overview and Capabilities

The tool processes dependency graphs generated from Software Bill of Materials (SBOM) files and features pre-configured reports and visualizations that deliver actionable insights. Its key capabilities include:

Vulnerability Impact Analysis: Identifies which projects are impacted by a vulnerability and prioritizes fixes based on interdependencies (e.g., determining which project updates must occur first to avoid cascading issues).

Detection of Bad Practices:
- Incorrect version pinning, which can cause runtime errors if improperly executed.
- Circular dependencies.
- Non-Semantic Versioning (Non-SemVer).
- Use of SNAPSHOT versions in production releases.

From the perspectives of AppSec, Architecture, and Engineering, these reports help uncover design flaws, poor practices, and errors. The tool is particularly valuable during zero-day vulnerability scenarios, enabling rapid identification of all affected projects and dependencies.

Strategic Potential and Future Enhancements

The tool also has potential for further enhancements by enriching the graph with additional data points. For example, by incorporating metrics such as the security and quality ratings of libraries, we can enable advanced dependency threat modeling. This will allows you to proactively identify and mitigate risks by replacing less secure libraries with more robust alternatives.

The Project is made up of 3 parts:

1. A Python library for processing CycloneDX files and storing them in a GraphDB
1. A Release Listener for SCA Scans that retrieves the CycloneDX file and processes it
1. A Flask application for visualizing graph data structures from FalkorDB, providing insights into dependency relationships, SNAPSHOT dependencies, and self-dependency detection.

   **Features**
    - **K-Partite Dependency Visualization**: Hierarchical visualization of transitive dependencies with color-coded partition levels
    - **Bi-Partite Graph**: Shows project versions and their direct dependants in a two-column layout
    - **Dependants Graph**: Full reverse dependency tree from a library back to leaf applications
    - **Excel Exports**: Download dependency data as Excel spreadsheets
    - **JSON Exports**: Download dependency data as JSON with documented schemas
    - **Reports**: HTML tables, Excel exports, and JSON exports for:
      - All projects with versions
      - SNAPSHOT dependencies
      - Self-dependency detection
      - Multi-version dependency source tracking
      - Non-SemVer version detection
      - Transitive dependencies (what a version depends on)
      - Dependants with partition levels and paths
    - **Interactive UI Features**:
      - Internal Only Toggle: Filter views between all projects and INTERNAL-labeled only
      - Dynamic download links that respect current filter state
      - Interactive API documentation with forms to test all endpoints
      - Frozen table headers: Headers stay visible while scrolling through data
