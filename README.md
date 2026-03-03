![SBOM-Graph](./sbom-graph-logo.jpeg)

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

The project is made up of 3 parts:

1. **sbom-graph-model** -- A Python library for processing CycloneDX files and storing them in a GraphDB
2. **sonatype-lifecycle-release-listener** -- A release listener for SCA scans that retrieves the CycloneDX file and processes it
3. **sbom-graph-api** -- A Flask application for visualizing graph data, ingesting CycloneDX SBOMs via authenticated API, and providing insights into dependency relationships, SNAPSHOT dependencies, and self-dependency detection

For detailed architecture documentation, see [SPECIFICATION.md](SPECIFICATION.md).
For a full deployment walkthrough (prerequisites, TLS setup, Helm configuration, local and remote Kubernetes), see [GETTING_STARTED.md](GETTING_STARTED.md).

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
  - **Supply-Chain Trust Score**: Composite trust score combining signals from OpenSSF Scorecard, OSV, Sonatype OSS Index, and deps.dev. Four-category scoring (Security Practices, Vulnerability Profile, Maintenance Health, Supply-Chain Hygiene). Inherited risk propagation through the dependency graph. CI/CD gate endpoint for policy enforcement. Remediation priority analysis.

## Project Structure

```
sbom-graph/
├── sbom-graph-model/     # Python library for CycloneDX → FalkorDB
├── sbom-graph-api/     # Flask visualization app
├── sonatype-lifecycle-release-listener/      # SCA scan release listener
├── helm/
│   └── sbom-graph/        # Umbrella Helm chart for all components
├── build-images.sh       # Docker build script
└── SPECIFICATION.md      # Detailed architecture documentation
```

## Deployment

Deploy all components (FalkorDB, data-views, sonatype-lifecycle-release-listener) with the umbrella Helm chart:

```bash
helm install sbom-graph ./helm/sbom-graph
```

## Docker Builds

All Docker images are built from the **repository root** because Dockerfiles
reference sibling project directories. A build script is provided to handle
build ordering and dependencies.

### Build all images

```bash
./build-images.sh
```

This will:

1. Build the `sbom-graph-model` wheel (required by `sonatype-lifecycle-release-listener`)
2. Build the `sbom-graph-api` Docker image
3. Build the `sonatype-lifecycle-release-listener` Docker image

### Build individual targets

```bash
./build-images.sh model                # Wheel only
./build-images.sh sbom-graph-api    # sbom-graph-api image only
./build-images.sh sonatype-lifecycle-release-listener     # sonatype-lifecycle-release-listener image only (auto-builds wheel if missing)
```

### Custom image tags

```bash
./build-images.sh --adv-tag myrepo/adv:v2 --rl-tag myrepo/rl:v2
```

### Rebuild without cache

```bash
./build-images.sh --no-cache
```

Run `./build-images.sh --help` for the full list of options.

## License

This project is open source under the **MIT** licence.

### Infrastructure Dependency: FalkorDB (SSPLv1)

This project depends on [FalkorDB](https://www.falkordb.com/) as its graph
database. FalkorDB is licensed under the **Server Side Public License v1
(SSPLv1)**, which has implications for how the complete stack can be deployed:

| Deployment Scenario | SSPLv1 Obligation |
|---------------------|-------------------|
| **Internal use** (not offered as a service to third parties) | No restrictions. Use freely. |
| **Offered as a service to external users** (e.g., SaaS, hosted API) | You must open-source the **entire service stack** under SSPLv1 — or obtain a [commercial licence](https://www.falkordb.com/) from FalkorDB. |
| **Distributing this source code** (without FalkorDB binary) | No SSPL obligation. MIT applies to this code. |

The SSPLv1 applies to the FalkorDB **server binary** only. The FalkorDB Python
client library used by this project is MIT-licensed. This project's MIT licence
does not conflict with the SSPL because FalkorDB is consumed as a separate
network service, not linked or embedded.

**If your organisation cannot accept SSPLv1 terms**, you will need either a
commercial FalkorDB licence or to adapt the persistence layer to use an
alternatively-licensed graph database.

### Other Dependencies

All Python library dependencies use permissive licences (MIT, BSD-3, Apache-2.0)
with one exception: **ldap3** (LGPL-3, weak copyleft). See
[threat-model.md](threat-model.md) for the full licence assessment.

## Contributing

Contact the Brett Crawley for contribution guidelines.
