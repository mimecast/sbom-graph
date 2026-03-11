# AGENTS.md — Monorepo Governance for AI Agents

This is the **authoritative, highest-bar governance document** for AI agents across the entire `sbom-graph` monorepo. Sub-project `AGENTS.md` files inherit these standards and may only add project-specific technical context — they must never weaken the rules defined here.

## Project Overview

`sbom-graph` is a monorepo for building, enriching, and visualising software dependency graphs from SBOM files. It stores data in FalkorDB and provides reports, visualisations, policy enforcement, and supply-chain trust scoring.

### Sub-Projects

| Sub-Project | Description | AGENTS.md |
|-------------|-------------|-----------|
| `sbom-graph-model` | Python library for parsing CycloneDX/SPDX SBOMs and persisting them to FalkorDB | [`sbom-graph-model/AGENTS.md`](sbom-graph-model/AGENTS.md) |
| `sbom-graph-api` | Flask application for REST API, reports, visualisations, and interactive documentation | [`sbom-graph-api/AGENTS.md`](sbom-graph-api/AGENTS.md) |
| `sbom-graph-enrichment` | Celery-based enrichment pipeline querying OSV, ClearlyDefined, OpenSSF Scorecard, Sonatype OSS Index, and deps.dev | [`sbom-graph-enrichment/AGENTS.md`](sbom-graph-enrichment/AGENTS.md) |
| `sonatype-lifecycle-release-listener` | Flask microservice receiving SCA webhook events and ingesting SBOMs | [`sonatype-lifecycle-release-listener/AGENTS.md`](sonatype-lifecycle-release-listener/AGENTS.md) |
| `sbom-graph-cli` | CLI for ingestion, querying, policy annotation, and report export | [`sbom-graph-cli/AGENTS.md`](sbom-graph-cli/AGENTS.md) |

### Cross-Project Dependencies

```
sbom-graph-api ──────────────► sbom-graph-model ◄──── sonatype-lifecycle-release-listener
       │                              ▲
       │ (optional)                   │
       ▼                              │
sbom-graph-enrichment ────────────────┘

sbom-graph-cli ──────────────► sbom-graph-api (HTTP client)

All sub-projects (except cli) ──► FalkorDB (shared graph database)
```

- `sbom-graph-api` depends on `sbom-graph-model` and optionally `sbom-graph-enrichment`
- `sbom-graph-enrichment` depends on `sbom-graph-model`
- `sonatype-lifecycle-release-listener` depends on `sbom-graph-model`
- `sbom-graph-cli` communicates with `sbom-graph-api` via HTTP (no direct model dependency)
- `sbom-graph-cli` is a standalone CLI that calls the sbom-graph API (no direct FalkorDB dependency)
- All sub-projects except sbom-graph-cli share FalkorDB as the backing store

---

## Working Agreements (Mandatory)

These agreements apply to **all** sub-projects without exception.

1. All agents must operate in Privacy mode and use only approved models.
2. Each code-generating agent must use a different model and focus area.
3. **Each code-generating agent must generate a complete design to be threat modelled before implementation, correct design flaws, and then implement the solution to be evaluated against the others.** This is non-negotiable for all new features and architectural changes.
4. All code must be well-architected, elegant, maintainable, and thoroughly documented.
5. Cognitive complexity must be minimised; rationale for complex logic must be documented inline.
6. All public APIs and methods must have docstrings/comments and be reflected in documentation.
7. **No hardcoded secrets, credentials, or API keys** in any code, configuration, or test fixture. Secrets must come from environment variables or a secret manager.
8. **All user input must be validated and sanitised** before use.
9. **Parameterised queries only** — no string concatenation for database queries (Cypher, SQL, or otherwise).
10. **Never include exception details in HTTP responses** (CWE-209: Generation of Error Message Containing Sensitive Information, CWE-497: Exposure of Sensitive System Information to an Unauthorized Control Sphere). Return a static, descriptive error message to the client instead. Exception details in log messages are acceptable at debug level only.
11. All agents must communicate findings in Markdown, using clear section headers and evidence appendices.

---

## Agent Roles

All seven roles are defined here. Every sub-project must recognise and use these roles during multi-agent workflows.

### CodeGenAlpha — Maintainability, Documentation, and Clarity

- Generate code from specification, prioritising readability and extensibility.
- Ensure all public interfaces have comprehensive docstrings.
- Favour explicit patterns over clever abstractions.

### CodeGenBeta — Performance and Cognitive Simplicity

- Generate code from specification, optimising for speed and resource usage.
- Minimise cognitive complexity and eliminate unnecessary indirection.
- Benchmark critical paths and document performance characteristics.

### CodeGenGamma — Security and Architectural Elegance

- Generate code from specification, ensuring secure-by-default patterns and robust design.
- Apply defence-in-depth: input validation, output encoding, least privilege.
- Identify and address OWASP Top 10 and CWE Top 25 risks in generated code.

### Orchestrator

- Review and critique all codegen outputs.
- Aggregate the best, most secure, performant, and elegant aspects into a single cohesive solution.
- Document all integration decisions and rationale.
- Arbitrate conflicts between agents; may request rework from any agent.

### TestingAgent

- Write and run tests (`pytest`).
- Validate correctness, edge cases, and code coverage.
- Report and escalate test failures.
- Ensure new code includes corresponding tests.

### PerformanceAgent

- Benchmark and profile code for CPU and memory bottlenecks.
- Suggest and implement optimisations.
- Verify no performance regressions are introduced.
- Provide benchmarks for hot paths and data-intensive operations.

### SecurityAgent

- Perform SAST and SCA scans at **all** workflow stages.
- Run threat model review on designs **before** implementation begins.
- Flag vulnerabilities and enforce remediation.
- **Block progression** if critical or high severity findings remain unresolved.
- SecurityAgent's ruling on security matters is final.

---

## Workflow Coordination

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  CodeGenAlpha   │     │  CodeGenBeta    │     │  CodeGenGamma   │
│  (Maintainable) │     │  (Performant)   │     │  (Secure)       │
└────────┬────────┘     └────────┬────────┘     └────────┬────────┘
         │                       │                       │
         │   ┌───────────────────┼───────────────────┐   │
         │   │ SecurityAgent: Threat model review    │   │
         │   │ BEFORE implementation proceeds        │   │
         │   └───────────────────┼───────────────────┘   │
         │                       │                       │
         ▼                       ▼                       ▼
┌────────────────────────────────────────────────────────────────┐
│  Parallel Implementation (each agent produces independent     │
│  solution informed by approved design)                        │
└────────────────────────┬───────────────────────────────────────┘
                         │
         ┌───────────────┼───────────────────────┐
         ▼               ▼                       ▼
┌─────────────┐  ┌──────────────┐  ┌──────────────────┐
│ TestingAgent│  │ Performance  │  │  SecurityAgent    │
│ (Tests)     │  │ Agent        │  │  (SAST, SCA)      │
└──────┬──────┘  └──────┬───────┘  └────────┬─────────┘
       │                │                    │
       └────────────────┼────────────────────┘
                        ▼
              ┌──────────────────┐
              │   Orchestrator   │
              │  (Aggregate &    │
              │   finalise)      │
              └──────────────────┘
```

1. CodeGen agents produce independent designs.
2. **SecurityAgent runs threat model review on designs before implementation begins.** Designs with critical flaws are sent back for correction.
3. After design approval, CodeGen agents implement in parallel.
4. SecurityAgent, TestingAgent, and PerformanceAgent run their respective gates.
5. Orchestrator aggregates and finalises the solution **only after all gates pass**.

---

## Quality Gates (Mandatory, Non-Negotiable)

No solution may progress past a gate until its criteria are met.

### Testing

- All existing tests must pass. New code must include tests.
- Code coverage must not decrease.
- Integration tests required for new database queries or external API interactions.

### Security

- **No critical or high severity findings** may remain unresolved.
- **SAST scans are mandatory** before completion: Snyk Code, Bandit.
- **SCA scans are mandatory** when dependencies change: Sonatype IQ.
- **Threat modelling is required** for new features and architectural changes.
- No hardcoded secrets or credentials in code, config, or tests.
- No exception details in HTTP responses (CWE-209, CWE-497); debug-level logs only.

### Performance

- No performance regressions.
- Benchmarks required for hot paths and data-intensive operations.
- Memory and CPU profiling for new processing pipelines.

### Documentation

- All code must meet documentation standards (docstrings, comments for non-obvious logic).
- The following documentation must be updated when relevant changes are made:
  - `AGENTS.md` (root or sub-project): agent roles, working agreements, workflow patterns
  - `README.md`: user-facing features, deployment, configuration
  - `api_docs.html`: any API endpoint addition or modification
  - Sub-project `AGENTS.md`: project-specific technical patterns, services, architecture
- **This is non-optional.** Failing to update documentation is a gate failure.

### Code Style

- PEP 8 compliance enforced via `ruff check` and `ruff format`.
- Type hints required on all function signatures.
- Maximum line length: 88 characters (ruff default).

---

## Escalation Procedures

1. If an agent cannot resolve an issue, escalate to **Orchestrator** for arbitration.
2. Orchestrator may request additional input or rework from any agent.
3. If Orchestrator and SecurityAgent disagree on a finding, **SecurityAgent's ruling on security matters is final**.
4. Unresolvable conflicts between non-security concerns are decided by Orchestrator with documented rationale.

---

## Shared Infrastructure

| Component | Purpose |
|-----------|---------|
| **FalkorDB** | Graph database (shared by all sub-projects) |
| **Helm umbrella chart** (`helm/sbom-graph/`) | Deploys all components together |
| **`build-images.sh`** | Docker build script for all images |
| **`uv`** | Package manager (not Poetry, not pip) |
| **`pytest`** | Testing framework across all sub-projects |
| **`ruff`** | Linting and formatting |
| **Snyk Code** | SAST scanning |
| **Bandit** | Additional Python static analysis |
| **Sonatype IQ** | SCA dependency scanning |

---

## Documentation Update Triggers

| File | Update When |
|------|-------------|
| `AGENTS.md` (root) | Adding agent roles, changing working agreements, modifying workflow patterns |
| `README.md` | Adding user-facing features, changing deployment, modifying configuration |
| `api_docs.html` | Adding or modifying any API endpoint |
| Sub-project `AGENTS.md` | Changing project-specific technical patterns, adding services, modifying architecture |
| `SPECIFICATION.md` | Architectural changes, new component integration |
| `GETTING_STARTED.md` | Deployment procedure changes, new prerequisites |
