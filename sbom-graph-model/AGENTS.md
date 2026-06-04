# AGENTS.md - AI Agent Instructions for sbom-graph-model

This document provides instructions and context for AI agents working on this codebase.

## Working Agreements

- All agents must operate in Privacy mode and use only approved models.
- Each code-generating agent must use a different model and generate a complete design to be threat modeled before being implemented, correct design flaws and the implement the solution to be evaluated against the others.
- All code must be well-architected, elegant, maintainable, and thoroughly documented.
- Cognitive complexity should be minimized; rationale for complex logic must be documented.
- All public APIs and methods must be commented and included in documentation.

## Quality Gates

- No solution may progress unless all tests pass and no critical security issues remain.
- Performance regressions must be addressed before finalization.
- All code must meet maintainability and documentation standards.

## Escalation Procedures

- If an agent cannot resolve an issue, escalate to Orchestrator for arbitration.
- Orchestrator may request additional input or rework from any agent as needed.

## Domain Context

- **Internal prefix functionality**: The `Persistence` class supports `internal_prefixes` to mark projects as INTERNAL based on configurable field prefixes (`group`, `name`, `purl`). Use `parse_internal_prefixes()` to parse env strings and `is_internal(project)` to check a project. Document any changes to this behavior.

- **Kubernetes host resolution (`k8s_service_host.resolve_k8s_service_link_host`)**: Returns the input host unchanged by default. Service-link ClusterIP fallback (reading `<NAME>_SERVICE_HOST` env vars injected by kubelet when `enableServiceLinks: true`) is **opt-in** via `FALKORDB_USE_SERVICE_LINK=true`. The opt-in default exists because the Python redis client validates TLS certificates against the host in the connection URL; substituting a ClusterIP causes `CERTIFICATE_VERIFY_FAILED: IP address mismatch` because the cert SAN is the cluster DNS name. Only enable the opt-in when TLS to FalkorDB is disabled AND cluster DNS is unavailable in the pod. Helm deployments should additionally set `enableServiceLinks: false` on the pod spec so kubelet does not inject the env vars at all.
