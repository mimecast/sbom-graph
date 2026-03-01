# AGENTS.md - AI Agent Instructions for AppSec Data Views

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
