---
name: composite-skills
description: Modular skills for code generation, review, testing, performance, and security in a multi-agent system.
version: 1.0
license: MIT
---

# Composite SKILLS.md

## Code Generation Skills

- **well-architected-design**:  
  - Follow SOLID, DRY, and KISS principles.  
  - Modularize code, separate concerns, and ensure extensibility.
  - Use architecture patterns, design patterns, security patterns
  - Carefully select appropriate data structures and algorithms

- **cognitive-complexity-management**:  
  - Minimize nested logic, use clear control flow, and refactor complex methods.  
  - Document rationale for non-trivial decisions.

- **documentation-and-commenting**:  
  - Every public method/class must have docstrings.  
  - Inline comments for non-obvious logic.  
  - Update `README.md` and `docs/` for new features.

- **maintainability**:  
  - Use descriptive names, avoid magic numbers, and ensure testability.  
  - Refactor duplicated code.

## Review & Aggregation Skills

- **multi-agent-critique**:  
  - Compare all codegen outputs for correctness, security, performance, and elegance.  
  - Identify strengths and weaknesses of each solution.

- **solution-aggregation**:  
  - Merge the best aspects of each solution into a single, cohesive codebase.  
  - Resolve conflicts and document integration decisions.

## Testing Skills

- **test-generation**:  
  - Write comprehensive unit and integration tests.  
  - Ensure at least 90% code coverage.

- **test-validation**:  
  - Run all tests, report failures, and suggest fixes.

## Performance Skills

- **benchmarking**:  
  - Profile code for bottlenecks.  
  - Suggest and implement optimizations.

- **resource-usage-analysis**:  
  - Monitor memory and CPU usage, recommend improvements.

## Security Skills

- **threat-modeling**
  - Threat model the design before implementation and correct design flaws
  - Threat model the choice of 3rd party components based on the project level security practices (frequency of vulnerabilities, mean time to remediate and average number of open vulnerabilities), only consider projects that are actively maintained, with an established user base and a good reputation. Then choose the project that has the best features for the lowest risk on balance.

- **sast-scan**:  
  - Run static analysis tools (e.g., Bandit, Snyk, CodeQL) on all code.  
  - Flag vulnerabilities and suggest remediations.

- **sca-scan**:  
  - Analyze dependencies for known vulnerabilities (e.g., SonaType, OWASP Dependency-Check).  
  - Enforce license compliance.

- **security-remediation**:  
  - Apply or recommend fixes for all critical/high vulnerabilities before progression.

## Output Format

- All agents must output results in Markdown with clear section headers.
- Include evidence (test logs, scan reports, benchmarks) as appendices.
- Summarize key findings and decisions at the top of each output.

---

> **Note:**  
> Skills are modular and can be invoked independently or in sequence as required by the workflow.
