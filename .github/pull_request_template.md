## Security-Strict Pull Request Checklist

### Governance
- [ ] Change is scoped and minimal, with no unrelated edits.
- [ ] All branch protection checks are passing.
- [ ] At least one approving review is present.
- [ ] All review conversations are resolved.

### Security Controls
- [ ] No plaintext secrets, tokens, or keys were introduced.
- [ ] Authentication and authorization logic remains centralized.
- [ ] Rate limiting, input validation, and error handling were preserved.
- [ ] Docker/runtime changes do not run as root unless explicitly justified.

### Multi-Language Assurance
- [ ] Security impact considered for all touched language surfaces.
- [ ] Semgrep, CodeQL, and Trivy findings are reviewed and addressed.
- [ ] Dependency changes are justified and vulnerability-audited.

### Validation Evidence
- [ ] Local tests and relevant integration/security tests pass.
- [ ] CI evidence is attached or visible in workflow runs.
- [ ] Documentation and changelog are updated for security-impacting changes.

### Risk Statement
Provide a short risk summary and rollback plan for this change.
