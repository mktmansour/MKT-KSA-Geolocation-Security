# Security Policy

This document defines strict engineering and operational security controls for this repository.

## Supported Versions

| Version line | Security support |
| --- | --- |
| 2.x | Supported |
| 1.x | Not supported |

Only the latest stable line receives security patches.

## Security Engineering Baseline

These controls are mandatory for all code regardless of implementation language.

1. Authentication and authorization
- Centralized auth validation path only.
- No endpoint-local hardcoded secrets.
- Least-privilege claim checks.

2. Secrets and key management
- No plaintext secrets in code, tests, or docs.
- Secret scanning and push protection are required.
- Exposed token or key must be revoked and rotated immediately.

3. Dependency and supply chain
- Lockfiles are required for deterministic builds.
- Critical and high dependency findings fail CI.
- Third-party caches and build artifacts must stay out of analysis scope and VCS tracking.

4. CI and workflow security
- Explicit workflow permissions are required.
- Security workflows are required checks for main branch integration.
- Direct pushes to protected branch must be disabled in repository settings.

5. Cryptography
- Only approved modern algorithms are allowed.
- Weak or obsolete algorithms are prohibited.
- Crypto behavior must be tested and centrally reviewed.

6. Logging and privacy
- Security logs must not leak credentials or sensitive user data.
- Structured logs are required for incident response.

## Multi-Language Security Coverage

This repository enforces layered controls designed to stay valid as services are added in Rust, Go, Python, JavaScript, Java, or other languages.

1. Static analysis
- CodeQL workflow for repository-relevant scope.
- Semgrep multi-language SAST workflow.

2. Secret detection
- Gitleaks workflow for commit history and workspace leaks.
- GitHub Secret Scanning must be enabled at repository level.

3. Dependency and filesystem risk
- Trivy workflow for high and critical findings.
- Language-specific advisories must be denied at CI gate.

## Vulnerability Reporting

Do not open public issues for vulnerabilities.

Report privately using one of the following:
- GitHub Security Advisory (preferred)
- Email: mkt-edge@outlook.sa

Include:
- Clear vulnerability description
- Reproduction steps
- Expected vs actual secure behavior
- Impact assessment
- Optional proof of concept

## Response SLA

- Initial triage response: within 2 business days
- Confirmed vulnerability remediation target: 7 to 14 days
- Status updates continue until closure

## Secure Change Requirements

Every security-sensitive change must include:
1. Threat-focused test coverage
2. CI evidence with passing required checks
3. Changelog entry documenting security impact
4. Updated security documentation when control behavior changes


