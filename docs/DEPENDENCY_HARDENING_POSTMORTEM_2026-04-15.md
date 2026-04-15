# Dependency Hardening Postmortem - 2026-04-15

## 1. Executive Summary
This report documents the dependency hardening cycle performed on 2026-04-15 after detecting non-compliant security paths in the dependency graph and CI noise that increased merge risk.

The corrective strategy combined three tracks:
1. Security architecture correction (remove risky transitive routes).
2. CI/PR governance correction (close stale failing PRs and clarify check interpretation).
3. Operational hygiene correction (automate cleanup of transient artifacts).

## 2. Incident Context
### Observed Symptoms
- Presence of dependency routes tied to previously flagged cryptographic and randomness chains.
- Open dependency PRs remained unmerged because they were behind `main` and failing required checks.
- Orange/neutral `clippy` indicator caused operational confusion, while required workflow checks were the true merge blockers.

### Impact
- Increased risk of reintroducing vulnerable dependency paths.
- Reduced CI signal quality and higher chance of incorrect merge decisions.
- Additional maintenance overhead for repository owners.

## 3. Root-Cause Analysis (Scientific Format)
### 3.1 Primary Technical Causes
1. Excessive reliance on transitive security-sensitive crates via legacy integration choices.
2. Sanitization dependency choice introduced an avoidable legacy randomness path.
3. PR queue contained stale branches that no longer matched hardened `main` baseline.

### 3.2 Process Causes
1. Dependency updates were not consistently re-based on latest protected `main` before merge decisions.
2. Ambiguity in check naming/signaling (`clippy` required workflow vs neutral informational context) increased interpretation error probability.

### 3.3 Five-Whys Snapshot
1. Why did blockers persist? Because required checks failed on stale PR heads.
2. Why were PR heads stale? Because `main` changed with hardening updates and PRs were not synchronized.
3. Why did confusion happen? Because similarly named check contexts had different semantics.
4. Why did dependency risk exist? Because previous architecture accepted transitive security-sensitive routes unnecessarily.
5. Why was recurrence possible? Because cleanup and dependency-governance controls were incomplete.

## 4. Corrective Actions Executed
1. Removed legacy JWT dependency route and applied internal HS512 path.
2. Replaced HTML sanitizer dependency route with strict escaping approach.
3. Closed stale/failing dependency PRs that were behind `main` and non-mergeable under required protections.
4. Extended cleanup automation in `scripts/ci/cleanup_workspace.sh` to remove temporary/random artifacts and packaging residues.

## 5. Preventive Controls to Avoid Recurrence
### 5.1 Dependency Controls
1. Minimize security-critical transitive dependencies unless strictly required.
2. For each dependency update PR, require fresh rebase on latest `main` before merge decision.
3. Keep required checks mapped to authoritative workflows only.

### 5.2 CI and Governance Controls
1. Treat required check failure as a hard merge stop.
2. Treat neutral informational checks as non-blocking unless explicitly configured as required.
3. Periodically prune stale dependency PRs that are behind hardened baseline and failing checks.

### 5.3 Workspace Hygiene Controls
1. Run cleanup script before CI-critical validation when workspace reuse is possible.
2. Remove swap/temp/backup residues and packaging stage outputs systematically.

## 6. Verification Evidence
Validation was executed after hardening actions:
- `cargo update`
- `cargo check`
- `cargo test -q`
- `cargo audit -q`

Observed result: validation commands completed successfully on current baseline.

## 7. Outcome and Acceptance Criteria
Hardening cycle is considered complete for this phase when all conditions are true:
1. No open stale dependency PRs blocking operational clarity.
2. Required security/build checks are the only merge gate source of truth.
3. Dependency graph no longer includes the removed risky legacy routes.
4. Cleanup automation is active and documented.

## 8. Follow-Up Recommendation
Adopt a monthly dependency governance review with the following checklist:
1. Required checks health trend.
2. Stale PR age and failure status.
3. New transitive crypto/randomness paths.
4. Audit result deltas and remediation lead time.
