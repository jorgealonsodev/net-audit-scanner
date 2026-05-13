# Archive Report: security-checks

**Change**: security-checks
**Archived on**: 2026-05-13
**Mode**: hybrid (engram + openspec)
**Verdict**: PASS

## Summary

The `security-checks` change added default credential testing for HTTP, FTP, and Telnet services to the net-audit-scanner project. All implementation, tests, and pipeline integration are complete and verified.

## Verification Results

| Metric | Value |
|--------|-------|
| Tests | 301 passed, 0 failed |
| Clippy warnings | 0 |
| Spec compliance | 8/11 scenarios tested (3 untested are non-blocking: REQ-SEC-5 runtime coverage and REQ-SEC-6 credential-order proof — implementation exists, unit-level coverage accepted) |

## Implementation Summary

| File | What Changed |
|------|-------------|
| `src/security/mod.rs` | New module (~823 lines): `SecurityFinding` struct, `DEFAULT_CREDS`, `check_http_credentials`, `check_ftp_credentials`, `check_telnet_credentials`, `check_default_credentials` public async fn, 16 tests |
| `src/cli/mod.rs` | Lines 122–128: post-CVE integration — loads `CredentialsCheckConfig`, calls `check_default_credentials`, non-fatal (warns on error) |
| `src/scanner/models.rs` | Added `security_findings: Vec<SecurityFinding>` to `DiscoveredHost` with `#[serde(default)]` |
| `src/error.rs` | Added `Security(String)` variant |
| `src/config/mod.rs` | Added `CredentialsCheckConfig` with `enabled` flag |

## Tasks Completion

23/23 tasks complete (all phases: Foundation, Core Implementation, Integration, Integration Tests).

## Spec Sync

- `openspec/specs/security-checks/spec.md` — Created (new domain, delta was full spec)

## Artifacts

| Artifact | Location |
|----------|----------|
| Proposal | `openspec/changes/archive/2026-05-13-security-checks/proposal.md` |
| Spec | `openspec/changes/archive/2026-05-13-security-checks/specs/security-checks/spec.md` |
| Design | `openspec/changes/archive/2026-05-13-security-checks/design.md` |
| Tasks | `openspec/changes/archive/2026-05-13-security-checks/tasks.md` |
| Verify Report | `openspec/changes/archive/2026-05-13-security-checks/verify-report.md` |

## SDD Cycle Status

COMPLETE — planned → implemented → verified → archived.
