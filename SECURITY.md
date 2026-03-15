# Security Policy

Mission Clearance is a security-focused project that manages permissions for
autonomous AI agents. We take vulnerability reports seriously and appreciate
responsible disclosure.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, please report vulnerabilities privately:

1. **Email:** Send a detailed report to the repository maintainers via GitHub's
   private vulnerability reporting feature (Security tab > "Report a
   vulnerability").
2. **Include:**
   - A description of the vulnerability and its potential impact.
   - Steps to reproduce or a proof-of-concept.
   - The affected crate(s) and version(s).
   - Any suggested fix, if you have one.

## What to Expect

- **Acknowledgment:** We will acknowledge receipt of your report within 48
  hours.
- **Assessment:** We will assess severity and impact within 7 days.
- **Fix timeline:** Critical vulnerabilities (e.g., vault key exposure, policy
  bypass, trace log tampering) will be prioritized for a fix within 14 days.
  Lower-severity issues will be scheduled for the next release.
- **Disclosure:** We will coordinate disclosure timing with you. We aim for a
  fix to be available before any public disclosure.

## Scope

The following areas are especially security-sensitive:

- **mc-vault** -- Encryption, key derivation, credential storage and retrieval.
  Any bypass of AES-256-GCM encryption or Argon2id key derivation is critical.
- **mc-kernel** -- Capability checking and content analysis. Any bypass that
  allows an operation without a matching capability is critical.
- **mc-policy** -- Policy pipeline evaluation. Any bypass of fail-closed
  semantics or deterministic deny rules is critical.
- **mc-trace** -- Tamper-evidence of the SHA-256 chained event log. Any ability
  to modify or delete events without detection is critical.
- **mc-core** -- Resource pattern matching. Any pattern that matches more
  broadly than intended could escalate privileges.
- **mc-adapters** -- Protocol normalization. Any request that is normalized
  incorrectly could bypass policy checks.
- **mc-api** -- Authentication and authorization. Any unauthenticated access to
  protected endpoints is high severity.

## Out of Scope

- Denial-of-service attacks against the local API server (it is intended to run
  as a local sidecar, not exposed to the internet).
- Issues in development dependencies or test-only code that do not affect the
  published crates.

## Recognition

We are happy to credit reporters in release notes (with your permission).

Thank you for helping keep Mission Clearance secure.
