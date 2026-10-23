# Changelog

## Unreleased

- Render bundled and Debian package documentation with the package build identity; correct documentation versioning instructions while preserving source templates and historical versions.
- Inject release versions and source commits at build time; use explicit development identities for ordinary CI and local builds.
- Derive Debian versions, installer package selection, source archive metadata and documentation from one build identity, with prerelease ordering and publish-time cross-checks.

- Add fish-style fuzzy Tab candidates with descriptions and cycling, plus `clear`.
- Generate shortcuts for every requested purpose and select output through numeric menus.
- Review credentials with `proxy list` / `proxy show`; store new temporary passwords directly while accepting legacy hashes.
- Delete inactive revoked, expired, or fully consumed credentials individually or with `d all` in `proxy list`, preserving audit history.

## 0.2.1

### Web administration

- Replace the generic management view with grouped navigation, an overview, named references, search, pagination and readable dates/statuses.
- Explicitly distinguish retaining, importing and generating target private keys. Preserve existing keys by default and reject simultaneous generation/import inputs.
- Add capability/resource choices and quota units. Preserve references that the current user cannot read.
- Retain SSH-bound change confirmation, concurrent-record checks and sensitive-state cleanup.

### Upgrade handling

- Keep database schema 1 and existing encrypted envelopes, identities and record revisions.
- Add offline `ghbctl upgrade-check` and a root-only pre-upgrade snapshot with before/after state comparison.
- Document installation, rollback, backup and operational verification.

### Public project

- Publish the module as `github.com/zwz211123/gatehouse` under MIT.
- Replace deployment-specific documents with reusable examples and contributor documentation.
- Add public CI and package-artifact workflows. Workflow configuration is not a claim that remote checks have already passed.

## 0.2.0

- Harden delegation/deny handling, source CIDR checks and owner protection.
- Add exclusive data locks, graceful process termination and protocol timeout handling.
- Improve TCP half-close handling, SCP path safety and mixed shell/SFTP PTY checks.
- Add doctor, TLS pair rotation and deployment acceptance tools.

## 0.1.0

- Initial SSH menu, delegated permissions, temporary endpoints, web administration and backup implementation.
