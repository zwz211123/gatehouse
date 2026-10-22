# Contributing

Gatehouse accepts focused bug fixes, tests, documentation improvements and access-control changes with clear security boundaries. User documentation and the web UI currently use Simplified Chinese; English issue reports and pull requests are welcome.

## Before opening a pull request

1. Read [DESIGN.md](DESIGN.md) and [SECURITY.md](SECURITY.md).
2. Describe a concrete problem and the resulting behavior. Keep unrelated refactors separate.
3. Preserve existing database identities, encrypted envelopes and privilege boundaries. Schema changes need an explicit migration and recovery plan.
4. Run the checks relevant to your change; see [development](docs/development.md).
5. For security-sensitive changes, add a regression test showing both the allowed case and the denied case. Do not add tests that merely repeat implementation details.

Do not commit generated private keys, instance configurations, certificates, databases, backups, live credentials, environment files or release binaries. Test keys must be generated at runtime. Runtime state and generated artifacts are excluded from the repository and source archives.

## Changes requiring particular care

- Delegation, deny rules, group membership and source conditions must not widen a parent's scope.
- Web UI permissions are not authorization. Core checks remain authoritative.
- A displayed temporary password and a target shell's normal file access are intended features.
- SSH host verification must remain enabled. Client compatibility does not justify silently authorizing extra requests.
- Backup and upgrade checks must fail closed. Do not rewrite existing identity material without an explicitly requested rotation.

## Pull requests

Include the trigger, before/after behavior, relevant tests and any validation gaps. Do not describe an unexecuted deployment or browser check as passed. Use the existing MIT license for contributions unless discussed with maintainers before submission.

For suspected vulnerabilities, follow [SECURITY.md](SECURITY.md) instead of posting production data publicly.
