# Security policy

## Reporting a vulnerability

Use this repository's **Security → Advisories → Report a vulnerability** when private vulnerability reporting is available. Do not include live private keys, master keys, temporary credentials, database archives, session tokens, or production host details in public issues.

If private reporting is unavailable, open an issue requesting a private contact without exploit details or sensitive attachments. The project does not currently publish a response-time SLA, bug bounty, independent audit certification, or long-term support commitment. Fixes target the maintained default branch; use the latest tested release and review its upgrade notes.

## Trust model

Host root, the core process, configuration, and trusted ingress source metadata are within the trust boundary. Encryption protects stored target private keys from disclosure without the master key; it does not protect them from a fully compromised core or host root.

Ingress processes have separate UIDs and restricted Unix sockets. The core checks peer credentials, capabilities, delegation constraints, request fields, current authorization, and audit availability. This is defense in depth, not a claim that compromise of an ingress process cannot affect the source metadata it supplies.

## Intended behavior

- Temporary usernames and passwords are intentionally displayed to the requester. A holder may use them within their recorded lifetime, purpose, source and usage limits.
- Ordinary SSH menu credentials and temporary endpoint credentials are distinct. Temporary accounts cannot mint web login tokens.
- Full target shells have the remote account's normal authority. Denying SFTP does not prevent an independently authorized shell from writing files.
- Exact command strings do not guarantee immutable behavior of scripts, binaries, arguments interpreted by the target shell, or mutable target configuration.
- Servers can validate observed SSH requests, not arbitrary client-side command lines, local file names, or local bind addresses.
- Generic SFTP path checks are not a race-proof remote filesystem sandbox. Strict isolation relies on a verified target-side chroot.
- Local event audit is not terminal recording, nonrepudiation of a natural person's identity, or externally immutable logging.

## Deployment responsibilities

Verify SSH host keys through a trusted channel, trust the correct HTTPS CA, protect master-key and backup material, retain independent maintenance SSH, and configure target users, sudo and isolation according to the intended access. Do not disable host verification or certificate checks to make a failed connection pass.

See [DESIGN.md](DESIGN.md), [IMPLEMENTATION.md](IMPLEMENTATION.md), and [TEST-REPORT.md](TEST-REPORT.md) for implementation and validation scope.
