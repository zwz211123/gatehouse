# Gatehouse

[Documentation (中文)](https://zwz211123.github.io/gatehouse/) · [Quick start (中文)](docs/quickstart.md)

[简体中文](README.md)

An SSH bastion for Debian-based systems, with delegated access control, SSH-issued web login, and temporary credentials for standard SSH clients.

Users authenticate with their public key to a controlled menu. They can connect to authorized target accounts or request a temporary endpoint for a specific purpose. Temporary usernames and passwords are displayed together with complete connection details and a ready-to-run Bash command. Temporary connections authenticate with that password, not with the original user's key.

## Features

- Target servers, pinned SSH host keys, encrypted target private keys, accounts, users, public keys, and groups.
- Capability and resource scopes, delegation chains, cascading revocation, source CIDRs, time windows, connection/channel limits, traffic and shared rate limits.
- Interactive SSH, exact remote commands, SFTP, modern SCP, and fixed-destination TCP forwarding.
- Web administration using a one-time token obtained through `web login` in an existing ordinary SSH menu session. No password, TOTP, Passkey, or account-recovery web login.
- SSH confirmation bound to each web mutation, optimistic record concurrency, encrypted backups, separate master-key export, and offline recovery.
- Four component packages plus a meta package for `amd64` and `arm64`. Go and Node.js are not runtime requirements.

The web interface is currently in Chinese. This is a single-node application; it is not an unrestricted transparent SSH relay.

## Install

Use a Debian-based Linux host running systemd. Prepare an administrator public key and a TLS certificate/private key matching the public web hostname. Product ports default to SSH 2222 and HTTPS 8443. The system's maintenance SSH service is retained.

Download the appropriate architecture bundle from [Releases](https://github.com/zwz211123/gatehouse/releases), or [build from source](docs/development.md) if no assets are available.

~~~bash
mkdir gatehouse-install
tar -xzf gatehouse-0.2.1-amd64.tar.gz -C gatehouse-install
cd gatehouse-install
sha256sum -c SHA256SUMS-amd64
sudo bash install.sh

sudo ghbctl init \
  --user admin \
  --public-key /root/admin.pub \
  --public-host jump.example.com \
  --public-port 2222 \
  --web-url https://jump.example.com:8443 \
  --web-listen 0.0.0.0:8443 \
  --tls-cert /root/tls/fullchain.pem \
  --tls-key /root/tls/key.pem

sudo bash acceptance.sh
~~~

Replace the example hostname and file paths with your own. Configure DNS, firewall access, and certificate trust first. Use the matching `arm64` bundle on ARM64 hosts. Existing installations must follow [UPGRADE.md](UPGRADE.md) and must not run `init` again.

## Connect

~~~bash
ssh -p 2222 -i ~/.ssh/id_ed25519 admin@jump.example.com
~~~

In the Gatehouse menu:

~~~text
list
connect ACCOUNT_ID
web login
proxy create
~~~

In the web manager, prepare a credential, register the target's verified SSH host keys, bind a target account, and grant access. Targets normally only need an existing SSH server and the corresponding authorized public key; no Gatehouse agent is required.

## Security boundaries

Temporary credentials are intentionally displayed and are usable by whoever holds them, subject to the recorded restrictions. An authorized full target shell retains the target account's normal program and file access. SFTP restrictions do not sandbox a separate shell permission.

Host root, the core process, and deployment configuration are trusted. Auditing is local event logging, not terminal recording or an external tamper-proof ledger. Strict file isolation relies on a verified target-side chroot. Generic path checks are not a system sandbox.

Read [SECURITY.md](SECURITY.md) before deployment. Most detailed operational documentation and the web UI are currently in Chinese.

## Development

~~~bash
go mod download
go test -race ./...
go vet ./...
python3 packaging/build.py
~~~

The minimum Go version is specified in `go.mod`. HTML/CSS/JavaScript assets are embedded in the binaries. See [CONTRIBUTING.md](CONTRIBUTING.md), [development](docs/development.md), and the explicitly scoped [test report](TEST-REPORT.md).

## License

[MIT](LICENSE); dependency notices are in [THIRD-PARTY-LICENSES.txt](THIRD-PARTY-LICENSES.txt).
