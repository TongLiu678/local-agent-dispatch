# Security policy

local-agent-dispatch can inspect local system metadata and, when explicitly
configured, launch commands or workloads through remote adapters. Treat task
packets, runtime state, logs, and host inventories as sensitive operational
data even when the source code is public.

## Supported versions

| Version line | Security fixes |
| --- | --- |
| `0.1.x` | Supported |

Pre-release snapshots may change their state and packet formats. Use the
version and commit identifier when reporting an issue.

## Reporting a vulnerability

Please do not include credentials, private hostnames, SSH commands, personal
paths, provider account details, task prompts, or unredacted logs in a public
issue or pull request.

Use GitHub's private vulnerability reporting or a security advisory for this
repository when it is enabled. If private reporting is not available, open a
minimal public issue titled `[security] private contact requested` with no
exploit details; maintainers will provide a private channel. This project does
not treat a public issue as permission to reproduce an attack against a live
provider or server.

Include, through the private channel:

- affected version and operating system;
- a minimal reproduction using a fake provider or temporary directory;
- impact and the trust boundary crossed; and
- sanitized logs or a patch, if available.

The maintainers aim to acknowledge a report within five business days, provide
an initial severity assessment within ten business days, and coordinate a fix
and disclosure date with the reporter. Do not publish a proof of concept while
the affected release is unpatched.

## Security expectations for contributors

- Never commit API keys, access tokens, cookies, private keys, subscription
  snapshots, host inventories, or runtime state.
- Keep provider calls and remote execution opt-in, explicit, and visible in the
  dispatch plan. Offline commands must not authenticate or send prompts.
- Preserve path confinement, adapter allowlists, validation gates, artifact
  freshness checks, and shared-pool failure handling.
- Redact secrets from environment snapshots, command output, task packets,
  progress events, and error messages. A redaction test is required when a new
  field can carry credentials.
- Use temporary public-shaped fixtures for tests. Never use a real account,
  endpoint, dataset, model download, or server in CI.

If you suspect that a credential was committed, revoke it first, then report
the incident privately with only the minimum required context.
