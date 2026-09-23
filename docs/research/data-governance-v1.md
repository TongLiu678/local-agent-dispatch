# Data Governance v1 (WP0)

Frozen data policy for the local-agent-dispatch research program. Its public
research context is [`docs/research-program.md`](../research-program.md); the
repository `SKILL.md` supplies the operational privacy rules.

## 1. Data classes

| Class | Examples | Handling |
| --- | --- | --- |
| `public` | sanitized fixtures, scenarios, this repository's committed files | commit normally |
| `internal` | run metadata, digests, redacted summaries | store locally; publish only redacted projections |
| `sensitive` | prompts, private code, SSH details, tokens, user-behavior traces | stay local; never published |
| `forbidden_remote` | credentials, private keys, unlicensed data | never leave the machine |

Unknown classification defaults to `sensitive` and stays local.

## 2. Local-first rules

- Prompts, private code, SSH details, tokens, and user-behavior traces remain
  local.
- Hashes, references, and redacted summaries are stored by default; prompt
  bodies and credentials are refused by the provenance store and removed by
  public projections.
- Large files use a data plane, never prompts or the control-message channel.
- Runtime state defaults to `$HOME/.codex/local-agent-dispatch` (relocatable
  via `LOCAL_AGENT_DISPATCH_HOME`); private inventories stay outside the
  repository.

## 3. Repository commit rules

For this public repository, commit only source, tests, templates, schemas,
and sanitized examples. Never commit:

- `hosts.json`, preflight/runtime snapshots, provider account details;
- PIDs, logs, task packets, local paths, SSH endpoints, artifacts;
- credentials, tokens, or private inventories.

## 4. Publication and retention

- Publish only synthetic or manually scrubbed traces.
- Set explicit retention and deletion rules for behavioral and usage data;
  stale PIDs, temporary clones, and Git packs are the dominant retained bytes
  and are prime cleanup targets.
- Verify dataset/model/code licenses before any remote copy or public
  release.

## 5. Prohibitions

- Never use the scheduler to bypass quotas, account rules, or provider terms.
- Never let an LLM judge alone promote scientific claims or irreversible
  work.
- Never convert unknown quota/cost/resource state into a fabricated number;
  report `unknown`.

## 6. Research stops on data grounds

- Privacy leak or unauthorized side effect -> stop and revert to shadow.
- Telemetry too incomplete to determine safe execution -> stop execution.
