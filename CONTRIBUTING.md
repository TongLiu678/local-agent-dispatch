# Contributing to local-agent-dispatch

Thank you for helping improve local-agent-dispatch. The project is an
offline-first dispatch and planning toolkit: it inventories a machine,
describes resource and quota constraints, and produces reviewable packets for
an explicitly configured runtime. Contributions should preserve that boundary.

## Development setup

The package has no runtime dependencies beyond Python. Use Python 3.10 or
newer and work from a clean checkout:

```bash
python -m pip install --no-deps -e .
```

The command-line entry point is `lad`. `lad doctor --offline` and
`lad demo --offline` are safe smoke checks; they do not authenticate, contact a
provider, or send a model prompt.

## Required checks

Before opening a pull request, run the same provider-free checks used by CI:

```bash
PYTHONDONTWRITEBYTECODE=1 python -m unittest discover -s tests -p 'test_*.py'
python -m compileall -q src scripts
for script in scripts/*.sh; do bash -n "$script"; done
python -m local_agent_dispatch.cli --version
python -m local_agent_dispatch.cli doctor --offline
python -m local_agent_dispatch.cli demo --offline
wheel_dir=$(mktemp -d)
install_dir=$(mktemp -d)
python -m pip wheel --no-deps --no-build-isolation -w "$wheel_dir" .
python -m pip install --no-deps --target "$install_dir" "$wheel_dir"/*.whl
PYTHONPATH="$install_dir" python -m local_agent_dispatch.cli doctor --offline
```

Tests must be deterministic and must not require a subscription, account,
network endpoint, GPU, SSH host, or private file. Use fake providers, temporary
directories, and saved public-shaped fixtures for provider or remote-runtime
behavior.

## Design and implementation rules

- Keep system discovery read-only and redact credentials, environment values,
  process arguments, and personal paths from public snapshots.
- Treat model catalog visibility, runtime acceptance, quota, and host
  reachability as separate pieces of evidence. Do not turn an unknown value
  into an available quota or a ready host.
- Preserve explicit model IDs, variants, shared-pool accounting, validation
  commands, artifact freshness checks, and write-scope boundaries.
- Keep desktop-authenticated model execution separate from remote workload
  placement. Remote work must use an explicit, reviewed adapter and a verified
  server-side route.
- Do not add standalone Claude/DeepSeek dispatch backends or silently broaden
  the approved model policy.
- Do not put credentials, subscription data, SSH endpoints, machine-specific
  paths, runtime state, logs, model artifacts, or downloaded data in the
  repository. Add sanitized fixtures instead.

## Adding a provider or runtime

New integrations should expose a small adapter contract and a fake adapter for
tests. Document:

1. how the catalog and capability evidence are collected without sending a
   prompt;
2. how quota, rate limits, authentication failures, and capability rejections
   affect the shared pool;
3. what exact command or API invocation is used after an assignment is
   approved;
4. how prompts, logs, outputs, and artifacts are kept within the declared
   write scope; and
5. how a failed or disconnected run can be resumed safely.

Paid or networked smoke tests belong outside CI and require an explicit local
authorization. They must never be hidden behind a normal unit-test command.

## Pull requests

Keep changes focused and explain the evidence level of new behavior (for
example, offline fixture, local-only probe, or authorized runtime observation).
Include tests for failure paths and path/secret redaction when changing the
controller, planner, scanner, or adapter boundary. Update `CHANGELOG.md` for
user-visible behavior and update the relevant schema or reference document
when a packet or state contract changes.

Reviewers may request a narrower scope when a change would make an implicit
network call, broaden credentials, bypass validation, or blur local execution
and server workload placement.
