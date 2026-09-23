# Threat model

The control plane handles task prompts, local paths, provider credentials, and
remote host metadata. The source repository is public; runtime state and
credentials are not.

## Protected assets

- provider credentials, cookies, tokens, and subscription state;
- task prompts and private source files;
- SSH hostnames, identity-file paths, and remote project paths;
- model/runtime inventory and artifact contents;
- queue state, leases, logs, and validation output.

## Main boundaries

1. Discovery is read-only and uses a redacted environment. It must not send a
   paid prompt merely to populate a catalog.
2. Explicit execution is the only path that preserves provider credentials.
   It requires an exact persisted model/variant and adapter contract.
3. Task and artifact paths are canonicalized under the declared workspace;
   traversal and symlink escapes are rejected.
4. Modern packets require a validator, write scope, artifacts, and exact
   attempts. Secret-like keys are rejected before queue persistence.
5. Remote bulk transfers require a verified server route and durable logs;
   the Mac is never a bulk relay.
6. Monitor output is observation only. Replan constraints are copy-on-write and
   do not enqueue or execute a provider by themselves.

The remaining pre-1.0 risks are the external Antigravity adapter dependency,
Cursor's legacy prompt-via-argv contract, remote worktree synchronization,
and automatic controller integration of replan output. These are explicit
release gates, not silently trusted behavior.
