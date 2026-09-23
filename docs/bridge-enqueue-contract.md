# Plan → packet → SQLite enqueue boundary

Planning and queue mutation are separate evidence stages:

```text
lad dispatch (read-only report)
       │ explicit --enqueue/--execute + --adapters + --db only
       ▼
plan_packet_bridge (path/model/validator contract)
       │ provider-free SQLiteController.enqueue
       ▼
SQLite WAL queue (queued job; no provider process started)
```

`lad bridge` and `scripts/plan_packet_bridge.py` default to `dry-run`. They
validate assignments and emit packets without creating a database. The
`enqueue-ready` mode is still only a review state; it is not a write. A caller
must additionally pass `--enqueue` (or `--execute`) and an explicit `--db`.
The nested enqueue response contains only job summaries, database identity,
and provider-free evidence. The surrounding bridge audit may retain the
declared validation-bound argv needed to reproduce a packet, but it never
copies prompt text.

`lad dispatch` can perform the same explicit boundary after producing its
system-first report:

```bash
lad dispatch --workspace WORKSPACE --jobs JOBS.json --preflight PREFLIGHT.json \
  --adapters ADAPTERS.json --db dispatch.sqlite3 --enqueue
```

The command bridges only an `ok` dispatch plan and persists the updated audit
report when `--output` was supplied. It never launches an adapter, sends a
model prompt, opens SSH, downloads data, or starts the SQLite worker. Run the
durable worker as a separate reviewed step (`lad run --backend sqlite ...`).

If bridge validation or SQLite enqueue fails, the response is `ok=false` and
records whether any job was already enqueued. A failed or partial enqueue must
be reviewed before retrying; idempotent identical job IDs are accepted by the
SQLite store, while conflicting payloads fail closed.

## SSH server-local packets

For a `server_local` SSH assignment, the adapter registry/job must declare a
remote workspace (or use the inventory host's `project_path`), remote artifact
paths, and a validator executable available on that host (for example
`python3`, not the local Mac's absolute Python path). The bridge emits the
remote workspace in the packet and sets `output_path` to null so the local
controller cannot accidentally publish stdout into a remote path. A remote
coding adapter is still responsible for creating the declared artifacts; the
controller only observes hashes and runs the remote validator before marking
the job completed.
