# Local resource admission

The recurring local “cannot create thread lock”/pause symptom is not a model
quota failure.  The control plane can have usable Codex quota while the local
workspace, cache, SQLite/WAL, log, or temporary filesystem is nearly full.
Python/Node startup and lock creation then fail before the task body runs.

The dispatch path therefore has two gates:

1. `local_system_scan.py` reports the coarse bulk-work and new-lane gate using
   memory pressure plus workspace/cache disk evidence.
2. `resource_admission.py` performs a final read-only `statvfs` check immediately
   before a local `Popen`.  It checks the workspace, the actual temporary
   filesystem, and controller PID/log paths.  Unknown or sub-floor evidence is
   blocked before creating a child, lock, WAL, or temporary file.

For SQLite packets that explicitly declare `resource_request.new_disk_gib`, the
controller performs the same read-only probe before reservation and passes the
minimum observed writable headroom (minus a small controller guard) into the
fenced host-capacity transaction.  Multiple disk-bearing lanes therefore
share one aggregate disk capacity check.  Packets without a disk estimate stay
on the legacy migration path; they are still subject to the final pre-launch
gate and should not be used for bulk work.

Resource admission is a placement result, not a provider/model result.  The
controller records `error_class=resource`, the monitor marks the local host
unavailable, and no other local model is retried.  A task may continue only if
its already-approved packet contains an explicit SSH attempt with its own
workspace, validator, write scope, and artifact contract.  The gate never
kills or deletes processes and never cleans user data automatically.

This distinction is important for server-first operation: the Mac retains the
small control plane and receipts, while heavy work is routed to a verified
remote host whose own capacity and writable mount are checked independently.

## SQLite locality gate

The SQLite Controller is a local control-plane database, not a data-volume
artifact.  Before opening it, `SQLiteController` runs
`resource_admission.check_sqlite_storage`. On Linux it resolves the most
specific entry in `/proc/self/mountinfo` and accepts only a known local
filesystem type. On macOS it reads `/sbin/mount` and requires the selected
mount's explicit `local` flag. On Windows it uses the volume and drive-type
APIs and requires an explicitly local drive. All platforms block known shared
filesystems (`nfs`, `nfs4`, `cifs`, `smbfs`, `sshfs`, `lustre`, `ceph`, and
similar), RAM/tmp filesystems, and unknown locality. This prevents a tempting
but unsafe placement such as `/data/project/.lad/dispatch.sqlite3` when
`/data` is an NFS/shared mount.

The workload, datasets, model caches, and PBS artifacts may remain on a
verified server data mount; only the Controller WAL database and its short
transaction files need a known-local filesystem. Provider-free tests inject
Linux mount, macOS mount, and Windows volume evidence without fabricating a
network/local classification.

The locality decision proves a usable local SQLite locking boundary; it is not
automatically a cross-reboot retention guarantee. The receipt therefore keeps
`allowed` and `persistent` separate. A conventional temporary path or
container overlay may be admitted for bounded tests while reporting
`persistent=false`. Put a continuity queue on a known-local, non-temporary
path and require `persistent=true` when it must survive a reboot or environment
replacement.

Use `lad storage-pressure` to inspect recurring growth. The ledger is bounded
and read-only; `--previous REPORT.json` adds only a directional comparison and
marks root byte counts as lower bounds when traversal was capped.  It records
the need for a user-approved archive/cleanup but does not perform one
automatically.
