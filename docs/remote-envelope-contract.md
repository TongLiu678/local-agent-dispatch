# Cross-host envelope contract

`remote_worker.py` provides a durable worker spool, and the provider-free
`scripts/remote_envelope.py` module is the transport record that survives a
dropped SSH session. The worker and SSH client now expose receive, complete,
and pending operations using this canonical envelope. SQLite migration 6 and
`SQLiteController.enqueue_remote()` bind an approved SSH packet and its
metadata envelope in one local transaction. The controller-side
`scripts/remote_outbox.py` adds a bounded `sync_once()` seam: dry-run is the
default, `--execute` is explicit, accepted receipts are fenced into SQLite,
and transport failures leave the request pending for retry. The explicit
`reconcile_once()` path reads worker terminal receipts and writes them back
under the controller lease/fence; it never promotes a pending or accepted
row without outcome evidence. `scripts/reverse_envelope_service.py` exposes
the same fixed operations over a loopback-only JSON socket, while
`scripts/reverse_tunnel_supervisor.py` owns a fixed loopback `ssh -N -T -R`
child and writes a redacted lifecycle status. A long-running cross-host fault
matrix, supervisor installation, and forward-ready handshake remain follow-up
work.

## What is persisted

An envelope contains:

- a stable `request_id`/`idempotency_key`;
- source and target identities and an operation name;
- the prepared packet SHA-256, not the packet or prompt;
- an allow-listed task summary (exact model/variant, placement, write scope,
  artifact count, and validation/resource digests).

The payload summary rejects prompt, argv, environment, token, credential, and
arbitrary fields. It is therefore safe to put in a controller outbox or a
server inbox, subject to the normal private runtime-directory policy.

## Delivery and recovery

`EnvelopeStore` uses one filesystem lock and atomic, fsync-backed JSON writes:

1. `enqueue()` writes `outbox/<request_id>.json`.
2. `receive()` writes `inbox/<request_id>.json` and an `accepted` receipt.
3. A reviewed worker may call `complete()` with a result digest and a
   `completed` or `failed` terminal receipt.
4. `pending()` lists both local outbox requests and received-but-uncompleted
   inbox requests after a network or process interruption.

Repeating the same request and payload returns the existing receipt and does
not increase `effect_count`. Reusing a request ID with a different payload
digest fails closed. This is an idempotency/receipt boundary, not a claim that
an arbitrary external side effect is exactly-once; adapters must still fence
their own leases and publish artifacts only after validation.

```python
from remote_envelope import EnvelopeStore, build_envelope

store = EnvelopeStore("/srv/lad/envelopes")
envelope = build_envelope(
    request_id="job-1-attempt-1",
    source_id="controller",
    target_id="server-a",
    operation="execute.prepared",
    packet_digest="<sha256-of-approved-packet>",
    payload_summary={
        "job_id": "job-1",
        "model": "opencode-go/deepseek-v4-flash",
        "variant": "max",
        "execution_host": "controller",
        "workload_host": "server-a",
        "write_scope": ".lad/jobs/job-1",
        "required_artifact_count": 1,
        "validation_required": True,
    },
)
store.enqueue(envelope)       # controller side
store.receive(envelope)       # worker side, after transport delivery
store.complete("job-1-attempt-1", result_digest="<sha256-of-receipt>")
```

The module never opens SSH, runs a shell, invokes OpenCode, downloads a model,
or infers a new task after quota loss. The worker/client and bounded outbox
integration and terminal receipt reconciliation are covered by provider-free
tests; a long-lived reconnect service, lease fencing across independent hosts,
and the full fault matrix are still required before claiming durable
distributed execution.
