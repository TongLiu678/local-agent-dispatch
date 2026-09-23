# Evidence model

The dispatcher must not collapse different observations into a single
`ready=true` flag.

| Evidence | Meaning | Does not prove |
| --- | --- | --- |
| `catalog_state=visible` | An exact model ID was listed by a local CLI | The request endpoint accepts it or quota remains |
| `auth_state=configured` | A local credential/configuration exists | The credential is valid for this model or task |
| `runtime_state=accepted` | An authorized request or smoke contract succeeded | A future request cannot be rate-limited |
| `quota_state=known` | A provider supplied attributable remaining/reset data | Other processes are not consuming the shared pool |
| `quota_state=unknown` | No numeric remaining balance is available | Zero, full quota, or quota-free execution |
| `host_state=reachable` | A lightweight probe reached the host | The workload fits, is writable, or has a compatible GPU |
| `probe_failure_code=compute_probe_timeout` | The bounded probe did not return before its deadline | The host is permanently unavailable or safe to retry immediately |
| `probe_failure_code=compute_probe_connection_refused` | The target actively rejected the connection before a host result | The host is down, authenticated, or safe for a new lane |
| `probe_failure_code=compute_probe_dns_failure` | Name resolution failed before a host result | The configured name is permanently invalid or the route is safe |
| `probe_failure_code=compute_probe_auth_failed` | The transport reached an authentication boundary but could not authenticate | Credentials should be copied or the host is executable |
| `probe_failure_code=compute_probe_auth_context_unavailable` | The local keychain or SSH signing agent could not authorize the probe in this execution context | Network reachability failed or credentials should be copied |
| `artifact_fresh=true` | Required files changed and have hashes | The contents are correct without validation |
| `validation.ok=true` | The declared validator passed | The task should be merged or published automatically |

Every dispatch decision should preserve the evidence source and timestamp.
Runtime failures are scoped narrowly: capability rejection affects the exact
model/variant; quota, authentication, and network failures affect the shared
pool.
