# LAD package ecosystem

The package layer gives local-agent-dispatch a Homebrew/pip-like separation of
concerns without making installation an execution boundary:

```text
manifest data -> deterministic catalog resolution -> exact lock
local source directory -> verified atomic store -> explicit active pins
                                             -> rollback / safe uninstall
```

It is stdlib-only and provider-free. Catalog resolution performs no discovery
or network request. Installation never imports a Python entrypoint, launches an
executable or container, contacts an endpoint, or invokes a plugin operation.

## Package manifest

`src/local_agent_dispatch/packages/manifest.py` defines the v1 manifest. A
manifest identifies one exact SemVer coordinate, package kind, entrypoint type,
platforms, dependencies, permissions, and a complete artifact inventory. Every
artifact has a normalized relative path, SHA-256 digest, exact byte size, and
an executable flag. Package names and every artifact component must also be
portable across supported filesystems: Windows device names, forbidden/control
characters, backslashes, trailing dots/spaces, and ambiguous path components
are rejected on every host. Metadata must be strict JSON; `NaN` and infinities
are not accepted or persisted.

Packages can describe Python adapters, native harnesses, containers, endpoint
contracts, or data-only bundles. The entrypoint is inert metadata at install
time. Package installation is not plugin registration, and plugin registration
is not route authorization.

The default local source layout is:

```text
my-adapter/
  lad-package.json
  adapter.py
  resources/schema.json
```

`lad-package.json` is the only source file that need not appear in the artifact
inventory. All other regular files must be declared exactly.

## Deterministic catalog resolution

`PackageCatalog` stores already-parsed manifests in memory. `resolve()` accepts
root `Dependency` values or a `name -> constraint` mapping and returns a
`ResolutionResult` containing one exact version per package.

Resolution rules are fail-closed:

- all required transitive dependencies must exist;
- every selected version must satisfy every accumulated constraint;
- selected manifests must match the requested OS and architecture;
- dependency cycles are rejected, even if their version constraints agree;
- optional dependencies are excluded unless `include_optional=True`;
- duplicate coordinates with different manifest digests are rejected;
- candidates are tried in descending SemVer order with deterministic
  backtracking and a full-version tie-break for equal SemVer precedence.
- an exact `==` constraint includes build metadata even though build metadata
  does not affect ordinary SemVer precedence.

The result is ordered dependencies-first. `ResolutionResult.to_lock_dict()`
contains exact versions and manifest digests; range constraints never survive
as an executable installation choice.

```python
from local_agent_dispatch.packages import Dependency, PackageCatalog

result = PackageCatalog(manifests).resolve(
    [Dependency("pbs-harness", ">=1.2.0,<2.0.0")],
    os_name="linux",
    arch="x86_64",
)
exact_pins = result.pins
lock_payload = result.to_lock_dict()
```

Catalog resolution does not fetch or install the selected packages. A caller
must obtain each source through a separately authorized channel and compare it
with the locked manifest digest.

## Canonical package lockfiles

`resolve_to_lock()` closes the data-only resolution loop without turning it
into an install or execution boundary. It freezes an immutable catalog
snapshot, resolves against that snapshot, and returns a `PackageLock` with:

- lock schema and format versions;
- exact root requirements and the target OS/architecture;
- one name, version, manifest digest, kind, and normalized platform-constraint
  set for every resolved package;
- whether optional dependencies participated in resolution;
- a SHA-256 digest over every manifest identity in the catalog snapshot.

`PackageLock.to_json()` emits canonical UTF-8 JSON with sorted object keys and
no insignificant whitespace. `PackageLock.digest` is the `sha256:` digest of
those exact canonical bytes. Package and root arrays are normalized before
serialization, so catalog insertion order cannot change the lock.

```python
from local_agent_dispatch.packages import resolve_to_lock, verify_lock

lock = resolve_to_lock(
    catalog,
    {"pbs-harness": ">=1.2.0,<2.0.0"},
    os_name="linux",
    arch="x86_64",
)
lock_path.write_text(lock.to_json(), encoding="utf-8")

# Re-resolves the roots and requires the exact same catalog snapshot.
catalog_evidence = verify_lock(lock, catalog)

# Also inventories installed packages and re-hashes every artifact.
store_evidence = verify_lock(lock, catalog, store=store)
```

`load_lock_json()` rejects duplicate JSON keys at every nesting level, unknown
fields, scalar coercion, duplicate roots or packages, unknown kinds, invalid
digests, non-concrete target platforms, and unsupported schema versions. A
catalog verification fails if even an unselected catalog manifest has changed,
because that means the resolver did not observe the recorded snapshot. Store
verification additionally requires the same target platform, the exact locked
manifest metadata, a complete installed-file inventory, and matching artifact
sizes and SHA-256 digests.

Neither lock creation nor verification imports an entrypoint, starts a process,
contacts a provider, or accesses a registry. The catalog and store must already
exist locally.

### Lockfile CLI

The provider-free CLI exposes the same boundary without adding a registry or
installer:

```bash
lad package resolve \
  --catalog ./catalog \
  --requirements ./requirements.json \
  --output ./lad.lock.json

lad package verify-lock \
  --catalog ./catalog \
  --lock ./lad.lock.json \
  --store ./store
```

The catalog is deliberately simple and read-only: every immediate child must
be a real directory containing one regular `lad-package.json`. Symlink entries,
non-directory entries, missing manifests, duplicate coordinates, invalid
manifests, and an empty catalog fail closed. Resolution reads manifest data
only; it does not read or run catalog artifacts.

`requirements.json` is a strict versioned envelope:

```json
{
  "schema_version": 1,
  "platform": {"os": "linux", "arch": "x86_64"},
  "include_optional": false,
  "requirements": [
    {"name": "pbs-harness", "constraint": ">=1.2.0,<2.0.0", "optional": false}
  ]
}
```

All fields are required. Duplicate JSON keys, unknown fields, duplicate root
names, scalar coercion, a non-concrete platform, and an empty requirement set
are rejected. `--output -` emits exactly one canonical lock JSON value on
stdout, suitable for redirection. A file output is published with a
same-directory atomic replace and the command emits a JSON receipt containing
`filesystem_written: true`; failure before the replace preserves an existing
file. `verify-lock` emits `LockVerification` evidence with
`filesystem_written: false`. Adding `--store` hashes the already-installed
artifacts but still does not download, install, activate, import, or execute
anything. The machine-readable lock contract is
`schemas/package_lock.schema.json`.

## Verified local installation

`PackageStore.install()` accepts only an existing local directory. URL-shaped
sources are rejected. Before publishing a version, the store:

1. parses the inert manifest without loading its entrypoint;
2. inventories the complete source tree;
3. rejects undeclared or missing files, symlinks, special files, and paths that
   resolve outside the source root;
4. streams every declared artifact into a staging directory while checking its
   exact size and SHA-256 digest;
5. writes a canonical installed manifest;
6. atomically renames the staged payload into the versioned package store.

Staging resides under the store root so publication uses a same-filesystem
rename. Failed verification leaves no published package and removes its private
staging directory. On POSIX, installed regular files receive deterministic
`0644` or `0755` modes according to the artifact record; on Windows the
executable flag remains verified manifest metadata and callers must invoke the
declared entrypoint explicitly. Source ownership and setuid bits are not copied.
Artifact components are also checked against Windows drive and
reserved-device syntax, Unicode-normalized case collisions, and manifest-name
collisions on every OS, so a package accepted on one platform cannot become a
path escape or overwrite on another.

```python
from local_agent_dispatch.packages import PackageStore

store = PackageStore("/var/lib/lad/packages")
receipt = store.install("/approved/local-source/my-adapter")
print(receipt.name, receipt.version, receipt.manifest_digest)
```

The default install activates a dependency-valid package. Passing
`activate=False` only stores the verified version. A resolved group can be
installed inactive and switched atomically with:

```python
store.activate_pins(result.pins, replace=True)
```

Activation verifies that every exact pin is installed, platform-compatible,
digest-consistent, acyclic, and satisfies the required dependencies of every
other active package.

## Store and lock layout

```text
STORE/
  packages/NAME/VERSION/
    manifest.json
    ... verified artifacts ...
  .staging/
  state/
    active-v1.json
    locks/
      00000000000000000001.json
      00000000000000000002.json
```

Every active mutation creates a monotonically increasing, immutable lock
generation containing exact versions and manifest digests, then atomically
replaces `active-v1.json`. If a crash occurs between those writes, the prior
active file remains authoritative. Rollback follows the committed
`previous_generation` lineage, so a lock written before a failed active-file
swap is treated as an orphan and is never silently activated.

`rollback()` validates the installed artifacts and recorded manifest digests
from an earlier generation, then records the restored pins as a new generation.
It never rewinds or overwrites history.

`uninstall()` refuses to remove:

- the currently active version;
- any version referenced by a retained rollback generation;
- a corrupt package or an unsafe/symlinked store path.

This intentionally favors recoverability over automatic garbage collection.
Versions that were installed with `activate=False` and never pinned can be
removed safely.

## Trust and current limitations

This layer provides integrity and deterministic local state, not publisher
trust or runtime sandboxing.

- There is no remote catalog, download client, Homebrew tap, PyPI index, wheel,
  signature, transparency log, or publisher-key verification yet.
- Constraint syntax is the manifest v1 subset (`*`, `==`, `<`, `<=`, `>`,
  `>=`, and comma-separated conjunctions); caret, tilde, and disjunctions are
  not supported.
- Resolution creates a canonical exact lock but does not perform a
  multi-package download/install transaction. Sources must be supplied locally.
- "Local source" currently means an existing filesystem directory rather than
  a URL. This layer does not attest whether that directory is backed by a local
  disk, a network mount, or removable media.
- The mutation lock is a fail-closed directory lock. A process killed during a
  mutation may leave a stale lock that requires operator review and removal.
- Atomic rename and `O_NOFOLLOW` are used where the OS provides them, but the
  store still assumes its root and source directory are not writable by a
  hostile concurrent user.
- Retained rollback locks currently have no pruning/garbage-collection API, so
  referenced versions remain intentionally uninstallable.
- Installing a package does not enable permissions, register a plugin, or run
  an entrypoint. Those require separate policy and execution boundaries.
