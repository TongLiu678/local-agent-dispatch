# Reproducibility and public evidence

This document defines the provider-free checks that a clean public checkout can
run without credentials, networked model execution, SSH, scheduler submission,
or access to a private runtime directory.

`current_provider_free_test_methods: 1235`

The field above is a static inventory of the repository's top-level
`unittest.TestCase` methods. It is checked against the source tree. It is not a
claim that a particular platform passed until the corresponding command exits
successfully on that exact commit.

## Core checks

From the repository root:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover -s tests -p 'test_*.py' -q
python3 -m compileall -q src scripts research tests
for script in scripts/*.sh; do bash -n "$script"; done
PYTHONPATH=src python3 -m local_agent_dispatch.cli --version
PYTHONPATH=src python3 -m local_agent_dispatch.cli doctor --offline
PYTHONPATH=src python3 -m local_agent_dispatch.cli demo --offline
```

The shell syntax loop is a Unix gate. Windows validation uses the portable
Python modules and CLI surfaces rather than claiming that Bash wrappers are
native Windows interfaces.

## Evidence interpretation

- A unit-test or replay pass is provider-free implementation evidence.
- A scan or catalog result is observation evidence; it does not establish live
  execution capability.
- A live lane requires fresh host, resource, route, authentication, ownership,
  and validator evidence for the exact task.
- A release claim belongs to one immutable public commit and its artifacts.
  Evidence from another checkout or an older tag does not transfer.
- Private paths, machine names, endpoints, quota snapshots, prompts, logs, and
  runtime receipts are not public reproducibility inputs.

## Release artifacts

For a release candidate, build and install the wheel in a clean environment,
inspect the wheel and source archive, run the offline CLI smoke, and publish
artifact checksums plus a validated SPDX or CycloneDX SBOM. A release receipt
may record the public commit, tag, test result, scrub-report hash, artifact
hashes, and SBOM hash, but must not contain private filesystem or network
identifiers.

The deterministic export and sanitization gates are described in
[`public-release.md`](public-release.md).
