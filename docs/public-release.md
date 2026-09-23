# Public release procedure

This repository must be published from a sanitized Git snapshot, not by
mirroring a developer checkout or its private runtime directory.  A passing
`public_scrub.py` report is necessary but not sufficient: it is a narrow,
offline guard for known path, topology, credential, and runtime-evidence
shapes, not a general-purpose secret scanner.

## Claim ceiling

- Linux CI runs the provider-free unit suite on every supported Python minor.
- macOS and Windows CI are bounded compatibility smokes for installation,
  import/plugin contracts, the scrubber, and offline host inspection.  They do
  not claim parity for remote workers, shell wrappers, PBS, service managers,
  or provider CLIs.
- No CI release gate authenticates to a provider, sends a model prompt, probes
  SSH hosts, submits a scheduler job, or measures live quota.
- Example cluster roots such as `/data`, `/srv`, and `/var/tmp` must use public
  placeholders.  A real username, project mount, host, address, receipt, or
  runtime path is release-blocking.

## Prepare a sanitized snapshot

1. Start from a reviewed, clean commit.  Record its full commit ID and do not
   include ignored files, untracked files, local databases, logs, PID files,
   provider state, prompts, inventories, receipts, or artifacts.
2. Create a new candidate from the exact reviewed commit with the deterministic
   exporter.  Keep the policy outside both the private repository and the
   candidate because its bounded literal matches can themselves contain private
   values.  This is enforced against the policy's resolved path, including the
   source worktree and its Git/common metadata directories; a policy may safely
   be a sibling of the new candidate.  After that real-path check, the policy is
   read once through a bounded, identity-checked file handle.  The exporter
   rejects a dirty source by default, reads Git objects without executing
   candidate content, refuses links/submodules and non-portable paths (including
   Win32-forbidden characters and device names), and returns only categories,
   counts, and hashes:

   ```bash
   python3 scripts/public_export.py \
     --repo <private-repository> \
     --ref <reviewed-private-commit> \
     --destination <new-empty-candidate-path> \
     --policy <private-policy.json> \
     > <private-export-manifest.json>
   ```

   Use exact exclusions for historical operational evidence that is not
   required to operate the package and count-bound literal replacements for
   machine- or account-specific examples.  A stale exclusion or replacement
   count blocks the export instead of silently producing a partial redaction.
   Initialize a new Git repository inside the resulting candidate; never copy
   the private `.git` directory.

   Git 2.27 or newer is required.  With Git 2.45 or newer every object read uses
   Git's global `--no-lazy-fetch` guard.  Git 2.27 through 2.44 is accepted only
   for a full repository with no `extensions.partialClone`, promisor remote, or
   partial-clone filter configuration.  The exporter disables every transport,
   replacement objects, optional locks, ambient Git repository/config routing,
   tracing, Windows stream redirection, and external Git helper lookup in both
   modes.  Git 2.27 through 2.29 also rejects option-like refs before using the
   older `rev-parse` interface.  Any Git command that exceeds the bounded
   timeout blocks the export with a redacted failure.
3. Commit the sanitized candidate and run the scrubber against that Git ref,
   not only against the current working tree:

   ```bash
   python3 scripts/public_scrub.py \
     --repo . \
     --ref <sanitized-commit> \
     --allow-path tests/fixtures/redaction \
     --allow-path research/scenarios \
     --output <private-report-path>
   ```

   The report deliberately contains only category, repository path, and line
   number for findings, plus the exact resolved source commit.  It uses the
   same Git 2.27/2.45 offline split and sealed Git environment as the exporter,
   rejects option-like refs, and checks object/worktree sizes before bounded
   reads.  Invalid UTF-8, unsupported entries, oversized files, and read errors
   remain blocking skips.  Keep the report outside the repository.  Review
   every allowlisted finding as well as the zero-blocker result.
4. Allowlisting is restricted to the explicit synthetic roots enforced by the
   scrubber.  Denied runtime paths, ignored files, unreadable files, binary
   files, and oversized files remain blocking.  Never add a broad source or
   documentation directory merely to make the gate green.

The private development history may still contain sensitive evidence even
when the sanitized tip is clean.  Publish a clean snapshot or a deliberately
rewritten public history; do not push private historical refs, reflogs,
temporary tags, or worktree refs.

## Release gates

Before creating a public tag, require all of the following on the exact
candidate commit:

1. Provider-free Linux CI and the bounded macOS/Windows compatibility smokes
   pass.
2. The public scrub report has `gate=pass`, no skipped files, and zero blocking
   findings.
3. A trusted secret scanner reviews the complete public history that will be
   pushed.  No external scanner is installed by this repository; enable GitHub
   secret scanning and push protection where available, and keep scanner logs
   private because they can contain the matched material.
4. Build wheel and source artifacts from the candidate, inspect their file
   lists, install the wheel in a clean environment, and rerun the offline CLI
   smoke.
5. Generate a standards-compliant SPDX or CycloneDX SBOM for the exact release
   artifacts in the release environment.  Verify it, hash it, and publish it
   beside the artifact checksums.  A package inventory or `pip list` dump must
   not be labelled an SBOM.
6. Record source commit, artifact hashes, scrub-report hash, test run, SBOM
   hash, and reviewer approval in a release receipt that contains no private
   endpoints or filesystem paths.

## Tag and verify

Create a new annotated tag only after the gates pass.  Do not move or reuse an
existing public tag, including an earlier alpha tag.  Push only the sanitized
branch and the intended new tag.  After publication, clone the repository from
GitHub into a clean directory and repeat the ref scrub, artifact build, wheel
install, and offline CLI smoke against what users can actually fetch.

If any post-publication check fails, stop distribution, rotate any exposed
credential, remove the affected release artifact, and publish a new corrected
tag.  Deleting a branch or moving a tag does not remove data already present in
Git history or caches.
