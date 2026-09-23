# Skill composition and evolution v1

This subsystem chooses a small, reviewable portfolio of skills instead of
treating retrieval rank as an execution plan. It is provider-free and pure:
it consumes already-built metadata and latent vectors, returns data, and never
loads a skill body, imports an entrypoint, starts a process, contacts a model,
or writes a proposal to the repository.

## Trust boundaries

The index contains only bounded metadata: identity, semantic version, a
single-line description, capabilities, methodological facets, explicit
platform/harness selectors, estimated cost, uncertainty, availability, and a
precomputed embedding. There is deliberately no field for a skill body,
prompt, source path, executable, or entrypoint. Unknown fields are rejected.
An active snapshot contains exactly one version for each skill id; historical
versions live in lineage/package records rather than competing in one plan.
Search hits omit embeddings; composition plans omit both embeddings and
descriptions. Consequently the body cannot flow from this API into search or
plan output.

The whole index carries `generated_at`, `ttl_seconds`, `evidence_state`, and a
source digest. A missing TTL, unknown evidence state, future-dated snapshot, or
expired snapshot blocks both search and composition. `availability=unknown`
also fails the per-skill eligibility gate. Unknown is never treated as zero
risk. Every returned composition plan repeats the exact index id, generation
time, and source digest so later outcome processing can bind evidence to the
same snapshot rather than merely trust a caller-supplied plan id.

## Selection pipeline

Only portfolio sizes 3, 5, and 10 are valid. A request declares required
capabilities, desired facets, platform, harness, optional allow/prohibit lists,
a total cost ceiling, a per-skill uncertainty ceiling, and a query embedding.

Selection is deterministic and proceeds in this order:

1. Verify index freshness and embedding dimensions.
2. Apply availability, allow/prohibit, platform, harness, uncertainty, and
   individual cost constraints. Rejected candidates never enter scoring.
3. Verify that the eligible union can cover every required capability.
4. Build exactly `k` entries using marginal required-capability coverage,
   desired-facet coverage, latent relevance, facet complementarity, latent
   redundancy, estimated cost, and uncertainty.
5. Recheck exact count, total budget, and full required coverage before
   returning a plan.

Cosine similarity scales both finite vectors before multiplying, avoiding
overflow for large-but-valid embeddings. Hard cost comparisons use decimal
values derived from the JSON numbers, so a valid `0.1 + 0.1 + 0.1 <= 0.3`
portfolio is not rejected by binary floating-point drift.

The marginal score is:

```text
100 * new required coverage
 + 30 * new desired-facet coverage
 + 12 * facet complementarity
 +  8 * latent relevance
 - 18 * latent redundancy
 -  5 * normalized cost
 - 10 * uncertainty
```

The large coverage terms are intentional. A cluster of nearly identical
high-similarity skills should not crowd out a lower-similarity skill that adds
a missing capability or methodological angle. Stable skill id and version
break all numerical ties, and plan ids are content-derived.

This is a transparent v1 heuristic, not a learned optimizer. Weights should be
changed only with holdout evaluations that measure task quality, diversity,
cost, and failure rate. Exact completion is deliberately bounded: one request
may contain at most 16 required capabilities and 128 eligible candidates, and
the dynamic program has fixed state and transition ceilings. Larger libraries
must use retrieval or `allowed_skill_ids` to produce a shortlist first. A
request that exceeds a bound fails closed rather than consuming unbounded CPU
or silently changing the optimization method.

## CLI boundaries

The search, compose, and analyze commands consume only caller-supplied strict
JSON. They perform no discovery, provider call, network access, skill-body
read, import, entrypoint execution, activation, or filesystem write:

```bash
lad skill search \
  --index skill-index.json \
  --request composition-request.json \
  --now 2026-09-22T12:01:00+00:00

lad skill compose \
  --index skill-index.json \
  --request composition-request.json \
  --now 2026-09-22T12:01:00+00:00

lad skill analyze \
  --index skill-index.json \
  --now 2026-09-22T12:01:00+00:00 \
  --threshold 0.9 \
  --limit 100
```

For search and compose, `--now` is optional and defaults to the current UTC
time; analyze requires it so every diagnostic is exactly replayable. Either
`--index` or `--request` may be `-` for stdin, but not both in one invocation
because stdin contains only one JSON value. Inputs are bounded to 8 MiB each,
duplicate keys at any depth and unknown fields fail closed, and success or
failure is emitted as one canonical JSON value on stdout. Exit status `2` is a
structured validation or freshness failure. Search and plan output omit
body/instruction fields and vector values.

`skill analyze` applies the same strict index and freshness gates. It computes
cosine mean/minimum/maximum across every available-skill pair, returns a
bounded top-pair view, marks pairs at or above the threshold, derives
connected redundancy groups, and reports per-capability and per-facet skill
counts/fractions. `--limit` bounds returned pair rows rather than changing the
aggregate statistics. Unknown or disabled skills are excluded and counted;
an index with no available skill fails closed. Vectors are used transiently
and never appear in the result. V1 also rejects indexes whose pair count or
dimension-weighted work exceeds its fixed local computation budget.

There is deliberately no `lad skill propose` command in v1. The current
evolution function requires a fresh `SkillIndexSnapshot`, the referenced
`CompositionPlan` objects, outcomes, policy, and time. A command that accepted
only `--outcomes`, `--policy`, and `--now` would drop those safety inputs. A
later CLI should expose one closed, versioned proposal envelope that binds all
five inputs rather than infer an index or weaken the freshness gate.

## Outcome and evolution loop

An outcome references the exact plan and skill versions and records only
structured status, bounded metrics, failure codes, and non-empty evidence
references. Before counting an observation, the proposal engine requires the
plan to exist, match the fresh index id/generation/source digest, contain every
reported skill version, predate the observation, and use evidence receipts not
reused by another outcome in the batch. It then groups fresh outcomes by exact
skill identity. When the minimum evidence count is reached and failure rate or
quality crosses policy thresholds, it emits a deterministic `proposed`
metadata revision. It does not edit a `SKILL.md`, create a package, install
anything, or activate the result.

A separately reviewed application step may turn an accepted proposal into a
strictly newer version and record `SkillLineage`. Lineage is also data-only:
child, unique parents, operation, proposal id, time, and evidence references.
Runtime and schema enforce zero parents for create, one for revise/split, and
at least two for merge; a child cannot also be its own parent. The v1 helper
applies `revise_metadata` only. Merge/split proposals fail closed until an
explicit multi-parent review API exists. The v1 API therefore separates four
states that must not be conflated:

```text
observed outcome -> proposed metadata change -> reviewed application -> lineage record
```

The package ecosystem supports a data-only `ExtensionManifest` with
`kind="skill"`. A skill package is a distribution and integrity boundary: it
requires `entrypoint_type="none"` and a root `SKILL.md`, and package inspection
or installation never imports or executes it. The composition index remains a
separate freshness/evidence boundary, and skill enablement plus any later
execution authorization remain separate again. A package-store version may be
pinned as the active installed version, but that pin is not composition-index
eligibility or skill enablement. Installing a skill package therefore does not
enable it or authorize an agent to use it.

## Create lifecycle

`skills/scaffold.py` provides the narrow reviewed-application step that v1 was
missing. `ScaffoldSpec` is a closed, provider-free contract containing an exact
SemVer package coordinate, a discriminating one-line description, and bounded
instructions. `load_scaffold_json` rejects duplicate or unknown fields and
does not coerce JSON scalars. The structural description checks are not a
substitute for human review of whether the routing language is genuinely
specific.

`create_skill_package(spec, destination)` treats instructions only as UTF-8
Markdown data. It produces exactly `SKILL.md` and canonical
`lad-package.json`; the latter is a `kind="skill"`, `entrypoint_type="none"`
manifest whose sole artifact binds the root `SKILL.md` by exact byte size and
SHA-256. The function stages both files beside the destination, fsyncs them,
and atomically publishes only to a destination that does not already exist.
Its receipt contains identity, paths, sizes, and digests but never the
instruction body.

The same boundary is available explicitly as:

```bash
lad skill create --spec scaffold.json --destination ./new-skill
```

The command's canonical receipt states that the filesystem was written while
installation, activation, indexing, enablement, import, and execution all
remain false.

Creation is not installation, activation, indexing, selection, or execution.
The scaffold performs no provider call, network request, import, subprocess,
or model invocation. A reviewer may separately verify or install the source
with `PackageStore`; even then, enablement and execution authorization remain
independent gates.

## Schemas and code

- `schemas/skill_index.schema.json`
- `schemas/skill_composition_request.schema.json`
- `schemas/skill_composition_plan.schema.json`
- `schemas/skill_latent_analysis.schema.json`
- `schemas/skill_outcome.schema.json`
- `schemas/skill_evolution_proposal.schema.json`
- `schemas/skill_lineage.schema.json`
- `schemas/skill_scaffold_spec.schema.json`
- `src/local_agent_dispatch/skills/models.py`
- `src/local_agent_dispatch/skills/composition.py`
- `src/local_agent_dispatch/skills/evolution.py`
- `src/local_agent_dispatch/skills/latent.py`
- `src/local_agent_dispatch/skills/scaffold.py`
- `src/local_agent_dispatch/cli.py` (`lad skill search|compose|analyze|create`)

Every schema object, including nested records, sets
`additionalProperties: false`. Runtime parsing enforces the same closed-world
rule and rejects booleans masquerading as integers, non-finite numbers, naive
timestamps, duplicate identifiers, dimension mismatches, and unbounded body
text.
