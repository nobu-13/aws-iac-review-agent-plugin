# Using this plugin as a Kiro Power

Kiro loads Agent Plugins packages as Powers. This document records what a Kiro
Power load depends on in this package, which files in the repository are
Kiro-specific and why they sit apart from the portable package, and exactly how
far the "loadable as a Kiro Power" claim has been verified.

`docs/architecture.md` owns the decision behind the shape described here: why
`plugin.json` carries no `extensions` field, and how every component is
classified as portable or client-specific. That reasoning is not restated below.
This document carries the verification, and it is the file the README's
"Using as a Kiro Power" section links to.

> **Status.** The structural preconditions a Power load depends on are verified
> mechanically and re-checked by the test suite on every run; the table in
> [What was verified](#what-was-verified) lists each one. The end-to-end Kiro
> Power load is now **verified on Kiro 1.0.337**: all five Skills reached the
> host agent, an `iac-review` entry point ran and produced a Review_Report, and
> nothing had to be added to the package. A first load had dropped three Skills
> for an out-of-spec `description`; that defect is fixed, guarded by a regression
> test, and both runs are recorded in
> [Verification procedure and result record](#verification-procedure-and-result-record).
> Requirement 10 AC7 is satisfied for that version. README Known Limitations
> (Task 27.1) notes the verification is version-specific, since a load observed
> on one Kiro version is evidence about that version only.

## The package is portable, and Kiro adds nothing to it

The package root is the repository root: `plugin.json` sits beside `skills/`,
`iacreview/` and `rules/`. There is no build step, nothing is generated, and
nothing is rearranged for a particular client. The directory a client is handed
is the repository directory.

| What a client needs to load this package | Where it is |
| --- | --- |
| A manifest at the package root | `plugin.json` |
| Skills as immediate children of `skills/` | `skills/<name>/SKILL.md`, five of them |
| The code each Skill runs | `skills/<name>/scripts/*.py`, importing `iacreview/` from the package root |
| The policy rules cfn-guard evaluates | `rules/**/*.guard` |

Nothing in that list is Kiro-specific, and nothing in it names a client. The
Skills' entry points are plain `python3` programs that take arguments and write
JSON to stdout, so the machinery that invokes them is the host agent's business
rather than the package's. The external tools -- cfn-lint, cfn-guard, and the
CDK CLI for `--confirm-cdk-synth` -- are resolved on `PATH` and are not bundled,
which is a property of the package independent of which client loaded it.

## What was verified

Every check below was run against this repository. Each is also pinned by a test,
so a change that breaks a precondition fails the suite rather than surfacing as a
load failure in a client.

| Precondition | Result | Re-checked by |
| --- | --- | --- |
| `plugin.json` exists at the package root and parses as a JSON object | Yes | `tests/unit/test_manifest.py` |
| Every key of `plugin.json` is one the Agent Plugins 1.0.0 manifest schema defines; the schema is closed (`additionalProperties: false`) | Yes, 9 keys, all defined | `tests/unit/test_manifest.py` |
| The two fields the schema requires, `$schema` and `name`, are present, and `$schema` equals the 1.0.0 manifest schema identifier | Yes | `tests/unit/test_manifest.py` |
| `name` satisfies the schema's pattern and length bound | Yes, 27 characters | `tests/unit/test_manifest.py` |
| `author` is an object whose keys are drawn from `name` / `email` / `url` (also a closed schema) | Yes | `tests/unit/test_manifest.py` |
| `keywords` is an array of strings, `version` is semver | Yes | `tests/unit/test_manifest.py` |
| `extensions` is absent, and no reverse-domain extension directory exists at the package root | Yes | `tests/unit/test_manifest.py` |
| `skills/` has exactly five child directories, each holding a `SKILL.md` | Yes | `tests/unit/test_skills.py` |
| Each `SKILL.md` declares a front matter `name` equal to its directory name | Yes | `tests/unit/test_skills.py` |
| Each `SKILL.md` front matter `description` is within the Agent Skills 1.0.0 1024-character cap, so no skill is dropped for an out-of-spec description | Yes, after the fix recorded below (was not, on the first load) | `tests/unit/test_skills.py` |
| No child of `skills/` is skipped by discovery: all five parse and carry a top-level heading | Yes | `tests/unit/test_skills.py` |
| Each of the six Skill entry points runs under plain `python3` and answers `--help` with exit 0 | Yes | `tests/integration/test_skill_*.py` run them for real; `tests/unit/test_bootstrap.py` pins the path bootstrap they depend on |
| No file under `skills/`, `iacreview/`, `rules/` or `benchmark/` reads anything from `.kiro/` | Yes, no reference exists | -- (owed to Task 26.7) |
| No `mcp.json` at the package root, and no tool binary bundled anywhere in it | Yes | `tests/unit/test_manifest.py` |
| The package contains no symbolic link | Yes | -- . Containment of a path that resolves outside the root is `tests/unit/test_pathguard.py`'s concern |

Two of those deserve a sentence more.

**The manifest was validated against the published schema**, not only against the
project's own reading of it. The document at the `$schema` identifier
[`plugin.schema.json` for Agent Plugins 1.0.0](https://agent-plugins.org/schemas/1.0.0/plugin.schema.json)
declares the top level closed, requires `$schema` and `name`, and constrains
`author` to a closed object. Each constraint was checked against `plugin.json`
field by field and all of them hold.

One difference between that schema and this project's own assertion is worth
recording, because it is the kind of thing that becomes a surprise later. The
published schema bounds `name` at 64 characters and its pattern admits neither
`_` nor a `--` or `..` sequence; Requirement 1 AC5 states a 128 character bound
and a pattern that admits `_`. The declared name, `aws-iac-review-agent-plugin`,
is 27 characters and satisfies both, so nothing in v0.1 depends on which bound is
the real one.

**Five Skills, one level deep, is the shape a non-recursive scan finds.** Agent
Plugins discovers Skills as the immediate children of `skills/`, so a Skill
nested any deeper would be invisible. `skills/` also holds a `.gitkeep`, which is
a file rather than a directory and therefore not a discovery candidate.
Requirement 10 AC8 is satisfied structurally by this shape rather than by
anything a client does.

## The load itself, and what remains version-specific

The load was verified on Kiro 1.0.337:
[Second recorded run](#second-recorded-run-after-the-fix----verified) records it.
All five Skills reached the host agent, an entry point ran and produced a
Review_Report, and nothing had to be added to the package. The three checks a
verification should make -- listed below -- all held on that version.

1. All five Skills -- `cfn-lint-review`, `cfn-guard-review`, `iam-review`,
   `cloudformation-review`, `iac-review` -- reach the host agent, not a subset.
2. Each Skill's `scripts/` entry point runs, which means the `parents[3]` path
   bootstrap resolved the package root correctly from wherever the Power was
   installed (see `docs/architecture.md`, "The shared package `iacreview/`").
3. Nothing had to be added to the package to make either of those happen.

What remains is version scope, not an unverified claim: a load observed on one
Kiro version is evidence about that version, not about Kiro in general. A
materially different Kiro version should be re-checked with the same procedure,
and the [Result record](#result-record) table is where such a run is captured.

This document still states no installation steps of its own. Kiro's own
documentation is the authoritative and current procedure for installing a Power,
including from a local directory: see
[Install powers](https://kiro.dev/docs/powers/installation/). A procedure copied
into a second place is a procedure that goes stale, so the verification links to
it rather than restating it.

## Verification procedure and result record

This section is the repeatable procedure behind Requirement 10 AC7 and the place
its outcomes are recorded. The load has been verified on Kiro 1.0.337
([Second recorded run](#second-recorded-run-after-the-fix----verified)); the
procedure remains here so a different Kiro version, or anyone reproducing the
result, has the exact steps and a table to fill in.

### Procedure

Kiro's own documentation is the authoritative and current source for the
client-specific steps, so they are linked rather than restated (a copied
procedure goes stale). Perform them in this order:

1. **Obtain the package directory.** Use this repository's root as-is: it is the
   package root, with `plugin.json` beside `skills/`, `iacreview/` and `rules/`.
   No build step and no rearrangement is needed.
2. **Install it as a Power from that local directory**, following
   [Install powers](https://kiro.dev/docs/powers/installation/). Do not copy any
   `mcp.json` into the root for this run; the load under test is the shipped
   package.
3. **Observe the Skills the host agent enumerates.** Confirm that all five --
   `cfn-lint-review`, `cfn-guard-review`, `iam-review`, `cloudformation-review`,
   `iac-review` -- are present, not a subset.
4. **Run one Skill's entry point through the agent** (for example an
   `iac-review` over `examples/minimal-s3/template.yaml`) and confirm it produces
   a Review_Report, which shows the `parents[3]` path bootstrap resolved the
   package root from wherever the Power was installed.
5. **Note whether anything had to be added to the package** to make steps 3 and 4
   succeed. If nothing did, the portable core loaded unchanged; if something did,
   it belongs under a `dev.kiro` `extensions` namespace (see below) and the
   addition is what this record should capture.

The record is complete only when the exact Kiro version is noted, because a load
that worked on one version is evidence about that version, not about Kiro in
general.

### Result record

Copy this table into a verification run's notes, or into a fork of this file, and
fill it in. An unfilled row means the verification has not been performed; a
filled one is evidence for the Kiro version it names and no other.

| Item | Result |
| --- | --- |
| Kiro version | |
| Date performed | |
| Skills observed | (list which of the five reached the host agent) |
| A Skill entry point ran and produced a report | (yes / no; which Skill) |
| Anything added to the package | (nothing / describe the `dev.kiro` extension needed) |
| Outcome | (verified / not verified, and why) |

Until a row of this table is filled in from a real run, this document states no
result for a run other than the one recorded below.

### First recorded run

A Kiro Power load was performed against this package. Kiro loaded the package as
a Power and reported per-component results, so this row is filled from an
observation rather than from the structural argument.

| Item | Result |
| --- | --- |
| Kiro version | Not recorded on this run (a follow-up run must note it; see the caveat below) |
| Skills observed | Two of five loaded: `cfn-lint-review` and `cfn-guard-review`. Three were dropped: `cloudformation-review`, `iac-review` and `iam-review` |
| Reason the three were dropped | Kiro reported each skipped skill as *"SKILL.md frontmatter has an invalid `description` field"* |
| Root cause | The Agent Skills 1.0.0 specification caps `description` at 1024 characters. The three dropped descriptions were 1217, 1345 and 1282 characters; the two that loaded were 720 and 1023. Kiro enforces the cap by dropping the whole skill, not by truncating |
| Fix applied | The three over-long descriptions were shortened to stay under the cap while keeping the capability and the selection / rejection guidance. A regression test (`tests/unit/test_skills.py::test_description_is_within_the_specification_length_cap`) now measures the folded length of every `description` and fails over the cap, so this cannot recur silently |
| Outcome | Not yet verified end to end. The over-length defect that this run exposed is fixed and guarded by a test, but that all five skills now load in Kiro has not been re-observed. A follow-up run must repeat the procedure, record the exact Kiro version, and confirm five of five |

This is why the [What was verified](#what-was-verified) table's skill-count row is
structural: the count of directories under `skills/` was always five, yet only
two skills reached the host agent, because a valid directory with an out-of-spec
`description` is dropped downstream of that check. The structural precondition and
the load result are different claims, and this run is the evidence that they can
disagree.

### Second recorded run (after the fix) -- verified

The Power load was repeated on a Kiro installation carrying the description fix,
and this time all five Skills reached the host agent and a Skill entry point ran
end to end. This run resolves the load verification (Requirement 10 AC7).

| Item | Result |
| --- | --- |
| Kiro version | 1.0.337 |
| Skills observed | Five of five: `cfn-lint-review`, `cfn-guard-review`, `iam-review`, `cloudformation-review`, `iac-review`. Kiro reported no excluded component |
| A Skill entry point ran and produced a report | Yes. The `iac-review` orchestrator was run through the agent over `benchmark/cases/case-001-iam-wildcard/template.yaml` and produced a Review_Report (two CRITICAL findings, exit 0), which shows the `parents[3]` path bootstrap resolved the package root from where the Power was installed |
| Anything added to the package | Nothing. The portable core loaded unchanged; no `dev.kiro` extension and no `mcp.json` were introduced |
| Outcome | Verified on Kiro 1.0.337. All five Skills load, an entry point runs, and nothing had to be added. This is evidence about Kiro 1.0.337; a materially different version should be re-checked with the same procedure |

Between the two runs, the only change was shortening the three over-long
`description` fields under the 1024-character cap; nothing else about the package
layout, the manifest or the entry points moved. The description-length regression
test in `tests/unit/test_skills.py` is what keeps a future edit from reopening the
gap that the first run exposed.

## The Kiro-specific files in this repository

| Path | What it is | Needed to load the plugin |
| --- | --- | --- |
| `.kiro/steering/` | The project's own development rules, read by Kiro while working on this repository | No |
| `.kiro/specs/` | Requirements, design and task documents for this feature | No |
| `docs/kiro-power.md` | This file. A portable file whose content is Kiro-specific | No. It is documentation, not part of loading |

The first two are development files: they configure Kiro as an environment for
*building* this plugin, not as a runtime for *running* it. The separation is not
only a convention -- no file under `skills/`, `iacreview/`, `rules/` or
`benchmark/` reads anything from `.kiro/`, so deleting the directory would not
change a single review result. That is what makes Requirement 10 AC9 concrete:
another Agent Plugins 1.0.0 client receives the same package, minus files it has
no reason to open.

## If a Kiro-specific hook is ever needed

The way in is a `dev.kiro` namespace under `extensions` in `plugin.json`, with a
matching top-level directory if the client requires one, leaving the portable
core loadable without either. `tests/unit/test_manifest.py` holds the door open
deliberately: one case asserts that adding an `extensions` object with a
`dev.kiro` namespace introduces exactly one top-level key and leaves the manifest
inside the closed schema, so the future change is known to be schema-legal before
anyone needs it.

This is a future path, not a current capability. v0.1 has no vendor-specific
setting to separate, which is why the field is absent rather than empty; the
reasoning is in `docs/architecture.md`, "`extensions` is unused in v0.1".

## Open design decision O-7

O-7 asked for the exact directory layout a Kiro Power load requires and whether a
Kiro-specific manifest is needed. It is resolved as follows.

| | Resolution |
| --- | --- |
| Directory layout | Unchanged from the portable Agent Plugins 1.0.0 layout. `plugin.json` at the package root, five Skills as immediate children of `skills/`. No layout change was needed for Kiro |
| Kiro-specific manifest | None. No file was added, and `extensions` stays absent |
| Requirement 10 AC8 | Satisfied. The preconditions a non-recursive discovery scan depends on are verified and pinned by tests, and confirmed by observation: Kiro 1.0.337 enumerated all five Skills |
| Requirement 10 AC9 | Satisfied and mechanically checked: no Kiro-specific file participates in loading, and no runtime file reads from `.kiro/` |
| Requirement 10 AC7 | Satisfied on Kiro 1.0.337. The load was performed on a real installation, all five Skills reached the host agent, an entry point ran, and nothing had to be added. The result is version-specific by nature; a materially different version should be re-checked |
| O-7's "if verification is not possible" row | No longer needed for the load, which was verified. The version-scope caveat is disclosed in the Status note above and in README Known Limitations (Task 27.1) |

The decision that mattered was the conservative one: nothing was added to the
portable core on the strength of an assumption about what Kiro might want. If
the load verification later shows something is missing, the package gains one
`extensions` namespace and every other client keeps loading exactly what it
loads today.
