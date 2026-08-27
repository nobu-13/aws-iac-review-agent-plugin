---
name: iac-review
description: >-
  Reviews CloudFormation templates, or a whole directory of them, with every
  available source at once: cfn-lint for syntax and resource property
  correctness, cfn-guard for the bundled policy rules covering encryption,
  public access, logging, tagging, IAM and backup, and the deterministic IAM
  detectors for wildcard permissions, privilege escalation patterns and
  cross-account principals. It merges equivalent findings from those sources,
  folds in findings produced by agent reasoning when they are supplied as a
  file, and emits one normalized Review_Report with sequential IDs, per-source
  attribution and a summary. Use this skill when the user asks for a review,
  audit, security check or quality check of a CloudFormation template or a
  directory of infrastructure as code, when synthesized CDK output under
  cdk.out has to be reviewed, or whenever the request does not name a single
  narrow concern. Do not use this skill when the user asks for exactly one of
  those concerns and wants nothing else: cfn-lint-review, cfn-guard-review and
  iam-review each answer their own question with a smaller report, and
  cloudformation-review carries the design review guidance. This skill requires
  Python 3.9 or newer; cfn-lint and cfn-guard are optional external runtime
  dependencies, and the review continues with the remaining sources when either
  is missing.
---

# IaC Review

The orchestrator. It runs every review source over every reviewable template
reachable from the target and returns a single answer.

## Purpose

Produce one Review_Report for a target, covering every concern the plugin can
speak to, with each finding attributed to the sources that detected it.

Three deterministic sources run, always in this order:

| Order | Source | Needs | Reports |
| --- | --- | --- | --- |
| 1 | `cfn-lint` | cfn-lint on `PATH` | Syntax, resource properties, intrinsic functions, deployability |
| 2 | `cfn-guard` | cfn-guard on `PATH` | Violations of the bundled `.guard` policy rules, plus any rules added with `--rules-dir` |
| 3 | `IAM Review` | nothing | Dangerous IAM patterns, matched deterministically |

A fourth source, `Agent Review`, contributes only what a host agent wrote to the
file named by `--agent-findings`. The order is fixed because it is the order in
which merged findings concatenate their evidence, so a report reads the same way
every time.

**A source that fails costs its own findings and nothing else.** An unavailable
tool, a crash, a timeout, unreadable output: each becomes one entry in `errors[]`
and the remaining sources still run. That is why a report can carry findings and
errors at the same time, and why the exit code is 0 in that case. The exit code
turns non-zero only when *nothing* was reviewed by *anything*.

### How this skill relates to the other four

It does not run them. It calls the same shared Python modules they call, so a
finding produced here is identical to the one the corresponding single-purpose
skill produces for the same template. There is no call dependency between
skills in either direction: each one can be used with the others absent.

## When to use this skill

Select this skill when the request is a review rather than a specific check:

- "review this template", "audit this stack", "check this infrastructure code";
- the target is a directory and it is not known what is in it;
- synthesized CDK output under `cdk.out/` has to be reviewed;
- several concerns are named at once (security *and* syntax, IAM *and* policy
  compliance);
- a report is wanted that a later run can be compared against, since stdout is
  byte-identical for identical input.

Do not select this skill when:

- only syntax or resource property correctness matters: use `cfn-lint-review`;
- only compliance with the bundled or organizational `.guard` rules matters: use
  `cfn-guard-review`;
- only IAM risk matters: use `iam-review`;
- design reasoning is wanted and the deterministic checks have already run: use
  `cloudformation-review`, whose guidance produces the agent findings this skill
  then merges.

### Reviewing a CDK project

`cdk synth` is **never** run unless it is explicitly confirmed with
`--confirm-cdk-synth`. Without the flag, a CDK project is reviewed using only
the templates already present under `cdk.out/`, and an `errors[]` entry records
that synthesis was skipped.

Before adding the flag, show the user this warning and obtain their agreement:

> `cdk synth` executes this project's own code and the lifecycle scripts of its
> dependencies. This plugin provides no sandboxing for that execution: the synth
> process runs with your full user privileges. Review CDK source you do not
> trust only after inspecting it.

The confirmation is a command line flag rather than a prompt because these
scripts never read stdin. That places the responsibility for obtaining consent
on you, the calling agent: passing `--confirm-cdk-synth` asserts that the user
saw the warning above and accepted it. Prefer asking the user to run `cdk synth`
themselves and pointing this skill at the resulting directory.

## Input

Run the script from the workspace root:

```bash
python3 skills/iac-review/scripts/run_iac_review.py --target templates/app.yaml
```

| Option | Required | Repeatable | Meaning |
| --- | --- | --- | --- |
| `--target PATH` | yes | yes | A template file, or a directory to scan for template files. |
| `--sources SOURCE` | no | yes | Restrict the review to a subset of the deterministic sources. Accepted values: `cfn-lint`, `cfn-guard`, `IAM Review`, and `iam-review` as a space-free spelling of the same source. Default: all three. |
| `--rules-dir PATH` | no | yes | Additional directory of `.guard` rules for the cfn-guard source. Additive: the bundled rules are always evaluated. Option order does not affect the output. |
| `--agent-findings PATH` | no | no | JSON file of findings produced by agent reasoning, to merge into the report. |
| `--confirm-cdk-synth` | no | no | Permit `cdk synth` for a CDK project target. See the warning above. |
| `--verbose` | no | no | Additional diagnostics on stderr. Never changes stdout. |

Every path is resolved inside the workspace root, which is the current working
directory. A path that escapes it through `..`, an absolute path or a symlink is
refused before any file is read and before any tool is started. Nothing is ever
written: the review reads the files it is pointed at and writes to stdout and
stderr only. No AWS API is called and no credential is read.

### Directory targets

A directory is scanned recursively for `*.yaml`, `*.yml`, `*.json`, `*.template`
and `*.template.json`. `cdk.out/`, `node_modules/`, `.git/` and `.venv/` are not
descended into; templates under `cdk.out/` are collected separately as the
synthesized group. Standalone templates are reviewed first.

A candidate file that turns out not to be a reviewable template is reported in
`errors[]` with its path and skipped, and the review continues with the rest. A
directory scan reaching a `package.json` is the normal case for that.

### Agent findings

The file holds either `{"schema_version": "1.0.0", "findings": [ ... ]}` or a
bare array of findings. `skills/iam-review/SKILL.md` documents the entry format
and the constraints on agent-produced findings in full; the loader enforces them.
A finding that fails validation is dropped, one `errors[]` entry names the
problem, and the remaining findings load. A file that cannot be read or parsed at
all is one `errors[]` entry and the review continues without agent findings. In
neither case does the exit code change: the deterministic review does not depend
on what the agent supplied.

## Output

One JSON document on stdout, and nothing else. Every diagnostic, warning and
error message goes to stderr.

**stdout is exactly the Review_Report envelope.** Top-level stdout keys, in the
order they are serialized: `errors`, `findings`, `schema_version`,
`sources_enabled`, `summary`, `target`, `tools`. The same seven in every run,
whichever sources were enabled.

| Key | Content |
| --- | --- |
| `schema_version` | Version of the report and Finding schema. |
| `target` | `files` (the standalone templates reviewed) and `cdk` (`detected`, plus `synthesized_templates`). Both arrays name only templates that were actually reviewed. |
| `sources_enabled` | The sources this run was configured to use, whether or not each produced findings. |
| `tools` | One entry per external tool a configured source needed: name, availability, detected version. |
| `findings` | Merged findings, sorted by severity descending then by resource, with `ID` numbered from 1 across the whole report. |
| `errors` | One structured entry per failure that did not stop the review. |
| `summary` | `total`, and counts `by_finding_type`, `by_severity`, `by_source`, `by_template_group`, plus `passed_all_checks`. |

`by_source` counts a finding once per source that detected it, so its values can
sum to more than `total` once a finding has been merged. `by_finding_type` and
`by_severity` do sum to `total`. `passed_all_checks` is `true` exactly when
`findings` is empty; it says nothing about `errors`, so a run in which a tool was
missing can report `true` while having reviewed less than it was asked to. The
`errors` array is what tells the two apart.

There is deliberately **no `stats` key**. Per-source counters (how many rules
cfn-guard evaluated, how many results cfn-lint returned, how many policy sites
the IAM detectors examined) are written to stderr under `--verbose`, keyed by
template and source. Two reasons: the envelope has to be readable by a consumer
that does not know which sources ran, and no counter is common to all three
sources.

The rule the five skills share, so that comparing them holds no surprises: stdout
is one JSON document, the Review_Report envelope carries the same seven keys
everywhere, and a counter appears on stdout only where an acceptance criterion
makes it part of the *result* rather than a diagnostic. Exactly one criterion does
-- Requirement 5 AC4, which asks a clean cfn-guard run to state how many rules it
evaluated -- so exactly one skill, `cfn-guard-review`, adds a top-level `stats`
object beside its envelope. Every other counter in the plugin, including all of
this skill's, is a diagnostic on stderr. An aggregating skill never adds `stats`:
the key set of a multi-source counters object would depend on which sources ran,
which is the one thing stdout must not do.

### The IAM informational message

When a template contains no IAM-related resource at all, the IAM source reports
zero findings together with an informational message saying so. That message is
written to **stderr**, not to stdout, and it is not gated on `--verbose`.

It is not a finding, because a finding names a resource and here there is none to
name. It is not an `errors[]` entry, because nothing failed. The envelope has no
field for it, and adding one would make stdout depend on which sources ran. The
standalone `run_iam_scan.py` writes it to stderr as well, so the message reads
the same however the source was invoked.

### Exit codes

| Code | Meaning | stdout |
| --- | --- | --- |
| 0 | At least one template was reviewed by at least one source. Zero findings is a success; so is a run in which some sources or some templates failed. | Report |
| 1 | Unexpected internal error, or a broken plugin installation. | Empty |
| 2 | Missing or unknown argument, an unknown `--sources` value, or a path containing a shell metacharacter. | Empty |
| 3 | A `--target`, `--rules-dir` or `--agent-findings` path does not exist or cannot be read. | Empty |
| 4 | Every candidate template failed to parse. | Report with `errors[]` |
| 5 | Every enabled source was unavailable, or the CDK CLI was absent after `--confirm-cdk-synth`. | Report with `errors[]` |
| 6 | Every enabled source failed while running, or `cdk synth` failed. | Report with `errors[]` |
| 7 | A path resolved outside the workspace root. | Empty |
| 8 | Nothing reviewable was found under `--target`. | Report with `errors[]` |

Codes 4, 5 and 6 describe a run in which *nothing* succeeded. The same failures
affecting only part of a run appear in `errors[]` with exit code 0, because a
non-zero exit would erase the distinction between "the review found nothing" and
"the review did not happen".

The script never reads stdin, never prompts, and never modifies the reviewed
files, the workspace, or any AWS resource.

## Limitations

- **Agent findings are absent unless a host agent produces them.** Without
  `--agent-findings`, the report contains deterministic findings only. Nothing in
  this skill performs reasoning; `Confidence` is `Confirmed` throughout such a
  report, and the design concerns `cloudformation-review` covers are simply not
  represented.
- **CDK source is not synthesized.** Templates are reviewed, not CDK code. With
  `--confirm-cdk-synth` the CDK CLI is invoked once, unsandboxed, and a failure
  is reported without any fallback; without the flag no `cdk` process is started
  at all. Reviewing CDK source starting from source code carries arbitrary code
  execution risk that this plugin does not mitigate.
- **Absence of findings is not evidence of compliance.** Each source sees what it
  covers: cfn-lint its rule set, cfn-guard the resource types its rules mention,
  the IAM detectors an enumerated list of dangerous patterns. A resource no
  source covers produces nothing.
- **Nothing outside the template is consulted.** No AWS account is contacted, so
  account-level settings, existing roles and policies, and whatever a `Ref`,
  `Fn::GetAtt` or `Fn::ImportValue` resolves to at deploy time are outside what
  any source can see.
- **Findings merge only within one template.** Equivalence is matched on resource
  logical ID and normalized category, and two templates may reuse one logical ID
  for unrelated resources, so a merge never crosses a template boundary. Two
  templates that describe the same stack are two sets of findings.
- **`Severity` is comparable only within one `FindingType`.** A `HIGH` security
  finding and a `HIGH` best-practice finding are not two findings of equal
  weight.
- **Determinism holds for the deterministic sources only.** stdout is
  byte-identical across runs and across macOS and Linux for the same input, with
  or without `--verbose`, as long as the tool versions are the same. Merging
  agent findings makes the report only as reproducible as the agent output it was
  given.
- **Findings are reported, never applied.** Remediation guidance describes a
  change; nothing is written back to any file.

## Dependencies

| Dependency | Minimum | Required | Notes |
| --- | --- | --- | --- |
| Python | 3.9 | yes | Standard library only for this script. |
| PyYAML | 6.0 | yes | Needed to read YAML templates. |
| cfn-lint | 1.0.0 | no | **External runtime dependency.** Not included in the plugin package. |
| cfn-guard | 3.0.0 | no | **External runtime dependency.** Not included in the plugin package. |
| AWS CDK CLI | 2.0.0 | no | **External runtime dependency.** Only ever invoked with `--confirm-cdk-synth`. |

**None of the three external tools is bundled with this plugin.** Each is an
external runtime dependency that must already be installed and reachable on the
system `PATH`; the plugin resolves them by name and never installs anything. Each
is verified with its own `--version` before use, once per run.

cfn-lint and cfn-guard are **optional**: when either is missing or too old, the
report names it in `errors[]` with the minimum version and the installation
command, lists it as unavailable in `tools[]`, and the remaining sources produce
the review. Only when every enabled source is unusable does the run exit
non-zero. The IAM source has no external dependency, so a review with no tools
installed at all still reports IAM findings.

The Guard rules themselves are bundled, under `rules/` in the plugin package.

No MCP server is required, and none is used. No network access and no AWS
credentials are needed or read.
