---
name: cfn-guard-review
description: >-
  Validates a CloudFormation template (YAML or JSON) against the plugin's
  bundled cfn-guard policy rules for encryption, public access, logging,
  tagging, IAM and backup, and converts every rule violation into the plugin's
  normalized Finding format with a FindingType, Severity, Confidence,
  Normalized_Category, the violated rule name, the target resource logical ID
  and remediation guidance. Use this skill when the user asks whether a template
  complies with an explicit policy such as "encryption must be enabled",
  "buckets must not be public", "logging is mandatory", "required tags must be
  present" or "backups must be retained", or when an organization-specific
  policy expressed as .guard rules has to be applied to a template. Do not use
  it for template syntax and resource property validation, for IAM risk
  analysis, or for architectural review; those belong to cfn-lint-review,
  iam-review, and cloudformation-review. Requires cfn-guard on the system PATH.
---

# cfn-guard Review

## Purpose

Checks a CloudFormation template against declarative policy rules and reports
each violation as a normalized Finding.

The rules are Guard files (`.guard`) shipped with the plugin, grouped into six
categories: `encryption`, `public-access`, `logging`, `tagging`, `iam` and
`backup`. cfn-guard decides *whether* a rule is violated. The plugin decides how
the violation is classified: the FindingType, the Severity and the
Normalized_Category come from the `_meta.json` file next to the rules of that
category, so classification is reviewable data rather than a judgement made per
run.

A rule violation always carries the logical ID of the resource it was raised on,
the property path cfn-guard reported, and a remediation statement describing the
change that resolves it.

## When to use this skill

Use it when the question is policy compliance:

- Encryption is required on storage and database resources.
- Public access must be blocked (S3 public access block, publicly accessible
  databases, security groups open to the internet).
- Access logging or trail logging must be enabled.
- A set of tags must be present on every resource.
- Backup retention or deletion protection must be configured.
- An organization maintains its own `.guard` rules that a template must satisfy.

Use it after `cfn-lint-review` when both are wanted: a template that does not
parse or that names a property incorrectly is better diagnosed as a lint problem
than as a policy violation.

Do not use it for:

- Template syntax, resource property correctness or intrinsic function checks:
  use `cfn-lint-review`.
- IAM policy risk analysis, privilege escalation paths or trust policy review:
  use `iam-review`. The bundled `iam` category holds one narrow structural rule
  (`Action: "*"` with `Resource: "*"`) and is not an IAM analysis.
- Cross-resource relationships, architectural risk and best practice reasoning:
  use `cloudformation-review`.
- A single combined review across all sources: use `iac-review`, which calls the
  same shared code directly.

## Input

Run the script from the workspace root:

```sh
python3 skills/cfn-guard-review/scripts/run_cfn_guard.py \
  --target examples/minimal-s3/template.yaml
```

| Option | Required | Repeatable | Meaning |
| --- | --- | --- | --- |
| `--target PATH` | yes | yes | CloudFormation template to review. Repeat to cover several templates in one report. |
| `--rules-dir PATH` | no | yes | Additional directory of `.guard` rules to evaluate. |
| `--verbose` | no | no | Additional diagnostics on stderr. Does not change stdout. |

Every path is resolved inside the workspace root (the current working
directory). A path that escapes it, through `..`, an absolute path or a symlink,
is refused before cfn-guard is started.

### Additional rule directories

`--rules-dir` is **additive**: the bundled rules are always evaluated, and each
directory given is evaluated in addition to them. Pointing at a directory does
not replace or disable any bundled rule, so the skill needs no configuration to
be useful and no configuration is lost by adding to it.

```sh
python3 skills/cfn-guard-review/scripts/run_cfn_guard.py \
  --target templates/app.yaml \
  --rules-dir policies/org \
  --rules-dir policies/team
```

The **order of `--rules-dir` options does not affect the result**. The
directories are sorted before the command line is built, and Findings are
ordered by rule name, so the two invocations above and the same two options
swapped produce byte-identical stdout.

To classify rules of your own, place a `_meta.json` next to them, following the
format of the bundled `rules/<category>/_meta.json`. A rule with no metadata is
still reported; it falls back to a conservative FindingType and Severity, and the
missing metadata is recorded in `errors[]`.

## Output

One JSON document on stdout, and nothing else. Diagnostics, warnings and error
messages go to stderr.

Top-level stdout keys, in the order they are serialized: `errors`, `findings`,
`schema_version`, `sources_enabled`, `stats`, `summary`, `target`, `tools`. Seven
of those are the Review_Report envelope, shared with every other Skill. `stats`
is the one key any Skill adds beside the envelope, and this is the only Skill
that adds it: Requirement 5 AC4 obliges a clean run to state how many rules it
evaluated, which makes that count part of the result rather than a diagnostic.
Every other per-run counter in the plugin is a diagnostic and goes to stderr.

The envelope:

| Key | Content |
| --- | --- |
| `schema_version` | Version of the report and Finding schema. |
| `target` | The reviewed template paths, workspace-relative. |
| `sources_enabled` | `["cfn-guard"]`. |
| `tools` | The cfn-guard version check: name, availability, detected version. |
| `findings` | Normalized Findings, sorted by Severity then resource, with `ID` numbered from 1. |
| `errors` | One structured entry per failure that did not stop the review. |
| `summary` | Counts by FindingType, Severity, source and template group, plus `passed_all_checks`. |

And the one key beside it:

| Key | Content |
| --- | --- |
| `stats` | Per-template rule counters, keyed by template path (see below). |

`stats` reports what a clean run evaluated, which is what makes "all rules
passed" a checkable claim:

| Field | Meaning |
| --- | --- |
| `tool_version` | The cfn-guard version that ran. |
| `exit_code` | The exit code it returned. Recorded, never interpreted on its own. |
| `violations_parsed` | Number of violated checks read out of its output. |
| `rules_evaluated` | Number of rules that were evaluated. |
| `rules_passed` | Number of rules that passed. |
| `rules_not_applicable` | Number of rules whose condition did not match, or `null` when that cannot be told apart from passing. |
| `rules_evaluated_source` | How the counts were arrived at: from cfn-guard's output, or from the number of rule declarations found on disk. |

`stats` sits next to the Review_Report rather than inside it, because the report
envelope is shared with the other skills and carries no per-source counters: no
counter is common to all sources, and their values are not of one kind, so a
counters section inside the envelope would have a key set that depends on which
sources ran. A report produced by `iac-review` therefore does not have this key,
and a consumer that reads only the seven envelope keys reads this report the same
way it reads any other.

Zero violations is a successful review: `findings` is empty, `errors` is empty,
`summary.passed_all_checks` is `true`, and `stats` still reports how many rules
were evaluated.

Exit codes:

| Code | Meaning | stdout |
| --- | --- | --- |
| 0 | Review completed. Findings may or may not be present. | Report |
| 1 | Unexpected internal error, or a broken plugin installation. | Empty |
| 2 | Missing or unknown argument, or a path containing a shell metacharacter. | Empty |
| 3 | A target or rule directory does not exist or cannot be read. | Empty |
| 4 | A target could not be parsed as YAML or JSON. | Report with `errors[]` |
| 5 | cfn-guard is not installed, or is older than the minimum version. | Report with `errors[]` |
| 6 | cfn-guard ran and failed: crash, timeout, or output that could not be read. | Report with `errors[]` |
| 7 | A path resolved outside the workspace root. | Empty |
| 8 | A target parsed but is not a reviewable template (no `Resources`). | Report with `errors[]` |

The script never reads stdin, never prompts, and never modifies the reviewed
files or any AWS resource.

## Limitations

- **Only the resource types the rules cover are checked.** A resource type no
  bundled rule mentions produces no Findings. Absence of Findings is not
  evidence that a resource is compliant, only that no rule applied to it.
- **cfn-guard has no notion of severity.** Severity, FindingType and
  Normalized_Category come from the `_meta.json` sidecar of the rule's category,
  and a rule with no metadata falls back to a conservative default. Changing a
  severity means editing that file, not the rule.
- Policy compliance is not correctness. A template that satisfies every rule can
  still be syntactically wrong (`cfn-lint-review`), grant excessive IAM
  permissions (`iam-review`) or be architecturally unsound
  (`cloudformation-review`).
- Rules are evaluated against the template text only. No AWS account is
  contacted, so account-level settings, existing resources, and anything a
  `Ref`, `Fn::GetAtt` or `Fn::ImportValue` resolves to at deploy time are outside
  what a rule can see.
- CDK sources are not synthesized here. Point `--target` at an already
  synthesized template under `cdk.out/`.
- Findings are reported, never applied. Remediation guidance describes a change;
  nothing is written back to the template.

## Dependencies

| Dependency | Minimum | Notes |
| --- | --- | --- |
| cfn-guard | 3.0.0 | **External runtime dependency.** Not included in the plugin package. |
| Python | 3.9 | Standard library only for this script. |
| PyYAML | 6.0 | Required to read YAML templates. JSON templates need nothing extra. |

**cfn-guard is not bundled with this plugin.** It is an external runtime
dependency that must already be installed and reachable on the system `PATH`.
The skill verifies it with `cfn-guard --version` before use; when it is absent or
too old, the skill reports that in `errors[]`, names the minimum version, points
at the installation documentation
(<https://github.com/aws-cloudformation/cloudformation-guard>) and exits 5. It
never attempts to install anything.

The Guard rules themselves *are* bundled, under `rules/` in the plugin package.
No network access and no AWS credentials are used.
