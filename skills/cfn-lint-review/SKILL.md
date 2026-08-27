---
name: cfn-lint-review
description: >-
  Runs cfn-lint against a CloudFormation template (YAML or JSON) and converts
  every cfn-lint result into the plugin's normalized Finding format with a
  FindingType, Severity, Confidence, and Normalized_Category. Use this skill
  when the user asks to lint, validate the syntax of, or check the resource
  property correctness of a CloudFormation template, or when a CloudFormation
  template must be checked for deployability before review of design concerns.
  Do not use this skill for IAM policy risk analysis, organizational policy
  compliance, or architectural review; those are handled by iam-review,
  cfn-guard-review, and cloudformation-review respectively. Requires cfn-lint
  to be installed and available on the system PATH.
---

# cfn-lint Review

## Purpose

Turn cfn-lint's verdict on a CloudFormation template into Findings that read the
same as every other Finding this plugin produces.

cfn-lint is the authority on CloudFormation syntax, resource property
correctness, intrinsic function usage, and `Parameters` / `Outputs` structure.
This skill does not re-derive any of that. It runs the tool and maps each result
onto the normalized Finding schema:

| cfn-lint result | FindingType | Severity |
| --- | --- | --- |
| Error, rule ID starting `E0` or `E1` | `Validity` | `CRITICAL` |
| Error, any other rule ID | `Validity` | `HIGH` |
| Warning | `BestPractice` | `MEDIUM` |
| Informational | `Informational` | `LOW` |

A rule listed as security-relevant in the plugin's category mapping gets
FindingType `Security` instead of `Validity`. Every Finding carries
`Confidence: Confirmed`: a rule either fired or it did not, and the rule that
fired is the evidence.

cfn-lint is invoked with `-f json` and with Informational rules enabled
(`--include-checks I`, spelled `-c I`), which cfn-lint does not evaluate by
default. Output from this skill therefore contains more Findings than a bare
`cfn-lint` run on the same template.

## When to use this skill

Use it when the question is whether a template is well-formed and deployable:

- linting or syntax-validating a CloudFormation template;
- checking that resource properties, types, and values are valid;
- checking intrinsic functions, `Ref` / `Fn::GetAtt` targets, `Parameters`, and
  `Outputs`;
- establishing that a template deploys at all, before reviewing its design.

Do not use it for:

- IAM policy risk analysis: use `iam-review`;
- organizational or explicit infrastructure policy compliance, such as mandatory
  encryption, public access prohibition, mandatory logging, tagging, or backup:
  use `cfn-guard-review`;
- cross-resource relationships, architectural risk, and best-practice reasoning:
  use `cloudformation-review`;
- a single combined review over all of the above: use `iac-review`.

## Input

Run the script from the workspace root:

```bash
python3 skills/cfn-lint-review/scripts/run_cfn_lint.py --target path/to/template.yaml
```

| Argument | Required | Meaning |
| --- | --- | --- |
| `--target PATH` | yes | Template to review. Repeat to review several templates into one report. |
| `--verbose` | no | Extra diagnostics on stderr. Does not change stdout. |

Both YAML and JSON templates are accepted; the format is detected from the file
content, not from the extension. Each `--target` must resolve inside the
workspace root, must exist, and must contain a top-level `Resources` mapping
with at least one entry. Paths containing a shell metacharacter
(`;` `|` `&` `$` `` ` `` `>` `<`) are rejected rather than escaped.

The script never reads stdin and never prompts, so it is safe to run
non-interactively.

## Output

A Review_Report JSON document on stdout, and nothing else on stdout. Diagnostics,
warnings, and stack traces go to stderr.

Top-level stdout keys, in the order they are serialized: `errors`, `findings`,
`schema_version`, `sources_enabled`, `summary`, `target`, `tools`. That is the
Review_Report envelope and nothing beside it. Per-run counters are diagnostics
here, not results, so they go to stderr under `--verbose`; the one Skill that
carries a counter on stdout is `cfn-guard-review`, which Requirement 5 AC4
obliges to report its evaluated-rule count as part of the result.

The report holds `schema_version`, `target`, `sources_enabled`, `tools`,
`findings[]`, `errors[]`, and `summary`. `target.files` lists every requested
target as a workspace-relative path, `sources_enabled` is always `["cfn-lint"]`,
and every Finding has `Source: ["cfn-lint"]`. A template with no violations
yields `findings: []` rather than no output.

`errors[]` carries one structured entry per failure that did not stop the run,
each with an `error_class`, the tool name, the tool's exit code where one exists,
and up to five lines of the tool's stderr.

Exit codes:

| Code | Meaning | stdout |
| --- | --- | --- |
| 0 | Every target was reviewed. Zero Findings is a success, not a failure. | report |
| 1 | Unexpected internal error, or a corrupt bundled category mapping. | empty |
| 2 | Missing or unknown argument, or a path containing a shell metacharacter. | empty |
| 3 | A `--target` does not exist or cannot be read. | empty |
| 4 | A `--target` could not be parsed as YAML or JSON. | partial report |
| 5 | cfn-lint is not installed, or is older than 1.0.0. | report with `errors[]` |
| 6 | cfn-lint crashed, timed out, or printed unexpected output. | report with `errors[]` |
| 7 | A `--target` resolves outside the workspace root. | empty |
| 8 | A `--target` contains no reviewable `Resources` mapping. | partial report |

With several `--target` values, the exit code is the first non-zero status any
target produced, and the report still contains the Findings of the targets that
succeeded.

## Limitations

- Design problems cfn-lint does not detect are out of scope. This skill adds no
  checks of its own.
- Results depend on the installed cfn-lint version and its bundled AWS resource
  specification. Two machines with different cfn-lint versions can legitimately
  produce different reports for the same template.
- Some `E3xxx` errors block deployment yet map to `HIGH` rather than `CRITICAL`,
  because the deployment-blocking set is deliberately limited to the `E0` and
  `E1` prefixes. The plugin's category mapping file can override any rule's
  severity.
- Informational rules are enabled explicitly, so this skill reports Findings a
  plain `cfn-lint` invocation does not.
- The report carries no count of rules *evaluated*. `cfn-lint -f json` reports
  only the rules that fired and says nothing about how many were checked;
  deriving a total from the number of distinct rule IDs seen would state
  something cfn-lint never claimed. Per-run counters that can be obtained
  honestly -- results parsed, distinct rules triggered, tool version, tool exit
  code, whether Informational rules were enabled -- are printed on stderr under
  `--verbose`, where they cannot affect the report.
- Processing stops at the first `--target` that cannot be parsed or holds no
  `Resources` mapping. `target.files` still lists every requested target, but
  only the targets reached before the failure contribute Findings.
- The template is not deployed, no AWS API is called, and no file is modified.
  Review is read-only.

## Dependencies

| Dependency | Minimum | Notes |
| --- | --- | --- |
| cfn-lint | 1.0.0 | External runtime dependency |
| Python | 3.9 | External runtime dependency |
| PyYAML | 6.0 | Python import, used to parse the template |

**cfn-lint is an external runtime dependency and is not included in the plugin
package.** The plugin bundles no binaries; it resolves `cfn-lint` on the system
PATH at run time. If cfn-lint is missing or too old, the skill exits 5 and
reports the tool name, the required minimum version, and the installation
command instead of failing silently:

```bash
pip install cfn-lint
```

Python 3.9 or newer is likewise expected to be present on the system. No other
external tool is required: this skill does not invoke cfn-guard, the AWS CDK
CLI, or any MCP server, and it makes no network requests of its own.
