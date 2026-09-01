# aws-iac-review-agent-plugin

An Agent Plugins 1.0.0 package that reviews AWS Infrastructure as Code by
combining deterministic static analysis with agent semantic reasoning, and emits
one normalized finding report.

A Japanese supplement is available as [`README.ja.md`](README.ja.md). It follows
the sections below one for one; this English document is the authoritative one.

## What is aws-iac-review-agent-plugin

A portable plugin package -- a manifest, five Skills, a shared Python 3 library
and a set of cfn-guard policy rules -- that reviews AWS CloudFormation templates
and synthesized AWS CDK output. It runs cfn-lint for syntax and resource
property correctness, cfn-guard for explicit policy rules, and its own
deterministic IAM detectors for dangerous permission patterns. It then merges
everything those sources found, folds in findings a host agent produced by
reasoning, and writes a single JSON `Review_Report` on stdout.

What it does today:

| Capability | How |
| --- | --- |
| CloudFormation syntax and resource property review | cfn-lint, results normalized into the plugin's Finding schema |
| Organizational policy review | cfn-guard against 36 bundled `.guard` rules covering encryption, public access, logging, tagging, IAM, backup, availability and data protection |
| Deterministic IAM review | 15 active detectors over wildcard permissions, privilege escalation actions, unrestricted `iam:PassRole` and `sts:AssumeRole`, missing confused-deputy conditions, cross-account and wildcard principals |
| Deterministic network review | Resource-graph analysis over gateway attachment, default routes, internet reachability and orphaned network resources |
| Deterministic secret review | Plaintext-secret detection in Lambda environment variables, EC2 UserData, and Parameter defaults, with values redacted in output |
| Deterministic quality review | Template-structure analysis over condition logic, unused parameters and conditions, circular dependencies and mixed-type allowed values |
| Agent semantic review | Two Skills (`cloudformation-review`, `iam-review` layer 2) reason over deterministically extracted facts and produce findings the pipeline validates and merges |
| One normalized report | Every finding carries the same 13 fields, one of 11 categories, and the sources that detected it. Equivalent findings merge. IDs are assigned deterministically |
| SARIF 2.1.0 output | `iac-review --format sarif` emits the report as SARIF for GitHub code scanning and CI result viewers; a deterministic transform that keeps Confidence, category, and the merged source list in each result's `properties` |
| Reviewing synthesized CDK output | Templates under `cdk.out/` are reviewed as a separate group. `cdk synth` runs only behind an explicit flag |

It is read-only. It calls no AWS API, deploys nothing, and applies no fix.

## Why this project exists

Reviewing AWS IaC means answering questions that no single tool answers.
Syntax, CloudFormation-specific rules, encryption, public access, logging,
backup, tagging, IAM permission design, and whether the architecture is sound
are usually checked by different tools, in different output formats, with the
architectural judgement left to a human. Reconciling those outputs is manual
work, and the result is hard to reproduce.

This project's position is that the two kinds of review should be combined
rather than chosen between, and kept strictly apart internally:

- **Anything an existing tool can decide, that tool decides.** cfn-lint owns the
  CloudFormation resource specification. cfn-guard owns declarative policy. The
  enumerated dangerous IAM patterns are matched by code. None of it is
  reimplemented as reasoning, and all of it is `Confidence: Confirmed`.
- **Anything no closed rule set expresses is left to agent reasoning.** Risk in
  the relationship between resources, architecture concerns, contextual
  severity, and best practices that are not encoded as rules. Those findings are
  `Likely` or `Contextual`, never `Confirmed`.
- **Everything after detection is deterministic code.** Normalization, merging,
  ordering, numbering and summarizing are Python, so the report is byte-identical
  across runs for the same input, which is what makes a review comparable to the
  one before it.

`docs/architecture.md` sets out the deterministic/agent boundary decision by
decision, including the three things an agent structurally cannot do.

## Architecture

```text
IaC (untrusted)
 -> deterministic checks: cfn-lint, cfn-guard, IAM detectors, network graph analysis, secret detection, template quality
 -> agent semantic review: IAM context, security, architecture, best practices
 -> Finding normalization
 -> deduplication and merge
 -> Review_Report (JSON on stdout)
```

Five Skills, each with its own responsibility and its own entry point. None
calls another; they share the `iacreview/` package at the plugin root, so a
finding does not depend on which Skill produced it.

| Skill | Answers | Needs |
| --- | --- | --- |
| [`cfn-lint-review`](skills/cfn-lint-review/SKILL.md) | Is the template syntactically valid and deployable? | cfn-lint on `PATH` |
| [`cfn-guard-review`](skills/cfn-guard-review/SKILL.md) | Does it comply with the bundled or your own `.guard` policy rules? | cfn-guard on `PATH` |
| [`iam-review`](skills/iam-review/SKILL.md) | What do its IAM policies allow, and which grants are dangerous? | nothing external |
| [`cloudformation-review`](skills/cloudformation-review/SKILL.md) | Is the design sound: cross-resource risk, single points of failure, contextual severity? | nothing external; this is the agent-reasoning Skill |
| [`iac-review`](skills/iac-review/SKILL.md) | All of the above, as one report | cfn-lint and cfn-guard optional |

Repository layout:

```text
plugin.json          the Agent Plugins 1.0.0 manifest
skills/              five Skills, each with SKILL.md and scripts/
iacreview/           the shared deterministic library (imported, never installed)
rules/               36 cfn-guard rules in 6 category directories
benchmark/           15 measured cases, ground truth, and the harness
examples/            small templates that are meant to pass review
tests/               unit, integration, negative, regression and property tests
docs/                architecture, security model, Finding schema, benchmark method, Kiro
```

Read `docs/architecture.md` for the pipeline, the layer guarantees, and why the
shared library sits beside `skills/` rather than inside it.

## Supported IaC

| Input | Supported | Notes |
| --- | --- | --- |
| CloudFormation template, YAML | Yes | Parsed with a `SafeLoader` subclass and an explicit allowlist of CloudFormation short tags |
| CloudFormation template, JSON | Yes | `json.loads`, no hooks. Works without PyYAML installed |
| A directory of templates | Yes | Scanned recursively for `*.yaml`, `*.yml`, `*.json`, `*.template`, `*.template.json` |
| Synthesized CDK output (`cdk.out/`) | Yes | Reviewed as a separate template group, counted separately in the summary |
| A CDK project, from source | Only behind `--confirm-cdk-synth` | The flow is `cdk synth` -> CloudFormation template -> review. Synthesis executes your project's code, unsandboxed. See Security Considerations |
| Terraform, Pulumi, other IaC | No | Not in v0.1. See Roadmap |

Which parser runs is decided by content, not by file extension: a document whose
first non-whitespace character is `{` or `[` is parsed as JSON. Intrinsic
functions are converted to their long form as data (`!Ref X` becomes
`{"Ref": "X"}`); nothing is resolved or evaluated.

## Requirements

Runtime:

| Dependency | Minimum | Required | Notes |
| --- | --- | --- | --- |
| Python 3 | 3.9 | Yes | Invoked as `python3` |
| PyYAML | 6.0 | Yes for YAML templates | The **only** runtime Python dependency. JSON templates review without it |
| cfn-lint | 1.0.0 | No | External runtime dependency, not bundled |
| cfn-guard | 3.0.0 | No | External runtime dependency, not bundled |
| AWS CDK CLI | 2.0.0 | No | External runtime dependency, not bundled. Only ever invoked with `--confirm-cdk-synth` |

**None of the three external tools ships with this plugin.** Each is resolved by
name on `PATH` and version-checked once per run; the plugin installs nothing. If
cfn-lint or cfn-guard is missing or too old, it is named in `errors[]` with its
minimum version and install command, listed as unavailable in `tools[]`, and the
remaining sources produce the review. With neither installed, a review still
reports IAM findings, because the IAM detectors are the plugin's own code.

Supported operating systems are **macOS and Linux**. Windows is out of scope for
v0.1: it is not tested, and some test helpers are POSIX shell scripts.

Development and test dependencies (`pytest`, `pytest-cov`, `hypothesis`) are
declared separately in `pyproject.toml` under the `dev` extra and are not part of
the runtime dependency budget. Nothing under `iacreview/`, `skills/` or
`benchmark/` imports them.

## Installation

The plugin ships as a directory. There is no build step, nothing is generated,
and it is never `pip install`-ed: the directory a client is handed is the
repository directory, with `plugin.json` at its root.

```sh
git clone https://github.com/nobu-13/aws-iac-review-agent-plugin.git
cd aws-iac-review-agent-plugin
```


Install PyYAML, needed to review YAML templates:

```sh
pip install 'PyYAML>=6.0'
```

Install the optional external tools you want. These are the commands the plugin
itself reports as remediation when a tool is absent:

| Tool | macOS | Linux |
| --- | --- | --- |
| cfn-lint | `pip install cfn-lint` | `pip install cfn-lint` |
| cfn-guard | `brew install cloudformation-guard` | `cargo install cfn-guard` |
| AWS CDK CLI | `npm install -g aws-cdk` | `npm install -g aws-cdk` |

Confirm the installation by reviewing a bundled example, which reports nothing:

```sh
python3 skills/iac-review/scripts/run_iac_review.py \
  --target examples/minimal-s3/template.yaml
```

## Using as a Kiro Power

Kiro loads Agent Plugins packages as Powers, and this package needs nothing
added to it for that: `plugin.json` sits at the package root and `skills/` holds
exactly five child directories, each with a `SKILL.md`, which is the shape a
non-recursive discovery scan finds.

See **[`docs/kiro-power.md`](docs/kiro-power.md)** for what a Power load depends
on, which files in this repository are Kiro-specific and why they sit outside the
portable package, and exactly how far the claim has been verified.

> **Status.** The structural preconditions a Power load depends on are verified
> and pinned by tests. Driving a Kiro installation to load this package and
> observing the five Skills reach the host agent has **not** been done, so no
> installation procedure is stated. Known Limitations records this.

The Kiro-specific development files (`.kiro/steering/`, `.kiro/specs/`) are not
needed to run the plugin. No file under `skills/`, `iacreview/`, `rules/` or
`benchmark/` reads anything from `.kiro/`.

## Usage

Run the scripts from the repository root. The working directory is the workspace
root, and every path is resolved inside it. Each writes one JSON document to
stdout and every diagnostic to stderr. Nothing reads stdin, nothing prompts, and
nothing is written to your workspace.

The whole review, one report:

```sh
python3 skills/iac-review/scripts/run_iac_review.py \
  --target examples/minimal-s3/template.yaml
```

```sh
python3 skills/iac-review/scripts/run_iac_review.py --target templates/
```

One concern at a time:

```sh
python3 skills/cfn-lint-review/scripts/run_cfn_lint.py --target examples/minimal-s3/template.yaml
python3 skills/cfn-guard-review/scripts/run_cfn_guard.py --target examples/minimal-s3/template.yaml
python3 skills/iam-review/scripts/run_iam_scan.py --target examples/lambda-with-role/template.yaml
```

Facts for an agent to reason over, which is how the agent-reasoning Skills start:

```sh
python3 skills/cloudformation-review/scripts/extract_facts.py --target examples/minimal-s3/template.yaml
python3 skills/iam-review/scripts/extract_policies.py --target examples/lambda-with-role/template.yaml
```

A structured review prompt built from those facts, ready for a host agent or an
optional MCP-connected model to reason over:

```sh
python3 skills/cloudformation-review/scripts/build_prompt.py --target examples/minimal-s3/template.yaml
```

Merging findings an agent produced back into the report:

```sh
python3 skills/iac-review/scripts/run_iac_review.py \
  --target templates/app.yaml \
  --agent-findings agent-findings.json
```

Emit SARIF 2.1.0 instead of the default JSON report, for GitHub code scanning or
another CI result viewer:

```sh
python3 skills/iac-review/scripts/run_iac_review.py \
  --target templates/app.yaml \
  --format sarif > review.sarif
```

`iac-review` options: `--target` (required, repeatable), `--sources` to restrict
which deterministic sources run, `--rules-dir` to add your own `.guard` rules on
top of the bundled ones, `--format {json,sarif}` (default `json`),
`--agent-findings`, `--confirm-cdk-synth`, `--verbose`.
Each `SKILL.md` documents its own options and output in full.

### Report envelope

stdout is exactly seven keys, in every run, whichever sources ran:
`schema_version`, `target`, `sources_enabled`, `tools`, `findings`, `errors`,
`summary`. One Skill adds a counter beside them: `cfn-guard-review` emits a
top-level `stats` object, because a clean cfn-guard run has to state how many
rules it evaluated. Every other counter this plugin produces is a stderr
diagnostic under `--verbose`, and `--verbose` never changes stdout.

`summary.passed_all_checks` is `true` exactly when `findings` is empty. It says
nothing about `errors`, so a run whose tool was missing can report `true` having
reviewed less than it was asked to. The `errors` array is what tells the two
apart.

`docs/finding-schema.md` is the reference for all 13 Finding fields, the five
closed value sets, the merge laws, and how to read a report.

### Exit codes

| Code | Meaning | stdout |
| --- | --- | --- |
| 0 | At least one template was reviewed by at least one source. Zero findings is a success | Report |
| 1 | Unexpected internal error, or a broken plugin installation | Empty |
| 2 | Missing or unknown argument, or a path containing a shell metacharacter | Empty |
| 3 | An input path does not exist or cannot be read | Empty |
| 4 | Every candidate template failed to parse | Report with `errors[]` |
| 5 | Every enabled source was unavailable | Report with `errors[]` |
| 6 | Every enabled source failed while running, or `cdk synth` failed | Report with `errors[]` |
| 7 | A path resolved outside the workspace root | Empty |
| 8 | Nothing reviewable was found under `--target` | Report with `errors[]` |

Codes 4, 5 and 6 describe a run in which *nothing* succeeded. The same failures
affecting only part of a run appear in `errors[]` with exit code 0, because a
non-zero exit would erase the difference between "the review found nothing" and
"the review did not happen".

The benchmark harness adds two codes of its own, 9 and 10, which are deliberately
outside the plugin's table. See `benchmark/README.md`.

## Review Categories

Every finding from every source carries exactly one `Normalized_Category` from a
closed set of 11. The authoritative list is the `categories` array of
`iacreview/category_map.json`.

| Category | Subject |
| --- | --- |
| `IAM` | Permission design in IAM policies, roles, users, groups, trust policies, resource-based policies |
| `Encryption` | Encryption at rest, encryption in transit, KMS key usage |
| `PublicAccess` | Reachability from the internet or from all AWS accounts |
| `Logging` | Access logs, audit logs, flow logs and their enablement |
| `Tagging` | Presence of required tags |
| `Availability` | Multi-AZ, redundancy, single points of failure |
| `Backup` | Backup configuration, retention periods, deletion protection |
| `NetworkSecurity` | Security Group, NACL and VPC boundary design that is not `PublicAccess` |
| `DataProtection` | Data retention, versioning, deletion prevention, handling of sensitive data |
| `TemplateQuality` | Syntax, property validity, deprecated constructs, template structure |
| `Other` | An agent finding that maps to nothing above. Excluded from deduplication matching |

`PublicAccess` and `NetworkSecurity` are separated by one rule: reachability from
the internet (`0.0.0.0/0`) or from all AWS accounts (`Principal: "*"`) is
`PublicAccess`; every other network boundary concern is `NetworkSecurity`.

The bundled cfn-guard rules, 36 files in 6 directories:

```text
rules/
  encryption/     s3_bucket_encryption, rds_storage_encrypted, ebs_volume_encrypted,
                  sns_topic_encrypted, logs_group_encrypted, sqs_queue_encrypted,
                  dynamodb_encryption, kinesis_encryption, redshift_encryption,
                  elasticache_encryption, efs_encryption
  iam/            iam_policy_no_star_star
  logging/        s3_access_logging, cloudtrail_enabled, logs_retention_set,
                  alb_access_logging, vpc_flow_logs, vpc_dns_hostnames
  public-access/  s3_public_access_block, security_group_open_ingress,
                  rds_publicly_accessible, ec2_imdsv2_required,
                  alb_https_only, cloudfront_https
  backup/         rds_backup_retention, rds_deletion_protection, rds_multi_az,
                  s3_deletion_policy, s3_versioning_enabled, dynamodb_pitr,
                  secrets_rotation, lambda_dlq, lambda_timeout,
                  asg_multi_az, ec2_ebs_optimized
  tagging/        required_tags
```

Each directory carries a `_meta.json` that assigns the FindingType, Severity and
`Normalized_Category` of its rules, so the classification is reviewable data
rather than a judgement made per run. Add your own rules with `--rules-dir`; the
bundled rules are always evaluated as well.

## Examples

[`examples/`](examples/) holds small, well-formed templates that are meant to
pass review. Templates with deliberate defects are not there; they are benchmark
cases.

| Example | Findings reported |
| --- | --- |
| [`examples/minimal-s3/template.yaml`](examples/minimal-s3/template.yaml) | None. `summary.passed_all_checks` is `true` |
| [`examples/lambda-with-role/template.yaml`](examples/lambda-with-role/template.yaml) | Exactly one: `HIGH`, `Security`, `IAM`, on the execution role's trust policy |
| [`examples/cdk-synth-output/README.md`](examples/cdk-synth-output/README.md) | How to review a CDK application after synthesizing it |

Both counts are asserted by `tests/integration/test_examples.py`, so an example
that starts reporting something new fails the suite rather than drifting.

The one finding on `lambda-with-role` is documented and correct: the IAM
detectors report an unconditioned service principal in a Lambda execution role's
trust policy, which is the trust policy AWS documents. The finding is right about
the shape of the policy and its recommendation is not actionable for that
service. [`examples/README.md`](examples/README.md) works the case through in
full, and Known Limitations records the asymmetry.

## Benchmark

The benchmark measures review quality. It is not the test suite: `tests/` asks
whether the plugin behaves as specified, and a failure there is a defect;
`benchmark/` asks how much of a known set of defects the review finds, and a
number there is a measurement.

```sh
python3 benchmark/harness/run_benchmark.py --cases benchmark/cases --mode combined
```

Current measurement over the 12 cases in this repository, with Python 3.9.6,
cfn-lint 1.46.0 and cfn-guard 3.2.1:

| Item | Value |
| --- | --- |
| Cases | 12: `case-001` to `case-010` with deliberate defects, `case-101` and `case-102` clean |
| Expectations | 21, all `deterministic` |
| Detected | 21 / 21, detection rate `100.0` |
| False positives | 0, precision `100.0`, severity accuracy `100.0` |
| Categories | 7 exercised, all `PASS` |
| `errors` | empty |
| Exit code | 0 |

What that does mean: every defect these 12 templates were built around is
detected, at the expected severity, with no undeclared finding alongside, and any
future change that stops one of those detections turns a category `FAIL` and the
exit code 9. What it does not mean: anything about templates this project did not
write, or about the false positive rate, which is measured on two clean
templates.

The harness runs no agent, so two runs over the same cases print byte-identical
stdout. Ground truth is authored from the defects deliberately placed in a
template, before any review is run against it, and is never reverse-engineered
from review output.

`benchmark/README.md` is the operator's guide; `docs/benchmark-methodology.md`
defines what each number means and how far it generalizes.

## Validation

| What | How |
| --- | --- |
| Test suite | `python3 -m pytest`, over 4000 tests, zero failures |
| Unit | 43 files over the deterministic modules: parsing, normalization, severity mapping, dedup, path validation, exit codes, network graph analysis, secret detection, template quality |
| Integration | 14 files running the seven entry points as real subprocesses over real templates, including 133 malformed-input cases |
| Negative | Clean templates produce no false positive of the counted classes |
| Regression | 11 files pinning security behaviours and previously found defects: path traversal, malformed YAML and JSON, shell-metacharacter filenames, missing external tool, invalid arguments, symlink cycles, no host path in errors, YAML alias bombs, non-regular files, and process-group reaping on timeout |
| Property | 13 files stating 31 named properties with `hypothesis`, including path containment against an independent oracle and an AST scan proving `iacreview.proc` is the only process-spawning path in the shipped code |
| Coverage | `python3 -m pytest --cov=iacreview --cov=benchmark/harness --cov-fail-under=80` |
| Benchmark | `python3 benchmark/harness/run_benchmark.py --cases benchmark/cases --mode combined`, all categories `PASS` |

Every command above was run against this repository. `docs/security-model.md`
carries a table mapping each security claim to the test that pins it.

v0.8.0 hardens the review against hostile input: a Template over 5 MiB, or a
directory whose Templates exceed 50 MiB in aggregate, is refused without being
read; a YAML alias bomb is bounded and fails as a parse error; a Template is read
through a single file descriptor so a symlink cannot be swapped between the
containment check and the read; a timed-out tool's descendants are reaped; and an
absolute host path in a tool's stderr is redacted before it reaches the report.
The benchmark harness additionally records Remediation Accuracy, Human
Intervention Count and Review Time as diagnostics that never affect its pass/fail
verdict, and offers `agent-only` and `human-review` modes alongside the
Source-subset modes. `docs/security-model.md` (R-2, R-4, R-8, R-9) and
`docs/benchmark-methodology.md` cover these.

## Security Considerations

This plugin processes Infrastructure as Code it has no reason to trust. Every
input template, every path, and every byte of external tool output is treated as
untrusted data. `docs/security-model.md` is the full account, including the
trust boundaries and the residual risks; the summary:

**Read-only by default.** No AWS resource is created, modified or deleted, and
no AWS API is called at all: there is no AWS SDK dependency. Nothing is
deployed, no account setting is changed, and no module opens a workspace file for
writing.

**No automatic remediation.** A fix is reported as the `SuggestedRemediation`
field of a finding. Nothing applies it anywhere.

**AWS credentials are withheld from child processes.** Process creation is
concentrated in one function, which passes children an environment allowlist of
`PATH`, `HOME`, `LANG`, `LC_ALL`, `TMPDIR`, `AWS_REGION` and
`AWS_DEFAULT_REGION` -- and nothing else. `AWS_ACCESS_KEY_ID`,
`AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`, `AWS_PROFILE` and every other
`AWS_*` variable are dropped. It is an allowlist rather than a denylist so that a
variable AWS invents later is withheld by default. No credential appears in any
file in this repository: benchmark and example values are obvious placeholders.

**No shell.** Every external tool is launched with an argv array and
`shell=False`, with stdin closed and a timeout. No command string is ever built
by concatenation. A property test parses every shipped `.py` file and fails if a
second process-spawning path appears anywhere.

**Path containment.** Every user-supplied path is resolved and then checked to
fall inside the workspace root, before any file is opened and before any tool is
started. Plugin-owned resources are contained to the plugin root. Values are
rejected, never sanitized.

**Untrusted IaC fails safely.** YAML is parsed by a `SafeLoader` subclass with an
explicit tag allowlist, so a tag such as `!!python/object/apply:os.system` raises
instead of executing. JSON uses no hooks. Every parse failure is a typed error
carrying a line and a column, never a traceback.

**`cdk synth` is the one arbitrary code execution boundary.** It is never
automatic. `--confirm-cdk-synth` is required, the warning is written to stderr on
both paths, a 120 second timeout applies, and there is no fallback. The synth
process runs your project's code and its dependencies' lifecycle scripts with
your full user privileges. **This plugin provides no sandboxing for that
execution.**

**MCP is not a dependency.** No `mcp.json` ships in the plugin root, and every
core capability works fully without one. If you add a configuration yourself,
the plugin's deterministic code still never opens an MCP connection -- only the
host agent does -- and a template path or template content sent to a server
leaves this plugin's control at that point.
[`docs/mcp/README.md`](docs/mcp/README.md) is the per-server record: purpose,
required permissions, network access, credentials, data sent externally, and
failure behaviour. Note that `.gitignore` does not currently exclude `mcp.json`,
so if you copy `docs/mcp/mcp.json.example` into the repository, take care not to
commit local configuration.

## Known Limitations

Nothing here is hidden or downplayed. Where a limitation is deliberate, the
reason is in the document named beside it.

**Scope**

- v0.1 does not cover Terraform, Pulumi, runtime security analysis, FinOps
  analysis, a full Well-Architected review, a web UI, automatic deployment, or
  automatic remediation. These are non-goals for this version, not partially
  implemented features. See Roadmap.
- **Windows is not supported.** Requirement 10 AC3 covers macOS and Linux only.
  The code may work on Windows and is not tested there; some test helpers are
  POSIX shell scripts that do not run.

**Execution safety**

- **There is no sandboxing for `cdk synth`.** Reviewing CDK source starting from
  source code executes that code with your full user privileges. The plugin
  mitigates this only by requiring an explicit flag, withholding AWS credentials
  from the child, and applying a timeout. `docs/security-model.md` explains why
  an incomplete sandbox was judged worse than none.
- **A filename containing `$` is rejected.** A file named `cost$estimate.yaml`
  cannot be reviewed in v0.1: `$` is one of seven shell metacharacters refused in
  user-supplied paths. The rejection is an explicit, named error. Values are
  rejected rather than sanitized, because stripping the character would silently
  redirect the read to a different file.
- **`errors[].stderr_head` carries external tool output, with absolute host
  paths redacted (v0.8.0).** It is up to five lines copied from a crashing tool,
  and each line is scanned so an absolute host path is replaced with a fixed
  `<path>` placeholder before it reaches the report, keeping the excerpt
  byte-identical between runs. The redaction covers absolute POSIX paths only:
  process identifiers, timestamps, and anything else a tool prints about the
  input are still passed through, so treat the field as untrusted external text.
  The five-line cap bounds how much, not what (`docs/security-model.md`, R-4).

**Reproducibility**

- **Agent Review output is not deterministic.** The deterministic pipeline is
  byte-identical for the same input, and byte-identical again for the same agent
  findings file, which is what makes a recorded agent output usable as a
  regression fixture. Generating those findings is not reproducible: an agent may
  report different findings, or word them differently, on a second run. Merging
  agent findings makes a report only as reproducible as the agent output it was
  given.
- **External tool version differences change results.** cfn-lint and cfn-guard
  each evolve their own rule sets, and neither is bundled or pinned. A newer
  cfn-lint may report a rule an older one did not. Findings that differ for that
  reason are outside the cross-platform consistency guarantee, which is about the
  operating system rather than the installed tool versions. The observed version
  is recorded in `tools[].version`; when a documented figure disagrees with a
  local run, compare tool versions first (`docs/architecture.md`).
- **Behaviour may differ between agent clients.** The reasoning Skills are
  interpreted by whichever host agent runtime loaded the package, so the agent
  layer's output depends on that client. The deterministic layer does not.

**Coverage**

- **The bundled cfn-guard rules only inspect the resource types they name.** The
  36 rules cover S3, RDS, IAM, CloudTrail, Security Group, Lambda, DynamoDB, SQS, SNS, EFS, Kinesis, Redshift, ElastiCache, ALB, CloudFront, ASG, EC2 and VPC
  configurations. A resource type no rule mentions produces no cfn-guard finding,
  which is not evidence that it is well configured. Add your own rules with
  `--rules-dir`.
- **Resource-based policy coverage is a fixed list.**
  `AWS::S3::BucketPolicy`, `AWS::KMS::Key`, `AWS::SQS::QueuePolicy`,
  `AWS::SNS::TopicPolicy`, `AWS::ECR::Repository`,
  `AWS::SecretsManager::ResourcePolicy` and `AWS::Lambda::Permission` are
  examined in v0.1. Other services carry resource-based policies and are not yet
  covered; a policy on such a resource is out of scope rather than reported.
- **Absence of findings is not evidence of compliance.** Each source sees what it
  covers, and nothing outside the template is consulted. No AWS account is
  contacted, so account-level settings, roles that exist only in the account, and
  whatever a `Ref`, `Fn::GetAtt` or `Fn::ImportValue` resolves to at deploy time
  are outside what any source can see.
- **The in-Kiro Power load is unverified.** The structural preconditions a Power
  load depends on are verified mechanically and pinned by tests, but no Kiro
  installation was driven to load this package, and no host agent was observed
  enumerating the five Skills. The claim that the Skills are discoverable in Kiro
  rests on a structural argument, not an observation, which is why
  `docs/kiro-power.md` states no installation procedure. Requirement 10 AC7 stays
  partly owed.

**Severity and FindingType conservatism**

Transcribed from `docs/finding-schema.md`, which owns the classification. Em
dashes in the original are written as `--` here to keep this file ASCII.

- The `CRITICAL` Severity is assigned conservatively. Only cfn-lint rules whose
  reported condition is verified to make a deployment impossible are promoted, so
  some genuinely deployment-blocking errors are reported as `HIGH` rather than
  `CRITICAL`. `HIGH` is never assigned in place of a lower Severity, so no
  finding is understated by this policy.
- The survey covers the cfn-lint **1.46.0** catalogue. A newer cfn-lint may add
  rules the mapping file does not know; those are classified from their level and
  reported as `HIGH` at `Error` level, never `CRITICAL`.
- `E3002` results are reported as `HIGH` even though many of them do block a
  deployment, because the rule ID alone does not identify which underlying schema
  failure occurred.
- The `Security` FindingType is assigned conservatively from cfn-lint results.
  Only 7 of the 66 `Warning` and `Informational` rules are marked, so a
  security-relevant condition that cfn-lint reports under a rule not on the list
  appears as `BestPractice` or `Informational` rather than `Security`. The
  cfn-guard, IAM Review, Network Review, Secret Review, Quality Review, and Agent Review Sources cover security conditions
  independently of this list.
- The survey covers the cfn-lint **1.46.0** catalogue. A rule added by a newer
  cfn-lint is classified from its level and never as `Security`.
- End-of-life Lambda runtimes and deprecated RDS engine versions are reported,
  but as `BestPractice` rather than `Security`, because the condition depends on
  the current date rather than on the Template.

**Context-dependent findings, and where a finding may not be actionable**

- **`Severity` is comparable only within one `FindingType`.** A `HIGH` security
  finding and a `HIGH` best-practice finding are not two findings of equal
  weight.
- **The deterministic IAM layer reports the shape of a policy, not a per-service
  table of what each AWS service honours.** `cross_service_missing_condition`
  reports a service principal that may call `sts:AssumeRole` with no `Condition`
  bounding it, and recommends `aws:SourceAccount`, `aws:SourceArn` or
  `aws:PrincipalOrgID`. Those keys bind only if the calling service populates
  them, and AWS does not document that for Lambda assuming an execution role:
  adding one there does not harden the role, it stops the function from being
  created. The finding is correct about the policy shape -- which is what
  `Confidence: Confirmed` claims -- while its recommendation is not actionable
  for such a service. This is deliberate Layer 1 conservatism: encoding a
  per-service table would make the detector depend on data that changes outside
  this repository, and silence would hide a real confused-deputy exposure from
  readers for whom it is one. The same asymmetry applies to any service that does
  not support the confused-deputy condition keys
  (`docs/finding-schema.md`, `examples/README.md`).
- **`wildcard_resource` reports the `:log-stream:*` ARN that hand-written Lambda
  logging permissions require.** A log stream name is chosen at invocation time,
  so the ARN has to end in a wildcard. Writing that statement by hand draws a
  `MEDIUM` finding; taking log delivery from the AWS managed policy
  `AWSLambdaBasicExecutionRole` instead keeps the tradeoff in one named place,
  which is what `examples/lambda-with-role` does.
- **Findings merge only within one template.** Equivalence is matched on resource
  logical ID and normalized category, and two templates may reuse one logical ID
  for unrelated resources, so a merge never crosses a template boundary.

**Benchmark**

- **The sample is 12 cases**, 10 with defects and 2 clean, covering the ten
  categories at roughly one case each. That is enough for a regression signal and
  for a claim that a specific detection worked on a specific template. It does
  not license a statement about detection rate on templates this project did not
  write, a per-category rate with meaningful precision -- a category with two
  expectations moves in 50-point steps -- or any conclusion about false positive
  rate, which is measured on two clean templates.
- **`cfn-lint-only` mode measures nothing.** No expectation in any case names
  cfn-lint in `detected_by`, so that mode evaluates an empty expectation set and
  reports `"N/A"` for every rate. This is deliberate: a cfn-lint expectation
  would tie a case's pass/fail to the installed cfn-lint rule catalogue rather
  than to the rule the case exists to measure. cfn-lint's normalization is
  covered by unit and integration tests instead.
- **Agent detection is unmeasured.** Every expectation in the current cases is
  `deterministic`, and the harness never invokes an agent, so no figure in this
  repository describes agent detection.
- **One cfn-guard rule clause is not exercised.** No case or test presents
  cfn-guard with an RDS instance declaring no `BackupRetentionPeriod` at all
  (`docs/benchmark-methodology.md`).
- **The ground-truth commit-ordering check is not implemented.** The rule that
  ground truth is authored before any review is run is enforced by human review
  today; the CI check that a case's `ground_truth.json` appears in the same
  commit as its `template.yaml`, or earlier, is still owed.

## Roadmap

Planned, not implemented, and not available today. Nothing in the sections above
depends on any of it.

**Delivered in v0.8.0.** The security-hardening and measurement items this
section listed at v0.1 have since shipped: input size limits and a YAML
alias-expansion budget (R-8), descriptor-based TOCTOU-safe reads (R-2),
process-group termination on timeout (R-9), and `stderr_head` host-path
redaction (R-4); and, for measurement, the cfn-lint contribution series, N-run
agent variation (`--agent-runs`), the Remediation Accuracy and Human
Intervention Count diagnostics, and the `agent-only` and `human-review` modes.
See CHANGELOG.md and `docs/security-model.md`.

**Additional IaC and analysis**

- Terraform support.
- Pulumi support.
- Runtime security analysis.
- FinOps analysis.
- A full Well-Architected review.
- A web UI.

Automatic deployment and automatic remediation are permanent non-goals rather
than roadmap items: this plugin reports, and does not act.

**Security hardening (remaining)**

- Extending `stderr_head` redaction beyond absolute host paths to process
  identifiers and timestamps a tool may print, which the plugin cannot yet
  recognize reliably (`docs/security-model.md`, R-4).
- The residual risks that remain by design rather than by omission: containment
  is not a child-process sandbox (R-1), `cdk synth` runs unsandboxed (R-5),
  `SIGKILL` can leave a temporary file for the OS sweeper (R-6), and redaction is
  not secret detection (R-7).

**Measurement (remaining)**

- Folding Review Time into a form the summary can carry, or a second output
  stream for it. It is measured on stderr today because a wall-clock figure
  cannot enter the byte-identical summary.
- Populating the reserved `expected_findings_agent_only` and
  `expected_findings_human_review` arrays. The `agent-only` and `human-review`
  modes that read them shipped in v0.8.0, but every bundled case still leaves
  both arrays empty, so the modes measure nothing until cases opt in.
- Authoring cases that declare `expected_remediation` and
  `expected_human_intervention_count`, so the Remediation Accuracy and Human
  Intervention Count diagnostics report a value rather than `N/A`
  (`docs/benchmark-methodology.md`).

**Packaging and experience**

- Verifying the Kiro Power load with a real installation, which is what
  Requirement 10 AC7 still owes.
- MCP enhancement, where a server does something the plugin cannot. MCP stays
  opt-in and never a dependency of the core review flow.
- A better CDK source review experience than `cdk synth` followed by a template
  review.

## Contributing

Contributions are welcome, under Apache-2.0.

`CONTRIBUTING.md` is the place to start. It covers the development environment
and the prerequisite tool versions, the coding standards, the commands that run
the tests and the benchmark, how to add a cfn-guard rule, how to add a Skill, how
to report a security issue, and what a pull request is expected to carry.

Orientation for a contributor:

| Question | Document |
| --- | --- |
| How does a review work, and what is decided by code rather than by an agent? | `docs/architecture.md` |
| What does the plugin defend against, and what does it not? | `docs/security-model.md` |
| What is a Finding, exactly? | `docs/finding-schema.md` |
| What does a benchmark number mean? | `docs/benchmark-methodology.md` and `benchmark/README.md` |
| How do I add a case? | `benchmark/README.md` |
| How does this load as a Kiro Power? | `docs/kiro-power.md` |

Report a security issue privately rather than as a public issue.

## License

Apache License 2.0. `plugin.json` declares `"license": "Apache-2.0"`, and
`LICENSE` at the root carries the full license text.

`NOTICE` records the project copyright and attributes every third-party
component a review run touches: PyYAML, the development and test packages, and
the three external tools invoked as subprocesses. None of them is bundled or
redistributed here, so that section is informational rather than an obligation
this package discharges. Source files carry no license header; Apache-2.0 does
not require one.
