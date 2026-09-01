# Changelog

All notable changes to `aws-iac-review-agent-plugin` are recorded in this file.

The format follows [Keep a Changelog][keep-a-changelog], and this project follows
[Semantic Versioning][semver]. The version a release entry names is the `version`
field of `plugin.json`. The manifest is the plugin's public interface, so it is
the single place the version is declared and this file quotes it; the two are
checked against each other by `tests/unit/test_root_docs.py`.

## What is recorded here

This file records changes that a user of the plugin can observe. Five kinds of
change are always recorded, because each one can break a caller that was working
before:

- **Breaking changes.** Any change to the command-line interface of a Skill
  script, to the exit code table, or to the shape of the report on stdout.
- **Finding schema changes.** The report envelope and the Finding are versioned
  together as `schema_version` (`iacreview.report.SCHEMA_VERSION`). A change to a
  field, or to one of the five closed value sets, is recorded here, and a
  breaking one bumps MAJOR. The normalized category vocabulary belongs to this
  group: `iacreview/category_map.json` carries its own `schema_version`, and
  because every Finding names a category from its closed `categories` set, adding
  a category, removing one, or moving a rule from one to another changes what a
  caller reads out of a report. Changes to that file are recorded here with its
  new `schema_version`.
- **Skill changes.** A Skill added, removed or renamed, and any change to the
  arguments, the output or the documented limitations of one.
- **Dependency changes.** A change to the run-time Python dependencies, or to the
  minimum supported version of Python, cfn-lint, cfn-guard or the AWS CDK CLI.
  Development and test dependencies are not recorded here.
- **Security fixes.** What the defect allowed, and which regression test now pins
  it. Details that would help exploit an unpatched installation are left out.

Every release heading links to the tag of that release. A release tag is the
version with a `v` prefix, so `0.1.0` is tagged `v0.1.0`.

Each release entry groups its changes under the six Keep a Changelog change
types, and under those six only: `Added`, `Changed`, `Deprecated`, `Removed`,
`Fixed` and `Security`. A change type with nothing under it is omitted rather
than kept as an empty heading, which is why the first release below carries
`Added` alone.

## [Unreleased]

Nothing yet.

## [0.3.0] - 2026-09-01

### Added

- **Agent review prompt builder** (`iacreview/agentprompt.py`): turns a
  template's deterministic facts into a structured review prompt. It calls no
  model and makes no network request; the prompt is a deterministic function of
  the facts.
- **`build_prompt.py`** entry point in the `cloudformation-review` Skill. It
  accepts either `--target` (extract facts in process) or `--facts` (read a
  facts file produced by `extract_facts.py`) and emits one JSON object with the
  prompt, a design-level checklist, and a schema version.
- **Design-level checklist**: the prompt builder surfaces leads no deterministic
  rule expresses -- an Internet Gateway with no attachment, a missing default
  route, a stateful resource that may sit in a single Availability Zone, an
  unused parameter, and a condition whose logic may not match its name.
- **MCP Agent-review documentation**: `docs/mcp/README.md` now describes the
  optional path where an MCP server sends the built prompt to a model. The
  plugin still opens no connection itself.

### Changed

- `iacreview/__init__.py` version aligned to the manifest (was left at 0.1.0).
- `skills/cloudformation-review/SKILL.md` documents the new `build_prompt.py`
  input path.
- MCP remains optional and is never a required dependency: the two model-free
  steps (extracting facts and building the prompt) stay reproducible whether or
  not a model is ever called.


## [0.2.0] - 2026-08-28

### Added

- **14 new cfn-guard rules** across four categories, bringing the total from 21
  to 35. New rules cover encryption (Kinesis, Redshift, ElastiCache, EFS, SQS,
  DynamoDB), logging (ALB access logs, VPC Flow Logs), public access (ALB HTTPS
  enforcement, CloudFront HTTPS), and availability (DynamoDB PITR, Secrets
  Manager rotation, Lambda DLQ, Lambda timeout, ASG Multi-AZ, EC2 EBS
  optimization).
- **4 IAM detector placeholders** registered in the detector table:
  `iam_user_inline_policy`, `access_key_in_template`,
  `iam_admin_policy_attached`, `overly_permissive_trust`. These are structural
  preparation for v0.3.0; they do not produce findings yet.
- Extended `required_tags` to cover `AWS::EC2::VPC` and `AWS::EC2::Subnet`.
- `rds_deletion_protection` re-categorized from Backup to Availability to avoid
  deduplication collision with `rds_backup_retention`.
- `s3_versioning_enabled` re-categorized from Backup to DataProtection for the
  same reason.
- `ec2_imdsv2_required` rule categorized as DataProtection (Security finding
  type).

### Changed

- Benchmark now covers 9 categories (added Availability and DataProtection to
  the exercised set).
- Total bundled rules: 21 -> 35.
- Ground truth updated for benchmark cases affected by new rules.
- `examples/lambda-with-role/template.yaml` now includes a `DeadLetterConfig`
  and `KmsKeyId` on its log group to satisfy the new rules.
- `tests/fixtures/valid/minimal_compliant_template.yaml` updated with
  `DeletionPolicy`, `VersioningConfiguration` to remain compliant.

## [0.1.0] - 2026-08-27

The first release. It is read-only by default: it reads templates, runs external
analysis tools, and writes one JSON report to stdout. It creates, changes and
deletes nothing in AWS, and applies no fix on its own.

### Added

- **Agent Plugins 1.0.0 manifest.** `plugin.json` declares the plugin name,
  version, description, license and keywords. No `mcp.json` ships in v0.1; MCP is
  documented under `docs/mcp/` as an optional integration rather than a
  dependency.
- **Five Skills, one concern each.** `cfn-lint-review` and `cfn-guard-review` wrap
  the two external analysers, `iam-review` runs the plugin's own IAM detectors and
  extracts policies for an agent to reason over, `cloudformation-review` extracts
  template facts for the same purpose, and `iac-review` runs the deterministic
  sources together and merges agent-produced findings into one report.
- **Deterministic core (`iacreview/`).** Template discovery and parsing for
  CloudFormation YAML and JSON, including the short-form intrinsic tags plain
  YAML rejects; adapters that turn cfn-lint and cfn-guard output into Findings;
  IAM detectors; normalization, deduplication and a stable ordering; the report
  envelope; the exit code table; workspace path containment; and PATH resolution
  with a minimum-version check for each external tool.
- **A single normalized Finding shape.** Every Finding, from every source, carries
  the same 13 fields with the same five closed value sets, so findings from
  different sources are comparable and can be deduplicated. The report envelope
  emits `schema_version` `1.0.0`, and `iacreview/category_map.json` declares
  `schema_version` `1.0.0` for the 11-value normalized category vocabulary and
  the rule-to-category mappings. `docs/finding-schema.md` is the reference.
- **11 cfn-guard rules across six categories.** `rules/` ships `encryption/`,
  `iam/`, `logging/`, `public-access/`, `backup/` and `tagging/`, each with a
  `_meta.json` that records one entry per `.guard` file. A caller can add its own
  rule directory on top of the bundled ones with `--rules-dir`.
- **Benchmark harness with 12 cases.** `benchmark/harness/` scores a review
  against ground truth authored ahead of any review output, and
  `benchmark/cases/` holds 10 cases with deliberate defects and 2 clean cases
  that a review should leave alone. `benchmark/ground_truth.schema.json` fixes the
  ground-truth shape and `docs/benchmark-methodology.md` describes the method.
- **Opt-in CDK synthesis.** A CDK project is only synthesized when
  `--confirm-cdk-synth` is passed. Without it the plugin reports what it would
  run and stops, because `cdk synth` executes project code and this release does
  not sandbox it. Already-synthesized templates need no flag.
- **Examples and documentation.** `examples/` holds small working templates and a
  walkthrough of the synthesized-output path. `docs/` holds the architecture,
  the security model, the benchmark methodology, the Finding schema reference,
  the Kiro Power notes and the optional MCP configuration. `README.md`,
  `CONTRIBUTING.md`, `LICENSE` and `NOTICE` are at the root.
- **Test suite.** Unit, integration, negative, property-based and regression
  tests, run with `python3 -m pytest`. Neither cfn-lint nor cfn-guard has to be
  installed to run it: stub executables under `tests/fakebin/` drive the adapters
  through their success, crash, timeout, too-old and missing paths, and the tests
  that call a real tool are skipped when it is absent.

[keep-a-changelog]: https://keepachangelog.com/en/1.1.0/
[semver]: https://semver.org/spec/v2.0.0/
[Unreleased]: https://github.com/nobu-13/aws-iac-review-agent-plugin/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/nobu-13/aws-iac-review-agent-plugin/releases/tag/v0.3.0
[0.2.0]: https://github.com/nobu-13/aws-iac-review-agent-plugin/releases/tag/v0.2.0
[0.1.0]: https://github.com/nobu-13/aws-iac-review-agent-plugin/releases/tag/v0.1.0
