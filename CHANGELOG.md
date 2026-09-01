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

## [0.7.0] - 2026-09-01

### Added

- **SARIF 2.1.0 output** (`iacreview/sarif.py`). A pure, deterministic transform
  from a Review_Report to a SARIF document: same report in, same SARIF out, byte
  for byte. It runs no review, reads no file, and makes no network call. This
  lets a review run surface in GitHub's code-scanning tab and other CI result
  viewers without a consumer learning the plugin's own Finding schema.
- **`iac-review --format {json,sarif}`**. The default stays `json` (the
  normalized report envelope on stdout); `sarif` emits the SARIF document
  instead. No other output path changed.
- **SARIF mapping that loses nothing.** Each distinct `Evidence[].RuleId`
  (falling back to the Source name) becomes one `tool.driver.rules` entry;
  Severity + FindingType map to a SARIF `level` (CRITICAL/HIGH -> `error`,
  MEDIUM -> `warning`, LOW/INFO -> `note`) with a numeric `security-severity`;
  and Confidence, Normalized_Category, and the full merged Source list, which
  have no native SARIF field, travel in each result's `properties` bag.
- **Three benchmark cases** bringing the total to 13 defect cases and 2 clean
  cases: `case-011-unattached-gateway` (Network Review, an Internet Gateway with
  no attachment), `case-012-lambda-plaintext-secret` (Secret Review, a plaintext
  secret in a Lambda environment variable), and `case-013-condition-logic-mismatch`
  (Quality Review, a condition whose logic contradicts its name). Each exercises
  one of the deterministic Sources added in v0.4.0-v0.6.0 against authored
  ground truth.

### Changed

- `benchmark/ground_truth.schema.json` `source` enum already carries every
  deterministic Source; the three new cases author findings against it.

## [0.6.0] - 2026-09-01

### Added

- **Quality Review, a sixth deterministic Source** (`iacreview/quality.py`). It
  reasons about the structure of a template -- Conditions, Parameters, and the
  dependency graph -- to find logic mistakes and dead configuration that no
  single-resource rule and no cfn-lint check reliably reports.
- **Five quality detectors**: `condition_name_logic_mismatch` (a condition
  named for one environment that tests for another), `unused_parameter`,
  `unused_condition`, `circular_dependency` (a cycle in the Ref / GetAtt /
  DependsOn graph), and `allowed_values_mixed_types`.
- Reuses the v0.4.0 resource-graph engine (`iacreview.netgraph`) for reference
  resolution and cycle detection.
- Quality Review is computed in process by `extract_facts.py`, so its findings
  join `deterministic_findings_summary`.

### Changed

- `iacreview.finding.SOURCES` gains `"Quality Review"` (rank 5, before
  `Agent Review`). The Source enum in `docs/finding-schema.md` and
  `benchmark/ground_truth.schema.json` were updated together.
- `iac-review --sources` accepts `Quality Review` and the alias
  `quality-review`.
- Condition logic contradictions and unused parameters/conditions, previously
  reachable only through Agent reasoning (v0.3.0), are now detected
  deterministically.

## [0.5.0] - 2026-09-01

### Added

- **Secret Review, a fifth deterministic Source** (`iacreview/secrets.py`). It
  walks the value-bearing locations where a credential ends up in cleartext --
  Lambda environment variables, EC2 UserData scripts, and Parameter defaults --
  and reports a finding when a value has the shape of a secret. cfn-lint's
  W1011 / W2501 warn about a parameter used as a password; this Source finds the
  value written down directly.
- **Three secret detectors**: `lambda_env_plaintext_secret`,
  `userdata_plaintext_secret`, `parameter_default_secret`. Each recognizes AWS
  access key IDs, provider tokens, PEM private keys, and high-entropy values
  assigned to password/api-key/secret-named fields.
- **Placeholder allowlist**: obvious placeholders (`EXAMPLE`, `changeme`,
  `your-...`) and unresolved references (`!Ref`, `$Ellipsis`, `<...>`) never fire,
  which is what keeps the Source from being trained away.
- Every Secret Review finding carries a redacted excerpt, never the value
  itself (steering/security.md). Findings are `DataProtection` / `Security` /
  HIGH / `Confirmed`.
- Secret Review is computed in process by `extract_facts.py`, so its findings
  join `deterministic_findings_summary`.

### Changed

- `iacreview.finding.SOURCES` gains `"Secret Review"` (rank 4, before
  `Agent Review`). The Source enum in `docs/finding-schema.md` and
  `benchmark/ground_truth.schema.json` were updated together.
- `iac-review --sources` accepts `Secret Review` and the alias `secret-review`.
- Plaintext secrets in Lambda env / UserData, previously reachable only through
  Agent reasoning (v0.3.0), are now detected deterministically.

## [0.4.0] - 2026-09-01

### Added

- **Network Review, a fourth deterministic Source** (`iacreview/netgraph.py`).
  It reasons about relationships between resources -- gateway attachment,
  default routes, reachability, orphaned resources -- which single-resource
  cfn-guard rules cannot express. Every finding is `Confidence: Confirmed`.
- **Resource relationship graph engine**: builds a Ref / Fn::GetAtt / DependsOn
  edge graph from the parsed template (pseudo-parameters excluded), used by the
  network detectors.
- **Four network detectors**: `igw_not_attached` (an Internet Gateway with no
  VPCGatewayAttachment), `route_table_no_default_route` (a route table with no
  0.0.0.0/0 route when an IGW exists), `rds_reachable_from_internet` (a public
  RDS instance behind an internet path), and `orphaned_route_table` (a route
  table nothing associates or references).
- **`vpc_dns_hostnames` cfn-guard rule** (36 bundled rules total): a VPC without
  EnableDnsHostnames.
- Network Review is computed in process by `extract_facts.py`, so its findings
  join `deterministic_findings_summary` and the Agent does not restate them.

### Changed

- `iacreview.finding.SOURCES` gains `"Network Review"` (rank 3, before
  `Agent Review`). The Source enum in `docs/finding-schema.md` and
  `benchmark/ground_truth.schema.json` were updated together.
- `iac-review --sources` accepts `Network Review` and the alias
  `network-review`.
- These issues -- unattached IGW, missing default route -- were previously only
  reachable through Agent reasoning (v0.3.0); they are now detected
  deterministically.

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
[Unreleased]: https://github.com/nobu-13/aws-iac-review-agent-plugin/compare/v0.7.0...HEAD
[0.7.0]: https://github.com/nobu-13/aws-iac-review-agent-plugin/releases/tag/v0.7.0
[0.6.0]: https://github.com/nobu-13/aws-iac-review-agent-plugin/releases/tag/v0.6.0
[0.5.0]: https://github.com/nobu-13/aws-iac-review-agent-plugin/releases/tag/v0.5.0
[0.4.0]: https://github.com/nobu-13/aws-iac-review-agent-plugin/releases/tag/v0.4.0
[0.3.0]: https://github.com/nobu-13/aws-iac-review-agent-plugin/releases/tag/v0.3.0
[0.2.0]: https://github.com/nobu-13/aws-iac-review-agent-plugin/releases/tag/v0.2.0
[0.1.0]: https://github.com/nobu-13/aws-iac-review-agent-plugin/releases/tag/v0.1.0
