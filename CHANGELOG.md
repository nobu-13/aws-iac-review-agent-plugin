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

### Added

- Phase 1 bounded remediation verifier (experimental, unreleased):
  `python3 -m iacreview.remediation init | verify | explain`. It checks one
  candidate fix to a CloudFormation Template against a remediation contract
  read from a trusted git revision, and writes a new
  Remediation_Verification_Report (schema 0.1.0) with decisions VERIFIED /
  BLOCKED / UNVERIFIED / ERROR and exit codes 0 / 20 / 21 / 22 of its own.
  Two profiles: `dynamodb-billing-mode-v1`, `iam-inline-policy-overbroad-v1`.
  It edits no file, calls no AWS API and never merges. See `docs/v2/phase1/`.
- Skill `iac-remediation-verify`, which drives that CLI. The five existing
  Skills, their scripts and outputs are unchanged.

### Fixed

- A directory target holding a symlink cycle no longer stops the review with
  exit 1 and a Python traceback on CPython 3.9-3.12; the cycle entry is skipped
  on every Python version, as 3.13 already did.

## [1.1.0] - 2026-10-26

Adds the Delta_Tool, a read-only, deterministic comparison of two
CloudFormation Templates and/or two Review_Reports, as a module entry point
rather than a Skill, and makes two v1.0 failure modes the same on every Python
version. The existing Skills, the 13-field Finding, the Review_Report and its
`schema_version` `1.0.0`, the exit code table and the run-time dependencies are
unchanged; the one observable change to a v1.0 review is that a JSON Template
nested deeper than 512 levels is now a parse failure on every version.

### Added

- **The Delta_Tool (v1.1): `python3 -m iacreview.deltacli`.** A read-only
  comparison of a Base and a Head CloudFormation Template (the Semantic Diff:
  added, removed and modified positions with qualifiers, limitations and
  uncompared paths) and/or a Base and a Head Review_Report (the Finding Delta:
  each Finding matched in two deterministic stages and classified `New`,
  `Resolved`, `Unchanged`, `Unconfirmed` or `Ambiguous`). Assumptions the tool
  cannot check are given with `--declare` and recorded as
  `declared_not_verified`; without them a one-sided Finding is `Unconfirmed`,
  and a failed comparability, integrity or correspondence condition makes it
  `Ambiguous` whatever was declared. Output is one Delta_Report JSON document
  with its own `delta_schema_version` `1.0.0`, anonymized by default
  (`--plain-identifiers` writes identifiers; Template values and Finding text are
  never written), byte-identical for identical inputs, and fail-closed at the
  input limits (5 MiB per Template or Report, 10000 Findings, depth 64, 3000000
  logical nodes, 200000 Change_Entries, 128 MiB of output). The schema, closed
  sets, failure Codes and known limitations are documented in
  `docs/delta-schema.md`. It is a module entry point, not a Skill: the existing
  Skills, the 13-field Finding, the Review_Report and its `schema_version`
  `1.0.0`, the exit code table and the run-time dependencies are unchanged.
  Markdown output and Git ref inputs are not part of it.
- **Delta_Tool: `--reviewed-template-path PATH` for both pairs in one run.**
  With a Template_Pair and a Report_Pair, it declares the workspace-relative
  path at which both Reports reviewed the Template, so that the Template /
  Report correspondence check can pass and `New` / `Resolved` can appear. The
  declaration is recorded as `finding_delta.reviewed_template_path` with the
  status `declared_not_verified` (`null` without it); the file is not read and
  nothing about it is verified. Report integrity, Comparable, the required
  declarations, rename hints and the limits are unchanged. A refused value
  exits 2 before any input is read.
- **Delta_Tool output safety.** C1 control characters and the bidirectional
  controls are written as `\uXXXX` escapes in the JSON (the decoded values are
  unchanged). An integer of a Finding `TemplatePath` is written as a list index
  only when the Finding is in the compared Template path and the index lies
  inside a list; otherwise it is a Token, so a digit-only key is not written in
  plain form by default.
- **Delta_Tool memory at the output limit.** The 128 MiB output limit is
  checked against a lower bound of the output size before rendering and while
  serializing, so the full text of an oversized output is never built. Output
  bytes, the schema and the failure Codes are unchanged.
- **Privacy Policy and Support documentation.** `docs/privacy-policy.md` states
  how the plugin handles data: no telemetry, no network call of its own,
  nothing stored in the workspace, AWS credentials withheld from every child
  process, and the host-agent and optional-MCP boundaries where data may leave
  the plugin's control. `README.md` and `README.ja.md` gain Support and Privacy
  Policy sections. Documentation only; no behaviour changed.

### Fixed

- **JSON nesting depth is bounded explicitly, the same on every Python
  version.** A JSON Template nested deeper than 512 arrays and objects
  (`iacreview.template.MAX_JSON_NESTING_DEPTH`) is refused before it is decoded,
  as a `parse_failure` (exit 4) with `error_type` `RecursionError` at line 1,
  column 1 and a fixed message. Before, the outcome depended on the
  interpreter's recursion limit: Python 3.9 failed near 990 levels (fewer with
  a deeper call stack), while Python 3.13 decoded about 10,000 levels and
  reviewed the document. Observable change: a valid JSON document nested 513 to
  about 990 levels, which Python 3.9 used to review, is now a parse failure on
  every version. The deepest Template in this repository nests 12 levels, and
  no YAML Template can exceed PyYAML's own limit (about 330). A document past
  the limit that also has a syntax error is reported as the depth failure.
  Pinned by `tests/unit/test_template.py` and
  `tests/regression/test_sec_malformed_json.py`.
- **A symlink cycle is `invalid_arguments` (exit 2) on Python 3.13 too.**
  CPython 3.13's `Path.resolve` no longer detects cycles, so a candidate path
  that is a cycle, or that traverses one, was reported as `input_not_found`
  (exit 3). The path check now detects the cycle itself when the OS reports
  `ELOOP`, without recursion, and reports it with the class and message Python
  3.9.0-3.9.22 gives (3.9.23 and later, like 3.10-3.12, name the whole
  unresolved path in the message; the class and exit code are the same). A long chain of links that is not a cycle still resolves as
  before, and every other symlink shape keeps its outcome. Pinned by
  `tests/regression/test_sec_symlink_loop.py` and `tests/unit/test_pathguard.py`.

## [1.0.0] - 2026-09-01

A maturation release. No new Source, no new deterministic check, and no new
dependency: it makes the CDK review outcome legible in the report, turns the
owed Kiro Power verification into a repeatable procedure with a place to record
its result, and pins MCP as a documented opt-in the plugin does not implement.
The determinism contract, the read-only default, and the unsandboxed-`cdk synth`
posture are unchanged.

### Added

- **`target.cdk.synthesis` in the report.** A closed-set field --
  `not_applicable`, `skipped_unconfirmed`, or `ran` -- that tells a consumer
  whether the target was a CDK project, whether synthesis was skipped for want
  of `--confirm-cdk-synth`, or whether it ran. An empty finding set from a
  skipped synthesis is no longer indistinguishable from a clean review
  (Requirement 23). The value is a deterministic function of the target layout
  and the confirmation flag, so the byte-identical stdout guarantee holds.
- **A Kiro Power verification procedure and result record** in
  `docs/kiro-power.md`: an ordered procedure for loading the package as a Power
  and observing all five Skills, and a table to record the Kiro version, which
  Skills were observed, and whether anything had to be added (Requirement 24).
  The in-Kiro load remains recorded as unverified until a human performs it.

### Changed

- **`docs/mcp/README.md` states MCP is not implemented in v1.0.0** and that a
  concrete server waits on a stated, checkable use case rather than being added
  for convenience (Requirement 25). MCP stays opt-in and no core capability
  depends on it; no `mcp.json` ships in the plugin root.

### Fixed

- **Three Skills were dropped by a real Kiro Power load** because their
  `SKILL.md` `description` exceeded the Agent Skills 1.0.0 1024-character cap;
  `cloudformation-review`, `iac-review` and `iam-review` did not reach the host
  agent, while `cfn-lint-review` and `cfn-guard-review` did. The three
  descriptions are shortened to stay under the cap with their capability and
  selection guidance intact, and `tests/unit/test_skills.py` now measures the
  folded length of every `description` and fails over the cap, so a skill can no
  longer be lost to an over-long description without a red test. Both loads --
  the first that dropped three Skills and the re-check after the fix -- are
  recorded in `docs/kiro-power.md`. After the fix the load is **verified on Kiro
  1.0.337**: all five Skills reached the host agent, an `iac-review` entry point
  ran and produced a Review_Report, and nothing had to be added to the package
  (Requirement 10 AC7).

## [0.9.0] - 2026-09-01

Closes the residual edges of v0.8.0: a wider deterministic `stderr_head`, Review
Time as structured data, the residual security risks settled as positions, and
benchmark cases that exercise the modes and diagnostics that shipped empty. The
byte-identical stdout contract and read-only default are unchanged, and no
Finding-schema or Ground_Truth-schema version is bumped for a breaking reason.

### Added

- **`run_benchmark.py --timing-report`.** Emits Review Time as a structured
  (JSON) diagnostic on stderr, per case and in aggregate, on a channel separate
  from the summary. It never appears on stdout, so the summary stays
  byte-identical, and it never affects PASS or FAIL (Requirement 21).
- **Ground_Truth `expected_remediation` and `expected_human_intervention_count`.**
  Two optional fields (a per-finding string and a top-level integer) that make
  the Remediation Accuracy and Human Intervention Count diagnostics report a
  value instead of "not applicable". Both are optional, so the Ground_Truth
  `schema_version` is unchanged, and every v0.1-v0.8 case is unaffected
  (Requirement 22 AC4, AC5).
- **Two benchmark measurement cases** (`case-201-agent-only-oversized-policy`,
  `case-202-human-review-naming-convention`) and an agent-finding fixture under
  `benchmark/agent-findings/`. They populate the reserved
  `expected_findings_agent_only` and `expected_findings_human_review` arrays so
  the `agent-only` and `human-review` modes measure a declared expectation
  rather than nothing; both carry empty `expected_findings`, so the deterministic
  pass/fail contract is unchanged (Requirement 22 AC2, AC3, AC6).

### Changed

- **`stderr_head` redaction widened** to labeled process identifiers
  (`pid 1234` -> `pid <pid>`) and recognized ISO-8601 / RFC-3339 timestamps
  (-> `<timestamp>`), in addition to absolute host paths. The reach is
  deliberately narrow: a bare integer, a rule id, a line number, a byte count,
  and a version number are preserved, so the diagnostic value survives
  (Requirement 20). The host-path redaction primitive is unchanged; the new
  composition lives in `iacreview.errors.redact_stderr_line`.
- **Residual risks R-1, R-5, R-6, R-7 are now stated as deliberate positions**
  in `docs/security-model.md` -- boundaries the plugin does not cross, each with
  its reason -- rather than roadmap candidates awaiting a fix (Requirement 22
  AC1).

## [0.8.0] - 2026-09-01

Robustness against untrusted input, a deterministic stderr excerpt, and an
expanded benchmark. Read-only by default is unchanged, and the deterministic
core's byte-identical output contract still holds.

### Added

- **Input size limits.** A single Template larger than
  `iacreview.template.MAX_TEMPLATE_BYTES` (5 MiB) is refused without being read,
  and a directory target whose Templates exceed `MAX_AGGREGATE_BYTES` (50 MiB in
  the `iac-review` orchestrator) stops the walk at the file that would exceed the
  limit. Both fail through the structured-error mechanism and name no absolute
  host path (Requirement 17 AC1, AC2, AC9).
- **YAML alias-expansion bound.** `iacreview.yamlcfn.MAX_ALIAS_EXPANSIONS`
  (10000) caps alias expansion so a "billion laughs" style payload fails as a
  parse failure with a position rather than exhausting memory (Requirement 17
  AC3).
- **Benchmark diagnostics.** The benchmark summary now carries a `diagnostics`
  block, per case and in aggregate: Remediation Accuracy and Human Intervention
  Count, computed from ground-truth expectations and recorded as `N/A` when a
  case declares none (Requirement 19 AC3, AC6). They never affect PASS or FAIL.
- **Benchmark modes `agent-only` and `human-review`.** They read the reserved
  `expected_findings_agent_only` and `expected_findings_human_review` ground-truth
  arrays without a schema-version bump; `human-review` is informational and never
  thresholded (Requirement 19 AC1).
- **`run_benchmark.py --agent-runs N`.** Repeats the Agent Source N times and
  reports its variation across runs as a stderr diagnostic; the deterministic
  Sources are still evaluated exactly once (Requirement 19 AC4).
- **cfn-lint contribution series** (`benchmark/cfn-lint-contribution/`). A
  measurement series, separate from the ground-truth cases, that records how many
  findings cfn-lint contributes pinned to a stated cfn-lint version. It is
  reported informationally and never thresholded, so the ground-truth pass/fail
  contract does not depend on the installed cfn-lint rule catalogue
  (Requirement 19 AC5).

### Changed

- **TOCTOU-safe Template reads.** A Template is opened once with `O_NOFOLLOW`,
  and its `(st_dev, st_ino)` are checked against the resolved path on that one
  descriptor, so a symlink or path substituted between the containment check and
  the read cannot cause a file outside the workspace to be read (Requirement 17
  AC5). A non-regular file (FIFO, device, directory) is refused (AC6).
- **Process-group termination on timeout.** An external tool is started as a
  session leader, and a timeout signals the whole process group, so no descendant
  of a timed-out tool survives the review (Requirement 17 AC7).
- **Review Time** is measured and reported on stderr as a diagnostic rather than
  omitted; it stays out of the byte-identical summary (Requirement 19 AC2). Of
  the three metrics deferred in v0.1, it is the only one still deferred from the
  summary.

### Fixed

- **`stderr_head` is deterministic.** An absolute host path in an external tool's
  stderr is redacted to a fixed `<path>` placeholder before it reaches the
  report, reconciling the first-5-stderr-lines requirement with the
  no-absolute-host-path, byte-identical output requirement (Requirement 18
  AC2, AC3).

### Security

- **`input_too_large` error class.** Added to the closed `ERROR_CLASSES` set so a
  read refused for size is distinguishable from a missing file. Refusing an
  oversized file, bounding alias expansion, reaping process groups, and redacting
  host paths from `stderr_head` close residual risks recorded in
  `docs/security-model.md` (R-8, R-2, R-9, R-4), each pinned by a regression test.

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
[Unreleased]: https://github.com/nobu-13/aws-iac-review-agent-plugin/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/nobu-13/aws-iac-review-agent-plugin/releases/tag/v1.1.0
[1.0.0]: https://github.com/nobu-13/aws-iac-review-agent-plugin/releases/tag/v1.0.0
[0.9.0]: https://github.com/nobu-13/aws-iac-review-agent-plugin/releases/tag/v0.9.0
[0.8.0]: https://github.com/nobu-13/aws-iac-review-agent-plugin/releases/tag/v0.8.0
[0.7.0]: https://github.com/nobu-13/aws-iac-review-agent-plugin/releases/tag/v0.7.0
[0.6.0]: https://github.com/nobu-13/aws-iac-review-agent-plugin/releases/tag/v0.6.0
[0.5.0]: https://github.com/nobu-13/aws-iac-review-agent-plugin/releases/tag/v0.5.0
[0.4.0]: https://github.com/nobu-13/aws-iac-review-agent-plugin/releases/tag/v0.4.0
[0.3.0]: https://github.com/nobu-13/aws-iac-review-agent-plugin/releases/tag/v0.3.0
[0.2.0]: https://github.com/nobu-13/aws-iac-review-agent-plugin/releases/tag/v0.2.0
[0.1.0]: https://github.com/nobu-13/aws-iac-review-agent-plugin/releases/tag/v0.1.0
