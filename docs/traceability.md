# Requirements Traceability

This document maps every acceptance criterion of the 16 requirements onto the
place where it is realized: a test file that verifies it, or, where the criterion
is an obligation on the documentation itself, the document that carries it.

It exists so that "is this requirement covered?" is a question with a mechanical
answer. `tests/unit/test_traceability.py` parses the tables below and fails if a
requirement disappears, if the number of criteria under a requirement stops
matching the requirements document, if a referenced path is not on disk, or if
any criterion is left without a realization. The same module checks that each of
the 31 correctness properties is implemented exactly once under
`tests/property/`.

## How to read a row

| Column | Meaning |
| --- | --- |
| AC | The acceptance criterion number, in the order the requirements document lists them |
| Criterion | A short restatement. The requirements document is authoritative; this column is a label, not a substitute |
| Verified by | Repository-relative paths. A test file means the criterion is asserted there. A document means the criterion is an obligation on that document, and the note says so |
| Notes | The correctness property that generalizes the criterion, a conflict, or a gap |

A criterion whose only realization is a document is not a weaker row than a
tested one when the criterion is itself about documentation: Requirement 13 AC9
asks for four references to exist, and the way to satisfy that is to write them.
A criterion that is only *partly* realized is marked PARTIAL and says what is
missing; one whose wording disagrees with something else is marked CONFLICT; one
with no mechanical check at all is marked GAP. Five rows carry such a marker: two
PARTIAL, two CONFLICT, and one GAP. All five are discussed under
"Gaps and conflicts" at the end.

Per-criterion counts, which `tests/unit/test_traceability.py` enforces:

| Requirement | Criteria | Requirement | Criteria |
| --- | --- | --- | --- |
| 1 | 11 | 9 | 8 |
| 2 | 16 | 10 | 9 |
| 3 | 6 | 11 | 16 |
| 4 | 13 | 12 | 12 |
| 5 | 8 | 13 | 11 |
| 6 | 13 | 14 | 13 |
| 7 | 17 | 15 | 7 |
| 8 | 11 | 16 | 11 |

182 criteria in total.

## Requirement 1: Plugin package structure

| AC | Criterion | Verified by | Notes |
| --- | --- | --- | --- |
| AC1 | `plugin.json` at the package root | `tests/unit/test_manifest.py` | - |
| AC2 | `skills/` holds at least one Skill with a valid `SKILL.md` | `tests/unit/test_skills.py`, `tests/unit/test_scaffold.py` | The Skill set is asserted exactly, not merely as non-empty |
| AC3 | Package files stay inside the plugin root; no symlink or outward relative path | `tests/unit/test_pathguard.py`, `tests/property/test_prop_pathguard.py`, `tests/unit/test_docs.py` | Property 18. The symlink half is `test_docs.py::test_package_contains_no_symlink` |
| AC4 | A Skill with no `SKILL.md`, or no top-level heading, is skipped without disabling its siblings | `tests/unit/test_skills.py` | - |
| AC5 | Manifest declares the seven fields; `name` matches the pattern, at most 128 characters | `tests/unit/test_manifest.py` | CONFLICT with the Agent Plugins 1.0.0 schema. See "Gaps and conflicts" |
| AC6 | `version` is semantic versioning | `tests/unit/test_manifest.py` | - |
| AC7 | No `mcp.json` in the v0.1 package | `tests/unit/test_manifest.py` | - |
| AC8 | An optional MCP example under `docs/`, with purpose, permissions, network scope, credentials, data sent, and failure behaviour | `tests/unit/test_docs.py` | Realized by `docs/mcp/README.md` and `docs/mcp/mcp.json.example`; the nine-item record is asserted section by section |
| AC9 | A user-added `mcp.json` declares an explicit transport type | `tests/unit/test_docs.py` | Asserted against the shipped example, which is the only configuration this repository controls |
| AC10 | Core review stays operational with no `mcp.json` | `tests/unit/test_docs.py`, `tests/integration/test_pipeline_end_to_end.py` | The capability table states it, and the whole suite runs in a checkout that has no `mcp.json` |
| AC11 | A missing or malformed manifest fails to load with a reported error | `tests/unit/test_manifest.py` | - |

## Requirement 2: Skill composition

| AC | Criterion | Verified by | Notes |
| --- | --- | --- | --- |
| AC1 | A `cloudformation-review` Skill | `tests/unit/test_skills.py` | - |
| AC2 | A `cfn-lint-review` Skill emitting the common Finding format | `tests/unit/test_skills.py`, `tests/integration/test_skill_cfn_lint.py` | - |
| AC3 | A `cfn-guard-review` Skill emitting the common Finding format | `tests/unit/test_skills.py`, `tests/integration/test_skill_cfn_guard.py` | - |
| AC4 | An `iam-review` Skill | `tests/unit/test_skills.py`, `tests/integration/test_skill_iam.py` | - |
| AC5 | An `iac-review` Skill that orchestrates and aggregates | `tests/unit/test_skills.py`, `tests/integration/test_skill_iac_review.py` | - |
| AC6 | `cfn-lint-review` works standalone | `tests/integration/test_skill_cfn_lint.py` | - |
| AC7 | `cfn-guard-review` works standalone | `tests/integration/test_skill_cfn_guard.py` | - |
| AC8 | `iam-review` works standalone | `tests/integration/test_skill_iam.py` | - |
| AC9 | `cloudformation-review` works standalone | `tests/integration/test_skill_cfn_review.py` | - |
| AC10 | A failed sub-skill becomes one error entry; the rest continue | `tests/property/test_prop_orchestration.py`, `tests/integration/test_skill_iac_review.py` | Property 24 |
| AC11 | Front matter declares `name` and a `description` covering capability and selection | `tests/unit/test_skills.py` | - |
| AC12 | Front matter `name` equals the containing directory name | `tests/unit/test_skills.py` | - |
| AC13 | The six required sections are present | `tests/unit/test_skills.py` | - |
| AC14 | `cloudformation-review` stays on relationships, architecture, context, and best practice | `tests/integration/test_skill_cfn_review.py`, `tests/unit/test_iam_source.py` | - |
| AC15 | A check a tool performs reliably is delegated to the tool | `tests/integration/test_skill_cfn_review.py`, `tests/integration/test_skill_iam.py` | - |
| AC16 | Each normalization and parsing routine lives in exactly one shared location | `tests/unit/test_scaffold.py`, `tests/unit/test_bootstrap.py` | The shared package is imported by every entry point rather than duplicated; the bootstrap assertions are what make that structural |

## Requirement 3: CloudFormation template review

| AC | Criterion | Verified by | Notes |
| --- | --- | --- | --- |
| AC1 | A parsed file with a non-empty top-level `Resources` is a reviewable Template | `tests/unit/test_template.py`, `tests/property/test_prop_template.py` | Property 16 |
| AC2 | Resource configuration is evaluated against best practices, each Finding carrying Severity, FindingType, category, and logical ID | `tests/unit/test_guard_rules.py`, `tests/integration/test_pipeline_end_to_end.py` | - |
| AC3 | Security issues are detected across the seven named categories | `tests/unit/test_guard_rules.py`, `tests/integration/test_benchmark_cases.py` | The bundled rules cover the categories; the benchmark cases exercise them |
| AC4 | Both YAML and JSON are accepted | `tests/unit/test_template.py`, `tests/property/test_prop_template.py` | Property 15 |
| AC5 | A parsed file with no `Resources` is reported as not reviewable, with its path | `tests/unit/test_template.py`, `tests/integration/test_malformed_input.py` | - |
| AC6 | An unparseable file is reported with error type, line, and column | `tests/unit/test_template.py`, `tests/regression/test_sec_malformed_yaml.py` | Property 17 |

## Requirement 4: cfn-lint integration

| AC | Criterion | Verified by | Notes |
| --- | --- | --- | --- |
| AC1 | cfn-lint is executed with `-f json` | `tests/integration/test_skill_cfn_lint.py`, `tests/unit/test_cfnlint_parse.py` | - |
| AC2 | Each result is parsed into a Finding with the nine named fields | `tests/unit/test_cfnlint_parse.py` | The exhaustive field-mapping test Requirement 12 AC9 also asks for |
| AC3 | An Error-level result is `Validity` | `tests/unit/test_categories.py` | - |
| AC4 | An Error-level result maps to HIGH | `tests/unit/test_categories.py` | - |
| AC5 | A deployment-blocking rule ID maps to CRITICAL | `tests/unit/test_categories.py`, `tests/unit/test_cfnlint_parse.py` | Property 8 |
| AC6 | A Warning is `BestPractice` and MEDIUM | `tests/unit/test_categories.py` | - |
| AC7 | An Informational result is `Informational` and LOW | `tests/unit/test_categories.py` | - |
| AC8 | Informational rules are enabled on the command line | `tests/unit/test_cfnlint_parse.py` | Without this the AC7 mapping is unreachable |
| AC9 | A security-relevant rule ID becomes `Security` instead of `Validity` | `tests/unit/test_categories.py`, `tests/property/test_prop_categories.py` | Property 9 |
| AC10 | cfn-lint unavailable reports the tool and `pip install cfn-lint` | `tests/unit/test_toolcheck.py`, `tests/integration/test_tool_unavailable.py` | - |
| AC11 | An exit code whose set bits are a subset of {2, 4, 8} is a successful run | `tests/unit/test_cfnlint_exit.py`, `tests/property/test_prop_cfnlint.py` | Property 10 |
| AC12 | Any other bit is a failure, reported with stderr, without stopping the pipeline | `tests/unit/test_cfnlint_exit.py`, `tests/integration/test_fakebin_drives_sources.py` | - |
| AC13 | Zero violations returns an empty list attributed to `cfn-lint` | `tests/unit/test_cfnlint_parse.py`, `tests/integration/test_skill_cfn_lint.py` | - |

## Requirement 5: cfn-guard integration

| AC | Criterion | Verified by | Notes |
| --- | --- | --- | --- |
| AC1 | cfn-guard runs with the bundled rules, within 60 seconds per Template | `tests/unit/test_cfnguard_normalize.py`, `tests/integration/test_skill_cfn_guard.py` | - |
| AC2 | At least one rule per each of the six categories | `tests/unit/test_guard_rules.py` | - |
| AC3 | A violation becomes a Finding carrying type, severity, category, rule name, logical ID, and remediation | `tests/unit/test_guard_rules.py`, `tests/unit/test_cfnguard_normalize.py` | Remediation comes from the rule's custom message, asserted per rule file |
| AC4 | A clean run reports that all rules passed, with the count evaluated | `tests/unit/test_cfnguard_parse.py`, `tests/integration/test_skill_cfn_guard.py` | - |
| AC5 | cfn-guard unavailable reports the tool and its installation documentation | `tests/unit/test_toolcheck.py`, `tests/integration/test_tool_unavailable.py` | - |
| AC6 | A non-violation failure is reported with stderr, and the pipeline continues | `tests/unit/test_cfnguard_parse.py`, `tests/integration/test_fakebin_drives_sources.py` | - |
| AC7 | Violation versus failure is decided by whether stdout parses, never by the exit code value | `tests/unit/test_cfnguard_parse.py` | The five measured exit codes are recorded in `docs/architecture.md` |
| AC8 | Rules live in per-category directories and are additive | `tests/unit/test_guard_rules.py` | - |

## Requirement 6: IAM security review

| AC | Criterion | Verified by | Notes |
| --- | --- | --- | --- |
| AC1 | `Action: "*"` with `Resource: "*"` is CRITICAL `Security` | `tests/unit/test_iam_detectors.py`, `tests/property/test_prop_iam.py` | Property 28 |
| AC2 | Sensitive action prefixes with no Condition are reported | `tests/unit/test_iam_detectors.py`, `tests/unit/test_iam_source.py` | - |
| AC3 | `iam:PassRole` and `sts:AssumeRole` usage is analyzed, unrestricted Resource included | `tests/unit/test_iam_detectors.py` | Two detectors, each with a positive and a negative case |
| AC4 | Wildcards in Action or Resource are detected | `tests/unit/test_iam_detectors.py` | - |
| AC5 | The named privilege escalation patterns are identified | `tests/unit/test_iam_detectors.py` | Three detectors: policy mutation, Lambda plus PassRole, broad trust |
| AC6 | Cross-service and cross-account Allow statements are checked for the three conditions | `tests/unit/test_iam_detectors.py` | - |
| AC7 | A literal 12-digit account ID in a Principal, bare or inside an ARN, is cross-account | `tests/unit/test_iam_intrinsics.py`, `tests/unit/test_iam_detectors.py` | - |
| AC8 | `AWS::AccountId`, direct or via `Ref`, is same-account | `tests/unit/test_iam_intrinsics.py`, `tests/property/test_prop_iam.py` | Property 26 |
| AC9 | Principal `"*"` or `{"AWS": "*"}` is CRITICAL `Security` | `tests/unit/test_iam_detectors.py` | - |
| AC10 | An `sts:ExternalId` condition lowers severity by one level and is recorded in Evidence | `tests/unit/test_iam_detectors.py`, `tests/property/test_prop_iam.py` | Property 27 |
| AC11 | The named dangerous service combinations are identified | `tests/unit/test_iam_detectors.py` | Three detectors: S3 read-write-delete, EC2 plus PassRole, Lambda update plus invoke |
| AC12 | No IAM resources yields zero findings and an informational message | `tests/unit/test_iam_detectors.py`, `tests/integration/test_skill_iam.py` | - |
| AC13 | A Finding carries severity, type, confidence, logical ID, statement location, and description | `tests/unit/test_iam_detectors.py`, `tests/unit/test_iam_locate.py` | Property 1 |

## Requirement 7: Unified review report

| AC | Criterion | Verified by | Notes |
| --- | --- | --- | --- |
| AC1 | Every Finding carries the 13 fields, with a sequential ID from 1 | `tests/unit/test_finding.py`, `tests/unit/test_report.py` | Property 1 |
| AC2 | FindingType is exactly one of four values | `tests/unit/test_finding.py`, `tests/integration/test_pipeline_end_to_end.py` | - |
| AC3 | Severity is exactly one of five values | `tests/unit/test_finding.py`, `tests/integration/test_pipeline_end_to_end.py` | - |
| AC4 | Severity is assigned relative to Findings of the same FindingType | `tests/unit/test_categories.py`, `tests/unit/test_docs.py` | Each Source's severity mapping stays inside its FindingType band; the rule is stated in `docs/finding-schema.md` |
| AC5 | The schema reference states that Severity compares only within one FindingType | `tests/unit/test_docs.py` | A documentation obligation, discharged by the "Severity is comparable only within one FindingType" section of `docs/finding-schema.md` |
| AC6 | `Validity` is CRITICAL only when the Template cannot deploy at all | `tests/unit/test_categories.py`, `tests/property/test_prop_categories.py` | Property 8 |
| AC7 | Confidence is exactly one of three values | `tests/unit/test_finding.py` | - |
| AC8 | cfn-lint and cfn-guard Findings are `Confirmed` | `tests/unit/test_cfnguard_normalize.py`, `tests/property/test_prop_finding_schema.py` | Property 6 |
| AC9 | Deterministic IAM Findings are `Confirmed` | `tests/unit/test_iam_source.py`, `tests/property/test_prop_finding_schema.py` | Property 6 |
| AC10 | Agent Findings are never `Confirmed` | `tests/unit/test_agentin.py`, `tests/property/test_prop_finding_schema.py` | Property 6 |
| AC11 | A non-`Confirmed` Finding quotes the Template content behind it | `tests/unit/test_agentin.py`, `tests/property/test_prop_finding_schema.py` | Property 7 |
| AC12 | A non-`Confirmed` description is phrased as a potential risk | `tests/unit/test_finding_wording.py` | - |
| AC13 | Source is one or more of the four names | `tests/unit/test_finding.py`, `tests/unit/test_source.py` | - |
| AC14 | Findings sharing logical ID and category are deduplicated | `tests/unit/test_dedup.py`, `tests/property/test_prop_dedup.py` | Properties 3, 4, and 11 |
| AC15 | Findings sort by Severity descending, then logical ID ascending | `tests/unit/test_report.py`, `tests/property/test_prop_report.py` | Property 12 |
| AC16 | No issues yields an empty list and a passing summary | `tests/unit/test_report.py`, `tests/negative/test_clean_templates.py` | - |
| AC17 | The summary counts Findings by type, by severity, and by source | `tests/unit/test_report.py`, `tests/property/test_prop_report.py` | Property 13 |

## Requirement 8: CDK support

| AC | Criterion | Verified by | Notes |
| --- | --- | --- | --- |
| AC1 | Synthesized templates are ordinary Template input | `tests/unit/test_cdk_detect.py`, `tests/integration/test_cdk.py` | - |
| AC2 | `cdk.json` is detected and reported, and existing synthesized templates are found | `tests/unit/test_cdk_detect.py`, `tests/integration/test_cdk.py` | - |
| AC3 | `cdk synth` is never run automatically | `tests/property/test_prop_orchestration.py`, `tests/integration/test_cdk.py` | Property 25 |
| AC4 | A review from CDK source warns about arbitrary code execution and requires confirmation | `tests/property/test_prop_orchestration.py`, `tests/integration/test_examples.py` | Property 25. The warning text is one constant, quoted verbatim by `docs/security-model.md` |
| AC5 | Without confirmation, only synthesized templates are used, or none is reported | `tests/unit/test_cdk_detect.py`, `tests/integration/test_cdk.py` | - |
| AC6 | A confirmed `cdk synth` gets a 120 second timeout and stderr capture | `tests/unit/test_cdk_detect.py`, `tests/integration/test_fakebin_drives_sources.py` | - |
| AC7 | A failure or timeout reports stderr and does not fall back | `tests/integration/test_cdk.py`, `tests/integration/test_fakebin_drives_sources.py` | - |
| AC8 | A missing CDK CLI is reported with its installation documentation | `tests/integration/test_tool_unavailable.py`, `tests/integration/test_cdk.py` | - |
| AC9 | Each available synthesized Template gets the full pipeline | `tests/integration/test_cdk.py`, `tests/integration/test_skill_iac_review.py` | - |
| AC10 | Standalone templates are reviewed first and reported separately | `tests/unit/test_cdk_detect.py`, `tests/integration/test_cdk.py` | - |
| AC11 | The documentation states that `cdk synth` is unsandboxed | `tests/unit/test_root_docs.py`, `tests/integration/test_cdk.py` | Carried by `docs/security-model.md` and the README "Known Limitations" section |

## Requirement 9: Security requirements

| AC | Criterion | Verified by | Notes |
| --- | --- | --- | --- |
| AC1 | No credential or secret in any repository file | `tests/unit/test_ci.py` | The scan runs over the whole repository locally and as a CI gate |
| AC2 | No secret is logged or emitted at run time | `tests/unit/test_redaction.py`, `tests/property/test_prop_security.py` | Property 29 |
| AC3 | Review is read-only; no AWS resource is created, changed, or deleted | `tests/regression/test_sec_shell_metacharacters.py`, `tests/property/test_prop_pathguard.py` | No AWS SDK ships, and an AST scan shows `iacreview/proc.py` is the only process-spawning path |
| AC4 | Commands are argument arrays, and shell metacharacters are rejected | `tests/property/test_prop_pathguard.py`, `tests/regression/test_sec_shell_metacharacters.py` | Property 19 |
| AC5 | A resolved path must stay inside the workspace root | `tests/unit/test_pathguard.py`, `tests/regression/test_sec_path_traversal.py` | Property 18 |
| AC6 | Temporary files are mode 0600 and removed, abnormal termination included | `tests/unit/test_tempfile.py`, `tests/property/test_prop_security.py` | Property 22 |
| AC7 | Templates are untrusted; nothing embedded in one is executed | `tests/unit/test_yamlcfn.py`, `tests/property/test_prop_template.py` | Property 21 |
| AC8 | The documentation describes the agent-to-MCP boundary, data flow, credentials, and network scope | `tests/unit/test_docs.py` | Carried by `docs/mcp/README.md`, whose nine record items are asserted individually |

## Requirement 10: Portability requirements

| AC | Criterion | Verified by | Notes |
| --- | --- | --- | --- |
| AC1 | Core review needs no vendor-specific extension | `tests/unit/test_manifest.py`, `tests/unit/test_docs.py` | - |
| AC2 | Vendor settings are separated from the portable core | `tests/unit/test_manifest.py` | `extensions` is deliberately unused in v0.1; the reasoning is in `docs/architecture.md` |
| AC3 | Deterministic components give identical results on macOS and Linux | `tests/property/test_prop_determinism.py`, `tests/unit/test_ci.py` | Property 14, run across the CI matrix on both operating systems |
| AC4 | Core review does not require an MCP server | `tests/unit/test_docs.py` | - |
| AC5 | An unavailable configured MCP server warns and the review continues | `tests/integration/test_tool_unavailable.py` | - |
| AC6 | External tool dependencies are documented with minimum versions and per-OS installation | `tests/unit/test_root_docs.py`, `tests/unit/test_toolcheck.py` | The documented minimums are compared against the versions the code enforces |
| AC7 | The Plugin is loadable as a Kiro Power and the steps are documented | `tests/unit/test_docs.py`, `tests/unit/test_skills.py` | PARTIAL. See "Gaps and conflicts" |
| AC8 | Every Skill under `skills/` is discoverable by the host agent in Kiro | `tests/unit/test_skills.py`, `tests/unit/test_docs.py` | PARTIAL, same gap as AC7 |
| AC9 | Kiro steps are separate, and no Kiro-specific file is needed elsewhere | `tests/unit/test_docs.py`, `tests/unit/test_manifest.py` | No file under the runtime trees references `.kiro/`, which is what makes the separation checkable |

## Requirement 11: Benchmark

| AC | Criterion | Verified by | Notes |
| --- | --- | --- | --- |
| AC1 | At least one syntactically valid, intentionally flawed Template per category | `tests/integration/test_benchmark_cases.py` | Every case template is parsed and reviewed |
| AC2 | The ten named categories are covered | `tests/integration/test_benchmark_cases.py`, `tests/unit/test_ground_truth.py` | - |
| AC3 | Ground truth is structured, with category, type, severity, logical ID, and a total | `tests/unit/test_ground_truth.py` | - |
| AC4 | Each expected Finding is `deterministic` or `agent-dependent` | `tests/unit/test_ground_truth.py` | - |
| AC5 | Detection Rate, False Positive count, Precision, and Recall are reported | `tests/unit/test_metrics.py`, `tests/property/test_prop_benchmark.py` | Property 30 |
| AC6 | Severity Accuracy is reported to one decimal place | `tests/unit/test_metrics.py`, `tests/property/test_prop_benchmark.py` | Property 30 |
| AC7 | A deterministic Detection Rate below 100 percent is a FAIL for the category | `tests/property/test_prop_benchmark.py`, `tests/integration/test_benchmark_harness.py` | Property 31, and a CI gate |
| AC8 | Agent-dependent expectations carry no pass or fail threshold | `tests/unit/test_metrics.py`, `tests/property/test_prop_benchmark.py` | Property 31 |
| AC9 | Agent-dependent matching uses logical ID, type, and category, not description text | `tests/unit/test_metrics.py` | - |
| AC10 | Per-Source attribution is retained so results can be filtered after the run | `tests/unit/test_metrics.py`, `tests/integration/test_benchmark_harness.py` | - |
| AC11 | The three Source subset modes are supported | `tests/unit/test_metrics.py`, `tests/integration/test_benchmark_harness.py` | - |
| AC12 | The data format reserves `agent-only` and `human-review` fields | `tests/unit/test_ground_truth.py`, `tests/unit/test_run_benchmark.py` | - |
| AC13 | The methodology defines the three deferred metrics and marks them out of scope | `tests/unit/test_docs.py` | Carried by `docs/benchmark-methodology.md`; each deferred metric is required to be a section of its own |
| AC14 | Contributor documentation requires ground truth to be authored before any review | `tests/unit/test_root_docs.py`, `tests/unit/test_ground_truth.py` | Also enforced as a commit-order gate in CI |
| AC15 | Contributor documentation prohibits deriving ground truth from review output | `tests/unit/test_root_docs.py`, `tests/unit/test_ci.py` | - |
| AC16 | A new rule or new review logic requires a Benchmark Template | `tests/unit/test_root_docs.py` | - |

## Requirement 12: Testing requirements

| AC | Criterion | Verified by | Notes |
| --- | --- | --- | --- |
| AC1 | Unit tests for the script components, at least 80 percent line coverage | `tests/unit/test_ci.py` | The floor is a CI gate measured over every declared coverage source |
| AC2 | Integration tests over at least three Templates, validating the Finding schema | `tests/integration/test_pipeline_end_to_end.py` | - |
| AC3 | Negative tests over at least two clean Templates with declared ground truth | `tests/negative/test_clean_templates.py` | - |
| AC4 | A clean Template yields no HIGH or CRITICAL deterministic Finding | `tests/negative/test_clean_templates.py` | - |
| AC5 | A clean Template yields no deterministic Finding outside ground truth | `tests/negative/test_clean_templates.py` | - |
| AC6 | The false positive count excludes Informational and BestPractice at LOW or INFO | `tests/negative/test_clean_templates.py` | - |
| AC7 | An unavailable tool yields a structured error naming the tool, with no traceback | `tests/integration/test_tool_unavailable.py`, `tests/unit/test_fakebin.py` | The fake executables are what make this reproducible without uninstalling anything |
| AC8 | Malformed input yields a structured error with type and location, no traceback | `tests/integration/test_malformed_input.py`, `tests/regression/test_sec_malformed_json.py` | - |
| AC9 | All cfn-lint field mappings into the Finding format are tested | `tests/unit/test_cfnlint_parse.py` | - |
| AC10 | A regression suite exists, and a fixed defect gains a regression test | `tests/unit/test_root_docs.py`, `tests/regression/test_sec_symlink_loop.py` | The obligation is on `CONTRIBUTING.md`; the symlink case is an example of it being met |
| AC11 | The regression suite covers the six named security classes | `tests/regression/test_sec_path_traversal.py`, `tests/regression/test_sec_malformed_yaml.py`, `tests/regression/test_sec_malformed_json.py` | The other three classes are `tests/regression/test_sec_shell_metacharacters.py`, `tests/regression/test_sec_tool_unavailable.py`, and `tests/regression/test_sec_invalid_arguments.py` |
| AC12 | A security-relevant change gains a regression test | `tests/unit/test_root_docs.py` | Asserted in both the testing and the security section of `CONTRIBUTING.md` |

## Requirement 13: Project structure and documentation

| AC | Criterion | Verified by | Notes |
| --- | --- | --- | --- |
| AC1 | The README carries the 17 named level-2 sections | `tests/unit/test_root_docs.py` | - |
| AC2 | "Known Limitations" lists out-of-scope features, the `cdk synth` sandboxing gap, and Agent non-determinism | `tests/unit/test_root_docs.py` | - |
| AC3 | A LICENSE with the full text of an OSI-approved license | `tests/unit/test_root_docs.py` | Compared against the license the manifest declares |
| AC4 | CONTRIBUTING carries the seven named sections | `tests/unit/test_root_docs.py` | - |
| AC5 | A CHANGELOG in Keep a Changelog form, each entry linking a version tag | `tests/unit/test_root_docs.py` | - |
| AC6 | The root documents and everything under `docs/` are English | `tests/unit/test_docs.py`, `tests/unit/test_root_docs.py` | Asserted as ASCII with an allowlist of the two English typographic dashes |
| AC7 | Every `SKILL.md` is English | `tests/unit/test_skills.py` | - |
| AC8 | Japanese supplements are suffixed and do not replace the English original | `tests/unit/test_root_docs.py`, `tests/unit/test_skills.py` | - |
| AC9 | `docs/` holds the architecture, security model, methodology, and schema references | `tests/unit/test_docs.py` | - |
| AC10 | The schema reference documents every field and its permitted values | `tests/unit/test_docs.py` | Compared against the constants in the code, not against a copied list |
| AC11 | No document presents an unimplemented capability as available; plans are in the Roadmap | `tests/unit/test_docs.py`, `tests/unit/test_root_docs.py` | Checked mechanically as "no document points at a path that does not exist", plus the Roadmap assertions |

## Requirement 14: Finding normalization and deduplication

| AC | Criterion | Verified by | Notes |
| --- | --- | --- | --- |
| AC1 | A closed category set, exactly one category per Finding | `tests/unit/test_categories.py`, `tests/property/test_prop_categories.py` | Property 2 |
| AC2 | The set includes the ten named categories | `tests/unit/test_categories.py` | - |
| AC3 | An unmappable Agent Finding becomes `Other` and is excluded from matching | `tests/unit/test_dedup.py`, `tests/property/test_prop_dedup.py` | Properties 2 and 11 |
| AC4 | One versioned mapping file holds every mapping | `tests/unit/test_categories.py` | - |
| AC5 | Equivalence is logical ID and category | `tests/unit/test_dedup.py`, `tests/property/test_prop_merge.py` | Property 5 |
| AC6 | A Finding with no logical ID matches nothing and stays a separate entry | `tests/unit/test_dedup.py`, `tests/property/test_prop_dedup.py` | Property 11 |
| AC7 | Equivalent Findings merge into one entry | `tests/unit/test_dedup.py`, `tests/integration/test_skill_iac_review.py` | - |
| AC8 | The highest Severity is retained | `tests/unit/test_dedup.py`, `tests/property/test_prop_merge.py` | Property 5 |
| AC9 | The highest Confidence is retained | `tests/unit/test_dedup.py`, `tests/property/test_prop_merge.py` | Property 5 |
| AC10 | FindingType follows the four-step precedence | `tests/unit/test_dedup.py`, `tests/property/test_prop_merge.py` | Property 5 |
| AC11 | Evidence is concatenated in Source order | `tests/unit/test_dedup.py`, `tests/property/test_prop_merge.py` | Property 5 |
| AC12 | A merged Finding names every detecting Source | `tests/unit/test_dedup.py`, `tests/unit/test_report.py` | - |
| AC13 | An unmatched Finding passes through unmodified | `tests/unit/test_dedup.py`, `tests/property/test_prop_dedup.py` | Property 11 |

## Requirement 15: External tool execution and path containment

| AC | Criterion | Verified by | Notes |
| --- | --- | --- | --- |
| AC1 | Tools are invoked by command name via PATH; no binary is bundled | `tests/unit/test_manifest.py`, `tests/unit/test_toolcheck.py` | The manifest test also rejects any executable file shipped in the package |
| AC2 | Each Skill that shells out documents the tool as an external dependency | `tests/unit/test_skills.py` | - |
| AC3 | Arguments use workspace-relative or runtime-supplied paths only | `tests/integration/test_skill_cfn_lint.py`, `tests/regression/test_sec_shell_metacharacters.py` | - |
| AC4 | A missing tool is reported with name, minimum version, and install command | `tests/unit/test_toolcheck.py`, `tests/integration/test_tool_unavailable.py` | - |
| AC5 | A stdio MCP example gives the command as one token with arguments in `args` | `tests/unit/test_docs.py` | Asserted against `docs/mcp/mcp.json.example` |
| AC6 | A tool below the minimum version is reported with detected, required, and upgrade | `tests/unit/test_toolcheck.py`, `tests/integration/test_fakebin_drives_sources.py` | - |
| AC7 | A non-violation failure reports tool, exit code, and the first 5 stderr lines | `tests/unit/test_errors.py`, `tests/property/test_prop_security.py` | Property 23. CONFLICT with Requirement 16 AC11. See "Gaps and conflicts" |

## Requirement 16: Deterministic component implementation policy

| AC | Criterion | Verified by | Notes |
| --- | --- | --- | --- |
| AC1 | The seven deterministic components are implemented in Python 3 | `tests/unit/test_scaffold.py`, `tests/property/test_prop_pathguard.py` | The AST scan also asserts that no shell script ships |
| AC2 | Shell scripts are limited to invocation wrappers | `tests/property/test_prop_pathguard.py` | Vacuously satisfied while no shell script ships, which is what the scan asserts |
| AC3 | The standard library plus at most one YAML dependency | `tests/unit/test_root_docs.py`, `tests/unit/test_docs.py` | Read from the declared dependency list rather than from prose |
| AC4 | Development and test dependencies are declared separately and are exempt | `tests/unit/test_root_docs.py` | - |
| AC5 | Explicit type annotations on every public function signature | `tests/unit/test_root_docs.py` | GAP: no mechanical check. See "Gaps and conflicts" |
| AC6 | No shell command string is built by concatenating user input | `tests/unit/test_proc.py`, `tests/property/test_prop_pathguard.py` | Property 19 |
| AC7 | Arguments are validated before any other work, and a failure exits non-zero | `tests/regression/test_sec_invalid_arguments.py`, `tests/property/test_prop_security.py` | Property 20 |
| AC8 | A distinct exit code per named failure class, documented | `tests/unit/test_exitcodes.py`, `tests/unit/test_skills.py` | Every code a `SKILL.md` documents is compared against the code the module defines |
| AC9 | Scripts are non-interactive and never read stdin | `tests/unit/test_proc.py`, `tests/integration/test_benchmark_harness.py` | - |
| AC10 | JSON on stdout, human-readable diagnostics on stderr | `tests/unit/test_bootstrap.py`, `tests/integration/test_skill_iac_review.py` | - |
| AC11 | Identical input gives byte-identical stdout, with no environment-dependent values | `tests/property/test_prop_determinism.py`, `tests/regression/test_sec_no_host_path_in_errors.py` | Property 14. See the AC7 conflict note under Requirement 15 |

## The 31 correctness properties

Every property in the design's "Correctness Properties" section is implemented
exactly once, marked by a tag comment of the form
`Feature: aws-iac-review-agent-plugin, Property N:` in the file that implements
it. `tests/unit/test_traceability.py` asserts the one-to-one relationship, so a
property that loses its implementation, or gains a second one, fails a test
rather than going unnoticed.

| Property | Implemented in |
| --- | --- |
| 1, 6, 7 | `tests/property/test_prop_finding_schema.py` |
| 2, 8, 9 | `tests/property/test_prop_categories.py` |
| 3, 4, 11 | `tests/property/test_prop_dedup.py` |
| 5 | `tests/property/test_prop_merge.py` |
| 10 | `tests/property/test_prop_cfnlint.py` |
| 12, 13 | `tests/property/test_prop_report.py` |
| 14 | `tests/property/test_prop_determinism.py` |
| 15, 16, 17, 21 | `tests/property/test_prop_template.py` |
| 18, 19 | `tests/property/test_prop_pathguard.py` |
| 20, 22, 23, 29 | `tests/property/test_prop_security.py` |
| 24, 25 | `tests/property/test_prop_orchestration.py` |
| 26, 27, 28 | `tests/property/test_prop_iam.py` |
| 30, 31 | `tests/property/test_prop_benchmark.py` |

The table above is a reader's index. The assertion that matters reads the tags
from the files themselves, so this table cannot be what keeps the mapping
honest, and a rename here is a documentation fix rather than a test failure.

## Gaps and conflicts

Five rows above are qualified: Requirement 1 AC5, Requirement 10 AC7 and AC8,
Requirement 15 AC7, and Requirement 16 AC5. They are collected here so that a
reader looking for the weak points does not have to find them by scanning 182
rows.

### Requirement 1 AC5 conflicts with the Agent Plugins 1.0.0 schema

AC5 fixes the `name` pattern as `^[a-z0-9]([a-z0-9._-]*[a-z0-9])?$` with a
maximum length of 128. That pattern admits `_`, and the published Agent Plugins
1.0.0 schema does not: it caps the length at 64 and additionally forbids `_`,
`--`, and `..`. The name this Plugin ships is 27 characters long and contains
none of the forbidden sequences, so it satisfies both readings, and nothing about
the package has to change either way.

`tests/unit/test_manifest.py` encodes AC5, because a test is not the place to
resolve a requirements-level disagreement. The narrower schema rule is the one a
client will actually apply, so a future `name` change should be checked against
64 characters and the three forbidden sequences, not against AC5's bound. The
conflict is recorded rather than resolved unilaterally.

### Requirement 10 AC7 and AC8 are structurally, not observationally, satisfied

AC7 asks for the Plugin to be loadable as a Kiro Power with documented steps, and
AC8 for every Skill to be discoverable once loaded. What is verified is the
structural half: the package is a valid Agent Plugins 1.0.0 package, the five
Skills are present with parseable front matter, each entry point resolves the
package root from its own location, no file under the runtime trees reads
anything from `.kiro/`, and the package contains no symlink. Those are the
conditions a load depends on.

The load itself was never observed. No Kiro installation was driven to install
this package as a Power, and no host agent was watched enumerating the Skills.
`docs/kiro-power.md` says so in its "What was not verified" section, states no
installation steps of its own for that reason, and points at Kiro's own
documentation as the authoritative procedure. The README repeats the limitation.
Marking these rows PARTIAL is the honest reading: claiming AC7 as verified would
be exactly the sort of unimplemented-capability claim Requirement 13 AC11
forbids.

### Requirement 15 AC7 and Requirement 16 AC11 pull in opposite directions

AC7 requires the first 5 lines of a failing tool's stderr to reach the caller.
AC11 requires stdout to be byte-identical across runs and to contain no absolute
host paths. External tools write absolute paths into stderr, so a verbatim
transcription can carry a value that AC11 forbids.

Both criteria are implemented as written, and the tension is recorded as residual
risk R-4 in `docs/security-model.md`, with a revisit listed under that document's
"Roadmap Candidates". Reconciling it needs a requirements-level decision about
which criterion yields; an implementation cannot satisfy both as they stand.
`tests/regression/test_sec_no_host_path_in_errors.py` pins the behaviour that was
chosen so that it cannot drift silently before that decision is made.

### Requirement 16 AC5 has no mechanical check

AC5 requires explicit type annotations on every public function signature.
`CONTRIBUTING.md` states the rule under "Coding standards", and the code follows
it, but nothing asserts it: `mypy` is recommended rather than required, so a
missing annotation would not fail the test suite. The row is marked GAP rather
than mapped to a test that does not check what the criterion says.

Closing it would mean either a type-checking gate, which makes a tool the project
does not depend on a requirement, or a test that inspects the signatures of the
public surface directly. The second is the smaller change and is the better
candidate.
