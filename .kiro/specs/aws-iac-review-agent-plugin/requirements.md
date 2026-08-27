# Requirements Document

## Introduction

AWS Infrastructure as Code (IaC) レビューを自動化する Agent Plugins 1.0.0 準拠のプラグインを構築する。CloudFormation および CDK テンプレートを対象に、決定論的な静的解析ツール（cfn-lint, cfn-guard）と Agent ベースのセマンティックレビュー（IAM セキュリティ、アーキテクチャ、ベストプラクティス）を組み合わせ、統一フォーマットのレビューレポートを生成する。

本プラグインはベンダーニュートラルかつ OSS として公開し、コミュニティによる拡張を前提とする。v0.1 スコープでは CloudFormation テンプレートレビューを主軸に、cfn-lint / cfn-guard 統合、IAM セキュリティレビュー、統一レポートフォーマットを実現する。

## Glossary

- **Plugin**: Agent Plugins 1.0.0 仕様に準拠したパッケージ。plugin.json をルートに持つディレクトリ構造
- **Skill**: Plugin 内の `skills/` ディレクトリ直下にある、`SKILL.md` を含むディレクトリ。Agent に機能を提供する単位
- **MCP_Server**: Model Context Protocol サーバー。mcp.json で宣言される外部プロセス
- **Review_Engine**: cfn-lint, cfn-guard, IAM Review, Agent Review の各レビューソースを統合するオーケストレーション層
- **Finding**: レビュー結果の個別検出事項。ID, Normalized_Category, FindingType, Severity, Confidence, Source, Resource, Location 等の構造化フィールドを持つ
- **FindingType**: Finding の性質を示す軸。`Validity`（テンプレートの正当性・デプロイ可能性）、`Security`（セキュリティ侵害リスク）、`BestPractice`（推奨構成からの逸脱）、`Informational`（参考情報）のいずれか。Severity とは直交する独立した軸
- **Severity**: Finding の重大度。`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO` のいずれか。同一 FindingType の範囲内で相対的に解釈される
- **Confidence**: Finding の確証度。`Confirmed`（決定論的ツールまたは決定論的パターンマッチにより確認済み）、`Likely`（Agent 推論による可能性の高いリスク）、`Contextual`（文脈依存の推奨事項）のいずれか
- **Normalized_Category**: 全 Source の Finding に付与される、閉じた集合として定義された正規化カテゴリ。Finding 重複排除およびベンチマーク照合のキーとして使用する
- **Benchmark_Harness**: Benchmark_Template に対するレビュー結果を Ground_Truth と照合し、評価指標を算出する決定論的な実行機構
- **cfn-lint**: AWS CloudFormation テンプレートの構文・リソース設定を検証する Python ベースの静的解析ツール
- **cfn-guard**: CloudFormation テンプレートに対してポリシールールを適用する Rust ベースのバリデーションツール
- **Guard_Rule**: cfn-guard が使用するポリシー定義ファイル（.guard 拡張子）
- **Template**: AWS CloudFormation テンプレートファイル（YAML または JSON 形式）
- **CDK_Project**: AWS CDK で記述された IaC プロジェクト。`cdk synth` により CloudFormation Template を生成する
- **Review_Report**: 全ソースの Finding を統合・重複排除した最終出力
- **Benchmark_Template**: 既知の問題を意図的に含むテスト用 CloudFormation テンプレート
- **Ground_Truth**: Benchmark_Template に対する期待される検出結果の定義

## Requirements

### Requirement 1: Plugin パッケージ構造

**User Story:** As a plugin consumer, I want the plugin to conform to Agent Plugins 1.0.0 specification, so that any compliant agent runtime can discover and load it.

#### Acceptance Criteria

1. THE Plugin SHALL contain a `plugin.json` file at the package root directory
2. THE Plugin SHALL contain a `skills/` directory at the package root with at least one Skill subdirectory that contains a valid `SKILL.md` file
3. THE Plugin SHALL constrain all package files within the plugin root directory (path containment), rejecting any symbolic link or relative path reference that resolves outside the plugin root
4. WHEN a Skill directory lacks a `SKILL.md` file or the `SKILL.md` file cannot be parsed as valid Markdown with a top-level heading, THE Plugin SHALL skip that Skill without disabling valid sibling Skills
5. THE Plugin SHALL declare `$schema`, `name`, `version`, `description`, `author`, `license`, and `keywords` fields in `plugin.json`, where `name` matches the pattern `^[a-z0-9]([a-z0-9._-]*[a-z0-9])?$` with a maximum length of 128 characters, and `keywords` is an array of strings
6. THE Plugin SHALL use semantic versioning format (MAJOR.MINOR.PATCH) as defined by semver.org for the `version` field in `plugin.json`
7. THE Plugin SHALL NOT include an `mcp.json` file in the v0.1 package
8. THE Plugin SHALL provide an optional MCP configuration example under `docs/` that a user may copy to the plugin root, together with documentation of the example's purpose, required permissions, network access scope, credential handling, data transmitted externally, and behavior when the MCP_Server fails
9. WHERE a user adds an `mcp.json` file to the plugin root, THE declared MCP_Servers SHALL use an explicit transport type (`stdio`, `streamable-http`, or `sse`) per Agent Plugins 1.0.0
10. THE Plugin core review functionality SHALL remain fully operational when no `mcp.json` file is present
11. IF `plugin.json` is absent from the package root or cannot be parsed as valid JSON, THEN THE Plugin SHALL fail to load and the runtime SHALL report an error indicating the missing or malformed manifest

### Requirement 2: Skill 構成

**User Story:** As a plugin consumer, I want clearly separated skills for each review capability, so that I can invoke individual review functions or the full orchestrated review.

#### Acceptance Criteria

1. THE Plugin SHALL provide a `cloudformation-review` Skill that performs AWS design perspective review of CloudFormation templates
2. THE Plugin SHALL provide a `cfn-lint-review` Skill that executes cfn-lint and converts output into the common Finding format defined in Requirement 7
3. THE Plugin SHALL provide a `cfn-guard-review` Skill that executes cfn-guard and reports policy violations in the common Finding format defined in Requirement 7
4. THE Plugin SHALL provide an `iam-review` Skill that performs IAM security analysis
5. THE Plugin SHALL provide an `iac-review` Skill that orchestrates all review Skills and aggregates their results into a unified Review_Report
6. WHEN invoked individually, THE `cfn-lint-review` Skill SHALL produce results independently without requiring other Skills
7. WHEN invoked individually, THE `cfn-guard-review` Skill SHALL produce results independently without requiring other Skills
8. WHEN invoked individually, THE `iam-review` Skill SHALL produce results independently without requiring other Skills
9. WHEN invoked individually, THE `cloudformation-review` Skill SHALL produce results independently without requiring other Skills
10. WHEN the `iac-review` Skill orchestrates sub-skills and a sub-skill fails, THE `iac-review` Skill SHALL include an error entry in the Review_Report for the failed sub-skill and continue processing remaining sub-skills
11. THE `SKILL.md` file of each Skill SHALL contain YAML front matter declaring a `name` field and a `description` field, where `description` states both the capability the Skill provides and the conditions under which a client should select the Skill
12. THE `name` field declared in each `SKILL.md` front matter SHALL be identical to the name of the directory containing that `SKILL.md`
13. THE `SKILL.md` file of each Skill SHALL contain sections documenting purpose, when to use the Skill, Input, Output, Limitations, and Dependencies
14. THE `cloudformation-review` Skill SHALL restrict its analysis to cross-resource relationships, architectural risk, contextual severity assessment, and best practice reasoning, and SHALL NOT re-implement checks that cfn-lint or cfn-guard already perform
15. WHERE a check is reliably performed by cfn-lint or cfn-guard, THE Plugin SHALL delegate that check to the external tool rather than to Agent reasoning
16. THE Plugin SHALL implement each normalization routine and each parsing routine in exactly one location that is shared by all Skills requiring it

### Requirement 3: CloudFormation テンプレートレビュー

**User Story:** As a cloud engineer, I want CloudFormation templates reviewed for quality, security, and best practices, so that I can identify issues before deployment.

#### Acceptance Criteria

1. WHEN a provided file parses as YAML or JSON and contains a top-level `Resources` mapping with at least one entry, THE Review_Engine SHALL treat the file as a CloudFormation Template and validate its syntax and structure
2. WHEN a CloudFormation Template is provided, THE Review_Engine SHALL evaluate AWS resource configuration against best practices and produce Findings that each carry a Severity, a FindingType, a Normalized_Category from the set defined in Requirement 14, and the logical ID of the target resource
3. WHEN a CloudFormation Template is provided, THE Review_Engine SHALL detect security issues across the Normalized_Categories `IAM`, `Encryption`, `PublicAccess`, `Logging`, `Tagging`, `Availability`, and `Backup`
4. THE Review_Engine SHALL accept CloudFormation Templates in both YAML and JSON formats
5. IF a provided file parses successfully as YAML or JSON but has no top-level `Resources` mapping, THEN THE Review_Engine SHALL report that the file is not a reviewable CloudFormation Template, including the file path in the report
6. IF a provided file cannot be parsed as YAML or JSON, THEN THE Review_Engine SHALL report the parse error type and the line number and column number at which parsing failed

### Requirement 4: cfn-lint 統合

**User Story:** As a cloud engineer, I want cfn-lint results integrated into the review, so that I get syntax and resource configuration validation automatically.

#### Acceptance Criteria

1. WHEN a CloudFormation Template is provided, THE `cfn-lint-review` Skill SHALL execute cfn-lint with JSON output format (`-f json`) against the Template
2. WHEN cfn-lint produces output, THE `cfn-lint-review` Skill SHALL parse each result into a normalized Finding with fields: FindingType, Severity, Confidence, Normalized_Category, rule ID, target resource logical ID, line number, and description
3. WHEN cfn-lint reports an Error-level result, THE `cfn-lint-review` Skill SHALL assign FindingType `Validity` to the resulting Finding
4. WHEN cfn-lint reports an Error-level result, THE `cfn-lint-review` Skill SHALL map the Severity to HIGH
5. WHEN cfn-lint reports an Error-level result whose rule ID is recorded as deployment-blocking in the mapping file described in Requirement 14, THE `cfn-lint-review` Skill SHALL map the Severity to CRITICAL, where the initial deployment-blocking set is the rule ID prefixes `E0` and `E1` as a conservative policy covering results that prevent the Template as a whole from being processed
6. WHEN cfn-lint reports a Warning-level result, THE `cfn-lint-review` Skill SHALL assign FindingType `BestPractice` and map the Severity to MEDIUM
7. WHEN cfn-lint reports an Informational-level result, THE `cfn-lint-review` Skill SHALL assign FindingType `Informational` and map the Severity to LOW
8. THE `cfn-lint-review` Skill SHALL invoke cfn-lint with Informational rules enabled (`--include-checks I`), because cfn-lint does not evaluate Informational rules by default and the mapping in the preceding criterion is otherwise unreachable
9. WHERE a cfn-lint rule ID is listed in the maintained security-relevance mapping table described in Requirement 14, THE `cfn-lint-review` Skill SHALL assign FindingType `Security` to the resulting Finding instead of `Validity`
10. IF cfn-lint is not installed or not available in the execution environment, THEN THE `cfn-lint-review` Skill SHALL return an error message indicating cfn-lint is unavailable and provide installation instructions including `pip install cfn-lint`
11. WHEN cfn-lint exits with a code whose set bits form a subset of {2, 4, 8}, indicating that findings were reported, THE `cfn-lint-review` Skill SHALL treat this as successful execution and parse the findings from stdout
12. IF cfn-lint exits with a code containing any bit outside the set {2, 4, 8}, including exit code 1 which indicates a crash or usage error, THEN THE `cfn-lint-review` Skill SHALL report the failure with the stderr output without terminating the overall review pipeline
13. WHEN cfn-lint finds zero violations, THE `cfn-lint-review` Skill SHALL return an empty findings list with source identified as `cfn-lint`

### Requirement 5: cfn-guard 統合

**User Story:** As a security engineer, I want cfn-guard policy validation integrated into the review, so that organizational compliance policies are automatically checked.

#### Acceptance Criteria

1. WHEN a CloudFormation Template is provided, THE `cfn-guard-review` Skill SHALL execute cfn-guard with bundled Guard_Rules against the Template and return results within 60 seconds per Template
2. THE Plugin SHALL bundle at least one Guard_Rule per each of the following categories: Encryption, Public Access, Logging, Tagging, IAM, and Backup
3. WHEN cfn-guard detects a policy violation, THE `cfn-guard-review` Skill SHALL produce a normalized Finding containing: FindingType (`Security` or `BestPractice`), Severity (one of CRITICAL, HIGH, MEDIUM, LOW), Normalized_Category, violated rule name, logical resource identifier of the target resource, and a remediation guidance statement describing what change resolves the violation
4. WHEN cfn-guard detects zero policy violations, THE `cfn-guard-review` Skill SHALL return a result indicating that all rules passed with the count of rules evaluated
5. IF cfn-guard is not installed or not available in the execution environment, THEN THE `cfn-guard-review` Skill SHALL return an error message stating that cfn-guard is unavailable and include a reference to the cfn-guard installation documentation
6. IF cfn-guard execution fails with a non-zero exit code unrelated to policy violations, THEN THE `cfn-guard-review` Skill SHALL report the failure including the captured stderr output and continue the overall review pipeline with remaining skills
7. WHEN cfn-guard exits with a non-zero exit code, THE `cfn-guard-review` Skill SHALL determine whether the result represents a policy violation or an execution failure by whether the tool's stdout parses as the expected result structure, and SHALL NOT base that determination on the specific exit code value
8. THE Plugin SHALL structure Guard_Rules so that each category is stored in a separate directory and new rule files can be added to a category directory without modifying existing rule files

### Requirement 6: IAM セキュリティレビュー

**User Story:** As a security engineer, I want deep IAM policy analysis, so that I can identify privilege escalation risks and overly permissive policies.

#### Acceptance Criteria

1. WHEN a CloudFormation Template contains IAM policies, THE `iam-review` Skill SHALL detect `Action: "*"` combined with `Resource: "*"` patterns and produce a Finding with FindingType `Security` and Severity CRITICAL
2. WHEN a CloudFormation Template contains IAM policies with `Effect: Allow` on sensitive action prefixes (`iam:`, `sts:`, `lambda:`, `s3:`) without a Condition block, THE `iam-review` Skill SHALL produce a Finding identifying the overly permissive policy
3. WHEN a CloudFormation Template contains IAM policies, THE `iam-review` Skill SHALL analyze `iam:PassRole` and `sts:AssumeRole` usage for security implications including unrestricted Resource targets
4. WHEN a CloudFormation Template contains IAM policies, THE `iam-review` Skill SHALL detect wildcard permissions (`*`) in Action or Resource fields
5. WHEN a CloudFormation Template contains IAM policies, THE `iam-review` Skill SHALL identify privilege escalation risk patterns including: iam:CreatePolicyVersion, iam:SetDefaultPolicyVersion, iam:AttachUserPolicy, iam:AttachGroupPolicy, iam:AttachRolePolicy, iam:PutUserPolicy, iam:PutGroupPolicy, iam:PutRolePolicy, lambda:CreateFunction combined with iam:PassRole, and sts:AssumeRole with overly broad trust policy
6. WHEN a CloudFormation Template contains IAM policies with Allow effect on cross-service or cross-account statements, THE `iam-review` Skill SHALL evaluate Condition blocks and flag statements lacking aws:SourceAccount, aws:SourceArn, or aws:PrincipalOrgID conditions
7. WHEN an IAM trust policy Principal or a resource policy Principal contains a literal 12-digit AWS account ID, or contains an ARN embedding a literal 12-digit account ID, THE `iam-review` Skill SHALL report a cross-account access Finding
8. WHERE a Principal is expressed using the `AWS::AccountId` pseudo parameter or a `Ref` to the `AWS::AccountId` pseudo parameter, THE `iam-review` Skill SHALL classify the Principal as same-account rather than cross-account
9. WHEN a Principal is the literal value `"*"` or the mapping `{"AWS": "*"}`, THE `iam-review` Skill SHALL report a Finding with FindingType `Security` and Severity CRITICAL
10. WHERE a cross-account Principal appears together with an `sts:ExternalId` condition in the same statement, THE `iam-review` Skill SHALL reduce the reported Severity of the corresponding Finding by one level and SHALL record the mitigating condition in the Evidence field
11. WHEN a CloudFormation Template contains IAM policies, THE `iam-review` Skill SHALL identify service-specific dangerous permission combinations including: s3:GetObject + s3:PutObject + s3:DeleteObject on `*` resource, ec2:RunInstances + iam:PassRole, and lambda:UpdateFunctionCode + lambda:InvokeFunction
12. WHEN a CloudFormation Template contains no IAM-related resources or policies, THE `iam-review` Skill SHALL return zero findings with an informational message
13. WHEN the `iam-review` Skill detects an issue, THE Finding SHALL include Severity, FindingType, Confidence, the logical resource ID, the specific policy statement location, and a description of the detected risk

### Requirement 7: 統一レビューレポート

**User Story:** As a cloud engineer, I want all findings in a single normalized format, so that I can prioritize and address issues efficiently.

#### Acceptance Criteria

1. THE Review_Report SHALL include for each Finding: ID (a unique identifier within the report, assigned as a sequential integer starting from 1), Normalized_Category, FindingType, Severity, Confidence, Source, Resource, Location, Finding description, Why it matters explanation, Evidence, Recommendation, and Suggested remediation
2. THE Review_Report SHALL assign each Finding a FindingType that is exactly one of `Validity`, `Security`, `BestPractice`, or `Informational`
3. THE Review_Report SHALL assign each Finding a Severity that is exactly one of `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, or `INFO`
4. THE Review_Engine SHALL assign the Severity of each Finding relative to other Findings sharing the same FindingType
5. THE Finding schema reference SHALL state that Severity is comparable only among Findings sharing the same FindingType
6. THE Review_Engine SHALL NOT assign Severity CRITICAL to a Finding whose FindingType is `Validity` unless the reported condition prevents the Template from being deployed at all
7. THE Review_Report SHALL assign each Finding a Confidence that is exactly one of `Confirmed`, `Likely`, or `Contextual`
8. WHEN a Finding originates from cfn-lint or cfn-guard, THE Review_Engine SHALL assign Confidence `Confirmed`
9. WHEN a Finding originates from deterministic IAM pattern matching, THE Review_Engine SHALL assign Confidence `Confirmed`
10. WHEN a Finding originates from Agent semantic reasoning, THE Review_Engine SHALL assign Confidence `Likely` or `Contextual`, and SHALL NOT assign Confidence `Confirmed`
11. WHERE a Finding carries Confidence `Likely` or `Contextual`, THE Finding SHALL include in its Evidence field the specific Template content that led to the conclusion
12. IF a Finding carries a Confidence other than `Confirmed`, THEN THE Review_Engine SHALL phrase the Finding description as a potential risk and SHALL NOT state that a vulnerability exists
13. THE Review_Report SHALL identify the Source of each Finding as one or more of: `cfn-lint`, `cfn-guard`, `IAM Review`, `Agent Review`
14. WHEN multiple sources produce Findings that reference the same resource logical ID and the same Normalized_Category, THE Review_Engine SHALL deduplicate those Findings according to Requirement 14
15. THE Review_Report SHALL sort Findings by Severity in descending order (CRITICAL, HIGH, MEDIUM, LOW, INFO) and then by resource logical ID in ascending alphabetical order
16. WHEN no issues are detected, THE Review_Engine SHALL return an empty findings list with a summary indicating the Template passed all checks
17. THE Review_Report SHALL include a summary section with total Finding counts grouped by FindingType, by Severity, and by Source

### Requirement 8: CDK サポート

**User Story:** As a CDK developer, I want my synthesized CDK templates reviewed through the same pipeline, so that I get consistent security and quality feedback without the plugin executing untrusted project code.

#### Acceptance Criteria

1. THE Review_Engine SHALL accept CloudFormation Templates produced by `cdk synth`, typically located under a `cdk.out/` directory, as ordinary CloudFormation Template input
2. WHEN a CDK_Project is detected by the presence of a `cdk.json` file in the provided directory, THE Review_Engine SHALL report the detection and SHALL identify already-synthesized CloudFormation Templates under the CDK output directory when such Templates are present
3. THE Review_Engine SHALL NOT execute `cdk synth` automatically as part of any review flow
4. WHEN the user explicitly requests a review starting from CDK source code, THE Review_Engine SHALL warn that `cdk synth` executes untrusted project code including dependency lifecycle scripts, and SHALL require explicit user confirmation before invoking `cdk synth`
5. IF the user does not confirm the warning described in acceptance criterion 4, THEN THE Review_Engine SHALL proceed using only already-synthesized Templates, or SHALL report that no reviewable Template is available
6. WHEN `cdk synth` is invoked after explicit user confirmation, THE Review_Engine SHALL apply a 120 second timeout to the invocation and SHALL capture stderr for error reporting
7. IF `cdk synth` exits with a non-zero exit code or exceeds the 120 second timeout, THEN THE Review_Engine SHALL report the captured stderr and SHALL NOT fall back to any alternative execution mode
8. IF CDK CLI is not found on the system PATH when `cdk synth` invocation has been confirmed, THEN THE Review_Engine SHALL report that CDK CLI is unavailable and include a reference to the official CDK installation documentation
9. WHEN synthesized CloudFormation Templates are available for review, THE Review_Engine SHALL apply the full CloudFormation review pipeline to each Template individually
10. WHEN both a CDK_Project and standalone CloudFormation Templates are present in the same directory, THE Review_Engine SHALL review the standalone CloudFormation Templates first and SHALL report results for standalone Templates and synthesized Templates separately
11. THE Plugin documentation SHALL state that the Plugin provides no sandboxing for `cdk synth` and that reviewing untrusted CDK source starting from source code carries arbitrary code execution risk

### Requirement 9: セキュリティ要件

**User Story:** As a security-conscious user, I want the plugin itself to be secure, so that running reviews does not introduce security risks.

#### Acceptance Criteria

1. THE Plugin SHALL NOT contain AWS credentials, API keys, or secrets in any repository file including manifests, source code, examples, benchmarks, or documentation
2. THE Plugin SHALL NOT log or output secrets or credential values during execution
3. THE Plugin SHALL perform read-only review operations and SHALL NOT modify, create, or delete AWS resources
4. WHEN constructing commands for cfn-lint, cfn-guard, or `cdk synth` execution, THE Plugin SHALL use parameterized command construction (array-based arguments with no shell interpolation) and SHALL reject execution and report an error if input values contain shell metacharacters (`;`, `|`, `&`, `$`, backticks, `>`, `<`)
5. WHEN resolving file paths from user input, THE Plugin SHALL validate that the resolved absolute path remains within the workspace root, rejecting any path containing `..` that resolves outside the workspace, and SHALL report an error indicating the path violation
6. WHEN creating temporary files during review, THE Plugin SHALL create files in system-designated temporary directories with permissions restricted to the creating process owner (mode 0600) and SHALL remove files after use, including on abnormal termination via a best-effort cleanup mechanism
7. THE Plugin SHALL treat all input IaC templates as untrusted content and SHALL NOT execute scripts or commands embedded within templates
8. WHERE MCP_Servers are configured by the user, THE Plugin documentation SHALL describe the security boundary between the agent and MCP_Server processes including data flow direction, credential isolation, and network access scope

### Requirement 10: ポータビリティ要件

**User Story:** As a plugin consumer using various agent runtimes, I want the plugin to work across different environments, so that I am not locked into a specific vendor or platform.

#### Acceptance Criteria

1. THE Plugin SHALL function with any Agent Plugins 1.0.0 compliant runtime without requiring vendor-specific extensions for core review functionality (cfn-lint execution, cfn-guard execution, IAM review, and unified report generation)
2. THE Plugin SHALL separate vendor-specific settings from the portable core using the `extensions` field in plugin.json or a designated extension directory
3. WHEN invoked with the same CloudFormation Template, THE Plugin's deterministic components (cfn-lint parsing, cfn-guard rule evaluation, Finding normalization) SHALL produce identical results regardless of host operating system among macOS and Linux
4. THE Plugin SHALL NOT require MCP_Server availability for core review functionality (cfn-lint execution, cfn-guard execution, skill-based review, unified report generation)
5. WHERE a user-supplied MCP configuration is present and the MCP_Server is unavailable, THE Plugin SHALL report a warning and continue the review using skill-only capabilities
6. THE Plugin SHALL document all external tool dependencies (cfn-lint, cfn-guard, CDK CLI, Python 3) with minimum version requirements and installation instructions for both macOS and Linux
7. THE Plugin SHALL be loadable as a Kiro Power, and THE Plugin documentation SHALL provide the concrete steps required to install and load the Plugin in Kiro
8. WHEN the Plugin is loaded in Kiro, all Skills declared under `skills/` SHALL be discoverable by the host agent
9. THE Plugin documentation SHALL present the Kiro-specific installation steps separately from the portable Agent Plugins packaging, such that no Kiro-specific file is required for the portable core to load in another Agent Plugins 1.0.0 compliant client

### Requirement 11: ベンチマーク

**User Story:** As a contributor, I want benchmark templates with ground truth definitions, so that I can measure review accuracy and prevent regressions.

#### Acceptance Criteria

1. THE Plugin SHALL include at least one syntactically valid Benchmark_Template per category that contains intentionally flawed CloudFormation resources
2. THE Plugin SHALL provide Benchmark_Templates covering the following categories: IAM wildcard permissions, Public S3 bucket, Encryption disabled, Logging disabled, Overly permissive Security Group, Missing backup configuration, Missing tags, Unsafe IAM PassRole, Public database endpoint, and Missing deletion protection
3. THE Plugin SHALL define Ground_Truth for each Benchmark_Template in a structured file (JSON or YAML) specifying for each expected Finding: Normalized_Category, FindingType, Severity, and target resource logical ID, together with the total expected Finding count
4. THE Ground_Truth SHALL classify each expected Finding as either `deterministic`, meaning detectable by cfn-lint, cfn-guard, or deterministic IAM pattern matching, or `agent-dependent`, meaning requiring Agent semantic reasoning
5. THE Benchmark_Harness SHALL compare actual review results against Ground_Truth and SHALL report Detection Rate (percentage to 1 decimal place), False Positive count (integer), Precision (percentage to 1 decimal place), and Recall (percentage to 1 decimal place) in a structured summary output
6. THE Benchmark_Harness SHALL report Severity Accuracy, defined as the proportion of correctly detected Findings whose reported Severity matches the Ground_Truth Severity, as a percentage to 1 decimal place
7. WHEN the Benchmark_Harness evaluates expected Findings classified as `deterministic` and the measured Detection Rate is below 100 percent, THE Benchmark_Harness output SHALL report a FAIL status for the affected category
8. WHEN the Benchmark_Harness evaluates expected Findings classified as `agent-dependent`, THE Benchmark_Harness SHALL report the measured Detection Rate without applying a pass or fail threshold
9. WHEN the Benchmark_Harness evaluates expected Findings classified as `agent-dependent`, THE Benchmark_Harness SHALL match actual Findings to expected Findings on target resource logical ID, FindingType, and Normalized_Category rather than by exact string comparison of the Finding description
10. THE Review_Report SHALL retain per-Source attribution for every Finding such that the Benchmark_Harness can filter results to a single Source after review execution
11. THE Benchmark_Harness SHALL support evaluating a configurable subset of Sources, supporting at minimum the modes `cfn-lint only`, `cfn-guard only`, and `combined`
12. THE benchmark data format SHALL reserve fields for `agent-only` and `human-review` result sets so that those modes can be added without changing the Ground_Truth format
13. THE benchmark methodology document SHALL define Review Time, Remediation Accuracy, and Human Intervention Count as deferred metrics together with their intended definitions, and SHALL state that implementation of those metrics is out of scope for v0.1
14. THE contributor documentation SHALL require that Ground_Truth is authored from the intended defects of the Benchmark_Template before any review is executed against that Benchmark_Template
15. THE contributor documentation SHALL prohibit deriving Ground_Truth from observed review output
16. WHEN a new Guard_Rule or new review logic is added, THE contributor documentation SHALL require at least one Benchmark_Template that exercises the added rule or logic

### Requirement 12: テスト要件

**User Story:** As a contributor, I want comprehensive tests, so that I can validate changes without introducing regressions.

#### Acceptance Criteria

1. THE Plugin SHALL include unit tests for all script-based components (parsers, normalizers, command builders) achieving at least 80 percent line coverage of executable script components
2. THE Plugin SHALL include integration tests that execute the full review pipeline against at least 3 sample CloudFormation Templates and validate that output conforms to the Finding schema defined in Requirement 7, with all required fields present and of the declared types
3. THE Plugin SHALL include negative tests using at least 2 valid, well-configured CloudFormation Templates for which Ground_Truth declares the expected set of Findings
4. WHEN a negative test Template is reviewed, THE deterministic Sources (cfn-lint, cfn-guard, deterministic IAM checks) SHALL produce zero Findings with Severity HIGH or CRITICAL
5. WHEN a negative test Template is reviewed, THE count of Findings produced by deterministic Sources that are absent from Ground_Truth SHALL be zero
6. WHEN the negative test false positive count is computed, THE test harness SHALL exclude Findings whose FindingType is `Informational` or `BestPractice` and whose Severity is LOW or INFO
7. WHEN cfn-lint or cfn-guard is unavailable in the test environment, THE Plugin integration tests SHALL verify that the Skill returns a structured error object containing the tool name and installation instructions, and does not produce an unhandled exception
8. WHEN provided with malformed YAML or JSON input (invalid syntax, truncated files, binary content), THE Plugin SHALL return a structured error response containing the parse error type and location, without producing an unhandled exception
9. THE Plugin SHALL include tests that validate all parser output field mappings between cfn-lint JSON output and the normalized Finding format
10. THE Plugin SHALL include a regression test suite, and WHEN a defect is fixed, THE contributor SHALL add a regression test that reproduces the original defect
11. THE regression test suite SHALL include security-focused cases covering at minimum: path traversal input, malformed YAML, malformed JSON, filenames containing shell metacharacters, missing external tool, and invalid command arguments
12. WHEN a security-relevant change is made to the Plugin, THE contributor SHALL add a corresponding regression test

### Requirement 13: OSS プロジェクト構成とドキュメント

**User Story:** As an open source contributor, I want standard project documentation in English, so that I can understand, use, and contribute to the project regardless of my locale.

#### Acceptance Criteria

1. THE Plugin SHALL include a README.md containing at minimum the following sections as level-2 headings: What is aws-iac-review-agent-plugin, Why this project exists, Architecture, Supported IaC, Requirements, Installation, Using as a Kiro Power, Usage, Review Categories, Examples, Benchmark, Validation, Security Considerations, Known Limitations, Roadmap, Contributing, and License
2. THE README.md "Known Limitations" section SHALL list the features explicitly out of scope for the current version, the absence of sandboxing for `cdk synth`, and the non-deterministic nature of Agent Review output
3. THE Plugin SHALL include a LICENSE file containing the full text of an OSI-approved open source license
4. THE Plugin SHALL include a CONTRIBUTING.md containing the following sections: development environment setup with prerequisite tool versions, coding standards, testing procedures with the commands to run tests, Guard_Rule contribution guide with directory structure and naming conventions, Skill contribution guide, security issue handling process, and pull request process
5. THE Plugin SHALL include a CHANGELOG.md with entries following Keep a Changelog format (headers: Added, Changed, Deprecated, Removed, Fixed, Security) where each entry links to a version tag
6. THE README.md, CONTRIBUTING.md, CHANGELOG.md, LICENSE, and all files under `docs/` SHALL be written in English
7. THE `SKILL.md` file of each Skill SHALL be written in English
8. WHERE Japanese supplementary documentation is provided, THE supplementary file SHALL carry a clearly identifying suffix such as `README.ja.md` and SHALL NOT replace the English original
9. THE Plugin SHALL include a `docs/` directory containing at minimum an architecture document, a security model document, a benchmark methodology document, and a Finding schema reference
10. THE Finding schema reference SHALL document every Finding field including FindingType, Severity, Confidence, Normalized_Category, and Source together with the permitted values of each field
11. THE Plugin documentation SHALL NOT describe unimplemented capabilities as available, and SHALL list planned capabilities in the README.md Roadmap section

### Requirement 14: Finding 正規化と重複排除戦略

**User Story:** As a reviewer, I want duplicated findings consolidated using a stable category vocabulary, so that I see each real issue only once with the best available context from all detection sources.

#### Acceptance Criteria

1. THE Plugin SHALL define a closed set of Normalized_Categories, and every Finding from every Source SHALL be assigned exactly one Category from that set
2. THE Normalized_Category set SHALL include at minimum: `IAM`, `Encryption`, `PublicAccess`, `Logging`, `Tagging`, `Availability`, `Backup`, `NetworkSecurity`, `DataProtection`, and `TemplateQuality`
3. WHEN an Agent Review Finding cannot be mapped to a Normalized_Category in the defined set, THE Review_Engine SHALL assign the Category `Other` and SHALL exclude that Finding from deduplication matching
4. THE Plugin SHALL maintain the mapping from cfn-lint rule prefixes and cfn-guard rule categories to Normalized_Categories, together with the cfn-lint security-relevance mapping referenced in Requirement 4, in a single versioned mapping file
5. THE Review_Engine SHALL determine Finding equivalence by matching on target resource logical ID AND Normalized_Category
6. WHERE a Finding has no target resource logical ID, THE Review_Engine SHALL treat that Finding as matching no other Finding and SHALL include it in the Review_Report as a separate entry
7. WHEN two or more Findings are determined equivalent, THE Review_Engine SHALL merge them into a single Finding entry
8. WHEN merging equivalent Findings, THE Review_Engine SHALL retain the highest Severity across sources using the ordering CRITICAL > HIGH > MEDIUM > LOW > INFO
9. WHEN merging equivalent Findings, THE Review_Engine SHALL retain the highest Confidence across sources using the ordering Confirmed > Likely > Contextual
10. WHEN merging equivalent Findings whose FindingType values differ, THE Review_Engine SHALL retain the FindingType using the precedence `Security` > `Validity` > `BestPractice` > `Informational`
11. WHEN merging equivalent Findings, THE Review_Engine SHALL concatenate Evidence from all detecting sources in the order: cfn-lint first, cfn-guard second, IAM Review third, Agent Review fourth
12. THE Review_Engine SHALL preserve the Source field of a merged Finding as a list naming all sources that detected it
13. WHEN a Finding matches no other Finding on target resource logical ID and Normalized_Category, THE Review_Engine SHALL include it in the Review_Report unmodified

### Requirement 15: 外部ツール実行とパスコンテインメント

**User Story:** As a plugin implementer, I want a clear strategy for executing external tools while respecting Agent Plugins 1.0.0 path containment, so that the plugin remains compliant yet functional.

#### Acceptance Criteria

1. WHEN executing cfn-lint, cfn-guard, or CDK CLI, THE Plugin SHALL invoke the external tool by command name relying on system PATH resolution rather than bundling tool binaries within the plugin directory
2. THE `SKILL.md` of each Skill that invokes an external tool SHALL document that the tool is an external runtime dependency not contained within the plugin package
3. WHEN constructing command arguments, THE Plugin SHALL use relative paths within the workspace or absolute paths provided by the runtime, and SHALL NOT reference plugin-owned resources outside the plugin containment boundary, where plugin-owned resources are the files the Plugin reads or writes as part of its own configuration or rule sets, excluding user workspace files under analysis
4. IF an external tool dependency is not found on the system PATH, THEN THE Plugin SHALL report the tool name, the minimum version required, and the installation command
5. WHERE a user-supplied MCP configuration uses stdio transport, THE configuration example SHALL specify the command as a single executable token with arguments in the `args` array per Agent Plugins 1.0.0
6. IF an external tool is found but reports a version below the minimum required, THEN THE Plugin SHALL report the detected version, the minimum version required, and upgrade instructions
7. IF an external tool exits with a non-zero exit code for reasons other than rule violations, THEN THE Plugin SHALL report the tool name, the exit code, and the first 5 lines of stderr content as an error to the caller

### Requirement 16: 決定論的コンポーネントの実装方針

**User Story:** As a plugin implementer, I want a single explicit implementation policy for deterministic components, so that the plugin stays testable, portable, and safe to run against untrusted input.

#### Acceptance Criteria

1. THE Plugin SHALL implement all deterministic script components in Python 3, where deterministic script components comprise Template parsing, cfn-lint output parsing, cfn-guard output parsing, IAM policy analysis, Finding normalization, Finding deduplication, and benchmark aggregation
2. THE Plugin SHALL limit Shell scripts to simple invocation wrappers containing no conditional data processing logic
3. THE deterministic script components enumerated in acceptance criterion 1 SHALL depend only on the Python standard library plus at most one YAML parsing dependency, and THE Plugin documentation SHALL justify every additional dependency against the dependency criteria recorded in the project technical policy
4. THE Plugin SHALL declare development and test dependencies separately from runtime dependencies, and those development and test dependencies SHALL NOT be subject to the constraint in the preceding criterion
5. THE Python components SHALL declare explicit type annotations on every public function signature
6. THE Plugin scripts SHALL NOT construct shell command strings by concatenating user-supplied input
7. WHEN a script is invoked, THE script SHALL validate all arguments before performing any other work, and IF validation fails, THEN THE script SHALL exit with a documented non-zero exit code
8. THE Plugin SHALL define and document a distinct exit code for each of the following failure classes: invalid arguments, input file not found or unreadable, input parse failure, required external tool unavailable, and external tool execution failure
9. THE Plugin scripts SHALL execute non-interactively and SHALL NOT read prompts for input from stdin
10. THE Plugin scripts SHALL emit machine-readable JSON output on stdout and SHALL emit human-readable diagnostics on stderr
11. WHEN a script is invoked twice with identical input, THE script SHALL produce byte-identical stdout containing no timestamps, no absolute host paths, and no other environment-dependent values

---

## Assumptions / Open Questions

### Assumptions

1. **外部ツール PATH 依存**: cfn-lint, cfn-guard, CDK CLI はシステム PATH に存在する外部コマンドとして呼び出す。Agent Plugins 1.0.0 のパスコンテインメントは plugin-owned ファイルに適用され、外部ツール実行は PATH 解決に委ねられる。
2. **Python 3 は hard dependency**: 決定論的コンポーネントを Python で実装するため、実行環境に Python 3.9 以上が存在することを前提とする。cfn-lint 自体が Python ベースであるため、この前提は追加負担を生まない。
3. **v0.1 は mcp.json を同梱しない**: MCP は opt-in とし、`docs/` 配下に設定例とセキュリティ特性のドキュメントのみを提供する。core 機能は Skills のみで完結する。
4. **CDK レビューは template-first**: v0.1 では既に `cdk synth` 済みのテンプレートをレビューする。CDK ソースからのレビューは明示的なユーザー確認なしに `cdk synth` を実行しない。CDK ビルド環境のセットアップは本プラグインの責任範囲外。
5. **レビューは厳密に read-only**: v0.1 では AWS API 呼び出しを行わず、AWS リソースの作成・変更・削除も行わない。レビューはテンプレートファイルの静的解析のみ。
6. **Agent Review の実装形態**: `cloudformation-review` と `iam-review` における Agent Review は、SKILL.md のガイダンスをホスト Agent ランタイムが解釈する形で実現する。決定論的コード実行ではないため出力は非決定論的であり、Confidence は常に `Likely` または `Contextual` となる。
7. **structure.md との差分**: steering/structure.md は base structure に mcp.json を列挙しているが、これは最終的な target structure を示すものであり、steering/tech.md の「MCP を必須依存にしない」原則に従い v0.1 では意図的に同梱しない。
8. **共有 Python package の配置**: 共有 Python package `iacreview/` を plugin root 直下（`skills/` の外）に配置する。Agent Plugins 1.0.0 の skill discovery は `skills/` 直下の子ディレクトリのみを走査し再帰しないため、`iacreview/` が Skill として誤検出されることはなく、plugin root 内にあるため containment 要件も満たす。steering/structure.md の base structure にはこの package が記載されていないため、structure.md の更新を提案する。
9. **cfn-guard ルールの供給方式（決定済み）**: bundle 済みルールとユーザー指定ルールディレクトリの両方を受け付ける。既定は bundle 済みルールのみとし、追加設定なしでの動作を維持する。ユーザー指定ディレクトリは繰り返し指定可能な `--rules-dir` option で受け取り、workspace root に対するパス検証を通す。
10. **カテゴリマッピングの管理場所（決定済み）**: cfn-lint rule ID から Normalized_Category へのマッピングテーブルは本 Repository で維持する。Normalized_Category は本 Plugin が定義する概念であり、対応する upstream データが存在しないため。

### Open Questions

1. **段階リリースの採否**: v0.1 を v0.1a / v0.1b に分割する提案（下記「スコープに関する提言」）を採用するか。
2. **LICENSE の選定**: 候補は Apache-2.0 と MIT。Design フェーズで根拠とともに提案し、maintainer の確認を経て v0.1 リリース前に確定する。awslabs/agent-plugins の先例は Apache-2.0 であり、整合性の観点では Apache-2.0 が有力。
3. **Windows サポート**: v0.1 は macOS と Linux を対象とする。Windows を明示的にスコープ外とするか確認が必要。
4. **Kiro Power パッケージング**: Kiro Power としてロードする際の正確なディレクトリ配置と Kiro 固有 manifest の必要性を Design フェーズで確定する。
5. **Agent Review 非決定性の扱い**: ベンチマークの再現性を確保するため、Agent Review の変動をどう境界付けるか（例: 複数回実行して変動幅を報告する）。
6. **mapping file の rule ID 母集団**: `blocks_deployment` および `security_relevant` としてマークする cfn-lint rule ID の母集団は、実装時に cfn-lint の rule カタログを調査して決定する必要がある。v0.1 で調査が完了しない場合は保守的な prefix 既定値をそのまま採用し、CRITICAL の付与が保守的であること、および一部のデプロイ阻害エラーが HIGH として報告されることを README.md の Known Limitations に明記する。

### スコープに関する提言

v0.1 の Definition of Done は意欲的であるため、以下の段階的アプローチを提案する:

- **v0.1a (MVP)**: Plugin 構造 + Python 決定論的コンポーネント基盤 (Requirement 16) + cfn-lint-review + cfn-guard-review + iac-review オーケストレーション + 統一レポート (FindingType / Confidence / Normalized_Category を含む) + 基本テスト
- **v0.1b**: iam-review + cloudformation-review (Agent Review) + Benchmark_Harness + docs/ 一式
- **v0.2**: CDK ソースからのレビュー体験の強化 + Benchmark 比較モード拡張 (agent-only, human-review) + MCP enhancement

CDK の自動 `cdk synth` は arbitrary code execution リスクを伴うため v0.1 スコープ外とし、v0.1 では synth 済みテンプレートのレビュー（Requirement 8）に限定する。この段階分けにより、早期に動作するプラグインをリリースしつつ品質を維持できる。
