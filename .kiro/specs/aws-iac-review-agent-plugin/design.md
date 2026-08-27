# Design Document

## Overview

本 Plugin は AWS Infrastructure as Code (主に CloudFormation Template) を、決定論的な静的解析ツールと Agent 推論の両方でレビューし、単一の正規化された Finding 集合として出力する Agent Plugins 1.0.0 準拠パッケージである。

### 中核となる設計テーゼ

steering/development-principles.md の「Agent にすべて判断させない」原則を、アーキテクチャの第一級の制約として扱う。

- **決定論的に判定できるものは、決定論的コードとツールが判定する**。cfn-lint、cfn-guard、および Python による IAM パターンマッチが担当し、結果は `Confidence: Confirmed` を得る (Requirement 7 AC8, AC9)。
- **文脈・関係性・妥当性の評価のみを Agent が担当する**。Agent 由来の Finding は `Confidence: Likely` または `Contextual` に限定され、`Confirmed` を得られない (Requirement 7 AC10)。
- **両者の出力は同一の Finding schema に正規化され、同一のアルゴリズムで重複排除される** (Requirement 7, Requirement 14)。

この分離により、Agent の非決定性がレビュー結果全体の再現性を破壊することを防ぐ。決定論的部分は同一入力に対して byte-identical な stdout を返す (Requirement 16 AC11) ため、ベンチマークと回帰テストの基盤として機能する。

### 構築するもの (v0.1)

| 構成要素 | 内容 | 根拠 |
| --- | --- | --- |
| Plugin package | `plugin.json` + `skills/` を持つ Agent Plugins 1.0.0 パッケージ | Requirement 1 |
| 5 つの Skill | `cfn-lint-review`, `cfn-guard-review`, `iam-review`, `cloudformation-review`, `iac-review` | Requirement 2 |
| Python 決定論的コア | Template 解析、ツール出力解析、IAM 解析、正規化、重複排除、benchmark 集計 | Requirement 16 AC1 |
| Guard rule set | 6 カテゴリ (Encryption, PublicAccess, Logging, Tagging, IAM, Backup) 以上 | Requirement 5 AC2 |
| 統一 Review_Report | 13 フィールドを持つ Finding の JSON 配列 + summary | Requirement 7 |
| Benchmark harness | Ground_Truth 照合と指標算出 | Requirement 11 |
| Test suite | Unit / Integration / Negative / Regression / Tool-unavailable | Requirement 12 |
| OSS documentation | README, CONTRIBUTING, CHANGELOG, LICENSE, `docs/` 4 文書 | Requirement 13 |

### v0.1 で構築しないもの

steering/product.md の非目標および Requirement の明示的除外に従う。

| 除外項目 | 根拠 |
| --- | --- |
| `mcp.json` の同梱 | Requirement 1 AC7。`docs/` 配下に opt-in 例のみ提供 (AC8) |
| 自動 `cdk synth` 実行 | Requirement 8 AC3。明示的確認が必要 (AC4) |
| AWS API 呼び出し / 自動修正 / Deploy | Requirement 9 AC3、steering/security.md |
| Terraform / Pulumi 対応 | steering/product.md 非目標 |
| Runtime Security / FinOps / 完全な Well-Architected Review | steering/product.md 非目標 |
| Web UI | steering/product.md 非目標 |
| Windows サポート | Requirement 10 AC3 は macOS / Linux のみを対象とする |
| Benchmark の `agent-only` / `human-review` モード実装 | Requirement 11 AC12 はフィールド予約のみを求める |
| Review Time / Remediation Accuracy / Human Intervention Count の計測 | Requirement 11 AC13 で deferred と定義 |

### 要求仕様の訂正・上書き

設計が requirements.md の記述を訂正する箇所を「[Correction] 要求仕様への訂正事項」節にまとめる。requirements.md へ反映すべき差分として扱う。

---

## Architecture

### Review pipeline

```mermaid
flowchart TD
    subgraph INPUT["Input (Untrusted)"]
        A1["CloudFormation Template<br/>(YAML / JSON)"]
        A2["Directory<br/>(cdk.json / cdk.out)"]
    end

    subgraph DET["Deterministic Layer (Python 3 + external tools)"]
        B1["path_guard<br/>path containment"]
        B2["template_loader<br/>YAML/JSON parse + Resources check"]
        B3["cfn-lint runner<br/>subprocess argv"]
        B4["cfn-guard runner<br/>subprocess argv"]
        B5["iam_scan<br/>deterministic detectors"]
        B6["normalizer<br/>+ category_map"]
        B7["dedup<br/>merge rules"]
        B8["report<br/>sort + summary + JSON"]
    end

    subgraph AG["Agent Reasoning Layer (SKILL.md guidance)"]
        C1["cloudformation-review<br/>cross-resource / architecture"]
        C2["iam-review reasoning<br/>contextual IAM risk"]
    end

    A1 --> B1
    A2 --> B1
    B1 --> B2
    B2 --> B3
    B2 --> B4
    B2 --> B5
    B2 -.->|"normalized template facts JSON"| C1
    B2 -.->|"extracted policy documents JSON"| C2
    B3 --> B6
    B4 --> B6
    B5 --> B6
    C1 -.->|"agent findings JSON, Confidence not Confirmed"| B6
    C2 -.->|"agent findings JSON, Confidence not Confirmed"| B6
    B6 --> B7 --> B8
    B8 --> D["Review_Report<br/>stdout JSON"]

    classDef det fill:#e8f4ff,stroke:#2b6cb0
    classDef agent fill:#fff5e6,stroke:#b7791f
    class B1,B2,B3,B4,B5,B6,B7,B8 det
    class C1,C2 agent
```

境界の読み方: 実線は決定論的なデータフロー、点線は Agent を経由するフローである。Agent は **Finding を生成することはできるが、Finding を正規化・重複排除・整列することはできない**。正規化以降は必ず決定論的コードを通る。これにより Requirement 7 AC15 (整列順序) と Requirement 16 AC11 (byte-identical 出力) が Agent の揺らぎから保護される。

### レイヤ責務

| レイヤ | 実装 | 保証 |
| --- | --- | --- |
| Input validation | Python (`path_guard`, `argv` validation) | Requirement 9 AC4, AC5、Requirement 16 AC7 |
| Deterministic detection | cfn-lint, cfn-guard, `iam_scan` | `Confidence: Confirmed` (Requirement 7 AC8, AC9) |
| Semantic reasoning | Host Agent runtime が SKILL.md を解釈 | `Confidence: Likely` / `Contextual` (Requirement 7 AC10) |
| Normalization | Python (`normalizer` + `category_map.json`) | Category 閉集合 (Requirement 14 AC1) |
| Aggregation | Python (`dedup`, `report`) | 決定論的マージと整列 (Requirement 14, Requirement 7 AC15) |

### Agent 出力の受け渡し方式

Agent Review は決定論的コード実行ではない (requirements.md Assumption 6)。したがって Agent は自然言語ではなく **Finding schema に適合した JSON を生成し、それを正規化スクリプトの stdin ではなくファイル経由で渡す** 設計を採る。

- SKILL.md が Agent に対して、生成すべき JSON の schema と許可値を明示する。
- Agent は生成した JSON を workspace 内の一時ファイルへ書き、`iac_review.py --agent-findings <path>` に渡す。
- 正規化スクリプトは受け取った JSON を **厳格に検証** する。schema 違反・`Confidence: Confirmed` の指定・閉集合外の Category はエラーまたは補正 (`Other` へのフォールバック、Requirement 14 AC3) として扱う。

この方式を選ぶ理由は、Requirement 16 AC9 が「stdin からプロンプト入力を読まない」ことを求めており、かつ Agent 出力を検証可能な境界に閉じ込める必要があるためである。Agent を信頼して正規化を任せる設計は steering/development-principles.md の「決定論的処理と Agent 判断を分離する」に反する。

---

## The Deterministic / Agent Boundary

本節は設計上最も重要な決定である。steering/development-principles.md は「既存ツールで確実に判定できるものは、既存ツールを利用する」ことを求め、Requirement 2 AC15 は「cfn-lint または cfn-guard が確実に実行するチェックは外部ツールに委譲する」ことを義務付ける。以下の表は、レビュー観点ごとの担当を確定させたものである。

| # | Review concern | 担当 | 理由 |
| --- | --- | --- | --- |
| 1 | YAML / JSON 構文の妥当性 | Deterministic Python (`template_loader`) | Parse は完全に決定論的。行番号・列番号を返す必要がある (Requirement 3 AC6)。Agent に parse させると位置情報が不正確になる |
| 2 | CloudFormation 固有構文 (intrinsic function 形式、Ref 先の存在) | cfn-lint (`E1xxx`) | cfn-lint が Resource Specification を保持している。再実装は steering/tech.md「AI Agent に cfn-lint と同じ判定を再実装させない」に違反 |
| 3 | Resource property の型・必須・許可値 | cfn-lint (`E3xxx`) | 同上。AWS の spec 更新に追随する責務を upstream に委ねる |
| 4 | Parameters / Outputs / Mappings / Conditions の整合性 | cfn-lint (`E2xxx`, `E6xxx`, `E7xxx`, `E8xxx`) | 同上 |
| 5 | 非推奨・冗長な記述 (Warning / Informational) | cfn-lint (`W`, `I`) | 同上 |
| 6 | 明示的な組織ポリシー (暗号化必須、Public Access 禁止、Logging 必須、Tag 必須、Backup 必須) | cfn-guard | steering/tech.md「組織ポリシーや明示的な Infrastructure Policy の検証には cfn-guard を利用する」。ルールは宣言的に再利用可能 (Requirement 5 AC8) |
| 7 | IAM の構造的危険パターン (`Action: "*"` + `Resource: "*"`、既知の privilege escalation action 名、Principal `"*"`) | Deterministic Python (`iam_scan`) | 列挙可能な有限集合の照合であり、Requirement 6 AC1/AC5/AC9 が具体的な action 名を指定している。決定論的に判定でき `Confirmed` を付与すべき。cfn-guard でも一部表現可能だが、statement 単位の走査と Condition 相関評価は Guard DSL では表現が煩雑になるため Python を選ぶ |
| 8 | Cross-account Principal の検出 (12 桁 account ID、`AWS::AccountId` 判別、`sts:ExternalId` による severity 減算) | Deterministic Python (`iam_scan`) | Requirement 6 AC7-AC10 が判定規則を完全に規定している。規則が明文化されている以上 Agent 推論は不要かつ不安定 |
| 9 | Finding の Category 割り当て | Deterministic Python (`category_map.json`) | Requirement 14 AC4 が単一の versioned mapping file での維持を要求。Agent に都度判断させると閉集合性 (AC1) が壊れる |
| 10 | Severity / Confidence / FindingType の決定 (決定論的 Source 由来) | Deterministic Python (`normalizer`) | Requirement 4 AC3-AC9、Requirement 7 AC8/AC9 が写像を規定 |
| 11 | Finding の重複排除とマージ | Deterministic Python (`dedup`) | Requirement 14 AC5-AC13 がアルゴリズムを規定。決定論性が必須 |
| 12 | Finding の整列と summary 集計 | Deterministic Python (`report`) | Requirement 7 AC15, AC17。Requirement 16 AC11 の byte-identical 要件を満たすため |
| 13 | 複数 Resource 間の関係性リスク (例: Lambda の実行ロールが同テンプレート内の S3 バケットへ過剰権限を持つ) | Agent reasoning | 関係性の意味的評価。cfn-lint は Resource 単位、cfn-guard は宣言的条件のみを扱い、リソース横断の意図を評価できない。Requirement 2 AC14 が明示的にこの範囲を Agent に割り当てている |
| 14 | Architecture risk (単一 AZ 構成、SPOF、スケーラビリティ上の懸念) | Agent reasoning | 「妥当かどうか」は文脈依存であり閉じたルールに落とせない。steering/development-principles.md が Agent 処理として列挙 |
| 15 | AWS Best Practice の妥当性評価 (ルール化されていない推奨) | Agent reasoning | 同上 |
| 16 | Severity の文脈評価 (例: 開発環境向けテンプレートでの緩い設定の位置づけ) | Agent reasoning | steering/development-principles.md が Agent 処理として列挙。ただし決定論的 Source が付与した Severity を Agent が書き換えることは許さない (後述) |
| 17 | 修正理由の説明 (WhyItMatters の文章化) | Agent reasoning (決定論的 Source は固定文言) | 決定論的 Source は mapping file の固定文言を使用し、Agent Finding のみ生成文を使う。これにより決定論的部分の出力が安定する |
| 18 | 修正案の提示 (SuggestedRemediation) | 両方 | cfn-guard rule は custom message (`<<`) で remediation を持つ (Requirement 5 AC3)。Agent Finding は生成文を持つ。いずれも自動適用しない (steering/security.md) |

### 境界に関する 3 つの禁止事項

steering/development-principles.md の分離原則から導かれる。

1. **Agent は決定論的 Source の Finding の Severity / Confidence / FindingType / Category を書き換えられない**。Agent は自身の Finding を追加できるのみである。上記 #16 の「文脈評価」は Agent Finding として独立に出力され、`dedup` のマージ規則 (Requirement 14 AC8-AC10) を通じてのみ最終 Severity に影響する。マージは最大値を採るため、Agent が Severity を下げることは構造的に不可能である。
2. **Agent は正規化・重複排除・整列を行わない**。すべて Python が行う。
3. **Agent は `Confidence: Confirmed` を出力できない**。`normalizer` は Agent 由来の Finding に `Confirmed` が指定されていた場合、`Likely` へ降格し警告を stderr に出す (Requirement 7 AC10)。

### 決定論的 IAM 検査を Agent ではなく Python にした理由

Requirement 6 は 13 の acceptance criteria のうち AC1, AC4, AC5, AC7, AC8, AC9, AC10, AC11 で **具体的な action 名・値・判定規則を列挙している**。列挙された規則の照合は定義上決定論的であり、Agent に委ねる理由がない。steering/development-principles.md の「Agent による処理」に挙がっているのは「IAM の文脈的評価」であって「IAM の構造的照合」ではない。したがって Requirement 6 は 2 層に分割する (「IAM Review Architecture」節参照)。

---

## Directory Structure

### 完全なツリー

```text
aws-iac-review-agent-plugin/
├── plugin.json                              # Agent Plugins 1.0.0 manifest (Req 1 AC1)
├── iacreview/                               # 共有 Python package (Req 2 AC16)
│   ├── __init__.py
│   ├── bootstrap.py                         # sys.path 解決 helper
│   ├── errors.py                            # 例外階層 + exit code 定義 (Req 16 AC8)
│   ├── exitcodes.py
│   ├── pathguard.py                         # path containment (Req 9 AC5, Req 15)
│   ├── proc.py                              # argv-array subprocess wrapper (Req 9 AC4)
│   ├── toolcheck.py                         # PATH 探索 + version 検証 (Req 15 AC4, AC6)
│   ├── template.py                          # YAML/JSON loader + Resources 判定 (Req 3)
│   ├── yamlcfn.py                           # CloudFormation 短縮タグ対応 SafeLoader
│   ├── finding.py                           # Finding dataclass + schema validation (Req 7)
│   ├── categories.py                        # category_map.json loader (Req 14 AC4)
│   ├── category_map.json                    # 単一 versioned mapping file (Req 14 AC4)
│   ├── cfnlint.py                           # cfn-lint 実行 + 出力正規化 (Req 4)
│   ├── cfnguard.py                          # cfn-guard 実行 + 出力正規化 (Req 5)
│   ├── iam/
│   │   ├── __init__.py
│   │   ├── locate.py                        # policy document 抽出 (Req 6)
│   │   ├── detectors.py                     # 決定論的検出器 (Req 6 AC1-AC11)
│   │   └── intrinsics.py                    # Ref / Fn::Sub 等の解決方針
│   ├── agentin.py                           # Agent 生成 JSON の検証 (Req 7 AC10)
│   ├── dedup.py                             # 等価判定 + マージ (Req 14 AC5-AC13)
│   ├── report.py                            # 整列 + summary + JSON 出力 (Req 7 AC15, AC17)
│   └── cdk.py                               # cdk.json / cdk.out 検出 (Req 8)
├── skills/
│   ├── cfn-lint-review/
│   │   ├── SKILL.md
│   │   └── scripts/
│   │       └── run_cfn_lint.py              # entry point (thin)
│   ├── cfn-guard-review/
│   │   ├── SKILL.md
│   │   └── scripts/
│   │       └── run_cfn_guard.py
│   ├── iam-review/
│   │   ├── SKILL.md
│   │   └── scripts/
│   │       ├── run_iam_scan.py
│   │       └── extract_policies.py          # Agent 推論用の入力抽出
│   ├── cloudformation-review/
│   │   ├── SKILL.md
│   │   └── scripts/
│   │       └── extract_facts.py             # Agent 推論用の template facts 抽出
│   └── iac-review/
│       ├── SKILL.md
│       └── scripts/
│           └── run_iac_review.py            # orchestrator entry point
├── rules/                                   # cfn-guard rules (Req 5 AC8)
│   ├── encryption/
│   │   ├── s3_bucket_encryption.guard
│   │   ├── rds_storage_encrypted.guard
│   │   └── _meta.json                       # severity metadata sidecar
│   ├── public-access/
│   │   ├── s3_public_access_block.guard
│   │   ├── security_group_open_ingress.guard
│   │   ├── rds_publicly_accessible.guard
│   │   └── _meta.json
│   ├── iam/
│   │   ├── iam_policy_no_star_star.guard
│   │   └── _meta.json
│   ├── logging/
│   │   ├── s3_access_logging.guard
│   │   ├── cloudtrail_enabled.guard
│   │   └── _meta.json
│   ├── backup/
│   │   ├── rds_backup_retention.guard
│   │   ├── rds_deletion_protection.guard
│   │   └── _meta.json
│   └── tagging/
│       ├── required_tags.guard
│       └── _meta.json
├── benchmark/                               # Req 11
│   ├── README.md
│   ├── cases/
│   │   ├── case-001-iam-wildcard/
│   │   │   ├── template.yaml
│   │   │   └── ground_truth.json
│   │   ├── case-002-public-s3/
│   │   ├── case-003-encryption-disabled/
│   │   ├── case-004-logging-disabled/
│   │   ├── case-005-permissive-sg/
│   │   ├── case-006-missing-backup/
│   │   ├── case-007-missing-tags/
│   │   ├── case-008-unsafe-passrole/
│   │   ├── case-009-public-database/
│   │   ├── case-010-missing-deletion-protection/
│   │   ├── case-101-clean-web-tier/          # negative case (Req 12 AC3)
│   │   └── case-102-clean-data-tier/         # negative case
│   ├── ground_truth.schema.json
│   └── harness/
│       ├── __init__.py
│       ├── run_benchmark.py
│       └── metrics.py
├── examples/                                # Req 13 / steering/structure.md
│   ├── minimal-s3/
│   │   └── template.yaml
│   ├── lambda-with-role/
│   │   └── template.yaml
│   └── cdk-synth-output/
│       └── README.md
├── tests/                                   # Req 12
│   ├── conftest.py
│   ├── unit/
│   │   ├── test_pathguard.py
│   │   ├── test_template.py
│   │   ├── test_cfnlint_parse.py
│   │   ├── test_cfnguard_parse.py
│   │   ├── test_categories.py
│   │   ├── test_iam_detectors.py
│   │   ├── test_dedup.py
│   │   ├── test_report.py
│   │   └── test_proc.py
│   ├── property/
│   │   ├── test_prop_finding_schema.py
│   │   ├── test_prop_dedup.py
│   │   ├── test_prop_merge.py
│   │   ├── test_prop_categories.py
│   │   ├── test_prop_determinism.py
│   │   └── test_prop_pathguard.py
│   ├── integration/
│   │   ├── test_pipeline_end_to_end.py
│   │   ├── test_tool_unavailable.py
│   │   └── test_malformed_input.py
│   ├── negative/
│   │   └── test_clean_templates.py
│   ├── regression/
│   │   ├── test_sec_path_traversal.py
│   │   ├── test_sec_shell_metacharacters.py
│   │   ├── test_sec_malformed_yaml.py
│   │   ├── test_sec_malformed_json.py
│   │   └── test_sec_invalid_arguments.py
│   ├── fixtures/
│   │   ├── valid/
│   │   ├── invalid/
│   │   ├── tool_output/
│   │   └── security/
│   └── fakebin/                             # PATH 差し替え用の偽ツール (Req 12 AC7)
│       ├── cfn-lint-missing/
│       ├── cfn-lint-crash/
│       └── cfn-lint-oldversion/
├── docs/                                    # Req 13 AC9
│   ├── architecture.md
│   ├── security-model.md
│   ├── benchmark-methodology.md
│   ├── finding-schema.md
│   ├── kiro-power.md                        # Kiro 固有手順 (Req 10 AC7, AC9)
│   └── mcp/
│       ├── README.md                        # MCP の目的・権限・リスク (Req 1 AC8)
│       └── mcp.json.example                 # opt-in 設定例
├── .kiro/                                   # Kiro 固有ファイル (steering/structure.md)
│   ├── steering/
│   └── specs/
├── pyproject.toml                           # test/lint 設定 (パッケージ配布はしない)
├── README.md
├── README.ja.md                             # Req 13 AC8
├── CONTRIBUTING.md
├── CHANGELOG.md
└── LICENSE
```

### steering/structure.md との差分と理由

| 差分 | 理由 |
| --- | --- |
| `mcp.json` がルートに無い | Requirement 1 AC7 が v0.1 での非同梱を要求。requirements.md Assumption 7 の通り structure.md は target structure を示すものであり、steering/tech.md「MCP を基本機能の必須依存にしない」に従う。opt-in 例は `docs/mcp/mcp.json.example` に置き、コピー手順を `docs/mcp/README.md` に記載する (Requirement 1 AC8) |
| `iacreview/` がルートに追加 | 後述の共有コード配置問題の解決。structure.md は「同じ種類のファイルはまとめる」「役割が不明確なファイルを Root に増やさない」を求めており、明確な単一責務を持つ package ディレクトリはこれに適合する |
| `benchmark/cases/` の階層化 | structure.md は「Benchmark 用ファイルと通常 Example を混在させない」ことのみ要求。case ごとに template と ground truth を同居させると対応関係が自明になる |
| `tests/property/` の追加 | steering/testing.md の Determinism 要件を property-based test として実装する。詳細は Testing Strategy 節 |

### 共有 Python コードの配置 (Requirement 2 AC16 の解決)

**問題**: Requirement 2 AC16 は「各正規化ルーチンと各解析ルーチンを、必要とする全 Skill が共有する厳密に 1 箇所に実装する」ことを求める。一方 Agent Plugins 1.0.0 の skill discovery は `skills/` の **直下の子ディレクトリのみ** を走査し、再帰しない。また containment 要件により、すべての package-relative path は plugin root 内に解決されなければならない。各 Skill が独自の `scripts/` を持つ構造では、共有コードの置き場所が自明でない。

**検討した 3 案**:

| 案 | 内容 | 評価 |
| --- | --- | --- |
| A. 複製 | 各 Skill の `scripts/` に共有コードをコピー | **却下**。Requirement 2 AC16 に直接違反する。steering/agent-plugin-standards.md「同一処理を複数 Skill へ重複実装しない」にも違反 |
| B. 単一 entry-point script | すべての機能を `skills/iac-review/scripts/` の 1 スクリプトに集約し、他 Skill は SKILL.md で「iac-review のスクリプトを使え」と指示 | **却下**。Requirement 2 AC6-AC9 が各 Skill の独立動作を要求しており、他 Skill のディレクトリへの依存は責務分離を壊す。steering/structure.md「巨大な単一 Skill を作らない」にも反する |
| C. plugin root 直下の共有 package | `iacreview/` を `skills/` の外・plugin root 直下に置き、各 Skill の entry-point script が path bootstrap で import する | **採用** |

**案 C の採用理由**:

- `skills/` の直下に置かないため、`iacreview/` が Skill として誤検出されることがない (discovery は `skills/` の子のみを見るため、そもそも走査対象外)。
- plugin root 内にあるため containment 要件を満たす。
- 実装が厳密に 1 箇所となり Requirement 2 AC16 を満たす。
- 各 Skill は独自の entry-point を保持するため Requirement 2 AC6-AC9 の独立動作を満たす。

**path bootstrap の具体実装**: 各 entry-point script の先頭で以下を行う。

```python
# skills/cfn-lint-review/scripts/run_cfn_lint.py
import sys
from pathlib import Path

# scripts/ -> skill dir -> skills/ -> plugin root
_PLUGIN_ROOT = Path(__file__).resolve().parents[3]
if str(_PLUGIN_ROOT) not in sys.path:
    sys.path.insert(0, str(_PLUGIN_ROOT))

from iacreview.cfnlint import run_and_normalize  # noqa: E402
```

`Path(__file__).resolve()` を用いることで symlink を解決した実体パスから plugin root を導出する。これは Agent Plugins 1.0.0 の「filesystem-resolved plugin root」の定義と一致する。

**トレードオフ**:

| 項目 | 影響 |
| --- | --- |
| 4 行の bootstrap boilerplate が 6 スクリプトに複製される | 許容する。共有コードそのものの複製ではなく、固定の 4 行である。これを共有ライブラリ化すると、その共有ライブラリを import するための bootstrap が必要になり循環する |
| `parents[3]` が相対深さに依存する | `iacreview/pathguard.py` に plugin root 検証関数を置き、bootstrap 直後に `plugin.json` の存在を確認する。存在しなければ明確なエラーで終了する。深さ変更を伴うディレクトリ移動は test で検出される |
| Python package として `pip install` されない | 意図的である。Requirement 15 AC1 に従い binary を bundle せず、plugin はディレクトリとして配布される。`pyproject.toml` は test / lint 設定のみを保持する |
| Agent Plugins 1.0.0 は共有コードの配置を規定していない | steering/agent-plugin-standards.md「Specification が曖昧な場合」に従い、最も保守的な選択 (仕様が規定する discovery 対象と衝突しない位置) を採り、本節を Assumption として記録する |

---

## Components and Interfaces

すべての Python public function に明示的な型注釈を付与する (Requirement 16 AC5)。

### `iacreview.pathguard`

| 項目 | 内容 |
| --- | --- |
| 責務 | ユーザー入力パスの検証と workspace / plugin root への封じ込め |
| Public API | `resolve_within(candidate: str, root: Path) -> Path`<br/>`assert_no_shell_metacharacters(value: str) -> None`<br/>`plugin_root() -> Path` |
| Input | ユーザー指定の相対 / 絶対パス文字列、root ディレクトリ |
| Output | 解決済み絶対 `Path` |
| Failure modes | `PathContainmentError` (root 外に解決)、`UnsafeArgumentError` (shell metacharacter 検出)、`InputNotFoundError` (存在しない / 読めない) |
| 根拠 | Requirement 9 AC4, AC5、Requirement 15 AC3、Requirement 1 AC3 |

### `iacreview.proc`

| 項目 | 内容 |
| --- | --- |
| 責務 | 外部コマンドの argv-array 実行 |
| Public API | `run(argv: list[str], timeout_s: int) -> ProcResult`<br/>`ProcResult(exit_code: int, stdout: str, stderr: str, timed_out: bool)` |
| Input | argv リスト (第 0 要素は実行可能名 1 トークン)、timeout 秒 |
| Output | `ProcResult` |
| Failure modes | `ToolUnavailableError` (PATH に無い)、`ToolTimeoutError`、`ToolExecutionError` |
| 制約 | `shell=False` 固定。文字列連結によるコマンド構築を行わない (Requirement 16 AC6)。`stdin` は `subprocess.DEVNULL` (Requirement 16 AC9) |
| 根拠 | Requirement 9 AC4、Requirement 16 AC6, AC9 |

### `iacreview.toolcheck`

| 項目 | 内容 |
| --- | --- |
| 責務 | 外部ツールの PATH 解決と最低バージョン検証 |
| Public API | `require_tool(name: str, min_version: str, version_argv: list[str]) -> ToolInfo` |
| Output | `ToolInfo(name: str, path: str, version: str)` |
| Failure modes | `ToolUnavailableError` (ツール名 + 最低バージョン + インストールコマンドを含む)、`ToolVersionError` (検出バージョン + 要求バージョン + upgrade 手順を含む) |
| 根拠 | Requirement 15 AC4, AC6、Requirement 4 AC10、Requirement 5 AC5 |

### `iacreview.template`

| 項目 | 内容 |
| --- | --- |
| 責務 | Template の読み込み、形式判定、reviewable 判定 |
| Public API | `load_template(path: Path) -> LoadedTemplate`<br/>`is_reviewable(doc: object) -> bool` |
| Output | `LoadedTemplate(path: Path, doc: dict, fmt: Literal["yaml","json"])` |
| Failure modes | `TemplateParseError(error_type: str, line: int, column: int)` (Requirement 3 AC6)、`NotReviewableError(path: str)` (Requirement 3 AC5) |
| 判定基準 | top-level `Resources` が mapping であり 1 件以上の entry を持つ (Requirement 3 AC1) |

`yamlcfn.py` は CloudFormation 短縮タグ (`!Ref`, `!GetAtt`, `!Sub`, `!If` 等) を扱う `yaml.SafeLoader` サブクラスを提供する。短縮タグは対応する長形式 mapping (`{"Ref": ...}`) へ変換して保持する。これにより下流の IAM 解析が形式差を意識しなくて済む。`SafeLoader` 派生であるため任意 Python オブジェクト構築は起こらない (Requirement 9 AC7)。

### `iacreview.finding`

| 項目 | 内容 |
| --- | --- |
| 責務 | Finding の正準表現と schema 検証 |
| Public API | `Finding` dataclass、`validate(f: Finding) -> None`、`to_dict(f: Finding) -> dict`、`from_dict(d: dict) -> Finding` |
| Failure modes | `SchemaViolationError(field: str, reason: str)` |
| 根拠 | Requirement 7 AC1-AC13 |

### `iacreview.categories`

| 項目 | 内容 |
| --- | --- |
| 責務 | `category_map.json` の読み込みと参照 API |
| Public API | `load_map(path: Path \| None = None) -> CategoryMap`<br/>`CategoryMap.for_cfnlint_rule(rule_id: str) -> CategoryDecision`<br/>`CategoryMap.for_guard_rule(rule_name: str) -> CategoryDecision`<br/>`CategoryMap.is_valid_category(name: str) -> bool` |
| Output | `CategoryDecision(category: str, finding_type: str \| None, severity_override: str \| None, why_it_matters: str)` |
| Failure modes | `MappingFileError` (読み込み / schema 不正)。未知の rule ID は例外ではなく既定値 (prefix 規則 → 該当なしなら `TemplateQuality` / `Other`) を返す |
| 根拠 | Requirement 14 AC4 |

### `iacreview.cfnlint` / `iacreview.cfnguard`

| 項目 | 内容 |
| --- | --- |
| 責務 | ツール実行 + 出力の Finding 化 |
| Public API | `run_and_normalize(template: Path, tool: ToolInfo) -> SourceResult`<br/>`parse_output(raw: str) -> list[RawResult]` (実行と分離してテスト可能にする) |
| Output | `SourceResult(source: str, findings: list[Finding], errors: list[StructuredError], stats: dict)` |
| Failure modes | ツール未導入 / バージョン不足 / crash / 出力 JSON 不正。いずれも `SourceResult.errors` に構造化エラーとして格納し、pipeline を止めない (Requirement 4 AC12、Requirement 5 AC6) |

実行 (`run_and_normalize`) と解析 (`parse_output`) を分離するのは Requirement 12 AC9 が「cfn-lint JSON 出力と正規化 Finding 形式の全フィールド対応を検証するテスト」を要求しており、固定 fixture に対する純関数テストが必要なためである。

### `iacreview.iam`

| 項目 | 内容 |
| --- | --- |
| 責務 | Template 内 policy document の抽出と決定論的検出 |
| Public API | `locate.find_policy_documents(doc: dict) -> list[PolicySite]`<br/>`detectors.scan(sites: list[PolicySite]) -> list[Finding]` |
| Output | `PolicySite(logical_id: str, kind: PolicyKind, json_path: str, document: dict)` |
| Failure modes | 解決不能な intrinsic function (方針は IAM 節参照)。policy document が dict でない場合は `Informational` Finding として記録し例外にしない |

### `iacreview.agentin`

| 項目 | 内容 |
| --- | --- |
| 責務 | Agent 生成 JSON の検証と正規化 |
| Public API | `load_agent_findings(path: Path) -> tuple[list[Finding], list[StructuredError]]` |
| 検証内容 | schema 適合、許可値、`Confidence != Confirmed` の強制、Category 閉集合 (外れたら `Other`)、Evidence 必須 (Requirement 7 AC11) |
| Failure modes | 個別 Finding の不正は当該 Finding を drop し `StructuredError` を記録する。ファイル全体の JSON 不正は `SchemaViolationError` |

### `iacreview.dedup`

| 項目 | 内容 |
| --- | --- |
| 責務 | 等価判定とマージ |
| Public API | `deduplicate(findings: list[Finding]) -> list[Finding]` |
| Failure modes | なし (純関数)。入力が schema 不正な場合は呼び出し前に検証済みであることを前提とし、`assert` ではなく `SchemaViolationError` で早期失敗する |

### `iacreview.report`

| 項目 | 内容 |
| --- | --- |
| 責務 | ID 付与、整列、summary 集計、JSON 直列化 |
| Public API | `build_report(findings: list[Finding], errors: list[StructuredError], meta: ReportMeta) -> dict`<br/>`dump(report: dict) -> str` |
| 制約 | `json.dumps(..., sort_keys=True, ensure_ascii=False, separators=(",", ": "), indent=2)` + 末尾改行。timestamp / 絶対パスを含まない (Requirement 16 AC11) |

### `iacreview.cdk`

| 項目 | 内容 |
| --- | --- |
| 責務 | `cdk.json` の検出と `cdk.out` 配下の synth 済み Template の列挙 |
| Public API | `detect_cdk_project(directory: Path) -> CdkDetection`<br/>`find_synthesized_templates(directory: Path) -> list[Path]` |
| 制約 | `cdk synth` を自動実行しない (Requirement 8 AC3) |

---

## Skill Design

### plugin.json

Agent Plugins 1.0.0 の `plugin.json` schema は **closed** である。許可される top-level field は `$schema`, `name`, `version`, `description`, `author`, `homepage`, `repository`, `license`, `keywords`, `extensions` のみで、`hooks` / `agents` / `commands` / `mcpServers` / `lspServers` を top-level に置いてはならない。

```json
{
  "$schema": "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json",
  "name": "aws-iac-review-agent-plugin",
  "version": "0.1.0",
  "description": "Reviews AWS CloudFormation and synthesized CDK templates by combining deterministic static analysis (cfn-lint, cfn-guard, IAM pattern matching) with agent semantic review, and emits a single normalized finding report.",
  "author": {
    "name": "aws-iac-review-agent-plugin maintainers"
  },
  "homepage": "https://github.com/<org>/aws-iac-review-agent-plugin",
  "repository": "https://github.com/<org>/aws-iac-review-agent-plugin",
  "license": "Apache-2.0",
  "keywords": [
    "aws",
    "cloudformation",
    "cdk",
    "iac",
    "security-review",
    "iam",
    "cfn-lint",
    "cfn-guard"
  ]
}
```

`name` は `^[a-z0-9]([a-z0-9._-]*[a-z0-9])?$` に適合し 30 文字で 128 文字上限内 (Requirement 1 AC5)。`version` は semver (Requirement 1 AC6)。`extensions` は v0.1 では出現させない (理由は Portability 節)。

### Skill 一覧

| Skill | 種別 | 外部依存 | 出力 |
| --- | --- | --- | --- |
| `cfn-lint-review` | Deterministic | cfn-lint, Python 3 | Finding JSON |
| `cfn-guard-review` | Deterministic | cfn-guard, Python 3 | Finding JSON |
| `iam-review` | Hybrid | Python 3 | Finding JSON (deterministic) + Agent Finding |
| `cloudformation-review` | Agent | Python 3 (facts 抽出のみ) | Agent Finding |
| `iac-review` | Orchestrator | 上記すべて (optional) | Review_Report |

### SKILL.md 共通構造

Requirement 2 AC11-AC13 が front matter と節を規定する。全 SKILL.md は英語 (Requirement 13 AC7)。

必須節: `## Purpose` / `## When to use this skill` / `## Input` / `## Output` / `## Limitations` / `## Dependencies`。

`## Dependencies` には Requirement 15 AC2 に従い「当該ツールは plugin package に含まれない外部 runtime 依存である」ことを明記する。

`## Output` には stdout の top-level key を明示する。全 Skill 共通の contract は [Correction] C-10 に定める: stdout は 1 つの JSON document であり、Review_Report envelope は全 Skill で同一の 7 key、counter が stdout に載るのは acceptance criterion がそれを diagnostic ではなく **result** の一部と定めている場合のみである。該当するのは Requirement 5 AC4 のみであり、`cfn-guard-review` だけが envelope の外に `stats` を追加する。

構造検証は `tests/unit/test_skills.py` が担う (front matter、必須 6 節、top-level heading、ASCII 本文、`## Dependencies` の外部 runtime 依存表記、documented exit code と `iacreview/exitcodes.py` の一致、stdout key contract)。entry point の bootstrap prologue は `tests/unit/test_bootstrap.py` が担当し、重複させない。

### 具体例: `skills/cfn-lint-review/SKILL.md` front matter

```markdown
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
```

`description` は「何ができるか」と「どのような条件でクライアントが選択すべきか」の両方を記述する (Requirement 2 AC11)。加えて **選択すべきでない条件** も書く。これは 5 つの Skill が近接した領域を扱うため、client が誤って `cfn-lint-review` に IAM 解析を求める事故を防ぐためである。`name` はディレクトリ名と一致する (Requirement 2 AC12)。

### `skills/cfn-lint-review`

| 項目 | 内容 |
| --- | --- |
| Purpose | cfn-lint の実行と Finding 正規化 (Requirement 2 AC2, Requirement 4) |
| When to use | 構文 / resource property / intrinsic function / Parameters / Outputs の検証。デプロイ可能性の確認 |
| Input | Template ファイルパス 1 つ以上 |
| Output | `run_cfn_lint.py` の stdout JSON。Review_Report envelope のみ (`findings[]`, `errors[]` を含む 7 key)。counter は stderr の `--verbose` diagnostic とする ([Correction] C-10) |
| Scripts | `scripts/run_cfn_lint.py` |
| External deps | cfn-lint (最低 1.0.0)、Python 3.9+ |
| Limitations | cfn-lint が検出しない設計上の問題は扱わない。cfn-lint の rule set と AWS spec 版に結果が依存する。`E3xxx` の一部は deploy を阻害するが v0.1 の severity 方針では HIGH に留まる (mapping file で上書き可能)。Informational rule を `-c I` で明示的に有効化するため、素の `cfn-lint` 実行 (Informational は既定で無効) より多くの Finding が出る |

### `skills/cfn-guard-review`

| 項目 | 内容 |
| --- | --- |
| Purpose | 同梱 Guard rule によるポリシー検証 (Requirement 2 AC3, Requirement 5) |
| When to use | 暗号化必須 / Public Access 禁止 / Logging 必須 / Tag 必須 / Backup 必須 などの明示的ポリシー適合確認 |
| Input | Template パス、任意の追加 rule ディレクトリ |
| Output | stdout JSON。Review_Report envelope (7 key) + envelope の外に置く top-level `stats` (`stats.rules_evaluated`, `stats.rules_passed`、Template パスごと)。Requirement 5 AC4 を満たす唯一の例外 ([Correction] C-10) |
| Scripts | `scripts/run_cfn_guard.py` |
| External deps | cfn-guard (最低 3.0.0)、Python 3.9+ |
| Limitations | 同梱 rule が対象とする resource type のみを検査する。rule 未整備の resource type は検出されない。Severity は rule metadata 由来であり cfn-guard 自体は severity を持たない |

### `skills/iam-review`

| 項目 | 内容 |
| --- | --- |
| Purpose | IAM policy の決定論的危険パターン検出 + 文脈的リスクの Agent 推論 (Requirement 2 AC4, Requirement 6) |
| When to use | IAM Role / Policy / trust policy / resource-based policy を含む Template のセキュリティ評価 |
| Input | Template パス |
| Output | `run_iam_scan.py` の stdout JSON (`Confidence: Confirmed` の Finding)。加えて `extract_policies.py` が出力する policy site 一覧に基づき Agent が生成する Finding (`Likely` / `Contextual`) |
| Scripts | `scripts/run_iam_scan.py`, `scripts/extract_policies.py` |
| External deps | Python 3.9+ のみ |
| Limitations | intrinsic function で値が解決不能な箇所は「解決不能」として報告し、危険と断定しない。IAM Access Analyzer 相当の到達可能性解析は行わない。AWS API を呼ばないため、Template 外の既存 Role / Policy は評価対象外 |

### `skills/cloudformation-review`

| 項目 | 内容 |
| --- | --- |
| Purpose | リソース横断関係、アーキテクチャリスク、文脈的 severity 評価、ベストプラクティス推論 (Requirement 2 AC1, AC14) |
| When to use | 構文検証とポリシー検証を終えた後、設計妥当性を評価したいとき |
| Input | `extract_facts.py` が出力する Template facts JSON |
| Output | Agent Finding JSON (`Confidence: Likely` または `Contextual`、Evidence 必須) |
| Scripts | `scripts/extract_facts.py` |
| External deps | Python 3.9+ のみ |
| Limitations | 出力は非決定論的であり実行ごとに変動しうる。cfn-lint / cfn-guard が扱う検査を再実装しない (Requirement 2 AC14)。`Confidence: Confirmed` を出力できない |

`extract_facts.py` が抽出する facts (Agent に渡す決定論的な事実):

- resource logical ID、type、主要 property の抜粋
- `Ref` / `Fn::GetAtt` による resource 間参照グラフ
- `DependsOn` 関係
- Parameters とその default 値、Conditions の定義
- AZ / Subnet / Multi-AZ 関連 property の有無
- 既に決定論的 Source が検出した Finding の要約 (重複提案を避けるため)

最後の項目は Requirement 2 AC14/AC15 の遵守を構造的に支援する。Agent に「cfn-lint がすでに指摘済みの内容」を提示することで再実装を抑止する。

### `skills/iac-review`

| 項目 | 内容 |
| --- | --- |
| Purpose | 全 Source の統合と Review_Report 生成 (Requirement 2 AC5) |
| When to use | 対象 Template / ディレクトリの包括的レビューを求められたとき |
| Input | Template パスまたはディレクトリパス、任意の Agent Finding JSON パス、任意の source subset 指定 |
| Output | Review_Report JSON |
| Scripts | `scripts/run_iac_review.py` |
| External deps | cfn-lint, cfn-guard (いずれも欠けても動作継続)、Python 3.9+ |
| Limitations | Agent Finding は host agent が生成しない限り含まれない。CDK ソースからの synth は行わない |

### orchestration の疎結合設計 (Requirement 2 AC10)

`iac-review` は他 Skill の SKILL.md や scripts を呼び出さない。代わりに **同じ共有モジュール (`iacreview.cfnlint` 等) を直接呼ぶ**。Skill 間には呼び出し依存が存在しない。

```python
SOURCES: list[SourceSpec] = [
    SourceSpec("cfn-lint",  cfnlint.run_and_normalize,  required=False),
    SourceSpec("cfn-guard", cfnguard.run_and_normalize, required=False),
    SourceSpec("IAM Review", iam_source.run_and_normalize, required=False),
]

def collect(template: Path, enabled: set[str]) -> tuple[list[Finding], list[StructuredError]]:
    findings: list[Finding] = []
    errors: list[StructuredError] = []
    for spec in SOURCES:
        if spec.name not in enabled:
            continue
        try:
            result = spec.fn(template)
        except IacReviewError as exc:               # 想定内の失敗
            errors.append(exc.to_structured_error(source=spec.name))
            continue
        except Exception as exc:                    # 想定外も pipeline を止めない
            errors.append(unexpected_error(spec.name, exc))
            continue
        findings.extend(result.findings)
        errors.extend(result.errors)
    return findings, errors
```

この構造が Requirement 2 AC10 を満たす理由:

1. 各 Source の失敗は `errors[]` の 1 エントリになり、ループは継続する。
2. Source の追加・削除は `SOURCES` リストの変更のみで済み、他 Source のコードに触れない。
3. `iac-review` が失敗しても各 Skill は独立に動作する (Requirement 2 AC6-AC9)。共有モジュールは各 Skill の entry-point からも直接呼ばれるため、依存方向は常に Skill → 共有モジュールの一方向である。

Agent Finding の取り込みは Source ループの外で行う。`--agent-findings <path>` が与えられた場合のみ `agentin.load_agent_findings` を通し、検証失敗は同じ `errors[]` に積む。

---

## Data Models

### Finding schema (authoritative)

Requirement 7 AC1 が定める 13 フィールドを正準とする。`docs/finding-schema.md` はこの節を出典とする (Requirement 13 AC10)。

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "Finding",
  "type": "object",
  "additionalProperties": false,
  "required": [
    "ID", "Normalized_Category", "FindingType", "Severity", "Confidence",
    "Source", "Resource", "Location", "Finding", "WhyItMatters",
    "Evidence", "Recommendation", "SuggestedRemediation"
  ],
  "properties": {
    "ID": {
      "type": "integer",
      "minimum": 1,
      "description": "Sequential identifier within one Review_Report, assigned after sorting."
    },
    "Normalized_Category": {
      "enum": ["IAM", "Encryption", "PublicAccess", "Logging", "Tagging",
               "Availability", "Backup", "NetworkSecurity", "DataProtection",
               "TemplateQuality", "Other"]
    },
    "FindingType": {
      "enum": ["Validity", "Security", "BestPractice", "Informational"]
    },
    "Severity": {
      "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
      "description": "Comparable only among Findings that share the same FindingType."
    },
    "Confidence": {
      "enum": ["Confirmed", "Likely", "Contextual"]
    },
    "Source": {
      "type": "array",
      "minItems": 1,
      "uniqueItems": true,
      "items": { "enum": ["cfn-lint", "cfn-guard", "IAM Review", "Agent Review"] }
    },
    "Resource": {
      "type": ["string", "null"],
      "description": "CloudFormation logical resource ID. null when the finding is template-level and has no resource context."
    },
    "Location": {
      "type": "object",
      "additionalProperties": false,
      "required": ["File"],
      "properties": {
        "File":       { "type": "string", "description": "Workspace-relative path. Never an absolute host path." },
        "Line":       { "type": ["integer", "null"], "minimum": 1 },
        "Column":     { "type": ["integer", "null"], "minimum": 1 },
        "TemplatePath": {
          "type": ["array", "null"],
          "items": { "type": ["string", "integer"] },
          "description": "Path into the template document, e.g. [\"Resources\",\"MyBucket\",\"Properties\",\"BucketEncryption\"]."
        }
      }
    },
    "Finding": {
      "type": "string",
      "minLength": 1,
      "description": "What was detected. Must be phrased as a potential risk when Confidence != Confirmed."
    },
    "WhyItMatters": { "type": "string", "minLength": 1 },
    "Evidence": {
      "type": "array",
      "minItems": 1,
      "items": {
        "type": "object",
        "additionalProperties": false,
        "required": ["Source", "Detail"],
        "properties": {
          "Source":    { "enum": ["cfn-lint", "cfn-guard", "IAM Review", "Agent Review"] },
          "Detail":    { "type": "string", "minLength": 1 },
          "RuleId":    { "type": ["string", "null"] },
          "Excerpt":   { "type": ["string", "null"],
                         "description": "Verbatim template content that led to the conclusion. Required when Confidence != Confirmed." }
        }
      }
    },
    "Recommendation": { "type": "string", "minLength": 1 },
    "SuggestedRemediation": {
      "type": ["string", "null"],
      "description": "Concrete change proposal. Never applied automatically."
    }
  }
}
```

追加の構造的制約 (JSON Schema では表現せず `finding.validate()` で強制する):

| 制約 | 根拠 |
| --- | --- |
| `Confidence == "Confirmed"` のとき `Source` に `"Agent Review"` を含まない | Requirement 7 AC10 |
| `Confidence != "Confirmed"` のとき `Evidence` の少なくとも 1 要素が `Excerpt` を持つ | Requirement 7 AC11 |
| `FindingType == "Validity"` かつ `Severity == "CRITICAL"` は、mapping file の `blocks_deployment` フラグが立つ rule 由来の場合のみ許可 | Requirement 7 AC6 |
| `Normalized_Category == "Other"` の Finding は dedup の照合対象から除外 | Requirement 14 AC3 |
| `Source` は昇順ソート済み (`cfn-lint` < `cfn-guard` < `IAM Review` < `Agent Review` の固定順序) | Requirement 16 AC11 |

### Review_Report schema

```json
{
  "schema_version": "1.0.0",
  "target": {
    "files": ["templates/app.yaml"],
    "cdk": { "detected": false, "synthesized_templates": [] }
  },
  "sources_enabled": ["cfn-lint", "cfn-guard", "IAM Review"],
  "tools": [
    { "name": "cfn-lint",  "available": true,  "version": "1.22.3" },
    { "name": "cfn-guard", "available": false, "version": null }
  ],
  "findings": [ /* Finding[] sorted per Requirement 7 AC15 */ ],
  "errors": [ /* StructuredError[] */ ],
  "summary": {
    "total": 7,
    "by_finding_type": { "Validity": 1, "Security": 4, "BestPractice": 2, "Informational": 0 },
    "by_severity":     { "CRITICAL": 2, "HIGH": 2, "MEDIUM": 2, "LOW": 1, "INFO": 0 },
    "by_source":       { "cfn-lint": 3, "cfn-guard": 2, "IAM Review": 3, "Agent Review": 0 },
    "passed_all_checks": false
  }
}
```

`by_source` の合計は `total` と一致しない場合がある。マージ済み Finding は複数 Source に計上されるためである。この意味論を `docs/finding-schema.md` に明記する。`passed_all_checks` は `findings` が空のときのみ `true` (Requirement 7 AC16)。

### StructuredError schema

```json
{
  "error_class": "tool_unavailable",
  "source": "cfn-guard",
  "tool": "cfn-guard",
  "exit_code": null,
  "message": "cfn-guard was not found on the system PATH.",
  "required_min_version": "3.0.0",
  "detected_version": null,
  "remediation": "Install cfn-guard: see https://github.com/aws-cloudformation/cloudformation-guard#installation",
  "stderr_head": []
}
```

`error_class` の許可値: `invalid_arguments`, `input_not_found`, `parse_failure`, `tool_unavailable`, `tool_version`, `tool_execution`, `tool_timeout`, `path_violation`, `no_reviewable_template`, `schema_violation`, `unexpected`。

`stderr_head` は stderr の先頭 5 行に限定する (Requirement 15 AC7)。5 行制限は情報漏えい面積を抑える効果も持つ。

### FindingType × Severity の直交性

`FindingType` は「Finding の性質」を、`Severity` は「その性質の範囲内での重大度」を表す独立した軸である (Requirement 7 AC4, AC5)。**異なる FindingType 間で Severity を比較してはならない**。

worked example — cfn-lint `E3002` (無効な property) と S3 の public access 設定:

| | Finding A | Finding B |
| --- | --- | --- |
| 内容 | `E3002: Invalid Property Resources/MyBucket/Properties/Encryped` | S3 バケットが `PublicAccessBlockConfiguration` を持たず、Bucket Policy が `Principal: "*"` を許可 |
| FindingType | `Validity` | `Security` |
| Severity | `HIGH` | `CRITICAL` |
| Confidence | `Confirmed` | `Confirmed` |
| Category | `TemplateQuality` | `PublicAccess` |
| 意味 | Validity 軸の中で高い。デプロイが失敗する可能性が高いが、環境が侵害されるわけではない | Security 軸の中で最上位。データが公開される |

もし単一の Severity 軸に両者を押し込めると、次の 2 つの誤りのいずれかが必ず起きる。

1. `E3002` を CRITICAL にすると、「typo による deploy 失敗」と「データ公開」が同じ緊急度に見える。対応順序の判断が壊れる。
2. public access を HIGH に抑えると、実害のあるセキュリティ問題が構文エラーに埋もれる。

したがって Requirement 7 AC6 は「Validity に CRITICAL を付けるのは Template が全くデプロイできない場合のみ」と制約し、`E3002` のような property レベルのエラーは HIGH に留める。`E0000` (parse 不能) は Template 全体がデプロイ不能であるため Validity + CRITICAL が正当である。

出力の並びは Severity 降順 (Requirement 7 AC15) であるため、`Validity/HIGH` は `Security/CRITICAL` の後に来る。これは意図した挙動である。レポート消費者は `FindingType` でフィルタしてから Severity を読むべきであり、`docs/finding-schema.md` にその読み方を明記する。

### Confidence の意味論

| 値 | 意味 | 付与主体 | 文言制約 |
| --- | --- | --- | --- |
| `Confirmed` | 決定論的ツールまたは決定論的パターンマッチが事実として確認した | cfn-lint, cfn-guard, `iam_scan` | 断定形で記述してよい |
| `Likely` | Agent 推論による、可能性の高いリスク | Agent | 「〜の可能性がある」形式。脆弱性の存在を断定しない (Requirement 7 AC12) |
| `Contextual` | 文脈依存の推奨事項。環境によっては問題でない | Agent | 同上 |

worked example — 同じ resource に対する 3 つの Confidence:

```text
Resource: AppExecutionRole

[Confirmed]  IAM Review: policy statement 0 has Action "*" with Resource "*".
             -> 事実。Severity CRITICAL, FindingType Security (Requirement 6 AC1)

[Likely]     Agent Review: AppExecutionRole is attached to a Lambda function that
             reads from a bucket also defined in this template; the wildcard policy
             likely grants far more than the function needs.
             -> 推論。Evidence.Excerpt に該当 policy と Lambda 定義の抜粋を含む

[Contextual] Agent Review: no permissions boundary is attached; organizations that
             mandate permissions boundaries may consider this a policy deviation.
             -> 環境依存。Evidence.Excerpt に Role 定義の抜粋を含む
```

`Confirmed` の Finding が存在するときも `Likely` / `Contextual` を捨てない。3 者は Category が異なれば独立に残り、同じ Category なら merge されて Confidence は `Confirmed` に、Evidence は 3 者すべてが保持される (Requirement 14 AC9, AC11)。

### Severity 減算規則 (`sts:ExternalId`)

Requirement 6 AC10 は cross-account Principal に `sts:ExternalId` condition が同一 statement 内に存在する場合、Severity を 1 段階下げることを求める。降格は `HIGH → MEDIUM` のように順序集合上の 1 段移動であり、`INFO` が下限である。緩和条件は `Evidence[].Detail` に記録する。

**重要な順序制約**: 降格は `normalizer` 段階、すなわち `dedup` の **前** に適用する。マージは Severity の最大値を採るため、降格後の値でマージに参加する。降格をマージ後に適用すると、他 Source の Severity を不当に下げてしまう。

---

## Normalized Category Vocabulary and the Mapping File

### 閉集合

Requirement 14 AC2 が定める 10 カテゴリに、AC3 が定める `Other` を加えた 11 要素の閉集合とする。

| Category | 対象 |
| --- | --- |
| `IAM` | IAM Policy / Role / User / Group / trust policy / resource-based policy の権限設計 |
| `Encryption` | 保存時暗号化、転送時暗号化、KMS key の使用 |
| `PublicAccess` | インターネットまたは全 AWS アカウントからの到達可能性 |
| `Logging` | アクセスログ、監査ログ、フローログの有効化 |
| `Tagging` | 必須タグの付与 |
| `Availability` | Multi-AZ、冗長化、SPOF |
| `Backup` | バックアップ設定、保持期間、削除保護 |
| `NetworkSecurity` | Security Group / NACL / VPC 境界 (PublicAccess に該当しないもの) |
| `DataProtection` | データ保持、versioning、削除防止、機密データ取り扱い |
| `TemplateQuality` | 構文、property 妥当性、非推奨記述、テンプレート構造 |
| `Other` | 上記に写像できない Agent Finding のみ。dedup 照合から除外 |

`PublicAccess` と `NetworkSecurity` の切り分け規則: **インターネット (`0.0.0.0/0`) または全 AWS アカウント (`Principal: "*"`) からの到達可能性は `PublicAccess`**。それ以外のネットワーク境界設計上の問題は `NetworkSecurity`。この規則を `category_map.json` の `notes` に記載し、Guard rule と cfn-lint rule の写像先を一貫させる。

### mapping file の設計

Requirement 14 AC4 は「cfn-lint rule prefix と cfn-guard rule category から Normalized_Category への写像、および Requirement 4 が参照する cfn-lint security-relevance 写像を、単一の versioned mapping file で維持する」ことを求める。

**ファイル**: `iacreview/category_map.json`。JSON を選ぶ理由は、標準ライブラリのみで読める (Requirement 16 AC3 の依存最小化) ことと、schema 検証しやすいことである。

**参照順序** (先に一致したものを採用):

1. `cfnlint.rule_overrides[<rule_id>]` — 完全一致 (最優先)
2. `cfnlint.prefix_rules[]` — 長い prefix を優先して照合
3. `cfnlint.default` — 上記いずれにも該当しない場合

`prefix_rules` は prefix 文字列の長さの降順で評価する。これにより `E30` の指定が `E3` より優先される。

```json
{
  "schema_version": "1.0.0",
  "categories": [
    "IAM", "Encryption", "PublicAccess", "Logging", "Tagging",
    "Availability", "Backup", "NetworkSecurity", "DataProtection",
    "TemplateQuality", "Other"
  ],
  "notes": {
    "public_access_vs_network_security": "Reachability from the internet (0.0.0.0/0) or from all AWS accounts (Principal \"*\") maps to PublicAccess. Other network boundary design issues map to NetworkSecurity.",
    "severity_axis": "Severity is comparable only among Findings sharing the same FindingType."
  },

  "cfnlint": {
    "level_defaults": {
      "Error":         { "finding_type": "Validity",      "severity": "HIGH" },
      "Warning":       { "finding_type": "BestPractice",  "severity": "MEDIUM" },
      "Informational": { "finding_type": "Informational", "severity": "LOW" }
    },
    "default": { "category": "TemplateQuality" },
    "prefix_rules": [
      { "prefix": "E0", "category": "TemplateQuality", "blocks_deployment": true },
      { "prefix": "E1", "category": "TemplateQuality", "blocks_deployment": true },
      { "prefix": "E2", "category": "TemplateQuality" },
      { "prefix": "E3", "category": "TemplateQuality" },
      { "prefix": "E4", "category": "TemplateQuality" },
      { "prefix": "E6", "category": "TemplateQuality" },
      { "prefix": "E7", "category": "TemplateQuality" },
      { "prefix": "E8", "category": "TemplateQuality" },
      { "prefix": "W",  "category": "TemplateQuality" },
      { "prefix": "I",  "category": "TemplateQuality" }
    ],
    "rule_overrides": {
      "W3037": {
        "category": "IAM",
        "security_relevant": true,
        "why_it_matters": "An invalid or malformed IAM action prevents the policy from granting the intended access, or grants access that was not intended.",
        "recommendation": "Correct the IAM action name to a valid service action."
      },
      "W2501": {
        "category": "DataProtection",
        "security_relevant": true,
        "why_it_matters": "A parameter that carries a credential value should be declared NoEcho so that it is not displayed in the console or API responses.",
        "recommendation": "Set NoEcho: true on the parameter."
      },
      "W1011": {
        "category": "DataProtection",
        "security_relevant": true,
        "why_it_matters": "A hardcoded secret value in a template is stored in plaintext in the template and in CloudFormation history.",
        "recommendation": "Use a dynamic reference to Secrets Manager or SSM Parameter Store."
      },
      "E3002": {
        "category": "TemplateQuality",
        "blocks_deployment": false
      }
    }
  },

  "cfnguard": {
    "rule_categories": {
      "encryption":    "Encryption",
      "public-access": "PublicAccess",
      "iam":           "IAM",
      "logging":       "Logging",
      "backup":        "Backup",
      "tagging":       "Tagging"
    },
    "rule_overrides": {
      "security_group_open_ingress": { "category": "NetworkSecurity" }
    }
  }
}
```

### security-relevance override の動作

`rule_overrides[<rule_id>].security_relevant == true` のとき、`normalizer` は `level_defaults` が与える `finding_type` を無視し `FindingType: "Security"` を割り当てる (Requirement 4 AC9)。`severity` は `level_defaults` の値を維持する。severity も変えたい場合は同じ override 内に `severity` を明記する。

```python
def classify_cfnlint(rule_id: str, level: str, cmap: CategoryMap) -> Classification:
    base = cmap.cfnlint_level_default(level)          # (finding_type, severity)
    entry = cmap.cfnlint_override(rule_id)            # dict | None
    prefix = cmap.cfnlint_prefix(rule_id)             # longest matching prefix rule

    category = (entry or {}).get("category") or prefix.category or cmap.cfnlint_default_category()
    finding_type = "Security" if (entry or {}).get("security_relevant") else base.finding_type
    severity = (entry or {}).get("severity") or base.severity

    blocks = (entry or {}).get("blocks_deployment")
    if blocks is None:
        blocks = prefix.blocks_deployment
    if level == "Error" and blocks:
        severity = "CRITICAL"                          # Requirement 4 AC5 / 7 AC6

    return Classification(category, finding_type, severity)
```

### CRITICAL override の表現

Requirement 4 AC5 は「rule ID prefix `E0` または `E1` のとき CRITICAL」と規定する。設計はこれを **prefix のハードコードではなく mapping file の `blocks_deployment` フラグ** として表現する。

理由: 実際には多くの `E3xxx` も deploy を阻害する。`E0`/`E1` を CRITICAL とするのは「Template 全体がデプロイ不能である場合に限る」(Requirement 7 AC6) という保守的な運用方針の初期値であって、「E0/E1 だけが deploy を阻害する」という事実主張ではない。この区別を mapping file 上のデータとして表現すれば、rule 単位の実測に基づき override を追加するだけで方針を調整でき、コード変更を伴わない。steering/development-principles.md「Magic Value を避ける」に適合する。

`blocks_deployment` の決定順序: `rule_overrides[<rule_id>].blocks_deployment` → `prefix_rules[].blocks_deployment` → 未指定は `false`。`level == "Error"` かつ `blocks_deployment == true` のときのみ CRITICAL に昇格する。Warning / Informational が CRITICAL になることはない。

### mapping file の versioning

`schema_version` を semver で持つ。Finding schema や mapping 構造の breaking change 時に MAJOR を上げ、CHANGELOG に記録する (steering/documentation.md「Finding Schema 変更」を CHANGELOG 対象として明記)。`categories` 配列は `finding.validate()` が参照する唯一の許可値定義であり、コード側に category 名を重複定義しない。

---

## cfn-lint Integration

### 実行コマンド

```text
argv = ["cfn-lint", "-f", "json", "-c", "I", "--", "<template-path>"]
```

`--` を置いて以降を positional 引数として確定させる。`shell=False`、`stdin=DEVNULL`、`timeout=60`。テンプレートパスは `pathguard.resolve_within()` を通過した値のみを渡す (Requirement 9 AC4, AC5)。

**`-c I` (`--include-checks I`) を常に付与する理由**: cfn-lint は後方互換性のため Informational (`I`) rule を既定で **実行しない**。一方 Requirement 4 AC7 は Informational level の結果を `FindingType: Informational` / `Severity: LOW` へ写像することを要求し、Requirement 7 AC17 は `FindingType` 別 (`Informational` を含む) の summary を要求する。`-c I` を付けない限りこれらのコードパスは到達不能であり、`category_map.json` の `level_defaults.Informational` も永久に未使用となる。したがって `-c I` の付与は設計上必須である。

このオプションは cfn-lint の既定挙動からの意図的な逸脱であり、素の `cfn-lint` 実行より多くの Finding が出る。これは承知の上での選択である。Requirement 12 AC6 は `FindingType` が `Informational` かつ `Severity` が LOW / INFO の Finding を negative test の false positive 計数から除外するため、Informational rule を有効化しても negative test を失敗させない。

**`--non-zero-exit-code` は指定しない**:

| 項目 | 内容 |
| --- | --- |
| 許可値 | `informational` (既定)、`warning`、`error`、`none` |
| 意味 | cfn-lint が非ゼロ exit code を返す severity の閾値を制御する |
| 設計の扱い | 本設計は本 flag を渡さず既定 (`informational`) に依拠する。後述の復号ロジックは findings bit の全組み合わせを成功として扱うため、閾値を変える必要がない |
| 将来変更時の注意 | 仮に `--non-zero-exit-code none` を渡すと exit code 0 が「findings なし」を意味しなくなる。その場合は `decode_cfnlint_exit` の `code == 0` 分岐を含む復号ロジックを再検討する必要がある |

バージョン確認: `argv = ["cfn-lint", "--version"]`。最低バージョン 1.0.0 (JSON 出力の `Rule` オブジェクト構造が安定している系列)。加えて、本設計が使用する `--include-checks` (`-c`) と `--non-zero-exit-code` が利用可能であることも最低バージョンの条件である。いずれも cfn-lint 1.x に存在する。

### Exit code の bit mask 復号

cfn-lint の exit code は bit mask である。

| Bit | 値 | 意味 |
| --- | --- | --- |
| — | 0 | findings なし |
| 1 | 2 | Error finding あり |
| 2 | 4 | Warning finding あり |
| 3 | 8 | Informational finding あり |

| 観測 exit code | 復号 | 扱い |
| --- | --- | --- |
| 0 | findings なし | 成功。空 findings + `Source: cfn-lint` (Requirement 4 AC13) |
| 2 | E | 成功。stdout を解析 |
| 4 | W | 成功。stdout を解析 |
| 6 | E + W | 成功。stdout を解析 |
| 8 | I | 成功。stdout を解析 |
| 10 | E + I | 成功。stdout を解析 |
| 12 | W + I | 成功。stdout を解析 |
| 14 | E + W + I | 成功。stdout を解析 |
| 1 | crash / usage error | `tool_execution` エラー。stderr 先頭 5 行を報告 |
| その他 (`code & ~14 != 0`) | 未知 | `tool_execution` エラー。stdout が期待 JSON として解析できる場合のみ findings も併せて報告する |

```python
_CFNLINT_FINDING_BITS = 2 | 4 | 8            # 14

def decode_cfnlint_exit(code: int) -> CfnLintExitDecision:
    if code == 0:
        return CfnLintExitDecision(ok=True, has_findings=False)
    if code & ~_CFNLINT_FINDING_BITS == 0:   # 2,4,6,8,10,12,14 のみ
        return CfnLintExitDecision(ok=True, has_findings=True)
    return CfnLintExitDecision(ok=False, has_findings=False)
```

#### [Correction] 要求仕様への訂正事項 (cfn-lint exit code)

Requirement 4 AC11 は当初「exit code 2 = linting violations found」、AC12 は「exit code 4 以上 = execution error」と記述していた。これは実際の cfn-lint の挙動と一致しない。

| requirements.md の記述 | 実際 | 設計の扱い |
| --- | --- | --- |
| 2 = violations | 2 = Error level の finding が報告されたことを示す bit。実行失敗ではない | 「findings あり」という方向性は正しいが、2 は findings を示す唯一の code ではない。4 (Warning) と 8 (Informational) も findings であり、bit の組み合わせも起こる |
| 4 以上 = execution error | 4 = Warning finding あり (正常)。8 = Informational finding あり (正常) | 4, 6, 8, 10, 12, 14 はすべて正常終了 |
| — | 1 = crash / usage error | AC12 が想定する execution error は主に 1 |

**設計は bit mask 復号を採用し、これによって当初の AC11 / AC12 の記述を上書きした**。AC11 の趣旨 (findings が出ても失敗扱いにしない) と AC12 の趣旨 (実行エラーは pipeline を止めずに報告する) は維持されるが、判定条件が異なる。以下の修正は requirements.md へ反映済みである。

- AC11 は「WHEN cfn-lint exits with a code whose set bits form a subset of {2, 4, 8}, indicating that findings were reported, THEN treat this as successful execution and parse the findings from stdout」となった。
- AC12 は「IF cfn-lint exits with a code containing any bit outside {2, 4, 8}, including exit code 1 (crash or usage error), THEN report the failure with the stderr output without terminating the overall review pipeline」となった。

### JSON field 対応表

cfn-lint の各 result object から Finding への写像。

| cfn-lint JSON path | Finding field | 変換 |
| --- | --- | --- |
| `Rule.Id` | `Evidence[0].RuleId` | そのまま |
| `Rule.Id` | (分類入力) | `category_map.json` の照合キー |
| `Rule.ShortDescription` | `WhyItMatters` | override の `why_it_matters` があればそれを優先 |
| `Rule.Description` | `Recommendation` | override の `recommendation` があればそれを優先 |
| `Rule.Source` | `Evidence[0].Detail` に URL として付記 | 参照 URL |
| `Level` | `FindingType`, `Severity` | `level_defaults` + override (前節参照) |
| `Message` | `Finding` | `"[{Rule.Id}] {Message}"` 形式 |
| `Location.Start.LineNumber` | `Location.Line` | そのまま |
| `Location.Start.ColumnNumber` | `Location.Column` | そのまま |
| `Location.Path` | `Location.TemplatePath` | そのまま (list) |
| `Location.Path` | `Resource` | 後述の抽出規則 |
| `Filename` | `Location.File` | workspace 相対パスへ正規化 (Requirement 16 AC11) |
| — | `Confidence` | 常に `"Confirmed"` (Requirement 7 AC8) |
| — | `Source` | 常に `["cfn-lint"]` |
| — | `SuggestedRemediation` | override に定義があれば設定、なければ `null` |
| — | `Evidence[0].Excerpt` | `null` (`Confirmed` のため不要) |

`Location.End` は保持しない。Finding schema が単一位置のみを持つためであり、必要になれば `TemplatePath` から特定できる。

### Resource logical ID の抽出

```python
def resource_from_path(path: list[object] | None) -> str | None:
    if not path:
        return None
    if len(path) >= 2 and path[0] == "Resources" and isinstance(path[1], str):
        return path[1]
    return None
```

| ケース | `Location.Path` | `Resource` |
| --- | --- | --- |
| Resource 配下 | `["Resources","MyBucket","Properties","BucketName"]` | `"MyBucket"` |
| Resource 自体 | `["Resources","MyBucket"]` | `"MyBucket"` |
| Parameters | `["Parameters","DbPassword"]` | `null` |
| Outputs | `["Outputs","BucketArn"]` | `null` |
| Template 全体 (`E0000` など) | `[]` または欠落 | `null` |

`Resource == null` の Finding の扱い:

- Requirement 14 AC5 の等価判定は resource logical ID と Category の一致を要求する。`null` は **どの Finding とも等価にならない** ものとして扱う。`null == null` によるマージは行わない。理由: template-level の Finding は互いに無関係でありうる (parse error と Outputs の警告が同じ Category を持つ場合など) ため、統合すると情報が失われる。
- 整列時 (Requirement 7 AC15 の logical ID 昇順) は `null` を空文字列として扱い、同一 Severity 内で先頭に置く。決定論性のためこの規則を固定する。

### ツール未導入 / バージョン不足

| 状況 | 挙動 |
| --- | --- |
| PATH に `cfn-lint` が無い | `StructuredError(error_class="tool_unavailable", tool="cfn-lint", required_min_version="1.0.0", remediation="pip install cfn-lint")` を返す。Requirement 4 AC10 が `pip install cfn-lint` の明示を要求 |
| バージョン < 1.0.0 | `StructuredError(error_class="tool_version", detected_version=..., required_min_version="1.0.0", remediation="pip install --upgrade cfn-lint")` (Requirement 15 AC6) |
| `--version` 出力が解析不能 | 警告を stderr に出し、実行は継続する。バージョン判定不能を理由にレビューを止めない (保守的だが可用性を優先。steering/agent-plugin-standards.md の「最も保守的な実装」は「安全側」を意味し、この場合はツール実行の副作用が read-only であるため継続が安全) |

単独 Skill として呼ばれた場合は exit code `5` (`TOOL_UNAVAILABLE`) で終了する。`iac-review` 経由の場合は `errors[]` に積んで継続する (Requirement 4 AC12)。exit code の一覧は Error Handling 節を参照する。

---

## cfn-guard Integration

### 実行コマンド

```text
argv = [
  "cfn-guard", "validate",
  "--data", "<template-path>",
  "--rules", "<plugin-root>/rules",
  "--output-format", "json",
  "--type", "CFNTemplate",
  "--show-summary", "none",
]
```

各フラグの根拠:

| Flag | 理由 |
| --- | --- |
| `validate` | Template に対する rule 適用の subcommand |
| `--data <template>` | 検査対象。`pathguard` を通した値のみ |
| `--rules <plugin-root>/rules` | 同梱 rule のルート。ディレクトリ指定時、cfn-guard は `.guard` と `.ruleset` 拡張子のみを収集する。したがって同ディレクトリに置く `_meta.json` は rule として読まれない |
| `--output-format json` | 機械可読出力。許可値は `json`, `yaml`, `single-line-summary`, `junit`, `sarif`。既定は `single-line-summary` であり人間向けなので明示的に上書きする |
| `--type CFNTemplate` | **これが最重要**。指定すると cfn-guard は CloudFormation の logical resource name を出力に含める。指定しない場合は raw property path のみとなり、Requirement 5 AC3 が求める「target resource の logical resource identifier」を得られない |
| `--show-summary none` | summary ブロックを抑制し、findings の JSON のみを得る。`--structured` を使う場合は `--show-summary all/fail/pass/skip` と競合するため、いずれにせよ `none` が必要 |

`--structured` (`-z`) は採用しない。`--output-format json` + `--show-summary none` で必要な情報が得られ、`verbose` / `print-json` との競合を考慮する必要がなくなるためである。将来 `--structured` に切り替える場合は `--show-summary none` との併用を維持する。

`--rules` と `--data` は繰り返し指定可能である。v0.1 では 1 Template ずつ実行する。理由: Requirement 5 AC1 が「Template あたり 60 秒以内」を求めており、Template 単位で timeout を制御する必要があるためと、Template 単位で `errors[]` を分離できるためである。

バージョン確認: `argv = ["cfn-guard", "--version"]`。最低バージョン 3.0.0。

追加 rule ディレクトリ: Open Question 7 に対する設計判断として、v0.1 では `--rules <dir>` を **繰り返し指定できる CLI option (`--rules-dir`) を `run_cfn_guard.py` に用意する**。既定は同梱 rule のみ。ユーザー指定ディレクトリは `pathguard.resolve_within(workspace_root)` を通す。これは Requirement 15 AC3 の「plugin-owned resource は containment 境界内」を守りつつ、ユーザー資産をワークスペース内に限定する。

### rule ディレクトリ構成

Requirement 5 AC2 が 6 カテゴリの rule を、AC8 が「カテゴリごとの別ディレクトリ」と「既存 rule ファイルを変更せずに新規 rule を追加可能」を要求する。

```text
rules/
├── encryption/
│   ├── s3_bucket_encryption.guard
│   ├── rds_storage_encrypted.guard
│   └── _meta.json
├── public-access/
│   ├── s3_public_access_block.guard
│   ├── security_group_open_ingress.guard
│   ├── rds_publicly_accessible.guard
│   └── _meta.json
├── iam/
├── logging/
├── backup/
└── tagging/
```

ファイル名規約: `<lowercase_snake_case>.guard`。ファイル名 (拡張子なし) が Guard rule 名の prefix と一致させる。1 ファイル 1 rule を原則とする。

### rule 例

```text
# rules/encryption/s3_bucket_encryption.guard
let s3_buckets = Resources.*[ Type == 'AWS::S3::Bucket' ]

rule s3_bucket_encryption when %s3_buckets !empty {
  %s3_buckets.Properties.BucketEncryption exists
    << Server-side encryption is not configured on this S3 bucket. Add a BucketEncryption property with a ServerSideEncryptionConfiguration entry (for example SSEAlgorithm AES256 or aws:kms). >>
}
```

```text
# rules/public-access/security_group_open_ingress.guard
let security_groups = Resources.*[ Type == 'AWS::EC2::SecurityGroup' ]

rule security_group_open_ingress when %security_groups !empty {
  %security_groups.Properties.SecurityGroupIngress[*].CidrIp != "0.0.0.0/0"
    << An ingress rule allows traffic from 0.0.0.0/0. Restrict CidrIp to the specific source ranges that require access, or reference a source security group. >>
}
```

`<<` の custom message が Requirement 5 AC3 の remediation guidance になる。Guard の出力に含まれるためパースで取得できる。

### Severity の付与方式

**cfn-guard は severity という概念を持たない**。したがって Plugin 側が付与する必要がある。3 案を検討した。

| 案 | 内容 | 評価 |
| --- | --- | --- |
| A. rule 名の命名規約に severity を埋める (`critical_s3_public.guard`) | 追加ファイル不要 | **却下**。rule 名変更なしに severity を変えられない。rule 名は Ground_Truth や mapping からも参照されるため変更コストが高い |
| B. `category_map.json` に全 Guard rule の severity を列挙 | 単一ファイル管理 | **却下**。Requirement 5 AC8 が「新規 rule 追加時に既存 rule ファイルを変更しない」ことを求める。`category_map.json` は既存ファイルであり、rule 追加ごとに編集が必要になる |
| C. カテゴリディレクトリごとの `_meta.json` sidecar | rule 追加は当該カテゴリの `_meta.json` に 1 エントリ追加 | **採用** |

案 C でも `_meta.json` の編集は発生するが、これは AC8 が禁じる「既存 **rule ファイル** の変更」には当たらない。かつ変更範囲が当該カテゴリディレクトリ内に閉じるため、複数の contributor が異なるカテゴリに同時に rule を追加しても衝突しない。案 B は全 contributor が同一ファイルを編集するため衝突が集中する。

```json
{
  "schema_version": "1.0.0",
  "category": "public-access",
  "normalized_category": "PublicAccess",
  "default": {
    "finding_type": "Security",
    "severity": "HIGH"
  },
  "rules": {
    "s3_public_access_block": {
      "severity": "CRITICAL",
      "why_it_matters": "Without a public access block, a later bucket policy or ACL change can expose object data to the internet.",
      "recommendation": "Add a PublicAccessBlockConfiguration with all four settings enabled."
    },
    "security_group_open_ingress": {
      "severity": "HIGH",
      "normalized_category": "NetworkSecurity",
      "why_it_matters": "An ingress rule open to 0.0.0.0/0 exposes the attached instances to the entire internet.",
      "recommendation": "Restrict the source CIDR to the ranges that require access."
    },
    "rds_publicly_accessible": {
      "severity": "CRITICAL",
      "why_it_matters": "A publicly accessible database endpoint is reachable from the internet and only protected by network ACLs and credentials.",
      "recommendation": "Set PubliclyAccessible to false and place the instance in private subnets."
    }
  }
}
```

解決順序: `rules[<rule_name>].<field>` → `default.<field>` → hardcoded fallback (`finding_type: "BestPractice"`, `severity: "MEDIUM"`)。`normalized_category` は rule 単位の上書きを許す (`security_group_open_ingress` が `NetworkSecurity` になる例)。`category_map.json` の `cfnguard.rule_overrides` も同じ上書きを表現できるが、**`_meta.json` を優先** する。理由: rule と同じディレクトリにあるため rule 追加時の編集が 1 箇所で済む。`category_map.json` 側は cfn-lint 用の写像と全体の閉集合定義を担う。

`_meta.json` が欠落または不正なカテゴリは、そのカテゴリ全体を fallback 値で処理し、`errors[]` に `error_class: "parse_failure"` を記録する。rule 実行そのものは継続する。

### 出力の解析

cfn-guard の JSON 出力から取得するフィールドと Finding への写像。

| Guard 出力の情報 | Finding field | 変換 |
| --- | --- | --- |
| rule 名 | `Evidence[0].RuleId` | そのまま。`_meta.json` の照合キー |
| logical resource name (`--type CFNTemplate` により取得) | `Resource` | そのまま。取得できない場合は property path から `Resources.<id>` を抽出、それも不能なら `null` |
| property path | `Location.TemplatePath` | 区切り (`/` または `.`) を list へ分解し、正規形へ変換する。sequence index は `int` にする ([Correction] C-9) |
| provided value / expected value | `Evidence[0].Detail` | `"provided: <v>, expected: <e>"` 形式 |
| custom message (`<<...>>`) | `SuggestedRemediation` | そのまま。無い場合は `_meta.json` の `recommendation` を使用 |
| — | `Finding` | `"[{rule_name}] {custom message の1文目 または 既定文}"` |
| — | `FindingType`, `Severity`, `Normalized_Category` | `_meta.json` から解決 |
| — | `Confidence` | 常に `"Confirmed"` (Requirement 7 AC8) |
| — | `Source` | 常に `["cfn-guard"]` |
| — | `Location.Line` / `Column` | `null`。cfn-guard は行番号を安定して提供しない。行番号が必要な場合は `TemplatePath` から特定する |

cfn-guard の JSON 構造はバージョン間で差異があるため、`parse_output()` は **必要フィールドの存在を検証し、期待構造に一致しない場合は `error_class: "parse_failure"` を返して findings を捨てる**。部分的に解釈して誤った Finding を出すよりも、解析不能を明示する方が安全である (steering/security.md「推測だけで脆弱性が存在すると断定しない」)。

`rules_evaluated` / `rules_passed` の件数は Requirement 5 AC4 が要求する。cfn-guard 出力から取得できない場合は、`rules/` 配下の `.guard` ファイル内 `rule` 宣言数を数えて `rules_evaluated` とし、`rules_passed = rules_evaluated - 違反 rule 数` とする。この算出方法を `docs/architecture.md` に明記する。

### Exit code の曖昧性への対処

cfn-guard は exit 0 = 全 rule pass を保証するが、非ゼロコードの内訳は公式ドキュメントに列挙されていない。cfn-guard は「rule 違反」と「内部エラー / parse エラー」を異なる非ゼロコードで区別するが、その具体値を設計時に確定できない。

**方針: exit code を判定の一次情報にしない**。この方針は Requirement 5 AC7 が要求事項として明文化しており、「非ゼロ exit code が rule 違反か実行失敗かの判定は、stdout が期待する結果構造として解析できるかによって行い、特定の exit code 値には依拠しない」ことを求める。したがって以下は設計上の選択ではなく要求の実装である。

```python
def interpret_guard_result(result: ProcResult) -> GuardInterpretation:
    if result.timed_out:
        return GuardInterpretation(kind="timeout")
    if result.exit_code == 0:
        return GuardInterpretation(kind="all_passed")
    parsed = try_parse_guard_json(result.stdout)
    if parsed is not None:
        # 期待する JSON 構造が得られた -> rule 違反として扱う
        return GuardInterpretation(kind="violations", payload=parsed, exit_code=result.exit_code)
    # JSON が得られない -> tool error として扱う
    return GuardInterpretation(kind="tool_error", exit_code=result.exit_code,
                               stderr_head=result.stderr.splitlines()[:5])
```

非ゼロ + 期待 JSON 解析成功 = 違反、非ゼロ + 解析失敗 = ツールエラー (Requirement 5 AC7)。この判定は特定の exit code 値に依存しないため、cfn-guard のバージョン差に対して頑健である。観測した exit code は `StructuredError.exit_code` に記録し、Requirement 15 AC7 を満たす。

正確な exit code 値の実測は「Open Design Decisions」に実装時タスクとして記録する。実測後は `interpret_guard_result` に exit code による早期判定を **追加** できるが、JSON 解析による判定を置き換えてはならない。

### contributor が rule を追加する手順 (Requirement 5 AC8)

1. 該当カテゴリディレクトリに `<rule_name>.guard` を新規作成する。既存の `.guard` ファイルは変更しない。
2. 同ディレクトリの `_meta.json` の `rules` に 1 エントリを追加する。
3. `benchmark/cases/` に当該 rule を発火させる Benchmark_Template と Ground_Truth を追加する (Requirement 11 AC16)。
4. `tests/unit/test_cfnguard_parse.py` に、当該 rule 名が `_meta.json` で解決できることを確認するケースが自動的に含まれる (全 `.guard` の rule 名が `_meta.json` に存在することを網羅検証するテストを置く)。

手順 4 の網羅テストにより、`_meta.json` への追記忘れが CI で検出される。

---

## IAM Review Architecture

Requirement 6 を 2 層に分割する。分割の根拠は「決定論的/Agent 境界」節 (#7, #8) に示した通り、AC1/AC4/AC5/AC7-AC11 が判定規則を完全に列挙しているためである。

| 層 | 実装 | Confidence | 対象 |
| --- | --- | --- | --- |
| Layer 1: deterministic pattern matching | `iacreview/iam/detectors.py` | `Confirmed` | 列挙された action 名 / 値 / 構造の照合 |
| Layer 2: agent reasoning | `iam-review` SKILL.md のガイダンス | `Likely` / `Contextual` | 最小権限からの乖離度、resource 間の権限過剰、組織ポリシー観点 |

Layer 2 の入力は `extract_policies.py` が出力する決定論的な policy site 一覧である。Agent は Template を直接読むのではなく、抽出済みの構造化データと Layer 1 の検出結果を受け取る。これにより Layer 1 が既に `Confirmed` で報告した内容の重複提案を抑制する。

### Layer 1: 決定論的検出器

| Detector | Requirement | 検出条件 | FindingType | Severity | Category |
| --- | --- | --- | --- | --- | --- |
| `star_action_star_resource` | 6 AC1 | 同一 statement 内で `Effect: Allow` かつ Action に `"*"` かつ Resource に `"*"` | Security | CRITICAL | IAM |
| `wildcard_action` | 6 AC4 | Action に `"*"` を含む要素 (`s3:*` を含む) | Security | HIGH | IAM |
| `wildcard_resource` | 6 AC4 | Resource に `"*"` を含む要素 | Security | HIGH | IAM |
| `sensitive_prefix_without_condition` | 6 AC2 | `Effect: Allow` かつ Action prefix が `iam:` / `sts:` / `lambda:` / `s3:` のいずれかで、statement に `Condition` が無い | Security | HIGH | IAM |
| `passrole_unrestricted` | 6 AC3 | `iam:PassRole` を含み Resource が `"*"` または `arn:aws:iam::*:role/*` 形式のワイルドカード | Security | CRITICAL | IAM |
| `assumerole_unrestricted` | 6 AC3 | `sts:AssumeRole` を含み Resource が `"*"` | Security | HIGH | IAM |
| `privesc_policy_mutation` | 6 AC5 | `iam:CreatePolicyVersion`, `iam:SetDefaultPolicyVersion`, `iam:AttachUserPolicy`, `iam:AttachGroupPolicy`, `iam:AttachRolePolicy`, `iam:PutUserPolicy`, `iam:PutGroupPolicy`, `iam:PutRolePolicy` のいずれかを `Allow` | Security | CRITICAL | IAM |
| `privesc_lambda_passrole` | 6 AC5 | 同一 policy document 内に `lambda:CreateFunction` と `iam:PassRole` が併存 | Security | CRITICAL | IAM |
| `privesc_broad_trust` | 6 AC5 | trust policy で `sts:AssumeRole` を許可し Principal が `"*"` またはサービス Principal に条件なし | Security | CRITICAL (Principal `"*"`) / HIGH (条件なし service principal) | IAM |
| `cross_service_missing_condition` | 6 AC6 | cross-service / cross-account statement に `aws:SourceAccount`, `aws:SourceArn`, `aws:PrincipalOrgID` のいずれの Condition も無い | Security | HIGH | IAM |
| `cross_account_principal` | 6 AC7 | Principal に literal 12 桁 account ID、または 12 桁 account ID を埋め込んだ ARN | Security | HIGH | IAM |
| `principal_star` | 6 AC9 | Principal が `"*"` または `{"AWS": "*"}` | Security | CRITICAL | IAM |
| `dangerous_s3_combo` | 6 AC11 | `s3:GetObject` + `s3:PutObject` + `s3:DeleteObject` が Resource `"*"` 上で併存 | Security | HIGH | IAM |
| `dangerous_ec2_passrole` | 6 AC11 | `ec2:RunInstances` と `iam:PassRole` が併存 | Security | HIGH | IAM |
| `dangerous_lambda_combo` | 6 AC11 | `lambda:UpdateFunctionCode` と `lambda:InvokeFunction` が併存 | Security | HIGH | IAM |
| `no_iam_resources` | 6 AC12 | IAM 関連 resource / policy が 0 件 | (Finding なし) | — | — |

検出器は互いに独立した純関数として実装する。1 つの statement が複数の検出器に該当する場合は複数の Finding が生成され、すべて Category `IAM` であるため `dedup` が同一 resource 上でマージする (Requirement 14 AC5-AC11)。マージ後の Severity は最大値、Evidence は全検出器の記録が保持される。これは意図した挙動であり、「なぜ CRITICAL なのか」の根拠が複数残る。

`no_iam_resources` の場合は空の findings と `stats.informational_message` を返す (Requirement 6 AC12)。Finding として出力しない理由は、Finding schema が resource を要求する場面で意味を持たないためである。

すべての Layer 1 Finding は Requirement 6 AC13 に従い、Severity / FindingType / Confidence / logical resource ID / statement 位置 (`Location.TemplatePath`) / 検出リスクの説明 (`Finding`) を含む。

### Policy document の所在

Template 内の IAM policy document は複数の場所に現れる。`locate.find_policy_documents()` は以下を網羅する。

| `PolicyKind` | 所在 | 例 |
| --- | --- | --- |
| `inline_role_policy` | `AWS::IAM::Role` の `Properties.Policies[*].PolicyDocument` | Role に埋め込まれた policy |
| `trust_policy` | `AWS::IAM::Role` の `Properties.AssumeRolePolicyDocument` | 信頼ポリシー |
| `permissions_boundary` | `AWS::IAM::Role` / `AWS::IAM::User` の `Properties.PermissionsBoundary` | ARN 参照のみ。document は Template 内に無いため所在記録のみ |
| `managed_policy` | `AWS::IAM::ManagedPolicy` の `Properties.PolicyDocument` | 独立した managed policy |
| `standalone_policy` | `AWS::IAM::Policy` の `Properties.PolicyDocument` | Role/User/Group に attach される policy |
| `inline_user_policy` | `AWS::IAM::User` の `Properties.Policies[*].PolicyDocument` | |
| `inline_group_policy` | `AWS::IAM::Group` の `Properties.Policies[*].PolicyDocument` | |
| `resource_policy` | resource-based policy を持つ resource type の該当 property | `AWS::S3::BucketPolicy.PolicyDocument`, `AWS::KMS::Key.KeyPolicy`, `AWS::SQS::QueuePolicy.PolicyDocument`, `AWS::SNS::TopicPolicy.PolicyDocument`, `AWS::Lambda::Permission` (policy 形式ではないが Principal を持つため別扱い), `AWS::ECR::Repository.RepositoryPolicyText`, `AWS::SecretsManager::ResourcePolicy.ResourcePolicy` |

`resource_policy` の対象 resource type と property 名は `iacreview/iam/locate.py` 内の table として定義する。v0.1 では上記に限定し、未対応の resource type が存在することを SKILL.md の Limitations に明記する。table への追加は 1 行の追記で済む。

`AWS::Lambda::Permission` は policy document 形式ではないが `Principal` / `SourceAccount` / `SourceArn` を持つため、`cross_account_principal` と `cross_service_missing_condition` の対象として別 `PolicyKind` (`lambda_permission`) で扱う。

### Cross-account 判定ロジック (Requirement 6 AC7-AC10)

```python
_ACCOUNT_ID = re.compile(r"^\d{12}$")
_ARN_ACCOUNT = re.compile(r"^arn:[^:]*:[^:]*:[^:]*:(\d{12}):")

def classify_principal(value: object, template_account_refs: set[str]) -> PrincipalClass:
    """Returns one of: star | same_account | cross_account | service | unresolvable."""
    if value == "*" or value == {"AWS": "*"}:
        return PrincipalClass.STAR                       # AC9
    if isinstance(value, dict):
        if "Ref" in value and value["Ref"] == "AWS::AccountId":
            return PrincipalClass.SAME_ACCOUNT           # AC8
        if "Fn::Sub" in value:
            return _classify_sub(value["Fn::Sub"])       # 下記参照
        if "Fn::GetAtt" in value or "Fn::ImportValue" in value:
            return PrincipalClass.UNRESOLVABLE
    if isinstance(value, str):
        if "${AWS::AccountId}" in value:
            return PrincipalClass.SAME_ACCOUNT           # AC8
        if _ACCOUNT_ID.match(value) or _ARN_ACCOUNT.match(value):
            return PrincipalClass.CROSS_ACCOUNT          # AC7
        if value.endswith(".amazonaws.com"):
            return PrincipalClass.SERVICE
    return PrincipalClass.UNRESOLVABLE
```

`AWS::AccountId` の扱い (AC8): `{"Ref": "AWS::AccountId"}` 形式、および `Fn::Sub` 内の `${AWS::AccountId}` 置換文を same-account と分類する。`Fn::Sub` の文字列が `${AWS::AccountId}` 以外の置換変数を含む場合は、その変数が account ID を注入しうるため `UNRESOLVABLE` とする。

`sts:ExternalId` による Severity 減算 (AC10):

```python
def apply_external_id_mitigation(finding: Finding, statement: dict) -> Finding:
    if not _has_external_id_condition(statement):
        return finding
    return replace(
        finding,
        Severity=lower_one_level(finding.Severity),
        Evidence=finding.Evidence + [Evidence(
            Source="IAM Review",
            Detail="Mitigating condition present: sts:ExternalId is required in this statement, "
                   "which prevents the confused-deputy pattern. Severity was reduced by one level.",
            RuleId="cross_account_principal",
            Excerpt=None,
        )],
    )
```

`_has_external_id_condition` は `Condition` 配下の任意の operator (`StringEquals`, `StringLike`, `ArnEquals` 等) の key が `sts:ExternalId` (大文字小文字を区別しない比較) であるかを確認する。**同一 statement 内** に限る (AC10 の "in the same statement")。他 statement の condition は適用しない。

適用対象は `cross_account_principal` 由来の Finding のみである。`principal_star` (AC9) には適用しない。`Principal: "*"` に ExternalId があっても、ExternalId を知る任意の第三者にアクセスを許すため CRITICAL を維持する。この判断を `docs/security-model.md` に記録する。

### 解決不能な intrinsic function の扱い

`Ref`, `Fn::Sub`, `Fn::GetAtt`, `Fn::If`, `Fn::ImportValue` により Action / Resource / Principal の実値が確定しない場合がある。**静的解析では原理的に解決できない値が存在する**ため、方針を明示的に定める。

| 状況 | 方針 |
| --- | --- |
| 値が literal | 通常の検出器を適用する |
| `{"Ref": "AWS::AccountId"}` / `${AWS::AccountId}` | same-account として確定扱い (AC8) |
| `{"Ref": "<Parameter>"}` で Parameter に `Default` があり、かつ `AllowedValues` が無い | **解決しない**。`UNRESOLVABLE` として扱う。Default 値は deploy 時に上書きされるため、Default に基づく断定は誤検出になる |
| `{"Ref": "<Parameter>"}` で `AllowedValues` が定義されている | AllowedValues の **全要素** に対して検出器を適用する。全要素が危険なら `Confirmed`、一部のみ危険なら `UNRESOLVABLE` 扱いにして下記の Informational Finding を出す |
| `Fn::Sub` で置換後の文字列が固定部分のみで危険パターンに一致 (例: `"arn:aws:iam::${AWS::AccountId}:role/*"` の末尾 `*`) | 固定部分に基づく判定を行う。置換変数部分は不定として扱い、固定部分のみで危険と言える場合に `Confirmed` を付与する |
| `Fn::GetAtt` / `Fn::ImportValue` | `UNRESOLVABLE` |
| `Fn::If` | **両分岐を独立に評価する**。いずれかの分岐が危険なら Finding を出し、Evidence にどちらの分岐かを記録する。Condition の真偽は deploy 時に決まるため両方を報告するのが保守的である |

`UNRESOLVABLE` に到達した場合の出力方針 — **黙って無視しない**。

```json
{
  "Normalized_Category": "IAM",
  "FindingType": "Informational",
  "Severity": "INFO",
  "Confidence": "Confirmed",
  "Source": ["IAM Review"],
  "Resource": "AppExecutionRole",
  "Location": {
    "File": "templates/app.yaml",
    "Line": null,
    "Column": null,
    "TemplatePath": ["Resources", "AppExecutionRole", "Properties", "Policies", 0,
                     "PolicyDocument", "Statement", 1, "Resource"]
  },
  "Finding": "[unresolvable_value] The Resource value at this location is produced by Fn::ImportValue and cannot be evaluated statically, so IAM checks were not applied to it.",
  "WhyItMatters": "A value that cannot be resolved at review time may grant broader access than intended once the stack is deployed. This location was skipped by the deterministic IAM checks, so it is not covered by the Confirmed findings in this report.",
  "Evidence": [
    { "Source": "IAM Review",
      "Detail": "Unresolved intrinsic function: Fn::ImportValue",
      "RuleId": "unresolvable_value",
      "Excerpt": null }
  ],
  "Recommendation": "Review this value manually, or replace the cross-stack import with an explicit resource reference so that it can be evaluated statically.",
  "SuggestedRemediation": null
}
```

`FindingType: Informational` / `Severity: INFO` / `Confidence: Confirmed` とする理由: 「解決できなかった」という事実自体は決定論的に確認済みであり、リスクの推定ではない。リスクを断定していないため steering/security.md の「推測だけで脆弱性が存在すると断定しない」に適合する。同時に検査カバレッジの欠落を利用者に開示するため、監査上必要な情報である。

Requirement 12 AC6 により、negative test の false positive 集計は `Informational` かつ `INFO` の Finding を除外するため、この方針が negative test を不当に失敗させることはない。

### Layer 2: Agent reasoning の入力と制約

`extract_policies.py` の出力:

```json
{
  "policy_sites": [
    {
      "logical_id": "AppExecutionRole",
      "kind": "inline_role_policy",
      "json_path": "Resources.AppExecutionRole.Properties.Policies.0.PolicyDocument",
      "statement_count": 3,
      "actions": ["s3:GetObject", "s3:PutObject", "logs:CreateLogStream"],
      "resources": ["arn:aws:s3:::${AppBucket}/*", "*"],
      "principals": [],
      "has_conditions": [false, false, true],
      "unresolvable_locations": ["Resources.AppExecutionRole...Statement.1.Resource"]
    }
  ],
  "attached_to": {
    "AppExecutionRole": ["AppFunction"]
  },
  "deterministic_findings_summary": [
    { "rule": "wildcard_resource", "resource": "AppExecutionRole", "severity": "HIGH" }
  ]
}
```

SKILL.md が Agent に課す制約:

1. `deterministic_findings_summary` に含まれる内容を再度 Finding として出力しない (Requirement 2 AC14, AC15)。
2. 出力する Finding は `Confidence` を `Likely` または `Contextual` に限る (Requirement 7 AC10)。
3. `Evidence[].Excerpt` に判断根拠となった Template 内容を含める (Requirement 7 AC11)。
4. `Finding` の文言は可能性の表現に限り、脆弱性の存在を断定しない (Requirement 7 AC12)。
5. `Normalized_Category` は閉集合から選ぶ。適切なものが無ければ `Other` を用いる (Requirement 14 AC3)。

---

## Review Flow and Orchestration

### 単一 Template のシーケンス

```mermaid
sequenceDiagram
    autonumber
    participant U as User / Host Agent
    participant O as run_iac_review.py
    participant PG as pathguard
    participant TL as template loader
    participant CL as cfn-lint subprocess
    participant CG as cfn-guard subprocess
    participant IAM as iam_scan
    participant N as normalizer
    participant D as dedup
    participant R as report

    U->>O: run_iac_review.py --target templates/app.yaml
    O->>O: validate argv per Req 16 AC7
    O->>PG: resolve_within target workspace_root
    alt path outside workspace
        PG--)O: PathContainmentError
        O--)U: exit 7 path_violation
    end
    PG-->>O: absolute path
    O->>TL: load_template path
    alt parse failure
        TL--)O: TemplateParseError with type line column
        O--)U: exit 4 parse_failure
    else no Resources mapping
        TL--)O: NotReviewableError path
        O--)U: exit 8 no_reviewable_template
    end
    TL-->>O: LoadedTemplate

    O->>CL: argv cfn-lint -f json -- path
    alt cfn-lint unavailable
        CL--)O: ToolUnavailableError
        O->>O: record tool_unavailable then continue
    else
        CL-->>O: exit code and stdout JSON
        O->>N: normalize cfn-lint results
        N-->>O: Findings with Confidence Confirmed
    end

    O->>CG: argv cfn-guard validate --data path --rules rules
    alt cfn-guard unavailable or tool error
        CG--)O: error
        O->>O: record error then continue
    else
        CG-->>O: exit code and stdout JSON
        O->>N: normalize guard results
        N-->>O: Findings with Confidence Confirmed
    end

    O->>IAM: scan policy sites
    IAM-->>O: Confirmed Findings plus INFO for unresolvable values

    opt agent findings file provided
        O->>N: load_agent_findings path
        N-->>O: Findings with Confidence Likely or Contextual
    end

    O->>D: deduplicate all findings
    D-->>O: merged Findings
    O->>R: build_report findings errors meta
    R-->>O: report dict sorted with IDs assigned
    O--)U: stdout JSON exit 0
```

Source の実行順序は `cfn-lint` → `cfn-guard` → `IAM Review` → `Agent Review` に固定する。理由は Requirement 14 AC11 が Evidence の連結順序をこの順に規定しており、収集順序を同じにしておけば `dedup` で並べ替える必要がなくなるためである。ただし `dedup` は入力順序に依存せず正しい順序を出す実装とする (後述の property 参照)。

### 複数 Template / ディレクトリ入力

```mermaid
flowchart TD
    A["--target <directory>"] --> B["pathguard.resolve_within"]
    B --> C{"cdk.json exists?"}
    C -->|yes| D["report cdk.detected = true<br/>(Req 8 AC2)"]
    C -->|no| E["cdk.detected = false"]
    D --> F["enumerate standalone templates<br/>(excluding cdk.out)"]
    E --> F
    F --> G["review standalone templates first<br/>(Req 8 AC10)"]
    D --> H["enumerate cdk.out/*.template.json"]
    H --> I["review synthesized templates"]
    G --> J["merge into one Review_Report<br/>with per-template grouping"]
    I --> J
    J --> K{"any reviewable template?"}
    K -->|no| L["exit 8 + no_reviewable_template"]
    K -->|yes| M["stdout JSON"]
```

複数 Template の結果の扱い:

- **`dedup` は Template 単位で実行する**。異なる Template の同名 logical ID は別 resource であるため、Template 境界を越えたマージは誤りである。
- Finding ID は Review_Report 全体で連番となる (Requirement 7 AC1)。Template の処理順序 (パス昇順) を固定した上で、全 Template の Finding を統合してから Requirement 7 AC15 の整列を適用し、その後に ID を振る。
- `Location.File` により Finding がどの Template 由来かが判別できる。
- Requirement 8 AC10 の「standalone と synthesized を別々に報告する」は、`target.files` と `target.cdk.synthesized_templates` の 2 配列で表現し、各 Finding は `Location.File` でどちらに属するか判別できる。加えて `summary` に `by_template_group` (`standalone` / `synthesized`) を追加する。

ディレクトリ走査は再帰的に `*.yaml`, `*.yml`, `*.json`, `*.template`, `*.template.json` を収集し、パス昇順でソートする (決定論性)。`cdk.out/`, `node_modules/`, `.git/`, `.venv/` は除外する。除外リストは `iacreview/cdk.py` に定数として持つ。

### CDK フロー (Requirement 8)

```mermaid
flowchart TD
    A["directory input"] --> B{"cdk.json present?"}
    B -->|no| Z["normal template review"]
    B -->|yes| C["report detection (AC2)"]
    C --> D{"cdk.out/*.template.json present?"}
    D -->|yes| E["review synthesized templates (AC1, AC9)"]
    D -->|no| F{"user explicitly requested<br/>review from CDK source?"}
    F -->|no| G["report: no reviewable template (AC5)"]
    F -->|yes| H["warn: cdk synth executes untrusted<br/>project code including dependency<br/>lifecycle scripts (AC4, AC11)"]
    H --> I{"explicit confirmation<br/>--confirm-cdk-synth?"}
    I -->|no| G
    I -->|yes| J{"cdk on PATH?"}
    J -->|no| K["report CDK CLI unavailable + docs link (AC8)"]
    J -->|yes| L["run cdk synth, timeout 120s (AC6)"]
    L --> M{"exit 0 within timeout?"}
    M -->|no| N["report stderr, no fallback (AC7)"]
    M -->|yes| E
```

確認ゲートは `--confirm-cdk-synth` フラグとして実装する。Requirement 16 AC9 が「スクリプトは非対話実行であり stdin からプロンプト入力を読まない」ことを求めるため、対話プロンプトではなく明示的フラグで確認を表現する。フラグ無しで CDK ソースからのレビューが要求された場合は、警告文を `errors[]` に `error_class: "invalid_arguments"` として出し、synth 済み Template のみで続行するか (AC5) `no_reviewable_template` を返す。

警告文は SKILL.md にも記載し、host Agent がユーザーへ提示してから `--confirm-cdk-synth` を付与するフローを促す。これにより「明示的なユーザー確認」(AC4) が Agent 層で担保される。

---

## Deduplication Algorithm

### 等価判定

Requirement 14 AC5: 等価キーは `(Resource, Normalized_Category)`。

```python
def dedup_key(f: Finding) -> tuple[str, str] | None:
    if f.Normalized_Category == "Other":
        return None            # Req 14 AC3: dedup 照合から除外
    if f.Resource is None:
        return None            # template-level finding は互いにマージしない
    return (f.Resource, f.Normalized_Category)
```

`None` を返す Finding は必ず単独で残る (Requirement 14 AC13)。

**`Other` を照合から除外する理由** (Requirement 14 AC3): `Other` は「閉集合のどれにも写像できなかった」ことを意味する残余カテゴリであり、意味的な共通性を持たない。同一 resource 上の `Other` Finding 2 件は全く別の問題を指している可能性が高い。これらをマージすると、無関係な 2 つの問題が 1 件に統合され、Severity は最大値に、Evidence は連結され、結果として意味不明な Finding になる。閉集合内のカテゴリは「同一 resource の同一の関心事」を保証するのに対し、`Other` は保証しない。

### マージ規則

| 対象 | 規則 | 根拠 |
| --- | --- | --- |
| `Severity` | 最大値 (`CRITICAL > HIGH > MEDIUM > LOW > INFO`) | Req 14 AC8 |
| `Confidence` | 最大値 (`Confirmed > Likely > Contextual`)。ただし union に `Agent Review` を含む場合は `Likely` を上限とする ([Correction] C-8) | Req 14 AC9 + Req 7 AC10 |
| `FindingType` | 優先度最大 (`Security > Validity > BestPractice > Informational`) | Req 14 AC10 |
| `Evidence` | Source 順に連結 (`cfn-lint` → `cfn-guard` → `IAM Review` → `Agent Review`)。同 Source 内は入力内の元順序を保持 | Req 14 AC11 |
| `Source` | 全 Source の union を固定順序でソート | Req 14 AC12 |
| `Resource`, `Normalized_Category` | 等価キーなので同一 | — |
| `Location` | 最も情報量の多いものを採用。決定規則: `Line` を持つものを優先、同条件なら Source 順序で先のもの | 設計判断 (下記) |
| `Finding` | Source 順序で先のものを採用 | 設計判断 |
| `WhyItMatters` | 採用した `Finding` と同じ Source のものを採用 | 設計判断 |
| `Recommendation` | 採用した `Finding` と同じ Source のものを採用 | 設計判断 |
| `SuggestedRemediation` | 非 `null` のうち Source 順序で先のもの。全て `null` なら `null` | 設計判断 |
| `ID` | マージ後、整列後に再割り当て | Req 7 AC1 |

`Finding` / `WhyItMatters` / `Recommendation` / `Location` の決定規則は Requirement 14 が規定していないため設計判断である。**Source 順序で先のものを採用** する理由は、その順序が決定論的 Source を優先 (cfn-lint, cfn-guard, IAM Review が Agent Review より先) しており、Agent の非決定的な文言が代表文言になることを避けられるためである。これは Requirement 16 AC11 の byte-identical 要件にも寄与する。全 Evidence は保持されるため情報は失われない。

`Location` については `Line` を持つ方 (通常 cfn-lint) を優先する。行番号のある Location はエディタ連携で有用度が高い。

`Location` の比較は `TemplatePath` が Source 間で同一の綴りであることを前提とする。Source ごとに sequence index を `0` と `"0"` に書き分けると、同一位置が 2 つの位置に見える。そのため `TemplatePath` の正規形 (sequence index は `int`) を Source 境界で確定させる ([Correction] C-9)。

**`Confidence` の上限** ([Correction] C-8): Requirement 14 AC9 の最大値規則と AC12 の Source union をそのまま適用すると、`Confirmed` な決定論的 Finding と `Likely` な Agent Finding のマージ結果が `Confidence: "Confirmed"` かつ `Source` に `Agent Review` を含む状態になる。これは Requirement 7 AC10 (Agent 由来は `Confirmed` を取らない) に反し、`finding.validate` の structural constraint 1 が拒否する。マージは AC9 どおり最大値を取り、その後 union に `Agent Review` があれば `Likely` へ丸める。`finding.validate` 側は緩めない。

```python
_SEV_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
_CONF_ORDER = {"Confirmed": 2, "Likely": 1, "Contextual": 0}
_TYPE_ORDER = {"Security": 3, "Validity": 2, "BestPractice": 1, "Informational": 0}
_SOURCE_ORDER = {"cfn-lint": 0, "cfn-guard": 1, "IAM Review": 2, "Agent Review": 3}


def deduplicate(findings: list[Finding]) -> list[Finding]:
    groups: dict[tuple[str, str], list[Finding]] = {}
    singles: list[Finding] = []
    for f in findings:
        key = dedup_key(f)
        if key is None:
            singles.append(f)
        else:
            groups.setdefault(key, []).append(f)

    merged: list[Finding] = []
    for key in sorted(groups):                      # 決定論的なグループ処理順
        group = groups[key]
        if len(group) == 1:
            merged.append(group[0])                 # Req 14 AC13
            continue
        merged.append(_merge_group(group))
    return merged + singles


def _merge_group(group: list[Finding]) -> Finding:
    ordered = sorted(
        group,
        key=lambda f: (_SOURCE_ORDER[_primary_source(f)], f.Finding),
    )
    primary = _location_primary(ordered)
    sources = sorted({s for f in ordered for s in f.Source}, key=_SOURCE_ORDER.__getitem__)
    confidence = max(ordered, key=lambda f: _CONF_ORDER[f.Confidence]).Confidence
    if "Agent Review" in sources:                    # [Correction] C-8
        confidence = _cap_at_likely(confidence)      # Req 7 AC10
    return Finding(
        ID=0,                                        # report 段階で再割り当て
        Normalized_Category=ordered[0].Normalized_Category,
        FindingType=max(ordered, key=lambda f: _TYPE_ORDER[f.FindingType]).FindingType,
        Severity=max(ordered, key=lambda f: _SEV_ORDER[f.Severity]).Severity,
        Confidence=confidence,
        Source=sources,
        Resource=ordered[0].Resource,
        Location=primary.Location,
        Finding=ordered[0].Finding,
        WhyItMatters=ordered[0].WhyItMatters,
        Evidence=[e for f in ordered for e in sorted(f.Evidence, key=lambda e: _SOURCE_ORDER[e.Source])],
        Recommendation=ordered[0].Recommendation,
        SuggestedRemediation=next((f.SuggestedRemediation for f in ordered
                                   if f.SuggestedRemediation is not None), None),
    )
```

`ordered` の tie-breaker に `f.Finding` を含めることで、同一 Source の複数 Finding が存在する場合も順序が確定する。これが `dedup` の入力順序非依存性 (置換不変性) を保証する。

`max()` は Python の仕様上、最大値が複数あるとき最初の要素を返す。`ordered` が既に決定論的に並んでいるため、結果は決定論的である。

### Worked example: 3 Source が同一 resource を検出

入力 (`dedup` 前):

```json
[
  {
    "Normalized_Category": "IAM", "FindingType": "Security", "Severity": "HIGH",
    "Confidence": "Confirmed", "Source": ["cfn-lint"], "Resource": "AppExecutionRole",
    "Location": { "File": "templates/app.yaml", "Line": 42, "Column": 9,
                  "TemplatePath": ["Resources","AppExecutionRole","Properties","Policies",0,"PolicyDocument","Statement",0,"Action"] },
    "Finding": "[W3037] IAM action \"s3:GetObjects\" is not a valid action.",
    "WhyItMatters": "An invalid or malformed IAM action prevents the policy from granting the intended access, or grants access that was not intended.",
    "Evidence": [{ "Source": "cfn-lint", "Detail": "Rule W3037 (https://github.com/aws-cloudformation/cfn-lint/...)", "RuleId": "W3037", "Excerpt": null }],
    "Recommendation": "Correct the IAM action name to a valid service action.",
    "SuggestedRemediation": null
  },
  {
    "Normalized_Category": "IAM", "FindingType": "Security", "Severity": "MEDIUM",
    "Confidence": "Confirmed", "Source": ["cfn-guard"], "Resource": "AppExecutionRole",
    "Location": { "File": "templates/app.yaml", "Line": null, "Column": null,
                  "TemplatePath": ["Resources","AppExecutionRole","Properties","Policies",0,"PolicyDocument"] },
    "Finding": "[iam_policy_no_star_star] A policy statement allows all actions on all resources.",
    "WhyItMatters": "A statement with Action \"*\" and Resource \"*\" grants unrestricted access.",
    "Evidence": [{ "Source": "cfn-guard", "Detail": "provided: \"*\", expected: not \"*\"", "RuleId": "iam_policy_no_star_star", "Excerpt": null }],
    "Recommendation": "Restrict Action and Resource to the minimum required.",
    "SuggestedRemediation": "Replace Action \"*\" with the specific actions the role needs."
  },
  {
    "Normalized_Category": "IAM", "FindingType": "Security", "Severity": "CRITICAL",
    "Confidence": "Confirmed", "Source": ["IAM Review"], "Resource": "AppExecutionRole",
    "Location": { "File": "templates/app.yaml", "Line": null, "Column": null,
                  "TemplatePath": ["Resources","AppExecutionRole","Properties","Policies",0,"PolicyDocument","Statement",0] },
    "Finding": "[star_action_star_resource] Statement 0 allows Action \"*\" on Resource \"*\".",
    "WhyItMatters": "This grants every permission in the account to any principal that can assume the role.",
    "Evidence": [{ "Source": "IAM Review", "Detail": "Effect=Allow, Action=[\"*\"], Resource=[\"*\"]", "RuleId": "star_action_star_resource", "Excerpt": null }],
    "Recommendation": "Enumerate the specific actions and resource ARNs the role requires.",
    "SuggestedRemediation": "Replace the wildcard statement with least-privilege statements."
  },
  {
    "Normalized_Category": "IAM", "FindingType": "BestPractice", "Severity": "MEDIUM",
    "Confidence": "Likely", "Source": ["Agent Review"], "Resource": "AppExecutionRole",
    "Location": { "File": "templates/app.yaml", "Line": null, "Column": null,
                  "TemplatePath": ["Resources","AppExecutionRole"] },
    "Finding": "The role is attached to AppFunction, which only reads from AppBucket, so the granted permissions may be far broader than the function requires.",
    "WhyItMatters": "Excess permissions increase the blast radius if the function is compromised.",
    "Evidence": [{ "Source": "Agent Review", "Detail": "AppExecutionRole is referenced by AppFunction.Properties.Role", "RuleId": null,
                   "Excerpt": "AppFunction:\n  Type: AWS::Lambda::Function\n  Properties:\n    Role: !GetAtt AppExecutionRole.Arn" }],
    "Recommendation": "Scope the policy to s3:GetObject on AppBucket and the CloudWatch Logs actions the runtime needs.",
    "SuggestedRemediation": null
  }
]
```

`dedup_key` はすべて `("AppExecutionRole", "IAM")` であるため 1 グループ。マージ結果:

```json
{
  "ID": 1,
  "Normalized_Category": "IAM",
  "FindingType": "Security",
  "Severity": "CRITICAL",
  "Confidence": "Likely",
  "Source": ["cfn-lint", "cfn-guard", "IAM Review", "Agent Review"],
  "Resource": "AppExecutionRole",
  "Location": {
    "File": "templates/app.yaml", "Line": 42, "Column": 9,
    "TemplatePath": ["Resources","AppExecutionRole","Properties","Policies",0,"PolicyDocument","Statement",0,"Action"]
  },
  "Finding": "[W3037] IAM action \"s3:GetObjects\" is not a valid action.",
  "WhyItMatters": "An invalid or malformed IAM action prevents the policy from granting the intended access, or grants access that was not intended.",
  "Evidence": [
    { "Source": "cfn-lint",    "Detail": "Rule W3037 (https://github.com/aws-cloudformation/cfn-lint/...)", "RuleId": "W3037", "Excerpt": null },
    { "Source": "cfn-guard",   "Detail": "provided: \"*\", expected: not \"*\"", "RuleId": "iam_policy_no_star_star", "Excerpt": null },
    { "Source": "IAM Review",  "Detail": "Effect=Allow, Action=[\"*\"], Resource=[\"*\"]", "RuleId": "star_action_star_resource", "Excerpt": null },
    { "Source": "Agent Review","Detail": "AppExecutionRole is referenced by AppFunction.Properties.Role", "RuleId": null,
      "Excerpt": "AppFunction:\n  Type: AWS::Lambda::Function\n  Properties:\n    Role: !GetAtt AppExecutionRole.Arn" }
  ],
  "Recommendation": "Correct the IAM action name to a valid service action.",
  "SuggestedRemediation": "Replace Action \"*\" with the specific actions the role needs."
}
```

各フィールドの導出:

| Field | 値 | 導出 |
| --- | --- | --- |
| `Severity` | `CRITICAL` | `max(HIGH, MEDIUM, CRITICAL, MEDIUM)` (AC8) |
| `Confidence` | `Likely` | `max(Confirmed, Confirmed, Confirmed, Likely)` = `Confirmed` (AC9)、`Source` に `Agent Review` を含むため `Likely` へ丸める (Req 7 AC10、[Correction] C-8) |
| `FindingType` | `Security` | `Security > BestPractice` (AC10) |
| `Source` | 4 Source を固定順序で | (AC12) |
| `Evidence` | cfn-lint → cfn-guard → IAM Review → Agent Review | (AC11) |
| `Location` | cfn-lint 由来 (`Line` を持つ唯一のもの) | 設計判断 |
| `Finding` / `WhyItMatters` / `Recommendation` | cfn-lint 由来 (Source 順序で先頭) | 設計判断 |
| `SuggestedRemediation` | cfn-guard 由来 (非 `null` で最初) | 設計判断 |

**この例が示す限界**: cfn-lint の `W3037` (無効な action 名) と IAM Review の `star_action_star_resource` は本来別の問題である。Requirement 14 AC5 の等価キーが `(Resource, Category)` のみであるため、同一 resource 上の異なる IAM 問題は統合される。この粗さは意図されたものであり、Evidence 全件が保持されることで情報損失は起きない。ただし Finding 件数が実際の問題数より少なくなるため、`docs/finding-schema.md` に「1 Finding は 1 resource × 1 category の問題群を表す」と明記する。ベンチマークの Ground_Truth も同じ粒度で記述する必要があり、`benchmark/README.md` にこの前提を記載する (Requirement 11 AC3 の「expected Finding 件数」がこの粒度で数えられる)。

### 整列と ID 割り当て

```python
def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (
        -_SEV_ORDER[f.Severity],        # Severity 降順 (Req 7 AC15)
        f.Resource or "",               # logical ID 昇順、None は空文字列
        f.Normalized_Category,          # 決定論性のための tie-breaker
        f.Finding,                      # 同上
    ))
```

`Normalized_Category` と `Finding` の tie-breaker は Requirement 7 AC15 に規定がないが、同一 Severity + 同一 resource の Finding が複数ある場合に順序を確定させるため必要である。これなしでは Requirement 16 AC11 の byte-identical 要件を満たせない。

整列後、先頭から 1 起点の連番で `ID` を割り当てる (Requirement 7 AC1)。

---

## Error Handling

### Exit code

Requirement 16 AC8 は 5 つの failure class に固有 exit code を要求する。設計は追加の 3 コードを含めて確定する。

| Exit code | 名称 | 意味 | Requirement |
| --- | --- | --- | --- |
| 0 | `OK` | 正常終了。findings が 0 件でも 0 | — |
| 2 | `INVALID_ARGUMENTS` | 引数の検証失敗 (不足、未知フラグ、shell metacharacter 検出) | 16 AC8 |
| 3 | `INPUT_NOT_FOUND` | 入力ファイルが存在しない / 読めない | 16 AC8 |
| 4 | `PARSE_FAILURE` | 入力 Template の YAML / JSON 解析失敗 | 16 AC8 |
| 5 | `TOOL_UNAVAILABLE` | 必須外部ツールが PATH に無い、またはバージョン不足 | 16 AC8 |
| 6 | `TOOL_EXECUTION_FAILURE` | 外部ツールの実行失敗 (crash, timeout, 出力解析不能) | 16 AC8 |
| 7 | `PATH_VIOLATION` | 解決パスが workspace / plugin root 外 | 9 AC5 (設計追加) |
| 8 | `NO_REVIEWABLE_TEMPLATE` | レビュー対象の Template が存在しない | 3 AC5, 8 AC5 (設計追加) |
| 1 | `UNEXPECTED` | 想定外の例外 (bug)。stack trace を stderr に出す | 設計追加 |

1 を `UNEXPECTED` に割り当てるのは、Python が未捕捉例外に対して既定で 1 を返すためである。捕捉できた場合も 1 に統一し、意味を一貫させる。

**exit code はスクリプト単位の終了状態である**。`iac-review` が複数 Source を実行する場合、個別 Source の失敗は `errors[]` に記録され exit 0 を維持する。exit 5 / 6 を返すのは、単独 Skill として実行され当該ツールが唯一の Source である場合、または全 Source が失敗した場合である。この規則を各 SKILL.md の `## Output` に明記する。

### stdout / stderr の分離

Requirement 16 AC10 に従う。

| 出力先 | 内容 |
| --- | --- |
| stdout | 機械可読 JSON のみ。exit code が非ゼロの場合も、可能であれば `errors[]` を含む部分レポートを出す。JSON を構築できない致命的失敗 (exit 1, 2) では stdout は空 |
| stderr | 人間可読の診断。警告、進捗、stack trace |

stderr に secret を出さない (Requirement 9 AC2)。`stderr_head` を 5 行に制限し (Requirement 15 AC7)、外部ツール stderr をそのまま無制限に転載しない。

### Failure mode マトリクス

| Failure mode | 検出箇所 | Exit code (単独 Skill) | `iac-review` での挙動 | stdout | stderr |
| --- | --- | --- | --- | --- | --- |
| 引数不足 / 未知フラグ | argv 検証 (最初の処理) | 2 | 2 | 空 | usage + 不足内容 |
| ファイル名に shell metacharacter (`;` `\|` `&` `$` backtick `>` `<`) | `pathguard.assert_no_shell_metacharacters` | 2 | 2 | 空 | 検出文字とパス |
| 入力ファイルが存在しない | `pathguard.resolve_within` | 3 | 3 | 空 | パスと errno |
| 入力ファイルが読めない (permission) | 同上 | 3 | 3 | 空 | パスと errno |
| YAML / JSON parse failure | `template.load_template` | 4 | 4 | `errors[]` を含む部分レポート | parse error type + line + column |
| binary / truncated 入力 | 同上 | 4 | 4 | 同上 | 同上 |
| `Resources` mapping 無し | `template.is_reviewable` | 8 | 8 (全 Template が該当時) / `errors[]` (一部の場合) | `errors[]` + パス | 対象外である旨 |
| cfn-lint が PATH に無い | `toolcheck.require_tool` | 5 | `errors[]` に記録し継続 | `errors[]` に `tool_unavailable` + `pip install cfn-lint` | 警告 1 行 |
| cfn-guard が PATH に無い | 同上 | 5 | `errors[]` に記録し継続 | `errors[]` に `tool_unavailable` + docs URL | 警告 1 行 |
| ツールバージョン不足 | `toolcheck.require_tool` | 5 | `errors[]` に記録し継続 | `errors[]` に `tool_version` + detected/required/upgrade | 警告 1 行 |
| cfn-lint crash (exit 1 等) | `decode_cfnlint_exit` | 6 | `errors[]` に記録し継続 | `errors[]` に `tool_execution` + exit code + `stderr_head` | stderr 先頭 5 行 |
| cfn-guard 非ゼロ + JSON 解析不能 | `interpret_guard_result` | 6 | `errors[]` に記録し継続 | 同上 | 同上 |
| ツール出力 JSON の構造不一致 | `parse_output` | 6 | `errors[]` に記録し継続。当該 Source の findings は破棄 | `errors[]` に `parse_failure` | 期待構造との差異 |
| timeout (cfn-lint / cfn-guard 60s、cdk synth 120s) | `proc.run` | 6 | `errors[]` に記録し継続。子プロセスを kill | `errors[]` に `tool_timeout` + timeout 秒 | timeout 発生の旨 |
| path が workspace 外に解決 | `pathguard.resolve_within` | 7 | 7 | 空 | 解決先と workspace root |
| symlink が workspace 外を指す | 同上 | 7 | 7 | 空 | 同上 |
| CDK CLI が PATH に無い (synth 確認済み) | `toolcheck.require_tool` | 5 | 5 | `errors[]` に `tool_unavailable` + CDK docs URL | 警告 |
| `cdk synth` 非ゼロ / timeout | `proc.run` | 6 | 6 (fallback しない、Req 8 AC7) | `errors[]` + `stderr_head` | stderr 先頭 5 行 |
| Agent Finding JSON の schema 違反 (個別) | `agentin.load_agent_findings` | — | 当該 Finding を破棄し `errors[]` に記録、継続 | `errors[]` に `schema_violation` | 破棄件数 |
| Agent Finding JSON 全体が不正 | 同上 | 4 | `errors[]` に記録し Agent Finding 抜きで継続 | `errors[]` に `parse_failure` | 位置情報 |
| `category_map.json` が読めない / 不正 | `categories.load_map` | 1 | 1 | 空 | 不正内容。**これは plugin の bug または破損であり継続しない** |
| `_meta.json` が読めない / 不正 (1 カテゴリ) | `cfnguard` 側 | 0 (継続) | `errors[]` に記録し fallback severity で継続 | `errors[]` に `parse_failure` | 警告 |
| 想定外の例外 | 各 Source の except 節 | 1 | `errors[]` に `unexpected` として記録し継続 | `errors[]` | stack trace |

`category_map.json` の不正を継続不能とする理由: Category 閉集合の定義そのものが失われるため、Requirement 14 AC1 を満たす出力を生成できない。誤った出力を出すより明確に失敗する方が安全である。

### 構造化エラーの一貫性

すべての failure は `iacreview.errors` の例外階層を経由し、`to_structured_error()` で同一形状の dict になる。

```python
class IacReviewError(Exception):
    error_class: ClassVar[str]
    exit_code: ClassVar[int]

    def to_structured_error(self, source: str | None = None) -> dict[str, object]: ...

class InvalidArgumentsError(IacReviewError):    error_class = "invalid_arguments";      exit_code = 2
class InputNotFoundError(IacReviewError):       error_class = "input_not_found";        exit_code = 3
class TemplateParseError(IacReviewError):       error_class = "parse_failure";          exit_code = 4
class ToolUnavailableError(IacReviewError):     error_class = "tool_unavailable";       exit_code = 5
class ToolVersionError(IacReviewError):         error_class = "tool_version";           exit_code = 5
class ToolExecutionError(IacReviewError):       error_class = "tool_execution";         exit_code = 6
class ToolTimeoutError(IacReviewError):         error_class = "tool_timeout";           exit_code = 6
class PathContainmentError(IacReviewError):     error_class = "path_violation";         exit_code = 7
class UnsafeArgumentError(IacReviewError):      error_class = "invalid_arguments";      exit_code = 2
class NotReviewableError(IacReviewError):       error_class = "no_reviewable_template"; exit_code = 8
class SchemaViolationError(IacReviewError):     error_class = "schema_violation";       exit_code = 4
class MappingFileError(IacReviewError):         error_class = "unexpected";             exit_code = 1
```

この階層により Requirement 12 AC7 (「構造化エラーオブジェクトを返し unhandled exception を出さない」) と AC8 (「malformed 入力で構造化エラー」) が単一の仕組みで満たされる。各 entry-point script の `main()` は `IacReviewError` を捕捉して `exit_code` を返し、`Exception` を捕捉して exit 1 を返す。

---

## Security Design

### 信頼境界

```mermaid
flowchart LR
    subgraph UNTRUSTED["Untrusted"]
        T1["IaC template content"]
        T2["User-supplied paths"]
        T3["CDK project source<br/>+ dependencies"]
    end

    subgraph PLUGIN["Plugin (trusted code, untrusted data)"]
        P1["argv validation"]
        P2["pathguard"]
        P3["SafeLoader parse"]
        P4["deterministic analysis"]
        P5["report"]
    end

    subgraph EXT["External tools (trusted binaries, untrusted input)"]
        E1["cfn-lint"]
        E2["cfn-guard"]
    end

    subgraph DANGER["Arbitrary code execution boundary"]
        E3["cdk synth"]
    end

    subgraph AGENT["Host Agent runtime"]
        A1["Agent reasoning"]
    end

    T2 --> P1 --> P2
    T1 --> P3
    P2 --> P3 --> P4 --> P5
    P2 -->|"argv array, shell=False"| E1
    P2 -->|"argv array, shell=False"| E2
    E1 --> P4
    E2 --> P4
    T3 -.->|"explicit --confirm-cdk-synth only"| E3
    E3 -.-> P3
    P4 -.->|"facts JSON"| A1
    A1 -.->|"findings JSON, validated"| P4

    classDef bad fill:#ffe6e6,stroke:#c53030
    class E3 bad
```

| 境界 | 越えるもの | 制御 |
| --- | --- | --- |
| Untrusted paths → Plugin | パス文字列 | argv 検証 + `pathguard` (Req 9 AC4, AC5) |
| Untrusted template → Plugin | YAML / JSON テキスト | `SafeLoader` 派生 parser。実行しない (Req 9 AC7) |
| Plugin → External tool | argv 配列 | `shell=False`、文字列連結なし (Req 9 AC4, Req 16 AC6) |
| External tool → Plugin | stdout JSON | 構造検証。不一致は破棄 (Req 5, Req 4) |
| CDK source → `cdk synth` | 任意コード実行 | 明示的確認ゲート + 警告 + sandbox 無しの明記 (Req 8 AC4, AC11) |
| Plugin → Agent | facts JSON | 決定論的抽出のみ。secret を含めない |
| Agent → Plugin | findings JSON | schema 検証 + `Confirmed` 禁止 (Req 7 AC10) |
| Plugin → AWS | **なし** | v0.1 は AWS API を呼ばない (Req 9 AC3) |

### コマンド実行 (Requirement 9 AC4, Requirement 16 AC6)

```python
def run(argv: list[str], timeout_s: int) -> ProcResult:
    if not argv or not isinstance(argv[0], str):
        raise InvalidArgumentsError("argv must start with an executable name")
    resolved = shutil.which(argv[0])
    if resolved is None:
        raise ToolUnavailableError(tool=argv[0])
    try:
        cp = subprocess.run(
            [resolved, *argv[1:]],
            shell=False,                  # 常に False
            stdin=subprocess.DEVNULL,     # Req 16 AC9
            capture_output=True,
            text=True,
            timeout=timeout_s,
            env=_minimal_env(),
            cwd=None,
        )
    except subprocess.TimeoutExpired as exc:
        raise ToolTimeoutError(tool=argv[0], timeout_s=timeout_s) from exc
    return ProcResult(cp.returncode, cp.stdout, cp.stderr, timed_out=False)
```

`_minimal_env()` は `PATH`, `HOME`, `LANG`, `LC_ALL`, `TMPDIR`, および `AWS_*` を除く必要最小限を継承する。`AWS_*` を除外する理由: v0.1 は AWS API を呼ばず、cfn-lint / cfn-guard も静的解析のみを行う。credential を子プロセスに渡さないことで、想定外の API 呼び出しや credential の stderr 混入を構造的に防ぐ。ただし cfn-lint の一部機能 (`--include-experimental` 等) が region 情報を必要とする場合があるため、`AWS_DEFAULT_REGION` と `AWS_REGION` は継承する。これは credential ではない。

### shell metacharacter 拒否の位置づけ (Requirement 9 AC4)

Requirement 9 AC4 は `;` `|` `&` `$` backtick `>` `<` を含む入力値に対して実行を拒否することを求める。

**主たる制御は `shell=False` + argv 配列である**。shell を経由しないため、これらの文字は特別な意味を持たず、shell injection は原理的に成立しない。したがって metacharacter 拒否は **defense-in-depth** であり、以下の副次的な価値を持つ。

1. 将来 shell 経由の実行経路が誤って追加された場合の保険。
2. 攻撃的な意図を持つファイル名 (`report.yaml; rm -rf /`) を早期に拒否し、ログや Finding 出力に混入させない。
3. Requirement 12 AC11 が要求する「shell metacharacter を含むファイル名」の regression test の判定基準になる。

副作用として、`$` を含む正当なファイル名が拒否される。これは v0.1 では許容し、README の Known Limitations に記載する。拒否は **エラーとして明示** されるため、利用者は原因を理解できる。sanitize (文字を除去して続行) ではなく reject を選ぶのは、パス文字列の書き換えが別の脆弱性 (意図しないファイルへのアクセス) を生むためである。

検査対象は「ユーザー入力に由来する argv 要素」に限る。Plugin 自身が構築する固定フラグ (`-f`, `json`, `--output-format` 等) は検査しない。`plugin_root()/rules` のような plugin-owned パスは、plugin root 自体が metacharacter を含む位置に配置されている場合に誤って拒否される可能性があるため、**plugin-owned パスは metacharacter 検査の対象外とし、containment 検査のみを適用する**。この区別を `docs/security-model.md` に記載する。

### Path containment (Requirement 9 AC5, Requirement 1 AC3, Requirement 15 AC3)

```python
def resolve_within(candidate: str, root: Path) -> Path:
    assert_no_shell_metacharacters(candidate)
    root_real = root.resolve(strict=True)
    target = Path(candidate)
    if not target.is_absolute():
        target = root_real / target
    # strict=False: 存在しないパスでも正規化する。存在確認は後で行う
    target_real = target.resolve(strict=False)
    try:
        target_real.relative_to(root_real)
    except ValueError:
        raise PathContainmentError(path=candidate, resolved=str(target_real), root=str(root_real))
    if not target_real.exists():
        raise InputNotFoundError(path=candidate)
    return target_real
```

設計上の要点:

| 要点 | 内容 |
| --- | --- |
| resolve 後に検証する | `..` の文字列検査ではなく、`Path.resolve()` による正規化後に prefix 判定する。`a/../../b` のような多段や、`..` を含まない symlink 経由の脱出も捕捉できる |
| symlink | `Path.resolve()` は symlink を追跡して実体パスを返す。したがって workspace 内の symlink が外部を指す場合、実体パスが root 外になり拒否される。Agent Plugins 1.0.0 の「filesystem-resolved plugin root」と同じ意味論 |
| `relative_to` による prefix 判定 | 文字列 `startswith` は `/workspace-evil` が `/workspace` の prefix 判定を通す問題がある。`Path.relative_to` はパス要素単位で比較するためこの誤りが起きない |
| 2 つの root | ユーザー入力パスは workspace root、plugin-owned パス (`rules/`, `category_map.json`) は plugin root に対して検証する。`plugin_root()` は bootstrap で導出した `Path(__file__).resolve().parents[1]` を返し、`plugin.json` の存在で検証する |
| TOCTOU | `resolve()` 後にファイルが差し替えられる余地は残る。v0.1 では read-only 操作のみであり、影響は「別ファイルを読む」に限られる。この残余リスクを `docs/security-model.md` に記載する |

containment は **sandbox ではない**。Agent Plugins 1.0.0 が明記する通り、containment は package 内のパス解決を制約するのみで、起動したプロセスが到達できる範囲を制約しない。cfn-lint / cfn-guard / `cdk synth` は containment の外側で任意のファイルにアクセスしうる。この事実を `docs/security-model.md` と README の Security Considerations に明記する。

### 一時ファイル (Requirement 9 AC6)

v0.1 の設計では一時ファイルの必要性を最小化する。cfn-lint / cfn-guard はいずれも入力 Template のパスを直接受け取り、stdout で結果を返すため、中間ファイルは不要である。

一時ファイルが必要になる場面は以下に限られる。

1. `cdk synth` の出力先 (ユーザーが `--output` を指定しない場合、CDK 既定の `cdk.out/` を使う。これは workspace 内であり一時ファイルではない)。
2. Agent Finding の受け渡し (Agent が書き、Plugin が読む。workspace 内のファイル)。

それでも将来の必要に備え、統一 helper を用意する。

```python
@contextmanager
def secure_temp_file(suffix: str) -> Iterator[Path]:
    fd, name = tempfile.mkstemp(suffix=suffix)   # 0600 で作成される
    path = Path(name)
    try:
        os.close(fd)
        os.chmod(path, 0o600)                     # 明示的に再確認
        yield path
    finally:
        with contextlib.suppress(OSError):
            path.unlink()
```

- `tempfile.mkstemp` は system-designated temporary directory (`TMPDIR`) に、作成者のみ読み書き可能 (0600) で作成する。予測可能な名前による symlink 攻撃を受けない。
- `finally` により正常終了・例外の双方で削除される。
- **異常終了 (SIGTERM, SIGKILL, プロセスクラッシュ) では `finally` が走らない**。Requirement 9 AC6 が求める "best-effort cleanup" として、`main()` に `atexit` と `signal.SIGTERM` / `SIGINT` ハンドラを登録し、登録済み一時ファイルを削除する。`SIGKILL` は捕捉不能であり、その場合は OS の temp ディレクトリ清掃に委ねる。この残余を `docs/security-model.md` に記載する。

### Template 内容を評価しない (Requirement 9 AC7)

- YAML の読み込みは `yaml.SafeLoader` を継承したクラスのみを使用する。`yaml.Loader` / `yaml.UnsafeLoader` / `yaml.load()` の default loader は使用しない。`!!python/object` 等のタグは `SafeLoader` が拒否する。
- CloudFormation 短縮タグ (`!Ref` 等) の対応は `add_multi_constructor` ではなく、許可タグの明示的な allowlist を `add_constructor` で登録する方式とする。未知のタグは例外になり、`TemplateParseError` として報告される。
- JSON は `json.loads` を使用する。object_hook を設定しない。
- Template 内の文字列を `eval` / `exec` / `subprocess` に渡さない。Template から取り出した値は Finding の `Evidence[].Excerpt` と `Location.TemplatePath` に **データとして** 格納されるのみである。
- Template 内の値が argv に混入する経路は存在しない。argv は Plugin が構築する固定フラグとユーザー入力パスのみで構成される。

### `cdk synth` の任意コード実行 (Requirement 8, Requirement 9)

`cdk synth` は CDK プロジェクトの TypeScript / Python コードを実行し、その過程で依存パッケージの lifecycle script も実行しうる。これは **Plugin が提供する他のすべての機能とは質的に異なるリスク** である。

| 制御 | 内容 | 根拠 |
| --- | --- | --- |
| 自動実行の禁止 | いかなるレビューフローでも `cdk synth` を自動実行しない | Req 8 AC3 |
| 警告 | CDK ソースからのレビュー要求時、依存の lifecycle script を含む任意コード実行であることを警告する | Req 8 AC4 |
| 明示的確認 | `--confirm-cdk-synth` フラグを要求する。無い場合は synth 済み Template のみで続行、または `no_reviewable_template` | Req 8 AC4, AC5 |
| timeout | 120 秒 | Req 8 AC6 |
| fallback の禁止 | 失敗時に代替実行モードへ移行しない | Req 8 AC7 |
| sandbox 無しの明記 | README Known Limitations と `docs/security-model.md` に記載 | Req 8 AC11, Req 13 AC2 |

sandbox を実装しない理由: 適切な sandbox (container, seccomp, namespace) は OS 依存の重い依存関係を必要とし、steering/tech.md の「不要な Framework や依存関係を追加しない」「可搬性を損なわない」に反する。不完全な sandbox は誤った安心を与えるため、実装しないことを明示する方が安全である。この判断を `docs/security-model.md` に記録する。

### Credential (Requirement 9 AC1, AC2)

| 対策 | 実装 |
| --- | --- |
| Repository 内に credential を置かない | Benchmark / Example の credential 相当値はすべて明らかなプレースホルダ (`123456789012`, `AKIAIOSFODNN7EXAMPLE` 相当は使わず `EXAMPLE_ACCESS_KEY_PLACEHOLDER`) を使う。CI に secret scanning を追加する |
| ログ / 出力に credential を出さない | `Evidence[].Excerpt` は Template から抜粋するため、Template 内に hardcode された secret が転載される可能性がある。**対策**: cfn-lint の `W1011` / `W2501` 相当の検出位置および `NoEcho` パラメータ参照箇所については、`Excerpt` を出力せず `"[redacted: this location may contain a credential value]"` を代入する |
| 子プロセスへ credential を渡さない | `_minimal_env()` が `AWS_*` を除外 (`AWS_REGION` / `AWS_DEFAULT_REGION` を除く) |
| stderr の転載を制限 | `stderr_head` を 5 行に制限 (Req 15 AC7) |

`Excerpt` の redaction 規則は decision として重要である。Finding の Evidence は判断根拠として必要だが、Template に平文の secret が書かれている場合、それを Review_Report に転載すると secret がレポート経路 (ログ、CI artifact、issue) へ拡散する。Requirement 9 AC2 の「実行中に secret を出力しない」を守るため、**Evidence の完全性より secret の非拡散を優先する**。redaction が発生した Finding には Evidence に redaction 済みである旨を明記する。

### MCP の security boundary (Requirement 9 AC8, Requirement 1 AC8)

v0.1 は `mcp.json` を同梱しない (Requirement 1 AC7)。`docs/mcp/README.md` に以下を記載する。

| 項目 | 記載内容 |
| --- | --- |
| 用途 | 例として何のために MCP を追加しうるか |
| 必要 Permission | MCP Server プロセスが必要とする権限 |
| Network Access | loopback か外部か。Agent Plugins 1.0.0 は remote non-loopback endpoint に HTTPS を要求する |
| Credentials | Agent Plugins 1.0.0 は v1 で OAuth も portable な credential reference も定義していない。package で設定する header は **可視データであり secret 機構ではない**。したがって MCP に credential を渡す portable な方法は存在せず、環境変数等のクライアント固有機構に依存する |
| 外部送信される Data | Template 内容が外部へ送信されうるか |
| Failure 時の挙動 | MCP Server が起動しない場合、Agent Plugins 1.0.0 は当該エントリのみをスキップし他のコンポーネントの読み込みを継続する。Plugin の core 機能は影響を受けない (Req 10 AC4, AC5) |
| データフロー方向 | Agent → MCP Server (Template パスや内容)、MCP Server → Agent (応答)。Plugin の決定論的コードは MCP を経由しない |
| stdio transport の記法 | `command` は 1 つの実行可能トークン、引数は `args` 配列 (Req 15 AC5)。bundled executable は `./` 始まりの plugin 相対パス。`${PLUGIN_ROOT}` / `${PLUGIN_DATA}` プレースホルダが利用できる |

---

## Portability Design

### Portable core と client 固有拡張の切り分け

Requirement 10 AC1 は core review 機能 (cfn-lint 実行、cfn-guard 実行、IAM review、統一レポート生成) が vendor 固有拡張なしで動作することを求める。

| 構成要素 | 分類 | 理由 |
| --- | --- | --- |
| `plugin.json` | Portable | Agent Plugins 1.0.0 の closed schema に準拠 |
| `skills/**/SKILL.md` | Portable | Agent Skills 仕様。Agent Plugins は SKILL.md を再定義しない |
| `skills/**/scripts/*.py` | Portable | Python 3 のみに依存 |
| `iacreview/**` | Portable | 同上 |
| `rules/**` | Portable | cfn-guard の rule DSL |
| `docs/kiro-power.md` | Portable な文書 (内容は Kiro 固有) | 文書であり、core の読み込みに関与しない |
| `.kiro/steering/`, `.kiro/specs/` | Kiro 固有 | 開発用ファイル。plugin の実行に不要 |

### `extensions` フィールドと `com.*` ディレクトリの判断

**v0.1 では `plugin.json` に `extensions` を出現させず、reverse-domain ディレクトリも作らない。**

理由:

1. Requirement 10 AC1 が求める core 機能はすべて Skills + Python + 外部ツールで完結する。Kiro 固有の hook / command / agent 定義を必要としない。
2. Agent Plugins 1.0.0 において hooks / commands / agents は **portable な v1 コンポーネントではない**。これらを追加すると、他クライアントが無視する機能に依存した体験が生まれ、Requirement 10 AC9 の「portable core が他クライアントで Kiro 固有ファイルなしにロードできる」を維持しにくくなる。
3. 未使用の `extensions` を空で置くことは、schema 上は許容されうるが意味を持たない。steering/development-principles.md の「過度な抽象化を避ける」「便利そうという理由だけで新機能を追加しない」に従い置かない。

Requirement 10 AC2 は「vendor 固有設定を `extensions` フィールドまたは指定拡張ディレクトリで portable core から分離する」ことを求める。v0.1 は **vendor 固有設定を一切持たない** ことでこの要求を満たす。分離すべきものが存在しないため、分離機構も不要である。将来 Kiro 固有の hook を追加する場合は `plugin.json` の `extensions` に `dev.kiro` 名前空間を追加し、必要なら同名のトップレベルディレクトリを作る。この方針を `docs/architecture.md` に記録する。

Kiro 固有の導入手順 (Power としての読み込み手順) は `docs/kiro-power.md` に分離し、README からリンクする (Requirement 10 AC7, AC9、Requirement 13 AC1 の "Using as a Kiro Power" 節)。手順書はファイルとして plugin に含まれるが、他クライアントでの読み込みに影響しない。

Requirement 10 AC8 (Kiro で全 Skill が discoverable) は、`skills/` 直下に 5 つの Skill ディレクトリを置き各々に `SKILL.md` を持たせることで満たす。skill discovery が非再帰であることに対し、`skills/<name>/SKILL.md` の 1 階層構造は仕様に完全に適合する。

### OS 間の一貫性 (Requirement 10 AC3)

macOS と Linux で決定論的コンポーネントが同一結果を返すための設計要件。

| 差異要因 | 対処 |
| --- | --- |
| パス区切り | `pathlib.Path` を使用。`Location.File` は `PurePosixPath` で `/` 区切りに正規化して出力する |
| 改行 | ファイル読み込みは `newline=None` (universal newlines)。出力は `\n` 固定 |
| ファイルシステムの大文字小文字 | ディレクトリ走査結果を常にパス昇順ソートする。macOS の case-insensitive FS でも同一順序になる |
| `os.listdir` の順序 | 常に `sorted()` を適用 |
| dict 順序 | Python 3.7+ は挿入順を保証。加えて JSON 出力時に `sort_keys=True` |
| locale による文字列比較 | `sorted()` は Python の既定でコードポイント順。`locale.strcoll` は使用しない |
| 外部ツールのバージョン差 | Finding は tool version を `tools[].version` に記録する。バージョン差による findings の差異は OS 差ではないため AC3 の対象外である旨を `docs/architecture.md` に明記 |
| Windows | v0.1 では対象外 (requirements.md Open Question 3)。README に明記 |

### Python 3 の最低バージョン

**Python 3.9 を最低要件とする。**

| 検討 | 内容 |
| --- | --- |
| 必要な言語機能 | `dict` の順序保証 (3.7+)、dataclasses (3.7+)、`functools.cached_property` (3.8+)、`dict` merge operator は使わない |
| 型注釈 | `list[str]` / `dict[str, int]` / `str \| None` 形式を使いたいが、前者は 3.9+、後者 (PEP 604) は 3.10+。**`from __future__ import annotations` を全モジュール先頭に置くことで、3.9 でも両形式を注釈として記述できる** (実行時に評価されないため)。実行時に型を評価する箇所 (`typing.get_type_hints`) は作らない |
| cfn-lint の要件 | cfn-lint は独自に Python バージョン要件を持つが、Plugin は cfn-lint を subprocess として呼ぶため、Plugin の Python と cfn-lint の Python は同一である必要がない。したがって cfn-lint の要件は Plugin の下限を押し上げない |
| 3.9 を選ぶ理由 | requirements.md Assumption 2 が 3.9 以上を前提としている。3.9 は主要 Linux ディストリビューション (RHEL 9, Ubuntu 20.04) と macOS の一般的な環境で入手可能。下限を上げるとポータビリティが下がる |
| 3.8 以下を除外する理由 | 3.8 は EOL。`list[str]` 形式の注釈が `from __future__ import annotations` を使ってもエラーになるケース (dataclass の `field` 解決等) を避ける |

CI で 3.9 / 3.11 / 3.13 の 3 バージョンをテストし、3.9 で動作することを保証する。

### 単一 YAML 依存 (Requirement 16 AC3)

**依存名: `PyYAML` (>= 6.0)。**

Requirement 16 AC3 は「Python 標準ライブラリ + 最大 1 つの YAML 解析依存」を許す。steering/tech.md の 5 つの確認事項に照らす。

| 確認事項 | 評価 |
| --- | --- |
| 1. 標準機能では実現できないか | **できない**。Python 標準ライブラリに YAML parser は存在しない。CloudFormation Template は YAML が主流であり、YAML 対応は Requirement 3 AC4 が必須としている。自前実装は YAML 仕様の複雑さ (anchor, alias, multi-document, block scalar) から現実的でなく、かつ untrusted 入力を扱うため自前 parser は security risk が高い |
| 2. 本当に必要か | **必要**。Requirement 3 AC4 が YAML 対応を要求する |
| 3. 保守されているか | PyYAML は広く使われ継続的に保守されている。cfn-lint 自身も YAML 解析を行うため、cfn-lint をインストールした環境には既に PyYAML 系の依存が入っている可能性が高く、実質的な追加負担が小さい |
| 4. Security Risk はないか | `yaml.load()` の default loader は任意オブジェクト構築を許すため危険である。設計は `SafeLoader` 派生のみを使用し、未知タグを拒否する allowlist 方式を採る (Security Design 節参照)。この使い方であれば untrusted 入力に対して安全である |
| 5. 可搬性を損なわないか | pure Python fallback を持ち (`libyaml` が無くても動作)、macOS / Linux 双方で `pip install PyYAML` で導入できる |

代替候補 `ruamel.yaml` を採らない理由: コメントや書式を保持する機能は本 Plugin には不要 (レビューは read-only であり Template を書き戻さない) であり、依存が重く API が複雑になる。steering/tech.md「数行のコード削減だけを目的に Dependency を追加しない」の裏返しとして、不要な機能のために重い依存を採らない。

**インストール方法**: Plugin は binary を bundle しない (Requirement 15 AC1) ため、PyYAML も bundle しない。README の Requirements 節に `pip install PyYAML` を記載する。加えて `iacreview/yamlcfn.py` の import 失敗時に、以下の明確なエラーを返す。

```python
try:
    import yaml
except ImportError as exc:
    raise ToolUnavailableError(
        tool="PyYAML",
        required_min_version="6.0",
        remediation="Install PyYAML: pip install 'PyYAML>=6.0'",
    ) from exc
```

**JSON 入力のみの場合の縮退動作**: PyYAML が無い環境でも JSON Template のレビューは可能である。`yamlcfn` の import を遅延させ、YAML ファイルを読もうとした時点で初めて失敗させる。これにより PyYAML 欠如が JSON レビューを阻害しない。この縮退を `docs/architecture.md` に記載する。

### 外部ツールの最低バージョン (Requirement 10 AC6)

| Tool | 最低バージョン | 検出コマンド | インストール (macOS) | インストール (Linux) |
| --- | --- | --- | --- | --- |
| Python 3 | 3.9 | `python3 --version` | `brew install python@3.11` | ディストリビューションのパッケージ、または `pyenv` |
| PyYAML | 6.0 | import 時に `yaml.__version__` | `pip install 'PyYAML>=6.0'` | 同左 |
| cfn-lint | 1.0.0 | `cfn-lint --version` | `pip install cfn-lint` | `pip install cfn-lint` |
| cfn-guard | 3.0.0 | `cfn-guard --version` | `brew install cloudformation-guard` または公式インストールスクリプト | 公式インストールスクリプト、または `cargo install cfn-guard` |
| AWS CDK CLI | 2.0.0 | `cdk --version` | `npm install -g aws-cdk` | `npm install -g aws-cdk` |

CDK CLI は `--confirm-cdk-synth` を使う場合のみ必要な optional 依存である。この区別を README の Requirements 節で明示する。

---

## Determinism Design

Requirement 16 AC11 は「同一入力での 2 回の実行が byte-identical な stdout を生成し、timestamp、絶対ホストパス、その他の環境依存値を含まない」ことを求める。

### 排除する非決定性

| 非決定性の源 | 対処 |
| --- | --- |
| Timestamp | Review_Report に生成時刻を含めない。`schema_version` のみを持つ |
| 絶対パス | `Location.File` は workspace root からの相対パスを `/` 区切りで出力。`target.files` も同様。`StructuredError` のパスも相対化する |
| ユーザー名 / ホスト名 | 出力に含めない |
| 環境変数 | 出力に含めない |
| ディレクトリ走査順 | 常に `sorted()` |
| dict のキー順 | `json.dumps(..., sort_keys=True)` |
| set の反復順 | `Source` の union は `sorted()` で固定順序化。他の set 反復も必ずソートする |
| `id()` / メモリアドレス | 出力に使わない |
| 乱数 | 使わない |
| 浮動小数点 | Finding schema に float フィールドを持たない。Benchmark の percentage は小数第 1 位で丸めた文字列表現として出力する |
| Python の hash randomization | `sort_keys=True` と明示的な `sorted()` により、`PYTHONHASHSEED` の影響を受けない |
| 外部ツールの出力順 | ツール出力をそのまま順序として使わない。必ず `dedup` → `sort_findings` を通す |
| 例外の stack trace | stdout に出さない (stderr のみ) |

### 出力の直列化

```python
def dump(report: dict[str, object]) -> str:
    return json.dumps(
        report,
        sort_keys=True,
        ensure_ascii=False,
        indent=2,
        separators=(",", ": "),
    ) + "\n"
```

`ensure_ascii=False` を選ぶ理由: Template 内の非 ASCII 文字 (日本語のコメントや Tag 値) が `\uXXXX` エスケープされずそのまま出力される方が可読性が高い。UTF-8 で書き出すため byte 列は決定論的である。出力ストリームのエンコーディングは `sys.stdout.reconfigure(encoding="utf-8", newline="\n")` で明示的に固定し、`LANG` / `LC_ALL` の影響を排除する。

`indent=2` と `separators=(",", ": ")` を明示するのは、`indent` 指定時の Python の既定 separator が `(",", ": ")` であることに依存せず固定するためである。

### ID 割り当ての安定性

`ID` は「整列後の位置」で決まるため、findings の集合が同じなら ID も同じになる。整列キーには Severity / Resource / Category / Finding 文字列が含まれ、これらすべてが決定論的 Source では安定している。したがって ID も安定する。

### 非決定的メタデータの置き場所

生成時刻やツールの絶対パスといった値は運用上有用である。これらは **stdout の Review_Report には含めず**、以下に置く。

| 情報 | 置き場所 |
| --- | --- |
| 生成時刻 | stderr の診断行 (`--verbose` 時のみ) |
| ツールの解決済み絶対パス | stderr の診断行 (`--verbose` 時のみ) |
| workspace root の絶対パス | stderr の診断行 (`--verbose` 時のみ) |
| 実行所要時間 | stderr の診断行 (`--verbose` 時のみ) |

`--verbose` の有無は stdout を変えない。この不変性をテストで検証する。

### Agent Review を含む場合の決定論性の範囲

Agent Finding が含まれる場合、Review_Report 全体は決定論的ではない。Requirement 16 AC11 が対象とするのは決定論的コンポーネントである (Requirement 10 AC3 も「deterministic components」と限定している)。

設計上の保証:

1. **Agent Finding を除いた入力に対して、パイプラインは byte-identical な出力を返す**。
2. **同一の Agent Finding JSON を入力すれば、パイプライン全体も byte-identical な出力を返す**。すなわち `dedup` と `sort_findings` は Agent Finding に対しても決定論的に振る舞う。
3. Agent Finding の生成そのものが非決定論的である。この事実を README の Known Limitations に記載する (Requirement 13 AC2)。

保証 2 が重要である。これにより Agent の出力を fixture として固定すれば、パイプライン全体を回帰テストできる。

---

## Testing Strategy

### テストフレームワークの選定

**`pytest` (>= 7.0) と `hypothesis` (>= 6.0) を dev dependency として採用する。`coverage` は `pytest-cov` 経由で使う。**

steering/tech.md の依存最小化方針に対する評価:

| 依存 | 分類 | 標準機能では実現できないか | 判断 |
| --- | --- | --- | --- |
| `pytest` | dev only | `unittest` で代替可能。しかし parametrize、fixture、`monkeypatch`、簡潔な assert が Requirement 12 の網羅要求 (AC1 の 80% coverage、AC9 の全フィールド対応検証) を現実的なコード量で実現するために有効。`unittest` では parametrize 相当を自前で書く必要があり、テストコード量が大幅に増える | **採用** |
| `hypothesis` | dev only | 代替不能。property-based testing を自作すると shrinking や再現用 seed 管理を自前実装することになり、steering/tech.md「数行のコード削減だけを目的に Dependency を追加しない」の逆で、大量の実装を避けるための正当な依存である | **採用** |
| `pytest-cov` | dev only | `coverage.py` を直接使うことも可能。`pytest-cov` は薄いプラグインであり、Requirement 12 AC1 の coverage 計測を CI で 1 コマンドにする | **採用** |

Requirement 16 AC3 が制約するのは **Python components の runtime 依存** (「標準ライブラリ + 最大 1 つの YAML 依存」) である。dev / test 依存はこの制約の対象外である。この解釈を `docs/architecture.md` と CONTRIBUTING.md に明記する。runtime と dev の依存を分離して管理する。

`pyproject.toml`:

```toml
[project]
name = "aws-iac-review-agent-plugin"
requires-python = ">=3.9"
dependencies = ["PyYAML>=6.0"]

[project.optional-dependencies]
dev = ["pytest>=7.0", "pytest-cov>=4.0", "hypothesis>=6.0"]

[tool.pytest.ini_options]
testpaths = ["tests"]
addopts = "-q --strict-markers"

[tool.coverage.run]
source = ["iacreview", "benchmark/harness"]
```

`pyproject.toml` は依存宣言と test / coverage 設定のためだけに存在し、PyPI 配布は行わない。Plugin はディレクトリとして配布される。

### テスト種別の対応表

| Requirement / steering | テスト種別 | 場所 | 技法 |
| --- | --- | --- | --- |
| 12 AC1 (unit, 80% line coverage) | Unit | `tests/unit/` | 純関数への直接呼び出し。`pytest --cov` で計測。CI で 80% を下回ったら失敗させる |
| 12 AC2 (integration, 3 Template 以上, schema 適合) | Integration | `tests/integration/test_pipeline_end_to_end.py` | `examples/` の 3 Template に対して `run_iac_review.py` を subprocess 実行し、stdout JSON を Finding JSON Schema で検証 |
| 12 AC3-AC6 (negative test, 2 Template 以上) | Negative | `tests/negative/test_clean_templates.py` | `benchmark/cases/case-101-*`, `case-102-*` を使用。決定論的 Source の HIGH/CRITICAL が 0 件、Ground_Truth 外の Finding が 0 件を検証 (AC6 の除外規則を適用) |
| 12 AC7 (tool unavailable) | Tool-unavailable | `tests/integration/test_tool_unavailable.py` | 後述の `fakebin` 方式 |
| 12 AC8 (malformed 入力) | Integration / Regression | `tests/integration/test_malformed_input.py` | `tests/fixtures/invalid/` の不正 YAML / JSON / truncated / binary |
| 12 AC9 (cfn-lint 全フィールド対応) | Unit | `tests/unit/test_cfnlint_parse.py` | `tests/fixtures/tool_output/cfnlint_*.json` の固定 fixture に対する `parse_output()` の純関数テスト。全 13 Finding フィールドの値を明示的に assert する |
| 12 AC10-AC12 (regression, security) | Regression | `tests/regression/` | 各セキュリティケースを個別ファイルに分離 |
| steering/testing.md (Determinism) | Property | `tests/property/test_prop_determinism.py` | `hypothesis` で生成した Finding 集合に対する byte-identical 検証 |
| steering/testing.md (構造化評価) | Property | `tests/property/` | Correctness Properties 節の各 property に 1 テスト |

### tool-unavailable テストの技法

**ツールをアンインストールせずに検証する**。`monkeypatch` で `PATH` を差し替える。

```text
tests/fakebin/
├── cfn-lint-missing/          # 空ディレクトリ。PATH をこれだけにすると cfn-lint が見つからない
├── cfn-lint-crash/
│   └── cfn-lint              # #!/bin/sh; echo "boom" >&2; exit 1
└── cfn-lint-oldversion/
    └── cfn-lint              # #!/bin/sh; [ "$1" = "--version" ] && echo "cfn-lint 0.83.0"; exit 0
```

```python
def test_cfn_lint_missing_returns_structured_error(monkeypatch, tmp_path):
    monkeypatch.setenv("PATH", str(FAKEBIN / "cfn-lint-missing"))
    result = cfnlint.run_and_normalize(VALID_TEMPLATE)
    assert result.findings == []
    assert len(result.errors) == 1
    err = result.errors[0]
    assert err["error_class"] == "tool_unavailable"
    assert err["tool"] == "cfn-lint"
    assert "pip install cfn-lint" in err["remediation"]
```

この方式の利点:

- 実際のツールをアンインストールしないため CI とローカルの両方で安全に実行できる。
- crash / 古いバージョン / timeout の 3 パターンを、実ツールでは再現困難な形で決定論的に再現できる。
- `fakebin` のスクリプトは POSIX sh の数行であり、steering/tech.md の「Shell Script は単純な補助処理に限定する」に適合する。実行ビットを git で管理する。

timeout の検証には `sleep 999` を実行する fake tool を用意し、`timeout_s` を 1 に縮めたテストで `ToolTimeoutError` を確認する。

同様の方式で cfn-guard、`cdk` の未導入 / crash も検証する。

### coverage 80% の達成方針 (Requirement 12 AC1)

計測対象は `iacreview/` と `benchmark/harness/` である。`skills/**/scripts/*.py` は path bootstrap と `main()` のみの薄い層であり、integration test が subprocess 経由で実行するため line coverage には反映されにくい。**計測対象から除外せず、`coverage` の subprocess 計測 (`COVERAGE_PROCESS_START`) を有効にする** ことで integration test の実行も計上する。これにより「テストしやすい部分だけを計測対象にする」ことを避ける。

除外するのは `if TYPE_CHECKING:` ブロックと `if __name__ == "__main__":` 行のみとする。

### Negative test の判定 (Requirement 12 AC3-AC6)

```python
_EXCLUDED = {("Informational", "LOW"), ("Informational", "INFO"),
             ("BestPractice", "LOW"), ("BestPractice", "INFO")}

def count_false_positives(findings: list[dict], ground_truth: list[dict]) -> int:
    expected = {(g["resource"], g["normalized_category"]) for g in ground_truth}
    count = 0
    for f in findings:
        if "Agent Review" in f["Source"] and len(f["Source"]) == 1:
            continue                                    # 決定論的 Source のみを対象 (AC5)
        if (f["FindingType"], f["Severity"]) in _EXCLUDED:
            continue                                    # AC6 の除外規則
        if (f["Resource"], f["Normalized_Category"]) not in expected:
            count += 1
    return count
```

AC6 は「`FindingType` が `Informational` または `BestPractice` であり、かつ `Severity` が LOW または INFO」の Finding を除外する。両条件の AND であるため、`BestPractice` + `MEDIUM` は除外されず false positive として数えられる。これは意図した厳しさである。

IAM review の `unresolvable_value` Finding は `Informational` + `INFO` であるため除外され、negative test を失敗させない (IAM 節の設計と整合)。

### Property-based test の構成

各 property は 1 つのテスト関数として実装する。最低 100 iteration。

```python
# tests/property/test_prop_dedup.py
from hypothesis import given, settings

# Feature: aws-iac-review-agent-plugin, Property 2: For any list of Findings,
# deduplicate is idempotent: deduplicate(deduplicate(x)) equals deduplicate(x).
@settings(max_examples=100)
@given(findings=finding_lists())
def test_dedup_is_idempotent(findings: list[Finding]) -> None:
    once = deduplicate(findings)
    twice = deduplicate(once)
    assert twice == once
```

`finding_lists()` は `tests/property/strategies.py` に置く共有 strategy であり、Finding schema の許可値のみを生成する。resource logical ID は小さな集合 (`{"A", "B", "C", None}`) から選ぶことで衝突を意図的に発生させ、マージ経路を確実に踏ませる。

### テスト失敗時の方針

steering/testing.md に従い、テストを通すために Requirement を弱めない。失敗原因を Implementation Bug / Test Bug / Requirement 不足 / Agent 非決定性 / Tool 差異 のいずれかに分類し、CONTRIBUTING.md にその分類手順を記載する。

---

## Benchmark Strategy

### Harness 設計

```mermaid
flowchart TD
    A["run_benchmark.py --cases benchmark/cases --mode combined"] --> B["enumerate case directories (sorted)"]
    B --> C["for each case: load ground_truth.json"]
    C --> D["run review pipeline on template<br/>with source subset per --mode"]
    D --> E["match actual findings to expected findings"]
    E --> F["metrics.compute per case and per category"]
    F --> G["stdout JSON summary"]
    G --> H{"any deterministic category<br/>with detection rate < 100%?"}
    H -->|yes| I["status FAIL for that category<br/>(Req 11 AC7)"]
    H -->|no| J["status PASS"]
```

Harness は `benchmark/harness/run_benchmark.py` にあり、`iacreview` を import して pipeline を実行する。Agent Finding は取り込まない (`--agent-findings` を渡さない) ため、`combined` モードでも決定論的 Source のみが対象になる。`agent-dependent` の expected finding は「検出されなかった」として記録され、AC8 に従い pass/fail 閾値を適用しない。

**Harness は決定論的である** (Requirement 11 の `Benchmark_Harness` の定義)。Agent 出力を取り込む場合は `--agent-findings <dir>` で固定 fixture として渡す形を用意し、非決定性を実行時に持ち込まない。

### Ground_Truth ファイル形式

```json
{
  "schema_version": "1.0.0",
  "case_id": "case-001-iam-wildcard",
  "template": "template.yaml",
  "description": "An IAM role with a policy granting Action \"*\" on Resource \"*\", plus an unrestricted iam:PassRole statement.",
  "authored_before_review": true,
  "expected_finding_count": 2,
  "expected_findings": [
    {
      "resource": "AdminRole",
      "normalized_category": "IAM",
      "finding_type": "Security",
      "severity": "CRITICAL",
      "detection_class": "deterministic",
      "detected_by": ["IAM Review", "cfn-guard"],
      "note": "Action \"*\" with Resource \"*\" in the inline policy."
    },
    {
      "resource": "DeployRole",
      "normalized_category": "IAM",
      "finding_type": "Security",
      "severity": "CRITICAL",
      "detection_class": "deterministic",
      "detected_by": ["IAM Review"],
      "note": "iam:PassRole with Resource \"*\"."
    }
  ],
  "expected_findings_agent_only": [],
  "expected_findings_human_review": []
}
```

| Field | 意味 | 根拠 |
| --- | --- | --- |
| `expected_finding_count` | 期待 Finding 総数 | Req 11 AC3 |
| `expected_findings[].resource` / `normalized_category` / `finding_type` / `severity` | 照合キーと期待値 | Req 11 AC3 |
| `detection_class` | `deterministic` または `agent-dependent` | Req 11 AC4 |
| `detected_by` | 期待される Source。`--mode` によるフィルタ時の照合に使う | Req 11 AC10, AC11 |
| `expected_findings_agent_only` | **予約フィールド**。v0.1 では常に空配列 | Req 11 AC12 |
| `expected_findings_human_review` | **予約フィールド**。v0.1 では常に空配列 | Req 11 AC12 |
| `authored_before_review` | Ground_Truth がレビュー実行前に作成されたことの宣言 | Req 11 AC14, AC15 |

予約フィールドを空配列として **必ず存在させる** ことで、将来モードを追加する際に Ground_Truth 形式を変更する必要がなくなる (AC12)。`ground_truth.schema.json` でこの 2 フィールドを `required` にし、v0.1 では `maxItems: 0` の制約を課さない (将来値を入れられるようにする)。

`authored_before_review` は機械的に検証できない宣言である。CONTRIBUTING.md で「Ground_Truth は Benchmark_Template の意図した欠陥から先に記述し、レビュー出力から逆算してはならない」(Requirement 11 AC14, AC15) と規定し、review process でこの宣言を確認する。加えて `git log` 上で `ground_truth.json` が `template.yaml` と同一 commit または先行 commit で追加されていることを CI でチェックする。これは完全な保証ではないが、逆算の抑止として機能する。

### 「正しい検出」の判定

Requirement 11 AC9 は `agent-dependent` の照合を「target resource logical ID、FindingType、Normalized_Category による照合であり、Finding description の文字列完全一致ではない」と規定する。設計は **全 detection class に同じ照合規則を適用する**。

```python
def match_key(item: Mapping[str, object]) -> tuple[str, str, str]:
    return (
        str(item["resource"] if "resource" in item else item["Resource"]),
        str(item["finding_type"] if "finding_type" in item else item["FindingType"]),
        str(item["normalized_category"] if "normalized_category" in item else item["Normalized_Category"]),
    )
```

**「正しい検出」= actual finding の `match_key` が expected finding の `match_key` と一致すること**。Severity は照合キーに含めない。Severity は別途 Severity Accuracy として計測する (Requirement 11 AC6)。Severity を照合キーに含めると、Severity のずれが「未検出」として扱われ Detection Rate と Severity Accuracy が二重にペナルティを受けるためである。

`Resource` が `null` の finding は `match_key` の第 1 要素を空文字列とする。

照合は 1 対 1 マッチングとする。同一 `match_key` の expected が複数ある場合 (通常は起きないが Ground_Truth の記述次第で起こりうる)、actual を先着順に消費する。処理順序は expected の記述順 (Ground_Truth 内の配列順) に固定し決定論性を保つ。

### 指標の定義

記号:

- `E` = 評価対象の expected findings 集合 (`--mode` および detection class によるフィルタ後)
- `A` = 評価対象の actual findings 集合 (`--mode` によるフィルタ後)
- `TP` = `E` の要素と `match_key` で 1 対 1 マッチした `A` の要素数
- `FN` = `|E| - TP` (マッチしなかった expected)
- `FP` = `|A| - TP` (マッチしなかった actual)
- `SM` = TP のうち、actual の `Severity` が expected の `severity` と一致する件数

| 指標 | 定義式 | 出力形式 | Requirement |
| --- | --- | --- | --- |
| Detection Rate | `TP / |E| * 100` | 小数第 1 位までの percentage 文字列 | 11 AC5 |
| False Positive count | `FP` | 整数 | 11 AC5 |
| Precision | `TP / (TP + FP) * 100` | 小数第 1 位までの percentage 文字列 | 11 AC5 |
| Recall | `TP / (TP + FN) * 100` | 小数第 1 位までの percentage 文字列 | 11 AC5 |
| Severity Accuracy | `SM / TP * 100` | 小数第 1 位までの percentage 文字列 | 11 AC6 |

境界条件:

| 条件 | 扱い |
| --- | --- |
| `|E| == 0` | Detection Rate = `"N/A"`。Recall = `"N/A"` |
| `TP + FP == 0` | Precision = `"N/A"` (Finding が 1 件も出なかった) |
| `TP == 0` | Severity Accuracy = `"N/A"` |

`Recall` は本設計では `TP / (TP + FN) = TP / |E|` であり **Detection Rate と数値的に一致する**。Requirement 11 AC5 が両方を要求しているため両方を出力するが、この同一性を `docs/benchmark-methodology.md` に明記する。異なる値になるのは「検出したが誤った Severity を付けた」を FN に数える定義を採る場合であり、本設計はその定義を採らない (前述の二重ペナルティ回避のため)。

percentage の丸め: `f"{value:.1f}"` を使用する。Python の `round` は banker's rounding であるため、境界値での挙動を `docs/benchmark-methodology.md` に記載する。値は文字列として出力し、浮動小数点の表現差による非決定性を排除する。

### Source subset モード (Requirement 11 AC10, AC11)

| `--mode` | 有効化する Source | expected 側のフィルタ |
| --- | --- | --- |
| `cfn-lint-only` | `cfn-lint` | `detected_by` に `cfn-lint` を含む expected のみ |
| `cfn-guard-only` | `cfn-guard` | `detected_by` に `cfn-guard` を含む expected のみ |
| `iam-only` | `IAM Review` | `detected_by` に `IAM Review` を含む expected のみ |
| `combined` (既定) | `cfn-lint`, `cfn-guard`, `IAM Review` | 全 expected |

actual 側のフィルタは Finding の `Source` list に対して行う。マージ済み Finding は複数 Source を持つため、`Source` に対象 Source を含めば評価対象に入る。これが Requirement 11 AC10 の「per-Source attribution を保持し、レビュー実行後に単一 Source へフィルタできる」を満たす。**フィルタはレビュー実行後に行う** ため、モードごとに pipeline を再実行する必要がない。ただし Source を無効化した状態での挙動も検証したいため、`--mode` は pipeline 実行時の Source 有効化にも作用する。両者を区別するために `--filter-only` フラグを用意し、既定は実行時無効化とする。

### Pass / Fail 判定 (Requirement 11 AC7, AC8)

```python
def category_status(dr: float | None, has_deterministic: bool) -> str:
    if not has_deterministic:
        return "INFO"          # agent-dependent のみ -> 閾値なし (AC8)
    if dr is None:
        return "INFO"
    return "PASS" if dr >= 100.0 else "FAIL"
```

`deterministic` に分類された expected findings の Detection Rate が 100% 未満のカテゴリは `FAIL` (AC7)。`agent-dependent` は測定値のみを報告し閾値を適用しない (AC8)。Harness の exit code は、いずれかのカテゴリが `FAIL` のとき非ゼロとする。これにより CI で回帰を検出できる。

### Deferred 指標 (Requirement 11 AC13)

`docs/benchmark-methodology.md` に定義のみを記載し、v0.1 では実装しない。

| 指標 | 意図する定義 | v0.1 |
| --- | --- | --- |
| Review Time | 1 Template あたりのレビュー完了までの実時間。決定論的部分と Agent 部分を分離して計測する | 未実装 |
| Remediation Accuracy | `SuggestedRemediation` を適用した Template が、当該 Finding を解消し、かつ新たな Finding を生じない割合 | 未実装 |
| Human Intervention Count | レビュー完了までに人間の判断を要した回数 | 未実装 |

Review Time は実行環境依存であり Requirement 16 AC11 の byte-identical 出力と衝突するため、実装する場合も Review_Report の stdout には含めず別出力とする。この制約を方法論文書に記載する。

### Benchmark case の網羅 (Requirement 11 AC1, AC2)

| Case | カテゴリ | 主な期待 Source |
| --- | --- | --- |
| `case-001-iam-wildcard` | IAM wildcard permissions | IAM Review, cfn-guard |
| `case-002-public-s3` | Public S3 bucket | cfn-guard |
| `case-003-encryption-disabled` | Encryption disabled | cfn-guard |
| `case-004-logging-disabled` | Logging disabled | cfn-guard |
| `case-005-permissive-sg` | Overly permissive Security Group | cfn-guard |
| `case-006-missing-backup` | Missing backup configuration | cfn-guard |
| `case-007-missing-tags` | Missing tags | cfn-guard |
| `case-008-unsafe-passrole` | Unsafe IAM PassRole | IAM Review |
| `case-009-public-database` | Public database endpoint | cfn-guard |
| `case-010-missing-deletion-protection` | Missing deletion protection | cfn-guard |
| `case-101-clean-web-tier` | negative (Req 12 AC3) | — |
| `case-102-clean-data-tier` | negative (Req 12 AC3) | — |

全 case の `template.yaml` は **構文的に妥当** である (Requirement 11 AC1)。cfn-lint の Error を意図的に含めない。理由: 構文エラーがあると cfn-lint が解析を中断し、他の検査結果が得られなくなるためである。構文エラーの検出は `tests/fixtures/invalid/` の unit / integration test で検証する。

---

## Dependency Strategy

### 依存インベントリ

steering/tech.md の 5 つの確認事項をすべての依存に適用する。

#### Runtime 依存 (Python)

| 依存 | 版 | 1. 標準機能で不可か | 2. 本当に必要か | 3. 保守状況 | 4. Security Risk | 5. 可搬性 |
| --- | --- | --- | --- | --- | --- | --- |
| Python 標準ライブラリ | 3.9+ | — | — | — | — | — |
| `PyYAML` | >= 6.0 | **不可**。標準に YAML parser が無い | **必要**。Req 3 AC4 が YAML 対応を要求 | 広く利用され継続保守 | `SafeLoader` 派生のみ使用で緩和。default loader を使わない | pure Python fallback あり。macOS / Linux で `pip` 導入可 |

Requirement 16 AC3 の「標準ライブラリ + 最大 1 つの YAML 依存」を厳密に満たす。runtime 依存は 1 つのみである。

#### Runtime 依存 (外部ツール、PATH 経由)

Requirement 15 AC1 に従い binary を bundle しない。

| ツール | 最低版 | 必須か | 欠如時の挙動 |
| --- | --- | --- | --- |
| `cfn-lint` | 1.0.0 | optional | `errors[]` に `tool_unavailable`。他 Source は継続 |
| `cfn-guard` | 3.0.0 | optional | 同上 |
| `cdk` (AWS CDK CLI) | 2.0.0 | optional | `--confirm-cdk-synth` 使用時のみ必要 |

「optional」とするのは Requirement 4 AC12 / Requirement 5 AC6 / Requirement 10 AC5 が「ツールが使えなくてもパイプラインを継続する」ことを求めるためである。ただし cfn-lint と cfn-guard の両方が欠けると決定論的 Source は IAM Review のみになる。この縮退状態を `summary` の `tools[]` で明示する。

#### Dev / Test 依存

| 依存 | 版 | 1. 標準機能で不可か | 2. 本当に必要か | 3. 保守状況 | 4. Security Risk | 5. 可搬性 |
| --- | --- | --- | --- | --- | --- | --- |
| `pytest` | >= 7.0 | `unittest` で代替可だが parametrize / fixture が無く、Req 12 の網羅要求に対しテストコード量が数倍になる | 必要 | 事実上の標準 | dev only。runtime に影響しない | 全 OS |
| `pytest-cov` | >= 4.0 | `coverage.py` 直接使用で代替可 | Req 12 AC1 の 80% 計測を 1 コマンドにするため採用 | 保守されている | dev only | 全 OS |
| `hypothesis` | >= 6.0 | **不可**。shrinking と再現 seed を自前実装するのは非現実的 | Correctness Properties の実装に必要 | 保守されている | dev only | 全 OS |

dev 依存が Requirement 16 AC3 の対象外である根拠: **Requirement 16 AC4 が「開発依存とテスト依存を runtime 依存と分離して宣言し、それらは AC3 の制約対象外である」ことを明文化している**。加えて AC3 自身も「THE deterministic script components enumerated in acceptance criterion 1」と対象を限定しており、AC1 が定義する deterministic script components (Template 解析、出力解析、IAM 解析、正規化、重複排除、benchmark 集計) を指す。テストコードはこれに含まれない。この解釈を CONTRIBUTING.md と `docs/architecture.md` に明記する。

#### 採用しない依存

| 候補 | 用途 | 不採用理由 |
| --- | --- | --- |
| `ruamel.yaml` | YAML 解析 | コメント・書式保持は不要。依存が重い |
| `jsonschema` | Finding schema 検証 | 検証ロジックは `finding.validate()` として 100 行程度で書ける。閉集合の検証と構造制約のみであり汎用 schema engine を必要としない。テストで JSON Schema による検証を行う場合も dev 依存に留める。**判断: runtime には入れない。dev 依存としても v0.1 では採らず、`finding.validate()` を単一の真実とする** |
| `boto3` | AWS API | v0.1 は AWS API を呼ばない (Req 9 AC3) |
| `click` / `typer` | CLI 構築 | `argparse` で十分。Req 16 AC7 が求める引数検証は `argparse` + 自前検証で実現できる |
| `pydantic` | データ検証 | `dataclasses` + `finding.validate()` で足りる。過度な抽象化を避ける (steering/development-principles.md) |
| `rich` | 出力整形 | stdout は JSON、stderr は plain text (Req 16 AC10)。整形ライブラリは不要 |
| `ruff` / `mypy` | lint / 型検査 | **採用を推奨するが v0.1 の必須依存にしない**。CI で optional に実行し、失敗を warning とする。Req 16 AC5 の型注釈は `mypy` なしでも記述できる。CONTRIBUTING.md に推奨として記載する |

### 依存の追加手続き

CONTRIBUTING.md に以下を規定する。新しい依存を提案する PR は、steering/tech.md の 5 項目に対する回答を PR 説明に含めなければならない。runtime 依存の追加は Requirement 16 AC3 に抵触するため、requirements.md の変更を伴う。

---

## License Recommendation

Requirement 13 AC3 は OSI 承認ライセンスの全文を含む `LICENSE` を要求する。requirements.md Open Question 2 は Apache-2.0 と MIT を候補として挙げ、Design フェーズでの提案と maintainer 確認を求めている。

### 比較

| 観点 | Apache-2.0 | MIT |
| --- | --- | --- |
| 特許 | 明示的な特許ライセンス付与 (Section 3) と、特許訴訟提起時のライセンス終了条項を持つ | 特許条項なし。特許リスクが不明確 |
| 商標 | 商標の使用を明示的に許諾しない (Section 6) | 言及なし |
| 帰属表示 | `NOTICE` ファイル機構により、再配布時の帰属表示を構造化できる (Section 4) | copyright notice の保持のみ |
| 変更の告知 | 改変ファイルへの変更告知を要求 (Section 4b) | 要求しない |
| 長さ・可読性 | 長い。法務レビューを要する場面がある | 短い。理解が容易 |
| 貢献の扱い | Section 5 で、明示的な別合意がない限り貢献が同ライセンス下に入ることを規定 | 規定なし。CLA 等を別途整備する必要がある |
| GPL 互換 | GPLv3 と互換。GPLv2 とは非互換 | GPLv2 / v3 の双方と互換 |
| エコシステム先例 | awslabs/agent-plugins は Apache-2.0。AWS 関連 OSS の大半が Apache-2.0 | 広く使われる |

### 推奨: Apache-2.0

理由を優先順に述べる。

1. **エコシステム整合性**: Agent Plugins の参照実装である awslabs/agent-plugins が Apache-2.0 である。同一エコシステムのプラグインが同じライセンスであれば、両者を組み合わせて利用・再配布する利用者の法務判断が単純になる。cfn-lint と cfn-guard も AWS 系 OSS であり Apache-2.0 系である。
2. **特許グラント**: 本 Plugin はセキュリティ検出ロジックと policy rule を配布する。検出手法に特許が関わる可能性は低いが、企業が組織内に導入して配布する際、明示的な特許ライセンスの有無は導入判断に影響する。Apache-2.0 の Section 3 はこの不確実性を除去する。
3. **NOTICE 機構**: Guard rule や検出ロジックはコミュニティからの貢献を前提とする (steering/product.md)。`NOTICE` ファイルにより、第三者由来の rule や派生元の帰属を構造化して記録できる。MIT では copyright header の管理に依存する。
4. **貢献の扱い**: Section 5 が、明示的な別合意なしに貢献が同ライセンス下に入ることを規定する。CLA を用意しない OSS プロジェクトにとって、貢献ライセンスの曖昧さを減らす。
5. **企業導入**: セキュリティレビューツールは企業環境で使われる。多くの企業の OSS 利用ポリシーは Apache-2.0 を明示的に許容リストに含めている。

### MIT を選ぶべき場合

以下のいずれかを重視する場合、MIT が合理的である。

- GPLv2 プロジェクトへの組み込み可能性を確保したい (Apache-2.0 は GPLv2 と非互換)。
- ライセンス文書を最小限に保ちたい。
- 特許グラントによる将来的な制約 (Apache-2.0 の特許終了条項) を避けたい。

### 実装への影響

Apache-2.0 を採る場合、以下を用意する。

| ファイル | 内容 |
| --- | --- |
| `LICENSE` | Apache License 2.0 の全文 (Requirement 13 AC3) |
| `NOTICE` | プロジェクト名、copyright、第三者由来コンポーネントの帰属 |
| ソースファイル header | Apache-2.0 の推奨 header を Python ファイル先頭に置くかは maintainer 判断。ファイル数が多いため、v0.1 では `LICENSE` + `NOTICE` のみとし header を省略することを提案する (Apache-2.0 は header を必須としない) |
| CONTRIBUTING.md | 「貢献は Apache-2.0 の下でライセンスされる」旨を明記 |

**これは推奨であり決定ではない。** maintainer の確認を経て v0.1 リリース前に確定する必要がある (requirements.md Open Question 2)。確定までの間、`plugin.json` の `license` フィールドは `"Apache-2.0"` を暫定値として置く。

---

## Correctness Properties

*A property is a characteristic or behavior that should hold true across all valid executions of a system — essentially, a formal statement about what the system should do. Properties serve as the bridge between human-readable specifications and machine-verifiable correctness guarantees.*

本 Plugin の決定論的コアは、Template 解析、ツール出力の正規化、Finding の重複排除、レポート生成という純関数の連鎖である。入力空間が広く (任意の Template、任意のツール出力、任意の Finding 集合)、かつ不変条件が明確であるため property-based testing が適する。以下の property は `tests/property/` に 1 property = 1 test 関数として実装する。各テストは最低 100 iteration を実行し、対応する property 番号をタグとして記述する。

Agent Review 部分は非決定論的であるため property の対象外である。ただし「Agent 由来の Finding が正規化層を通った後に満たすべき不変条件」(Property 6, 7) は Agent が何を出力しても成立しなければならないため、property として検証する。

### Property 1: Finding schema validity

*For any* Template document, *for any* cfn-lint output, *for any* cfn-guard output, and *for any* Agent finding input accepted by the pipeline, every Finding present in the resulting Review_Report satisfies the Finding schema: all 13 required fields are present, `FindingType` is one of `Validity` / `Security` / `BestPractice` / `Informational`, `Severity` is one of `CRITICAL` / `HIGH` / `MEDIUM` / `LOW` / `INFO`, `Confidence` is one of `Confirmed` / `Likely` / `Contextual`, `Source` is a non-empty list of recognized source names, `ID` is a positive integer, and `Evidence` is a non-empty list.

**Validates: Requirements 3.2, 7.1, 7.2, 7.3, 7.7, 7.13**

### Property 2: Category closure

*For any* Finding emitted by any Source through the normalization layer, `Normalized_Category` is a member of the closed set declared in `category_map.json` (`IAM`, `Encryption`, `PublicAccess`, `Logging`, `Tagging`, `Availability`, `Backup`, `NetworkSecurity`, `DataProtection`, `TemplateQuality`, `Other`).

**Validates: Requirements 14.1, 14.2, 14.3**

### Property 3: Deduplication idempotence

*For any* list of schema-valid Findings, applying deduplication twice produces the same result as applying it once: `deduplicate(deduplicate(x)) == deduplicate(x)`.

**Validates: Requirements 7.14, 14.7**

### Property 4: Deduplication permutation invariance

*For any* list of schema-valid Findings and *for any* permutation of that list, deduplication produces the same result. This subsumes commutativity and associativity of the merge operation over `Severity`, `Confidence`, `FindingType`, `Source`, and `Evidence`.

**Validates: Requirements 14.7, 14.8, 14.9, 14.10, 14.11, 14.12**

### Property 5: Merge join laws

*For any* group of two or more Findings sharing the same non-`Other` `Normalized_Category` and the same non-null `Resource`, the merged Finding satisfies all of the following: its `Severity` equals the maximum input `Severity` under the ordering `CRITICAL > HIGH > MEDIUM > LOW > INFO`; its `Confidence` equals the maximum input `Confidence` under `Confirmed > Likely > Contextual`; its `FindingType` equals the highest-precedence input `FindingType` under `Security > Validity > BestPractice > Informational`; its `Source` list equals the union of the input `Source` lists; and the sequence of `Evidence[].Source` rank values is non-decreasing in the order `cfn-lint`, `cfn-guard`, `IAM Review`, `Agent Review`.

**Validates: Requirements 14.8, 14.9, 14.10, 14.11, 14.12**

### Property 6: Confidence is determined by Source

*For any* Finding in a Review_Report, if `Source` contains only `Agent Review` then `Confidence` is not `Confirmed`; and if `Source` contains no `Agent Review` entry then `Confidence` is `Confirmed`.

**Validates: Requirements 7.8, 7.9, 7.10**

### Property 7: Non-Confirmed Findings carry template evidence

*For any* Finding whose `Confidence` is `Likely` or `Contextual`, at least one entry in `Evidence` has a non-null `Excerpt` field, unless that Excerpt was redacted for credential protection, in which case the redaction marker is present.

**Validates: Requirements 7.11**

### Property 8: Validity CRITICAL requires a deployment-blocking rule

*For any* cfn-lint result classified by the normalization layer, if the resulting `FindingType` is `Validity` and the resulting `Severity` is `CRITICAL`, then the resolved `blocks_deployment` flag for that rule ID is true.

**Validates: Requirements 4.5, 7.6**

### Property 9: cfn-lint classification totality

*For any* pair of a rule ID string and a cfn-lint level (`Error`, `Warning`, `Informational`), the classification function returns a `FindingType`, a `Severity`, and a `Normalized_Category` all drawn from their respective closed sets, and never raises. Additionally: a `security_relevant` rule ID always yields `FindingType` `Security`; a `Warning` level with no override yields `BestPractice` and `MEDIUM`; an `Informational` level with no override yields `Informational` and `LOW`.

**Validates: Requirements 4.3, 4.4, 4.6, 4.7, 4.9**

### Property 10: cfn-lint exit code decoding

*For any* integer exit code, the decoder classifies the invocation as successful if and only if the set bits of that code form a subset of `{2, 4, 8}`.

**Validates: Requirements 4.11, 4.12**

### Property 11: Unmatched Findings pass through unmodified

*For any* list of schema-valid Findings, every Finding whose deduplication key is unique in the list, whose `Normalized_Category` is `Other`, or whose `Resource` is null, appears in the deduplication output with every field except `ID` identical to its input value.

**Validates: Requirements 14.3, 14.13**

### Property 12: Report ordering

*For any* Review_Report, every adjacent pair of Findings in the `findings` array is non-increasing in `Severity` rank, and within any run of equal `Severity` the sequence of `Resource` values (with null treated as the empty string) is non-decreasing in ascending alphabetical order.

**Validates: Requirements 7.15**

### Property 13: Summary conservation

*For any* Review_Report, the sum of the values in `summary.by_finding_type` equals `summary.total`, the sum of the values in `summary.by_severity` equals `summary.total`, `summary.total` equals the length of the `findings` array, and for every source name `s`, `summary.by_source[s]` equals the number of Findings whose `Source` list contains `s`.

**Validates: Requirements 7.17**

### Property 14: Determinism of stdout

*For any* Template and *for any* fixed configuration of Source availability and Agent finding input, two successive invocations of the review entry point produce byte-identical stdout; and that stdout contains no absolute host path, no ISO-8601 timestamp, and no value derived from the host environment.

**Validates: Requirements 10.3, 16.11**

### Property 15: YAML and JSON equivalence

*For any* Template document, reviewing its YAML serialization and reviewing its JSON serialization produce identical Findings after normalizing `Location.File`.

**Validates: Requirements 3.4**

### Property 16: Reviewability predicate

*For any* parsed document, the reviewability predicate returns true if and only if the document is a mapping whose `Resources` key maps to a mapping containing at least one entry.

**Validates: Requirements 3.1, 3.5**

### Property 17: Safe failure on arbitrary input bytes

*For any* byte string written to an input file, loading that file either succeeds or raises a documented `IacReviewError` subclass carrying an `error_class`, and never propagates an unhandled exception; when the failure is a parse failure, the reported error carries a parse error type, a line number, and a column number.

**Validates: Requirements 3.6, 12.8**

### Property 18: Path containment

*For any* candidate path string and *for any* root directory, path resolution either raises `PathContainmentError` or returns an absolute path whose filesystem-resolved form is inside the filesystem-resolved root, including when the candidate traverses a symbolic link.

**Validates: Requirements 1.3, 9.5, 15.3**

### Property 19: Shell metacharacter rejection

*For any* string containing at least one character from the set `;`, `|`, `&`, `$`, backtick, `>`, `<`, the argument validator raises `UnsafeArgumentError`; and *for any* string containing none of those characters, it does not raise. Additionally, *for any* external tool invocation constructed by the plugin, the subprocess is spawned with `shell=False` and the argument vector is a list whose elements are never concatenated from user input.

**Validates: Requirements 9.4, 16.6**

### Property 20: No side effects before argument validation

*For any* invalid argument vector, the entry point exits with a documented non-zero exit code drawn from the defined set, and no subprocess is spawned and no file is created or modified.

**Validates: Requirements 16.7, 16.8**

### Property 21: Template content is never executed

*For any* Template containing a YAML tag outside the CloudFormation short-form allowlist, loading raises `TemplateParseError`, and no constructor side effect is observable.

**Validates: Requirements 9.7**

### Property 22: Temporary file safety

*For any* suffix, the temporary file helper yields a path whose permission mode is `0600`, and after the context exits — whether normally or by exception — that path no longer exists.

**Validates: Requirements 9.6**

### Property 23: stderr transcription is bounded

*For any* stderr text produced by an external tool, the `stderr_head` field of the resulting structured error contains at most 5 elements, and element `i` equals line `i` of the input text.

**Validates: Requirements 15.7**

### Property 24: Orchestration survives partial Source failure

*For any* subset of Sources injected to fail and *for any* failure class among tool-unavailable, tool-execution-failure, timeout, and unexpected exception, the resulting Review_Report contains exactly one error entry naming each failed Source, retains every Finding produced by the Sources that did not fail, and the entry point exits with code 0 when at least one Source succeeded.

**Validates: Requirements 2.10, 4.12, 5.6, 10.5**

### Property 25: cdk synth is never invoked without confirmation

*For any* input directory layout, including layouts containing `cdk.json` and layouts containing a `cdk.out` directory, running the review without the explicit confirmation flag never invokes the `cdk` executable.

**Validates: Requirements 8.3, 8.4, 8.5**

### Property 26: Cross-account principal classification

*For any* IAM Principal value expressed via the `AWS::AccountId` pseudo parameter, whether as `{"Ref": "AWS::AccountId"}` or as a `Fn::Sub` string containing `${AWS::AccountId}` and no other substitution variable, the classification is same-account and never cross-account.

**Validates: Requirements 6.8**

### Property 27: ExternalId reduces cross-account severity by exactly one level

*For any* statement that produces a cross-account Principal Finding, adding an `sts:ExternalId` condition to that same statement lowers the reported `Severity` by exactly one level under the ordering `CRITICAL > HIGH > MEDIUM > LOW > INFO`, never below `INFO`, and adds an Evidence entry recording the mitigating condition.

**Validates: Requirements 6.10**

### Property 28: Wildcard action and resource is always CRITICAL Security Confirmed

*For any* IAM policy document containing a statement with `Effect: Allow`, an Action list including `"*"`, and a Resource list including `"*"`, the deterministic IAM scan produces at least one Finding for the owning resource with `FindingType` `Security`, `Severity` `CRITICAL`, `Confidence` `Confirmed`, and `Normalized_Category` `IAM`.

**Validates: Requirements 6.1, 6.4**

### Property 29: Credential values never reach Evidence

*For any* Template containing a value at a redaction-triggering location (a parameter declared `NoEcho`, or a location flagged by a credential-detection rule), no `Evidence[].Excerpt` in the resulting Review_Report contains that value.

**Validates: Requirements 9.2**

### Property 30: Benchmark metric well-formedness

*For any* expected finding set and *for any* actual finding set, every percentage metric produced by the benchmark harness is either the string `"N/A"` or a string that parses to a float in the closed interval `[0, 100]` with exactly one digit after the decimal point; and when the actual set matches the expected set exactly under the match key, Detection Rate, Precision, and Recall are all `"100.0"` and the false positive count is `0`.

**Validates: Requirements 11.5, 11.6**

### Property 31: Benchmark pass/fail threshold

*For any* computed Detection Rate value, the category status is `FAIL` if and only if the category contains at least one expected Finding classified as `deterministic` and the Detection Rate for those Findings is below 100 percent.

**Validates: Requirements 11.7, 11.8**

### 実装規約 (property-based test)

| 規約 | 内容 |
| --- | --- |
| 最低 iteration | 100 (`@settings(max_examples=100)`) |
| タグ | 各テスト直上のコメントに `Feature: aws-iac-review-agent-plugin, Property {number}: {property_text}` を記述する |
| 1 property = 1 test | 各 property を単一の property-based test で実装する |
| ライブラリ | `hypothesis`。自前実装しない |
| Strategy の共有 | `tests/property/strategies.py` に Finding / Template / policy document の generator を集約する |
| 再現性 | 失敗時の counterexample を regression test として `tests/regression/` に固定する (steering/testing.md) |

### 上記の property が対象としない acceptance criteria

以下は property-based testing の対象外であり、example / edge-case / integration / smoke test で検証する。

| 対象 | 種別 | 場所 |
| --- | --- | --- |
| `plugin.json` の field / name pattern (Req 1 AC5, AC6) | EXAMPLE | `tests/unit/test_manifest.py` |
| `plugin.json` / `mcp.json` の存在・非存在 (Req 1 AC1, AC7) | SMOKE | 同上 |
| SKILL.md の front matter と必須節 (Req 2 AC11-AC13) | EXAMPLE (parametrized) | `tests/unit/test_skills.py` |
| cfn-lint JSON の全フィールド対応 (Req 4 AC2, Req 12 AC9) | EXAMPLE | `tests/unit/test_cfnlint_parse.py` |
| ツール未導入時のエラー内容 (Req 4 AC10, Req 5 AC5, Req 15 AC4, AC6) | EXAMPLE | `tests/integration/test_tool_unavailable.py` |
| `.guard` の rule 名が `_meta.json` で解決可能 (Req 5 AC8) | EXAMPLE (parametrized) | `tests/unit/test_cfnguard_parse.py` |
| IAM 個別検出器 (Req 6 AC2, AC3, AC5, AC6, AC7, AC9, AC11) | EXAMPLE | `tests/unit/test_iam_detectors.py` + benchmark cases |
| IAM resource 不在時の挙動 (Req 6 AC12) | EDGE_CASE | 同上 |
| 問題ゼロ時の summary (Req 7 AC16) | EDGE_CASE | `tests/negative/test_clean_templates.py` |
| `cdk synth` の timeout 値と fallback 禁止 (Req 8 AC6, AC7) | EXAMPLE | `tests/integration/test_cdk.py` |
| Repository 内の credential 不在 (Req 9 AC1) | SMOKE | CI の secret scan |
| coverage 80% (Req 12 AC1) | SMOKE | CI gate |
| Ground_Truth の予約フィールド存在 (Req 11 AC12) | EXAMPLE (parametrized) | `tests/unit/test_ground_truth.py` |
| Documentation の必須見出し (Req 13 AC1, AC4, AC5) | EXAMPLE | `tests/unit/test_docs.py` |
| 非 Confirmed Finding の文言 (Req 7 AC12) | EXAMPLE (lint 的検査) | `tests/unit/test_finding_wording.py` |
| binary 非同梱 (Req 15 AC1) | EXAMPLE | `tests/unit/test_manifest.py` |

---

## [Correction] 要求仕様への訂正事項

設計が requirements.md を訂正または上書きした箇所をここに集約する。C-1, C-2, C-3, C-4, C-5, C-7 の提案はいずれも requirements.md へ反映済みである。何が誤っていたか、なぜ訂正したかの記録として本節を維持し、各項目には反映後の acceptance criterion 番号を示す。

C-8, C-9, C-10, C-11 は種類が異なる。requirements.md ではなく **design.md 自身の記述の訂正** であり、requirements.md への差分はない。実装時に design の記述が自己矛盾していることが判明した箇所であるため、同じ形式でここに記録する。

### C-1: cfn-lint の exit code 意味論 (Requirement 4 AC11, AC12)

| 項目 | 内容 |
| --- | --- |
| 状態 | **反映済み**。現在の Requirement 4 AC11 / AC12 が bit mask 判定を規定している |
| requirements.md の当初の記述 | AC11「exit code 2 = linting violations found」、AC12「exit code 4 以上 = execution error」 |
| 事実 | cfn-lint の exit code は bit mask である。`2` = Error finding あり、`4` = Warning あり、`8` = Informational あり。これらは組み合わさる (`6` = E+W、`14` = E+W+I)。crash / usage error は `1` |
| 事実 (AC11 との関係) | 当初の AC11 が言う「exit code 2 = violations found」は方向としては誤りではない。`2` は Error level の finding が報告されたことを示し、実行失敗ではない。ただしその記述は `2` が findings を示す唯一の code であり `4` 以上が実行エラーであることを含意するため、依然として誤りであった |
| 設計の扱い | bit mask を復号する。set bit が `{2, 4, 8}` の部分集合であれば正常終了として stdout を解析し、それ以外の bit を含む場合 (`1` を含む) をツール実行エラーとする |
| 影響 | 当初の AC12 の記述通りに実装すると、Warning のみを含む Template (exit 4) や Informational のみを含む Template (exit 8) が「実行エラー」と誤判定され、cfn-lint の findings が失われる。これは機能上の重大な欠陥になる |
| 反映内容 | AC11: 「WHEN cfn-lint exits with a code whose set bits form a subset of {2, 4, 8}, indicating that findings were reported, THEN THE `cfn-lint-review` Skill SHALL treat this as successful execution and parse the findings from stdout」<br/>AC12: 「IF cfn-lint exits with a code containing any bit outside {2, 4, 8}, including exit code 1 (crash or usage error), THEN THE `cfn-lint-review` Skill SHALL report the failure with the stderr output without terminating the overall review pipeline」 |

### C-2: `E0` / `E1` prefix と CRITICAL の関係 (Requirement 4 AC5)

| 項目 | 内容 |
| --- | --- |
| 状態 | **反映済み**。現在の Requirement 4 AC5 が mapping file の `blocks_deployment` を一次情報とし、`E0` / `E1` prefix を保守的な初期値として位置付けている |
| requirements.md の当初の記述 | AC5 は `E0` / `E1` prefix を「parse and structural errors that prevent the Template from being deployed at all」と括弧で説明していた |
| 事実 | 多くの `E3xxx` (Resource property の型・必須・許可値の違反) も実際にはデプロイを阻害する。`E0`/`E1` だけがデプロイを阻害するわけではない |
| 設計の扱い | `E0`/`E1` → CRITICAL は「Template 全体がデプロイ不能である場合に限り CRITICAL を付与する」(Requirement 7 AC6) という **保守的な運用方針の初期値** として実装する。prefix のハードコードではなく `category_map.json` の `blocks_deployment` フラグとして表現し、rule 単位の実測に基づき override を追加できるようにする |
| 影響 | 実装方針のみ。AC5 が要求する結果 (`E0`/`E1` が CRITICAL になること) は満たされる |
| 反映内容 | AC5 は deployment-blocking の判定を Requirement 14 の mapping file に委ね、`E0` / `E1` prefix を initial deployment-blocking set かつ conservative policy として記述するようになった |

### C-3: cfn-guard の exit code (Requirement 5 AC6、反映先 AC7)

| 項目 | 内容 |
| --- | --- |
| 状態 | **反映済み**。判定方法は独立した criterion として **Requirement 5 AC7** に追加された。設計の `interpret_guard_result` はこの criterion の実装である |
| requirements.md の当初の記述 | AC6「IF cfn-guard execution fails with a non-zero exit code unrelated to policy violations, THEN ...」のみで、違反と実行失敗の判別方法が未定義であった |
| 事実 | cfn-guard は「rule 違反」と「内部エラー / parse エラー」を異なる非ゼロ exit code で区別するが、公式ドキュメントはその具体値を列挙していない |
| 設計の扱い | exit code の具体値を判定の一次情報にしない。exit 0 = 全 pass、非ゼロ + 期待 JSON 解析成功 = 違反、非ゼロ + 解析失敗 = ツールエラーとする。観測した exit code は `StructuredError.exit_code` に記録する |
| 影響 | AC6 の意図 (違反以外の失敗を報告して継続する) は満たされる。判定方法が exit code 依存でないため、cfn-guard のバージョン差に対して頑健になる |
| 反映内容 | AC7: 「WHEN cfn-guard exits with a non-zero exit code, THE `cfn-guard-review` Skill SHALL determine whether the result represents a policy violation or an execution failure by whether the tool's stdout parses as the expected result structure, and SHALL NOT base that determination on the specific exit code value」 |

### C-4: Requirement 16 AC3 の適用範囲 (反映先 AC4)

| 項目 | 内容 |
| --- | --- |
| 状態 | **反映済み**。dev / test 依存の分離と制約対象外である旨は **Requirement 16 AC4** として追加された |
| requirements.md の当初の記述 | AC3「THE Python components SHALL depend only on the Python standard library plus at most one YAML parsing dependency」 |
| 曖昧点 | テストコードが "Python components" に含まれるかが明示されていなかった |
| 設計の解釈 | AC1 が定義する deterministic script components (Template 解析、cfn-lint 出力解析、cfn-guard 出力解析、IAM policy 解析、Finding 正規化、Finding 重複排除、benchmark 集計) を指し、テストコードは含まない。dev / test 依存 (`pytest`, `pytest-cov`, `hypothesis`) は制約対象外とする |
| 影響 | この解釈なしでは property-based testing (`hypothesis`) と coverage 計測が実施できず、Requirement 12 AC1 の 80% coverage 要求と Correctness Properties の実装が矛盾する |
| 反映内容 | AC3 の対象が「the deterministic script components enumerated in acceptance criterion 1」に限定され、AC4「THE Plugin SHALL declare development and test dependencies separately from runtime dependencies, and those development and test dependencies SHALL NOT be subject to the constraint in the preceding criterion」が追加された |

### C-5: `Resource` が null の Finding の等価判定 (Requirement 14 AC5、反映先 AC6)

| 項目 | 内容 |
| --- | --- |
| 状態 | **反映済み**。logical ID を持たない Finding の扱いは **Requirement 14 AC6** として追加された |
| requirements.md の当初の記述 | AC5「THE Review_Engine SHALL determine Finding equivalence by matching on target resource logical ID AND Normalized_Category」のみ |
| 曖昧点 | resource logical ID を持たない template-level Finding (cfn-lint の `E0000`、Parameters / Outputs 由来の Finding) の扱いが未定義であった |
| 設計の判断 | `Resource` が null の Finding は互いに等価にならない。`null == null` によるマージを行わず、すべて単独で残す |
| 理由 | template-level Finding は互いに無関係でありうる。parse error と Outputs の警告が同一 Category を持つ場合にこれらを統合すると情報が失われる |
| 反映内容 | AC6: 「WHERE a Finding has no target resource logical ID, THE Review_Engine SHALL treat that Finding as matching no other Finding and SHALL include it in the Review_Report as a separate entry」 |

### C-6: steering/structure.md の base structure との差分

requirements.md Assumption 7 が既に記録済みである。設計はこれを確認し、`mcp.json` を v0.1 で同梱せず `docs/mcp/mcp.json.example` として提供する。追加の差分として、共有 Python package `iacreview/` を plugin root 直下に置く。structure.md の「役割が不明確なファイルを Repository Root に増やさない」に対し、`iacreview/` は単一責務を持つ明確な package であり、この原則に反しない。structure.md の更新を提案する。

### C-7: Informational level の到達条件 (Requirement 4 AC7、反映先 AC8)

| 項目 | 内容 |
| --- | --- |
| 状態 | **反映済み**。`--include-checks I` 付きでの起動は注記ではなく独立した criterion として **Requirement 4 AC8** に追加された |
| 分類 | 当初は要求仕様の欠陥ではなく **設計上の明確化** として記録した項目である |
| requirements.md の記述 | AC7「Informational level の結果を `FindingType: Informational` / `Severity: LOW` へ写像する」 |
| 事実 | cfn-lint は後方互換性のため Informational (`I`) rule を既定で実行しない。`-c I` / `--include-checks I` を渡さない限り Informational level の結果は 1 件も生成されない |
| 設計の扱い | cfn-lint を常に `-c I` 付きで起動することで AC7 を満たす (cfn-lint Integration 節「実行コマンド」参照)。これにより AC7 の写像および Requirement 7 AC17 の `Informational` 別 summary が到達可能になる |
| 影響 | `-c I` を渡さない実装では AC7 と `category_map.json` の `level_defaults.Informational` が dead code になり、AC7 を「満たしているように見えて実際には検証不能」な状態になる |
| 反映内容 | AC8: 「THE `cfn-lint-review` Skill SHALL invoke cfn-lint with Informational rules enabled (`--include-checks I`), because cfn-lint does not evaluate Informational rules by default and the mapping in the preceding criterion is otherwise unreachable」 |

### C-8: マージ後 `Confidence` の上限 (design.md 内の訂正、Requirement 14 AC9 × Requirement 7 AC10)

| 項目 | 内容 |
| --- | --- |
| 状態 | **design.md 内の訂正**。requirements.md への差分はない。Deduplication Algorithm 節のマージ規則表・擬似コード・worked example を修正した |
| design.md の当初の記述 | Deduplication Algorithm 節の worked example が、マージ結果を `Confidence: "Confirmed"` かつ `Source: ["cfn-lint", "cfn-guard", "IAM Review", "Agent Review"]` と記載していた |
| 誤り | この組み合わせは Requirement 7 AC10 (Agent 由来の Finding は `Confirmed` を取らない) に反する。Data Models 節の structural constraint 1 がこれを禁じており、`finding.validate` が実際に拒否する。すなわち design.md が「不変条件」と「その不変条件を破る出力例」の両方を記載していた |
| 原因 | Requirement 14 AC9 (`Confidence` は最大値) と AC12 (`Source` は union) が独立に規定されており、両者を同時に適用した結果が AC10 に抵触することが requirements 側で考慮されていなかった。決定論的 Source と Agent Source が同一 `(Resource, Category)` を検出したときに必ず発生する |
| 設計の判断 | マージは AC9 どおり最大値を取り、その直後に union へ `Agent Review` が含まれる場合のみ `Likely` へ丸める。`Contextual` は丸めの対象外 (すでに `Likely` 未満) |
| 却下した代替案 | (a) structural constraint 1 を「単一 Source の Finding にのみ適用」へ緩める。マージ済み Finding が `Confirmed` を主張できてしまい、Agent の推論が決定論的判定と区別できなくなる。Requirement 7 AC10 の目的そのものを損なうため却下。(b) `Agent Review` を union から除く。AC12 に反し、Agent が検出した事実を報告から消す |
| 情報損失 | ない。決定論的判定は `Evidence` に Source ごとに保持され、`Source` に決定論的 Source 名が並ぶ。`Confidence` は Finding 全体の主張の強さであり、最も弱い根拠を含む主張は `Confirmed` を名乗るべきではない、というのが AC10 の意味論と整合する |
| 副作用 | 丸めた結果 `Confidence != "Confirmed"` となるため、structural constraint 2 (非 `Confirmed` は `Excerpt` を要求) が有効になる。Agent Finding は Requirement 7 AC11 により必ず `Excerpt` を持つので、`Agent Review` が union にある限り自動的に満たされる |

### C-9: `Location.TemplatePath` の正規形 (design.md 内の訂正)

| 項目 | 内容 |
| --- | --- |
| 状態 | **design.md 内の訂正**。requirements.md への差分はない。cfn-guard Integration 節の記述と `iacreview/cfnguard.py` を修正した |
| design.md の当初の記述 | Data Models と Deduplication Algorithm 節の例はいずれも sequence index を `int` で書いている (`["Resources","AppExecutionRole","Properties","Policies",0,...]`)。一方 cfn-guard Integration 節は property path を `/` 区切り文字列から分割すると記述しており、分割結果は全要素が `str` になる |
| 誤り | 実装がその記述に従うと、cfn-guard だけが `"0"` を、cfn-lint と IAM Review が `0` を出力する。同一位置が 2 通りに綴られ、design.md の例と実装が一致しない |
| 影響 | `Location` は dedup のマージで 1 つだけ採用される。Source ごとに綴りが違うと、同一 statement を指す 2 つの Location が別物に見え、report の差分比較・エディタ連携・`TemplatePath` による照合がいずれも Source に依存する |
| 設計の判断 | `TemplatePath` の正規形を「sequence index は `int`、mapping key は `str`」と定め、各 Source 境界で確定させる。実装は `iacreview.finding.canonical_template_path` の単一定義とし、区切り文字列から path を再構成する cfn-guard と IAM Review の両方がこれを通す |
| 例外 | index 1 は変換しない。top-level section (`Resources`, `Parameters`, `Outputs` など) はすべて mapping であり、その member 名は必ず key である。数字のみの logical ID は CloudFormation として有効なので、`int` に変えると存在しない位置を指す |
| 適用時点 | 経路全体を組み立てた後に 1 回だけ適用する。cfn-guard の `UnResolved` check は traversal path と remaining query の 2 断片を連結して path を作るため、断片ごとに正規化すると 2 断片目の index 1 が誤って除外される |

### C-10: stdout の top-level key contract (design.md 内の訂正、Requirement 5 AC4 × Requirement 16 AC10)

| 項目 | 内容 |
| --- | --- |
| 状態 | **design.md 内の訂正**。requirements.md への差分はない。Skill Design 節 (`SKILL.md 共通構造`、`skills/cfn-lint-review`、`skills/cfn-guard-review` の Output 行) を修正し、5 つの `SKILL.md` に stdout key の明示を追加した |
| design.md の当初の記述 | Review_Report schema 節は envelope を 7 key と定義する。一方 Skill Design 節は `cfn-lint-review` の Output を「`findings[]`, `errors[]`, `stats.rules_evaluated`」、`cfn-guard-review` の Output を「`findings[]`, `errors[]`, `stats.rules_evaluated`, `stats.rules_passed`」と記述しており、`stats` が envelope の内側か外側かを述べていなかった |
| 誤り | 3 点ある。(1) envelope 定義と Skill Design 節が `stats` の所在について整合していない。(2) `cfn-lint-review` の `stats.rules_evaluated` は取得不能である。cfn-lint の `-f json` 出力は *発火した* rule のみを列挙し、評価した rule 数を述べない。distinct rule ID 数から総数を逆算すると cfn-lint が主張していない数値を報告することになる (`iacreview/cfnlint.py` の `STATS_KEYS` に `rules_evaluated` がないのはこのため)。(3) 結果として実装は Skill ごとに異なる契約を持ち、`run_cfn_guard.py` は envelope の外へ `stats` を出し、`run_cfn_lint.py` は counter を stderr へ出し、`run_iac_review.py` (Task 18.6) は後者に倣いつつ「Task 18.7 で解決する」旨の注記を残していた |
| 影響 | Skill 間で stdout の形が予測できない。5 Skill を比較する利用者と、どの Source が動いたか知らずに report を読む consumer の双方が、Skill ごとに読み方を変えなければならない。Requirement 2 AC16 (正規化ルーチンの単一実装) の精神にも反する |
| 設計の判断 (pinned contract) | 全 Skill 共通の規則を 1 つ定める。**(1)** stdout は 1 つの JSON document であり、他には何も書かない。**(2)** Review_Report envelope は全 Skill で同一の 7 key (`iacreview.report.REPORT_KEYS`) であり、Skill ごとに増減しない。**(3)** counter が stdout に載るのは、acceptance criterion がそれを diagnostic ではなく *result* の一部と定めている場合に限る。該当するのは Requirement 5 AC4 のみである。**(4)** よって `run_cfn_guard.py` だけが envelope の *外側* に top-level `stats` を追加する。Template パスごとの counter を保持し、envelope の schema は変更しない。**(5)** 集約 Skill (`iac-review`) は `stats` を持たない。**(6)** 他のすべての counter は diagnostic であり、stderr の `--verbose` に出す |
| 却下した代替案 (a) | 全 Skill で stdout を `REPORT_KEYS` に統一し、cfn-guard の rule 数も stderr へ移す。**Requirement 5 AC4 を弱める**ため却下。AC4 は「THE Skill SHALL *return a result* indicating that all rules passed with the count of rules evaluated」であり、Requirement 16 AC10 が result を stdout、diagnostic を stderr に割り当てている。count を stderr へ移すと AC4 は半分しか満たされない: 「all rules passed」に相当する `summary.passed_all_checks` は stdout に残る一方、それを限定する count だけが別 channel、しかも `--verbose` 時のみ存在することになる |
| 却下した代替案 (b) | `stats` を `REPORT_KEYS` の 8 番目の key として envelope に追加する。却下。全 Source に共通する counter は 1 つもなく (cfn-lint は解析した result 数、cfn-guard は違反数と rule 数、IAM Review は policy site 数)、値の型も揃わない (`rules_evaluated_source` は文字列、IAM の `informational_message` はメッセージ)。envelope に入れると key 集合が「どの Source が動いたか」に依存し、Source 構成を知らない consumer が読めるという envelope の存在理由そのものを失う。加えて共有 schema、`docs/finding-schema.md`、envelope を assert する全 test に波及する |
| 却下した代替案 (c) | 差分を Skill ごとの意図的な例外として記録するだけに留める。却下。規則ではなく個別の言い訳になり、6 番目の Skill が追加されたときに従うべき基準が残らない |
| 情報損失 | ない。Requirement 5 AC4 の count は stdout に残る。他の Skill の counter は `--verbose` の stderr に残り、いずれも acceptance criterion が result として要求していないものである |
| 検証 | documentation 側は `tests/unit/test_skills.py` が担う (各 `SKILL.md` の `## Output` が宣言する top-level key 集合を `iacreview.report.REPORT_KEYS` と照合し、`stats` を宣言できる Skill が `cfn-guard-review` 1 つだけであることを assert する)。実行時の bytes 側は既存の integration test が担う (`test_skill_cfn_guard.py` が `REPORT_KEYS + ("stats",)`、`test_skill_cfn_lint.py` / `test_skill_iam.py` / `test_skill_iac_review.py` が `REPORT_KEYS` 完全一致) |

### C-11: `複数 Template / ディレクトリ入力` flowchart の exit code (design.md 内の訂正)

| 項目 | 内容 |
| --- | --- |
| 状態 | **design.md 内の訂正**。requirements.md への差分はない。当該 mermaid flowchart を修正した。実装変更は不要 |
| design.md の当初の記述 | `複数 Template / ディレクトリ入力` 節の flowchart が、reviewable な Template が 1 つも無い場合を `exit 7 + no_reviewable_template` と記載していた |
| 誤り | `error_class` と exit code の対応が壊れている。同じ design.md の exit code 表と failure mode matrix、および `iacreview/exitcodes.py` はいずれも `no_reviewable_template` を **8** (`NO_REVIEWABLE_TEMPLATE`)、7 を `path_violation` (`PATH_VIOLATION`) と定めている。図の 1 箇所だけが 7 を指していた |
| 影響 | 図だけを読んだ実装は、path containment 違反と「レビュー対象なし」を同一 exit code で報告する。Requirement 16 AC8 が failure class ごとに異なる exit code を要求しているため、2 つの failure class が区別できなくなる |
| 設計の判断 | 図を `exit 8 + no_reviewable_template` に修正する。exit code 表を一次情報とし、図をそれに合わせる |
| 実装との関係 | 実装は当初から 8 を返しており (`iacreview/errors.py` の `NotReviewableError.exit_code = 8`、`skills/iac-review/SKILL.md` の exit code 表も 8)、変更は不要である。Task 18.6 の実装時に図との不一致として検出された |

---

## Requirements Traceability

| Requirement | 設計セクション | 主要コンポーネント |
| --- | --- | --- |
| 1: Plugin パッケージ構造 | Skill Design (plugin.json)、Directory Structure、Security Design (path containment) | `plugin.json`, `skills/*/SKILL.md`, `iacreview/pathguard.py` |
| 2: Skill 構成 | Skill Design (SKILL.md 共通構造)、Directory Structure (共有コード配置)、The Deterministic / Agent Boundary、[Correction] C-10 | 5 Skill ディレクトリ、`iacreview/` package、`run_iac_review.py` の `SOURCES` ループ |
| 3: CloudFormation テンプレートレビュー | Components and Interfaces (`iacreview.template`)、Data Models、Error Handling | `iacreview/template.py`, `iacreview/yamlcfn.py` |
| 4: cfn-lint 統合 | cfn-lint Integration、Normalized Category Vocabulary、[Correction] C-1 / C-2 | `iacreview/cfnlint.py`, `iacreview/category_map.json` |
| 5: cfn-guard 統合 | cfn-guard Integration、[Correction] C-3 / C-9 / C-10 | `iacreview/cfnguard.py`, `rules/**/*.guard`, `rules/**/_meta.json` |
| 6: IAM セキュリティレビュー | IAM Review Architecture、The Deterministic / Agent Boundary (#7, #8) | `iacreview/iam/locate.py`, `iacreview/iam/detectors.py`, `iacreview/iam/intrinsics.py` |
| 7: 統一レビューレポート | Data Models (Finding schema, FindingType × Severity, Confidence)、Deduplication Algorithm (整列と ID) | `iacreview/finding.py`, `iacreview/report.py` |
| 8: CDK サポート | Review Flow and Orchestration (CDK フロー)、Security Design (`cdk synth` 境界) | `iacreview/cdk.py`, `iacreview/proc.py` |
| 9: セキュリティ要件 | Security Design (全節)、Determinism Design (絶対パス排除) | `iacreview/pathguard.py`, `iacreview/proc.py`, `iacreview/yamlcfn.py`, `secure_temp_file` |
| 10: ポータビリティ要件 | Portability Design、Determinism Design (OS 間一貫性) | `plugin.json` (`extensions` 不使用)、`docs/kiro-power.md` |
| 11: ベンチマーク | Benchmark Strategy | `benchmark/harness/run_benchmark.py`, `benchmark/harness/metrics.py`, `benchmark/cases/*/ground_truth.json` |
| 12: テスト要件 | Testing Strategy、Correctness Properties | `tests/unit/`, `tests/property/`, `tests/integration/`, `tests/negative/`, `tests/regression/`, `tests/fakebin/` |
| 13: OSS プロジェクト構成とドキュメント | Directory Structure (`docs/`)、License Recommendation | `README.md`, `README.ja.md`, `CONTRIBUTING.md`, `CHANGELOG.md`, `LICENSE`, `NOTICE`, `docs/*.md` |
| 14: Finding 正規化と重複排除戦略 | Normalized Category Vocabulary and the Mapping File、Deduplication Algorithm、[Correction] C-5 / C-8 | `iacreview/categories.py`, `iacreview/category_map.json`, `iacreview/dedup.py` |
| 15: 外部ツール実行とパスコンテインメント | cfn-lint Integration、cfn-guard Integration、Security Design、Portability Design (最低バージョン表) | `iacreview/toolcheck.py`, `iacreview/proc.py`, `iacreview/pathguard.py` |
| 16: 決定論的コンポーネントの実装方針 | Components and Interfaces、Error Handling (exit code)、Determinism Design、Dependency Strategy、[Correction] C-4 / C-10 / C-11 | `iacreview/**` 全体、`iacreview/errors.py`, `iacreview/exitcodes.py`, `iacreview/report.py` |

### Acceptance criteria 単位の対応 (主要なもの)

| AC | 設計上の実現箇所 |
| --- | --- |
| 1 AC3 (path containment) | Security Design / `resolve_within`、Property 18 |
| 1 AC7, AC8 (mcp.json 非同梱と opt-in 例) | Directory Structure (`docs/mcp/`)、Security Design (MCP boundary) |
| 1 AC4 (SKILL.md 欠落 / top-level heading なしの Skill を skip) | Skill Design (SKILL.md 共通構造)、`tests/unit/test_skills.py` |
| 2 AC10 (sub-skill 失敗時の継続) | Skill Design (orchestration の疎結合設計)、Property 24 |
| 2 AC11, AC12, AC13 (front matter と必須節) | Skill Design (SKILL.md 共通構造)、[Correction] C-10、`tests/unit/test_skills.py` |
| 2 AC14, AC15 (Agent による再実装の禁止) | The Deterministic / Agent Boundary、`extract_facts.py` の `deterministic_findings_summary` |
| 2 AC16 (単一実装箇所) | Directory Structure (共有 Python コードの配置、案 C) |
| 3 AC6 (parse error の位置) | Components (`TemplateParseError`)、Error Handling、Property 17 |
| 4 AC5 (E0/E1 → CRITICAL) | Normalized Category (`blocks_deployment`)、Property 8、[Correction] C-2 |
| 4 AC8 (Informational rule の有効化) | cfn-lint Integration (`-c I`)、[Correction] C-7 |
| 4 AC9 (security-relevance override) | Normalized Category (`security_relevant`)、Property 9 |
| 4 AC11, AC12 (exit code) | cfn-lint Integration (bit mask)、Property 10、[Correction] C-1 |
| 5 AC3 (remediation guidance) | cfn-guard Integration (`<<` custom message → `SuggestedRemediation`) |
| 5 AC4 (clean run の rule 数報告) | cfn-guard Integration (`stats`)、[Correction] C-10 |
| 5 AC7 (違反と実行失敗の判別) | cfn-guard Integration (`interpret_guard_result`)、[Correction] C-3 |
| 5 AC8 (rule 追加時の非破壊性) | cfn-guard Integration (`_meta.json` sidecar、案 C) |
| 6 AC8 (`AWS::AccountId` 判別) | IAM Review Architecture (`classify_principal`)、Property 26 |
| 6 AC10 (ExternalId で severity 減算) | IAM Review Architecture (`apply_external_id_mitigation`)、Property 27 |
| 6 AC13 (Finding の必須情報) | Data Models (Finding schema)、Property 1 |
| 7 AC4, AC5 (Severity は FindingType 内で比較) | Data Models (FindingType × Severity の直交性) |
| 7 AC6 (Validity CRITICAL の制約) | Data Models、Property 8 |
| 7 AC10 (Agent は Confirmed 不可) | Components (`agentin`)、Deduplication Algorithm (`Confidence` の上限)、Property 6、[Correction] C-8 |
| 7 AC11 (非 Confirmed は Evidence 必須) | Data Models、Property 7 |
| 7 AC15 (整列) | Deduplication Algorithm (`sort_findings`)、Property 12 |
| 7 AC17 (summary) | Data Models (Review_Report schema)、Property 13 |
| 8 AC3, AC4, AC5 (自動 synth 禁止と確認) | Review Flow (CDK フロー)、Property 25 |
| 8 AC11 (sandbox 無しの明記) | Security Design (`cdk synth` 節)、README Known Limitations |
| 9 AC2 (secret を出力しない) | Security Design (Excerpt redaction)、Property 29 |
| 9 AC4 (argv 配列と metacharacter 拒否) | Security Design、Property 19 |
| 9 AC6 (temp file 0600 と cleanup) | Security Design (`secure_temp_file`)、Property 22 |
| 9 AC7 (Template 内容を実行しない) | Security Design (`SafeLoader` allowlist)、Property 21 |
| 10 AC3 (OS 間の一貫性) | Determinism Design、Property 14 (CI で macOS / Linux 双方実行) |
| 10 AC9 (Kiro 手順の分離) | Portability Design (`docs/kiro-power.md`) |
| 11 AC4 (detection class) | Benchmark Strategy (Ground_Truth 形式) |
| 11 AC5, AC6 (指標) | Benchmark Strategy (指標の定義)、Property 30 |
| 11 AC7, AC8 (pass/fail) | Benchmark Strategy (`category_status`)、Property 31 |
| 11 AC9 (agent-dependent の照合) | Benchmark Strategy (`match_key`) |
| 11 AC12 (予約フィールド) | Benchmark Strategy (Ground_Truth 形式) |
| 11 AC13 (deferred 指標) | Benchmark Strategy (Deferred 指標) |
| 12 AC1 (80% coverage) | Testing Strategy (subprocess coverage) |
| 12 AC6 (false positive の除外規則) | Testing Strategy (`count_false_positives`) |
| 12 AC7 (tool unavailable test) | Testing Strategy (`fakebin` 方式) |
| 12 AC11 (security regression) | Testing Strategy、`tests/regression/` の 5 ファイル |
| 13 AC3 (LICENSE) | License Recommendation |
| 14 AC3 (`Other` を dedup 除外) | Deduplication Algorithm、Property 2、Property 11 |
| 14 AC4 (単一 versioned mapping file) | Normalized Category Vocabulary (`category_map.json`) |
| 14 AC6 (logical ID なしの Finding は単独で残す) | Deduplication Algorithm (`equivalence_key` の `None`)、Property 11、[Correction] C-5 |
| 14 AC8-AC12 (マージ規則) | Deduplication Algorithm、Property 4、Property 5、[Correction] C-8 |
| 15 AC1 (binary を bundle しない) | Dependency Strategy、Portability Design |
| 15 AC7 (stderr 先頭 5 行) | Error Handling (`StructuredError`)、Property 23 |
| 16 AC4 (dev / test 依存の分離) | Dependency Strategy (Dev / Test 依存)、[Correction] C-4 |
| 16 AC8 (failure class ごとの exit code) | Error Handling (exit code 表)、Property 20、[Correction] C-11 |
| 16 AC10 (stdout JSON / stderr 診断) | Error Handling (stdout / stderr の分離)、[Correction] C-10 |
| 16 AC11 (byte-identical) | Determinism Design、Property 14 |

---

## Open Design Decisions Carried to Implementation

実装フェーズで確定させる必要がある項目。いずれも設計が保守的な既定値を持っており、確定を待たずに実装を開始できる。

### O-1: cfn-guard の exit code の実測

| 項目 | 内容 |
| --- | --- |
| 未解決点 | cfn-guard が「rule 違反」「parse エラー」「内部エラー」に割り当てる具体的な exit code 値 |
| 現在の設計 | exit code に依存しない判定 (exit 0 = pass、非ゼロ + JSON 解析成功 = 違反、非ゼロ + 解析失敗 = ツールエラー) |
| 実装時タスク | cfn-guard 3.x に対して、正常系 / 違反あり / 不正 Template / 存在しない rule ディレクトリ / 不正 rule 構文の各ケースで exit code を実測し `docs/architecture.md` に記録する |
| 確定後の扱い | exit code による早期判定を **追加** できる。ただし JSON 解析による判定を置き換えてはならない (バージョン差への頑健性を失うため)。Requirement 5 AC7 が exit code 値に依拠しないことを要求しているため、これは設計上の推奨ではなく要求である |

### O-2: cfn-lint の CRITICAL override リストの母集団

| 項目 | 内容 |
| --- | --- |
| 未解決点 | `blocks_deployment: true` を付与すべき rule ID の具体的な集合。特に `E3xxx` のうちどれが実際にデプロイを阻害するか |
| 現在の設計 | `E0*` / `E1*` prefix に `blocks_deployment: true`。`E3002` は明示的に `false` |
| 実装時タスク | cfn-lint の rule 一覧を走査し、rule ごとにデプロイ阻害性を判定して `category_map.json` の `rule_overrides` を拡充する。判定根拠を `docs/finding-schema.md` に記録する |
| リスク | 母集団が大きいため v0.1 で網羅できない可能性がある。網羅できない場合、既定値 (prefix 規則) のままとし、Known Limitations に「CRITICAL の付与範囲は保守的であり、一部の deploy 阻害エラーは HIGH として報告される」と記載する |

### O-3: cfn-lint の security-relevance rule リスト

| 項目 | 内容 |
| --- | --- |
| 未解決点 | `security_relevant: true` を付与すべき cfn-lint rule ID の集合 (Requirement 4 AC9, Requirement 14 AC4) |
| 現在の設計 | `W3037` (無効な IAM action)、`W2501` (`NoEcho` 未設定)、`W1011` (hardcoded secret) の 3 件を初期値とする |
| 実装時タスク | cfn-lint の Warning / Informational rule を走査し、セキュリティ関連のものを特定して追加する |
| 判定基準 | 「その rule が指摘する状態が、セキュリティ侵害リスクを直接生じるか」。Template 品質のみに関わる rule は対象外とする。判定基準を `docs/finding-schema.md` に明記する |

### O-4: 段階リリース (v0.1a / v0.1b) の採否

| 項目 | 内容 |
| --- | --- |
| 未解決点 | requirements.md Open Question 1。v0.1 を v0.1a / v0.1b に分割するか |
| 設計への影響 | **なし**。設計はコンポーネント境界が明確であり、`iacreview/` の各モジュールと Skill が独立して実装・テストできる。分割する場合、v0.1a は `pathguard`, `proc`, `toolcheck`, `template`, `finding`, `categories`, `cfnlint`, `cfnguard`, `dedup`, `report` と `cfn-lint-review` / `cfn-guard-review` / `iac-review` Skill、v0.1b は `iam/`, `agentin`, `iam-review` / `cloudformation-review` Skill と `benchmark/` になる |
| 判断者 | maintainer |

### O-5: LICENSE の確定

| 項目 | 内容 |
| --- | --- |
| 未解決点 | requirements.md Open Question 2 |
| 設計の推奨 | Apache-2.0 (License Recommendation 節に根拠を記載) |
| 暫定値 | `plugin.json` の `license` に `"Apache-2.0"` を置く |
| 確定期限 | v0.1 リリース前 |

### O-6: Windows サポートの明示的スコープ外化

| 項目 | 内容 |
| --- | --- |
| 未解決点 | requirements.md Open Question 3 |
| 設計の前提 | Requirement 10 AC3 が macOS / Linux のみを対象としているため、v0.1 は Windows を対象外とする |
| 設計への影響 | `pathlib` 使用と `/` 区切り出力により、Windows でも動作する可能性はあるが検証しない。`_minimal_env()` と `fakebin` の POSIX sh スクリプトは Windows で動作しない |
| 実装時タスク | README の Requirements 節と Known Limitations に「Windows は v0.1 でサポートされない」と明記する |

### O-7: Kiro Power としてのパッケージング詳細

| 項目 | 内容 |
| --- | --- |
| 未解決点 | requirements.md Open Question 4。Kiro Power としてロードする際の正確なディレクトリ配置と Kiro 固有 manifest の必要性 |
| 現在の設計 | Kiro 固有ファイルを一切追加せず、Agent Plugins 1.0.0 準拠パッケージとして読み込めることを前提とする (Portability Design 節) |
| 実装時タスク | Kiro で実際に読み込み、5 Skill すべてが discoverable であること (Requirement 10 AC8) を検証する。追加ファイルが必要と判明した場合は `plugin.json` の `extensions` に `dev.kiro` 名前空間を追加し、`docs/kiro-power.md` に手順を記載する。portable core が影響を受けないことを確認する (Requirement 10 AC9) |
| 検証できない場合 | `docs/kiro-power.md` に検証済みの手順のみを記載し、未検証の内容を書かない (Requirement 13 AC11) |

### O-8: カテゴリマッピングの管理方式

| 項目 | 内容 |
| --- | --- |
| 未解決点 | requirements.md Open Question 5。cfn-lint rule prefix → Normalized_Category のマッピングを本 Repository で維持するか、upstream 由来のデータを取り込むか |
| 設計の判断 | **本 Repository で維持する**。理由: Normalized_Category は本 Plugin が定義する概念であり upstream に対応するデータが存在しない。upstream から取り込めるのは rule ID の一覧のみであり、それは動的に取得するのではなく `category_map.json` の prefix 規則で網羅する方が決定論的である (Requirement 16 AC11) |
| 実装時タスク | `category_map.json` の `rule_overrides` が cfn-lint のバージョン更新で陳腐化しないよう、未知の rule ID が prefix 規則で必ず解決されることを property test (Property 9) で保証する |

### O-9: Agent Review の非決定性の境界付け

| 項目 | 内容 |
| --- | --- |
| 未解決点 | requirements.md Open Question 6。ベンチマークの再現性確保のため Agent Review の変動をどう境界付けるか |
| 現在の設計 | Benchmark_Harness は Agent Finding を実行時に生成せず、`--agent-findings <dir>` で固定 fixture として受け取る。これにより Harness は決定論的である |
| 未解決の部分 | Agent Review の検出能力そのものを評価する方法 |
| 実装時タスク | v0.1 では `agent-dependent` の expected finding を測定値のみ報告する (Requirement 11 AC8) 方針を維持し、複数回実行による変動幅の報告は v0.2 以降の候補として `docs/benchmark-methodology.md` に記録する |

### O-10: cfn-guard rule の供給方式

| 項目 | 内容 |
| --- | --- |
| 未解決点 | requirements.md Open Question 7。bundle 済み rule のみか、ユーザー指定 rule ディレクトリも受け付けるか |
| 設計の判断 | **両方を受け付ける**。既定は bundle 済み rule のみ。`run_cfn_guard.py --rules-dir <path>` で追加でき、`pathguard.resolve_within(workspace_root)` を通す |
| 根拠 | steering/product.md がコミュニティによる拡張を前提としており、組織固有ポリシーの適用は本 Plugin の主要な価値である。既定を bundle のみとすることで、追加設定なしの動作 (Requirement 10 AC1) を維持する |
| 実装時タスク | `--rules-dir` を複数回指定可能にし、指定順を出力の決定論性に影響させないよう (rule 名でソート) 実装する |

### O-11: `Excerpt` redaction のトリガ条件

| 項目 | 内容 |
| --- | --- |
| 未解決点 | どの位置を「credential を含みうる」と判定して `Excerpt` を redact するか (Requirement 9 AC2) |
| 現在の設計 | `NoEcho: true` の Parameter を参照する箇所、および cfn-lint の `W1011` / `W2501` が指摘した位置 |
| 未解決の部分 | key 名のパターン (`password`, `secret`, `token`, `apikey` 等) による追加検出を行うか |
| 実装時タスク | 初期実装は上記 2 条件のみとし、key 名パターンによる検出は false positive (redaction 過剰による Evidence の有用性低下) と false negative (secret 漏えい) のトレードオフを評価してから決定する。判断結果を `docs/security-model.md` に記録する |
| 保守的な既定 | 判断が付かない場合は redaction する側に倒す。Evidence の情報量より secret の非拡散を優先する |

### O-12: cfn-lint の Informational rule を既定で有効にするか

| 項目 | 内容 |
| --- | --- |
| 未解決点 | `-c I` (`--include-checks I`) を常時付与するか、`run_cfn_lint.py` の CLI flag (例: `--no-informational`) で切り替え可能にするか |
| 保守的な既定 | **有効にする**。Requirement 4 AC7 が Informational level の写像を義務付けており、`-c I` なしでは当該 acceptance criterion が到達不能になる。Requirement 4 AC8 が `--include-checks I` 付きでの起動を明示的に要求しているため、既定を無効にする選択肢はない ([Correction] C-7 参照) |
| トレードオフ | cfn-lint の既定挙動より Finding 件数が増える。Informational は `Severity: LOW` であり Requirement 12 AC6 の false positive 計数から除外されるため negative test には影響しないが、レポートの読み手にとってノイズになりうる |
| 実装時タスク | v0.1 では常時有効とし flag を追加しない。運用フィードバックで件数が過剰と判断された場合に `--no-informational` を追加する。flag を追加する場合も既定値は「有効」を維持し、無効化した実行では Requirement 4 AC7 の写像が検証されないことを stderr の警告として明示する |
