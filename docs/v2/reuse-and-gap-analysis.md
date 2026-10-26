# v2.0 再利用資産と GAP 分析

前提: Baseline は commit `5e5ed36fe9cb26f58486806f04a9795d2332c83f`（`main`）。根拠の詳細は `docs/v2/baseline-audit.md` を参照。
本書の「既存資産」は Repository 内に実装とテストが存在するものに限り、それ以外は「新規実装が必要」とする。

凡例:

- **再利用可**: 既存の関数をそのまま呼び出せる
- **部分再利用**: 一部を流用できるが、追加・移設・ラップが必要
- **新規**: 該当する既存実装がない

---

## F. v1.1（差分ベース Review）への再利用可能性

| # | 機能 | 判定 | 既存資産（path / 関数） | 不足点 |
| --- | --- | --- | --- | --- |
| F-1 | Git Base/Head の差分取得 | **新規** | なし。`iacreview/`・`skills/` は git を呼ばない。安全な process 起動は `iacreview/proc.py` `run`（argv 配列, `shell=False`, env allowlist, timeout, process group kill）を再利用可。CI 用の read-only git 呼び出し例は `.github/scripts/check_ground_truth_order.py`（`_run`, `rev-parse`, `log --diff-filter=A`）、`.github/scripts/scan_secrets.py` `tracked_files`（`ls-files -z`） | ref 検証（`-` 始まり拒否、`rev-parse --verify --end-of-options`）、blob 取得（`git cat-file` 等）、`proc.run` に `cwd` 引数がない（`cdk._working_directory` は `os.chdir` で回避しており、git では `-C` を使う方が安全）、untrusted repo config の無効化、git の version check（`toolcheck.TOOL_REQUIREMENTS` に git がない） |
| F-2 | CloudFormation 構造解析 | **再利用可** | `iacreview/template.py` `parse_template_text(text, path)`（file を介さず text を parse）、`is_reviewable`、`LoadedTemplate`。`iacreview/yamlcfn.py` `load_yaml`（short tag を long form に正規化するため、YAML の `!Ref X` と JSON の `{"Ref": "X"}` は同じ dict になる） | git blob から取得した bytes に対して、`MAX_TEMPLATE_BYTES` 相当の size 上限と UTF-8 decode を適用する薄い wrapper が必要（`_read_bytes_toctou_safe` は file 専用）。parse 後の doc は行番号を持たない |
| F-3 | Logical ID / Property の比較 | **部分再利用** | 走査の部品: `skills/cloudformation-review/scripts/extract_facts.py` `_resource_bodies`, `_properties`, `_reference_graph`, `_depends_on`（Skill script 内の private 関数のため `iacreview/` から import できない）。`iacreview/netgraph.py` `build_graph`（network resource 限定）。path 表現は `iacreview/finding.py` `canonical_template_path` | Resource 追加・削除・Type 変更・Property 単位の追加/削除/変更を出す Semantic Diff 本体は存在しない。list の順序の扱い（順序差を変更とみなすか）、intrinsic の比較方針、`Metadata`/`DependsOn`/`Condition`/`DeletionPolicy` 等 resource attribute の扱いも未定義 |
| F-4 | Finding 同一性判定 | **部分再利用** | `iacreview/dedup.py` `dedup_key` = `(Resource, Normalized_Category)`、`iacreview/finding.py` `is_dedup_eligible`（`Other` と `Resource=None` は対象外）。`benchmark/harness/metrics.py` `match_key` = `(resource, finding_type, normalized_category)` と `match`（canonical JSON で tie-break する決定論的 1 対 1 matching）。`docs/finding-schema.md` が cross-report key として `(Resource, Normalized_Category)` を推奨 | `Finding.ID` は report 内の位置であり cross-report key にならない。複数 Template の report では `Location.File` を key に含める必要がある。`metrics.match` は benchmark harness 内（plugin 外の contributor tool）にあるため、`iacreview/` へ移設または同等の再実装が必要。Logical ID 変更（rename）は追跡できない |
| F-5 | New / Resolved / Unchanged / Ambiguous 分類 | **新規**（部品は F-4） | `metrics.match` の `pairs` / `unmatched_expected` / `unmatched_actual` が Unchanged / Resolved / New の原型として使える | Ambiguous の定義（同 key に複数 Finding、`Resource=None`、`Other`、logical ID rename 疑い、Source 失敗で比較不能）が存在しない。`errors[]` を見て「Tool 不在で消えた Finding」を Resolved と誤分類しない仕組みもない |
| F-6 | JSON / Markdown の差分 Report | **部分再利用（JSON）/ 新規（Markdown）** | JSON: `iacreview/report.py` `dump`, `configure_stdout`, `normalize_output_path`, `sort_findings`（決定論的直列化）。SARIF: `iacreview/sarif.py` `to_sarif`（参考実装） | 7-key envelope（`REPORT_KEYS`）は閉じているため、Delta は別 envelope と別 `schema_version` が必要。Markdown renderer は `iacreview/` に存在しない |

### F 補足: v1.1 で特に注意すべき既存仕様

- `summary.passed_all_checks` は `not findings` のみで、`errors[]` を見ない（`iacreview/report.py` `_summary`）。Delta で「Head が合格」と判定する際は `errors[]` と `tools[].available` を併せて評価する必要がある。
- Deduplication は Template 単位（`run_iac_review.py` `IacReview._report` の `buckets`）。Delta の identity key にも `Location.File` を含めないと、別 Template の同じ logical ID が混同される。
- 決定論性は既存の強い性質（`tests/property/test_prop_determinism.py`、`tests/property/test_prop_dedup.py`）。Delta 側も同じ性質を property test で保つ前提で設計できる。

---

## v2.0 Stage 別マッピング

### Stage 1: IaC Review（既存）

| 区分 | 内容 |
| --- | --- |
| 既存資産 | 6 決定論 Source（`cfnlint`, `cfnguard`, `iam`, `netgraph`, `secrets`, `quality`）、`agentin`、`dedup`、`report`、`sarif`、`run_iac_review.py`。テスト 4,279 件（4,241 pass / 2 fail / 36 skip）、coverage 96.94%、benchmark PASS |
| GAP | `tests/unit/test_root_docs.py` の 2 件 FAIL（README 見出し不整合）、IAM placeholder detector 4 件（`iam/detectors.py`）、ruff/mypy の advisory 指摘、module docstring の「three Sources」記述の陳腐化 |
| 互換性制約 | 13-field Finding（`finding.FINDING_FIELDS`）、7-key envelope（`report.REPORT_KEYS`）、6-key summary（`report.SUMMARY_KEYS`）、9-key StructuredError（`errors.STRUCTURED_ERROR_KEYS`）、exit code 0-8、`schema_version = "1.0.0"` |

### Stage 2: Remediation Contract（修正可能範囲と維持条件）

| 区分 | 内容 |
| --- | --- |
| 既存資産 | `SuggestedRemediation`（文字列、自動適用なし）、`Location.TemplatePath`（`canonical_template_path` による正規化済み path）、`Resource`、`Normalized_Category`、cfn-guard rule の custom message。IAM / Network / Quality の detector は「どの property が問題か」を TemplatePath で示す |
| 新規実装が必要 | Contract の schema（許可される変更範囲: 対象 Resource・TemplatePath の allowlist、禁止事項: Resource 削除・Type 変更・IAM 拡大など）、Invariant の表現形式（例: 「Finding X が Resolved」「新規 Finding が増えない」「指定 property が不変」）、Contract の validate 関数、Finding → Contract の生成規則 |
| 依存 | Semantic Diff（v1.1）と Finding Delta（v1.1）がないと Invariant を機械的に検証できない |

### Stage 3: Agentic Remediation（Agent による修正案生成）

| 区分 | 内容 |
| --- | --- |
| 既存資産 | Agent 出力を file で受け、厳格に validate する境界パターン（`iacreview/agentin.py`：未知 key 拒否、`Confirmed` 降格、Source 偽装の reject、Excerpt redaction）。prompt 生成部品（`iacreview/agentprompt.py` `build_prompt`、`skills/cloudformation-review/scripts/build_prompt.py`） |
| 新規実装が必要 | 修正案（patch / 修正後 Template）の受け取り形式と validate、Skill（SKILL.md）による Agent 指示、修正案を workspace に書かずに検証する経路（steering の Read Only 原則により、自動適用は禁止） |
| 注意 | 現行コードは template への書き込み経路を持たない。修正案の生成・保存先・適用は user の明示操作とする必要がある |

### Stage 4: Independent Verification（修正前後の差分・Evidence・Invariant 検証）

| 区分 | 内容 |
| --- | --- |
| 既存資産 | 修正後 Template の再 Review は Stage 1 をそのまま実行できる（`run_iac_review.py`）。決定論的 report により before/after の比較が byte 単位で再現可能。`errors[]` / `tools[]` で Tool 不在を検出できる |
| 新規実装が必要 | Semantic Diff（F-3）、Finding Delta（F-4/F-5）、Contract の Invariant 判定、Verification 結果の schema と Report |
| v1.1 との関係 | **v1.1 の Semantic Diff + Finding Delta が Stage 4 の中核部品になる**。v1.1 を先行させる根拠 |

### Stage 5: Bounded Autonomy（再試行・停止・人間への委譲）

| 区分 | 内容 |
| --- | --- |
| 既存資産 | 閉じた exit code 体系（`iacreview/exitcodes.py`）、閉じた error class（`errors.ERROR_CLASSES`）、benchmark の `human_intervention_count` 指標（`benchmark/harness/metrics.py` `HUMAN_INTERVENTION_EXPECTATION_FIELD`） |
| 新規実装が必要 | 再試行上限・停止条件・hand-off 条件の policy、試行履歴の記録形式、Verification 結果 → 次 action の決定論的判定関数 |
| 注意 | `passed_all_checks` を停止条件にそのまま使うと Tool 不在時に誤って「合格」となる（baseline-audit C-3） |

---

## 既存資産 vs 新規実装 一覧

### 既存資産（そのまま再利用できるもの）

| 資産 | Path |
| --- | --- |
| 安全な process 起動 | `iacreview/proc.py` `run` |
| path containment / metacharacter 拒否 | `iacreview/pathguard.py` `resolve_within`, `assert_no_shell_metacharacters` |
| Template parse（text 入力可） | `iacreview/template.py` `parse_template_text`, `is_reviewable`; `iacreview/yamlcfn.py` `load_yaml` |
| Finding model / validate / (de)serialize | `iacreview/finding.py` `Finding`, `validate`, `to_dict`, `from_dict`, `canonical_template_path` |
| StructuredError と exit code | `iacreview/errors.py`, `iacreview/exitcodes.py` |
| 決定論的 JSON 出力 | `iacreview/report.py` `dump`, `configure_stdout`, `normalize_output_path` |
| Entry point の骨格 | `iacreview/bootstrap.py` `new_parser`, `run_entry_point`, `require_plugin_root` |
| Tool version check | `iacreview/toolcheck.py` `require_tool`, `extract_version` |
| 既存 Review 全体 | `skills/iac-review/scripts/run_iac_review.py` |
| テスト基盤 | `tests/fakebin/`（fake tool）、`tests/property/strategies.py`（hypothesis strategy）、`tests/regression/skillrun.py` |

### 部分再利用（移設・ラップが必要なもの）

| 資産 | Path | 必要な対応 |
| --- | --- | --- |
| 1 対 1 matching | `benchmark/harness/metrics.py` `match`, `match_key`, `_canonical_form` | plugin 本体から benchmark harness へ依存させないため、`iacreview/` 側に同等のロジックを置く（benchmark 側は変更しない） |
| Resource / 参照グラフ走査 | `skills/cloudformation-review/scripts/extract_facts.py` `_resource_bodies`, `_properties`, `_reference_graph` | Skill 内 private 関数のため、共通化する場合は `iacreview/` に移設が必要（既存 Skill 出力を変えない範囲で） |
| dedup key | `iacreview/dedup.py` `dedup_key` | `Location.File` を加えた delta 用 identity key が別途必要 |

### 新規実装が必要なもの

- Git ref 検証と blob 取得（read-only、untrusted config 無効化）
- Template Semantic Diff（Resource / Type / Property 単位）
- Finding Delta（New / Resolved / Unchanged / Ambiguous）
- Delta report の JSON envelope と schema version
- Markdown renderer
- Remediation Contract schema と Invariant 判定（v2.0 Stage 2 以降）
- 修正案の受け取り・検証（Stage 3）
- Verification 結果 schema（Stage 4）
- Bounded Autonomy の policy と判定（Stage 5）

---

## 重大な技術的 GAP（優先度順）

1. **安定した Finding identity がない**: `ID` は report 内の連番。Delta / Verification / Contract のすべてが cross-report identity を前提とするため、v1.1 で定義する必要がある。
2. **Template Semantic Diff がない**: Stage 2 の Invariant と Stage 4 の検証に必須。
3. **`passed_all_checks` が `errors[]` を無視する**: 互換性のため値の意味は変えられない。v2.0 では別の判定（例: Delta 側の `comparable` フラグ）を新設する必要がある。
4. **Git 取得経路がない**: `proc.run` は `cwd` を持たず、env allowlist は `HOME` を通す。git 導入時は untrusted repository config の扱いを設計する必要がある。
5. **Markdown 出力がない**: 人間向け Delta Report は新規。
6. **HEAD のテストが 2 件 FAIL**: v1.1 着手前に Baseline を緑に戻す判断が必要（本調査では修正していない）。
