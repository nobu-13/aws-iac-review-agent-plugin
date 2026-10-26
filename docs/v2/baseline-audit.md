# v2.0 Baseline Audit — aws-iac-review-agent-plugin

本書は v2.0「AWS IaC Bounded Remediation」開発に先立ち、現行実装（v1.0.0 + HEAD の docs 追加）を調査した Baseline Audit である。
調査のみを行い、Source・Test・設定は一切変更していない。根拠のない項目は `NOT VERIFIED` と明記する。

- 調査日: 2026-10-16 (ローカル実行)
- 調査者: Kiro（Agent workflow による調査）
- 対象: `<repo>`（本 Repository の root）

---

## A. Repository Baseline

### A-1. Git 状態

| 項目 | 値 | 取得方法 |
| --- | --- | --- |
| Branch | `main` | `git branch --show-current` |
| Commit SHA (HEAD) | `5e5ed36fe9cb26f58486806f04a9795d2332c83f` | `git rev-parse HEAD` |
| HEAD の内容 | `Merge pull request #6 from nobu-13/docs/privacy-policy-support` | `git log --oneline -5` |
| 直近 tag | `v1.0.0` = `eb0367e`（HEAD はその 2 commit 先） | `git log --oneline -5` |
| Remote 追跡 | `origin/main` = HEAD | 同上 |
| Tracked file 数 | 299 | `git ls-files \| wc -l` |

#### 調査開始時の `git status --porcelain`

```text
(出力なし — 作業ツリーはクリーン)
```

`git status --porcelain --ignored` で確認した無視対象（Git 管理外・本調査では変更していない）:

```text
!! .coverage
!! .hypothesis/
!! .kiro/
!! .mypy_cache/
!! .pytest_cache/
!! .ruff_cache/
!! sample/
!! semantic-review/
```

注記: `.kiro/`（steering / specs）、`sample/`、`semantic-review/` は `.gitignore` で除外されている。多くの docstring が参照する `design.md` / `requirements.md` は `.kiro/specs/aws-iac-review-agent-plugin/` にあり、**公開 Repository には含まれない**。

#### 調査終了時の `git status --porcelain`

```text
?? docs/v2/
```

`git status --porcelain --untracked-files=all` の結果:

```text
?? docs/v2/baseline-audit.md
?? docs/v2/reuse-and-gap-analysis.md
?? docs/v2/v1.1-implementation-proposal.md
```

それ以外の tracked / untracked file に変化はない。`git status --porcelain --ignored` の無視対象一覧も開始時と同一で、`find . -path ./.git -prune -o -mtime -1 -print` でも過去 24 時間以内に更新された file は上記 3 file（と、それを含む `docs/`・`docs/v2/` directory）のみだった。`.coverage`、`.hypothesis/`、`.pytest_cache/` の mtime は調査前と同じ。

追加確認: 3 file を含めた一時コピーで `scan_secrets.py`（worktree mode）を実行 → `0 finding(s) in 302 file(s)`。`tests/unit/test_docs.py`, `test_root_docs.py`, `test_manifest.py`, `test_scaffold.py`, `test_traceability.py`, `test_ground_truth.py` を実行した結果、失敗は Baseline と同じ既知の 2 件（D-2）のみで、新しい失敗はない。なお `docs/v2/` は依頼に従い日本語で書いている。`.kiro/steering/documentation.md` は公開文書を英語基本としているため、公開前に英語化するかどうかの判断が必要（`tests/unit/test_docs.py` の英語チェックは固定 list `DOCUMENTS` だけが対象で、`docs/v2/` は対象外）。

### A-2. Version / Manifest

| 項目 | 値 | 根拠 |
| --- | --- | --- |
| Plugin version | `1.0.0` | `plugin.json` `version` |
| Package version | `1.0.0` | `iacreview/__init__.py` `__version__` |
| Report schema version | `1.0.0` | `iacreview/report.py` `SCHEMA_VERSION` |
| Agent findings 受理 MAJOR | `1` | `iacreview/agentin.py` `SUPPORTED_SCHEMA_MAJOR` |
| CHANGELOG 最新 | `## [1.0.0] - 2026-09-01`（`[Unreleased]` は空見出し） | `CHANGELOG.md` |
| `plugin.json` `$schema` | `https://agent-plugins.org/schemas/1.0.0/plugin.schema.json` | `plugin.json` |
| `mcp.json` | **Plugin root に存在しない**（`.gitignore` で除外。例示のみ `docs/mcp/mcp.json.example`） | `ls mcp.json` → No such file |
| `pyproject.toml` | `name`, `requires-python`, `dependencies`, optional deps、tool 設定のみ。`[build-system]` / `[project.scripts]` なし | `pyproject.toml` |

`plugin.json` は `name`, `version`, `description`, `author`, `homepage`, `repository`, `license`, `keywords` のみで、Skill や MCP の明示的な列挙はない（Agent Plugins の `skills/` 自動探索に依存）。

### A-3. Directory 構造（tracked のみ、要約）

```text
.github/workflows/ci.yml          CI (4 gate + determinism + advisory lint)
.github/scripts/                  scan_secrets.py, check_ground_truth_order.py, install_cfn_guard.py
benchmark/                        cases/ (17 case), harness/ (run_benchmark.py, metrics.py),
                                  agent-findings/, cfn-lint-contribution/, ground_truth.schema.json
docs/                             architecture.md, finding-schema.md, security-model.md,
                                  benchmark-methodology.md, traceability.md, kiro-power.md,
                                  privacy-policy.md, mcp/README.md, mcp/mcp.json.example
examples/                         minimal-s3/, lambda-with-role/, cdk-synth-output/
iacreview/                        共有 Python package (27 .py file, iam/ sub-package)
rules/                            cfn-guard rule 36 個 (backup 11, encryption 11, iam 1,
                                  logging 6, public-access 6, tagging 1) + 各 _meta.json
skills/                           cfn-guard-review, cfn-lint-review, cloudformation-review,
                                  iac-review, iam-review (各 SKILL.md + scripts/)
tests/                            unit/, integration/, property/, regression/, negative/,
                                  fixtures/, fakebin/
```

`iacreview/` の module（27 `.py` file、`wc -l` 合計 18,277 行）: `agentin`, `agentprompt`, `bootstrap`, `categories` (+`category_map.json`), `cdk`, `cfnguard`, `cfnlint`, `dedup`, `errors`, `exitcodes`, `finding`, `netgraph`, `pathguard`, `proc`, `quality`, `report`, `sarif`, `secrets`, `source`, `template`, `toolcheck`, `yamlcfn`, `iam/{__init__,detectors,intrinsics,locate}`。

### A-4. Runtime / Dependency / 外部 Tool

| 種別 | 宣言 | 根拠 |
| --- | --- | --- |
| Python | `requires-python = ">=3.9"` / `toolcheck.TOOL_REQUIREMENTS[PYTHON3].min_version = "3.9"` | `pyproject.toml`, `iacreview/toolcheck.py` |
| Runtime 依存 | `PyYAML>=6.0`（唯一） | `pyproject.toml` `dependencies` |
| Dev 依存 | `pytest>=7.0`, `pytest-cov>=4.0`, `hypothesis==6.141.1` | `pyproject.toml` `[project.optional-dependencies].dev` |
| Lint 依存 (advisory) | `ruff==0.8.6`, `mypy==1.14.1` | `pyproject.toml` `lint` |
| cfn-lint | 最小 `1.0.0`、CI pin `1.46.0` | `toolcheck.TOOL_REQUIREMENTS`, `ci.yml` `CFN_LINT_VERSION` |
| cfn-guard | 最小 `3.0.0`、CI pin `3.2.1`（SHA-256 検証付き install） | `toolcheck.TOOL_REQUIREMENTS`, `.github/scripts/install_cfn_guard.py` `CFN_GUARD_VERSION` |
| AWS CDK CLI | 最小 `2.0.0`、`--confirm-cdk-synth` 時のみ | `toolcheck.TOOL_REQUIREMENTS`, `iacreview/cdk.py` |

### A-5. CLI Entry Point / Package 構造

- Python package は **pip install されない**。各 Skill script が `Path(__file__).resolve().parents[3]` を `sys.path` に挿入し、`bootstrap.require_plugin_root(__file__)` で `plugin.json` の存在と import 元の一致を検証する（`iacreview/bootstrap.py` `SCRIPT_DEPTH_TO_PLUGIN_ROOT = 3`、`docs/architecture.md`「The shared package `iacreview/`」）。
- `console_scripts` / `__main__.py` は存在しない。Entry point は以下の script のみ。

| Script | 主な引数 | 役割 |
| --- | --- | --- |
| `skills/iac-review/scripts/run_iac_review.py` | `--target`(必須,反復), `--sources`, `--rules-dir`, `--agent-findings`, `--confirm-cdk-synth`, `--format json\|sarif`, `--verbose` | 全 Source の統合 Review_Report |
| `skills/cfn-lint-review/scripts/run_cfn_lint.py` | `--target` | cfn-lint 単独 |
| `skills/cfn-guard-review/scripts/run_cfn_guard.py` | `--target`, `--rules-dir` | cfn-guard 単独（envelope + `stats`） |
| `skills/iam-review/scripts/run_iam_scan.py` | `--target` | IAM Layer 1 |
| `skills/iam-review/scripts/extract_policies.py` | `--target` | IAM Layer 2 用 policy site 抽出 |
| `skills/cloudformation-review/scripts/extract_facts.py` | `--target`, `--deterministic-report` | Agent 用 template facts |
| `skills/cloudformation-review/scripts/build_prompt.py` | `--facts`, `--target` | Agent 用 prompt 生成 |
| `benchmark/harness/run_benchmark.py` | `--cases`(必須), `--mode`, `--filter-only`, `--agent-findings`, `--agent-runs`, `--timing-report` | Contributor 用 benchmark（plugin.json 非公開） |

---

## B. 既存 Review 機能

### B-1. 機能別 Evidence 表

| 機能 | 実装ファイル | 主要関数 | 入力 | 出力 | 失敗時の動作 |
| --- | --- | --- | --- | --- | --- |
| Template 読み込み | `iacreview/template.py` | `load_template`, `_read_bytes_toctou_safe`, `parse_template_text`, `detect_format`, `is_reviewable` | pathguard 済みの `Path` | `LoadedTemplate(path, doc, fmt)` | 5 MiB 超 → `InputTooLargeError`(`input_too_large`)、UTF-8/構文不正・空 → `TemplateParseError`（error_type, line, column 付き, exit 4）、`Resources` なし/空 → `NotReviewableError`(exit 8)、非 regular file / inode 不一致 → `path_violation` |
| YAML 解析 (intrinsic tag) | `iacreview/yamlcfn.py` | `load_yaml`, `cfn_safe_loader`, `_build_loader`(`CfnSafeLoader(yaml.SafeLoader)`), `_make_constructor`, `long_form_key` | text | `!Ref`→`{"Ref":..}`、`!GetAtt`→`{"Fn::GetAtt":[..]}` など long form の dict | allowlist (`SHORT_TAGS` 18 種) 外の tag・`!!python/*` → `ConstructorError`→parse_failure。alias 展開 `MAX_ALIAS_EXPANSIONS=10000` 超で停止。PyYAML 不在 → `ToolUnavailableError` |
| JSON 解析 | `iacreview/template.py` | `parse_template_text`, `detect_format` (`JSON_START_CHARACTERS="{["`) | text | dict | `json` decode error → `TemplateParseError`（位置付き） |
| cfn-lint 連携 | `iacreview/cfnlint.py` | `build_argv` → `[exe,"-f","json","-c","I","--",path]`, `decode_cfnlint_exit`(bitmask `CFNLINT_FINDING_BITS=14`), `parse_output`, `normalize_results`, `finding_from_result`, `run_and_normalize` | template path, `ToolInfo` | `SourceResult(findings, errors, stats)` | timeout 60s (`TIMEOUT_S`) → `tool_timeout`、bitmask 外の exit → `tool_execution`、出力構造不正 → `parse_failure`（Source の findings は破棄） |
| cfn-guard 連携 | `iacreview/cfnguard.py` | `build_argv`(`validate --data <t> --rules <d>... --output-format json --type CFNTemplate --show-summary none`), `interpret_guard_result`, `parse_records`, `parse_output`, `load_rule_metadata`, `resolve_rules_dirs`, `normalize_results`, `run_and_normalize` | template path, rules dirs（bundled `rules/` + `--rules-dir`）, `_meta.json` | `SourceResult` + `stats.rules_evaluated/rules_passed` | `interpret_guard_result` は exit 値で分岐せず構造判定: timed_out→`timeout`、0→`all_passed`、それ以外は stdout が parse できれば `violations`、できなければ `tool_error`。空 stdout は失敗扱い。timeout 60s |
| IAM Review (Layer 1) | `iacreview/iam/__init__.py`, `iam/detectors.py`, `iam/intrinsics.py`, `iam/locate.py` | `run_and_normalize`, `extract_policy_sites`, `scan`, `scan_sites`, `scan_target`, `DETECTORS`, `apply_external_id_mitigation`, `unresolvable_finding`, `malformed_document_finding` | `LoadedTemplate`（parse 再利用） | `Confirmed` / Security Finding、未解決値は `Informational/INFO` | IAM 無し template → findings 0 + stderr に informational message（Finding ではない）。非 mapping の PolicyDocument → 「解析不能」Finding |
| IAM Review (Layer 2) | `skills/iam-review/scripts/extract_policies.py` + `skills/iam-review/SKILL.md` | — | template | policy site JSON（Agent が推論） | Agent 出力は `--agent-findings` で再入場 |
| Network Review | `iacreview/netgraph.py` | `build_graph`, `detect_igw_not_attached`, `detect_route_table_without_default_route`, `detect_rds_public_subnet_exposure`, `detect_orphaned_network_resource`, `review`, `run_and_normalize` | parsed doc | `Confirmed` Finding | 例外は orchestrator の `collect` で `errors[]` 化 |
| Secret Review | `iacreview/secrets.py` | `SECRET_RULES`, `looks_like_secret`, `review`, `run_and_normalize` | parsed doc | `Confirmed` Finding | 同上 |
| Quality Review | `iacreview/quality.py` | `detect_condition_name_logic_mismatch`, `detect_unused_parameter`, `detect_unused_condition`, `detect_circular_dependency`, `detect_allowed_values_mixed_types`, `review`, `run_and_normalize` | parsed doc | `Confirmed` Finding | 同上 |
| Category 正規化 | `iacreview/categories.py`, `iacreview/category_map.json` | `load_map`, `classify_cfnlint`, `CategoryMap`, `GUARD_FALLBACK_CATEGORY="Other"` | rule id / level | `Normalized_Category`, FindingType, Severity | mapping file 不正 → `MappingFileError`（exit 1） |
| Agent findings 取り込み | `iacreview/agentin.py` | `load_agent_findings`, `findings_from_payload`, `_normalize_confidence`(Confirmed→Likely 降格), `_normalize_category`(→Other), `_normalize_source`, `_normalize_evidence` | `--agent-findings` JSON | `(findings, errors)` | 個別 Finding の schema 違反 → drop + `errors[]`、file 全体が不正 → `SchemaViolationError`（orchestrator は errors[] 化し exit 0 維持） |
| 重複排除・merge | `iacreview/dedup.py` | `dedup_key`, `deduplicate`, `_merge_group`, `_merged_confidence`, `_merged_evidence`, `_location_primary` | Finding list（Template 単位） | merge 済み list（`ID=0`） | 例外なし（入力 validate 済み前提） |
| Report 生成 (JSON) | `iacreview/report.py` | `sort_findings`, `_sort_key`, `assign_ids`, `_summary`, `build_report`, `dump`, `configure_stdout`, `normalize_output_path` | findings, errors, `ReportMeta` | 7-key envelope dict / JSON text | 出力境界で `finding.validate` 失敗、絶対 path・`..` → `SchemaViolationError` |
| Report 生成 (SARIF) | `iacreview/sarif.py` | `to_sarif`, `level_for` | 組み立て済み report | SARIF 2.1.0 dict | 純関数（I/O なし） |
| **Markdown Report** | — | — | — | — | **存在しない**（`iacreview/` に Markdown renderer なし。grep で確認） |
| Orchestration | `skills/iac-review/scripts/run_iac_review.py` | `build_parser`, `IacReview.validate/_discover/_verify_tools/_build_specs/collect/_load_agent_findings/_report/exit_code/partial_report/run`, `main`, `source_ran`, `unexpected_error` | argv | stdout に report、exit code | 下記 B-3 |
| CDK | `iacreview/cdk.py` | `detect_cdk_project`, `partition_templates`, `find_templates`, `synth_if_confirmed`, `build_synth_argv`, `_working_directory` | directory | template path list | flag なし → process 起動なし + `invalid_arguments` を errors[] に記録し exit 0。synth 失敗/timeout(120s) → fallback せず停止 |
| Agent prompt | `iacreview/agentprompt.py`, `skills/cloudformation-review/scripts/*` | `build_checklist`, `build_prompt` / `build_facts` | facts JSON | prompt text | — |

### B-2. Agent Plugin / Skills

5 Skill が `skills/<name>/SKILL.md`（YAML front matter `name` / `description`）+ `scripts/` 構成。Skill 同士は互いの script を呼ばず、共有 `iacreview/` のみに依存する（`run_iac_review.py` module docstring、`docs/architecture.md` Option C）。`tests/unit/test_skills.py`・`tests/unit/test_bootstrap.py` が SKILL.md 契約と bootstrap 深さを検証する。

- `iac-review`: 決定論 Source 群 + `--agent-findings` を統合。`SKILL.md` に `python3 skills/iac-review/scripts/run_iac_review.py --target templates/app.yaml` の呼び出し例と引数表あり。
- `cloudformation-review` / `iam-review` Layer 2: Agent 推論。結果は JSON file として `--agent-findings` に渡す設計で、Agent は Finding の正規化・merge・採番に関与できない（`docs/architecture.md`「Three things an agent cannot do」）。

### B-3. エラー処理・部分的 Tool 失敗

- `errors[]` の要素は `StructuredError`（`iacreview/errors.py` `STRUCTURED_ERROR_KEYS` の 9 key 固定: `error_class`, `source`, `tool`, `exit_code`, `message`, `required_min_version`, `detected_version`, `remediation`, `stderr_head`）。`error_class` は閉集合 `ERROR_CLASSES` 12 値。
- `stderr_head` は先頭 5 行（`STDERR_HEAD_MAX_LINES`）で、`redact_stderr_line` が絶対 path → `<path>`、`pid N` → `pid <pid>`、ISO-8601 → `<timestamp>` に置換。
- cfn-guard 不在で cfn-lint 成功の場合（コードで確認）: `IacReview._verify_tools` が `require_known_tool` 失敗を `tool_unavailable` として `errors[]` に記録し、その Source を `specs` から除外。他 Source が 1 つでも成功すれば `exit_code()` は `OK`(0)。`tools[]` には `{"name":"cfn-guard","available":false,"version":null}`。テスト: `tests/regression/test_sec_tool_unavailable.py::test_the_orchestrator_records_the_failure_and_keeps_going`、`tests/integration/test_tool_unavailable.py`。
- Source 実行中の想定外例外: `collect` が `unexpected_error()`（例外の型名のみ、traceback は stderr）として記録し次 Source へ。
- 全 Source 失敗時は最初の失敗の exit code（5/6 等）。`PARTIAL_REPORT_ERROR_CLASSES` に該当する失敗では部分 report を stdout に出す。

Exit code（`iacreview/exitcodes.py`）: 0 OK, 1 UNEXPECTED, 2 INVALID_ARGUMENTS, 3 INPUT_NOT_FOUND, 4 PARSE_FAILURE, 5 TOOL_UNAVAILABLE, 6 TOOL_EXECUTION_FAILURE, 7 PATH_VIOLATION, 8 NO_REVIEWABLE_TEMPLATE。benchmark harness のみ追加で 9 `BENCHMARK_FAILURE`, 10 `CASE_NOT_EVALUATED`。

### B-4. 実装と文書の差分（Informational）

| 観察 | 根拠 |
| --- | --- |
| `iam/detectors.py` `DETECTORS` は 19 要素だが、`iam_user_inline_policy`, `access_key_in_template`, `iam_admin_policy_attached`, `overly_permissive_trust` の 4 つは `DetectorResult(())` を返す placeholder（docstring に "Not yet implemented"）。実働は 15（`docs/architecture.md` の「15 deterministic detectors」と一致） | `iacreview/iam/detectors.py` L2004-2042、`tests/unit/test_iam_detectors.py:1040` の skip "placeholder detector not yet implemented" |
| `run_iac_review.py` の module docstring / `DESCRIPTION` は「three deterministic Sources」と記述するが、実装の `SOURCE_ORDER_FOR_COLLECTION` は 6 Source（cfn-lint, cfn-guard, IAM, Network, Secret, Quality） | `skills/iac-review/scripts/run_iac_review.py` |
| Benchmark 出力の `sources_evaluated` は `["cfn-lint","cfn-guard","IAM Review"]` のみを列挙（Network/Secret/Quality が出現しない）。指標値への影響は未調査 | benchmark 実行結果（D-3）。原因は **NOT VERIFIED** |
| docstring が参照する `design.md` / `requirements.md` は gitignore 下の `.kiro/specs/` にあり公開されていない | `.gitignore` `.kiro/` |

---

## C. v2.0 互換性

### C-1. 13-field Finding Schema

定義は `iacreview/finding.py` の `@dataclass class Finding`。`FINDING_FIELDS = tuple(f.name for f in fields(Finding))` で dataclass から導出され、**コード上も 13 field**（文書 `docs/finding-schema.md`「The 13 fields」と一致）。

| # | Field | 型 (Python) | Nullable | 制約 |
| --- | --- | --- | --- | --- |
| 1 | `ID` | `int` | no | `>= 1`。sort 後に report 内連番。内部未採番値 `UNASSIGNED_ID = 0` |
| 2 | `Normalized_Category` | `str` | no | `category_map.json` の 11 値: `IAM`, `Encryption`, `PublicAccess`, `Logging`, `Tagging`, `Availability`, `Backup`, `NetworkSecurity`, `DataProtection`, `TemplateQuality`, `Other` |
| 3 | `FindingType` | `str` | no | `FINDING_TYPES = ("Validity","Security","BestPractice","Informational")` |
| 4 | `Severity` | `str` | no | `SEVERITIES = ("CRITICAL","HIGH","MEDIUM","LOW","INFO")` |
| 5 | `Confidence` | `str` | no | `CONFIDENCES = ("Confirmed","Likely","Contextual")` |
| 6 | `Source` | `List[str]` | no | `SOURCES = ("cfn-lint","cfn-guard","IAM Review","Network Review","Secret Review","Quality Review","Agent Review")`、1 件以上・重複なし・`SOURCE_ORDER` 順 |
| 7 | `Resource` | `Optional[str]` | yes | logical ID。空文字不可 |
| 8 | `Location` | `Location(File, Line?, Column?, TemplatePath?)` | no | `File` は workspace 相対。`TemplatePath` は `canonical_template_path` で index=int / key=str（index 1 は例外） |
| 9 | `Finding` | `str` | no | 非空 |
| 10 | `WhyItMatters` | `str` | no | 非空 |
| 11 | `Evidence` | `List[Evidence(Source, Detail, RuleId?, Excerpt?)]` | no | 1 件以上 |
| 12 | `Recommendation` | `str` | no | 非空 |
| 13 | `SuggestedRemediation` | `Optional[str]` | yes | 自動適用しない |

`validate` の追加制約 4 つ（`docs/finding-schema.md`「Constraints JSON Schema cannot express」）: Confirmed は Agent Review を含めない／非 Confirmed は Excerpt 必須／Validity+CRITICAL は `blocks_deployment` rule 必須／`Other` は merge 済み Source 不可。テスト: `tests/unit/test_finding.py`, `tests/property/test_prop_finding_schema.py`。

**JSON Schema ファイルについて**: `docs/finding-schema.md` は「JSON Schema `required` list in design.md」と記述するが、Finding / Review_Report の JSON Schema ファイルは公開 Repository に存在しない（存在するのは `benchmark/ground_truth.schema.json` のみ）。

### C-2. Review_Report Schema

`iacreview/report.py` `build_report` が返す envelope は `REPORT_KEYS` の 7 key 固定:

```text
schema_version, target{files, cdk{detected, synthesis, synthesized_templates}},
sources_enabled, tools[{name, available, version}], findings[], errors[], summary
```

- `target.cdk.synthesis` は `CDK_SYNTHESIS_OUTCOMES = ("not_applicable","skipped_unconfirmed","ran")`。
- `summary` は `SUMMARY_KEYS` 6 key: `total`, `by_finding_type`(4), `by_severity`(5), `by_source`(7, merge により total 超過あり), `by_template_group`(`standalone`,`synthesized`), `passed_all_checks`。全 counter は 0 埋め。
- `cfn-guard-review` Skill のみ envelope の横に `stats` を追加（`docs/finding-schema.md` C-10）。`iac-review` の出力に `stats` はない。
- `dump` は `json.dumps(sort_keys=True, ensure_ascii=False, indent=2, separators=(",", ": "))` + 改行。timestamp・絶対 path なし。

### C-3. `summary.passed_all_checks`

実装は `report._summary` の `"passed_all_checks": not findings`（`findings` は採番後の list）。**`errors[]` は考慮しない**。Tool が失敗・不在でも Finding が 0 件なら `true` になる（コメントと `docs/finding-schema.md` で意図的と明記）。v2.0 の Verification / Bounded Autonomy でこの値を「合格」判定に直接使うと、cfn-guard 不在時に誤って合格と判定されうる。

### C-4. `errors[]`

`build_report` は `errors` を順序を保ったまま deep copy（sort しない）。追加される主な場面: Tool 不在/版不足（`_verify_tools`）、Source 実行失敗（`collect`）、Agent findings の drop / file 不正（`_load_agent_findings`）、CDK synth 未確認（`invalid_arguments`, exit 0）、Template parse 失敗・非 reviewable、aggregate size 超過（`input_too_large`）。

### C-5. Finding ID 生成方法

- `report.assign_ids`: `replace(f, ID=index)` を `sort_findings` 後に 1 から連番付与。hash ではない。
- sort key（`report._sort_key`）: `(-severity_rank, Resource or "", Normalized_Category, Finding, canonical JSON (ID 除外))` — 内容のみで決まる全順序のため、**同一入力では順序・ID は決定論的**（`tests/property/test_prop_determinism.py::test_stdout_is_a_function_of_the_input_alone`、`tests/property/test_prop_dedup.py::test_deduplication_is_permutation_invariant`）。
- ただし ID は **report 内の位置**であり、別 report 間の安定 identity ではない（`docs/finding-schema.md`「`ID`」節が明言。cross-report key として `(Resource, Normalized_Category)` を推奨）。Finding が 1 件増えるだけで後続の ID がずれる。

### C-6. 既存 CLI の互換性面

互換性を維持すべき surface: `run_iac_review.py` の引数 6 種 + `--verbose`、exit code 0-8、stdout = 7-key JSON（または `--format sarif`）、stderr = 診断。`--verbose` は stdout を変えない。stdin を読まない（Requirement 16 AC9 相当、`proc.run` も `stdin=DEVNULL`）。

### C-7. Semantic Diff / Finding Delta への拡張点

| 拡張点 | 現状 | 根拠 |
| --- | --- | --- |
| parse 済み doc の再利用 | `LoadedTemplate.doc` は intrinsic を long form に正規化済みの dict。`parse_template_text(text, path)` は file を介さず text から parse 可能 | `iacreview/template.py`, `iacreview/yamlcfn.py` |
| Finding の (de)serialize | `to_dict` / `from_dict`（未知 key 拒否）、`validate` | `iacreview/finding.py` |
| Finding の cross-report key | 文書上 `(Resource, Normalized_Category)`。実装上は `dedup.dedup_key`（`Other`/`Resource=None` は `None`） | `iacreview/dedup.py`, `docs/finding-schema.md` |
| 1 対 1 matching | `benchmark/harness/metrics.py` `match`（`match_key = (resource, finding_type, normalized_category)`、canonical JSON で tie-break）。**benchmark 側にあり `iacreview/` には無い** | `benchmark/harness/metrics.py` |
| 新しい出力 envelope | `report.dump` / `configure_stdout` を再利用可能。7-key envelope は閉じているため、Delta は別 envelope にする必要あり | `iacreview/report.py` |
| Git 差分取得 | **存在しない**（`iacreview/`・`skills/` に git 呼び出しなし。git を呼ぶのは CI script のみ） | grep 結果（E-3） |
| Markdown 出力 | **存在しない** | B-1 |

---

## D. テスト・品質 Baseline

### D-1. 実行環境

| 項目 | 値 |
| --- | --- |
| OS | macOS 26.6.2 (arm64)（`sw_vers`, `uname -a` の出力から OS 版と architecture のみ記載） |
| テスト用 Python | `/usr/bin/python3` = Python 3.9.6（macOS CommandLineTools 同梱の system Python。PATH 先頭の Homebrew 版 `python3` は 3.14.7 で PyYAML・pytest 未導入のため不使用） |
| pip | 21.2.4 / `pip check`: `No broken requirements found.` (exit 0) |
| PyYAML / pytest / pytest-cov / hypothesis / coverage | 6.0.3 / 8.3.4 / 6.0.0 / 6.141.1 / 7.10.7 |
| cfn-lint | 1.46.0（system Python 3.9 の user site に pip で導入）— CI pin と一致 |
| cfn-guard | 3.2.1（Homebrew で導入）— CI pin と一致 |
| AWS CDK CLI | 2.1139.0 (build d51353e)（Homebrew で導入） |
| Node.js | v26.8.1 |
| ruff / mypy | 0.8.6 / 1.14.1 — `lint` extra の pin と一致 |

Dependency の install / upgrade は一切行っていない。

### D-2. テスト実行

実行場所: 一時コピー `/tmp/iacaudit.XXXXXX/repo`（`rsync -a --exclude .git --exclude .coverage --exclude .hypothesis --exclude .pytest_cache --exclude .mypy_cache --exclude .ruff_cache --exclude sample --exclude semantic-review --exclude .kiro`）。gitignore 対象を除外し、CI の checkout と同じ構成にした。終了後に削除。

| 項目 | 値 |
| --- | --- |
| Command（CI `test` job と同一） | `/usr/bin/python3 -m pytest --cov=iacreview --cov=benchmark/harness --cov-fail-under=80 -rs` |
| Exit code | **1** |
| 合計 | 4,279（collected） |
| PASS | 4,241 |
| FAIL | **2** |
| SKIP | 36 |
| ERROR | 0 |
| 実行時間 | 413.58 s（pytest 表示）/ 414 s（wall） |
| Coverage | 96.94%（`TOTAL 4938 stmts, 151 miss`）— 80% floor は達成 |

注記: 最初の試行は tool の 120 秒 timeout で中断（`KeyboardInterrupt`、174 passed 時点）したため、`nohup` による detached 実行で再実行した。上表は再実行の結果。

#### 失敗テスト（コードは修正していない）

| Test | 失敗内容 | 原因 |
| --- | --- | --- |
| `tests/unit/test_root_docs.py::test_readme_level_2_headings_are_exactly_the_required_sequence` | README.md の `##` 見出し列が `README_REQUIRED_SECTIONS` より 2 項目多い（first extra: `Support`） | HEAD 直前の commit `a12a4f5`（docs: add Privacy Policy and Support sections）が `README.md` に `## Support` と `## Privacy Policy` を追加したが、`tests/unit/test_root_docs.py` の `README_REQUIRED_SECTIONS`（L1649）は v0.1.0 (`81f77b5`) 以降更新されていない |
| `tests/unit/test_root_docs.py::test_readme_ja_sections_follow_the_english_order` | README.ja.md の見出し列が `README_JA_SECTION_TITLES` より 2 項目多い（first extra: `Support`） | 同じ commit で `README.ja.md` に同じ 2 見出しが追加された |

分類: **Test と Documentation の不整合**（Implementation Bug ではない）。HEAD の `main` は CI の `test` gate を通過しない状態と推定されるが、GitHub 上の CI 結果は **NOT VERIFIED**。

#### SKIP の内訳（36 件）

| 件数 | 理由 | 箇所 |
| --- | --- | --- |
| 4 | clean / agent-only case に deterministic expectation がない | `tests/integration/test_benchmark_cases.py:260` |
| 8 | case が cfn-guard に何も帰属しない | 同 `:439` |
| 14 | case が IAM Review に何も帰属しない | 同 `:469` |
| 4 | clean case（空であること自体が目的） | `tests/unit/test_ground_truth.py:915` |
| 4 | placeholder detector 未実装 | `tests/unit/test_iam_detectors.py:1040` |
| 1 | `sample/buggy-template.yaml` が checkout にない（gitignore） | `tests/integration/test_skill_build_prompt.py:60` |
| 1 | `.kiro/specs/.../requirements.md` が checkout にない（gitignore） | `tests/unit/test_traceability.py:324` |

補足確認: `.kiro/` と `sample/` を別の一時コピーに含めて `tests/unit/test_traceability.py tests/integration/test_skill_build_prompt.py` を実行 → **72 passed**（exit 0）。gitignore 対象の有無で 2 skip が pass になることを確認した。

#### Determinism job（CI `determinism` 相当）

`PYTHONHASHSEED=random /usr/bin/python3 -m pytest tests/property/test_prop_determinism.py -p no:cacheprovider` → **1 passed**, exit 0, 20.90 s。

### D-3. Benchmark

| 項目 | 値 |
| --- | --- |
| Command（CI と同一） | `/usr/bin/python3 benchmark/harness/run_benchmark.py --cases benchmark/cases --mode combined` |
| Exit code | **0** |
| 実行時間 | 16 s |
| 全体 status | `PASS` |
| metrics | expected 34 / actual 34 / matched 34、detection_rate・precision・recall・severity_accuracy すべて `100.0`、FP 0 / FN 0 |
| case 別 | case-001〜013: `PASS`、case-101/102（clean）・201/202（agent-only / human-review）: `INFO` |
| diagnostics | `human_intervention_count: 1`, `remediation_accuracy: "N/A"` |
| `errors` | `[]` |
| `sources_evaluated` | `["cfn-lint","cfn-guard","IAM Review"]`（B-4 参照） |

`agent_findings_supplied: false`。Agent findings を使う benchmark モードは実行していない（**NOT VERIFIED**）。

### D-4. Lint / 型検査 / Repository hygiene

すべて一時コピーで実行（`ruff --no-cache`）。CI では `lint` job は `continue-on-error: true`（advisory）。

| Command | Exit | 結果 |
| --- | --- | --- |
| `ruff check . --no-cache` | 1 | 40 件: E402 ×26（tests の sys.path bootstrap 由来）、F401 ×13、F841 ×1 |
| `ruff check iacreview --no-cache` | 1 | 5 件: `agentprompt.py:43` F401 ×2（`Optional`,`Sequence`）、`netgraph.py:28` F401、`quality.py:34` F401、`quality.py:335` F841（`types`） |
| `mypy iacreview` | 1 | 12 errors / 7 files: `finding.py:254-255`, `cfnlint.py:374-375`, `cfnguard.py:578-579,1512-1513`（例外への動的属性 `field`/`reason` 代入 `attr-defined`）、`yamlcfn.py:311`（`yaml.SafeLoader` name-defined、PyYAML stub 無し設定由来）、`report.py:498`（`frozenset` を `Sequence` 引数へ）、`secrets.py:190`, `quality.py:154`（`List[str]` vs `List[Union[str,int]]`） |
| `python3 .github/scripts/scan_secrets.py`（一時コピー, worktree mode） | 0 | `0 finding(s) in 299 file(s)` |
| `python3 .github/scripts/scan_secrets.py`（実 repo, tracked mode, `PYTHONDONTWRITEBYTECODE=1`） | 0 | `0 finding(s) in 299 file(s)` |
| `python3 .github/scripts/check_ground_truth_order.py --cases benchmark/cases`（実 repo, read-only git） | 0 | `17/17 case(s) verified` |
| `python3 -m pip check` | 0 | `No broken requirements found.` |

mypy 指摘はいずれも型注釈上の問題で、テスト上は実行時エラーとして現れていない（実行時影響は全テスト pass の範囲で確認）。`.github/scripts/install_cfn_guard.py` は install を伴うため実行していない。

---

## E. Security / Trust Boundary

### E-1. 確認内容

| 観点 | 実装 | 根拠テスト |
| --- | --- | --- |
| Path traversal | `pathguard.resolve_within` → `_resolve_under_root`: `resolve(strict=False)` 後に `relative_to(root_real)`。`..`、絶対 path、外向き symlink を `PathContainmentError`(exit 7) | `tests/regression/test_sec_path_traversal.py`（`test_the_classic_traversal_string_is_refused`, `test_a_symlink_pointing_outside_the_root_is_refused`, `test_a_sibling_root_sharing_the_prefix_is_refused` 等 6 件）、`tests/property/test_prop_pathguard.py::test_path_resolution_stays_inside_the_root` |
| Symlink / TOCTOU | `template._read_bytes_toctou_safe`: `os.open(O_RDONLY\|O_NOFOLLOW\|O_NONBLOCK)` + `fstat` で regular file と `(st_dev, st_ino)` 一致を確認。symlink loop は `RuntimeError` も捕捉 | `tests/regression/test_sec_symlink_loop.py`（5 件）, `tests/regression/test_sec_non_regular_file.py` |
| Shell metacharacter | `pathguard.assert_no_shell_metacharacters`（`; \| & $ \` > <`）を defense in depth として拒否 | `tests/regression/test_sec_shell_metacharacters.py`（5 件） |
| 外部 command 実行 | 唯一の起動点 `proc.run`: `subprocess.Popen([resolved, *argv[1:]], shell=False, stdin=DEVNULL, env=_minimal_env(), start_new_session=True)`、timeout 時は process group に SIGTERM→SIGKILL。`shell=True`・`os.system`・`eval`/`exec` は `iacreview/`・`skills/`・`benchmark/`・`.github/scripts/` に存在しない（grep 確認） | `tests/unit/test_proc.py`, `tests/regression/test_sec_process_group_reaped.py::test_timed_out_tool_reaps_its_grandchild`, `tests/property/test_prop_pathguard.py::test_shell_metacharacters_are_rejected_and_argv_reaches_the_child_as_a_list` |
| 環境変数 | `proc.INHERITED_ENV_VARS = {PATH, HOME, LANG, LC_ALL, TMPDIR, AWS_REGION, AWS_DEFAULT_REGION}` の allowlist。`AWS_ACCESS_KEY_ID` 等は子 process に渡らない | `tests/unit/test_proc.py`（`_minimal_env` の部分集合 assert） |
| Unsafe YAML | `CfnSafeLoader(yaml.SafeLoader)` + tag allowlist、`yaml.load(..., Loader=cfn_safe_loader())` のみ。alias bomb 上限あり | `tests/regression/test_sec_malformed_yaml.py::test_a_python_object_tag_is_refused_and_never_evaluated`, `tests/regression/test_sec_yaml_alias_bomb.py` |
| サイズ上限 | 単一 5 MiB（`MAX_TEMPLATE_BYTES`）、集約 50 MiB（`MAX_AGGREGATE_BYTES`） | `tests/regression/`（R-8 として `docs/security-model.md` 記載） |
| Host path 漏えい | `errors.redact_stderr_line`、`report.normalize_output_path`（絶対 path 拒否） | `tests/regression/test_sec_no_host_path_in_errors.py` |
| AWS Credentials 要求 | plugin は AWS API を呼ばない（`docs/security-model.md`「AWS API Access」）。`iacreview/` に boto3 / AWS SDK import はない | `pyproject.toml` 依存が PyYAML のみ |
| Git 操作 | plugin runtime（`iacreview/`, `skills/`）は git を呼ばない。CI script のみ read-only で使用: `scan_secrets.py`（`git -C <root> ls-files -z`）、`check_ground_truth_order.py`（`rev-parse --is-inside-work-tree`, `--is-shallow-repository`, `log --diff-filter=A`） | grep 確認 |
| Secret の repository 混入 | `scan_secrets.py` 0 件（D-4） | — |
| CI 権限 | workflow top-level `permissions: contents: read`。`pull_request_target` なし、`secrets.*` 参照なし。third-party action は `actions/checkout@3d3c42e…` (# v7.0.1) と `actions/setup-python@5fda3b9…` (# v7.0.0) のみで commit SHA pin | `.github/workflows/ci.yml` |
| MCP | `mcp.json` は同梱されない（`.gitignore`）。`docs/mcp/mcp.json.example` は placeholder の stdio server 1 件のみ。`iacreview/` は network 接続しない（`docs/security-model.md`「MCP」） | `docs/mcp/README.md` |
| 自動 Remediation | `SuggestedRemediation` は文字列のみで適用コードは存在しない。file 書き込みは一時 file（`pathguard.secure_temp_file`, mode 0600）のみで v0.1 code path からは未使用と文書化 | `docs/security-model.md` R-6, `iacreview/pathguard.py` |

### E-2. Security Finding 分類

#### 確認済み Issue

なし。コード上で脆弱性と断定できる事項は確認されなかった。

#### 高い可能性のある Risk

| ID | 内容 | 根拠 |
| --- | --- | --- |
| S-1 | `--confirm-cdk-synth` 時、`cdk synth` は project code を権限そのままで実行する（文書化済み R-5）。加えて `proc.INHERITED_ENV_VARS` は `HOME` を子 process に渡すため、`AWS_*` 環境変数を除去しても `~/.aws/credentials` / `~/.aws/config` の default profile は子 process（および project code）から読める。`docs/security-model.md` の「withholds AWS credentials」は環境変数に限った保証。CDK CLI が実際に shared credentials を読み込むかの実機確認は **NOT VERIFIED** | `iacreview/proc.py` `INHERITED_ENV_VARS`、`iacreview/cdk.py` `synth_if_confirmed` |
| S-2 | v2.0 で git 操作を導入する場合、`HOME` 経由で user の global gitconfig が読み込まれ、未信頼 repository の `.git/config`（`core.fsmonitor`、diff driver、textconv、filter 等）も評価されうる。現行コードは git を呼ばないため現時点の Risk ではなく、v1.1 以降の設計上の Risk | `iacreview/proc.py`（env allowlist に `HOME`）、v1.1 提案書 |

#### 文脈依存 Recommendation

| ID | 内容 | 根拠 |
| --- | --- | --- |
| R-1 | `agentin.load_agent_findings` は `Path(path).read_text()` で読み込み、Template と違って size 上限・`O_NOFOLLOW`・inode 再確認がない（containment は呼び出し側の `resolve_within` のみ）。Agent 出力も未信頼入力とするなら、Template と同等の読み込み経路に揃える余地がある | `iacreview/agentin.py` L520-573 |
| R-2 | CI の `pip install` は `PyYAML>=6.0`, `pytest>=7.0`, `pytest-cov>=4.0` の範囲指定、`pip install --upgrade pip` は無 pin、hash 検証（`--require-hashes`）なし | `.github/workflows/ci.yml` |
| R-3 | `actions/checkout` に `persist-credentials: false` が指定されていない。`contents: read` のため影響は限定的 | `.github/workflows/ci.yml` |
| R-4 | `summary.passed_all_checks` は `errors[]` を無視する（C-3）。v2.0 の Verification 判定に流用すると Tool 不在時に誤判定しうる | `iacreview/report.py` `_summary` |

#### Informational

- `cfn-lint` / `cfn-guard` / `cdk` も sandbox なしで実行される（文書化済み R-1）。
- Agent が `Confirmed` を主張すると `Likely` に降格、`Source` に決定論 Tool を名乗ると reject（`iacreview/agentin.py`）。
- Excerpt redaction は `NoEcho` 参照と `W1011`/`W2501` のみ（R-7、key 名による推定はしない）。
- `PathContainmentError` の message は絶対 path を含むが、`path_violation` は `PARTIAL_REPORT_ERROR_CLASSES` に含まれず stdout に report を出さない（stderr のみ）。
- mypy の `attr-defined`（例外への動的属性）は型安全性の Informational。

#### NOT VERIFIED

- CI workflow の action commit SHA が記載 tag（v7.0.1 / v7.0.0）と一致するか（network 確認未実施）。
- GitHub 上の HEAD (`5e5ed36`) に対する CI の実結果。
- CDK CLI が `HOME` 経由で shared credentials を読むかの実機挙動（S-1）。
- Windows 上の挙動（コードは POSIX 前提、`docs/security-model.md` O-6 で対象外）。
- Python 3.11 / 3.13、Linux 上でのテスト結果（今回は macOS + Python 3.9.6 のみ）。
- Agent findings を含む benchmark モードの結果。
- `docs/kiro-power.md` に記載の Kiro Power 読み込み検証。
