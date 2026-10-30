# Phase 2 M1 — CI Integration: Implementation Report

* Source: `docs/v2/phase2/m1/ci-readiness/`（承認済みの設計）、`.github/workflows/ci.yml`、`.github/scripts/evidence_ci_check.py`、`tests/fixtures/evidence_replay/expected.json`、`tests/unit/test_ci.py`、`tests/unit/test_evidence_ci_check.py`
* 目的: M1 Evidence Integrity Foundation を GitHub Actions で検証するための変更を記録する
* 状態: ローカルで実装・検証した。**GitHub Actions では一度も実行していない**（CI 上の結果は NOT_VERIFIED）。Push、PR、Merge、GitHub API アクセス、Repository 設定の変更はしていない

## 1. 変更・追加ファイル

| ファイル | 種別 | 内容 |
| --- | --- | --- |
| `.github/workflows/ci.yml` | 変更 | Job `evidence-integrity` を追加。`repository-hygiene` に Public Preflight の Step を追加。冒頭の Comment に Gate 5、6 を追記。既存の Job、Matrix（6組）、Step、Trigger、権限は変えていない |
| `.github/scripts/evidence_ci_check.py` | 新規 | Evidence Gate の検査 Script（標準ライブラリと Plugin のみ） |
| `tests/fixtures/evidence_replay/expected.json` | 新規 | 承認済み Baseline の期待値 |
| `tests/unit/test_evidence_ci_check.py` | 新規 | 検査 Script の Test（41件） |
| `tests/unit/test_ci.py` | 変更 | `GATE_JOBS` に `evidence-integrity` を追加（既存 Test の期待値変更）。新 Job と Preflight の Step を検査する Test を8件追加 |
| `docs/v2/phase2/m1/ci-readiness/` の4文書 | 追加（前回作成、未 Commit） | CI Readiness Audit。公開安全性を確認して Commit 候補に含める |
| `docs/v2/phase2/m1/ci-integration/` の4文書 | 新規 | 本書を含む |

変更していないもの: `iacreview/` の Source（Evaluator Source の SHA-256 は Baseline の `ee765e0c…` のまま）、Definition v1、Phase 1 の原本・Helper・Evidence・旧 Test、`pyproject.toml`、Dependency。

## 2. CI Job の構成

| Job | 変更 | 内容 |
| --- | --- | --- |
| `test`（6組） | なし | 全 pytest（M1 の Test を含む）と Benchmark |
| `determinism` | なし | — |
| `repository-hygiene` | Step を1つ追加 | Secret Scan、Ground Truth の順序、**Public Preflight** |
| `evidence-integrity` | 新規 | 下表 |
| `lint` | なし | Advisory のまま |

`evidence-integrity` の Step:

| Step | 内容 |
| --- | --- |
| Checkout | `actions/checkout`（SHA 固定、v7.0.1）、`fetch-depth: 0`、`persist-credentials: false` |
| Set up Python | `actions/setup-python`（SHA 固定、v7.0.0）、Python 3.11、Cache なし |
| Install pytest | `python3 -m pip install "${PYTEST_SPEC}"` だけ（既存の Workflow 変数）。PyYAML、hypothesis、cfn-lint は入れない |
| Run the evidence tests | `pytest -p no:cacheprovider -rs --junitxml="${RUNNER_TEMP}/evidence-junit.xml" tests/unit/test_evidence_*.py` |
| Check skips, replay hashes and the baseline | `if: ${{ always() }}` で `evidence_ci_check.py` を実行。Test の Step が失敗しても Summary を書く。Job の失敗は取り消さない（`continue-on-error` なし） |

Workflow の権限は `contents: read` のまま（Job の上書きなし）。Secret、Cache、Artifact、`pull_request_target`、`workflow_run` は使わない。

## 3. 指示された8つの検査と実装の対応

| 検査 | 実装 |
| --- | --- |
| 1. Registry / Definition Validation | Evidence Test（`test_evidence_registry.py`、`test_evidence_s7_definition.py`、`test_evidence_rule_outcomes.py`）と、Script の `check_source_and_definition`（`replay.load_definition()` が Registry の検証を通す） |
| 2. Evidence Unit Tests | `tests/unit/test_evidence_*.py`（ローカルで 519件） |
| 3. 32 Mutation Tests | `test_evidence_mutations.py`（Evidence Test の一部、必須） |
| 4. Offline Replay | Script の `check_replay`: 同一 Process 2回（Socket 禁止）、`PYTHONHASHSEED=random` の別 Process 2回（`replay --expect`） |
| 5. Final Report Hash Verification | 同上の Final Report の SHA-256 を期待値と照合 |
| 6. Source / Definition Hash Verification | 現在の Evaluator Source と Definition（id、version、SHA-256）、Evaluator Version を期待値と照合。さらに Baseline Commit の Source と Definition が期待値に Hash されることを照合（`check_baseline`） |
| 7. History 照合 | 必須 Test `test_every_historical_clause_occurs_once_at_every_verified_commit` と、Script の `check_history`（検証済み Commit 5件の存在） |
| 8. SKIP 分類と Gate 判定 | Script の `check_junit`（§4） |

## 4. SKIP の分類

| 分類 | 対象 | 扱い |
| --- | --- | --- |
| Required（ファイル単位） | `test_evidence_registry.py`、`test_evidence_s7_definition.py`、`test_evidence_rule_outcomes.py`、`test_evidence_replay.py`、`test_evidence_pipeline.py`、`test_evidence_report.py`、`test_evidence_mutations.py` の全 Test | 1件でも SKIP、または1件も実行されない → exit 19 |
| Required（個別） | History 照合、Public Preflight の Test（`test_this_repository_public_set_passes_the_preflight`）、Mutation の2件、`test_the_shipped_definition_agrees_with_the_reachable_outcomes` | SKIP または未実行 → exit 19 |
| Local-only | `.agents/` を必要とする3件（`test_every_phase1_source_is_unchanged_since_the_map_was_made`、`test_the_committed_results_are_reproduced_byte_for_byte`、`test_the_phase1_sources_are_unchanged_by_the_reevaluation`） | Job は失敗させない。Summary の「Local-only tests (NOT_VERIFIED in CI)」と、AC 表の M1-10 / M1-12 の行に NOT_VERIFIED (CI) と理由を書く |
| それ以外の SKIP | 上のどれにも当たらない Evidence Test の SKIP | exit 19（想定外の SKIP） |

Summary の先頭に「this is not a PASS of M1 as a whole」と書き、Local-only と常に NOT_PROVEN の項目を必ず列挙する。

## 5. Expected Hash の管理

`tests/fixtures/evidence_replay/expected.json` の値（Version Policy §4 の初回 Baseline と同じ）:

| Key | 値 |
| --- | --- |
| `baseline_commit` | `dd6f6295272834175b1eb0eb10ddf23dffc46fed` |
| `evaluator_version` | `iacreview.evidence.evaluator/1` |
| `evaluator_source_sha256` | `ee765e0c18ba76b9d4a27a0d4277548f21296757f03a77879763d1824dae58d6` |
| `definition_id` / `definition_version` | `phase1-app-demo-s7` / 1 |
| `definition_sha256` | `fb4ddef0b86d36e436e4492e1ff2d209812e80b6e993dea47ba07dc7a856b1d0` |
| `native_result_sha256` | `24f091d1f8be65603a4d5d2cd62052758295155e00be200b59a8ff45238a2a48` |
| `final_report_sha256` | `4b1f2c5441ea9a421bdb0b8d402a608acbf96ced7f128d30f443939746f55b47` |
| `legacy_result_sha256` | `731a1846ce5bb6102bea478fbc613b85ccb6b3cf90fc736dd62b8bbeaa8e1748` |

規則:

* Script は期待値を読むだけで、書き換えない（`test_an_altered_expected_hash_is_a_mismatch_not_an_update`）。CI の実行中に現在の出力から期待値を更新する経路はない
* Key の集合、形式（SHA-256、40桁の Commit、安全な相対 Path）を厳密に検査し、違えば exit 10
* 評価対象の Commit が Baseline と違うのは正常。PR の Merge Commit（`refs/pull/<n>/merge`）でも、Baseline Commit が HEAD の祖先であればよい（`git merge-base --is-ancestor`）
* 期待値が Baseline に由来することを、Baseline Commit の Evaluator Source と Definition を `git cat-file` で読み、Hash して確かめる。現在の Source が期待値と一致すれば、評価対象の Source は Baseline と同じ
* 期待値の変更は Human Review の対象。変更した Commit では、Summary の「Changed since the baseline, review required」に `tests/fixtures/evidence_replay/expected.json` が出る
* 限界: PR が Evaluator、`expected.json`、`baseline_commit` を同時に変え、`baseline_commit` を PR 自身の Commit に向ければ、Script の検査は通る。この回避は CI の内側では防げない（`ci-security-acceptance.md` §2）

## 6. 終了 Code

| Code | 名前 | 条件 |
| --- | --- | --- |
| 0 | OK | すべて一致、想定外の SKIP なし |
| 2 | CHECK_ERROR | 引数の誤り、入力の読み込み失敗、Script 内の予期しない例外 |
| 10 | EXPECTED_INVALID | 期待値ファイルの形式違反 |
| 11 | SOURCE_MISMATCH | Evaluator Source の SHA-256 の不一致 |
| 12 | DEFINITION_MISMATCH | Definition、Evaluator Version の不一致、Definition の検証失敗 |
| 13 | BASELINE_MISMATCH | Baseline Commit がない、祖先でない、またはその Source / Definition が期待値に Hash されない |
| 14 | HISTORY_INSUFFICIENT | 検証済み Commit が Clone にない |
| 15 | REPLAY_MISMATCH | Native Replay の不一致、別 Process の Replay が非ゼロ終了 |
| 16 | REPORT_MISMATCH | Final Report の不一致 |
| 17 | LEGACY_RESULT_MISMATCH | Commit された Legacy 結果の Hash、または中の Source / Definition の Hash の不一致 |
| 18 | FORBIDDEN_CHANGE | Baseline 以降に `docs/v2/phase1/`、`.agents/`、`.kiro/` が変わった |
| 19 | REQUIRED_TEST_SKIPPED | Required の SKIP / 未実行、想定外の SKIP |
| 20 | TEST_FAILURES | JUnit の failure / error、または Test が0件 |

すべての検査を実行し、失敗した検査のうち表の順で最初のものの Code を返す。失敗の一覧は Summary に出す。

## 7. 既存 Test の期待値変更

* `tests/unit/test_ci.py`: `GATE_JOBS` に `evidence-integrity` を追加。これで既存の Gate 共通 Test（`continue-on-error` なし、失敗を握りつぶす断片なし、Action の SHA 固定など）が新 Job にも適用される。既存 Test の Assertion は緩めていない
