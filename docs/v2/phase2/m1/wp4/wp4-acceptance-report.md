# Phase 2 / M1 / WP4 — Acceptance Report

> **Pre-Commit Remediation の注記（後から追加）**: 本書が参照する `docs/v2/phase2/m1/wp4/legacy-reevaluation-results.json`（SHA-256 `b17e6881…29f7d544`、最初の版 `15b866b8…` を含む）は公開対象から外し、非公開の作業領域に保全した。この結果は WP4 時点の Evaluator Source と Definition で作ったもので、現在の Source では再現できない。本書の Hash・件数・判定は WP4 時点の記録であり、現在の判定の根拠にしない。最終の値は `docs/v2/phase2/m1/precommit/remediation-report.md` を参照する。

* Source: WP4 指示（WP4-1〜WP4-6）、`docs/v2/phase2/m1/wp0/m1-acceptance-test-matrix.md`（M1-02、M1-03、M1-05、M1-12）
* 目的: WP4 の Acceptance 条件を、実行した Command と Test の結果で判定する
* 状態: 実施済み。**Git Commit なし**（HEAD `4bd6e015d88b01d34dc83dc2b2d2ffb0058358b2`）。GitHub API の呼び出しなし、CI 変更なし、Dependency 追加なし。Human レビュー待ち

## 1. 判定

| AC | 判定 | 根拠 |
| --- | --- | --- |
| M1-03 Mutation Detection | **PASS** | 12 / 12 Killed（`mutation-test-results.md`） |
| M1-05 Deterministic Replay | **PASS（合成 Raw の範囲）** | 同一 Process 4回・別 Process（`PYTHONHASHSEED=random`）4回で SHA-256 が一致、Drift 9種を拒否、Network 不使用（`replay-reproducibility-report.md`） |
| M1-05 — 実際の GitHub Raw による End-to-End | **NOT_PROVEN** | Phase 2 で実 Raw を未取得。Phase 1 には Raw がない |
| M1-02 Alignment（§7 Criterion と Rule の対応） | **PASS（S7-19 を除く）** | 26 Criterion 中 25 の rule_behaviour Test が IMPLEMENTED。S7-19 は PLANNED（WP5）で、評価では `rule_not_implemented` の NOT_PROVEN（`evaluator-rule-coverage.md`） |
| M1-12 Historical Regression | **PASS** | Phase 1 の Helper・Evidence・rev2 / rev3 文書の SHA-256 が記録値と一致。再評価は別 Artifact（`legacy-reevaluation-differences.md`） |

## 2. 必須の挙動

| 挙動 | 結果 | 根拠 |
| --- | --- | --- |
| G3 / G3S / G6 で `isRequired = true` の Impostor があると Required Criterion が FAILED | 確認 | Native 合成 G3: `required_check = FAILED`、`merge_blocking = PASS`、`s7_result = FAILED`（`test_native_replay_judges_the_synthetic_scenarios`）。Legacy E18〜E21 の G3 / G3S / G6 も同じ |
| Merge Blocking の PASS で相殺しない | 確認 | 上記。S7-02 の合成は FAILED 優先（`test_s7_compose_all_parts`） |
| App の失敗が BLOCKED を説明するとき Issuer Pinning 独立証明は NOT_PROVEN | 確認 | P2-IP-01 `app_failure_explains_block`（`test_phase2_issuer_pinning_independent_proof`、MU-03） |
| 欠損 Evidence は NOT_PROVEN | 確認 | `MISSING` は NOT_PROVEN（MU-04）。検証に失敗した Group は Binding されず NOT_PROVEN（`test_a_group_that_fails_validation_is_not_bound`） |
| 未実装 Rule は PASS にならない | 確認 | `not_implemented_rules == ["s7.open_questions.recorded"]`、該当 Criterion は `rule_not_implemented` |
| 3 Mode の分離 | 確認 | `wp4-architecture-note.md` §3。Historical Reference は `used_by_rules: false`（MU-12） |

## 3. 実行した Command と結果

Python は `/usr/bin/python3`（3.9.6、PyYAML 6.0.3、pytest 8.3.4）。pytest は `PYTHONDONTWRITEBYTECODE=1`、`-p no:cacheprovider` で実行した。

| Gate | Command | exit | 結果 | 所要時間 |
| --- | --- | --- | --- | --- |
| Evidence Unit Test | `pytest tests/unit/test_evidence_*.py` | 0 | 429 passed、0 failed、0 skipped | 14秒 |
| Mutation | `python3 tests/mutation/evidence_mutants.py --json /tmp/wp4_mut.json` | 0 | Baseline 10 passed、Killed 12 / 12 | 5.85秒 |
| pytest + coverage（全体） | `pytest -q --cov=iacreview --cov=benchmark/harness --cov-fail-under=80`（`HYPOTHESIS_STORAGE_DIRECTORY`、`COVERAGE_FILE` は `/tmp`） | 0 | 7,665件: PASS 7,629、FAIL 0、SKIP 36。coverage 95.03% | 695秒 |
| Benchmark | `python3 benchmark/harness/run_benchmark.py --cases benchmark/cases --mode combined` | 0 | status PASS、17 Case（PASS 13、INFO 4）、matched 34 / 34、FP 0、FN 0、errors 0 | 18秒 |
| Determinism | `PYTHONHASHSEED=random pytest tests/property/test_prop_determinism.py` | 0 | 1 passed | 24秒 |
| Ground_Truth 順序 | `python3 .github/scripts/check_ground_truth_order.py --cases benchmark/cases` | 0 | 17 / 17 verified | — |
| Secret scan | `python3 .github/scripts/scan_secrets.py` | 0 | 0 finding（633 files、tracked mode） | — |
| Public preflight | `python3 .github/scripts/public_preflight.py` | 0 | 8 check すべて PASS、698 files（tracked と untracked。本書の追加後に再実行した値） | — |
| Phase 1 Helper Test | `cd .agents/tasks/phase1/henv && pytest --rootdir=. test_phase1_*.py` | 0 | 516 passed | 72秒 |
| ruff（Advisory） | `ruff check --no-cache iacreview` / WP4 の新規 Path | 1 / 0 | 5件（Baseline と同じ）/ All checks passed | — |
| mypy（Advisory） | `mypy --cache-dir=/tmp/wp4_mypy iacreview` | 1 | 12 errors in 7 files（Baseline と同じ）。`iacreview/evidence` は 0件 | — |

全体 pytest の件数は、`-q` 出力の進捗文字（`.` 7,629、`s` 36、`F` / `E` 0）を数えた値。終了行の集計は出力に含まれなかった。

WP4 Module の coverage（全体 pytest の Report）: `canonical.py` 95%、`snapshot.py` 94%、`facts.py` 90%、`rules_s7.py` 91%、`evaluator.py` 96%、`replay.py` 96%、`legacy_reeval.py` 54%（CLI の `main` と実 Phase 1 ファイルに依存する経路）。

### 実行中に起きた失敗と対処

* `test_evidence_legacy_reeval.py::test_the_committed_results_are_reproduced_byte_for_byte` が FAIL した（Evidence Test と `test_docs.py` をまとめて実行したとき）
* 原因分類: Implementation（生成物の古さ）。`legacy-reevaluation-results.json` を生成した後に `evaluator.py` を編集したため、結果に記録した `evaluator.source_sha256` が現在のソースと一致しなくなった
* 対処: 旧ファイルを削除し、CLI で再生成した（新 SHA-256 `b17e6881…29f7d544`）。旧版との違いは4件の `evaluator.source_sha256` だけで、判定結果は同一（JSON 比較で確認）。Test と Rule は変更していない
* 全体 pytest は再生成の前に開始した（再生成は進捗約17%の時点）。再生成後に Evidence Test 429件を再実行し、すべて PASS した

## 4. 既存 Test の期待値変更

`tests/unit/test_evidence_registry.py` と `tests/unit/test_evidence_s7_definition.py` の期待値を WP4 の状態（20 Rule が IMPLEMENTED、PLANNED の例は S7-19）に合わせて変更した。WP1 時点の Test の期待値変更は WP2、WP3 に続き3回目。Phase 1 の Test と WP4 以前の製品 Test（`tests/unit/test_evidence_*` 以外）は変更していない。

## 5. Phase 1 の不変性

SHA-256 の先頭8桁で、記録値と現在値を照合した（14ファイルすべて一致）。

* Helper: `phase1_appdemo.py` `493177b4`、`phase1_henv.py` `26b497e0`、`phase1_henv_owner.py` `47682fb1`
* E18 / E19: `a1296349`
* rev3: `52b3f803`、`c472d86c`、`bc6d4720`、`fe095ad2`
* rev2: `a78895c4`、`6f1ef692`、`07216f60`、`fabcf596`、`facc1da1`
* github-evidence: `e7e4c342`

Legacy Evidence Map の全件照合（`legacy.current_state`）: 130行（MATCH 122、HISTORICAL_MATCH 8）、changed 0、missing 0。

## 6. 実行していない項目

| 項目 | 状態 | 理由 |
| --- | --- | --- |
| 実 GitHub Raw の取得と End-to-End Replay | NOT_VERIFIED | WP4 の範囲外。GitHub API を呼ばない制約 |
| CI 上の結果 | NOT_VERIFIED | Push しない。ローカル結果だけ |
| Collector、Secret Gate、Integrity Validator の Mutation Test | NOT_VERIFIED | WP4 の MU-01〜MU-12 の範囲外 |
| 実 Job Log の取り込み | NOT_VERIFIED | Secret Gate の誤検知 FP-1 の見込み。規則変更は Human 決定 H-1〜H-4 |
| S7-19 の Rule | 未実装（WP5） | 計画どおり |
