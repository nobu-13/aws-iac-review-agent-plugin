# Phase 2 M1 — CI Integration: Test Results

* Source: ローカルの Local Acceptance（Gate 0〜13）。記録は `.agents/tasks/phase2-m1-ci/gate/`（Git 管理外）。Summary の SHA-256 `9eff7ce2935093807b5af2366c51b03e86c544ff08965858495f948ba123011d`
* 目的: CI Integration の変更をローカルで検証した結果を記録する
* 状態: **ローカルの結果だけ**。GitHub Actions は実行していない。CI 上の結果は NOT_VERIFIED。Python は `/usr/bin/python3`（3.9.6、macOS）。CI の `evidence-integrity` Job は Python 3.11（Linux）で、この組み合わせは未確認

## 1. 固定した検証対象

* 対象: `git ls-files -co --exclude-standard` から本書だけを除いた 727 files（tracked 717、新規10）。Manifest の SHA-256 `95f2d1e72834e0f5c9a3e501101dabd902ce2a95ea3eb37208a4de8bd6341256`
* 各 Gate の開始時と終了時に、Manifest、Git Status、Phase 1 の15ファイルの Hash、HEAD を照合した。14 Gate すべてで固定時と一致した
* 本書は Gate の結果を記録するため Gate の後に書いた。Source、Fixture、Definition、生成 JSON を含まない

## 2. 結果

| # | Gate | Command | exit | 結果 | 秒 |
| --- | --- | --- | --- | --- | --- |
| 0 | YAML 構文と Workflow 構成 | `pytest tests/unit/test_ci.py tests/unit/test_evidence_ci_check.py` | 0 | 147 passed（`test_ci.py` 106、検査 Script 41） | 16 |
| 1 | Full pytest + coverage | `pytest --cov=iacreview --cov=benchmark/harness --cov-fail-under=80` | 0 | 7,767件: PASS 7,731 / FAIL 0 / SKIP 36、coverage 95.10% | 722 |
| 2 | Evidence Test | `pytest tests/unit/test_evidence_*.py` | 0 | 519 passed | 40 |
| 3 | Benchmark | `run_benchmark.py --cases benchmark/cases --mode combined` | 0 | PASS、17 Case（PASS 13 / INFO 4）、matched 34 / 34、FP 0、FN 0 | 23 |
| 4 | Determinism | `PYTHONHASHSEED=random pytest tests/property/test_prop_determinism.py` | 0 | 1 passed | 30 |
| 5 | Ground Truth | `check_ground_truth_order.py` | 0 | 17 / 17 | 6 |
| 6 | Phase 1 Helper Regression | Phase 1 Helper の Test | 0 | 516 passed | 78 |
| 7a | ruff（iacreview） | `ruff check iacreview` | 1 | 5 errors（Baseline と同じ） | 7 |
| 7b | ruff（M1 と CI の新しい Path） | Evidence、Mutation、Preflight、検査 Script、`test_ci.py` | 0 | All checks passed | 6 |
| 7d | ruff（Repository 全体、CI の `lint` と同じ） | `ruff check .` | 1 | 40 errors。Baseline `dd6f629` の浅い Clone でも 40。すべて今回変更していないファイル | 6 |
| 7c | mypy | `mypy iacreview` | 1 | 12 errors（Baseline と同じ） | 7 |
| 8 | Public Preflight | `public_preflight.py` | 0 | 8 Check PASS、727 files | 9 |
| 9 | Secret Scan | `scan_secrets.py` | 0 | 0 finding、717 files（tracked mode） | 9 |
| 10 | Replay byte comparison | 同一 Process 4回、別 Process 4回、Legacy の再生成 | 0 | Native `24f091d1…2a48`（8回とも同じ）、Final Report `4b1f2c54…5b47`、Legacy `731a1846…1748` が byte 一致 | 7 |
| 11 | Mutation | `tests/mutation/evidence_mutants.py` | 0 | Baseline 39 passed、Killed 32 / 32 | 23 |
| 12 | Clean Checkout | 公開候補 727 files の複写（`.agents/`・`.kiro/` なし） | 0 | Evidence Test 514 passed / 5 skipped。新規10件に Account 名・Home Path・実 App id 0件。Quickstart の手順が期待どおり（改変後 exit 4 `SNAPSHOT_CHANGED`） | 38 |
| 13 | Evidence Job の模擬実行 | §3 | 0 | 完全な Clone で exit 0、浅い Clone で exit 13 | 72 |

Mutation の検出率は、実施した32 Mutant の集合に対する値。Clean Checkout の SKIP 5件（`.agents/` 3件、git Checkout でない1件、履歴なし1件）は PASS に数えていない。

## 3. Evidence Job の模擬実行（Gate 13）

GitHub Actions は使っていない。Job の Command を、ローカルの一時 Clone で同じ順に実行した。一時 Clone では、作業 Tree の公開候補を重ねて一時的な Commit を作った（一時 Clone の中だけ。対象の Repository には Commit していない）。

| Clone | 内容 | pytest | 検査 Script | 主な Summary の値 |
| --- | --- | --- | --- | --- |
| 完全（`fetch-depth: 0` 相当、67 Commit、`.agents/`・`.kiro/` なし） | CI の想定 | exit 0、516 passed / 3 skipped | **exit 0**（verdict: PASS for the checks this job runs） | Native `24f091d1…`、Report `4b1f2c54…`、skipped 3（Local-only の3件、理由付き）、verified commits 5、Baseline 以降の変更12件のうち Review 対象5件（`ci.yml`、検査 Script、期待値、`test_ci.py`、新しい Test） |
| 浅い（depth 1） | 履歴が足りない場合 | exit 0、515 passed / 4 skipped | **exit 13** | `BASELINE_MISMATCH`、`HISTORY_INSUFFICIENT`、`FORBIDDEN_CHANGE`（差分を列挙できない）、`REQUIRED_TEST_SKIPPED`（History 照合） |

浅い Clone では pytest 自体は exit 0 で終わる（SKIP は失敗ではない）。検査 Script がこれを FAILED に変える。これが「SKIP を PASS にしない」の実装の確認になる。

## 4. 異常系の Test（`tests/unit/test_evidence_ci_check.py`、41件）

| 指示の異常系 | Test |
| --- | --- |
| Replay Hash 不一致 | `test_a_replay_hash_mismatch_fails`、`test_an_altered_expected_hash_is_a_mismatch_not_an_update` |
| Source Hash 不一致 | `test_a_source_hash_mismatch_fails` |
| Definition Hash 不一致 | `test_a_definition_hash_mismatch_fails`、`test_an_evaluator_version_mismatch_fails` |
| Baseline Commit 不一致 | `test_a_baseline_commit_not_in_the_clone_fails`、`test_a_baseline_commit_that_is_not_an_ancestor_fails`、`test_another_baseline_commit_fails`、`test_expected_values_that_do_not_come_from_the_baseline_fail` |
| Required Test の SKIP | `test_a_skipped_required_test_fails`（4件）、`test_a_required_test_that_did_not_run_fails`、`test_an_unlisted_skip_fails` |
| History 不足 | `test_missing_history_fails` |
| Expected JSON 改変 | `test_an_altered_expected_file_is_refused`（6件）、`test_an_altered_expected_hash_is_a_mismatch_not_an_update` |
| 許可されない File 変更 | `test_a_change_to_a_phase1_original_fails`、`test_a_tracked_private_path_fails`（2件）、`test_an_unlistable_diff_fails` |
| 検査 Script の異常終了 | `test_bad_arguments_and_unreadable_inputs_exit_2`、`test_an_unexpected_exception_exits_2_not_0` |
| Network 不要の Replay | `test_the_replay_needs_no_network` |

その他: Final Report と Legacy 結果の不一致、Test の失敗、空の JUnit、Local-only の SKIP が NOT_VERIFIED になり PASS と書かれないこと、Review 対象の Path の列挙、期待値ファイルが Version Policy §4 の Baseline と一致すること、検査 Script の合成 Spec が Pipeline Test の Spec と同じ bytes を出すこと、終了 Code が互いに異なること。

## 5. NOT_VERIFIED

* GitHub Actions 上のすべての Job の結果
* Linux と Python 3.11 / 3.13 での Evidence Test と Replay の bytes
* PR の Merge Commit 上での検査 Script の結果
