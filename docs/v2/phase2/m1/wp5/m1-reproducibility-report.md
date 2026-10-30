# Phase 2 / M1 — Reproducibility Report（M1-05、WP5-4、WP5-7）

> **Pre-Commit Remediation の注記（後から追加）**: 本書の Hash と実測値（Evaluator Source `dfaec952…`、Definition `efd934b0…`、固定 Manifest `360d731b…`、Replay `4dc16d9b…`、Final Report `27eecd68…`、Legacy 結果 `f205b5d4…`、Mutant 29件など）は Pre-Commit Remediation の前の値で、最終 Source では再現しない。`docs/v2/phase2/m1/wp5/legacy-reevaluation-results.json` は最終 Source から再生成し直した。WP4 の結果ファイルは公開対象から外した。最終の値は `docs/v2/phase2/m1/precommit/remediation-report.md` を参照する。

* Source: `iacreview/evidence/canonical.py`、`replay.py`（`--expect`）、`final_report.py`、`tests/unit/test_evidence_pipeline.py`、Final Frozen Quality Gate attempt 4 の Gate 10
* 目的: 最終 Source を固定した後に、同じ入力から同じ bytes が出ること、変更や欠損で Replay が拒否されることを示す
* 状態: 実施済み。Git Commit なし。**正式な Hash は固定後（attempt 4）の値だけ**。WP4 の値（`2e52bc1c…`）と固定前の値は参考扱い
* 範囲: 合成 Raw だけ。実 GitHub Raw による End-to-End は NOT_PROVEN（`github-e2e-verification-plan.md`、未実行）

## 1. 固定した検証対象

| 項目 | 値 |
| --- | --- |
| 固定範囲 | `git ls-files -co --exclude-standard` のうち `docs/v2/phase2/m1/wp5/*.md` を除く 703 ファイル |
| Manifest の SHA-256 | `360d731b5b10a30e231bbf01ae76b50055698c7ab9bf15d934ec042bba18aec5` |
| Evaluator Source の SHA-256（`evaluator_source_sha256()`） | `dfaec9527be9861ac3fe4ee85e7c8000cd82259af0b92220f2375db8fe6cdbf8` |
| Definition の SHA-256（v1） | `efd934b0badd8cbdc50ec13fcc0be4dec0e501ad26bf0507f546dd6d36e28589` |
| HEAD | `4bd6e015d88b01d34dc83dc2b2d2ffb0058358b2`（固定範囲の大半は未追跡ファイル） |

`docs/v2/phase2/m1/wp5/*.md` を除いたのは、これらの文書が Gate の結果を記録するため、Gate の後に書くから。除いた文書は Source、Fixture、Definition、生成 JSON を含まない。文書を書いた後に、文書を対象とする検査（Public Preflight、Secret Scan、Docs Test）を再実行した（`wp5-acceptance-report.md` §6）。

各 Gate の開始時と終了時に Manifest、`git status --porcelain --untracked-files=all`（同じ除外）、Phase 1 の15ファイルの Hash、HEAD を照合した。attempt 4 の12 Gate すべてで、開始時・終了時とも固定時の値と一致した。

## 2. Native Replay（Gate 10）

合成 Store（G0、G1、G2、G3（Impostor required）、G3S、G6、G11（Artifact 付き））を別々の一時 Directory（a、b）に作り、それぞれで実行した。

| 実行 | 回数 | exit | 結果の SHA-256 |
| --- | --- | --- | --- |
| 同一 Process `replay.replay(spec)` | a 2回、b 2回 | — | `4dc16d9bdc364f6b40213816d7e0547f2d807888d4e41ac61541818e5e8be6a4`（4回とも同じ） |
| 別 Process `python3 -m iacreview.evidence.replay spec.json --expect expected.json`、`PYTHONHASHSEED=random` | a 2回、b 2回 | 0（4回） | 同上（4回とも同じ） |
| Final Report `final_report.report_bytes` | a 2回、b 2回 | — | `27eecd686231c787338ade7c4ce568084675d4ec4017d78e22cd467329816d1a`（4回とも同じ） |

結果は 47,915 bytes。WP4 の結果（43,830 bytes、`2e52bc1c…`）と違うのは、WP5 で `open_questions`（S7-19）を追加し、Evaluator Source と Definition の Hash が変わったため。

## 3. Legacy Derived Re-evaluation（Gate 10）

| 項目 | 値 |
| --- | --- |
| ファイル | `docs/v2/phase2/m1/wp5/legacy-reevaluation-results.json`（112,316 bytes） |
| ファイルの SHA-256 | `f205b5d4e9b1d8b91c8c35869dec7972d918215cefebbdc17d24590ad9bb70ed` |
| 再生成した bytes の SHA-256 | `f205b5d4e9b1d8b91c8c35869dec7972d918215cefebbdc17d24590ad9bb70ed`（byte 一致: true） |

WP4 のファイル（`docs/v2/phase2/m1/wp4/legacy-reevaluation-results.json`、`b17e6881…29f7d544`）は WP4 の記録として残した。Evaluator Source が変わったため、現在の Source では再現しない。これは `SOURCE_CHANGED` として拒否される想定どおりの挙動。

## 4. Clean Checkout での Replay（Gate 12）

公開候補のファイル（706 files、`.agents/` と `.kiro/` なし）を新しい Directory に複写し、Quickstart の手順をそのまま実行した。

| 手順 | 結果 |
| --- | --- |
| 合成 Spec の生成 | exit 0 |
| Replay | exit 0、結果 SHA-256 `f13701773fc907f8881ce0baaa0c9a0adf6d5b63c5279a2f1b8b1ab00cfb34a4` |
| Final Report | exit 0、SHA-256 `623a401c6983973716de6fd7dbe29dc53989cae4b66fc8c35c37901b6acc10b7` |
| `diagnose()` | `store_valid: true`、unusable 0件 |
| `--expect` で再実行 | exit 0 |
| Raw を1つ変えて `--expect` | exit 4、`SNAPSHOT_CHANGED` |

Clean Checkout の Scenario は G1、G2、G3 の3つで、§2 とは入力が違うため Hash も違う。

## 5. 拒否の確認（Test、Gate 1 と Gate 2 で PASS）

| 条件 | 期待 | Test |
| --- | --- | --- |
| 同一入力 | 結果と Report が byte 一致 | `test_the_same_input_gives_identical_result_and_report_bytes` |
| 別 Process | `--expect` で exit 0、stdout が一致。Final Report も一致 | `test_a_separate_process_reproduces_the_result_and_the_report` |
| Replay 前の Raw の Hash 不一致 | `SNAPSHOT_CHANGED`。該当 Group は FAILED、Scenario は PASS にならない | `test_a_raw_hash_mismatch_before_the_replay_is_refused` |
| Snapshot 後の Raw 変更 | `SnapshotDrift` | `test_a_raw_hash_mismatch_after_the_snapshot_is_refused` |
| Source の変更（Package を複写し1行追加） | exit 4、`SOURCE_CHANGED`、stdout 空 | `test_a_source_change_is_refused` |
| Definition の変更 | `DEFINITION_CHANGED`。Evaluator も Hash の違う Definition を拒否 | `test_a_definition_change_is_refused` |
| Evidence の欠損（Raw の削除） | `SNAPSHOT_CHANGED`。G1 は NOT_PROVEN | `test_missing_evidence_is_refused_and_never_pass` |
| Incomplete Revision（Seal されない Revision） | `SNAPSHOT_CHANGED`。Binding 0件、PASS の Scenario 0件 | `test_an_incomplete_revision_is_refused` |
| 未実装 Rule | `rule_not_implemented` の NOT_PROVEN、Scenario は PASS にならない、Report は `rules_implemented: NOT_PROVEN` | `test_an_unimplemented_rule_never_passes` |
| Network なし | `socket`、`create_connection`、`getaddrinfo` を禁止しても Replay と Report が完了 | `test_the_replay_and_the_report_complete_without_network` |

## 6. 固定前の失敗と再実行

| attempt | 結果 | 原因と対処 |
| --- | --- | --- |
| 1 | Gate 1 FAIL（coverage 54.30%、Test は 7,649 PASS / 36 SKIP） | 原因分類: Test Bug。`test_a_source_change_is_refused` の子 Process が pytest-cov の環境変数を引き継ぎ、複写した Package を計測した。子 Process の環境から `COV_CORE_SOURCE` を外した。Test の Assertion は変えていない |
| 2 | 12 Gate すべて期待どおり | 採用せず。WP0 固定 Mutant の不足（`m1-security-regression.md` §3）に気づき、Mutant を追加したため |
| 3 | 12 Gate すべて期待どおり | 採用せず。WP0 MU-05 / MU-06 の個別 Mutant を追加したため |
| 4 | 12 Gate すべて期待どおり、固定状態の変化なし | **採用** |

attempt 1〜3 の Summary は `.agents/tasks/phase2-m1-wp5/` に残した（Git 管理外）。

## 7. 判定

* M1-05（合成 Raw）: **PASS**
* M1-05（実 GitHub Raw の End-to-End）: **NOT_PROVEN**
* M1-05 ③（CI の複数 Python Version）: **NOT_VERIFIED**（CI を実行していない。ローカルは Python 3.9.6 だけ）
* 第三者による独立再現: **NOT_PROVEN**
