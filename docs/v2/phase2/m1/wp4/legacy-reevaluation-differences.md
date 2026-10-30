# Phase 2 / M1 / WP4 — Legacy Re-evaluation Differences（M1-12）

> **Pre-Commit Remediation の注記（後から追加）**: 本書が参照する `docs/v2/phase2/m1/wp4/legacy-reevaluation-results.json`（SHA-256 `b17e6881…29f7d544`、最初の版 `15b866b8…` を含む）は公開対象から外し、非公開の作業領域に保全した。この結果は WP4 時点の Evaluator Source と Definition で作ったもので、現在の Source では再現できない。本書の Hash・件数・判定は WP4 時点の記録であり、現在の判定の根拠にしない。最終の値は `docs/v2/phase2/m1/precommit/remediation-report.md` を参照する。

* Source: `docs/v2/phase2/m1/wp4/legacy-reevaluation-results.json`（本 WP の新規 Artifact）、Legacy Evidence Map（WP3）、Phase 1 rev2 / rev3 の結果（Definition の `historical_classification` に引用済み）、helper の `app-evidence` ファイルの `classification` 欄
* 目的: Phase 1 helper の Evidence（E18〜E21）を WP4 の Evaluator で再評価した結果と、Phase 1 の結果・helper が保存した分類との違いを、理由とともに記録する
* 状態: 実施済み・Git Commit なし
* **Phase 1 の結果は変更しない**。本書と JSON は別の Artifact で、Phase 1 の結果を置き換えない

## 1. 3つの値の区別

| 値 | Mode | 出所 | Rule が使うか |
| --- | --- | --- | --- |
| 再評価結果 | `LEGACY_DERIVED_REEVALUATION` | WP4 の `rules_s7` を helper の転記 Fact に適用 | — |
| Phase 1 の結果 | `HISTORICAL_CLASSIFICATION_REFERENCE` | Legacy Map の subject（rev2 / rev3 からの引用） | 使わない（`used_by_rules: false`） |
| helper が保存した分類 | 参考（JSON には含めない） | 各 `app-evidence` ファイルの `classification`（status / outcome） | 使わない |

再評価の入力は helper が転記した Field で、当時の GitHub 応答そのものではない。このため全件で `capture_integrity.status = NOT_PROVEN`（`RAW_UNAVAILABLE`）とした。

## 2. 入力と出力

* 入力: E18、E19、E20、E21（`.agents/tasks/phase1/henv/out/app-demo-2/` の `app-evidence` 4ファイル）、E09 `app-w0-views.json`、E17 Report Artifact。各ファイルを Legacy Map の SHA-256 と照合し、一致しなければ `LegacyDrift` で拒否（`test_a_legacy_file_that_differs_from_the_map_is_refused`）
* Binding した Evidence 数: E18 13、E19 13、E20 12、E21 12
* 出力: `legacy-reevaluation-results.json`、88,410 bytes、SHA-256 `b17e6881d20e27987da62716595629212afcdcf0529d9f313e26474a29f7d544`。`O_EXCL` で作成（上書きしない。既存ファイルへの再出力は exit 2 で拒否）。再実行で byte 一致（`test_the_committed_results_are_reproduced_byte_for_byte`）
* 再生成の記録: 最初の出力（SHA-256 `15b866b8…59e2df`）の後に `evaluator.py` を編集したため、結果に含まれる `evaluator.source_sha256` が現在のソースと合わなくなり、上記 Test が FAIL した。旧ファイルを削除して再生成した。旧版と新版の違いは4件の `evaluator.source_sha256` だけで、判定結果を含む他の内容は同一（JSON 比較で確認）
* Phase 1 の入力ファイルは再評価の前後で変わらない（`test_the_phase1_sources_are_unchanged_by_the_reevaluation`）

## 3. 再評価結果

`s7` = `s7_result`、`p2` = `phase2_result`。

| Scenario | E18 s7 / p2 | E19 s7 / p2 | E20 s7 / p2 | E21 s7 / p2 |
| --- | --- | --- | --- | --- |
| G0 | PASS / PASS | PASS / PASS | PASS / PASS | PASS / PASS |
| G1 | PASS / PASS | PASS / PASS | PASS / PASS | PASS / PASS |
| G2 | PASS / PASS | PASS / PASS | PASS / PASS | PASS / PASS |
| G3 | FAILED / FAILED | FAILED / FAILED | FAILED / FAILED | FAILED / FAILED |
| G3S | FAILED / FAILED | FAILED / FAILED | FAILED / FAILED | FAILED / FAILED |
| G4 | PASS / PASS | PASS / PASS | PASS / PASS | PASS / PASS |
| G5 | PASS / PASS | PASS / PASS | PASS / PASS | PASS / PASS |
| G6 | FAILED / FAILED | FAILED / FAILED | FAILED / FAILED | FAILED / FAILED |
| G9 | PASS / PASS | PASS / PASS | PASS / PASS | PASS / PASS |
| G10 | PASS / PASS | PASS / PASS | PASS / PASS | PASS / PASS |
| G11 | PASS / NOT_PROVEN | PASS / NOT_PROVEN | NOT_PROVEN / NOT_PROVEN | NOT_PROVEN / NOT_PROVEN |

Limit は4ファイルとも同じ: G8 `needs_a_merge`、AC28 `needs_a_write_only_second_account`、admin_bypass `needs_a_merge_attempt`、same_app_with_key `limit_same_app_with_key`（いずれも S7-18 で NOT_PROVEN）、G7 `scenario_not_run`。

### G3 / G3S / G6 の軸（4ファイルで同じ）

| 軸 | 結果 | 理由 |
| --- | --- | --- |
| required_check | **FAILED** | S7-08、S7-14a、S7-15、S6-G* がいずれも `impostor_is_required` |
| merge_blocking | PASS | S7-10 `blocked`、S7-14b `blocked` |
| issuer_pinning_independent_proof | **NOT_PROVEN** | P2-IP-01 `app_failure_explains_block`（同じ head の App 失敗が BLOCKED を説明する） |
| gate_provenance、app_check_provenance | PASS | S7-03〜S7-07 |

Merge Blocking の PASS は Required Check の FAILED を相殺しない（S7-02）。

### G11

* E18 / E19: §7 の Part（gate、app_check、required、steal）はすべて PASS で `s7_result = PASS`。`g11_environment_boundary` 軸は S7-17（Limit）を含むため NOT_PROVEN。`artifact_integrity` 軸は Artifact Evidence を渡していないため NOT_PROVEN。よって `phase2_result = NOT_PROVEN`
* E20 / E21: 当時 G11 の PR がなく、全軸 NOT_PROVEN

## 4. Phase 1 の結果との差分

`historical_classification_reference.comparisons` の内容。

| Evidence | Scenario | Phase 1 | 再評価 s7 | 再評価 p2 | `differs`（s7） | `differs_phase2` |
| --- | --- | --- | --- | --- | --- | --- |
| E18、E19 | G3 / G3S / G6 | FAILED | FAILED | FAILED | false | false |
| E18、E19 | G11 | NOT_PROVEN | **PASS** | NOT_PROVEN | **true** | false |
| E20、E21 | G3 / G3S / G6 | FAILED | FAILED | FAILED | false | false |
| E20、E21 | G11 | NOT_PROVEN | NOT_PROVEN | NOT_PROVEN | false | false |

G11 の差分の理由: §7 には Artifact の条項がないため、§7 だけで評価すると PASS になる。Phase 1 は、観測した `steal.yml` が監査済みの版から変わっていた（`cef683fb`）ことを理由に G11 を NOT_PROVEN へ取り消した（rev2 §3-3）。この理由は Phase 2 では Artifact Integrity（P2-AI-01 / 02）の軸にあたる。`phase2_result` は NOT_PROVEN で Phase 1 と一致する。Phase 1 の結果は変更しない。

## 5. helper が保存した分類との差分

helper の `classification`（status / outcome）は Phase 1 の最終結果ではない。参考として比較する。

| Evidence | helper の分類 | 再評価との違い | 理由 |
| --- | --- | --- | --- |
| E18、E19 | G3 / G3S / G6 = NOT_PROVEN / PARTIAL | 再評価は FAILED | helper の `_required_part` は `isRequired` を記録するだけで判定に使わなかった（WP0 HA-1）。また PARTIAL は §7 にない分類 |
| E18、E19 | G11 = PROVEN / PASS | s7 は PASS で一致、p2 は NOT_PROVEN | helper は Artifact の Drift を見ない |
| E18、E19 | 他の G0、G1、G2、G4、G5、G9、G10 = PROVEN / PASS | 一致 | — |
| E20 | E18 と同じ（G11 は NOT_PROVEN） | G3 / G3S / G6 のみ異なる（理由は上と同じ） | — |
| E21 | G2、G3、G3S、G4、G5、G6、G9、G10 = FAILED、G0 / G1 = PROVEN、G11 = NOT_PROVEN | 再評価は G3 / G3S / G6 以外を PASS | 当時の helper の Gate Rule の誤分類。E20 はこれを再分類したファイル（`reclassified_from: app-evidence.json`）。同じデータに WP4 の Rule を適用すると G2、G4、G5、G9、G10 は PASS |

## 6. 判定（M1-12）

* Phase 1 の結果は変更していない。Phase 1 Helper、Evidence、rev2 / rev3 文書の SHA-256 は記録値と一致（`wp4-acceptance-report.md` §5）
* 再評価は別 Artifact に出力し、上書きしない
* G3 / G3S / G6 は Phase 1 と同じ FAILED、G11 の §7 単独の差分は理由とともに報告した
* 当時の Capture の完全性・真正性は NOT_PROVEN のまま
