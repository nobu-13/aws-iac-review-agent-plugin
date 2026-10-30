# Phase 2 / M1 — Final Acceptance Matrix（M1-01〜M1-12）

> **Pre-Commit Remediation の注記（後から追加）**: 本書の Hash と実測値（Evaluator Source `dfaec952…`、Definition `efd934b0…`、固定 Manifest `360d731b…`、Replay `4dc16d9b…`、Final Report `27eecd68…`、Legacy 結果 `f205b5d4…`、Mutant 29件など）は Pre-Commit Remediation の前の値で、最終 Source では再現しない。`docs/v2/phase2/m1/wp5/legacy-reevaluation-results.json` は最終 Source から再生成し直した。WP4 の結果ファイルは公開対象から外した。最終の値は `docs/v2/phase2/m1/precommit/remediation-report.md` を参照する。

* Source: `docs/v2/phase2/m1/wp0/m1-acceptance-test-matrix.md`（条件）、WP1〜WP5 の Acceptance Report、Final Frozen Quality Gate attempt 4（`.agents/tasks/phase2-m1-wp5/frozen-gate-attempt4/`、Git 管理外）
* 目的: M1 の各 AC を、同じ形式で、根拠と限定条件を付けて判定する
* 状態: **Source はすべて未 Commit**（HEAD `4bd6e015d88b01d34dc83dc2b2d2ffb0058358b2`、新規ファイルは untracked）。固定範囲の Manifest SHA-256 `360d731b5b10a30e231bbf01ae76b50055698c7ab9bf15d934ec042bba18aec5`（703 files）
* 判定値: PASS / PARTIAL / FAILED / NOT_PROVEN。NOT_VERIFIED は「実行していない」の意味で、判定の補足に使う

## 1. 判定の一覧

保証の段階を分けて示す。「—」はその AC に当てはまらない。

| AC | 判定 | Rule 実装 | Test PASS（固定後） | 合成 Evidence で検証 | 実 GitHub Evidence で証明 | 第三者の独立再現 |
| --- | --- | --- | --- | --- | --- | --- |
| M1-01 Git 管理 | **NOT_PROVEN** | — | PASS（Clean Copy） | — | — | NOT_PROVEN |
| M1-02 条文と Rule・Test の対応 | **PASS** | 24 / 24 | PASS | — | — | NOT_PROVEN |
| M1-03 Mutation Detection | **PASS**（29 Mutant の集合） | — | PASS | PASS | — | NOT_PROVEN |
| M1-04 Raw Evidence の Hash 付き保存 | **PASS**（合成 Fixture） | — | PASS | PASS | NOT_PROVEN | NOT_PROVEN |
| M1-05 Deterministic Replay | **PASS**（合成 Raw）/ 実 Raw は **NOT_PROVEN** | — | PASS | PASS | NOT_PROVEN | NOT_PROVEN |
| M1-06 欠損・改変の検出 | **PASS**（保存後の改変） | — | PASS | PASS | NOT_PROVEN | NOT_PROVEN |
| M1-07 Provenance の区別 | **PASS** | — | PASS | PASS | NOT_PROVEN | NOT_PROVEN |
| M1-08 Secret / Token / PII | **PASS**（規則の範囲） | — | PASS | PASS | NOT_PROVEN | NOT_PROVEN |
| M1-09 非上書き Revision | **PASS** | — | PASS | PASS | — | NOT_PROVEN |
| M1-10 Traceability — 欠損の追跡 | **PASS**（`.agents/` のある環境） | — | PASS | — | — | NOT_PROVEN |
| M1-10 Traceability — 歴史的 Raw への到達 | **NOT_PROVEN** | — | — | — | NOT_PROVEN | — |
| M1-11 Source / Commit / Artifact | **PASS**（合成 Git と合成 Contents）/ 実 GitHub は **NOT_PROVEN** | 2 / 2 | PASS | PASS | NOT_PROVEN | NOT_PROVEN |
| M1-12 Historical Regression | **PASS** | — | PASS | — | — | NOT_PROVEN |

## 2. AC ごとの記録

共通: 「Test PASS」は attempt 4 の Gate 1（Full pytest、7,685件: PASS 7,649 / FAIL 0 / SKIP 36、coverage 95.06%、exit 0）と Gate 2（Evidence Test 449件 PASS、exit 0）を指す。Source Commit はすべて「未 Commit」。

### M1-01 Helper・AC・Evaluator・Test の Git 管理

| 項目 | 内容 |
| --- | --- |
| 判定 | **NOT_PROVEN** |
| テスト条件 | WP0 の正常系①（`git ls-files` に含まれる）②（Provenance 記録）③（Clean Checkout で M1 の Test が動く）、異常系①〜③ |
| 実測結果 | ① 未達: `iacreview/evidence/`、`tests/unit/test_evidence_*.py` などは untracked で `git ls-files` に出ない。② Helper の関数名と Alignment は Definition の `historical_implementation` に記録（M1 は Helper のコードを抽出せず、Rule を新しく実装した）。③ Clean Copy（706 files、`.agents/`・`.kiro/` なし）で Evidence Test 444 PASS / 5 SKIP、exit 0。異常系: `.agents/` の import なし（Clean Copy で動作）。個人 Account 名・Targets への参照5件はいずれも依存ではない（`m1-integration-test-results.md` §4） |
| 対応 Test | Gate 12（Clean Checkout）、`test_evidence_preflight.py` |
| Source Commit | 未 Commit |
| Evidence Locator | `.agents/tasks/phase2-m1-wp5/frozen-gate-attempt4/gate12.log` |
| Evidence SHA-256 | `e0fd4bcb4e551f633f8da0fff1335d4afa51cdaeac25396b44e9a711e4562695` |
| 限定条件 | Clean Copy はファイルの複写で、Git の Clone ではない。git が必要な Test 1件と、検証済み Commit が必要な Test 1件は Skip |
| 未解決 Risk | Commit 後に `git ls-files` と Clone からの Test で再判定が必要。Commit 対象の選定（`.gitignore` の変更を含む）は Human 判断 |

### M1-02 条文と判定コード・Test の対応

| 項目 | 内容 |
| --- | --- |
| 判定 | **PASS** |
| テスト条件 | 各 Criterion に Rule が1つ、Rule が Catalog と実装に存在、Rule の Test が存在し状態が一致、条文の Fidelity |
| 実測結果 | 26 Criterion → 24 Rule（S6-G3 / G3S / G6 が1 Rule を共有）。Catalog の IMPLEMENTED 24、PLANNED 0、`catalog_problems() == []`。全 Criterion の rule_behaviour Test が IMPLEMENTED で、関数が存在する（Registry 検査） |
| 対応 Test | `test_evidence_s7_definition.py::test_every_s7_clause_maps_to_one_catalog_rule_and_a_rule_test_matching_its_status`、`test_evidence_registry.py::test_all_twenty_four_rules_are_implemented`、`test_every_historical_clause_occurs_once_at_every_verified_commit` |
| Source Commit | 未 Commit（条文の出典は Commit `24b7a6e`〜`4bd6e01` の `docs/v2/phase1/app-demo-plan.md`） |
| Evidence Locator | `iacreview/evidence/definitions/phase1-app-demo-s7.v1.json`、`iacreview/evidence/rules.py` |
| Evidence SHA-256 | Definition `efd934b0badd8cbdc50ec13fcc0be4dec0e501ad26bf0507f546dd6d36e28589`、`rules.py` `f8a553fcb4fc9678c3b1725e27cf95b5306cab34e237aa0f9905e03dfbdb5bee` |
| 限定条件 | Rule が実装済みであることは PASS の結果を意味しない。S7-19 の Rule は条文の解釈を含む（`wp5-acceptance-report.md` §3） |
| 未解決 Risk | Definition v1 は未 Commit のまま内容が変わった（WP4、WP5）。Commit 後の変更では version を上げる必要がある |

### M1-03 Mutation Test による誤実装の検出

| 項目 | 内容 |
| --- | --- |
| 判定 | **PASS**（実施した29 Mutant の集合に対して） |
| テスト条件 | 固定した Mutant をすべて Kill する。WP0 固定の12件を含む |
| 実測結果 | Gate 11: exit 0、Baseline 33 passed、Killed 29 / 29、20秒。WP0 固定 MU-01〜MU-12 はすべて対応する Mutant があり Killed（対応表は `m1-security-regression.md` §3） |
| 対応 Test | `tests/unit/test_evidence_mutations.py`（2件）、Harness `tests/mutation/evidence_mutants.py` |
| Source Commit | 未 Commit |
| Evidence Locator | `.agents/tasks/phase2-m1-wp5/frozen-gate-attempt4/mutation.json` |
| Evidence SHA-256 | `79e8fe73f40ac1506ba96ba028f10aa6c8720d619802f8a888cc69d81a7ddb48`（Harness `dc461e7b…fbef51c`） |
| 限定条件 | 検出率は集合に対する値で、一般的な欠陥検出率ではない |
| 未解決 Risk | WP4 の Harness は WP0 の ID 番号と違う条件を実装していた。WP5 で不足分を追加して訂正した |

### M1-04 GitHub API Raw Evidence の Hash 付き保存

| 項目 | 内容 |
| --- | --- |
| 判定 | **PASS**（合成 Fixture の範囲） |
| テスト条件 | 応答 bytes を変えずに保存、Envelope と Manifest の Hash 一致、Pagination、失敗応答、上限超過、Next の拒否 |
| 実測結果 | Collector 33件、Store 70件を含む Evidence Test 449件 PASS。Pipeline Test で Capture → Store を通し確認 |
| 対応 Test | `test_evidence_collector.py`、`test_evidence_store.py`、`test_evidence_pipeline.py::test_the_whole_path_from_capture_to_final_report` |
| Source Commit | 未 Commit |
| Evidence Locator | `iacreview/evidence/collector.py`、`store.py`、`.agents/tasks/phase2-m1-wp5/frozen-gate-attempt4/gate2.log` |
| Evidence SHA-256 | `collector.py` `84d751fcacf318998cbae500532ee4590a773ef995c6ba7c445e4515e30589fe`、`store.py` `4c95194da7cb9bf8fdb68f6f4e27a821419e3a3904c98b1cd34ef452aff9e8a6` |
| 限定条件 | 実 GitHub からは取得していない。Redirect（Job Log、Artifact）は取得できない |
| 未解決 Risk | 実応答での Secret Gate の誤検知（FP-1）。GitHub 由来であることの証明はない |

### M1-05 同一入力による同一判定・同一出力 Hash

| 項目 | 内容 |
| --- | --- |
| 判定 | **PASS**（合成 Raw）。実 GitHub Raw の End-to-End は **NOT_PROVEN**、CI の複数 Python は **NOT_VERIFIED** |
| テスト条件 | 同一入力で2回一致、`PYTHONHASHSEED=random` の別 Process で一致、Report も一致、時刻を含まない、変更・欠損で拒否 |
| 実測結果 | Gate 10: 同一 Process 4回・別 Process 4回（exit 0）で `4dc16d9b…d6a4`、Report 4回で `27eecd68…16d1a`。Legacy 再評価の再生成が byte 一致（`f205b5d4…70ed`） |
| 対応 Test | `test_evidence_pipeline.py`（12件）、`test_evidence_replay.py`（22件） |
| Source Commit | 未 Commit |
| Evidence Locator | `.agents/tasks/phase2-m1-wp5/frozen-gate-attempt4/gate10.log` |
| Evidence SHA-256 | `3dc9b9b4d6241012d3990e9e01ca1c97936dff4259accf1250548ac3a049e462` |
| 限定条件 | macOS、Python 3.9.6 だけ。合成 Raw だけ |
| 未解決 Risk | 実 Raw の取得計画（`github-e2e-verification-plan.md`）は未承認・未実行 |

### M1-06 Evidence の欠損・改変の検出

| 項目 | 内容 |
| --- | --- |
| 判定 | **PASS**（保存後の改変） |
| テスト条件 | 削除、1 byte 改変、Manifest 外ファイル、Manifest 改変、必須 Field 欠落、不完全、Symlink など。依存する軸が NOT_PROVEN になる |
| 実測結果 | Integrity Test 33件 PASS。Pipeline で Raw 改変・欠損・Incomplete Revision が `SNAPSHOT_CHANGED` で拒否され、PASS の Scenario が出ない。MU-16、MU-17 Killed |
| 対応 Test | `test_evidence_integrity.py`、`test_evidence_pipeline.py::test_missing_evidence_is_refused_and_never_pass`、`test_an_incomplete_revision_is_refused` |
| Source Commit | 未 Commit |
| Evidence Locator | `iacreview/evidence/integrity.py`、`snapshot.py` |
| Evidence SHA-256 | `integrity.py` `9165fb42282a0ffc20c670cd825f4074a03cc646801598ccc2efbec25cefce23`、`snapshot.py` `88cb0cbbabb468dac62baacb0b45dbdbea9ef441517f7477a9c3e4267364ffbd` |
| 限定条件 | 保存前の改変は検出できない |
| 未解決 Risk | 複数 Process の同時書き込みは扱わない |

### M1-07 Human / API / Local Provenance の区別

| 項目 | 内容 |
| --- | --- |
| 判定 | **PASS** |
| テスト条件 | Envelope の `source_type` が閉集合、要求に合わない Provenance は使わない（V7）、Legacy Map の分類 |
| 実測結果 | V7 Test PASS、MU-26（HUMAN で API 要求を満たす）Killed。Legacy Map 71 Entry の `source_type`: DERIVED_HELPER_OUTPUT 28、DOCUMENT 22、LOCAL_FILE 5、LOCAL_GIT_DERIVED 5、HELPER_CODE 4、HUMAN_REPORT 3、API_TRANSCRIBED 3、GIT_HISTORY 1。E18 は DERIVED_HELPER_OUTPUT、H01 は HUMAN_REPORT、GE-JSON は API_TRANSCRIBED |
| 対応 Test | `test_evidence_integrity.py::test_the_wrong_provenance_is_not_proven_v7`、`test_evidence_legacy.py` |
| Source Commit | 未 Commit |
| Evidence Locator | `iacreview/evidence/legacy/phase1-legacy-evidence-map.v1.json` |
| Evidence SHA-256 | `d0bd9342441234fc18246269ef16948a883fc8f6fa56e85ee105c3666c97df15` |
| 限定条件 | Final Report は Evidence ごとの Provenance を表示しない（結果の `evidence` 表に `source_type` がある） |
| 未解決 Risk | なし（WP5 で新たに見つかったもの） |

### M1-08 Secret / Token / PII の保存・公開防止

| 項目 | 内容 |
| --- | --- |
| 判定 | **PASS**（Secret Gate と Secret Scan の規則の範囲） |
| テスト条件 | Canary を含む応答を保存しない、値を出力しない、保存しない Header、公開対象で Scan 0件 |
| 実測結果 | Secret Gate 27件、Collector の拒否 Test、Pipeline の拒否 Test PASS。MU-13、MU-14 Killed。Gate 8 Preflight exit 0（8 Check PASS、706 files）、Gate 9 Secret Scan 0件（633 files） |
| 対応 Test | `test_evidence_secretgate.py`、`test_evidence_pipeline.py::test_a_secret_in_a_capture_never_reaches_the_store` |
| Source Commit | 未 Commit |
| Evidence Locator | `.agents/tasks/phase2-m1-wp5/frozen-gate-attempt4/gate8.log`、`gate9.log` |
| Evidence SHA-256 | `secretgate.py` `a688c6ceb0e63aae681cc1bb7dbfe2c27c9217f205bb15f65091c1b8206479a9` |
| 限定条件 | 規則外の形式の Secret は NOT_PROVEN。PII は email だけ。0件は不存在の証明ではない |
| 未解決 Risk | FP-1（Human 決定 H-1〜H-4） |

### M1-09 非上書き Revision 管理

| 項目 | 内容 |
| --- | --- |
| 判定 | **PASS** |
| テスト条件 | 既存 Path への書き込み失敗、確定済み Revision への追加拒否、Quarantine は新 Revision、Chain の改変を V3 で検出 |
| 実測結果 | Store 70件と Integrity 33件 PASS。MU-17 Killed。`legacy_reeval` の出力は O_EXCL（既存ファイルへの再出力は exit 2） |
| 対応 Test | `test_evidence_store.py`、`test_evidence_integrity.py::test_a_broken_chain_fails_v3` |
| Source Commit | 未 Commit |
| Evidence Locator | `iacreview/evidence/store.py` |
| Evidence SHA-256 | `4c95194da7cb9bf8fdb68f6f4e27a821419e3a3904c98b1cd34ef452aff9e8a6` |
| 限定条件 | 単一 User の Directory を前提 |
| 未解決 Risk | なし（WP5 で新たに見つかったもの） |

### M1-10 rev2 / rev3 Evidence ID から原本への Traceability

| 項目 | 内容 |
| --- | --- |
| 判定 | 欠損の追跡 **PASS**（`.agents/` のある環境）、歴史的 Raw への到達 **NOT_PROVEN** |
| テスト条件 | 全 Evidence ID が Map にある、Path と Hash、欠損・不一致・失効参照の報告 |
| 実測結果 | Map 71 Entry、照合130行（MATCH 122、HISTORICAL_MATCH 8）、changed 0、missing 0（`legacy.current_state`、WP5 で再実行）。Phase 1 の Raw API 応答はない |
| 対応 Test | `test_evidence_legacy.py`（33件、うち1件は Clean Copy で Skip） |
| Source Commit | 未 Commit |
| Evidence Locator | `iacreview/evidence/legacy/phase1-legacy-evidence-map.v1.json` |
| Evidence SHA-256 | `d0bd9342441234fc18246269ef16948a883fc8f6fa56e85ee105c3666c97df15` |
| 限定条件 | `.agents/` のない環境では NOT_PROVEN として報告される（Test 済み） |
| 未解決 Risk | 当時の Raw は存在しないため、今後も NOT_PROVEN のまま。新しく取得する Raw で置き換えない |

### M1-11 Source / Commit / Published Artifact の整合性

| 項目 | 内容 |
| --- | --- |
| 判定 | **PASS**（合成 Git Repository と合成 Contents 応答）。実 GitHub 上の内容は **NOT_PROVEN** |
| テスト条件 | Whole Tree の byte 一致、Published の git blob id 一致、不一致・不完全・承認 Source なしの扱い |
| 実測結果 | Artifact Test 17件 PASS。Pipeline の G11 で P2-AI-01 / 02 PASS、Drift で FAILED（`test_the_published_artifact_drift_is_failed`）。Phase 1 G11 の Drift は既存 Evidence 3件で同じ値（`wp5-acceptance-report.md` §4。判定は NOT_PROVEN のまま） |
| 対応 Test | `test_evidence_artifact.py`、`test_evidence_replay.py::test_the_published_artifact_drift_is_failed` |
| Source Commit | 未 Commit |
| Evidence Locator | `iacreview/evidence/artifact.py` |
| Evidence SHA-256 | `1ef926e000e6826d75a9fb31ec0f33ededce0858059c0b6f4c72bc295cd05b58` |
| 限定条件 | 承認済み Source の記録が前提。Phase 1 G11 には事前に固定した記録がない |
| 未解決 Risk | G11 の承認 Source を Helper の記録で代用するかは Human 判断（H-5） |

### M1-12 Phase 1 結果と安全機構の Regression 防止

| 項目 | 内容 |
| --- | --- |
| 判定 | **PASS** |
| テスト条件 | Phase 1 のファイル Hash 不変、Phase 1 結果の不変、Legacy 再評価で G3 / G3S / G6 = FAILED、Helper Test 516件 PASS、M1 の新コードに書き込み経路がない |
| 実測結果 | Phase 1 の15ファイル（Helper 3、E18 / E19、rev3 4、rev2 5、github-evidence）の SHA-256 が記録値と一致し、全 Gate の前後で不変。Gate 6 Helper Test 516 passed。Legacy 再評価 E18〜E21 で G3 / G3S / G6 = FAILED（Phase 1 と一致）、G11 の `phase2_result` = NOT_PROVEN（一致）。`iacreview/evidence/` に subprocess、socket、HTTP Client の import なし。Collector が許すのは GET と GraphQL の POST だけで、Transport を持たない |
| 対応 Test | Gate 6、`test_evidence_legacy_reeval.py::test_the_results_report_keeps_phase1_and_reports_differences`、`test_the_phase1_sources_are_unchanged_by_the_reevaluation`、`test_evidence_collector.py::test_only_allowed_read_requests_are_made` |
| Source Commit | 未 Commit。Phase 1 の文書は Git 管理外（`.agents/`） |
| Evidence Locator | `.agents/tasks/phase2-m1-wp5/frozen-gate-attempt4/phase1.txt`、`docs/v2/phase2/m1/wp5/legacy-reevaluation-results.json` |
| Evidence SHA-256 | Legacy 結果 `f205b5d4e9b1d8b91c8c35869dec7972d918215cefebbdc17d24590ad9bb70ed` |
| 限定条件 | G11 の §7 単独の再評価（PASS）は Phase 1 の結果（NOT_PROVEN）と違う。差分として報告し、Phase 1 の結果は変えていない |
| 未解決 Risk | Phase 1 の Evidence が `.agents/` にしかないため、公開 Checkout では M1-12 を再現できない |
