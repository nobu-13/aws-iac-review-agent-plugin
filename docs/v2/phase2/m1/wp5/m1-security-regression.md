# Phase 2 / M1 — Security and Mutation Regression（WP5-5）

> **Pre-Commit Remediation の注記（後から追加）**: 本書の Hash と実測値（Evaluator Source `dfaec952…`、Definition `efd934b0…`、固定 Manifest `360d731b…`、Replay `4dc16d9b…`、Final Report `27eecd68…`、Legacy 結果 `f205b5d4…`、Mutant 29件など）は Pre-Commit Remediation の前の値で、最終 Source では再現しない。`docs/v2/phase2/m1/wp5/legacy-reevaluation-results.json` は最終 Source から再生成し直した。WP4 の結果ファイルは公開対象から外した。最終の値は `docs/v2/phase2/m1/precommit/remediation-report.md` を参照する。

* Source: `tests/mutation/evidence_mutants.py`（SHA-256 `dc461e7bb3952f7011e63d3ea2cdf6d2aa2f3855e8134ad115b5fb139fbef51c`）、`tests/unit/test_evidence_mutations.py`（`c5ef6986a794db678e34f162309fc64e21806da829233914b6268a6ae900c96e`）、`docs/v2/phase2/m1/wp0/m1-acceptance-test-matrix.md`（WP0 固定 Mutant）
* 目的: Collector、Secret Gate、Integrity Validator、Snapshot、Replay 比較、Rule Catalog、S7-19 の Fail-closed 条件を Mutation Test で検査する
* 状態: Final Frozen Quality Gate（attempt 4）の Gate 11 で実行。Git Commit なし
* 検出率の範囲: 下表の **29 Mutant の集合に対する値だけ**。一般的な欠陥検出率ではない。表にない誤実装を検出できることは示していない

## 1. 方法

* 各 Mutant は、`iacreview/`、`tests/unit/`、Definition、Fixture、`legacy-reevaluation-results.json` を一時 Directory に複写し、**複写側**のソースだけを書き換える。作業 Tree のソースは書き換えない（`test_every_mutant_is_killed_in_an_isolated_copy` が `iacreview/evidence/*.py` の SHA-256 を前後で比較）
* 書き換える文字列は、ソースにちょうど1回現れることを先に検査する（`test_every_mutant_edit_matches_its_source_exactly_once`）
* Killed の条件: Kill Test が exit 1 で終わり、最初の `E` 行が Assertion、`DID NOT RAISE` または `SnapshotDrift` を含む。Import Error や収集エラーは Killed に数えない
* Baseline: 書き換えない複写で Kill Test（重複を除いて 26件、parametrize の展開後 33実行）がすべて PASS する

実行 Command（Gate 11）:

```text
PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 tests/mutation/evidence_mutants.py --json /tmp/wp5_gate/mutation.json
```

実測: exit 0、Baseline `33 passed in 1.35s`、**Killed 29 / 29**、所要 20秒。結果 JSON の SHA-256 `79e8fe73f40ac1506ba96ba028f10aa6c8720d619802f8a888cc69d81a7ddb48`（`.agents/tasks/phase2-m1-wp5/frozen-gate-attempt4/mutation.json`、Git 管理外）。

## 2. WP5 で追加した Mutant（MU-13〜MU-29）

Kill Test の Path は `tests/unit/` からの相対。

| ID | 書き換えた条件 | 対象 | Kill Test | 実際の失敗行 | 結果 |
| --- | --- | --- | --- | --- | --- |
| MU-13 | secret detection disabled (a matched rule is not reported) | `secretgate.py` | `test_evidence_secretgate.py::test_each_canary_shape_is_detected_and_never_echoed`、`test_evidence_pipeline.py::test_a_secret_in_a_capture_never_reaches_the_store` | `AssertionError: assert ('CLEAN' == 'DETECTED'` | Killed（1 failed in 0.15s） |
| MU-14 | the collector's security gate is bypassed (no page is scanned before it is kept) | `collector.py` | `test_evidence_collector.py::test_a_secret_in_a_page_is_refused_and_the_capture_is_incomplete`、`test_evidence_pipeline.py::test_a_secret_in_a_capture_never_reaches_the_store` | `AssertionError: assert ([] == ['cap-test-001-p002']` | Killed（1 failed in 0.16s） |
| MU-15 | an unfinished pagination is recorded as complete | `collector.py` | `test_evidence_collector.py::test_an_unfinished_pagination_is_never_complete` | `assert False` | Killed（1 failed in 0.12s） |
| MU-16 | a raw content change is not detected (store manifest check and envelope check both disabled) | `store.py + envelope.py` | `test_evidence_integrity.py::test_one_raw_byte_changed_fails_v1`、`test_evidence_pipeline.py::test_a_raw_hash_mismatch_before_the_replay_is_refused` | `AssertionError: assert ('PASS' == 'FAILED'` | Killed（1 failed in 0.16s） |
| MU-17 | a broken revision chain is not detected (previous manifest hash not compared) | `store.py` | `test_evidence_integrity.py::test_a_broken_chain_fails_v3` | `AssertionError: assert 'previous_manifest_sha256_mismatch' in []` | Killed（1 failed in 0.14s） |
| MU-18 | snapshot drift of an envelope is ignored | `snapshot.py` | `test_evidence_replay.py::test_an_envelope_changed_after_the_snapshot_refuses_the_evaluation` | `Failed: DID NOT RAISE <class 'iacreview.evidence.snapshot.SnapshotDrift'>` | Killed（1 failed in 0.24s） |
| MU-19 | the replay comparison ignores a changed snapshot | `replay.py` | `test_evidence_pipeline.py::test_an_incomplete_revision_is_refused`、`test_evidence_pipeline.py::test_missing_evidence_is_refused_and_never_pass` | `AssertionError: assert 'RESULT_MISMATCH' == 'SNAPSHOT_CHANGED'` | Killed（1 failed in 0.27s） |
| MU-20 | an unimplemented rule is judged PASS | `evaluator.py` | `test_evidence_pipeline.py::test_an_unimplemented_rule_never_passes` | `AssertionError: assert ('PASS', 'rul..._implemented') == ('NOT_PROVEN'..._implem…` | Killed（1 failed in 0.31s） |
| MU-21 | S7-19: a question with no evidence is recorded as answered | `open_questions.py` | `test_evidence_report.py::test_s7_open_questions_recorded` | `AssertionError: assert {'Q1': 'NOT_R...4': 'NOT_RUN'} == {'Q1': 'NOT_R...4': 'NO…` | Killed（1 failed in 0.14s） |
| MU-22 | S7-19: the catalog status is not consulted (a registered rule answers by itself) | `evaluator.py` | `test_evidence_report.py::test_registration_alone_is_not_an_answer` | `AssertionError: assert ({'criterion_i...ecorded', ...} == {'criterion_i...ecorde…` | Killed（1 failed in 0.14s） |
| MU-23 | WP0 MU-04: composition prefers NOT_PROVEN over FAILED (S7-02) | `rules_s7.py` | `test_evidence_evaluator_s7.py::test_s7_compose_all_parts` | `AssertionError: assert 'NOT_PROVEN' == 'FAILED'` | Killed（1 failed in 0.16s） |
| MU-24 | WP0 MU-11: composition returns PARTIAL for a mixed scenario | `rules_s7.py` | `test_evidence_evaluator_s7.py::test_s7_compose_all_parts` | `AssertionError: assert 'PARTIAL' == 'NOT_PROVEN'` | Killed（1 failed in 0.15s） |
| MU-25 | WP0 MU-12: two same-named App checks on the head are PASS (S7-04) | `rules_s7.py` | `test_evidence_evaluator_s7.py::test_s7_app_check_exactly_one_app_check` | `AssertionError: assert 'PASS' == 'FAILED'` | Killed（1 failed in 0.15s） |
| MU-26 | WP0 MU-10: HUMAN provenance satisfies an API requirement (V7) | `integrity.py` | `test_evidence_integrity.py::test_the_wrong_provenance_is_not_proven_v7` | `AssertionError: assert ('PASS' == 'NOT_PROVEN'` | Killed（1 failed in 0.13s） |
| MU-27 | WP0 MU-02: an impostor with isRequired = true makes S7-15 NOT_PROVEN instead of FAILED | `rules_s7.py` | `test_evidence_evaluator_s7.py::test_s7_required_impostor_required_fails_scenario` | `AssertionError: assert 'NOT_PROVEN' == 'FAILED'` | Killed（1 failed in 0.16s） |
| MU-28 | WP0 MU-05: a missing gate fact is defaulted to true (token_permissions, log facts such as validator_checked_out) | `rules_s7.py` | `test_evidence_evaluator_s7.py::test_s7_gate_base_gate_provenance` | `AssertionError: assert 'PASS' == 'NOT_PROVEN'` | Killed（1 failed in 0.16s） |
| MU-29 | WP0 MU-06: effective rules not read (None) do not stop the issuer-pinning proof | `rules_s7.py` | `test_evidence_evaluator_s7.py::test_phase2_issuer_pinning_independent_proof` | `AssertionError: assert 'PASS' == 'NOT_PROVEN'` | Killed（1 failed in 0.16s） |

WP5 指示の6項目との対応:

| 指示の項目 | Mutant |
| --- | --- |
| Secret 検出を無効にする | MU-13（検出結果を返さない）、MU-14（Collector が Gate を通さない） |
| Pagination 未完了を COMPLETE にする | MU-15 |
| Raw 改変を見逃す | MU-16（Store の Manifest 照合と Envelope の Raw 照合を両方無効にする。片方だけでは、もう片方が V1 で検出する） |
| Revision Chain 破損を見逃す | MU-17 |
| Snapshot Drift を無視する | MU-18（Envelope の Binding 照合）、MU-19（Replay 比較が Snapshot の違いを無視）。Manifest と Raw の Binding は WP4 の MU-08 / MU-09 |
| 未実装 Rule を PASS にする | MU-20（`_judge`）、MU-22（S7-19 で Catalog を参照しない） |

## 3. WP0 固定 Mutant との対応

WP0 の Matrix は MU-01〜MU-12 を「追加は可、削除は不可」として固定した。WP4 の Harness は同じ ID 番号で別の条件を実装していたため、WP0 の5件（MU-02、MU-04、MU-10、MU-11、MU-12）と、一般化した Mutant で代替していた2件（MU-05、MU-06）が個別には検査されていなかった。WP5 で MU-23〜MU-29 として追加し、12件すべてを個別の Mutant にした。

| WP0 ID | WP0 の条件 | Harness ID | 結果 |
| --- | --- | --- | --- |
| MU-01 | `isRequired` を判定に使わない | MU-01（Impostor の `isRequired = true` を PASS にする） | Killed |
| MU-02 | 偽装 `isRequired = true` を FAILED にせず NOT_PROVEN にする | MU-27 | Killed |
| MU-03 | App check の `isRequired = true` 条件を省く | MU-02 | Killed |
| MU-04 | 合成で FAILED より NOT_PROVEN を優先する | MU-23 | Killed |
| MU-05 | 欠落 Field を既定値で真にする | MU-28 | Killed |
| MU-06 | 有効 Rule 未読（None）を PASS 扱い | MU-29 | Killed |
| MU-07 | Validator 失敗の Evidence で判定を続ける | MU-10 | Killed |
| MU-08 | Pagination 未完了を無視 | MU-15 | Killed |
| MU-09 | App failure による BLOCKED を Issuer Pinning の PASS にする | MU-03 | Killed |
| MU-10 | HUMAN provenance だけで API 要求を満たす | MU-26 | Killed |
| MU-11 | Scenario 判定に PARTIAL を返す | MU-24 | Killed |
| MU-12 | 同名 App check が2件で PASS | MU-25 | Killed |

`mutation-test-results.md`（WP4）の表は WP4 時点の記録として変更していない。WP4 文書の「Source: WP0 Matrix（MU-01〜MU-12）」という記述は、ID 番号が WP0 と一致していなかった。この不一致は本書で訂正する。

## 4. Security Regression Test（Mutation 以外）

| 対象 | Test | 結果（Gate 2） |
| --- | --- | --- |
| Secret Gate | `test_evidence_secretgate.py`（Canary 各種、JSON 内、Unicode escape、base64、Binary、Size 超過、例外、規則なし） | PASS |
| Collector の Gate | `test_a_secret_in_a_page_is_refused_and_the_capture_is_incomplete`、`test_a_secret_in_a_kept_header_is_refused` | PASS |
| Pipeline の Gate | `test_evidence_pipeline.py::test_a_secret_in_a_capture_never_reaches_the_store` | PASS |
| Raw の扱い | `test_evidence_raw_policy.py`（18件） | PASS |
| Public Preflight | `test_evidence_preflight.py`（36件） | PASS（Clean Copy では git が必要な1件が Skip） |
| Network 不使用 | `test_replay_never_opens_a_network_socket`、`test_the_replay_and_the_report_complete_without_network` | PASS |

Gate 8（Public Preflight）: exit 0、8 Check PASS、706 files。Gate 9（Secret Scan）: exit 0、0 finding（633 files、tracked mode）。0件は Secret が存在しないことの証明ではない。

## 5. 残る Risk

* Mutant は人が選んだ条件。表にない誤実装（例: Canonical の別の破れ方、Store の同時書き込み）は検査していない
* MU-16 は2か所を同時に無効にしている。Store 側の照合だけを無効にした場合、Envelope 側の照合が残り、1 byte 改変は V1 FAILED（理由コード `envelope_invalid`）、overall FAILED のままだった（一時 Copy で実測）。この1か所だけの Mutant は集合に入れていない
* 実 GitHub の応答に対する Secret Gate の誤検知（FP-1）と見逃しは、合成 Canary の範囲でしか検査していない
