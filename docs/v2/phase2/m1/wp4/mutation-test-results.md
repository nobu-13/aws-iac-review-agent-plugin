# Phase 2 / M1 / WP4 — Mutation Test Results（M1-03）

> **Pre-Commit Remediation の注記（後から追加）**: 本書が参照する `docs/v2/phase2/m1/wp4/legacy-reevaluation-results.json`（SHA-256 `b17e6881…29f7d544`、最初の版 `15b866b8…` を含む）は公開対象から外し、非公開の作業領域に保全した。この結果は WP4 時点の Evaluator Source と Definition で作ったもので、現在の Source では再現できない。本書の Hash・件数・判定は WP4 時点の記録であり、現在の判定の根拠にしない。最終の値は `docs/v2/phase2/m1/precommit/remediation-report.md` を参照する。

* Source: `docs/v2/phase2/m1/wp0/m1-acceptance-test-matrix.md`（MU-01〜MU-12）、`tests/mutation/evidence_mutants.py`、`tests/unit/test_evidence_mutations.py`
* 目的: 12の Mutant が、指定した Kill Test で検出されることを実測で示す
* 状態: 実施済み・Git Commit なし

## 1. 方法

* Harness は必要なファイル（`iacreview/`、`tests/unit/` の該当 Test、Definition、`legacy-reevaluation-results.json`）を一時 Directory に複写し、**複写側**のソースを1か所（MU-06、07、10 は2か所）書き換えてから Kill Test を実行する。作業 Tree のソースは書き換えない
* 書き換え対象の文字列がソースにちょうど1回現れることを先に確認する（`test_every_mutant_edit_matches_its_source_exactly_once`）。ソースが変わって Mutant が空振りする状態を防ぐ
* 「Killed」の条件: Kill Test が exit code 1 で終わり、出力に Assertion の失敗行または `DID NOT RAISE` 行がある。Import Error や収集エラーによる失敗は Killed に数えない
* Baseline: 書き換えない複写で Kill Test 10件がすべて PASS すること

実行 Command:

```text
PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 tests/mutation/evidence_mutants.py --json /tmp/wp4_mut.json
```

実測: exit code 0、Baseline `10 passed in 0.62s`、**Killed 12 / 12**、全体 5.85秒（`time` の total）。pytest からは `tests/unit/test_evidence_mutations.py::test_every_mutant_is_killed_in_an_isolated_copy` で同じ Harness を実行する。

## 2. 結果

Kill Test の Path は `tests/unit/` からの相対。

| ID | 書き換えた条件 | Kill Test | 期待する失敗 | 実際の失敗行 | 結果 |
| --- | --- | --- | --- | --- | --- |
| MU-01 | `isRequired = true` の Impostor を S7-08 で PASS にする | `test_evidence_evaluator_s7.py::test_s7_required_impostor_not_required` | G3 が FAILED であるべきところ PASS | `AssertionError: assert 'PASS' == 'FAILED'` | Killed（1 failed in 0.15s） |
| MU-02 | App Check の `isRequired = false` を無視する（S7-09） | `test_evidence_evaluator_s7.py::test_s7_required_app_check_required` | `app_required=False` は FAILED | `AssertionError: assert 'NOT_PROVEN' == 'FAILED'` | Killed（0.15s） |
| MU-03 | App の失敗による BLOCKED を Issuer Pinning の PASS にする | `test_evidence_evaluator_s7.py::test_phase2_issuer_pinning_independent_proof` | G3 の P2-IP-01 は NOT_PROVEN のまま | `AssertionError: assert 'PASS' == 'NOT_PROVEN'` | Killed（0.15s） |
| MU-04 | 欠損 Evidence を PASS にする（`MISSING` が PASS を返す） | `test_s7_required_app_check_required`、`test_s7_compose_all_parts` | App Check 不在・Gate Run 欠損は NOT_PROVEN | `AssertionError: assert 'PASS' == 'NOT_PROVEN'` | Killed（0.15s） |
| MU-05 | Source App id の比較を無効にする（全 Check Run を App のものとする） | `test_s7_required_impostor_not_required` | GitHub Actions の Impostor を App と取り違えない | `AssertionError: assert 'PASS' == 'FAILED'` | Killed（0.15s） |
| MU-06 | Gate Run の Head SHA 比較を無効にする（2か所） | `test_s7_gate_base_gate_provenance` | 別 head の Gate Run は base gate ではない（NOT_PROVEN） | `AssertionError: assert 'PASS' == 'NOT_PROVEN'` | Killed（0.15s） |
| MU-07 | Gate Workflow の Provenance（event、path）を無効にする（2か所） | `test_s7_gate_base_gate_provenance` | `pull_request` event や別 Path は FAILED | `AssertionError: {'event': 'pull_request'}` | Killed（0.15s） |
| MU-08 | Manifest Hash の照合をしない | `test_evidence_replay.py::test_a_manifest_changed_after_the_snapshot_refuses_the_evaluation` | Snapshot 後に変えた Manifest で読み込みを拒否 | `Failed: DID NOT RAISE <class 'iacreview.evidence.snapshot.SnapshotDrift'>` | Killed（0.24s） |
| MU-09 | Raw Content Hash の照合をしない | `test_evidence_replay.py::test_raw_changed_after_the_snapshot_refuses_the_evaluation` | Snapshot 後に変えた Raw で評価を拒否 | `Failed: DID NOT RAISE <class 'iacreview.evidence.snapshot.SnapshotDrift'>` | Killed（0.24s） |
| MU-10 | Snapshot / Revision Binding を無効にする（未 Binding の ID を Store から読む。2か所） | `test_evidence_replay.py::test_an_unbound_evidence_id_is_never_read` | 検証に失敗した Group の Evidence を読まない | `AssertionError: assert ((RevisionReport(...` | Killed（0.24s） |
| MU-11 | 評価結果に実行時刻を入れる | `test_evidence_replay.py::test_two_runs_give_identical_bytes` | 2回の実行で同じ bytes | `assert (b'{"capture_i...` の bytes 不一致 | Killed（0.28s） |
| MU-12 | Legacy の Historical Classification を Evaluator の結果として使う | `test_evidence_legacy_reeval.py::test_the_historical_classification_is_never_the_evaluator_result` | 再評価は自身の結果を出し、差分を報告する | `AssertionError: assert ('FAILED' == 'FAILED'`（差分が報告されなくなった） | Killed（0.14s） |

## 3. 補足

* MU-08 と MU-09 が別々に Killed になるのは、`Snapshot.read` が `store.verify()` を呼ばず、Manifest と Raw を別の条件で照合するため（`wp4-architecture-note.md` §2）
* MU-12 の Kill Test は合成した helper 行を使う。Legacy Map は G3 を FAILED としているが、Impostor が required でないデータでは再評価の `required_check` が PASS になり、比較欄に `differs: true` が出ることを確認する。Mutant は `s7_result` を Map の FAILED で上書きするため差分が消え（`'FAILED' == 'FAILED' and differs is True` が偽）、Assertion が失敗する
* Mutant は Phase 2 M1 の Evaluator と Snapshot の条件に限る。Collector、Secret Gate、Integrity Validator の Mutation Test は WP4 の範囲外（**NOT_VERIFIED**）
