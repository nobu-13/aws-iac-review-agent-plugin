# Phase 2 / M1 — Integration Test Results（WP5-4、WP5-6）

> **Pre-Commit Remediation の注記（後から追加）**: 本書の Hash と実測値（Evaluator Source `dfaec952…`、Definition `efd934b0…`、固定 Manifest `360d731b…`、Replay `4dc16d9b…`、Final Report `27eecd68…`、Legacy 結果 `f205b5d4…`、Mutant 29件など）は Pre-Commit Remediation の前の値で、最終 Source では再現しない。`docs/v2/phase2/m1/wp5/legacy-reevaluation-results.json` は最終 Source から再生成し直した。WP4 の結果ファイルは公開対象から外した。最終の値は `docs/v2/phase2/m1/precommit/remediation-report.md` を参照する。

* Source: `tests/unit/test_evidence_pipeline.py`（SHA-256 `f5a3bc5243bfe3780c7003ad07fe7392692ae1371d9151857ac58a9f014c67f3`）、`tests/unit/test_evidence_report.py`（`738c922419e8e12fefad52be9e123fcfbb5d6514e7db11164c43a476915a2f75`）、Final Frozen Quality Gate attempt 4
* 目的: Capture から Final Report までの全経路を、合成 Raw で通しで検証した結果と、Clean Checkout での結果を記録する
* 状態: 実施済み。Git Commit なし
* 範囲: 合成 Raw だけ。実 GitHub との接続はない

## 1. 経路と担当 Module

| 段階 | Module | 経路上の確認 |
| --- | --- | --- |
| Capture | `collector.py`（Fake Transport） | `evidence_synth.Builder` が全応答を `Collector.capture` / `non_api_evidence` で取得 |
| Security Gate | `secretgate.py`（Collector 内） | 全 Page を走査。Secret を含む Page は保存されない |
| Immutable Store | `store.py` | 1 Revision に Seal、`verify().valid` |
| Integrity Validator | `integrity.py` | Group ごとに V1〜V9、W1〜W5。結果の `validation` がすべて PASS |
| Verified Snapshot | `snapshot.py` | PASS の Group だけを Hash で Binding |
| Evaluator | `evaluator.py`、`rules_s7.py`、`open_questions.py`、`artifact.py` | 26 Criterion を IMPLEMENTED の Rule で判定、`not_implemented_rules == []` |
| Offline Replay | `replay.py`（`--expect`） | 再実行と byte 比較、拒否理由コード |
| Final Report | `final_report.py` | 結果の SHA-256 で結果に結び付いた要約 |

## 2. Test 一覧（`tests/unit/test_evidence_pipeline.py`、12件）

| Test | 確認内容 |
| --- | --- |
| `test_the_whole_path_from_capture_to_final_report` | 全経路。G3 は `s7_result = FAILED` / `merge_blocking = PASS`、G11 は `phase2_result = PASS`、S7-19 は NOT_PROVEN、Report の `capture_authenticity = NOT_PROVEN` |
| `test_the_same_input_gives_identical_result_and_report_bytes` | 同一入力の完全一致（結果と Report） |
| `test_a_separate_process_reproduces_the_result_and_the_report` | 別 Process（`PYTHONHASHSEED=random`）で exit 0、bytes 一致 |
| `test_the_replay_and_the_report_complete_without_network` | Network 未接続で完了 |
| `test_a_raw_hash_mismatch_before_the_replay_is_refused` | Hash 不一致 → `SNAPSHOT_CHANGED` |
| `test_a_raw_hash_mismatch_after_the_snapshot_is_refused` | Snapshot 後の変更 → `SnapshotDrift` |
| `test_a_source_change_is_refused` | Source 変更 → exit 4 `SOURCE_CHANGED` |
| `test_a_definition_change_is_refused` | Definition 変更 → `DEFINITION_CHANGED`、Evaluator も拒否 |
| `test_missing_evidence_is_refused_and_never_pass` | Evidence 欠損 → `SNAPSHOT_CHANGED`、PASS にならない |
| `test_an_incomplete_revision_is_refused` | Incomplete Revision → `SNAPSHOT_CHANGED`、Binding 0件 |
| `test_an_unimplemented_rule_never_passes` | 未実装 Rule の PASS 防止。Registry は「PLANNED の Rule に IMPLEMENTED の Test」という不整合な Definition も拒否する |
| `test_a_secret_in_a_capture_never_reaches_the_store` | Security Gate の段階で拒否、Store に入らない |

`tests/unit/test_evidence_report.py`（8件）は S7-19 と Final Report の単体の振る舞いを検査する（`wp5-acceptance-report.md` §3）。

## 3. 実行結果（attempt 4）

| Gate | Command | exit | 結果 | 所要時間 |
| --- | --- | --- | --- | --- |
| 1 Full pytest | `pytest -p no:cacheprovider --cov=iacreview --cov=benchmark/harness --cov-fail-under=80` | 0 | 7,685件: PASS 7,649、FAIL 0、SKIP 36。coverage 95.06%（12,006 statements、miss 593） | 696秒 |
| 2 Evidence Test | `pytest -p no:cacheprovider tests/unit/test_evidence_*.py` | 0 | 449 passed、0 failed、0 skipped | 31秒 |

Evidence Test 449件の内訳は、WP4 時点の 429件、`test_evidence_report.py` 8件、`test_evidence_pipeline.py` 12件。

WP5 の新 Module の coverage（Gate 1 の Report）: `open_questions.py` 99%、`final_report.py` 94%、`replay.py` 89%、`evaluator.py` 97%。`legacy_reeval.py` は 54%（CLI の `main` は Test から呼んでいない。`run` は Phase 1 の非公開 Evidence がある環境の Test だけが通る）。

## 4. Clean Checkout Test（Gate 12）

方法: `git ls-files -co --exclude-standard` の全ファイル（tracked と、ignore されない untracked）を `rsync -R` で新しい Directory に複写し、その中で実行した。Git の Checkout ではなく、Commit 前のファイル集合の複写。Script は `.agents/tasks/phase2-m1-wp5/wp5_clean.sh`（Git 管理外）。

| 項目 | 結果 |
| --- | --- |
| 複写したファイル | 706（固定範囲 703 と、Gate 前に存在した WP5 文書3件） |
| `.agents/`、`.kiro/` | どちらも存在しない |
| Evidence Test | exit 0、444 passed、5 skipped |
| Skip の内訳 | Phase 1 の非公開 Source がない 3件、git Checkout でない 1件、検証済み Commit がない 1件。いずれも `NOT VERIFIED` の理由付き。Skip は PASS に数えない |
| Quickstart §3〜§5 | 合成 Spec 生成 exit 0、Replay exit 0、Final Report exit 0、`diagnose` `store_valid: true`、`--expect` exit 0、Raw 改変後 `--expect` exit 4 `SNAPSHOT_CHANGED` |
| 個人アカウント・Targets への参照（`appdemo-targets`、Account 名、Home Path） | 5件。どれも依存ではない: `iacreview/sarif.py` の Project URL（既存）、`test_evidence_preflight.py` の拒否 File 名一覧、WP0 / WP1 文書の監査記述 |

実施していないこと: 第三者による導入、別 Machine・別 OS・別 Python Version、`pip install`、Setup 時間の計測。
