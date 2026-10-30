# Phase 2 / M1 / WP3 — Acceptance Report

* Source: WP3 指示（WP3-1〜WP3-6、§8）、`docs/v2/phase2/m1/wp0/m1-acceptance-test-matrix.md`（M1-06、M1-08〜M1-11）
* 目的: WP3 の Acceptance 条件を、実行した Command と Test の結果で判定する
* 状態: 2026-10-29 実施。**Git Commit なし**（HEAD `4bd6e015d88b01d34dc83dc2b2d2ffb0058358b2`）。GitHub API の呼び出しなし。Human レビュー待ち

## 1. 判定

| AC | 判定 | 根拠 |
| --- | --- | --- |
| M1-06 Evidence 欠損・改変の検出 | **PASS** | §2 の Integrity Test。改変・欠損のどの状態でも overall は FAILED / NOT_PROVEN で、PASS にならない |
| M1-09 Revision Integrity | **PASS** | 連鎖・欠番・不完全 Bundle・中断境界5か所・Quarantine。自動修復なし |
| M1-10 Legacy Evidence Traceability — 欠損の追跡 | **PASS**（ローカル。`.agents/` のある環境） | 必須 ID 全件を Map 化、現在の122ファイルを再 Hash して全件一致、欠損 0件。`.agents/` のない環境では NOT_PROVEN として報告する（Test 済み） |
| M1-10 — 当時の Raw への到達 | **NOT_PROVEN** | Phase 1 に Raw API 応答はない（`RAW_UNAVAILABLE` 33件、`RAW_FIELD_ONLY` 2件） |
| M1-11 Source / Commit / Artifact Integrity | **PASS（合成 Git Repository と合成 Contents 応答の範囲）** | §2 の Artifact Test。P2-AI-01 / 02 が `IMPLEMENTED`。実際の GitHub 上の内容との照合は NOT_PROVEN |
| M1-08 Security Regression | **PASS（規則の範囲）** | WP2 の Gate Test すべて PASS、WP3 の Raw Policy Test、base64 content の検査追加。Secret Scan 0件は不存在の証明ではない |
| M1-05 Offline Replay | **NOT_PROVEN**（WP3 では PASS にしない） | Evaluator・Replay は WP4 |

## 2. 主要機能と Test

### Integrity Validator（`tests/unit/test_evidence_integrity.py`、33件）

| WP3-6 の項目 | Test |
| --- | --- |
| Raw の1バイト改変 | `test_one_raw_byte_changed_fails_v1` |
| Envelope の改変 | `test_envelope_changed_fails_v1`、`test_envelope_schema_broken_fails_v4` |
| Manifest の改変 | `test_manifest_changed_fails` |
| Revision Chain の切断 | `test_a_broken_chain_fails_v3` |
| Missing Revision | `test_a_missing_revision_fails_v3` |
| Duplicate Evidence ID | `test_a_duplicate_evidence_id_fails_w1` |
| Source Commit の不一致（Evidence） | `test_a_source_commit_mismatch_fails_w2` |
| Incomplete Bundle | `test_an_incomplete_bundle_fails_w3`、`test_every_crash_boundary_leaves_a_detected_unusable_revision`（5境界） |
| Secret Gate の不一致 | `test_a_secret_gate_disagreement_with_stored_content_fails_w4` |
| 不正な Fallback | `test_a_broken_latest_revision_never_falls_back_to_an_older_one` |
| その他 | `test_intact_complete_evidence_passes_every_check`、`test_not_proven_is_never_reported_as_pass`、`test_a_file_outside_the_manifest_fails_v2`、`test_a_named_evidence_id_that_does_not_exist_is_not_proven`、`test_loose_permissions_fail_w5`、`test_a_page_of_the_capture_not_named_is_not_proven_v5`、`test_an_http_error_is_not_usable_v6`、`test_the_wrong_provenance_is_not_proven_v7` |
| Recovery | `test_diagnose_is_read_only_and_lists_unusable_evidence`、`test_an_approved_quarantine_is_recorded_in_a_new_revision_and_nothing_is_deleted`、`test_a_stale_or_mismatched_approval_is_refused`（3通り）、`test_a_quarantined_revision_changed_after_approval_breaks_the_store_again`、`test_only_the_latest_revision_can_be_quarantined`、`test_a_valid_store_has_nothing_to_quarantine`、`test_a_forged_quarantine_of_a_valid_revision_fails_v8` |

### Artifact Integrity（`tests/unit/test_evidence_artifact.py`、17件）

| 項目 | Test |
| --- | --- |
| Artifact Commit / Source Commit の不一致 | `test_source_and_artifact_commit_mismatches_are_detected` |
| バイト差異 | `test_one_byte_of_difference_is_detected` |
| Extra / Missing File | `test_extra_and_missing_files_are_detected` |
| Mode 変更 | `test_a_mode_change_is_detected` |
| Symlink | `test_a_symlink_is_detected` |
| 不正な Git Object | `test_an_object_whose_bytes_do_not_hash_to_its_id_is_detected`、`test_a_gitlink_is_detected`、`test_an_unreadable_object_is_unverifiable_not_a_match` |
| Manifest の Artifact 参照の不一致 | `test_the_manifest_reference_matches_and_a_changed_record_is_detected`、`test_a_record_naming_another_commit_is_a_manifest_mismatch` |
| Rule P2-AI-01 / 02 | `test_phase2_artifact_whole_tree_matches_source`、`test_phase2_artifact_published_matches_source` |

### Legacy Evidence Map（`tests/unit/test_evidence_legacy.py`、33件）

| 項目 | Test |
| --- | --- |
| 必須 ID の網羅 | `test_the_shipped_map_is_valid_and_covers_every_required_id` |
| Raw なし・Historical Hash なし | `test_no_phase1_entry_claims_a_raw_api_body_or_completeness`、`test_entries_without_a_recorded_hash_are_historical_integrity_not_proven` |
| Legacy Evidence の欠損 | `test_missing_legacy_evidence_is_reported_missing_never_present`、`test_a_source_file_recorded_as_missing_must_say_so`、`test_a_symlinked_legacy_file_is_not_followed` |
| Phase 1 Classification の改変 | `test_altering_a_phase1_classification_is_refused`（7通り）、`test_altering_a_g3_axis_is_refused`（3通り） |
| Map の改変 | `test_an_altered_map_is_refused`（12通り）、`test_a_changed_legacy_file_is_detected` |
| 現在の Phase 1 ファイル | `test_every_phase1_source_is_unchanged_since_the_map_was_made`（`.agents/` がない環境では skip = NOT VERIFIED） |

### Raw Security Policy（`tests/unit/test_evidence_raw_policy.py`、18件）

Fixture ごとの事前期待値（`EXPECTED`）、Secret 応答・Prose 偽陽性、base64 content、Pagination、e-mail 応答の拒否、HTTP Error、上限超過。

### 実装を壊すと Test が失敗することの確認

Test が実際に不正な状態を拒否しているかを確かめるため、次の3か所を一時的に壊して Test を実行し、元に戻した（元のファイルに戻ったことを SHA-256 で確認）。

| 壊した箇所 | 失敗した Test |
| --- | --- |
| `store._verify_entry` の Raw Hash 比較を無効化 | `test_one_raw_byte_changed_fails_v1`、`test_one_changed_raw_byte_is_detected` |
| `artifact.compare_content` の mode 検査を無効化 | `test_a_mode_change_is_detected` |
| `legacy._entry_problems` の RAW_UNAVAILABLE 規則を無効化 | `test_an_altered_map_is_refused[<lambda>-RAW_UNAVAILABLE]` |

M1-03 の Mutation Test（12 Mutant）そのものは WP4 の範囲で、未実施。

## 3. 実行した Command と結果

| Command | Exit | 結果 | 所要 |
| --- | --- | --- | --- |
| `PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 -m pytest -q -p no:cacheprovider tests/unit/test_evidence_*.py` | 0 | 364 passed / 0 failed / 0 skipped（artifact 17、collector 33、integrity 33、legacy 33、preflight 36、raw_policy 18、registry 87、s7_definition 10、secretgate 27、store 70） | 約10秒 |
| 全体 `pytest --cov=iacreview --cov=benchmark/harness --cov-fail-under=80`（1回目） | 1 | 7,600件中 FAIL 1 / SKIP 36、coverage 95.36%。FAIL は `test_this_repository_public_set_passes_the_preflight`：本 WP の Policy 文書の表に `secret_assignment` に一致する例文があった。文書を修正 | 677秒 |
| 全体 pytest（2回目、文書修正後。コードは1回目と同一） | 0 | 7,600件中 FAIL 0 / SKIP 36、coverage 95.36% | 679秒 |
| `run_benchmark.py --cases benchmark/cases --mode combined` | 0 | PASS、34 matched | — |
| `PYTHONHASHSEED=random pytest tests/property/test_prop_determinism.py` | 0 | PASS | — |
| `check_ground_truth_order.py --cases benchmark/cases` | 0 | 17/17 | — |
| `scan_secrets.py` | 0 | 0 finding、633 ファイル（tracked mode） | — |
| `public_preflight.py`（文書修正後） | 0 | PASS、678 ファイル（追跡＋未追跡、本 Report 作成後の最終実行） | — |
| `ruff check --no-cache iacreview/evidence tests/unit/test_evidence_*.py .github/scripts/public_preflight.py` | 0 | All checks passed | — |
| `ruff check iacreview` / `mypy iacreview` | — | 5件 / 12 errors（Baseline と同数。`iacreview/evidence/` は0件） | — |
| Phase 1 Helper Test（変更なし、cache なし） | 0 | 516 passed / 0 failed / 0 skipped | 69秒 |

### 3-1. 実行していない Test・検証

* CI 上の実行: NOT VERIFIED（Push していない）
* `.agents/` のない Clean Checkout での `test_every_phase1_source_is_unchanged_since_the_map_was_made`: そこでは skip になる設計（NOT VERIFIED として扱う）。ローカルでは実行し PASS
* 電源断・OS の書き込み順序の入れ替え: 未検証（Process 中断の模擬のみ）
* 実 GitHub API からの取得・照合: 未実施
* M1-03 Mutation Test（WP4）、M1-05 Offline Replay（WP4）: 未実施

## 4. Phase 1 の非変更

Helper 3本、E18、rev3 の4ファイル、rev2 の5ファイル、`github-evidence.json` の SHA-256 は WP0〜WP2 の記録と一致した。Helper Test 14本は、rev3 `phase2-handoff.md` より後に更新されていない。`docs/v2/phase1/`、`scan_secrets.py`、CI、`pyproject.toml`、`tests/unit/test_phase1_traceability.py` に差分はない。Legacy Map の作成は読み取りだけで行った。

## 5. NOT_PROVEN・未実装

* M1-10 当時の Raw への到達: NOT_PROVEN（Raw が存在しない）
* M1-05 Offline Replay、M1-03 Mutation Test: WP4
* 残り21 Rule: PLANNED
* Evidence 単位の supersede / revoke: 未実装（Revision 単位の Quarantine のみ）
* 途中の Revision の Quarantine: 未対応（最新のみ）
* Sanitized Artifact: 未実装（V9 NOT_APPLICABLE）
* 実 GitHub 上の Artifact との照合、取得したバイト列の真正性: NOT_PROVEN
* Secret・PII が存在しないこと: 証明できない
