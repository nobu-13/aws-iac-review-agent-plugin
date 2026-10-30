# Phase 2 / M1 / WP2 — Acceptance Report

* Source: WP2 指示（WP2-1〜WP2-7）、`docs/v2/phase2/m1/wp0/m1-acceptance-test-matrix.md`（M1-02、M1-04、M1-07、M1-08、M1-09）
* 目的: WP2 の完了条件を、実行した Command と Test の結果で判定する
* 状態: 2026-10-29 実施。**Git Commit なし**（HEAD `4bd6e015d88b01d34dc83dc2b2d2ffb0058358b2`）。GitHub API の呼び出しなし。Human レビュー待ち

## 1. 判定

| 条件 | 判定 | 根拠 |
| --- | --- | --- |
| M1-04 Raw Capture と Hash 保存 | **PASS（合成応答の範囲）** / 実 GitHub 取得: **NOT_PROVEN** | §3 の Collector・Store Test |
| M1-07 Provenance の区別 | **PASS** | `test_invalid_provenance_is_refused`（7通り）、`test_non_api_evidence_is_local_or_human_and_never_claims_api_fields`、`test_the_rule_result_carries_no_evaluation_of_authenticity`。Legacy Map（Phase 1 Evidence への適用）は WP3 |
| M1-08 Secret Safety | **PASS（規則の範囲）** | §3 の Security Gate Test。0件は不存在の証明ではない。PII は e-mail だけ |
| M1-09 非上書き Revision 保存の基本実装 | **PASS** | §3 の Store Test。過去 Revision の移行・修復は WP3 |
| M1-02 S7-01 の Rule・Test 対応 | **PASS** | Rule `s7.evidence.raw_api_data_stored` が `IMPLEMENTED`、`rules.IMPLEMENTATIONS` に登録、Definition の rule_behaviour Test `tests/unit/test_evidence_store.py::test_s7_evidence_raw_api_data_stored` が `IMPLEMENTED` で存在し PASS。Registry が3つの一致を検査（`test_11_*`、`test_11b_*`）。他の23 Rule は `PLANNED` |
| End-to-End（実 GitHub API からの取得・保存・判定） | **NOT_PROVEN** | GitHub API を呼んでいない。GitHub に届く Transport は未実装 |
| M1-05 完全な Offline Replay | **NOT_PROVEN**（WP2 では PASS にしない） | Evaluator・Replay は WP4 |

## 2. 主要機能と Test

### Evidence Envelope（WP2-1）

| 機能 | Test |
| --- | --- |
| 必須 field の欠落で COMPLETE にしない（全21 field） | `test_an_envelope_missing_any_required_field_is_not_complete` |
| Schema Version 不一致 | `test_a_schema_version_mismatch_is_refused` |
| 不正な Provenance（未知の source_type、真正性の自称、`AUTHENTICATED`、HUMAN に API field、API に `api` なし、絶対 URL、`evaluated_at`） | `test_invalid_provenance_is_refused` |
| 取得時刻と評価（検証）時刻の分離 | `test_verification_time_is_separate_from_capture_time`、`test_a_single_page_is_captured_as_bytes_with_a_complete_envelope` |
| COMPLETE の自称の拒否 | `test_a_claimed_complete_status_for_unfinished_pagination_is_refused` |

### Raw Capture（WP2-2）

| 機能 | Test |
| --- | --- |
| Parse 前のバイト列、Body と Metadata の分離、Header の allowlist | `test_a_single_page_is_captured_as_bytes_with_a_complete_envelope` |
| 決定論的な Hash、1バイトで変わる | `test_the_hash_is_deterministic_and_depends_on_every_byte` |
| 取得上限、超過時の明示的失敗（途中まで保存しない） | `test_a_body_over_the_page_limit_is_dropped_not_truncated`、`test_the_total_byte_budget_spans_pages`、`test_a_capture_over_the_byte_limit_stores_no_partial_body` |
| HTTP Error の記録（401/403/404/500/302/204） | `test_an_http_error_is_recorded_with_its_body_and_is_incomplete`、`test_an_http_error_is_stored_as_incomplete_with_its_status` |
| Pagination の完了確認 | `test_pages_are_followed_and_each_page_is_its_own_evidence`、`test_an_unfinished_pagination_is_never_complete`、`test_a_next_link_outside_the_same_resource_is_not_followed`、`test_graphql_pagination_and_errors_are_incomplete`、`test_a_complete_graphql_answer_is_complete` |
| Response の欠落検出 | `test_a_missing_response_is_detected`（4通り）、`test_a_content_length_mismatch_is_a_truncated_body` |
| 読み取り以外の Request の拒否 | `test_only_allowed_read_requests_are_made` |
| API の申告と真正性の区別 | `test_a_single_page_is_captured_as_bytes_with_a_complete_envelope`（`SELF_DECLARED`、`authenticity_verified: false`）、`test_invalid_provenance_is_refused` |

### Security Gate（WP2-3）

| 機能 | Test |
| --- | --- |
| GitHub Token、Fine-grained PAT、PEM、Authorization Header、Bearer、JWT、環境変数形式、合成 PII（e-mail） | `test_each_canary_shape_is_detected_and_never_echoed`（8通り） |
| JSON に埋め込まれた Secret、`\u` escape | `test_a_secret_embedded_in_json_is_detected`、`test_a_unicode_escaped_secret_inside_json_is_detected_after_decoding` |
| 個人情報を含む合成データ | `test_synthetic_personal_data_in_a_user_object_is_detected` |
| 任意の PII を検出できるとは主張しない | `test_pii_beyond_email_is_not_claimed_to_be_detected` |
| Binary Content | `test_binary_content_is_unscannable_and_refused`、`test_binary_content_hiding_a_token_is_refused_too` |
| サイズ上限超過 | `test_content_over_the_size_limit_is_refused` |
| Scanner 例外 | `test_a_scanner_exception_is_an_error_and_refused`、`test_no_rules_is_an_error`、`test_non_bytes_content_is_an_error` |
| 既存 Scanner との整合（変更なし） | `test_every_ci_scanner_rule_is_also_caught_by_the_gate` |
| 値を出力しない | 上記の各 Test、`test_the_refusal_exception_names_rules_but_not_values` |
| Header・Page の拒否 | `test_a_secret_in_a_page_is_refused_and_the_capture_is_incomplete`、`test_a_secret_in_a_kept_header_is_refused` |

### Immutable Store（WP2-4）と WP2-6 の異常系

| WP2-6 の項目 | Test |
| --- | --- |
| Raw の1バイト変更 | `test_one_changed_raw_byte_is_detected` |
| 不正な Hash | `test_a_wrong_hash_in_the_envelope_is_refused_at_write`、`test_a_wrong_hash_in_the_manifest_is_detected` |
| 欠損 Content | `test_missing_content_is_detected`、`test_missing_raw_bytes_are_refused_at_write` |
| 重複 Evidence ID | `test_a_duplicate_evidence_id_is_refused_within_and_across_revisions` |
| Revision の上書き | `test_a_revision_is_never_overwritten`、`test_a_seal_never_replaces_an_existing_manifest` |
| Pagination 未完了 | `test_unfinished_pagination_is_stored_as_incomplete_evidence`、`test_a_claimed_complete_status_for_unfinished_pagination_is_refused` |
| HTTP Error | `test_an_http_error_is_stored_as_incomplete_with_its_status` |
| 取得上限超過 | `test_a_capture_over_the_byte_limit_stores_no_partial_body` |
| Secret 検出 | `test_secret_content_is_never_written`、`test_a_secret_in_the_revision_reason_is_refused_at_seal` |
| Scanner 実行失敗 | `test_a_failing_scanner_refuses_the_write` |
| Symlink / Path Traversal | `test_a_symlinked_store_root_is_refused`、`test_a_store_root_outside_or_equal_to_the_base_is_refused`、`test_a_revision_directory_swapped_for_a_link_is_refused`、`test_a_file_replaced_by_a_link_is_detected`、`test_an_evidence_id_that_could_traverse_is_refused` |
| 保存途中での異常終了 | `test_a_crash_in_the_middle_leaves_a_detected_incomplete_bundle`、`test_an_interrupted_seal_is_detected` |
| Schema Version 不一致 | `test_a_schema_version_mismatch_is_refused`、`test_a_manifest_schema_version_mismatch_is_detected` |
| 不正な Provenance | `test_invalid_provenance_is_refused` |
| Manifest と Content の不一致 | `test_a_manifest_that_disagrees_with_its_content_is_detected`、`test_an_unlisted_file_in_a_revision_is_detected` |

その他: `test_revisions_chain_to_the_previous_manifest`、`test_a_broken_chain_is_detected`、`test_a_gap_in_revision_numbers_is_detected`、`test_files_and_directories_are_private`、`test_looser_file_permissions_are_reported`、`test_an_empty_revision_cannot_be_sealed`。

### S7-01 Rule（WP2-5）

`test_s7_evidence_raw_api_data_stored`: PASS（全 Page を指定・検証済み・COMPLETE）、FAILED（HTTP 200 で Raw なし。他の欠落より優先）、NOT_PROVEN（Page の指定漏れ、Pagination 未完了、HTTP Error、HUMAN、不存在、指定なし、重複、Store の改変後）。

## 3. 実行した Command と結果

| Command | Exit | 結果 | 所要 |
| --- | --- | --- | --- |
| `PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 -m pytest -q -p no:cacheprovider tests/unit/test_evidence_*.py` | 0 | 263 passed / 0 failed / 0 skipped（collector 33、secretgate 27、store 70、registry 87、s7_definition 10、preflight 36） | 4秒 |
| 全体 `pytest --cov=iacreview --cov=benchmark/harness --cov-fail-under=80`（`-p no:cacheprovider`、Coverage と Hypothesis の DB は `/tmp`） | 0 | 7,491 件中 FAIL 0 / SKIP 36、coverage 95.89% | 671秒 |
| `run_benchmark.py --cases benchmark/cases --mode combined` | 0 | PASS、34/34 matched | — |
| `PYTHONHASHSEED=random pytest tests/property/test_prop_determinism.py` | 0 | PASS | — |
| `check_ground_truth_order.py --cases benchmark/cases` | 0 | 17/17 | — |
| `scan_secrets.py` | 0 | 0 finding、633 ファイル（tracked mode） | — |
| `public_preflight.py` | 0 | PASS、8 Check、659 ファイル（追跡＋未追跡、本 Report 作成後の最終実行） | — |
| `ruff check --no-cache iacreview/evidence .github/scripts/public_preflight.py tests/unit/test_evidence_*.py` | 0 | All checks passed | — |
| `ruff check --no-cache iacreview` / `mypy iacreview` | — | 5件 / 12 errors（Baseline と同数。`iacreview/evidence/` は0件） | — |
| Phase 1 Helper Test（変更なし、cache なし） | 0 | すべて PASS（WP1 と同じ516件の集合） | 70秒 |
| `iacreview/evidence/` の Coverage（新規 Test のみで計測） | — | 90%（collector 97%、secretgate 98%、store 87%、envelope 83%、rule 98%） | — |

* 途中の `public_preflight.py` が、新規 Test ファイルの Canary 表で `secret_assignment` に2件一致した（dict の key が Rule 名 `aws_secret_access_key` 等だったため）。Rule 名も断片の結合にして解消した。既存の `scan_secrets.py` は追跡ファイルだけを走査するので、この2件は検出していなかった。
* CI 上の実行は **NOT VERIFIED**（Push していない）。

## 4. Phase 1 の非変更

* Helper 3本、E18、rev3 の4ファイル、rev2 の5ファイルの SHA-256 は WP0 / WP1 の記録と一致した。
* Helper Test 14本は、rev3 `phase2-handoff.md` より後に更新されていない。
* `docs/v2/phase1/`、`.github/scripts/scan_secrets.py`、`.github/workflows/`、`pyproject.toml`、`tests/unit/test_phase1_traceability.py` に差分はない。
* Phase 1 の判定（FAILED / PARTIAL / NOT_PROVEN）、Historical Classification、事前 AC は変えていない。

## 5. NOT_PROVEN・未実施

* 実 GitHub API からの取得、End-to-End: NOT_PROVEN（GitHub に届く Transport は未実装）
* M1-05 Offline Replay: NOT_PROVEN（WP4）
* Legacy Evidence Map、Validator V1〜V9 の完全版、過去 Revision の移行・修復: WP3
* 残り23 Rule: PLANNED
* Secret・PII が存在しないこと: 証明できない（規則に一致しなかっただけ。PII は e-mail だけ）
* 取得したバイト列の真正性: 証明できない（署名なし。`authenticity_verified: false`）
* 一貫した書き直しの検出: できない（Architecture Note §5-1）
* CI 上の実行: NOT VERIFIED
* Git Commit、Push、CI 変更、Dependency 追加: 未実施

## 6. Git の状態

```text
 M .gitignore
?? .github/scripts/public_preflight.py
?? docs/v2/phase2/
?? iacreview/evidence/
?? tests/unit/test_evidence_collector.py
?? tests/unit/test_evidence_preflight.py
?? tests/unit/test_evidence_registry.py
?? tests/unit/test_evidence_s7_definition.py
?? tests/unit/test_evidence_secretgate.py
?? tests/unit/test_evidence_store.py
```

Staging 済み 0件。
