# Phase 2 / M1 / WP4 — Replay Reproducibility Report（M1-05）

> **Pre-Commit Remediation の注記（後から追加）**: 本書が参照する `docs/v2/phase2/m1/wp4/legacy-reevaluation-results.json`（SHA-256 `b17e6881…29f7d544`、最初の版 `15b866b8…` を含む）は公開対象から外し、非公開の作業領域に保全した。この結果は WP4 時点の Evaluator Source と Definition で作ったもので、現在の Source では再現できない。本書の Hash・件数・判定は WP4 時点の記録であり、現在の判定の根拠にしない。最終の値は `docs/v2/phase2/m1/precommit/remediation-report.md` を参照する。

* Source: WP4 指示（WP4-4）、`iacreview/evidence/canonical.py`、`iacreview/evidence/replay.py`、`tests/unit/test_evidence_replay.py`
* 目的: 同じ Snapshot から同じ bytes が出ること、Snapshot 後の変更で評価が拒否されること、Network を使わないことを実測で示す
* 状態: 実施済み・Git Commit なし
* 範囲: **合成 Raw（Test 内で生成した GitHub 応答）だけ**。実際の GitHub から取得した Raw による End-to-End の Replay は **NOT_PROVEN**（Phase 2 で実 Raw をまだ取得していない。Phase 1 には Raw がない）

## 1. Canonical Serialization の仕様

Evaluator を書く前に固定し、`canonical.py` の docstring に記載した。

* JSON。キーは code point 順（`sort_keys`）
* ASCII のみ。非 ASCII は `\uXXXX`（`ensure_ascii`）
* 区切り `,` と `:`、空白なし。末尾に改行1つ、他の改行なし
* 数値は整数のみ。float、NaN、Infinity は `CanonicalError`
* 実行時刻のキー（`generated_at`、`evaluated_at`、`checked_at`、`verified_at`、`captured_at`、`sealed_at`）は `CanonicalError`
* 先頭 `/` の文字列、`\` を含む文字列、Drive Path は `CanonicalError`（Host Path を出さない）
* 順序に意味のない配列は生成側でソートする
* 出力 Hash = canonical bytes の SHA-256。時刻などの実行メタデータは CLI の stderr にだけ出す

## 2. 再現性の実測

合成 Store（Scenario G0、G1、G2、G3（Impostor required）、G3S、G6、G11（Artifact 付き））を、別々の一時 Directory に2回作り、それぞれで次を実行した。

| 実行 | 回数 | exit code | 出力 SHA-256 |
| --- | --- | --- | --- |
| 同一 Process の `replay.replay(spec)` | 各 Directory で2回（計4回） | — | `2e52bc1c34216349d0355f07f8f1f2eaf08672d560b18651800356d231c2916a`（4回とも同じ） |
| 別 Process `python3 -m iacreview.evidence.replay spec.json`、`PYTHONHASHSEED=random` | 各 Directory で2回（計4回） | 0（4回） | 同上（4回とも同じ） |

出力は 43,830 bytes。一時 Directory の Path が違っても Hash は同じだった（出力に Host Path を含まないため）。

同じ内容を Test で常時確認している。

| Test | 確認内容 |
| --- | --- |
| `test_two_runs_give_identical_bytes` | 同一 Process の2回が同じ bytes |
| `test_a_separate_process_with_a_random_hash_seed_gives_the_same_hash` | 別 Process（`PYTHONHASHSEED=random`）2回の SHA-256 が同一 Process と一致 |
| `test_the_canonical_result_carries_no_time_path_or_host_information` | 改行1つ、再 Serialize で同じ bytes、一時 Path・日付・`evaluated_at` を含まない、`canonical.problems == []` |
| `test_the_canonical_serializer_refuses_what_the_specification_forbids` | 6種（run-time key、float、`/tmp/a`、`C:\a`、NaN、未対応型）を拒否 |
| `test_canonical_bytes_are_ascii_sorted_and_compact` | 期待 bytes との完全一致 |
| `test_evidence_legacy_reeval.py::test_the_committed_results_are_reproduced_byte_for_byte` | Legacy 再評価の再実行が `legacy-reevaluation-results.json`（SHA-256 `b17e6881…29f7d544`）と byte 一致 |

## 3. Network 不使用

* `replay.py`、`evaluator.py`、`snapshot.py`、`facts.py`、`rules_s7.py` は Transport を import しない
* `test_replay_never_opens_a_network_socket`: `socket.socket` と `socket.create_connection` を例外を送出する関数に置き換えても Replay が完了する

## 4. Snapshot 後の変更（Drift）の拒否

| 変更 | 結果 | Test |
| --- | --- | --- |
| Raw の変更 | `SnapshotDrift`、評価拒否 | `test_raw_changed_after_the_snapshot_refuses_the_evaluation` |
| Manifest の変更 | `SnapshotDrift` | `test_a_manifest_changed_after_the_snapshot_refuses_the_evaluation` |
| Envelope の変更 | `SnapshotDrift` | `test_an_envelope_changed_after_the_snapshot_refuses_the_evaluation` |
| Binding 済み ID を別 Store へ付け替え | `SnapshotDrift` | `test_a_bound_id_cannot_be_repointed_to_another_store` |
| 未 Binding の ID の読み込み | `SnapshotDrift` | `test_an_unbound_evidence_id_is_never_read` |
| 検証に失敗した Group | Binding しない。必要な Rule は NOT_PROVEN | `test_a_group_that_fails_validation_is_not_bound` |
| 別の Definition / Evaluator 向けの Snapshot | 拒否 | `test_a_snapshot_for_another_definition_or_evaluator_is_refused` |
| 不明な Role / Scenario | 拒否 | `test_an_unknown_role_or_scenario_is_refused` |
| CLI での Drift | exit code 3 | `test_the_replay_cli_reports_drift_with_exit_3` |

## 5. M1-05 の判定

* 合成 Raw: **PASS**（§2〜§4）
* 実際の GitHub Raw による End-to-End: **NOT_PROVEN**（未取得）
* Phase 1 Evidence: Raw がないため Native Replay の対象外。Legacy Derived Re-evaluation（`legacy-reevaluation-differences.md`）は Raw Replay ではない

## 6. 測定 Command

```text
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=.:tests/unit /usr/bin/python3 -  # test_evidence_replay.build() で2つの一時 Store を作り、
                                                                       # replay.replay を各2回、CLI を PYTHONHASHSEED=random で各2回実行
PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 -m pytest -q -p no:cacheprovider tests/unit/test_evidence_replay.py
```

一時 Directory は `/tmp/wp4_rep` 配下に作り、測定後に削除した。
