# Phase 2 / M1 / WP4 — Evaluator Rule Coverage

> **Pre-Commit Remediation の注記（後から追加）**: 本書が参照する `docs/v2/phase2/m1/wp4/legacy-reevaluation-results.json`（SHA-256 `b17e6881…29f7d544`、最初の版 `15b866b8…` を含む）は公開対象から外し、非公開の作業領域に保全した。この結果は WP4 時点の Evaluator Source と Definition で作ったもので、現在の Source では再現できない。本書の Hash・件数・判定は WP4 時点の記録であり、現在の判定の根拠にしない。最終の値は `docs/v2/phase2/m1/precommit/remediation-report.md` を参照する。

* Source: `iacreview/evidence/definitions/phase1-app-demo-s7.v1.json`（Definition v1）、`iacreview/evidence/rules.py`（Rule Catalog）、`iacreview/evidence/rules_s7.py`
* 目的: §7 Definition の各 Criterion について、Rule、入力 Evidence、判定条件、Test、NOT_PROVEN の理由、Phase 1 の Historical Classification との関係を示す
* 状態: 実装済み・Git Commit なし。数値は下記 Command の実測

## 1. 集計

| 項目 | 件数 | 根拠 |
| --- | --- | --- |
| Definition の Criterion | 26 | Definition JSON の `acceptance_criteria[].criteria[]` を数えた |
| Criterion の rule_behaviour Test が IMPLEMENTED | 25 | 同上。S7-19 だけ PLANNED（`planned_wp = WP5`） |
| Catalog の IMPLEMENTED Rule | 23 | WP2: `s7.evidence.raw_api_data_stored`、WP3: `phase2.artifact.*` 2件、WP4: 20件 |
| Catalog の PLANNED Rule | 1 | `s7.open_questions.recorded`（S7-19、WP5） |

26 Criterion と 24 Rule の差は、S6-G3 / S6-G3S / S6-G6 の3 Criterion が1 Rule `s6.expected.impostor_not_required` を共有するため（26 − 2 = 24）。

未実装 Rule の Criterion は `rule_not_implemented` で NOT_PROVEN になり、PASS にならない（`test_native_replay_judges_the_synthetic_scenarios` で `not_implemented_rules == ["s7.open_questions.recorded"]` を確認）。

## 2. Criterion → Rule

入力の Evidence Type は Definition の `required_evidence_types`。Test は rule_behaviour Test（`tests/unit/` 配下）。「Phase 1」は Definition の `historical_classification`（rev2 / rev3 からの引用）で、Rule は参照しない。

### evidence_recording

| Criterion | Rule | 入力 | 判定 | Test | 主な NOT_PROVEN 理由 | Phase 1 |
| --- | --- | --- | --- | --- | --- | --- |
| S7-01 | `s7.evidence.raw_api_data_stored` | graphql_status_rollup、rest_check_runs、actions_run、store_manifest | 4 Part の Raw が Store にある（WP2） | `test_evidence_store.py::test_s7_evidence_raw_api_data_stored` | Raw 欠損 | 未分類 |
| S7-18 | `s7.limits.recorded_not_proven` | acceptance_definition | Limit を NOT_PROVEN として記録 | `test_evidence_evaluator_s7.py::test_s7_limits_recorded_not_proven` | 常に NOT_PROVEN（`needs_a_merge` など） | G8 / AC28 / admin_bypass / same_app_with_key = NOT_PROVEN |
| S7-19 | `s7.open_questions.recorded` | acceptance_definition | **未実装（PLANNED、WP5）** | `test_s7_open_questions_recorded`（PLANNED） | `rule_not_implemented` | 未分類 |

### scenario_composition

| Criterion | Rule | 入力 | 判定 | Test | 主な NOT_PROVEN 理由 | Phase 1 |
| --- | --- | --- | --- | --- | --- | --- |
| S7-02 | `s7.compose.all_parts` | 各 Part の結果 | FAILED が1つでもあれば FAILED、全 PASS で PASS | `test_s7_compose_all_parts` | Part に NOT_PROVEN がある | G3 / G3S / G6 = FAILED |

### gate_provenance

| Criterion | Rule | 入力 | 判定 | Test | 主な NOT_PROVEN 理由 | Phase 1 |
| --- | --- | --- | --- | --- | --- | --- |
| S7-03 | `s7.gate.base_gate_provenance` | actions_run、actions_jobs、job_log | head 上の completed な Gate Run で、event = `pull_request_target`、Gate Path、Head SHA など全条件が真 | `test_s7_gate_base_gate_provenance` | `gate_runs_missing`、`no_completed_gate_run_on_head`、条件の Fact 欠損 | G3 / G3S / G6 = PASS |
| S7-03b | `s7.gate.verify_step_as_expected` | actions_jobs、job_log | verify step の結果が期待どおりで、決定が publish された | `test_s7_gate_verify_step_as_expected` | `verify_step_missing`、`publish_job_missing` | G3 / G3S / G6 = PASS |

### app_check_provenance

| Criterion | Rule | 入力 | 判定 | Test | 主な NOT_PROVEN 理由 | Phase 1 |
| --- | --- | --- | --- | --- | --- | --- |
| S7-04 | `s7.app_check.exactly_one_app_check` | rest_check_runs | App の同名 Check がちょうど1件（複数は FAILED） | `test_s7_app_check_exactly_one_app_check` | `check_runs_missing`、`app_check_absent` | PASS |
| S7-05 | `s7.app_check.external_id_names_gate_run` | rest_check_runs、actions_run | external_id が head 上の Gate Run を指す | `test_s7_app_check_external_id_names_gate_run` | `app_check_not_unique`、`no_completed_gate_run_on_head` | PASS |
| S7-06 | `s7.app_check.report_digest_matches` | actions_artifact、rest_check_runs | 再計算した Report Digest が一致 | `test_s7_app_check_report_digest_matches` | `report_artifact_missing` | PASS |
| S7-07 | `s7.app_check.conclusion_as_expected` | rest_check_runs | conclusion が Scenario の期待どおり | `test_s7_app_check_conclusion_as_expected` | `conclusion_missing`、`no_expectation` | PASS |

### required_check

| Criterion | Rule | 入力 | 判定 | Test | 主な NOT_PROVEN 理由 | Phase 1 |
| --- | --- | --- | --- | --- | --- | --- |
| S7-08 | `s7.required.impostor_not_required` | graphql_status_rollup、rest_check_runs、rest_commit_statuses | App 以外の同名 Context に `isRequired = true` があれば FAILED | `test_s7_required_impostor_not_required` | `rollup_or_check_source_missing`、`context_origin_unknown`、`impostor_is_required_missing` | G3 / G3S / G6 = FAILED |
| S7-09 | `s7.required.app_check_required` | graphql_status_rollup、rest_check_runs | App の Check が `isRequired = true`（false は FAILED） | `test_s7_required_app_check_required` | `app_check_not_unique_in_rollup`、`app_is_required_missing` | 未分類 |
| S7-14a | `s7.required.same_name_other_source` | 同 S7-08 | 他 Source の同名 Context があり、それが required でなく、App は required | `test_s7_required_same_name_other_source` | `impostor_not_observed`、`is_required_missing` | FAILED |
| S7-15 | `s7.required.impostor_required_fails_scenario` | 同 S7-08 | required な Impostor があれば Scenario を FAILED | `test_s7_required_impostor_required_fails_scenario` | `impostor_not_observed` | FAILED |
| S6-G3 / S6-G3S / S6-G6 | `s6.expected.impostor_not_required` | graphql_status_rollup と check_runs または commit_statuses | §6 の期待（Impostor は required でない）どおり | `test_s6_expected_impostor_not_required` | `not_a_spoof_scenario`、`context_origin_unknown` | 各 FAILED |

### merge_blocking

| Criterion | Rule | 入力 | 判定 | Test | 主な NOT_PROVEN 理由 | Phase 1 |
| --- | --- | --- | --- | --- | --- | --- |
| S7-10 | `s7.required.merge_state_as_expected` | graphql_status_rollup（branch_rules は使わない） | Merge State が期待どおり（G0 mergeable、G9 mergeable_then_blocked、禁止変更は BLOCKED） | `test_s7_required_merge_state_as_expected` | `merge_state_missing`、`mergeability_unsettled`、`not_mergeable_before_ruleset` | PASS |
| S7-14b | `s7.merge.spoof_scenario_blocked` | graphql_status_rollup | Spoof Scenario の PR が BLOCKED | `test_s7_merge_spoof_scenario_blocked` | `merge_state_missing`、`merge_state_unsettled` | PASS |

### issuer_pinning_independent_proof（Phase 2 追加）

| Criterion | Rule | 入力 | 判定 | Test | 主な NOT_PROVEN 理由 | Phase 1 |
| --- | --- | --- | --- | --- | --- | --- |
| P2-IP-01 | `phase2.issuer_pinning.independent_proof` | 同 S7-08 と effective rules | App の Check が Merge State を説明しない head で、成功した Impostor があっても BLOCKED なら PASS。Impostor が Rule を満たしたら FAILED | `test_phase2_issuer_pinning_independent_proof` | **`app_failure_explains_block`**、`no_passing_impostor`、`effective_rules_missing` | G3 / G3S / G6 / G12 = NOT_PROVEN |

### g11_environment_boundary

| Criterion | Rule | 入力 | 判定 | Test | 主な NOT_PROVEN 理由 | Phase 1 |
| --- | --- | --- | --- | --- | --- | --- |
| S7-12 | `s7.steal.no_step_executed` | actions_run、actions_jobs、check_run_annotations | `steal.yml` の全 Run が concluded で、Step 実行なし | `test_s7_steal_no_step_executed` | `steal_runs_missing`、`run_not_concluded_or_jobs_missing` | G11 = NOT_PROVEN、G11b = PASS |
| S7-13 | `s7.steal.app_checks_name_gate_runs` | rest_check_runs | App の Check がすべて Gate Run を指す | `test_s7_steal_app_checks_name_gate_runs` | `app_check_absent` | 未分類 |
| S7-16 | `s7.steal.environment_refuses_both_events` | actions_run、actions_jobs、annotations、check_runs | 両 Event が Environment で拒否された | `test_s7_steal_environment_refuses_both_events` | `not_both_events_observed`、`denial_reason_not_observed` | G11 = NOT_PROVEN、G11b = PASS |
| S7-17 | `s7.limit.same_app_with_key` | acceptance_definition | Limit。常に NOT_PROVEN | `test_s7_limit_same_app_with_key` | `limit_same_app_with_key` | NOT_PROVEN |

### artifact_integrity（Phase 2 追加、WP3 で実装）

| Criterion | Rule | 入力 | 判定 | Test | 主な NOT_PROVEN 理由 | Phase 1 |
| --- | --- | --- | --- | --- | --- | --- |
| P2-AI-01 | `phase2.artifact.whole_tree_matches_source` | local_git_tree、approved_source_definition | Commit の全 Tree が承認 Source と byte 一致 | `test_evidence_artifact.py::test_phase2_artifact_whole_tree_matches_source` | Tree / Source 欠損 | A08 = PARTIAL、G11b = PASS |
| P2-AI-02 | `phase2.artifact.published_matches_source` | rest_contents、local_git_tree、approved_source_definition | 公開内容が承認 Source と一致 | `test_evidence_artifact.py::test_phase2_artifact_published_matches_source` | `published_contents` 欠損 | G11 = NOT_PROVEN、G11b = PASS |

## 3. Historical Classification との関係

* Rule は Historical Classification を読まない（`rules_s7.py` の固定規則。MU-12 で検査）
* Legacy Re-evaluation の結果と Phase 1 の結果の比較は `legacy-reevaluation-differences.md`
* WP0 の Alignment（`historical_implementation.alignment`）が `NOT_IMPLEMENTED` だった S7-08、S7-09、S7-15 は、WP4 で初めて条文どおりの Rule になった。helper の `_required_part` は `isRequired` を記録するだけで判定に使っていなかった（WP0 helper audit HA-1）

## 4. 確認 Command

```text
/usr/bin/python3 - <<EOF   # Definition JSON の criteria を数える（26件、PLANNED 1件）
PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 -m pytest -q -p no:cacheprovider tests/unit/test_evidence_registry.py tests/unit/test_evidence_s7_definition.py tests/unit/test_evidence_evaluator_s7.py
```

結果は `wp4-acceptance-report.md` §3。
