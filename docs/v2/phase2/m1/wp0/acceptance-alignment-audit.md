# Phase 2 / M1 / WP0 — Acceptance Alignment Audit

対象基準: `docs/v2/phase1/app-demo-plan.md` §6〜§7（git `24b7a6e` で導入、`4bd6e01` まで維持、作業ツリーは HEAD と一致 [実測]。SHA-256 `fbc6dcc4…`）。

**本書は Phase 1 の判定を変更しない。** Phase 1 の確定結果（Scenario: PASS 8 / PARTIAL 1 / FAILED 3 / NOT_PROVEN 3、AC rev3: PASS 40 / PARTIAL 4 / FAILED 1 / NOT_PROVEN 3）と、G3 / G3S / G6 = FAILED、G11 = NOT_PROVEN、G11b = PASS、G12 = PARTIAL を前提にする。Evaluator が異なる値を出す箇所は「実装と基準の不一致」として記録する。

確度: [実測] / [文書] / [推論] / NOT_VERIFIED。

## 1. 監査方法

1. §7 の条文を文単位で分解し、条文IDを付けた（S7-xx）。
2. 各条文に対応する Helper 関数、Test、Evidence を特定した（`helper-audit.md` の行番号）。
3. E18（`app-evidence.20261028T045529589034Z-1.json`）を、現行 Helper の `classify` に in-memory で再入力した。ファイルは書いていない [実測]:

```text
G3   saved NOT_PROVEN/PARTIAL | replay NOT_PROVEN/PARTIAL | spoof NOT_PROVEN | required PROVEN
G3S  saved NOT_PROVEN/PARTIAL | replay NOT_PROVEN/PARTIAL | spoof NOT_PROVEN | required PROVEN
G6   saved NOT_PROVEN/PARTIAL | replay NOT_PROVEN/PARTIAL | spoof NOT_PROVEN | required PROVEN
G11  saved PROVEN/PASS        | replay PROVEN/PASS
replay identical to saved: True
```

4. Helper Test 516件を実行し、全件 PASS を確認した（`repository-baseline.md` §5）。Test が PASS であることは、Test が §7 と一致していることを意味しない。

## 2. 条文と実装の対応表

| ID | Criterion（§7 原文の要旨） | Evaluator Function | Test | Evidence | Gap |
| --- | --- | --- | --- | --- | --- |
| S7-01 | `app-evidence` stores **raw API data** | `cmd_app_evidence` 3744 / `collect` 3260 | なし | E18 | **不一致**。保存されるのは抽出・平坦化済みデータ（`helper-audit.md` HA-3） |
| S7-02 | PROVEN only if every part is PROVEN; any FAILED part makes it FAILED | `classify` 3439（`entry["status"]`） | `test_the_private_app_run_classifies_as_designed`（required 197） | E18 | `status` は条文どおり。ただし別に `outcome`（`scenario_outcome` 3557）があり、§7 にない PARTIAL を返す。Phase 1 rev1 はこの `outcome` を採用した（rev2 C1） |
| S7-03 | gate: event `pull_request_target`、gate path、PR head 上の記録、base checkout、validator `5412a73`、gate scripts `f77a58c`、`HEAD_SHA`=PR head、trusted contract only、token `Contents: read, Metadata: read`、verify step as expected | `_gate_part` 3296、`owner.provenance` 337、`owner.log_facts` 242、`_gate_run_detail` 2787 | outcome `test_expected_versus_observed`（gate 系4件）、`test_the_old_one_step_failure_shape_is_not_accepted` | E16、E18 | 条文の各条件に対応する key はある。**欠落時に真になる既定値**がある（HA-5）。条件の多くは Job log の文字列一致（`log_*`）で、log 形式が変わると判定が変わる [推論] |
| S7-04 | app_check: App 発行の `remediation-gate/verified` がちょうど1件 | `owner.classify_app_check` 523（`len(from_app) != 1`） | `test_phase1_appdemo.py`（app_check 系） | E18 | 対応あり。2件以上は FAILED、0件は NOT_PROVEN |
| S7-05 | `external_id` `<run>.<attempt>:<digest>` が gate run を指す | `classify_app_check`（`re.fullmatch`） | 同上 | E18 | 対応あり |
| S7-06 | 取得した Report の再計算 digest が一致 | `report_digest` 2765 ＋ `classify_app_check` | 同上 | E17 | 対応あり。Artifact ファイル自体の Hash は記録しない |
| S7-07 | conclusion as expected | `classify` 3460〜3463 付近（App check の conclusion を `scen["app"]` と比較） | outcome `prohibited change approved by the App` 等 | E18 | 対応あり |
| S7-08 | required: App 以外の同名 check run / status は **`isRequired = false`** | **なし**。`_required_part` は `is_required_info` に記録するだけ | **逆を固定**: `test_is_required_is_recorded_but_never_decides`（required 99）、fixture `node(..., required=True)` で偽装を true にしたまま PROVEN を期待（required 141, 197） | E18（3件とも偽装 `is_required: true` [実測]） | **不一致（重大）**。§3-1 |
| S7-09 | required: App の check が **`isRequired = true`** | **なし** | 同上（`required` を True / False / None に変えても PROVEN） | E18（App check も `true`） | **不一致**。条文の条件が実装されていない（E18 では値が true なので結果には影響しない [実測]） |
| S7-10 | required: merge state as expected | `_required_part`（`want_merge`） | `test_the_merge_decision_follows_the_app_check`（8件） | E18 `merge_state` | 対応あり |
| S7-11 | （§7 には明記なし）有効 Rule が App を pin していること | `rules_problems` 3346 | `test_the_effective_rules_must_pin_the_app` | E05 | 追加の検査。**Rule 未読（`None`）で PROVEN** を Test が固定（HA-6） |
| S7-12 | steal（G11）: すべての `steal.yml` run が完了し、どの job も step を実行しない | `steal_part` 3601、`_job_record` 2807 | `test_phase1_appdemo_g11.py`（14件） | E18、E24、E30、github-evidence | 対応あり。**Workflow 内容が監査済みかを見ない**。§3-6 |
| S7-13 | steal（G11）: Head 上のすべての App check が gate run を指す | `_foreign_app_checks` 3589 | `test_a_foreign_app_check_is_token_misuse_failed` | E18 | 対応あり |
| S7-14 | Same name, other source（G3/G3S/G6）: 偽装が存在し `isRequired = false`、App check が required、BLOCKED | `spoof_part` 3415 | `test_an_app_failure_with_a_spoof_proves_refusal_but_not_spoof_resistance` 等 | E18 | **不一致**。`spoof_part` は `isRequired` を見ず、「App failure が BLOCKED を説明するか」を判定する。§3-2 |
| S7-15 | **If GitHub reports `isRequired = true` for an impostor, the scenario is FAILED** | **なし** | **逆を固定**: `test_the_observed_run_gives_the_designed_outcomes`（outcome 48、60行で `PARTIAL` を要求）、`assert not any(... == "FAILED")`（required 197） | E18 | **不一致（重大）**。現行 Evaluator は同じ入力で PARTIAL を出す [実測] |
| S7-16 | Same name, same App（G11）: environment が両 Event を拒否（step 0、token なし、非 gate run を指す App check なし） | `steal_part` | g11 Test | E30（G11b）、github-evidence | 対応あり |
| S7-17 | `same_app_with_key` は limit であり pass ではない | `LIMITS` 158 | outcome `test_scenarios_not_run_are_not_proven` | — | 対応あり（常に NOT_PROVEN） |
| S7-18 | G8、AC28、admin bypass は NOT_PROVEN with reason | `LIMITS` | 同上 | — | 対応あり |
| S7-19 | Not verified until the run: `isRequired` が期待した発行元を反映するか | — | — | E18 | 計画自体が未確認と明記 [文書]。E18 で「反映しない」が観測された [実測] |
| S6-01 | §6 表: G3 / G3S / G6 の Impostors 列 = **not required** | `EXPECTED_OUTCOMES` 3510 には required 軸がなく、`spoof_resistance: "proven"` に置き換わっている | `test_every_scenario_has_expectations_fixed_in_advance`（outcome 35）は Helper 内の期待値と Helper 内の Scenario の一致だけを見る | — | **不一致**。期待値の出典が §6 ではなく Helper 定数になっている |

## 3. 不一致の詳細

### 3-1. `isRequired` が記録されるだけで判定に使われない（S7-08 / S7-09）

* 実装: `_required_part`（3361）の docstring は「isRequired is recorded, never decides」。本体は `out["is_required_info"]` を作るだけで、`status` の決定に使わない [実測]。
* Test: `test_is_required_is_recorded_but_never_decides`（required 99〜102）は、`isRequired` を True / False / None に変えても PROVEN であることを要求する。条文と異なる実装を、Test が正しいものとして固定している。
* Evidence（E18）[実測]:

| Scenario | 偽装 Context | 偽装 `is_required` | App check（REST app_id `<App id>`）`is_required` | merge_state |
| --- | --- | --- | --- | --- |
| G3（PR #5） | check_run `<check_run 1>`（app 15368）success | true | true（`<check_run 2>`、failure） | BLOCKED |
| G3S（PR #6） | status（creator `github-actions`）success | true | true（`<check_run 3>`、failure） | BLOCKED |
| G6（PR #9） | check_run `<check_run 4>`（app 15368）skipped | true | true（`<check_run 5>`、failure） | BLOCKED |

* §7 による判定: S7-15 により3件とも FAILED。Phase 1 rev2 の判定（C1）と一致する。
* 現行 Evaluator: 3件とも `status` NOT_PROVEN / `outcome` PARTIAL。**実装と基準の不一致**として記録する。Phase 1 の結果は変更しない。

### 3-2. 正規 App failure と Issuer Pinning の効果の混同（S7-14）

`spoof_part`（3415）は、偽装の扱いを「App failure が同じ Head にあれば BLOCKED は App failure だけで説明できる → NOT_PROVEN」と判定する。これは Phase 1 rev2 の「Issuer pinning の独立防御効果: NOT_PROVEN」と同じ考え方で、それ自体は妥当である [推論]。

問題は、この軸が §7 の required 軸の**代わり**として使われていること:

| 軸 | §7 の位置付け | Helper の扱い |
| --- | --- | --- |
| required（`isRequired`） | Scenario 判定に入る part。偽装 true なら FAILED | 判定に使わない |
| merge blocking（App failure による BLOCKED） | required part の一条件 | `_required_part` で PROVEN |
| Issuer pinning の独立効果 | §7 にない（Phase 1 rev2 で追加した軸） | `spoof_part` / `spoof_resistance`。NOT_PROVEN なら `outcome` を PARTIAL |

M1 では3軸を Registry 上で別の ID にし、Scenario 判定にどれが入るかを事前定義で固定する（`m1-architecture-proposal.md` §3-1）。AC27 rev3 の軸分割（§7 required: FAILED / Merge Blocking: PASS / Issuer Pinning 独立効果: NOT_PROVEN）と同じ形になる。

### 3-3. Evidence 不足を PASS に分類できる箇所

| 箇所 | 内容 | 影響 |
| --- | --- | --- |
| `owner.provenance` 354 | `log_validator_checked_out` が欠けると True | validator checkout の証拠がなくても gate 条件が真 |
| `owner.provenance` 357 | `token_permissions` が欠けると期待値と同一扱い | Token 権限の証拠がなくても真 |
| `owner.provenance` 355 | `log_head_env_is_pr_head` が欠けると旧 key `log_has_pr_head` に fallback | 意味の異なる旧 field で代替 |
| `_required_part` / `rules_problems` 3348 | Rule 未読（`None`）で検査を飛ばし PROVEN になりうる | Test `(None, "PROVEN")`（required 106）が固定 |
| `spoof_part` 3432 | App success＋偽装＋BLOCKED を PROVEN | BLOCKED の他の原因を排除していない [推論] |
| Pagination | 100件を超える Context / Run は黙って欠落（HA-4） | 欠落した Context が impostor だった場合に見逃す [推論] |

E18 の実データでは、上の既定値が実際に使われたかを NOT_VERIFIED（E18 の `gate_runs` には `log_validator_checked_out` と `token_permissions` の key が存在する [実測] ため、少なくとも G3 の gate run では既定値は使われていない）。

### 3-4. Revision 間で判定基準が暗黙に変化している

同じ demo-2 の Scenario に対する保存済み分類 [実測]:

| ファイル | G2 | G3 / G3S / G6 | G11 | Helper version の記録 |
| --- | --- | --- | --- | --- |
| `app-evidence.json`（E21、revoked） | FAILED | FAILED | NOT_PROVEN | なし |
| `app-evidence.20261028T044355543031Z-1.json`（E19） | PROVEN / PASS | NOT_PROVEN / PARTIAL | PROVEN / PASS | なし |
| `app-evidence.20261028T045529589034Z-1.json`（E18） | PROVEN / PASS | NOT_PROVEN / PARTIAL | PROVEN / PASS | なし |
| `app-evidence-reclassified.json`（E20） | PROVEN / PASS | NOT_PROVEN / PARTIAL | NOT_PROVEN / NOT_PROVEN | なし |

* E21 の G3 等の FAILED は §7 の `isRequired` 規則ではなく、gate 軸の誤分類によるもの（rev2 §2）。結果の語が §7 と一致していても、理由が異なる。
* E20 の G11 が NOT_PROVEN なのは、その時点の Helper で `actions_policy` などが無いためと推定される [推論、NOT_VERIFIED]。
* どのファイルにも判定規則の版がなく、どの Helper で作ったかを Evidence から特定できない。

### 3-5. Test が誤った期待結果を固定している箇所

| Test | 場所 | 固定している内容 | §7 との関係 |
| --- | --- | --- | --- |
| `test_is_required_is_recorded_but_never_decides` | required 99 | `isRequired` が判定に影響しない | S7-08 / S7-09 に反する |
| `test_an_app_failure_with_a_spoof_proves_refusal_but_not_spoof_resistance` | required 141 | 偽装 `isRequired=true` で required PROVEN | S7-08 / S7-15 に反する |
| `test_the_private_app_run_classifies_as_designed` | required 197 | G3 / G3S / G6 が NOT_PROVEN、FAILED が1件もない | S7-15 に反する |
| `test_the_observed_run_gives_the_designed_outcomes` | outcome 48（60行） | G3 / G3S / G6 が PARTIAL、FAIL が1件もない | S7-15 に反する。§7 にない語 |
| `test_the_effective_rules_must_pin_the_app`（`None` ケース） | required 106 | Rule 未読で PROVEN | Fail-closed に反する（§7 に明文なし） |

これらの Test は変更しない（既存 Test の変更禁止）。M1 の新 Evaluator の Test は、条文から独立に書く。既存 Test は「Phase 1 Helper の振る舞いの記録」として保全し、M1-12 の Regression 対象にする。

### 3-6. G11 の Artifact 結合の欠落（基準側の Gap）

* S7-12 / S7-16 は、Run と Job の観測だけを条件にしており、「Push した Workflow が監査済み内容であること」を要求していない [文書]。
* E18 の G11 は Helper 上 PASS だが、実際には drift した旧 Workflow（`cef683fb…`、監査済み `212809a3…` と不一致）の観測だった（E24、github-evidence `g11_workflow`）[実測]。Phase 1 rev2 はこの項目を失効させ G11 = NOT_PROVEN とした。
* これは Evaluator の実装ミスではなく、事前基準に Artifact 条件がなかったことによる（rev2 C4）。M1 では Artifact Integrity（M1-11）を、Scenario 判定の前提条件として Registry に明記する。

## 4. 既存 Evidence の保証範囲

| 主張 | 保証できる範囲 | 保証できない範囲 |
| --- | --- | --- |
| G3 / G3S / G6 の偽装 `isRequired = true`（AC27 §7 FAILED の根拠） | E18 の Helper 出力に `is_required: true` が3件記録されている [実測] | GraphQL 応答本文がない。平坦化前の値・取得時刻・取得時の Helper 版は確認できない（EG11）。rev3 でも再取得していない |
| Merge BLOCKED（G2〜G10） | E18 の `merge_state` [実測] | 同上。PR #14 の BLOCKED は人手報告（H02）のまま |
| Gate provenance（AC25） | Job log（E16）からの抽出と github-evidence の Run 情報 | Job log の Hash がなく、上書き保存の経路で書かれた |
| App check と Report digest の結合 | Report artifact（E17）の `payload_sha256` を再計算できる [実測可能] | Artifact ファイル取得時の Hash がない |
| G11b Artifact Integrity | E28 / E29 の SHA-256、github-evidence の blob id 一致 [実測] | n=1 |
| G11b Environment 拒否 | E30、github-evidence の Annotation 転記 | 応答本文ではなく転記（EG10） |
| G12 B1〜B3 | E22 | 事前定義（`G12_EXPERIMENTS`）の作成時刻は検証不可（EG4） |

M1 で新しい Raw を取得しても、それは**新しい観測**であり、Phase 1 当時の値を証明しない（`m1-acceptance-test-matrix.md` M1-10）。

## 5. rev3 との Gap

| # | Gap | rev3 での扱い | M1 での扱い |
| --- | --- | --- | --- |
| AG-1 | §7 と Evaluator の不一致（S7-08 / 09 / 15） | AC27 §7 軸 FAILED（人手の再判定）、EG6 残存 | 条文1つに判定関数1つと Test を対応させる（M1-02）。Phase 1 値は変更しない |
| AG-2 | Raw 応答なし | EG10 として新規記録 | Raw Evidence Collector / Store（M1-04） |
| AG-3 | `isRequired` の再取得なし | EG11 | M1 では取得しない（GitHub API 禁止の WP0 範囲外、取得は Human 承認後の P2）。欠損として検出できることを M1-06 / M1-10 で示す |
| AG-4 | Evidence ID → ファイルの対応が文書の表だけ | rev2 index（人手） | Legacy Evidence Map（ID、path、WP0 時点 SHA-256、provenance 区分）を機械可読化（M1-10） |
| AG-5 | 判定規則の版がない | 記録なし | Decision に Registry ID・Evaluator version・Source hash を入れる（M1-05） |
| AG-6 | 人手報告（H01〜H03）と API 実測の区別が文書だけ | [実測]/[人手報告]/[推論] の表記 | Provenance を Evidence Envelope の必須 field にする（M1-07） |
| AG-7 | rev2 / rev3 文書の作成時 Hash なし | rev1 のみ REVISIONS に記録 | WP0 時点の Hash を基準値として Legacy Map に入れる。作成時との同一性は NOT_PROVEN のまま |
| AG-8 | 公開 AC map が古い（AC42 PARTIAL） | EG8 | M1 の範囲外（`tests/unit/test_phase1_traceability.py` に影響、要承認） |

## 6. 結論

* §7 の required 軸（S7-08 / S7-09 / S7-15）は Helper に実装されておらず、既存 Test は §7 と逆の期待値を固定している。現行 Evaluator は E18 に対して G3 / G3S / G6 = PARTIAL を出す。Phase 1 rev2 / rev3 の FAILED は、§7 の文言を人手で適用した結果であり、Evaluator の出力ではない。
* Phase 1 の判定はいずれも変更しない。M1 の目的は、同じ不一致が再発しないこと（条文 → 判定関数 → Test の1対1対応と Mutation Test）と、判定の入力を Raw に結び付けることである。
