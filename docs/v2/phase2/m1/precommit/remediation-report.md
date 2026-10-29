# Phase 2 M1 — Pre-Commit Remediation Report

* Source: Pre-Commit Remediation の指示（C-1〜C-3、S7-01、Final Quality Gate）、`precommit-audit.md`、`publication-file-manifest.md`、`s7-19-interpretation-review.md`、`definition-versioning-policy.md`、Final Quality Gate attempt 1 の記録（`.agents/tasks/phase2-m1-precommit/frozen-gate-attempt1/`、Git 管理外）
* 目的: Human の決定を適用した結果と、修正後の再検証の結果を記録する
* 状態: 修正とローカル再検証まで。**Git Add、Commit、Push、PR、CI 変更、GitHub API アクセスはしていない**。HEAD `4bd6e015d88b01d34dc83dc2b2d2ffb0058358b2`。Phase 1 の原本・Helper・Test・Evidence は変更していない

## 1. C-1: 公開識別子

| ID | 適用 | 対象 | 変更前 → 変更後 SHA-256 |
| --- | --- | --- | --- |
| PC-1 | GitHub Account 名を `<account>` に置き換え（2か所） | `docs/v2/phase2/m1/wp0/repository-baseline.md` L51、`docs/v2/phase2/m1/wp0/m1-acceptance-test-matrix.md` L27 | `bb44137d…5f029e` → `2f6802ea…`、`80c11183…0235ae` → `bab8cb63…` |
| PC-2 | 実在の App id と Check Run id（5件）を伏せ字に置き換え | `docs/v2/phase2/m1/wp0/acceptance-alignment-audit.md` L58〜L62（`<App id>`、`<check_run 1>`〜`<check_run 5>`。GitHub Actions の公開 App id 15368 は維持） | `911317ea…6ed1f3` → `d56996cb…` |
| PC-2 | 合成 Test の実在値を合成値に置き換え: Check Run id → `900000001`、`external_id` の Run id → `900000002`、App id → `1000001`（`evidence_synth.py` の合成 App id と同じ値） | `tests/unit/test_evidence_secretgate.py` L161〜L163 | `b80e76e1…e939ee` → `c782f29e…` |
| PC-3 | Demo の Commit SHA（`049f19e…`）と Run id は、照合に必要な箇所だけ維持 | `iacreview/evidence/legacy/phase1-legacy-evidence-map.v1.json`（Run id を含む File 名は、非公開 Evidence を SHA-256 で照合するための Locator）、`docs/v2/phase2/m1/wp5/wp5-acceptance-report.md` §4-2（G11 の照合に使う Commit） | 変更なし |
| — | `.agents/` の相対 Path | Legacy Map（135件）、WP5 文書 | 維持。Secret・認証情報・Targets・PEM・Token の Path は0件（`.pem`、`key`、`token`、`secret`、`cred`、`targets`、`.env` を含む Path の検索で0件）。個人の絶対 Path は0件 |

差分（値は伏せて記録）:

```text
repository-baseline.md L51      `<実在の Account 名>` を含む  →  `<account>`（匿名化。Pre-Commit Remediation C-1）を含む
m1-acceptance-test-matrix.md L27 `<実在の Account 名>` 等のアカウント名 →  `<account>` 等のアカウント名（匿名化。…）
acceptance-alignment-audit.md   REST app_id <実在の7桁> → REST app_id `<App id>`；check_run <12桁 ×5> → `<check_run 1>`〜`<check_run 5>`
test_evidence_secretgate.py     "id": <実在の12桁> → 900000001；"external_id": "<実在の Run id>.1:" → "900000002.1:"；"app": {"id": <実在の7桁>} → 1000001
```

変更前のファイルは `.agents/tasks/phase2-m1-precommit/before/` に保全した（Git 管理外）。

確認: 新規候補83件（本書を除く）に、Account 名、個人の Home Path、実在の App id を含むファイルは0件（Gate 12 の Clean Copy で検索）。

範囲外の事実: 既に Commit 済みの tracked ファイル13件（`README.md`、`plugin.json`、`CHANGELOG.md`、`iacreview/sarif.py`、`docs/v2/phase1/` の文書など）には、この Repository の公開 URL として Account 名が含まれる。`docs/v2/phase1/app-demo-plan.md`（tracked、Phase 1 原本）には App id がある。どれも今回の Commit 候補ではなく、Phase 1 原本は変更禁止のため触れていない。

## 2. C-2: S7-17 / S7-18 / S7-19 の Definition・Rule・Test の整合

### 2-1. 原文で FAILED が成立するか

| Criterion | 原文（`docs/v2/phase1/app-demo-plan.md` §7） | FAILED の条件 | 判定 |
| --- | --- | --- | --- |
| S7-17 | 「Anyone who already holds the key can post a same-App success; that stays a limit (`same_app_with_key`), not a pass.」 | なし。限界として記録する文で、違反の条件を書いていない | 成立しない |
| S7-18 | 「Recorded as NOT_PROVEN with the reason: G8 (…), AC28 (…), admin bypass (…), `same_app_with_key`.」 | なし。NOT_PROVEN として記録することだけを定める | 成立しない |
| S7-19 | 「Not verified until the run: whether … ; whether … ; whether … ; whether … (if not, BLOCKED runs still publish failure).」 | なし。問いの列挙。望ましくない答えは S7-08 / S7-15（Impostor）、S7-03b / S7-07（失敗の Publish）が FAILED にする | 成立しない |

### 2-2. 適用した変更

* Definition v1（未 Commit）: 3 Criterion の `expected_result.violated` を `FAILED` → `NOT_PROVEN`。`satisfied` と `evidence_missing`、`criterion_text` は変えていない。SHA-256 `efd934b0…6cdbf8` → `fb4ddef0b86d36e436e4492e1ff2d209812e80b6e993dea47ba07dc7a856b1d0`。`definition_version` は 1 のまま（未 Commit のため。`definition-versioning-policy.md` §3-4）
* Rule Catalog（`rules.py`）: `RuleSpec.outcomes`（Rule が出せる状態の集合）を追加。S7-17 / S7-18 は `{NOT_PROVEN}`、S7-19 は `{PASS, NOT_PROVEN}`、他の21 Rule は3状態すべて。NOT_PROVEN を含まない宣言は `catalog_problems()` が拒否
* Registry（`registry.py` `_check_reachable_outcomes`）: `expected_result` の値の集合が、Rule の `outcomes` と一致しなければ拒否する。Rule が出せない値（例: S7-19 の `violated = FAILED`）と、Rule が出せるのに Definition が書いていない値（例: S7-08 の FAILED の欠落）の両方
* Rule のコードは変えていない（S7-01 の接続を除く。§3）

### 2-3. 追加した Test

| Test | 内容 |
| --- | --- |
| `tests/unit/test_evidence_rule_outcomes.py::test_every_declared_outcome_set_matches_the_rule_code` | 24 Rule の宣言を、Rule 関数（と同じ Module の呼び出し先）の AST から求めた出力の集合と照合。比較式の中の定数は出力に数えない |
| `test_the_limits_and_the_open_questions_never_produce_failed` | S7-17 / S7-18 / S7-19 の宣言とコード |
| `test_the_shipped_definition_agrees_with_the_reachable_outcomes` | 出荷する Definition が整合 |
| `test_an_intentional_mismatch_is_refused`（5件） | S7-19 / S7-17 の `violated = FAILED`、S7-18 の `satisfied = PASS`、S7-08 の `violated = NOT_PROVEN`、S7-19 の `satisfied = NOT_PROVEN` をそれぞれ拒否 |
| `test_a_catalog_entry_without_not_proven_is_inconsistent` | NOT_PROVEN を含まない宣言を拒否 |
| `test_the_definition_is_not_changed_to_fit_a_rule` | 3 Criterion の `criterion_text` が原文の引用のまま |

S7-19 の I-1〜I-6 と、Assertion が不足していた4経路（`tests/unit/test_evidence_report.py`）:

| 解釈・経路 | Test |
| --- | --- |
| I-1 FAILED を返さない | `test_s7_19_i1_never_failed`（6件の Parametrize） |
| I-2 Q1 / 経路1: App check `isRequired = false` の反例 | `test_s7_19_i2_q1_counterexample_from_an_app_check_not_required` |
| I-2 Q1 の全肯定と部分 | `test_s7_19_i2_q1_all_three_spoof_scenarios_settle_honours` |
| I-3 Q2 / 経路2: Pin のない Ruleset | `test_s7_19_i3_q2_a_ruleset_without_the_pin` |
| I-3 Q2 / 経路3: Ruleset 未観測 | `test_s7_19_i3_q2_no_ruleset_observed` |
| I-3 Q2: Pin があっても答えではない | `test_s7_19_i3_q2_a_pinned_ruleset_is_still_not_an_answer` |
| I-4 Q3 | `test_s7_19_i4_q3_is_never_answered` |
| I-5 Q4: 4 Criterion が必要、Digest 不一致は「届かなかった」としない | `test_s7_19_i5_q4_reached_needs_all_four_criteria` |
| I-5 Q4 / 経路4: Gate Run 未完了 | `test_s7_19_i5_q4_gate_run_not_completed_on_the_head` |
| I-6 宣言時だけ LIMIT_DECLARED | `test_s7_19_i6_limits_only_when_declared` |

Mutation Test の追加: MU-30（Registry の照合を外す）、MU-31（S7-01 が空でも PASS）、MU-32（S7-01 が未 Binding の Evidence を使う）。

## 3. S7-01 の Final Report への接続

* Evaluator: S7-01 を全 Scenario の Criterion に追加した。Native Replay では、S7-01 が求める3 Role（`rollup`、`check_runs`、`gate_run`）の Evidence がすべて Snapshot に Binding されているときだけ、WP2 の Rule（`raw_api_data_stored`）を Store の検証結果に対して実行する
  * Role がない → NOT_PROVEN `required_role_missing:<role>`
  * Binding されていない → NOT_PROVEN `evidence_not_bound`
  * Store が検証を通らない → NOT_PROVEN `store_integrity_not_verified`
  * Evidence の指定が空 → NOT_PROVEN `no_evidence_named`（WP2 の Rule）
  * Store の Evidence が渡されない評価（単体の `evaluate_scenario`）→ NOT_PROVEN `store_evidence_not_supplied`
  * Legacy 再評価 → NOT_PROVEN `raw_unavailable`（Helper は Raw 応答を残していない）
* S7-01 は報告軸 `evidence_recording` に入る。§7 の4 Part の合成（`s7_result`）と `phase2_result` には入れていない（§7 冒頭は合成を「four parts」で定めている）
* Final Report: `evidence_recording`（Scenario ごとの状態、件数、全体）を追加。全体は「1 Scenario 以上で評価され、すべて PASS」のときだけ PASS。空は NOT_PROVEN（`test_an_empty_s7_01_set_is_never_pass`、MU-31）
* Evaluator Source の Hash 対象に `rule_s7_evidence.py` を追加

### 26 Criterion の Coverage

| 数え方 | 修正前 | 修正後 |
| --- | --- | --- |
| Rule が IMPLEMENTED | 26 / 26 | 26 / 26 |
| rule_behaviour Test が IMPLEMENTED | 26 / 26 | 26 / 26 |
| Evaluator の結果に判定が出る | 25 / 26（S7-01 なし） | **26 / 26**（Scenario の23種 + S7-02 の合成 + S7-18 + S7-19） |
| Final Report に出る | 25 / 26 | **26 / 26**（S7-01 は `evidence_recording`） |
| 合成 Native Replay で Scenario ごとに判定（7 Scenario） | 22種 | 23種、89件（PASS 81 / FAILED 4 / NOT_PROVEN 4）。S7-01 は7 Scenario すべて PASS |
| Legacy 再評価で判定 | 22種 | 23種。S7-01 はすべて NOT_PROVEN `raw_unavailable` |
| PASS に到達しうる | 23 / 26 | 23 / 26（S7-17、S7-18 は常に NOT_PROVEN、S7-19 は現在の Evidence Role では PASS にならない） |
| 実 GitHub Raw で評価 | 0 | 0 |

## 4. C-3: 公開対象

* WP4 の旧結果 `docs/v2/phase2/m1/wp4/legacy-reevaluation-results.json`（`b17e6881…29f7d544`）を `.agents/tasks/phase2-m1-precommit/preserved/wp4-legacy-reevaluation-results.json` に複写し、byte 一致（`cmp`）を確認してから公開 Tree から削除した
* WP5 の結果は最終 Source から再生成した: `docs/v2/phase2/m1/wp5/legacy-reevaluation-results.json` `f205b5d4…70ed` → `731a1846ce5bb6102bea478fbc613b85ccb6b3cf90fc736dd62b8bbeaa8e1748`（119,224 bytes）。Gate 10 で再生成が byte 一致。旧版は `.agents/tasks/phase2-m1-precommit/preserved/` に保全。E18〜E21 の `s7_result` / `phase2_result` は旧版と全 Scenario で同じで、違いは S7-01（`raw_unavailable`）と Hash
* 再現できない結果への依存: WP4 の全文書6件、WP5 の文書6件（Quickstart と E2E 計画を除く）、Pre-Commit 監査の文書5件の冒頭に注記を入れ、旧 Hash が WP4 / Remediation 前の記録であることと、最終値が本書にあることを明記した。`tests/unit/test_evidence_legacy_reeval.py` の Comment も更新。WP4 の結果ファイルを読む Code と Test は0件（`grep`）

## 5. 修正前後の Hash

固定 Manifest: 修正前 `360d731b…18aec5`（703 files、WP5 文書を除外）→ 修正後 `ea8248311ad5efdd170f3732281a16e1177c042bd581687622205f51b110c515`（716 files、本書だけを除外）。同じ内容のファイルは 681件。変わったファイル:

| Path | 変化 | 変更前 SHA-256 | 変更後 SHA-256 |
| --- | --- | --- | --- |
| `docs/v2/phase2/m1/precommit/definition-versioning-policy.md` | 追加 | — | `d436eedf4daa7faa9cb5d7d455777b32d5f8895195fdc788433cdce3a985be44` |
| `docs/v2/phase2/m1/precommit/precommit-audit.md` | 追加 | — | `5e748cf5bb0d99f5f4a42e6494e6e15a14edaefa379cd1c4f7cbbf33c03f902f` |
| `docs/v2/phase2/m1/precommit/precommit-decision.md` | 追加 | — | `5d6af84a3f2042a79af3592768ffa15986b4530551a66c5153f677639d44bb2d` |
| `docs/v2/phase2/m1/precommit/publication-file-manifest.md` | 追加 | — | `9cf23f5539cefa556adb2424703f229af4d8caae7a8cc9152dbd028038e408ca` |
| `docs/v2/phase2/m1/precommit/s7-19-interpretation-review.md` | 追加 | — | `7eefd1d8461d9a58644e202a0bb51e88a2d9d80edbe7811eac1d479b41f471cf` |
| `docs/v2/phase2/m1/wp0/acceptance-alignment-audit.md` | 変更 | `911317ea2138e5f9d666a9901544d460b55f8f298ed9c1e7bede02b0ce6ed1f3` | `d56996cb5af47c0fb66d779c1751b9270008ca72251b01a15f607f1791ce5c92` |
| `docs/v2/phase2/m1/wp0/m1-acceptance-test-matrix.md` | 変更 | `80c111832cdbabb7b190744bf984fe7d4277046b2d216e390c5f165bb50235ae` | `bab8cb63b802c062d1d788acbca6054a8c00eed62f3653816986f662cafecbb3` |
| `docs/v2/phase2/m1/wp0/repository-baseline.md` | 変更 | `bb44137d1611d0ecf49729ab32f3b39ab4d96a49b214acf7ab139c362f5e029e` | `2f6802ea34764f5fa062a40d7b9aee2f6d16b5f30ecc22323911db666f15bf94` |
| `docs/v2/phase2/m1/wp4/evaluator-rule-coverage.md` | 変更 | `ec637a28f2011a0a0c7bc8383be2226a98e292b99d465eabdd3055198867fe54` | `cda7dde663136e140bf389f4e9f7228e374e1c796694442fbb5ca8619f86900b` |
| `docs/v2/phase2/m1/wp4/legacy-reevaluation-differences.md` | 変更 | `8bbafaa5fdb4752436d778abc8c7576dd2fc308015ea7a259646df6150920493` | `2b11865a8ded5fada25bb220e2eca77ecb0e757463841ce376beb38ffec625f4` |
| `docs/v2/phase2/m1/wp4/legacy-reevaluation-results.json` | 除外 | `b17e6881d20e27987da62716595629212afcdcf0529d9f313e26474a29f7d544` | — |
| `docs/v2/phase2/m1/wp4/mutation-test-results.md` | 変更 | `ec8be0c22e73afe37fbfabaa39084e2bcb6a98ce8f591a1d1a21f1a2af73f2f4` | `8280475ba8290be7bfe68fd2b062a7eab0216feefa89703efa8bb8657dbc4a0e` |
| `docs/v2/phase2/m1/wp4/replay-reproducibility-report.md` | 変更 | `666f078109d855e64ec898729bf4fb83190eea6ff3c094706eb13126e7d089b5` | `1fb4047c8f67591ac893cd8d77ee77a13720ca88008968617e3fbb80c35be32e` |
| `docs/v2/phase2/m1/wp4/wp4-acceptance-report.md` | 変更 | `3a4ef9e863b95f016022bd1226bffb6446a34d79b8a09950e94a4bdf1e6e95ce` | `97256b69f287d7ae54e79fe76f698cd21c6a185ae09bd798a604021ff9cb9057` |
| `docs/v2/phase2/m1/wp4/wp4-architecture-note.md` | 変更 | `866ca2289fc91339268b75499d442dd4acc1010529c5a5e55f1f0a3f2bea0aa8` | `06c49ceabb7002621ca14baac969dab00d652594dd8ab9f4ad4e5c049d996480` |
| `docs/v2/phase2/m1/wp5/legacy-reevaluation-results.json` | 変更 | `f205b5d4e9b1d8b91c8c35869dec7972d918215cefebbdc17d24590ad9bb70ed` | `731a1846ce5bb6102bea478fbc613b85ccb6b3cf90fc736dd62b8bbeaa8e1748` |
| `docs/v2/phase2/m1/wp5/m1-final-ac-matrix.md` | 変更（WP5 文書。旧固定範囲の外。変更前は先頭16桁のみ記録） | `8fa65265897a633a…` | `8f9ae6a9e054d0c5ee1ccc401339950255f8cbe748784a77570a7f4764cf698f` |
| `docs/v2/phase2/m1/wp5/m1-integration-test-results.md` | 変更（WP5 文書。旧固定範囲の外。変更前は先頭16桁のみ記録） | `ab1c74299b3511a8…` | `3faef60212896433fddbff6be559b25409ea87ae9f8e5cc99cbfb0709863b414` |
| `docs/v2/phase2/m1/wp5/m1-known-limitations.md` | 変更（WP5 文書。旧固定範囲の外。変更前は先頭16桁のみ記録） | `004e9478c915c03b…` | `2f75756f2a17d4732fabfe0cedcf7e5e95510e0b7a24b5563cce54545d4024d5` |
| `docs/v2/phase2/m1/wp5/m1-reproducibility-report.md` | 変更（WP5 文書。旧固定範囲の外。変更前は先頭16桁のみ記録） | `d4abf27fc30f7ab0…` | `54fd4d4334dac5597d96fff5bc8038206fc206ef72a03c58e321fdcc5754242e` |
| `docs/v2/phase2/m1/wp5/m1-security-regression.md` | 変更（WP5 文書。旧固定範囲の外。変更前は先頭16桁のみ記録） | `5c46d9fa7aff6230…` | `99d41ee447620fd3eecf420d200577442a29faaa8bb0bcee6133d1f6531c1efd` |
| `docs/v2/phase2/m1/wp5/oss-quickstart.md` | 変更（WP5 文書。旧固定範囲の外。変更前は先頭16桁のみ記録） | `70c512e9c70fa842…` | `318252181e888fcfcf7f90cb26b5f87d8f9863096c52bfab2b181ae5bee2c37f` |
| `docs/v2/phase2/m1/wp5/wp5-acceptance-report.md` | 変更（WP5 文書。旧固定範囲の外。変更前は先頭16桁のみ記録） | `b9cda0cd9b4a1ef7…` | `3c0a0261d25f898776d7305400d8d41651c556aeed1729355ff772f553690985` |
| `iacreview/evidence/definitions/phase1-app-demo-s7.v1.json` | 変更 | `efd934b0badd8cbdc50ec13fcc0be4dec0e501ad26bf0507f546dd6d36e28589` | `fb4ddef0b86d36e436e4492e1ff2d209812e80b6e993dea47ba07dc7a856b1d0` |
| `iacreview/evidence/evaluator.py` | 変更 | `68bb38b3bd08b5c173f572387243bbbc5f5968172efb92f755a783878349e85d` | `95edaa53a9566e1804e19e4126ecad2ddff83c827e78d0854e8a9d8d713e8e06` |
| `iacreview/evidence/final_report.py` | 変更 | `6be7e135fe35cfef1ff9aa1c3ff29b458c3a6345377df0cd85e52ee1c17a8135` | `7243ab38c08621d2248911d000c4c635dd4302ad3ef757934ecbe1bc9ed347ea` |
| `iacreview/evidence/registry.py` | 変更 | `3f91ec26477b7a78f10bed5891f0829d95f2c58b537ebf1e37ae550dbcd6c7ef` | `007df0b702285f6d76f9c650294fce5697df0e3d3fdcad8031ce514f92e32b6e` |
| `iacreview/evidence/rules.py` | 変更 | `f8a553fcb4fc9678c3b1725e27cf95b5306cab34e237aa0f9905e03dfbdb5bee` | `5d9271d14f569d95ff627ab69684c4ef00cbf61c8af6d2f695d1ce6ae89ae27c` |
| `tests/mutation/evidence_mutants.py` | 変更 | `dc461e7bb3952f7011e63d3ea2cdf6d2aa2f3855e8134ad115b5fb139fbef51c` | `1110f411b9a671bc391c09720dd83e26790d31ef4bd3789d15c8679663ba3b79` |
| `tests/unit/test_evidence_legacy_reeval.py` | 変更 | `dcee1cb15722261db08a306183b24aac89dd71b37c323be3831a5dc1db42ffd2` | `8dca3704663e7c8ced12649139ce1017c2e6d3835f09966f9209c8f8b2f1a3c1` |
| `tests/unit/test_evidence_mutations.py` | 変更 | `c5ef6986a794db678e34f162309fc64e21806da829233914b6268a6ae900c96e` | `4d1923cd717221e07904dc72e13a0b38ffb85e182cb4d37db1dcd5192166afbe` |
| `tests/unit/test_evidence_pipeline.py` | 変更 | `f5a3bc5243bfe3780c7003ad07fe7392692ae1371d9151857ac58a9f014c67f3` | `b927e921c7b38c5eb1cd8f37a3ea6ed87ffc0faa822ffb1774eae4a99b51a729` |
| `tests/unit/test_evidence_report.py` | 変更 | `738c922419e8e12fefad52be9e123fcfbb5d6514e7db11164c43a476915a2f75` | `8ee6090903b31d2e0e82eecbd9a081a42632b5d0d853b580ff0e5c68fe65fd8c` |
| `tests/unit/test_evidence_rule_outcomes.py` | 追加 | — | `3ce2d70806feaf872db8333d326d4bc3637e9c70538c899b875e24744deedd41` |
| `tests/unit/test_evidence_secretgate.py` | 変更 | `b80e76e1b2cc6ebf65fa34580ca235825adad6bcc9ccc8b2da9be1aa9ec939ee` | `c782f29eaa1ace450753ed1aad0bcd9598f308aa2f7b10b5a4ec76832affc5a8` |

Evaluator Source の SHA-256: `dfaec952…6cdbf8` → `ee765e0c18ba76b9d4a27a0d4277548f21296757f03a77879763d1824dae58d6`。`EVALUATOR_VERSION` の文字列は `…/1` のまま（規則 E-1 は未採用のため）。

## 6. 変更・追加・除外したファイル

* 変更（Source）: `iacreview/evidence/evaluator.py`、`final_report.py`、`registry.py`、`rules.py`、Definition v1
* 変更（Test）: `tests/unit/test_evidence_secretgate.py`（合成値）、`test_evidence_report.py`、`test_evidence_pipeline.py`、`test_evidence_legacy_reeval.py`（S7-01 の期待値、Comment）、`test_evidence_mutations.py`（32件）、`tests/mutation/evidence_mutants.py`（MU-12 の対象行、MU-30〜32）
* 追加（Test）: `tests/unit/test_evidence_rule_outcomes.py`
* 変更（文書）: WP0 の3件（匿名化）、WP4 の6件（注記）、WP5 の7件（注記、Quickstart に `evidence_recording`）、Pre-Commit 監査の5件（注記。`publication-file-manifest.md` は Account 名の削除も）
* 再生成: `docs/v2/phase2/m1/wp5/legacy-reevaluation-results.json`
* 除外（非公開で保全）: `docs/v2/phase2/m1/wp4/legacy-reevaluation-results.json`
* 追加（文書）: 本書

既存 Test の期待値変更（5回目）: `test_legacy_rows_are_judged_by_the_same_rules`（G2 の NOT_PROVEN 理由に `raw_unavailable` が加わる）、`test_evidence_mutations.py`（Mutant 数 29 → 32）、`test_the_whole_path_from_capture_to_final_report` と `test_an_incomplete_revision_is_refused`（S7-01 の Assertion を追加）。Assertion の緩和、Skip、削除はしていない。

## 7. Final Quality Gate（attempt 1、採用）

固定: Manifest `ea824831…c515`（716 files）。各 Gate の開始時・終了時に Manifest、Git Status、Phase 1 の15ファイルの Hash、HEAD を照合し、12 Gate すべてで固定時と一致した（Summary `818f90cf919d4ac9ab8596f69912070e2858c5cd0052941b628c05fa9ad85f8b`）。途中で対象ファイルを変更していないため、再実行は不要だった。

| # | Gate | exit | 結果 | 秒 |
| --- | --- | --- | --- | --- |
| 1 | Full pytest + coverage | 0 | 7,714件: PASS 7,678 / FAIL 0 / SKIP 36、coverage 95.10%（12,049 statements、miss 591） | 696 |
| 2 | Evidence Test | 0 | 478 passed | 31 |
| 3 | Benchmark | 0 | PASS、17 Case（PASS 13 / INFO 4）、matched 34 / 34、FP 0、FN 0、errors 0 | 22 |
| 4 | Determinism | 0 | 1 passed | 29 |
| 5 | Ground Truth | 0 | 17 / 17 verified | 6 |
| 6 | Phase 1 Helper Regression | 0 | 516 passed | 72 |
| 7a | ruff（iacreview） | 1 | 5 errors（Baseline と同じ） | 6 |
| 7b | ruff（M1 の Path） | 0 | All checks passed | 5 |
| 7c | mypy | 1 | 12 errors in 7 files（Baseline と同じ）、`iacreview/evidence` 0件 | 7 |
| 8 | Public Preflight | 0 | 8 Check PASS、716 files | 9 |
| 9 | Secret Scan | 0 | 0 finding、633 files（tracked mode） | 9 |
| 10 | Replay byte comparison | 0 | Native: 同一 Process 4回・別 Process 4回（exit 0）で `24f091d1f8be65603a4d5d2cd62052758295155e00be200b59a8ff45238a2a48`（49,056 bytes）、Final Report 4回で `4b1f2c5441ea9a421bdb0b8d402a608acbf96ced7f128d30f443939746f55b47`。Legacy 再生成が byte 一致 `731a1846…1748` | 7 |
| 11 | Mutation Test | 0 | Baseline 39 passed、Killed 32 / 32（結果 JSON `05de53f31a44b540ccc65fa6c2ef294925698c60afece5079843966a596fd3d8`） | 22 |
| 12 | Clean Checkout Test | 0 | 716 files、新規83件に Account 名・Home Path・実 App id 0件、Evidence Test 473 passed / 5 skipped、Quickstart の全手順が期待どおり（結果 `ce0c1c00…12a6`、Report `f983ed24…0d9e`、改変後 exit 4 `SNAPSHOT_CHANGED`） | 32 |

Mutation の検出率は、実施した32 Mutant の集合に対する値で、一般的な欠陥検出率ではない。Clean Checkout の SKIP 5件（Phase 1 の非公開 Source がない3件、git Checkout でない1件、検証済み Commit がない1件）は PASS に数えていない。

### 3つのファイル集合の差

| 集合 | 件数 | 内容 |
| --- | --- | --- |
| 固定 Manifest | 716 | `git ls-files -co --exclude-standard`（tracked 633 + 新規83）。本書は Gate の前に存在しなかった |
| Public Preflight（Gate 8） | 716 | 同じ集合 |
| Clean Checkout（Gate 12） | 716 | 同じ集合 |
| Public Preflight（本書の作成後、§8） | 717 | 上記 + `docs/v2/phase2/m1/precommit/remediation-report.md` |

固定範囲から除外したのは本書1件だけで、本書は Gate の結果を記録するため Gate の後に書いた。本書は Source、Fixture、Definition、生成 JSON を含まない。

## 8. Gate 後の確認

| 確認 | Command | exit | 結果 |
| --- | --- | --- | --- |
| 固定範囲の不変 | Manifest の再計算（本書を除外） | — | `ea824831…c515`（固定時と一致） |
| Docs Test | `python3 -m pytest -p no:cacheprovider tests/unit/test_docs.py tests/unit/test_root_docs.py` | 0 | 165 passed |
| Public Preflight | `python3 .github/scripts/public_preflight.py` | 0 | 8 Check PASS、717 files（本書を含む） |
| Secret Scan | `python3 .github/scripts/scan_secrets.py` | 0 | 0 finding、633 files（tracked mode） |
| 識別子の検索 | 新規84件に対する Account 名・Home Path・実 App id の検索 | — | 0件 |

この確認の後、本節の記入以外に変更していない。

## 9. Commit 候補の一覧

`.gitignore`（変更）と、新規84件（本書を含む）。`git add` はしていない。

初回ローカル Commit の承認時に、`definition-versioning-policy.md` に §4（確定した更新規則と初回 Baseline）を追記した。このため、本表のその行と本段落だけを更新し、最終品質検証を最初から再実行した。再実行の結果は Commit 時の記録（`.agents/tasks/phase2-m1-commit/`、Git 管理外）にある。

| # | Path | SHA-256（固定 Manifest） |
| --- | --- | --- |
| 0 | `.gitignore`（変更、5行追加） | `25bd42119aa09e5130eb77985bd6581bcef95abb4e1482e5201c4dd08c4efe4f` |
| 1 | `.github/scripts/public_preflight.py` | `70ccd44f100021afce9885ea91f28c9fb0b08bee5d00be2ee4c169edd4756406` |
| 2 | `docs/v2/phase2/m1/precommit/definition-versioning-policy.md` | `562a862f85ba568a22063a4a1d754a6ae53a948e1e47d2d4f4485b992b7887c4`（§4 を追記した後の値。追記前 `d436eedf4daa7faa…`） |
| 3 | `docs/v2/phase2/m1/precommit/precommit-audit.md` | `5e748cf5bb0d99f5f4a42e6494e6e15a14edaefa379cd1c4f7cbbf33c03f902f` |
| 4 | `docs/v2/phase2/m1/precommit/precommit-decision.md` | `5d6af84a3f2042a79af3592768ffa15986b4530551a66c5153f677639d44bb2d` |
| 5 | `docs/v2/phase2/m1/precommit/publication-file-manifest.md` | `9cf23f5539cefa556adb2424703f229af4d8caae7a8cc9152dbd028038e408ca` |
| 6 | `docs/v2/phase2/m1/precommit/remediation-report.md` | 本書（固定範囲の外。Gate の後に作成） |
| 7 | `docs/v2/phase2/m1/precommit/s7-19-interpretation-review.md` | `7eefd1d8461d9a58644e202a0bb51e88a2d9d80edbe7811eac1d479b41f471cf` |
| 8 | `docs/v2/phase2/m1/wp0/acceptance-alignment-audit.md` | `d56996cb5af47c0fb66d779c1751b9270008ca72251b01a15f607f1791ce5c92` |
| 9 | `docs/v2/phase2/m1/wp0/helper-audit.md` | `b5da5fa54613761e6823bcf06128a50619a9044ef3a42da388726d4ad5ce547a` |
| 10 | `docs/v2/phase2/m1/wp0/m1-acceptance-test-matrix.md` | `bab8cb63b802c062d1d788acbca6054a8c00eed62f3653816986f662cafecbb3` |
| 11 | `docs/v2/phase2/m1/wp0/m1-architecture-proposal.md` | `afd3a97158755e3eb9d383774cfeed238e9c6605c633a1ec5284717744731b0e` |
| 12 | `docs/v2/phase2/m1/wp0/repository-baseline.md` | `2f6802ea34764f5fa062a40d7b9aee2f6d16b5f30ecc22323911db666f15bf94` |
| 13 | `docs/v2/phase2/m1/wp1/wp1-acceptance-report.md` | `7a6d29943da6c2773650dd4a3569f93967d87f00657cafe29cbf5e1fd3bd07c4` |
| 14 | `docs/v2/phase2/m1/wp1/wp1-architecture-note.md` | `a0ecad7717228df60b8114fbe29d2ac5d70079e5d8c2a30689c11a9d13519877` |
| 15 | `docs/v2/phase2/m1/wp2/wp2-acceptance-report.md` | `d0ae21391197ed9694846b4b960df5f8a87d908f9f8443474f4825e1b7c6ebf3` |
| 16 | `docs/v2/phase2/m1/wp2/wp2-architecture-note.md` | `b027e7878be7fd138e381ddc24125eb7e16bd30cccd00828fd29866dee62453b` |
| 17 | `docs/v2/phase2/m1/wp3/raw-evidence-security-policy.md` | `adea3e540ef760e763371bdf323d628ef048221cf9faab6122b4c82e93ce2b0b` |
| 18 | `docs/v2/phase2/m1/wp3/wp3-acceptance-report.md` | `7bb18f58d9d012ce587e438652722b6e17a54a7fede6f685572459e5bf179084` |
| 19 | `docs/v2/phase2/m1/wp3/wp3-architecture-note.md` | `145f3d025e5a7b3a14564f34a91b9601f6cbc4bfdda02f19b259e5402ed27fb1` |
| 20 | `docs/v2/phase2/m1/wp4/evaluator-rule-coverage.md` | `cda7dde663136e140bf389f4e9f7228e374e1c796694442fbb5ca8619f86900b` |
| 21 | `docs/v2/phase2/m1/wp4/legacy-reevaluation-differences.md` | `2b11865a8ded5fada25bb220e2eca77ecb0e757463841ce376beb38ffec625f4` |
| 22 | `docs/v2/phase2/m1/wp4/mutation-test-results.md` | `8280475ba8290be7bfe68fd2b062a7eab0216feefa89703efa8bb8657dbc4a0e` |
| 23 | `docs/v2/phase2/m1/wp4/replay-reproducibility-report.md` | `1fb4047c8f67591ac893cd8d77ee77a13720ca88008968617e3fbb80c35be32e` |
| 24 | `docs/v2/phase2/m1/wp4/wp4-acceptance-report.md` | `97256b69f287d7ae54e79fe76f698cd21c6a185ae09bd798a604021ff9cb9057` |
| 25 | `docs/v2/phase2/m1/wp4/wp4-architecture-note.md` | `06c49ceabb7002621ca14baac969dab00d652594dd8ab9f4ad4e5c049d996480` |
| 26 | `docs/v2/phase2/m1/wp5/github-e2e-verification-plan.md` | `9e26209769ab664b98f79dbc2bb44642a136238625ff9acf26063cb38bf6b94a` |
| 27 | `docs/v2/phase2/m1/wp5/legacy-reevaluation-results.json` | `731a1846ce5bb6102bea478fbc613b85ccb6b3cf90fc736dd62b8bbeaa8e1748` |
| 28 | `docs/v2/phase2/m1/wp5/m1-final-ac-matrix.md` | `8f9ae6a9e054d0c5ee1ccc401339950255f8cbe748784a77570a7f4764cf698f` |
| 29 | `docs/v2/phase2/m1/wp5/m1-integration-test-results.md` | `3faef60212896433fddbff6be559b25409ea87ae9f8e5cc99cbfb0709863b414` |
| 30 | `docs/v2/phase2/m1/wp5/m1-known-limitations.md` | `2f75756f2a17d4732fabfe0cedcf7e5e95510e0b7a24b5563cce54545d4024d5` |
| 31 | `docs/v2/phase2/m1/wp5/m1-reproducibility-report.md` | `54fd4d4334dac5597d96fff5bc8038206fc206ef72a03c58e321fdcc5754242e` |
| 32 | `docs/v2/phase2/m1/wp5/m1-security-regression.md` | `99d41ee447620fd3eecf420d200577442a29faaa8bb0bcee6133d1f6531c1efd` |
| 33 | `docs/v2/phase2/m1/wp5/oss-quickstart.md` | `318252181e888fcfcf7f90cb26b5f87d8f9863096c52bfab2b181ae5bee2c37f` |
| 34 | `docs/v2/phase2/m1/wp5/wp5-acceptance-report.md` | `3c0a0261d25f898776d7305400d8d41651c556aeed1729355ff772f553690985` |
| 35 | `iacreview/evidence/__init__.py` | `6cfc743a2c047ecc5eeaca13edd9b9696537afbc565b1eb77ea52f5171ba45cc` |
| 36 | `iacreview/evidence/artifact.py` | `1ef926e000e6826d75a9fb31ec0f33ededce0858059c0b6f4c72bc295cd05b58` |
| 37 | `iacreview/evidence/canonical.py` | `91959db95fb2a5e06aeb3c3355ad2d76b8e15bd13b4cb233ee678a679eb46c89` |
| 38 | `iacreview/evidence/collector.py` | `84d751fcacf318998cbae500532ee4590a773ef995c6ba7c445e4515e30589fe` |
| 39 | `iacreview/evidence/definitions/phase1-app-demo-s7.v1.json` | `fb4ddef0b86d36e436e4492e1ff2d209812e80b6e993dea47ba07dc7a856b1d0` |
| 40 | `iacreview/evidence/envelope.py` | `774332eb6530f392072467e36d021282904457280945a52541fdfc560fa8bc9a` |
| 41 | `iacreview/evidence/evaluator.py` | `95edaa53a9566e1804e19e4126ecad2ddff83c827e78d0854e8a9d8d713e8e06` |
| 42 | `iacreview/evidence/facts.py` | `662fb5e12896679e9da862e6ddcf27dc7ae5cb324813fbd82d49c71425f5b865` |
| 43 | `iacreview/evidence/final_report.py` | `7243ab38c08621d2248911d000c4c635dd4302ad3ef757934ecbe1bc9ed347ea` |
| 44 | `iacreview/evidence/integrity.py` | `9165fb42282a0ffc20c670cd825f4074a03cc646801598ccc2efbec25cefce23` |
| 45 | `iacreview/evidence/legacy.py` | `8e2a1c985676fd294a567be86483a79850263283488f5f436529f148e3424d07` |
| 46 | `iacreview/evidence/legacy/phase1-legacy-evidence-map.v1.json` | `d0bd9342441234fc18246269ef16948a883fc8f6fa56e85ee105c3666c97df15` |
| 47 | `iacreview/evidence/legacy_reeval.py` | `3e55213d7df867f7c9dd86b1bac07d5bf26b5d204a65077a8c9c8be0449785f9` |
| 48 | `iacreview/evidence/open_questions.py` | `479025967e8f11ade944ca6e91dd6d9500ada5ea1ba36c7b1d34f65e014c49ba` |
| 49 | `iacreview/evidence/registry.py` | `007df0b702285f6d76f9c650294fce5697df0e3d3fdcad8031ce514f92e32b6e` |
| 50 | `iacreview/evidence/replay.py` | `141f81872df0012dd7771f58f34fc090af771fd9f1787fbe9f7ae4a48008e89c` |
| 51 | `iacreview/evidence/rule_s7_evidence.py` | `5d22859401aa235398c141c67e054df722ec403dfba772ccb2c378b060c0215f` |
| 52 | `iacreview/evidence/rules.py` | `5d9271d14f569d95ff627ab69684c4ef00cbf61c8af6d2f695d1ce6ae89ae27c` |
| 53 | `iacreview/evidence/rules_s7.py` | `83f79417d9c0a902c45bf9818edf820af23a85e7fe23dc812305f21b8af6c626` |
| 54 | `iacreview/evidence/schema/acceptance-definition.v1.schema.json` | `25e6e70f2e9e89af9a826b58ffbc293e3c612589f5fba0e32f44dab221ec8e33` |
| 55 | `iacreview/evidence/secretgate.py` | `a688c6ceb0e63aae681cc1bb7dbfe2c27c9217f205bb15f65091c1b8206479a9` |
| 56 | `iacreview/evidence/snapshot.py` | `88cb0cbbabb468dac62baacb0b45dbdbea9ef441517f7477a9c3e4267364ffbd` |
| 57 | `iacreview/evidence/store.py` | `4c95194da7cb9bf8fdb68f6f4e27a821419e3a3904c98b1cd34ef452aff9e8a6` |
| 58 | `tests/fixtures/evidence_raw/job_log_masked_header.json` | `ff38a66c8b0354b4142e291f215c1b1447718070afc4d955380ae2e4e8c1fb83` |
| 59 | `tests/fixtures/evidence_raw/rest_check_runs_safe.json` | `490b17fb69471acde2e40c0792eb3727865955b55a2674500a9a23323064e1bf` |
| 60 | `tests/fixtures/evidence_raw/rest_commit_with_email.json` | `3fd6bb14b63cb75d23f173391146000925d348797ff0b206845240c07309424f` |
| 61 | `tests/fixtures/evidence_raw/rest_http_error_404.json` | `109ea3ac03f05fd95fb980e8f76b8e113bb9bd96363cf43df433240355938556` |
| 62 | `tests/fixtures/evidence_raw/rest_installation_non_secret_urls.json` | `efdd98b3174ccf5998105b40e442c0c27276d2eec79a6923ba46d0366e9a548c` |
| 63 | `tests/fixtures/evidence_raw/rest_noreply_email.json` | `3ed2a666b70dde50f9cbef1194211573b7535b3d8cd0ff9a14f88b6409037c3f` |
| 64 | `tests/fixtures/evidence_raw/rest_pulls_page1.json` | `096d89518389ea6198c23cf3229d2eeab6b6b8d0d91840528a0e33916b936fbe` |
| 65 | `tests/fixtures/evidence_raw/rest_pulls_page2.json` | `5017a700933e8452b676ed732712f3937b0f2d401b856a929a077278fb97ae3e` |
| 66 | `tests/mutation/evidence_mutants.py` | `1110f411b9a671bc391c09720dd83e26790d31ef4bd3789d15c8679663ba3b79` |
| 67 | `tests/unit/evidence_synth.py` | `d5b4e6d96fe7e08cb1754191962684ba3412d0968f78549d52ca20e5f9fdea5f` |
| 68 | `tests/unit/test_evidence_artifact.py` | `70d55a427bcf5e67c76fb082a31a8ba575faf2eb89b47e3d44b76b98a728be8a` |
| 69 | `tests/unit/test_evidence_collector.py` | `5e6f785183e0888251203a0787a8b05886c4e40177ab0a3d5ac23dbcfdff08eb` |
| 70 | `tests/unit/test_evidence_evaluator_s7.py` | `53899eee96b4afc9b267990c473dda36151106e20379e78e0cd83ea41d489cba` |
| 71 | `tests/unit/test_evidence_integrity.py` | `01b77358e8e47783ff15bd33d19827d6ea7a388cf3f196a59a577caed7fcb82f` |
| 72 | `tests/unit/test_evidence_legacy.py` | `f43fba5f2b0b470c575891c4eb84ace474499a9173b882888ec0bd6264f236b9` |
| 73 | `tests/unit/test_evidence_legacy_reeval.py` | `8dca3704663e7c8ced12649139ce1017c2e6d3835f09966f9209c8f8b2f1a3c1` |
| 74 | `tests/unit/test_evidence_mutations.py` | `4d1923cd717221e07904dc72e13a0b38ffb85e182cb4d37db1dcd5192166afbe` |
| 75 | `tests/unit/test_evidence_pipeline.py` | `b927e921c7b38c5eb1cd8f37a3ea6ed87ffc0faa822ffb1774eae4a99b51a729` |
| 76 | `tests/unit/test_evidence_preflight.py` | `4bb28c019348f7353807637a613ae950e90bd5d30020043ff369b87300688fd6` |
| 77 | `tests/unit/test_evidence_raw_policy.py` | `4845f56358da037e28d5056c328cf47c8638036f00f233ce2c6effa97bdc5571` |
| 78 | `tests/unit/test_evidence_registry.py` | `a6a70fd768ad00b291e6e3b828ba93d5a576d4b584f0dc79714ab0f645aca585` |
| 79 | `tests/unit/test_evidence_replay.py` | `ee68a6a2ca0cce129342d76b09030d6a3ca3e8706ab5496f6175a1872e8257b5` |
| 80 | `tests/unit/test_evidence_report.py` | `8ee6090903b31d2e0e82eecbd9a081a42632b5d0d853b580ff0e5c68fe65fd8c` |
| 81 | `tests/unit/test_evidence_rule_outcomes.py` | `3ce2d70806feaf872db8333d326d4bc3637e9c70538c899b875e24744deedd41` |
| 82 | `tests/unit/test_evidence_s7_definition.py` | `1f15cad832ce329b78b20b271992b6eb2b822755ee4aacc40de81249679a2463` |
| 83 | `tests/unit/test_evidence_secretgate.py` | `c782f29eaa1ace450753ed1aad0bcd9598f308aa2f7b10b5a4ec76832affc5a8` |
| 84 | `tests/unit/test_evidence_store.py` | `4244d011ae8c6916ef82b055bf934e550326cbe47df5eff4fae6b3550ca30a2e` |

## 10. 未解決の NOT_PROVEN と Risk

* NOT_PROVEN: M1-01（未 Commit）、M1-10 の歴史的 Raw、実 GitHub Raw の End-to-End、`capture_authenticity`、第三者の独立再現、S7-17、S7-18、S7-19（Q2 / Q3）、P2-IP-01（G3 / G3S / G6）、G11 の Artifact Integrity と `phase2_result`、G7、Legacy 再評価の S7-01
* NOT_VERIFIED: CI 上の結果（History 照合は CI の浅い Checkout で Skip の見込み）、別 OS・別 Python Version、`legacy_reeval.main()` の exit 3 の経路、Spike 版 Workflow と Phase 1 で使った Gate Scripts（`f77a58c`）の一致
* Risk
  * Legacy Map は、非公開の Raw に近いファイル（Job Log、Report Artifact、Contents API の `content` Field）の相対 Path と Run id を Locator として持つ。内容は含まない。照合のために維持した（PC-3）。この扱いは Human の確認を要する
  * S7-01 を `s7_result` の合成に入れない設計は、§7 冒頭の「four parts」に基づく解釈で、Human の確認を要する
  * `EVALUATOR_VERSION` は Source が変わっても `…/1` のままだった。初回ローカル Commit の承認時に、`…/1`・Source `ee765e0c…`・Definition v1 `fb4ddef0…` を初回 Baseline とし、以降の更新規則を `definition-versioning-policy.md` §4 で確定した
  * 既存の tracked ファイルに Account 名（Repository の公開 URL）と、Phase 1 原本に App id がある（今回の範囲外）
