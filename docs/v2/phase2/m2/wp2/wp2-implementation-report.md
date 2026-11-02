# Phase 2 / M2 / WP2 — Implementation Report（Human Gate Record と Revision Binding）

* 状態: **ローカル実装・検証まで。** Commit、Push、PR、Merge、Ruleset 変更はしていない。GitHub Actions の結果は NOT_VERIFIED
* 改訂: Implementation Review（92/100、条件付き承認）の N2-2 / N2-3 修正を §8 に追記した。§1〜§7 は Review 前（rev1）の記録で、値は §8 で置き換わる
* 設計基準: `docs/v2/phase2/m2/wp0/` rev2（`wp0-revision-2.md` §8 を含む）、`docs/v2/phase2/m2/wp2/wp2-design-audit.md`
* Branch / HEAD: `feature/phase2-m2-wp2`、`336620859a5496b253bb347c40cbd462f45fb3ef`（Human が作成。Tree は `76e1b51` と同一であることを `git diff` で確認）

## 1. 変更ファイル

| 区分 | Path | 内容 |
| --- | --- | --- |
| 新規 | `iacreview/chain/gate.py` | Raw Capture の範囲検査（E-1〜E-7）、`page_sequence_problem`、Review の2段階集約、Gate Record の Builder / Schema 検査、GV-1〜GV-4、`regenerate` |
| 変更 | `iacreview/chain/links.py` | `check_gate` を `gate.check` に委譲（Record 0件は WP1 と同じ結果）、`LinkResult.aspects` と `gate_aspects` の出力 |
| 変更 | `iacreview/chain/status.py` | GV-1〜GV-4 の Reason Code 20件を追加。`gate_evaluation_not_implemented` は維持（D2-3） |
| 新規 | `tests/unit/test_chain_gate.py` | TC-08-01〜21、TC-09-01〜12、TC-10-01〜09・11 |
| 新規 | `tests/unit/test_chain_gate_replay.py` | Gate Anchor（3 Scenario）の仕様確認、4回の Replay、WP1 Anchor との分離 |
| 新規 | `tests/fixtures/chain_replay/expected-gate.json` | Gate 専用の Regression Anchor（D2-4） |
| 変更 | `tests/fixtures/chain_replay/expected.json` | WP1 Anchor の Revision 3（§4） |
| 変更 | `tests/unit/chain_synth.py` | 合成の pull / review Capture、Gate Record の書き出し、`GateChain`、Gate Anchor の Scenario |
| 変更 | `tests/mutation/chain_mutants.py`、`tests/unit/test_chain_mutations.py` | MU2-21〜29、MU2-33〜50 を追加（合計47） |
| 変更 | `.github/scripts/chain_ci_check.py` | `--expected` と同じ Directory の `expected-gate.json` を必須とし、形式・3 Scenario の Status・Validator Digest の一致を検査。必須 Test に WP2 の22件を追加（35 → 57） |
| 変更 | `tests/unit/test_chain_ci.py` | Test 用の期待値に Gate Anchor を追加。Gate Anchor の欠落・Digest 不一致・Status 違反の Test 3件を追加 |
| 変更 | `tests/unit/test_chain_status.py` | `test_tc_06_03_gate_records_are_not_evaluated_before_wp2` を `test_tc_06_03_a_self_declared_gate_record_is_never_a_pass` に置き換え（§6 N2-1） |

変更していないもの: `iacreview/evidence/`、`iacreview/remediation/`、M1 の期待値・Frozen Evidence、`.github/workflows/ci.yml`、`pyproject.toml`、`plugin.json`、`.gitignore`。

## 2. 実装した AC

| AC | 判定（ローカル） | 根拠 |
| --- | --- | --- |
| M2-08 GV-1 | PASS | TC-08-01〜21（Page 欠損・重複・未列挙、Review の重複・矛盾・語彙外、同時刻の競合、時刻順と id 順の食い違い、Dismissal、PII） |
| M2-09 GV-3 / GV-4 | PASS | TC-09-01〜12（古い Head への承認は NOT_PROVEN、Revision 偽装は BROKEN、PR Head 不一致は BROKEN、コードの区別） |
| M2-10 GV-2 | PASS（TC-10-10 は WP3） | TC-10-01〜09・11。`author_association` は判定に使わない（TC-10-06、静的検査 TC-10-08） |
| 統合 | PASS | 合成 Chain で COMPLETE（TC-10-07）、NOT_PROVEN、BROKEN、INCOMPLETE を再現 |

## 3. Test と Mutation（macOS、`/usr/bin/python3` 3.9.6）

| 項目 | Exit | 結果 |
| --- | --- | --- |
| Chain Test（`tests/unit/test_chain_*.py`） | 0 | 278件 PASS / FAIL 0 / SKIP 0、353 s |
| Chain CI Check | 0 | 必須57件、SKIP 0、Gate Anchor 3 Scenario、Validator Source 一致 |
| Chain Mutation | 0 | 47 / 47（WP1 の MU2-01〜20 と WP2 の27個） |
| 全体 pytest + coverage | 0 | 8,056件（PASS 8,020 / FAIL 0 / SKIP 36）、coverage 94.86%、1,085 s。M1 Mutation 32 / 32、Chain Mutation の Test も PASS |
| Clean Copy（公開対象のみ） | 0 / 0 | Chain Test 278件 PASS、CI Check PASS |
| M1 Evidence Test + CI Check | 0 / 0 | 519件、§5 の Hash 一致、`verified_commits` 5 |
| Benchmark / Determinism / Secret scan / Ground_Truth / Public Preflight | 0 | PASS / PASS / 0 finding（759 files）/ 17/17 / PASS（765 files） |
| `git diff --check` | 0 | 新規ファイルも行末空白・CRLF・末尾改行欠落 0件 |
| ruff / mypy | 1 / 1（advisory） | 40件 / 12件（Baseline と同じ）。`iacreview/chain/` は0件 |

Mutation の経過: 初回は MU2-38（Page 番号の飛びを受け付ける）が生き残った。M1 の V5 が同じ条件を検出するため、Gate 側の検査を外しても Chain の結果が変わらなかった。Gate 側の規則を `page_sequence_problem` に分け、直接の Test（`test_tc_08_11_the_page_sequence_rule`）を追加して再実行し、47 / 47 になった。

## 4. Hash の差分

| 項目 | 旧（WP1 Revision 2） | 新（WP2） |
| --- | --- | --- |
| Validator Source | `0790a1ca4265105a2fe34c434465ede979614cedc7b1c0e5bf8b42d4677b23ee` | `2260f7d6e9c6687c9ed4963ccc443a7f93e67b46ac1c90724e1335faf61a9f6b` |
| WP1 SC-01 payload | `7c5c30cf9c07f330d58f27c42b52cc5e14b4652bde0ad8703178ce85eccc7940` | `5b53eada571c6f709a107a0110ea91867df461e1b2634ec8a324e2e4c2661d70` |
| WP1 SC-02 payload | `f24c000188bca6349fcb75c3f130115d12225d7e52047ca22c4f20ed925b6736` | `d5bb5438afe9e37a3cad43d2115bbfa8aef2154bd689acb7d855e8b4c1226c36` |
| WP1 manifest、chain_status、links | — | 変化なし（INCOMPLETE、gate は `gate_record_missing` のみ） |

変更原因: `iacreview/chain/` の変更（`gate.py` の追加、Reason Code、`LinkResult.aspects`）による Validator Source の変化だけ。

検証: 新 Payload の `validator.source_sha256` を旧値 `0790a1ca…` に戻すと、両 Scenario とも旧 Payload Digest に一致した。再現手順: `PYTHONPATH=.:tests/unit python3` で `chain_synth.fixture_chain(<tmp>, "sc01" | "sc02")` と `validator.validate` を実行し、Payload の `validator.source_sha256` を置き換えて `iacreview.remediation.report.canonical` の SHA-256 を比べる。

途中の値: MU2-38 の対応の前に一度 Validator Source `00141670…` で値を記録したが、`gate.py` の変更で無効になったため、最終値で記録し直した（同じ検証を再実行）。

Gate Anchor（新規、`expected-gate.json`）:

| Scenario | chain_status | gate のコード | manifest | payload |
| --- | --- | --- | --- | --- |
| gate-complete | COMPLETE | — | `154a3c1391727d0ab9ea4f3085617dcc4728777c2519496d5e80be1b22913b31` | `859c494be6c6aa25e7921701d289160e1d043dcc6d33db6d6d8c808d9e876956` |
| gate-not-proven | NOT_PROVEN | `approval_not_shown` | `8a5f07618101f181a072530d7513a7c34871b9d968b65d800674f6e586bb9df0` | `582353b62b893d72460a79e38d02381549e0c5d2fea7963fdd1c73529326417f` |
| gate-broken | BROKEN | `pr_head_mismatch` | `5501f8c241a51a40c1f38e7a9139097cb5a18093b6d86a86a2ad2115400efe72` | `2565d223c121e16312e0ef7a36709613fe23ca0aacb111dc735a74f594eb3631` |

各 Scenario の Status とコードを仕様（TC-10-07、TC-10-04、TC-09-04）と照合してから値を記録した。Anchor は変化の検出用で、正しさの独立した証明ではない。

## 5. M1 固定 Hash

Evaluator `ee765e0c…`、Definition `fb4ddef0…`、native `24f091d1…`、final report `4b1f2c54…`、legacy `731a1846…`、M1 `expected.json` `ebe177bd…`。すべて不変。変更禁止範囲の差分 0件。

## 6. 仕様の解釈と Human 確認事項

| ID | 内容 |
| --- | --- |
| N2-1 | 既存 Test `test_tc_06_03_gate_records_are_not_evaluated_before_wp2`（WP1 の未実装の挙動を確認する Test）を、同じ入力で「自己申告の Record は LINKED にならない」ことを確認する Test に置き換えた。安全性の主張（Agent の承認 Record は通らない）は維持し、`gate_evaluation_not_implemented` が Catalog に残ることも確認する。既存 Test の期待値の変更なので承認が必要 |
| N2-2 | （rev1。Human 判断: 修正要求。§8 で修正）Raw から再生成した `candidate_review` / `merge_decision` の Record が提示されていない場合も `gate_record_mismatch`（BROKEN）とした |
| N2-3 | （rev1。Human 判断: 修正要求。§8 で修正）Schema 違反の Record が1件でもあれば、有効な Record があっても GV-1 に `approval_self_declared_only` を付ける |
| N2-4 | pull と review の Raw は重複 key と浮動小数点を拒否する strict JSON で読む。実 GitHub の応答で浮動小数点が出る場合は `review_capture_incomplete` になる（NOT_VERIFIED、WP5 で確認） |
| N2-5 | MU2-23 は Matrix の「`actor_ref` の代わりに login」を「仮名の代わりに生の User id」で実装した。Builder は login を読まないため |
| N2-6 | Email を含む Raw は M1 の Secret Gate が Page ごと拒否し、Store に入らない（TC-08-18）。実 GitHub の Review 応答に Email が入る場合、Capture が不完全になる |
| N2-7 | `chain_ci_check.py` が `expected-gate.json` を必須にした（CI Check Script の変更。`ci.yml` は無変更） |

## 7. 未検証事項と既知の制約

* GitHub Actions の全 Job: NOT_VERIFIED（Push していない）
* Python 3.11: ローカルに Interpreter がなく NOT_VERIFIED
* Python 3.13.15 / 3.14.7: Pure Python の PyYAML を一時的に読み込ませ、同一 Process で WP1 Anchor 2件と Gate Anchor 3件の Payload Digest が期待値と一致することを確認した。Replay Test の別 Process 部分は、子 Process に PyYAML がない Local 環境のため実行できなかった（環境の制約。CI で確認が必要）
* Approval Authority、Ruleset Enforcement、Merge 権限、Raw の真正性: NOT_PROVEN（`not_claimed`、`observed.approval_authority`）
* Review の却下の時刻・却下者: Raw にないため扱わない
* TC-10-10（Summary の文言）: WP3
* 実 GitHub E2E: WP5

## 8. Implementation Review 対応（N2-2 / N2-3）

Human 判断: 92/100、条件付き承認。N2-1 承認、N2-2・N2-3 修正要求、N2-4・N2-5 条件付き承認、N2-7 承認。

### 8-1. 修正内容

判定規則は `wp2-gate-record-decision-table.md`（G-01〜G-13）に明記した。WP0 rev2 の文書は変更せず、仕様差分（S-1〜S-8）と Test Matrix への追加案（TC-08-22〜29、MU2-51〜59）を同じ文書の §3・§4 にまとめた（Human 承認待ち）。

| 変更 | Path | 内容 |
| --- | --- | --- |
| 変更 | `iacreview/chain/gate.py` | Record 単位の判定（`Presented`、`states_an_approval`）。欠損は INCOMPLETE、確認できた矛盾は BROKEN、Schema 違反は `gate_record_invalid`、自己申告は `approval_self_declared_only`。`Facts.loaded` / `Facts.complete` で「完全に読めた Raw」を区別。GV-4 の自己申告の条件を「裏付けのある承認 Record がない」に修正 |
| 変更 | `iacreview/chain/status.py` | `gate_record_invalid`（INCOMPLETE）を追加。`gate_record_missing`、`gate_record_mismatch`、`approval_self_declared_only` の説明文を修正（Status は不変） |
| 変更 | `tests/unit/test_chain_gate.py` | `test_g_*` 11関数（G-02〜G-13、混在ケース）を追加。TC-08-06・TC-09-09 は全 Record を提示した上で Status まで確認するように強めた（自己申告の入力を3種に） |
| 変更 | `tests/mutation/chain_mutants.py`、`tests/unit/test_chain_mutations.py` | MU2-51〜59 を追加（合計56）。MU2-22 は置換対象行の追従のみ |
| 変更 | `.github/scripts/chain_ci_check.py` | 必須 Test に `test_g_*` 8件を追加（57 → 65） |
| 変更 | `tests/fixtures/chain_replay/expected.json`、`expected-gate.json` | Validator Source の変化による Payload Digest の更新（§8-4） |
| 新規 | `docs/v2/phase2/m2/wp2/wp2-gate-record-decision-table.md` | Decision Table、仕様差分、Matrix 追加案 |

N2-5 の条件（login などの非出力 Test の維持）: TC-08-18（login、Avatar URL、本文の canary が Record・Result・Validator 出力に出ない、Email を含む Page は M1 Secret Gate が拒否）は変更せず PASS。

### 8-2. Status / Reason Code の対応

| 区分 | rev1 の実装 | 修正後 |
| --- | --- | --- |
| Record ファイルの欠落（G-02） | INCOMPLETE `gate_source_missing` | INCOMPLETE `gate_record_missing` |
| 再生成 Record の省略（G-13） | BROKEN `gate_record_mismatch` | INCOMPLETE `gate_record_missing` |
| 完全な Raw にない Item の Record（G-09） | INCOMPLETE `gate_source_missing` | BROKEN `gate_record_mismatch` |
| Raw が範囲内にない Record（G-10） | INCOMPLETE `gate_source_missing` | 同じ |
| Raw はあるが読めない（G-11） | `gate_source_missing` ＋ 原因のコード | 原因のコードだけ |
| Schema 違反で承認を述べない（G-04） | NOT_PROVEN `approval_self_declared_only` | INCOMPLETE `gate_record_invalid` |
| 自己申告（G-05） | NOT_PROVEN `approval_self_declared_only` | 同じ（有効な承認があっても残す） |
| 同じ Item の Record が2件（G-07） | 判定なし | INCOMPLETE `gate_record_invalid`、各 Record を比較 |
| Digest 不一致（G-03）、`kind` 不一致（G-06）、再生成との差（G-12）、Revision 偽装（G-12a） | BROKEN | 同じ |
| GV-4 の自己申告 | `candidate_review` が1件もないとき | 裏付けのある承認 Record がないとき |

### 8-3. Test と Mutation（macOS、`/usr/bin/python3` 3.9.6）

| 項目 | Command | Exit | 結果 |
| --- | --- | --- | --- |
| Chain Test | `python3 -m pytest -p no:cacheprovider -rs --junitxml=… tests/unit/test_chain_*.py` | 0 | 305件 PASS / FAIL 0 / SKIP 0、436 s |
| Chain CI Check | `python3 .github/scripts/chain_ci_check.py --junit … --expected tests/fixtures/chain_replay/expected.json` | 0 | 必須65件、SKIP 0、Gate Anchor 3 Scenario、Validator Source 一致 |
| Chain Mutation | `python3 tests/mutation/chain_mutants.py --json …` | 0 | 56 / 56（WP1 20、WP2 36）。生存0 |
| 全体 pytest + coverage | `python3 -m pytest -p no:cacheprovider --cov=iacreview --cov=benchmark/harness --cov-fail-under=80` | 0 | 8,083件（PASS 8,047 / FAIL 0 / SKIP 36）、coverage 94.92%、1,147 s |
| M1 Evidence Test + CI Check | `tests/unit/test_evidence_*.py`、`evidence_ci_check.py` | 0 / 0 | 519件 PASS / SKIP 0、M1 固定 Hash 一致、`verified_commits` 5 |
| Benchmark | `run_benchmark.py --cases benchmark/cases --mode combined` | 0 | PASS |
| Determinism | `PYTHONHASHSEED=random python3 -m pytest tests/property/test_prop_determinism.py` | 0 | PASS |
| Secret scan | `scan_secrets.py` | 0 | 0 finding（759 files、tracked mode） |
| Canary | TC-08-18、Repository の canary 文字列検索 | 0 | canary は Test の Source（`test_chain_gate.py`）にだけある。docs、Anchor、`iacreview/chain/`、CI Script に Host の絶対 Path なし |
| Ground_Truth | `check_ground_truth_order.py --cases benchmark/cases` | 0 | 17/17 |
| Public Preflight | `public_preflight.py` | 0 | PASS（767 files） |
| `git diff --check` | — | 0 | — |
| ruff / mypy（advisory） | `ruff check .`、`mypy --no-site-packages iacreview` | 1 / 1 | 40件 / 12件（Baseline と同じ）。`iacreview/chain/` と変更した Test は0件 |

### 8-4. Hash の差分

| 項目 | 旧（rev1） | 新 |
| --- | --- | --- |
| Validator Source | `2260f7d6e9c6687c9ed4963ccc443a7f93e67b46ac1c90724e1335faf61a9f6b` | `8bef526d582ad51982a9605bbbca3ee14f5ba1de3555fd37e8aae34bd5a4f592` |
| WP1 sc01 payload | `5b53eada571c6f709a107a0110ea91867df461e1b2634ec8a324e2e4c2661d70` | `b084dabcacbbf46a89806c8778d4e283345868d33a54147a3e4f3c5091b2b4be` |
| WP1 sc02 payload | `d5bb5438afe9e37a3cad43d2115bbfa8aef2154bd689acb7d855e8b4c1226c36` | `575d6052923c8e42c2c3a62fd6bf093721bb29aef18654ab5cdc068a4dc00414` |
| gate-complete payload | `859c494be6c6aa25e7921701d289160e1d043dcc6d33db6d6d8c808d9e876956` | `3ac9406f9ef20d0ff72b620f28b3539109868b5abf299dd228b6cd6691722b72` |
| gate-not-proven payload | `582353b62b893d72460a79e38d02381549e0c5d2fea7963fdd1c73529326417f` | `5e386951f023dc608336c08037f97823f0abb0599023110368e9226077545c44` |
| gate-broken payload | `2565d223c121e16312e0ef7a36709613fe23ca0aacb111dc735a74f594eb3631` | `815a0671165be35386ab42de8a6a933c7ad7efd77062436d8409adb6c48b5f4a` |
| 5 Scenario の manifest、chain_status、gate のコード | — | 変化なし（sc01 / sc02 INCOMPLETE `gate_record_missing`、COMPLETE、NOT_PROVEN `approval_not_shown`、BROKEN `pr_head_mismatch`） |
| `expected.json` / `expected-gate.json` のファイル | — | `1653a829…` / `0b5611c4…` |

変更原因: `iacreview/chain/gate.py` と `status.py` の変更による Validator Source の変化だけ。

検証: 新 Payload の `validator.source_sha256` を旧値 `2260f7d6…` に戻すと、5 Scenario すべてで rev1 の Payload Digest に一致した。Python 3.13.15 / 3.14.7（Pure Python の PyYAML を一時的に使用）でも、同一 Process の5 Scenario の Payload Digest が 3.9.6 と一致した。

M1 固定 Hash（Evaluator、Definition、native、final report、legacy、M1 `expected.json` `ebe177bd…`、`verified_commits` 5）は不変。`iacreview/evidence/`、`iacreview/remediation/`、M1 Fixture、`ci.yml`、`pyproject.toml`、`plugin.json`、`.gitignore`、WP0 rev2 の文書の差分は、本対応で0件。

### 8-5. 残る NOT_VERIFIED と Human 確認事項

* GitHub Actions の全 Job（Python 3.9 / 3.11 / 3.13、Replay の別 Process 部分を含む）: NOT_VERIFIED（Push していない）
* Python 3.11: Local に Interpreter がなく NOT_VERIFIED
* Python 3.13 / 3.14 の Replay Test の別 Process 部分: Local の子 Process に PyYAML がなく未実行
* 実 GitHub Raw と strict JSON の互換性（N2-4）: NOT_VERIFIED（WP5）
* Approval Authority、Ruleset Enforcement、Merge 権限、Raw の真正性: NOT_PROVEN のまま
* Human 承認が必要: 仕様差分 S-1〜S-8、Matrix 追加案（TC-08-22〜29、MU2-51〜59）、`test_chain_mutations.py` の期待件数（47 → 56）、`chain_ci_check.py` の必須 Test（57 → 65）、2つの Anchor の更新

## 9. N2 修正 Review の最終確認（95/100、条件付き承認）

Human 承認済み: TC-08-22〜29、MU2-51〜59、Mutation 期待件数 56、CI 必須 Test 65、2つの Anchor の更新。S-1〜S-8 は個別確認まで保留。

### 9-1. 確認項目と結果

| 項目 | 結果 |
| --- | --- |
| 1. S-1〜S-8 の一覧 | `wp2-gate-record-decision-table.md` §3 に、変更前の仕様・変更後の仕様・理由・対応 Test・互換性への影響を記載。項目3・4の対応で S-9、S-10 が加わった |
| 2. WP0 rev2 への反映 | 承認済みの TC-08-22〜29、MU2-51〜59 を `m2-acceptance-test-matrix.md`（M2-08、§13、§13-1、§13-2）に反映。`m2-schemas.md` は、S-1〜S-10 が確認中のため未反映。Code と Schema の不一致は S-1〜S-10 に限られ、§3 に列挙した |
| 3. 一次原因と二次的な結果 | 区別できなかった（Digest 不一致の Record に `gate_record_missing` が重なり、別の省略と見分けられない）。G-13a で、使えない Entry の数を超える省略だけに `gate_record_missing` を付けるよう修正（S-9）。Status は下がらない。限界は Decision Table §2-2 |
| 4. 自己申告の検出対象 | 規則（key が `approv` で始まる）が `approval_state: "rejected"` などを誤検出していた。3つの形に閉じた（S-10、Decision Table §2-3）。誤検出しない24入力と、未定義の表記が G-04 になることを Test で確認 |
| 5. ID の一覧 | Mutation 59件（MU2-01〜29、MU2-33〜62）、重複0、全 Mutant の置換対象が Source に1回だけある。Kill Test 51件はすべて定義済み。必須 Test 70件、重複0、すべて定義済み。`test_g_*` 13関数のうち2件（TC-08-26 の一部、TC-08-27）が必須にも Kill Test にも入っていなかったため、必須に追加 |
| 6. M1 固定 Hash・Frozen Evidence | 不変（§9-3） |
| 7. WP1 互換・Record 0件 | TC-10-11（Record 0件は INCOMPLETE `gate_record_missing` だけ、`gate_aspects` なし）と TC-06-03 PASS。WP1 Anchor の chain_status・コード・manifest は不変 |

### 9-2. 変更ファイル（本確認での変更）

| Path | 内容 |
| --- | --- |
| `iacreview/chain/gate.py` | `APPROVER_KEYS` と `states_an_approval` の3形（S-10）。`Presented.unusable` / `refuse` と G-13a の判定（S-9） |
| `iacreview/chain/status.py` | `gate_record_missing`、`approval_self_declared_only` の説明文（Status は不変） |
| `tests/unit/test_chain_gate.py` | TC-08-23 に4入力を追加。`test_g_13a_*`、`test_g_05_the_three_*`、`test_g_05_other_fields_*` を追加。TC-08-29 の `digest` の期待と混在 Test の入力を変更（Decision Table §4-1） |
| `tests/mutation/chain_mutants.py`、`tests/unit/test_chain_mutations.py` | MU2-60〜62（期待件数 56 → 59） |
| `.github/scripts/chain_ci_check.py` | 必須 Test 65 → 70 |
| `tests/fixtures/chain_replay/expected.json`、`expected-gate.json` | Validator Source の変化による Payload Digest の更新 |
| `docs/v2/phase2/m2/wp0/m2-acceptance-test-matrix.md` | 承認済み事項の反映 |
| `docs/v2/phase2/m2/wp2/wp2-gate-record-decision-table.md` | G-05・G-13a、§2-2、§2-3、S-1〜S-10 の詳細、§4 |

### 9-3. 検証（macOS、`/usr/bin/python3` 3.9.6）

| 項目 | Exit | 結果 |
| --- | --- | --- |
| Chain Test（`tests/unit/test_chain_*.py`、Mutation の Test を含む） | 0 | 340件 PASS / FAIL 0 / SKIP 0、453 s |
| Chain CI Check | 0 | 必須70件、SKIP 0、Gate Anchor 3件、Validator Source 一致、Failures なし |
| Chain Mutation（単独実行） | 0 | 59 / 59 |
| M1 Evidence Test + CI Check | 0 / 0 | 519件 PASS / SKIP 0。Evaluator `ee765e0c…`、Definition `fb4ddef0…`、final report `4b1f2c54…`、legacy `731a1846…`、M1 `expected.json` `ebe177bd…`、`verified_commits` 5 |
| Public Preflight | 0 | PASS（767 files） |
| Secret scan | 0 | 0 finding（759 files） |
| `git diff --check` | 0 | — |
| ruff / mypy（advisory） | 1 / 1 | 40件 / 12件（Baseline と同じ）。変更した Code は0件 |
| 全体 pytest、Benchmark、Determinism、Ground_Truth | — | 本確認では未実行（指定の再検証の範囲外。§8-3 の結果は1つ前の Code に対するもの） |

### 9-4. Hash の変化

| 項目 | 旧（§8） | 新 |
| --- | --- | --- |
| Validator Source | `8bef526d582ad51982a9605bbbca3ee14f5ba1de3555fd37e8aae34bd5a4f592` | `09891f40edb248c412ed9307808293d80f8f57bbe3bd7983b5aa42fe0035b60a` |
| WP1 sc01 | `b084dabc…` | `2bd6b538035ae42f106bbf9dcea8f2f6b2c78d99ba29a6c7543849682e9b3586` |
| WP1 sc02 | `575d6052…` | `6913a37dcfd743af06b91c3322212a1ba8a5608f932219d072cbbb694c625b93` |
| gate-complete | `3ac9406f…` | `00e09c732187e48f95366f9c5885617f0b08b30da13de57d4f9efd5dc3c6f1e3` |
| gate-not-proven | `5e386951…` | `7013dc11b228e2fee4bac3630fd2f792f2fb1ee818910dd6674d3151b8df8e6c` |
| gate-broken | `815a0671…` | `688c8fff73e9309d2004d21945b1a94454cea60ff29c2b5b5362f4d86ab4c969` |
| `expected.json` / `expected-gate.json` | `1653a829…` / `0b5611c4…` | `cb5c28fb…` / `7bfcc339…` |

原因は `gate.py` と `status.py` の変更による Validator Source の変化だけ。Payload の `validator.source_sha256` を `8bef526d…` に戻すと、5 Scenario すべてで §8 の Digest に一致した。chain_status、gate のコード、manifest は不変。Python 3.13.15 / 3.14.7 の同一 Process でも5つの Payload Digest が一致した。

### 9-5. 残る NOT_VERIFIED と Human 確認事項

* GitHub Actions の全 Job（Python 3.9 / 3.11 / 3.13、Replay の別 Process 部分）: NOT_VERIFIED（Push していない）
* Python 3.11: Local に Interpreter がない
* 実 GitHub Raw と strict JSON の互換性（N2-4）: WP5
* Approval Authority、Ruleset Enforcement、Merge 権限、Raw の真正性: NOT_PROVEN のまま
* Human 確認が必要: S-1〜S-10、TC-08-30〜31、MU2-60〜62（期待件数 59）、必須 Test 70、承認済み TC-08-23・29 の中の変更（Decision Table §4-1）、2つの Anchor の再更新

## 10. WP2 Final Specification Review（97/100）

### 10-1. Human 承認結果

| 対象 | 判定 |
| --- | --- |
| S-1〜S-10 | 全件承認。WP0 rev2 への反映を許可 |
| TC-08-30〜31、MU2-60〜62 | 承認 |
| Mutation 期待件数 | 59件で承認 |
| CI 必須 Test | 70件で承認 |
| TC-08-23、TC-08-29 の期待値変更 | 承認 |
| `expected.json`、`expected-gate.json` の再更新（§9-4） | 承認 |

経過: Implementation Review 92/100（N2-1・N2-7 承認、N2-2・N2-3 修正要求、N2-4・N2-5 条件付き承認）→ N2 修正 Review 95/100（TC-08-22〜29、MU2-51〜59、56件、65件、Anchor 更新を承認、S-1〜S-8 は保留）→ Final Specification Review 97/100（本節）。

### 10-2. 反映内容

| Path | 内容 |
| --- | --- |
| `docs/v2/phase2/m2/wp0/m2-schemas.md` | 状態行に S-1〜S-10 の反映を記載。§2 規則に自己申告の3つの形（S-2、S-10）と重複 Record（S-7）。§2-4 GV-1 の表に S-1、S-3〜S-6、S-9 の行、G-13a の既知の制約。GV-4 の表に S-8。§4 の GV-1 の INCOMPLETE に `gate_record_missing`、`gate_record_invalid`、変更の記録 |
| `docs/v2/phase2/m2/wp0/m2-acceptance-test-matrix.md` | TC-08-30〜31、MU2-60〜62、TC-08-23・29 の期待、M2-08 の PASS 条件と §13 の対応表、§13-1 の Reason Code と TC の対応 |
| `docs/v2/phase2/m2/wp2/wp2-gate-record-decision-table.md` | 状態を承認済みに更新（内容の変更なし） |

Production Code、Test、Anchor は本節では変更していない（Validator Source は §9-4 の `09891f40…` のまま）。

### 10-3. 確認結果

| 項目 | 結果 |
| --- | --- |
| Branch / HEAD | `feature/phase2-m2-wp2`、HEAD `336620859a5496b253bb347c40cbd462f45fb3ef`（未 Commit の作業ツリー） |
| Matrix と実装の整合 | Matrix の Mutant ID 62個 = 実装59個 + WP4 の MU2-30〜32。TC-08 の行は TC-08-01〜31 の31行で重複なし。TC-08-22〜31 が名指す Test 関数はすべて定義済み。必須 Test 70件と Kill Test 51件はすべて定義済み |
| G-13a の既知の制約 | `m2-schemas.md` §2-4 と Decision Table §2-2 に記載 |
| 未知の自己申告の形 | 正しい Record 一式（COMPLETE の Chain）に、`approvedBy`、`APPROVED_BY`、`approval`、`decision: "Approved"`、自由文、`lgtm`、入れ子、配列、JSON 文字列、JSON でない bytes、`approved: "true"` の11入力を1件ずつ加え、Validator 全体で判定した。11件とも INCOMPLETE `gate_record_invalid` で、COMPLETE にならない（Private の確認 Script。Test には追加していない。同じ規則は TC-08-23、TC-08-31 が固定） |
| NOT_PROVEN の維持 | 上の11件と Anchor 3件で `observed.approval_authority` は `NOT_PROVEN`。`not_claimed` は7項目（`approver_permission`、`merge_enforcement`、`capture_authenticity` を含む）で不変（TC-06-07、TC-10-07） |
| M1 固定 Hash・Frozen Evidence | 不変（§10-4） |
| WP1 Anchor の変更原因 | Validator Source だけ（§9-4。旧値に戻すと旧 Digest を再現） |

### 10-4. 最終ローカル検証（macOS、`/usr/bin/python3` 3.9.6）

| 項目 | Exit | 結果 |
| --- | --- | --- |
| Chain Test（`tests/unit/test_chain_*.py`） | 0 | 340件 PASS / FAIL 0 / SKIP 0、454 s |
| Chain CI Check | 0 | 必須70件、SKIP 0、Validator Source `09891f40…` 一致、Failures なし |
| Chain Mutation（単独実行） | 0 | 59 / 59、261 s |
| WP1 Anchor（`test_chain_replay.py`） | 0 | sc01 / sc02 の4回 Replay、TC-07-01〜04 PASS |
| WP2 Gate Anchor（`test_chain_gate_replay.py`） | 0 | 3 Scenario の仕様確認と4回 Replay PASS |
| M1 Evidence Test + CI Check | 0 / 0 | 519件 PASS / SKIP 0 |
| Public Preflight | 0 | PASS（767 files） |
| Secret scan | 0 | 0 finding（759 files） |
| `git diff --check` | 0 | — |

5つの Anchor の Payload Digest（§9-4 から不変）: sc01 `2bd6b538035ae42f106bbf9dcea8f2f6b2c78d99ba29a6c7543849682e9b3586`、sc02 `6913a37dcfd743af06b91c3322212a1ba8a5608f932219d072cbbb694c625b93`、gate-complete `00e09c732187e48f95366f9c5885617f0b08b30da13de57d4f9efd5dc3c6f1e3`、gate-not-proven `7013dc11b228e2fee4bac3630fd2f792f2fb1ee818910dd6674d3151b8df8e6c`、gate-broken `688c8fff73e9309d2004d21945b1a94454cea60ff29c2b5b5362f4d86ab4c969`。

M1 固定 Hash（不変）: Evaluator `ee765e0c18ba76b9d4a27a0d4277548f21296757f03a77879763d1824dae58d6`、Definition `fb4ddef0b86d36e436e4492e1ff2d209812e80b6e993dea47ba07dc7a856b1d0`、native `24f091d1f8be65603a4d5d2cd62052758295155e00be200b59a8ff45238a2a48`、final report `4b1f2c5441ea9a421bdb0b8d402a608acbf96ced7f128d30f443939746f55b47`、legacy `731a1846ce5bb6102bea478fbc613b85ccb6b3cf90fc736dd62b8bbeaa8e1748`、M1 `expected.json` `ebe177bdd64e8ec74d90fab0c44ff4f982e93122109c9df8cfa524166346e841`、`verified_commits` 5。`iacreview/evidence/`、`iacreview/remediation/`、`tests/fixtures/evidence_replay/` の差分は0件。

### 10-5. 残る NOT_VERIFIED

* GitHub Actions の全 Job（Python 3.9 / 3.11 / 3.13、Replay の別 Process 部分）: Push していない
* Python 3.11: Local に Interpreter がない
* 実 GitHub Raw と strict JSON の互換性（N2-4）: WP5
* Approval Authority、Ruleset Enforcement、Merge 権限、Raw の真正性: NOT_PROVEN（主張しない）
* 全体 pytest、Benchmark、Determinism、Ground_Truth は本節の検証範囲外（Production Code の最終状態では §8-3 以降に未実行。§9 以降の Code 変更は `iacreview/chain/` だけ）

## 11. CI Performance Fix（PR #10 のタイムアウト対応、Human Review 97/100・条件付き承認）

背景: PR #10（Commit `ce9bac35`、CI Run 41305260650）で、macOS Intel / Python 3.9 の pytest が60分でキャンセルされた。ローカル計測（Apple M5 / Python 3.9.6）では、WP2 の追加で Chain Test が WP1 の約3.8倍になり、主因は `verification_report_bytes` の呼び出し（1回約1秒の cfn-lint / cfn-guard 実行、117回）だった。macOS Intel での実測値は NOT_VERIFIED。

### 11-1. 変更

| Path | 内容 |
| --- | --- |
| `tests/unit/chain_synth.py` | `verification_report_bytes` にプロセス内メモリのキャッシュ（Test Helper 限定）。Key は commit 群、contract、execution mode、子 Process が引き継ぐ環境変数、`cfn-lint` / `cfn-guard` の実体（実パス・サイズ・mtime・inode）、Python の実行ファイルと version。`cache=False` で常に再生成。`head=None`（未Commit の作業ツリーを読む Worktree Preview）はキャッシュしない（11-3）。Tool 実体識別の制約を `_tool_identity` の Docstring に記録 |
| `tests/unit/test_chain_synth_cache.py`（新規） | キャッシュの Test 9件 |
| `.github/scripts/chain_ci_check.py` | 必須 Test に上の9件を追加（70 → 79） |
| `.github/workflows/ci.yml` | `timeout-minutes: ${{ matrix.timeout-minutes \|\| 60 }}`。`macos-15-intel` / Python 3.9 の `include` エントリだけ `timeout-minutes: 90`。他の Job の Timeout、Job 名、Job 数は不変 |
| `tests/unit/test_ci.py` | Timeout 設定の静的 Test 2件を追加（Intel / 3.9 だけ90分・他の5組み合わせは60分、Job 名と他の Job の Timeout の不変、Required Check の数 10） |

変更していないもの: `iacreview/`、`skills/`、`rules/`、Frozen Evidence、期待 Hash（`expected.json`、`expected-gate.json`、M1 の `expected.json`）、Mutation の Mutant と Kill Test、`pyproject.toml`、`plugin.json`、`.gitignore`。

### 11-2. Production Code・Evidence 検証への影響

* `chain_synth` を import するのは `tests/unit/` の Test だけ（`iacreview/`、`skills/`、`plugin.json`、CI Script からの参照なし）。キャッシュは Production Code にも本番の Evidence 検証にも届かない
* キャッシュするのは `iacreview.remediation.verify` の出力で、全 Mutant が編集する `iacreview/chain/` の外。`test_no_chain_mutant_edits_what_the_cached_report_is_made_from` が、全 Mutant の編集先が `iacreview/chain/` だけであることと、`iacreview/remediation/` が `iacreview.chain` を参照しないことを固定する
* キャッシュは1つの Process のメモリだけ。Mutation Harness は Mutant ごとに新しい Process を使うので、各 Mutant のキャッシュは空から始まる

### 11-3. 未Commit のファイル状態と Cache Key（確認の結果、1件の修正）

* 確認: `verify.Request.head` が `None` のとき、検証は未Commit の作業ツリーを読む。実測では、作業ツリーの未Commit の編集でレポートが変わった。commit だけの Key では、古いレポートを返してしまう
* 現在の Chain Test は `head=None` の Setup を使わない（C01 / C02 / C05 はすべて Commit 済みの Head）。ただし Helper は一般的に使える形なので、将来の誤用を防ぐ
* 修正（最小）: `setup.head is None` のときはキャッシュを使わず毎回生成し（`bypassed` を数える）、`verification_cache_key` は `ValueError` を出す。Test `test_a_worktree_preview_is_never_served_from_the_cache` を追加（承認済みの8件に1件の追加。**Human の承認を要する**）
* Contract に Draft File を使う場合は、その内容の SHA-256 が Key に入る。プラグイン自身のソースは Key に入れない（Process 内で変わらない。Docstring に記載）

### 11-4. Tool 実体識別の制約（Docstring にも記録）

Tool Version の代わりに実体（実パス、サイズ、mtime、inode）を使う。Human の条件付き承認（Test Helper 限定）に従い、次の制約を記録した。

* version の文字列は Key に入らない（Mutant ごとに Process が新しいので、`--version` を毎回呼ぶと節約が相殺される）。レポートには、生成時の version が記録される
* パス・サイズ・mtime・inode が同じままの書き換え、または `cfn-lint` のスクリプトは変わらずにその背後の Package や Interpreter だけが変わる場合は検出しない。どちらも、1つの Process の実行中に環境が変わることを要するが、Test はそれを行わない
* Process をまたぐ用途、ディスクに残す用途には使わない

### 11-5. 実測（macOS arm64 / Python 3.9.6、同条件）

| 項目 | 改善前（`ce9bac35`） | 改善後 |
| --- | --- | --- |
| Chain Test（Mutation 含む、Coverage なし） | 452秒 | 268秒（11-2 の追加 Test 前の測定） |
| Chain Test（Mutation 除く） | 190秒 | 83秒 |
| `verification_report_bytes` の呼び出し / 実際の生成 | 117回 / 117回 | 117回 / 3回（Hit 114、Miss 3、Hit 率97.4%） |
| `cfn-lint` の実行 | 327回 | 99回 |
| Mutation（Harness 単独） | 256秒 | 178秒（Baseline 98.7秒 → 26.6秒） |
| 全体 pytest（`--cov` あり） | 1,225秒（FAIL 1、11-7） | 988秒（FAIL 0） |

### 11-6. 最終検証（本節の変更後、`/usr/bin/python3` 3.9.6）

| 項目 | Exit | 結果 |
| --- | --- | --- |
| Chain Test（`tests/unit/test_chain_*.py`、Chain Job と同じコマンド） | 0 | 349件 PASS / FAIL 0 / SKIP 0、272 s |
| Mutation（Harness 単独） | 0 | 59 / 59 Kill（Chain Test 内の `test_chain_mutations` も PASS） |
| Chain CI Check | 0 | 必須79件（70 + 9）、SKIP 0、Validator Source `09891f40…` 一致、Gate Anchor 3件 |
| 5つの Anchor | — | 期待値ファイルは不変。Replay Test PASS。Payload Digest: sc01 `2bd6b538…`、sc02 `6913a37d…`、gate-complete `00e09c73…`、gate-not-proven `7013dc11…`、gate-broken `688c8fff…` |
| M1 Regression（Evidence Test + CI Check） | 0 / 0 | 519件 PASS / SKIP 0。固定 Hash 一致（Evaluator `ee765e0c…`、Definition `fb4ddef0…`、native `24f091d1…`、final report `4b1f2c54…`、legacy `731a1846…`、M1 `expected.json` `ebe177bd…`、`verified_commits` 5） |
| 全体 pytest + Coverage | 0 | 8,129件（PASS 8,093 / FAIL 0 / SKIP 36）、Coverage 95%（80%以上）、996 s |
| Public Preflight / Secret scan | 0 / 0 | PASS（768 files）/ 0 finding（767 files） |
| `git diff --check` | 0 | — |

SKIP 36件は、改善前と同じ既存の内訳（Benchmark の宣言なし 26件ほか）。新しい SKIP・FAIL はない。

### 11-7. 実行環境と再現性の制約（`test_prop_determinism`、今回は修正しない）

* 全体 pytest は `USER=no-isa LOGNAME=no-isa` を明示して実行した。環境の記録: macOS 26.6.2 arm64（Apple M5）、Python 3.9.6、pytest 8.3.4、hypothesis 6.141.1、cfn-lint 1.46.0、cfn-guard 3.2.1。ツール用 Shell は `USER=no-isa`。改善前の全体 pytest（`--cov` あり）は、バックグラウンド実行の Process が `root` と解決される環境で、`test_stdout_is_a_function_of_the_input_alone` が1件 FAIL した
* 仕組み: `getpass.getuser()` の `root`（最小長4に該当）が検査対象になり、Template に `root` がなく `Principal.AWS` に12桁のアカウント ID がある例で、IAM Review の固定文言 `the account root` が出力に出る。この仕組みは決定論的に確認した（該当の Template を Review すると出力に `account root` が1回出る）
* 再現は確率的: `USER=root LOGNAME=root` での1回の実行（26秒）は PASS。失敗した実行は、Hypothesis が該当の Template 形を生成した場合。CI の `runner` ユーザーでは起きない見込みだが、CI では未確認
* 修正案（未適用、Test は変更していない）: ユーザー名の検査を、前後が区切り文字のパス文脈に限る。または、ユーザー名が Review の固定文言に含まれる場合は検査から外す

### 11-8. 残る NOT_VERIFIED

* macOS Intel / Python 3.9 の実際の所要時間（ローカル比 約3.3倍の見積もりでは、全体は約54分で、60分に近い。90分への延長がその余裕）。見積もりの前提は CI ログの目測で、PR #9 の Intel Job の所要時間は未確認
* `timeout-minutes: ${{ matrix.timeout-minutes || 60 }}` の式が、GitHub Actions 上で意図どおり評価されること（YAML としては読み込め、同じ展開規則を再現した静的 Test は PASS）
* GitHub Actions の全 Job、Python 3.11（ローカルに Interpreter なし）、他の Matrix Job の実測
* Approval Authority、Ruleset Enforcement、Merge 権限、Raw の真正性: NOT_PROVEN のまま（主張しない）
