# Phase 2 / M2 / WP2 — Gate Record Decision Table（Human Review N2-2 / N2-3 への対応）

* 状態: **実装済み・ローカル検証済み。WP2 Final Specification Review（97/100）で S-1〜S-10 を含む全件が Human 承認済み。** 正式な仕様は `docs/v2/phase2/m2/wp0/m2-schemas.md`（§2、§2-4、§4 に S-1〜S-10 を反映）と `m2-acceptance-test-matrix.md`（TC-08-22〜31、MU2-51〜62）。本文書は Record 単位の判定の詳細と、仕様差分の記録
* 対象: `iacreview/chain/gate.py` の GV-1（Integrity）のうち、提示された Gate Record の扱い
* Human 承認の経過: Implementation Review（92/100）で N2-2 / N2-3 の修正要求。N2 修正 Review（95/100）で TC-08-22〜29、MU2-51〜59、期待件数 56、必須 Test 65、Anchor 更新を承認。Final Specification Review（97/100）で S-1〜S-10、TC-08-30〜31、MU2-60〜62、期待件数 59、必須 Test 70、TC-08-23・29 の期待値変更、Anchor の再更新を承認

## 1. 判定の原則

1. 矛盾が**確認できた**ときだけ BROKEN にする。矛盾の相手は、Manifest の Digest・`kind`、完全に読めた Raw から再生成した Record、`config_commit` のいずれか
2. 矛盾を確認できない欠損（Record ファイルがない、Record が提示されていない、Raw がない）は INCOMPLETE にする
3. Schema 違反（読めない Record）と自己申告（Schema 外で承認を述べる Record）は別の原因として、別のコードを付ける
4. Record は1件ずつ判定する。1件の異常のコードは、他の Record が正常でも消えない。複数の異常があれば、原因ごとのコードがすべて残る
5. 自己申告は、Raw に裏付けのある承認が別にあっても NOT_PROVEN のコードを残す
6. Result のコードはすべて一次原因を表す。ある異常から機械的に生じる二次的な結果（使えない Record の分だけ再生成 Record が提示されていないこと）には、別のコードを付けない（G-13a）

「完全に読めた Raw」とは、その種類の Capture が Evidence の範囲（E-1〜E-7）を満たし、JSON として読め、集約できた（R-13〜R-15 に当たらない）ことをいう。このとき、その種類の Record はすべて再生成されている。

## 2. Decision Table（GV-1、Record 単位）

上から順に判定し、最初に当たった行で、その Record の判定を終える（G-07 だけは G-12 の比較も続ける）。G-13 / G-13a は再生成した Record の側から判定する。

| # | 状況 | 区分 | Status | 理由コード | 判定の根拠 |
| --- | --- | --- | --- | --- | --- |
| G-01 | Manifest が Record を1件も名指さない / `contract_approval` がない | Record 欠損 | INCOMPLETE | `gate_record_missing` | rev2 §2-4 GV-3（変更なし） |
| G-01b | Locator が Symlink、Chain Root の外 | Manifest | BROKEN（Manifest） | `locator_outside_root` | WP1 の Manifest 検査（変更なし） |
| G-02 | Manifest が名指す Record ファイルがない | Record 欠損 | INCOMPLETE | `gate_record_missing` | 欠損で、矛盾は確認できない |
| G-03 | Record ファイルの SHA-256 が Manifest と違う | Record 改変 | BROKEN | `gate_record_mismatch` | Manifest との矛盾（rev2 §2-4、変更なし） |
| G-04 | Record が読めない: 通常ファイルでない、64 KiB 超、読み取り不可、strict JSON でない（重複 key、浮動小数点、構文）、Object でない、閉じた Schema の外で G-05 のどの形でも承認を述べない | Schema 違反 | INCOMPLETE | `gate_record_invalid`（新規） | Record として使えず、矛盾も確認できない |
| G-05 | Schema の外で、次のどれかの形で承認を述べる（§2-3）: `decision` が文字列 `"approved"` / `approved` が `true` / `approved_by`・`approver`・`approvers` が空でない文字列または空でない配列 | 自己申告 | NOT_PROVEN | `approval_self_declared_only` | rev2 §2 規則、§2-4 GV-1（適用範囲は §3 S-3、S-10） |
| G-06 | Manifest の `kind` と Record の `kind` が違う | Record 改変 | BROKEN | `gate_record_mismatch` | Manifest との矛盾（変更なし） |
| G-07 | 同じ `(kind, item_ref)` の Record が2件以上（2件目以降） | Schema 違反 | INCOMPLETE | `gate_record_invalid` | rev2 §2「Reviewer ごとに1件」。各 Record は G-08 以降の比較も受ける |
| G-08 | `store_revision` が Manifest の Revision と違う / `evidence_ids` が Manifest の範囲外（E-2、E-3） | Raw 欠損 | INCOMPLETE | `gate_source_missing` | rev2 §2-1（変更なし） |
| G-09 | 再生成した Record に同じ `(kind, item_ref)` がなく、その種類の Raw は完全に読めた（存在しない Reviewer、別の PR 番号、別の Git Commit） | Record 改変 | BROKEN | `gate_record_mismatch` | 完全な Raw との矛盾 |
| G-10 | 同上で、その種類の Capture が範囲内にない（E-7 違反、Integrity 不合格、Capture の重複を含む） | Raw 欠損 | INCOMPLETE | `gate_source_missing` | rev2 §2-4「Record が参照する Raw がない」 |
| G-11 | 同上で、Capture はあるが読めない・集約できない | Raw 欠損 | （その原因のコード） | `review_capture_incomplete`、`review_capture_duplicate`、`review_conflict`、`gate_source_unrecognized` | 原因のコードがすでに付いている。Record 側では追加しない |
| G-12 | 再生成した Record と1 Field でも違う | Record 改変 | BROKEN | `gate_record_mismatch` | rev2 §2-4（変更なし） |
| G-12a | G-12 のうち、`candidate_review` の `binds_to.commit` が Raw の決定 Review と違う | Revision 偽装 | BROKEN | `approval_revision_misrecorded`（GV-3）＋ `gate_record_mismatch` | rev2 §2-4 GV-3（変更なし） |
| G-13 | Raw から再生成した `candidate_review` / `merge_decision` が提示されていない（一次原因） | Record 欠損 | INCOMPLETE | `gate_record_missing` | 省略は欠損で、矛盾は確認できない（N2-2） |
| G-13a | 同上の Record の数が、Manifest で同じ `kind` を名乗り G-02・G-03・G-04・G-06 で使えなかった Entry の数以下（二次的な結果） | — | （使えなかった Entry のコード） | 追加なし | 使えない Entry が再生成 Record の位置を占めていたと説明できる。その Entry のコードは INCOMPLETE 以上なので、Status は下がらない |

GV-2〜GV-4 は Raw の集約から判定し、提示された Record の有無に依存しない。このため、Record を省略しても、Raw の CHANGES_REQUESTED は GV-2 の `changes_requested_outstanding` として残る。

GV-4 の自己申告（rev2 §2-4 GV-4 の4行目）: 自己申告があり、Raw に裏付けのある承認 Record（G-12 を通った `decision: approved` の `candidate_review`）が提示されていないとき、`staleness` に `approval_self_declared_only` を付ける。

### 2-1. 区分ごとの要約

| 区分 | 矛盾を確認できる | Status | コード |
| --- | --- | --- | --- |
| Gate Record 欠損（G-01、G-02、G-13） | いいえ | INCOMPLETE | `gate_record_missing` |
| Raw 欠損（G-08、G-10、G-11） | いいえ | INCOMPLETE（G-11 は原因による） | `gate_source_missing` ほか |
| Record 改変（G-03、G-06、G-09、G-12） | はい | BROKEN | `gate_record_mismatch` |
| Revision 偽装（G-12a） | はい | BROKEN | `approval_revision_misrecorded` ＋ `gate_record_mismatch` |
| Schema 違反（G-04、G-07） | いいえ | INCOMPLETE | `gate_record_invalid` |
| 自己申告（G-05） | — | NOT_PROVEN | `approval_self_declared_only` |

### 2-2. 一次原因と二次的な結果（最終確認 項目3）

N2 修正の時点では、使えない Record（例: `merge_decision` のファイルの Digest 不一致）が再生成 Record の位置にあると、その再生成 Record が「提示されていない」ことにもなり、`gate_record_mismatch` と `gate_record_missing` が並んだ。Result からは、`gate_record_missing` が別の省略（一次原因）なのか、Digest 不一致の結果（二次的な結果）なのかを区別できなかった。

修正後（G-13a）: `kind` ごとに「提示されていない再生成 Record の数」と「その `kind` を名乗る使えない Entry の数」を比べ、前者が多いときだけ `gate_record_missing` を付ける。

| 入力（正しい Record 一式からの変更） | integrity のコード |
| --- | --- |
| B の Record ファイルを `[]` に置き換え（Digest は整合） | `gate_record_invalid` |
| 同上、かつ別の Reviewer の Record を省略 | `gate_record_invalid`、`gate_record_missing` |
| `merge_decision` の Digest を変える | `gate_record_mismatch` |
| B の Record を自己申告に置き換え | `approval_self_declared_only`、`gate_record_missing`（自己申告は数に入れない。NOT_PROVEN が INCOMPLETE より弱いため） |

限界: Manifest の `kind` は表示用の値で、改変された Entry の中身は読まない。このため、Record の省略と、同じ `kind` を名乗る使えない Entry の追加が同時にあると、省略は使えない Entry のコードで説明され、`gate_record_missing` は付かない。Status は使えない Entry のコード（INCOMPLETE 以上）で決まり、COMPLETE にはならない。Raw の CHANGES_REQUESTED は GV-2 に残る。

### 2-3. 自己申告の検出対象（最終確認 項目4）

`states_an_approval`（`iacreview/chain/gate.py`）は、`record_schema_ok` に通らなかった Record にだけ適用し、Record を承認として数えることはない。検出するのは、JSON Object の top-level にある次の3つの形だけ:

| 形 | 例 | 検出しない例 |
| --- | --- | --- |
| `decision` が文字列 `"approved"`（完全一致） | `{"decision": "approved"}` | `"APPROVED"`、`["approved"]`、`"none"` |
| `approved` が真偽値 `true` | `{"approved": true}` | `false`、`"yes"`、`1` |
| `approved_by`・`approver`・`approvers`（完全一致、小文字）が空でない文字列か空でない配列 | `{"approved_by": "agent"}`、`{"approvers": ["x"]}` | `""`、`[]`、`7`、`null`、`Approver`、`approvedBy`、`APPROVED_BY`、`approve`、`approval_state`、`approvals_count` |

検出しない表現（他の key 名、大文字小文字の違い、入れ子の Object、配列の要素、自由文の本文）はすべて G-04 の Schema 違反（INCOMPLETE `gate_record_invalid`）になる。G-04 は G-05 より弱くならないため、検出の漏れは Fail-closed の側に倒れる。N2 修正の時点の規則（key が `approv` で始まれば自己申告）は、`approval_state: "rejected"` のような承認でない Field を自己申告と誤認していたため、この3形に閉じた（S-10）。

## 3. WP0 rev2 からの仕様差分（Human 承認済み、`m2-schemas.md` に反映済み）

| ID | 変更前の仕様（WP0 rev2） | 変更後の仕様（実装） | 変更理由 | 対応 Test | 互換性への影響 |
| --- | --- | --- | --- | --- | --- |
| S-1 | 理由コードの表（§2-4 GV-1、§4）に Schema 違反専用のコードがない | `gate_record_invalid`（INCOMPLETE、GV-1）を追加 | N2-3: Schema 違反を自己申告と別の原因にする。`report_invalid`、`review_report_invalid`（INCOMPLETE）と同じ扱い | TC-08-23、TC-08-25、TC-08-29 | Catalog に1件追加。既存コードの Status は不変。Record 0件の Chain と WP1 Anchor の Status・コードは不変 |
| S-2 | §2 規則: Schema 違反の Record は自己申告として `approval_self_declared_only` | 自己申告（G-05）だけを `approval_self_declared_only`、他の Schema 違反は `gate_record_invalid`（G-04） | N2-3 | TC-08-06、TC-08-23、TC-08-24 | 承認を述べない Schema 違反の Status が NOT_PROVEN から INCOMPLETE に上がる（厳しくなる側） |
| S-3 | §2-4 GV-1: 「有効な承認 Record がなく、自己申告だけ」のとき `approval_self_declared_only`。有効な承認がある場合は未定義 | 有効な承認があっても `approval_self_declared_only` を付ける | 修正要件 5（正常な Record で異常を隠さない） | TC-08-24、TC-08-29 | 未定義の場合を NOT_PROVEN に定めた。LINKED だった Chain はない（rev1 の実装から同じ） |
| S-4 | `gate_record_missing` は GV-3（Record 0件、`contract_approval` なし）だけ | GV-1 でも使う: Record ファイルがない（G-02）、再生成 Record が提示されていない（G-13） | N2-2: 矛盾を確認できない欠損は INCOMPLETE | TC-08-22、TC-08-28、TC-08-29 | rev1 の実装では G-02 が `gate_source_missing`（INCOMPLETE）、G-13 が `gate_record_mismatch`（BROKEN）。G-13 の Status は BROKEN から INCOMPLETE に下がるが、COMPLETE にはならない |
| S-5 | `gate_record_mismatch`: 「再生成と1 Field でも違う」 | 再生成に同じ Item がなく、その種類の Raw が完全に読めた場合（G-09）も含める | 修正要件 3: 確認できた矛盾は BROKEN | TC-08-26 | rev1 の実装では G-09 が INCOMPLETE。BROKEN に上がる |
| S-6 | `gate_source_missing`: 「Record が参照する Raw がない」（範囲が未定義） | G-08、G-10 に限る。Capture はあるが読めない場合（G-11）は原因のコードだけ | 欠損の原因を1つのコードで表す | TC-08-07〜09、TC-08-27 | G-11 の Status は原因のコードで決まり、rev1 の実装と同じかより厳しい |
| S-7 | §2: `candidate_review` は Reviewer ごとに1件（違反時のコードが未定義） | 2件目以降に `gate_record_invalid`。各 Record は G-12 の比較も受ける | 正しい Record の後に置いた偽造 Record も BROKEN として検出する | TC-08-25 | 未定義の場合を INCOMPLETE 以上に定めた |
| S-8 | §2-4 GV-4 4行目: 「Raw に裏付けのある承認 Record がなく、自己申告だけ」（裏付けの定義なし） | 裏付け = G-12 を通った `decision: approved` の `candidate_review` | rev1 の実装は「`candidate_review` が1件でもあれば」としており、承認でない Record で条件を外せた | TC-08-06、TC-08-24、TC-09-09 | 承認でない Record だけの Chain で、GV-4 が LINKED から NOT_PROVEN になる（厳しくなる側） |
| S-9 | 一次原因と二次的な結果の区別がない（N2 修正の時点では、使えない Record に `gate_record_missing` が重なった） | 使えない Entry の数を超える省略だけに `gate_record_missing`（G-13a、§2-2） | 最終確認 項目3: Result のコードを一次原因に限る | TC-08-29、TC-08-30 | Digest 不一致などで `gate_record_missing` が付かなくなる。Status は使えない Entry のコード（INCOMPLETE 以上）で決まり、下がらない。限界は §2-2 |
| S-10 | §2 規則: 自己申告は「自由記述の承認者（`approved_by` など）」（形の定義なし）。N2 修正の時点の実装は key が `approv` で始まるもの | §2-3 の3つの形に閉じる | 最終確認 項目4: 承認でない Field の誤検出をなくす。検出の漏れは G-04（より厳しい側）になる | TC-08-06、TC-08-23、TC-08-31 | `Approver` などの表記は NOT_PROVEN から INCOMPLETE に上がる（厳しくなる側） |

Catalog（`iacreview/chain/status.py` `REASONS`）では、`gate_record_missing`、`gate_record_mismatch`、`approval_self_declared_only` の説明文を上記に合わせて書き換え、`gate_record_invalid` を追加した。既存コードの Status は変えていない。

共通の互換性: Gate Record 0件の Chain は WP1 と同じ結果（INCOMPLETE `gate_record_missing` だけ、`gate_aspects` なし。TC-10-11）。Finding 13 field、Review_Report、M1 の Schema・固定 Hash・Frozen Evidence は変更していない。

## 4. Test と Mutation

### 4-1. N2 修正 Review で承認（`m2-acceptance-test-matrix.md` に反映済み）

| TC | Test（`tests/unit/test_chain_gate.py`） | 行 |
| --- | --- | --- |
| TC-08-22 | `test_g_02_an_absent_record_file_is_missing_not_a_missing_raw` | G-02 |
| TC-08-23 | `test_g_04_a_record_outside_the_schema_is_invalid_not_a_self_declaration`（10入力） | G-04 |
| TC-08-24 | `test_g_05_a_self_declaration_next_to_a_real_approval_is_not_hidden`（3入力） | G-05、S-3 |
| TC-08-25 | `test_g_07_a_record_presented_twice_is_invalid_and_each_copy_is_compared` | G-07、S-7 |
| TC-08-26 | `test_g_09_a_reviewer_the_complete_raw_does_not_have_is_broken`、`test_g_09_a_merge_decision_of_another_pull_is_broken` | G-09 |
| TC-08-27 | `test_g_10_g_11_a_record_whose_raw_cannot_be_read_is_never_broken_by_the_record` | G-10、G-11 |
| TC-08-28 | `test_g_13_a_record_left_out_is_missing_not_broken`（3入力） | G-13 |
| TC-08-29 | `test_g_one_bad_record_among_good_ones_decides_the_gate`（6入力）、`test_g_several_bad_records_keep_every_cause` | 原則 4 |

最終確認での変更（承認済みの TC の中）:
* TC-08-23 の入力に、承認でない Field と未定義の表記の4入力を追加した（6 → 10入力）。N2 修正の時点の補助 Test `test_g_04_the_self_declaration_test_reads_only_failed_records` は、TC-08-31の2つの Test に置き換えた
* TC-08-29 の `digest` の期待を `gate_record_mismatch` と `gate_record_missing` から `gate_record_mismatch` だけに変えた（S-9）。`test_g_several_bad_records_keep_every_cause` は、省略が使えない Entry で説明されないよう、Schema 違反の Entry の `kind` を `merge_decision` にした（期待するコードは同じ4つ）

### 4-2. 最終確認で追加（Final Specification Review で承認、`m2-acceptance-test-matrix.md` に反映済み）

| TC | Test | 行 | 期待 |
| --- | --- | --- | --- |
| TC-08-30 | `test_g_13a_the_primary_cause_is_not_doubled_by_a_secondary_missing_code` | G-13a、S-9 | §2-2 の表の上3行 |
| TC-08-31 | `test_g_05_the_three_self_declaration_forms`（7入力）、`test_g_05_other_fields_and_undefined_wording_are_not_self_declarations`（24入力） | G-05、S-10 | §2-3 の表どおり |

| ID | 条件 | Kill Test |
| --- | --- | --- |
| MU2-60 | 使えない Entry の二次的な結果にも `gate_record_missing` を付ける | TC-08-30 |
| MU2-61 | key が `approv` で始まれば自己申告とする（N2 修正の時点の規則） | TC-08-31 |
| MU2-62 | 自己申告の Entry を「使えない Entry」に数え、省略を隠す（Status が弱くなる） | TC-08-30 |

* Mutation の期待件数: 56 → 59（MU2-60〜62、承認済み）
* CI 必須 Test: 65 → 70（TC-08-30、TC-08-31 の3件と、TC-08-26・27 で必須に入っていなかった2件、承認済み）

## 5. 確認していないこと

* 実 GitHub の応答に対する G-04（strict JSON）の適合: NOT_VERIFIED（N2-4、WP5 で確認）
* G-13a の限界（省略と同じ `kind` の使えない Entry の追加が同時にある場合）: §2-2
