# Phase 2 / M2 — WP0 rev2: WP2 Design Audit の Human Review の反映

* 状態: **WP0 rev2。設計文書だけを変更した。** Production Code、Test、期待 Hash は変更していない。Commit、Push、Merge、Ruleset 変更はしていない。WP2 の実装は Human 承認まで開始しない
* 入力: `docs/v2/phase2/m2/wp2/wp2-design-audit.md`（91/100、条件付き承認）、Human 決定 D2-1〜D2-6
* rev1 の写し: 非公開の作業記録（`.agents/`、Git 管理外）に保存し、差分の計算に使った

## 1. 必須設計修正への対応

| # | 修正事項 | 対応 | 反映先 |
| --- | --- | --- | --- |
| 1 | GV-2 を Account 分離の観測に限定し、Approval Authority を証明済みと表示しない | GV-2 を「Account Separation（観測）」に改名。LINKED は「Raw の上で別 Account の承認が観測された」ことだけ。Result に定数 `observed.approval_authority: "NOT_PROVEN"`。`author_association` は Record の観測値だけで、判定にも Payload にも使わない（D2-1）。`approver_association_not_shown` を削除 | `m2-schemas.md` §2-3、§2-4、§3 |
| 2 | APPROVED、CHANGES_REQUESTED、COMMENTED、PENDING、DISMISSED を含む集約規則 | §2-2 の手順 1〜3 と Decision Table R-01〜R-16。並べ順は `(submitted_at, id)` で、API の配列順を使わない（D2-2） | `m2-schemas.md` §2-2 |
| 3 | 同一 Reviewer の複数 Review と Dismissal | 最後の決定 Review（APPROVED / CHANGES_REQUESTED / DISMISSED）が状態を決める。DISMISSED は以前の承認を打ち消す。同時刻で状態が違えば `review_order_ambiguous`、時刻順と id 順が食い違えば `review_order_inconsistent`（どちらも NOT_PROVEN、数えない）。却下の時刻・却下者は Reviews API にないため NOT_PROVEN | `m2-schemas.md` §2-2 |
| 4 | Evidence を Manifest に列挙された同一 Revision の Raw に限定 | §2-1 の E-1〜E-7。Record の `source` を `capture_id` と全 Page の `evidence_ids` に変更 | `m2-schemas.md` §2、§2-1 |
| 5 | Pagination の完全性、重複 Page、欠損 Page、競合する Review の Fail-closed | 欠損・途中終了・不完全 → INCOMPLETE `review_capture_incomplete`。重複 Page・同一内容の重複 Review → INCOMPLETE `review_capture_duplicate`。同じ id で内容が違う Review → BROKEN `review_conflict` | `m2-schemas.md` §2-1、§2-2、§2-4 |
| 6 | Chain COMPLETE の意味を Evidence Chain の検証完了に限定 | §2-6 を新設。意味しないものを列挙し、Summary の固定文言と定数の観測値を定義 | `m2-schemas.md` §2-6、§3 |
| 7 | GV-1〜GV-4 の Status と Reason Code を Test Case に対応付ける | §13-1 の表（全コード → Test Case）、Decision Table → Test Case | `m2-acceptance-test-matrix.md` §13-1 |
| 8 | M1 固定 Hash と WP1 Anchor の保護方法を維持 | §4 の手順。M1 は無変更、WP1 Anchor は新旧比較なしに更新しない、Gate の Anchor は別ファイル | 本書 §4 |

## 2. Human 決定の反映

| ID | 決定 | 反映 |
| --- | --- | --- |
| D2-1 | `author_association` を GV-2 の安全性判定から除外、観測値のみ | `m2-schemas.md` §2（Field 表）、§2-3、§3。Test TC-10-06、Mutant MU2-41 |
| D2-2 | Reviewer ごとの最新の有効 Review。配列順への依存禁止 | `m2-schemas.md` §2-2。Test TC-08-03、TC-08-15〜17。Mutant MU2-33、MU2-42 |
| D2-3 | `gate_evaluation_not_implemented` を維持 | `m2-schemas.md` §2-4 末尾、§4。Test TC-10-11 |
| D2-4 | Gate を含む新しい Anchor を追加、WP1 Anchor を上書きしない | 本書 §4 |
| D2-5 | MU2-33 以降を承認、既存 Mutant を維持 | `m2-acceptance-test-matrix.md` §13-2（MU2-33〜MU2-45） |
| D2-6 | WP0 rev2 を作成 | 本書と各文書 |

WP1 で保留していた差異も rev2 で仕様に取り込んだ: N-1（`gate_evaluation_not_implemented`、`link_check_error` を正式な語彙に）、N-2（`finding_id` は整数。`m2-schemas.md` §1 の例を修正）、N-3（TC-04-02、TC-06-05 の期待値を (a) Finding なし → BROKEN、(b) Finding あり → INCOMPLETE に修正）、`metadata.diagnostics`（§3 で正式化）。N-4（`tools[]` が1件以上）は既存の P-A の定義どおりで、文書の変更はない。

## 3. Gate Schema と Status の確定案（要約）

正本は `m2-schemas.md` rev2 §2〜§4。

| 観点 | LINKED の条件 | BROKEN | INCOMPLETE | NOT_PROVEN |
| --- | --- | --- | --- | --- |
| GV-1 Integrity | Record が §2-1 の範囲の Raw から §2-2 で再生成したものと一致 | `gate_record_mismatch`、`review_conflict` | `gate_source_missing`、`gate_source_integrity_not_pass`、`review_capture_incomplete`、`review_capture_duplicate` | `gate_source_unrecognized`、`review_order_ambiguous`、`review_order_inconsistent`、`review_dismissal_effect_unknown`、`approval_self_declared_only` |
| GV-2 Account Separation（観測） | 別 Account の集約後の承認が1件以上、未解決の変更要求なし | — | — | `separation_of_duty_not_shown`、`approval_not_shown`、`changes_requested_outstanding`、`actor_relation_unknown` |
| GV-3 Revision Binding | Contract 承認 = config commit、Head への有効承認が1件以上 | `approval_revision_misrecorded`、`gate_binds_other_commit` | `gate_record_missing` | `approval_on_previous_head_only`、`approval_revision_unverifiable` |
| GV-4 Staleness | 取得時の `pull.head.sha` = Head | `pr_head_mismatch` | — | `approval_revision_unverifiable`、`approval_self_declared_only` |
| GV-5 Merge Enforcement | 判定しない | — | — | `not_claimed: merge_enforcement`（常に） |

## 4. 既存 WP1 への互換性影響

| 対象 | 影響 | 保護方法 |
| --- | --- | --- |
| M1 固定 Hash・Frozen Evidence・Definition・Evaluator Source | なし | `iacreview/evidence/` を読むだけ。RG-1、TC-00-01 |
| WP1 の Reason Code | `gate_evaluation_not_implemented`、`link_check_error` は維持。追加だけで削除なし（`approver_association_not_shown` は rev1 の案にあっただけで、WP1 の Catalog には未登録） | `test_every_reason_code_is_traceable`、`test_every_code_the_package_emits_is_in_the_catalog`。TC-10-11 |
| WP1 の Result の形 | Gate Record 0件の Chain は WP1 と同じ形（`gate_aspects` を出さない）。Record がある Chain だけ `gate_aspects` と `observed` が増える | TC-10-11 |
| WP1 Anchor（`tests/fixtures/chain_replay/expected.json`） | `iacreview/chain/` が変わるため Validator Source は必ず変わる。Replay fixture は Gate Record 0件なので、Payload の変化は `validator.source_sha256` だけになる見込み（NOT_VERIFIED） | 下記の手順 |
| `chain_ci_check.py` | 既存の `expected.json` の key 集合（`sc01`、`sc02`）の検査は変えない。Gate の Anchor を読むには Script の追加が要る | CI Gate の変更として Human 承認（下記） |

WP1 Anchor の更新手順（WP2 の実装時。D2-4、必須修正 8）:

1. 旧値を記録する（Validator Source `0790a1ca4265105a2fe34c434465ede979614cedc7b1c0e5bf8b42d4677b23ee`、SC-01 `7c5c30cf9c07f330d58f27c42b52cc5e14b4652bde0ad8703178ce85eccc7940`、SC-02 `f24c000188bca6349fcb75c3f130115d12225d7e52047ca22c4f20ed925b6736`、manifest は不変の見込み）
2. 新 Payload の `validator.source_sha256` を旧値に戻すと、旧 Payload Digest と一致することを両 Scenario で確認する。一致しなければ更新せず停止し、原因を Human に報告する（`chain_status`・`links` が変わった場合は WP1 との互換性の破れ）
3. 旧値・原因・新値・手順 2 の結果・Test 結果を `expected.json` の `note` と WP2 の報告に記録し、Human Review を経て更新する

Gate を含む Anchor（新規）:

* 別ファイル `tests/fixtures/chain_replay/expected-gate.json`（形式 `iacreview.chain.replay-expected-gate/1`）。既存 `expected.json` の key 集合と意味を変えない
* 内容（案）: 合成の SC-02 Chain に Gate Record を付けた3種 — COMPLETE（2 Account、Head に承認）、NOT_PROVEN（単一 Owner、`approval_not_shown`）、BROKEN（承認の後の Push で Chain が古い Head を検証、`pr_head_mismatch`）。各 `chain_status`、`manifest_sha256`、Payload の SHA-256
* 値は実装の出力を記録する Regression Anchor で、正しさの独立した証明ではない。各 Scenario の `chain_status` とコードは、本 Matrix の期待（TC-10-07、TC-10-04、TC-09-04）と先に一致させてから記録する
* `chain_ci_check.py` に新ファイルの検査を加えるのは CI Gate の変更で、WP2 の実装時に Human 承認を得る

## 5. 追加 Test / Mutation 計画（要約）

* Test: TC-08-01〜18（rev1 の8件から18件）、TC-09-01〜09（8件から9件）、TC-10-01〜11（9件から11件）。全コードと Decision Table の行を Test Case に対応付けた（Matrix §13-1）
* Mutant: MU2-33〜MU2-45 を追加（13個、合計45個）。MU2-44 / 45 は WP1 N-5 の処理に Mutant がなかった欠落の補完
* 合成 Raw は WP1 の `tests/unit/chain_synth.py` を拡張して作る（M1 の `evidence_synth.py` は変更しない）。複数 Page、重複 Page、欠損 Page、Review の並べ替えを作れるようにする

## 6. 未証明事項と Human 判断が必要な残課題

未証明（M2 では変わらない）:

* Raw の出所（`capture_authenticity`）、承認者の権限、Ruleset で数えられたこと、Merge Enforcement、Account の背後の人間
* Review の却下の時刻・却下者・理由（Timeline Events を取得しない）
* 取得後の PR の変化（GV-4 は取得時点だけ）
* Raw・Store MANIFEST・Chain Manifest・Local Git の整合的な全面改変（`m2-threat-model.md` §5）
* GitHub の Review id が提出順に増えること。rev2 は id を順序の根拠にせず、時刻順と食い違えば NOT_PROVEN にする

Human 判断が必要な残課題:

| ID | 事項 | 案 |
| --- | --- | --- |
| R2-1 | 2人の承認のうち1人だけ古い Head に対する承認の場合を BROKEN（TC-09-03）とするか。GitHub の「古い承認の自動却下」設定なしでは正規に起こりうる | rev2 は D-3 に従い BROKEN（不一致の確認）。代案: 古い承認は数えず、Head への承認だけで GV-2 / GV-3 を判定する |
| R2-2 | 未解決の CHANGES_REQUESTED を GV-2 の NOT_PROVEN にするか（`changes_requested_outstanding`） | rev2 は NOT_PROVEN。Ruleset の挙動は主張しない |
| R2-3 | PR 作成者自身の Review を Record に含めるか | rev2 は含める（`same_actor` として観測し、数えない） |
| R2-4 | Gate の Anchor の3 Scenario と、`chain_ci_check.py` への検査追加 | §4 の案 |
| R2-5 | WP2 の Branch の作成（Merge 後の main `3366208…` からの作成。Agent は fetch できない） | Human 操作 |

## 7. 変更差分（rev1 → rev2、行数）

`git diff --no-index --numstat` で、rev1 の写しと rev2 を比べた結果。

| ファイル | 追加 | 削除 | 主な変更 |
| --- | --- | --- | --- |
| `m2-schemas.md` | 189 | 83 | Gate Record の Field（`capture_id`、全 Page の `evidence_ids`、`deciding_review_ref`、`decision: none`）、§2-1 Evidence の範囲、§2-2 集約規則と Decision Table、§2-3〜2-4 の GV 規則、§2-5 事実の区別、§2-6 COMPLETE の意味、§3 Result 例と `metadata.diagnostics`、§4 理由コード、§1 の `finding_id` 例 |
| `m2-acceptance-test-matrix.md` | 116 | 53 | 状態行、§0 の GV-2 の表記、TC-04-02 / TC-06-05（N-3）、M2-08〜M2-10 の再構成、§13 の対応表、§13-1 Status / Code → Test、§13-2 追加 Mutant |
| `m2-threat-model.md` | 2 | 2 | 状態行、T-05 |
| `m2-work-plan.md` | 4 | 4 | 状態行、WP2 の行 |
| `github-e2e-plan.md` | 1 | 1 | GV-2 の表記 |
| `wp0-revision-2.md` | 新規 | — | 本書 |

変更していないもの: `m2-scope-and-baseline.md`、`passed-all-checks-investigation.md`、`wp0-revision-1.md`、`docs/v2/phase2/m2/wp1/`、`docs/v2/phase2/m2/wp2/wp2-design-audit.md`（監査時点の記録として残す）、Production Code、Test、期待値、CI。

## 8. rev2 追補（R2-1〜R2-5 の Human 決定、94/100 条件付き承認）

§6 の残課題 R2-1〜R2-5 は次のとおり決定され、`m2-schemas.md` §2-2〜§2-4、§2-6、§4 と Matrix M2-08〜M2-10、§13 に反映した。

| ID | 決定 | 反映 |
| --- | --- | --- |
| R2-1 | 古い Head への承認は有効承認に数えないが、それだけで BROKEN にしない。Revision の偽装は BROKEN。Head への承認がなければ NOT_PROVEN | GV-3 に `approval_on_previous_head_only`（NOT_PROVEN）と `approval_revision_misrecorded`（BROKEN）を分けて追加。rev1 の `approval_stale` を廃止し、GV-4 は Subject と PR の Head の比較だけ（`pr_head_mismatch`、BROKEN）。§6 の R2-1 の rev2 案（BROKEN）は撤回 |
| R2-2 | 未解決の CHANGES_REQUESTED は NOT_PROVEN、専用コード、COMPLETE 禁止 | `changes_requested_outstanding`（GV-2）。Commit に関係なく未解決として扱う（R-21）。§2-6 に COMPLETE 禁止を明記 |
| R2-3 | PR 作成者自身の Review は Record に含め、有効承認に数えない | §2-2「有効承認」、R-22 |
| R2-4 | Gate を含む COMPLETE / NOT_PROVEN / BROKEN の3例を別 Anchor に | §4 の案のまま（NOT_PROVEN は単一 Owner の `approval_not_shown`、BROKEN は `pr_head_mismatch`） |
| R2-5 | WP2 は Merge 後の main を基点とする専用 Branch | `m2-work-plan.md` WP2 の行のまま（Branch 作成は Human 操作） |

設計修正 1〜8 の反映先:

| # | 修正 | 反映先 |
| --- | --- | --- |
| 1 | 古い Head への承認と Revision 偽装を別々に判定 | `m2-schemas.md` §2-4 GV-3 |
| 2 | Review id 単位の Dismissal と Reviewer 単位の集約の分離 | §2-2 段階 A-3 と段階 B |
| 3 | 配列順に依存せず、曖昧な順序は Fail-closed | §2-2 段階 B（`review_order_ambiguous`、`review_order_inconsistent`、`review_dismissal_effect_unknown`） |
| 4 | GV-2 は Account Separation の観測に限定 | §2-3、§2-4 GV-2 |
| 5 | `author_association` を権限の判定に使わない | §2、§2-3（変更なし、維持） |
| 6 | 未解決の CR、古い承認、Evidence 欠損のコードを区別 | §2-4 末尾「理由コードの区別」、Test TC-09-12 |
| 7 | COMPLETE の意味を照合完了に限定 | §2-6（未解決 CR・古い承認・Evidence 欠損で COMPLETE にならないことを追記） |
| 8 | M1 固定 Hash と WP1 Anchor の保護 | 本書 §4（変更なし、維持） |

追加・変更した理由コード（WP1 の Catalog には未登録のため、WP1 との互換性への影響なし）: 追加 `approval_on_previous_head_only`、`approval_revision_misrecorded`、`pr_head_mismatch`、`review_dismissal_effect_unknown`。廃止 `approval_stale`（rev1 / rev2 案のみに存在）。

残る未証明事項: §6 のとおり。加えて、GitHub が却下済み Review の後にそれ以前の Review を有効として扱うかは Raw から決められないため、該当する Reviewer は数えない（`review_dismissal_effect_unknown`）。

変更していないもの: Production Code、Test、CI、期待 Hash、`m2-scope-and-baseline.md`、`passed-all-checks-investigation.md`、`wp0-revision-1.md`、`docs/v2/phase2/m2/wp1/`、`docs/v2/phase2/m2/wp2/wp2-design-audit.md`。
