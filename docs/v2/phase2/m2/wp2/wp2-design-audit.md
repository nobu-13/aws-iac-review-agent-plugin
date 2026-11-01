# Phase 2 / M2 / WP2 — 設計監査と実装計画（Human Gate Record と Revision Binding）

* 状態: **設計監査のみ。** 実装、Commit、Push、Merge、Ruleset 変更はしていない。既存ファイルは変更していない
* 監査対象: `docs/v2/phase2/m2/wp0/`（rev1）、`iacreview/chain/`、`iacreview/remediation/`、`iacreview/evidence/`
* 判定語: PASS / FAILED / NOT_PROVEN。NOT_VERIFIED は「実行・確認していない」

## 0. Evidence の区分

### 0-1. Human 提供 Evidence（Agent は Network 上で確認していない）

| 項目 | 値 | Agent 側の状況 |
| --- | --- | --- |
| WP1 Acceptance | PASS | — |
| PR #9 の Merge Commit | `336620859a5496b253bb347c40cbd462f45fb3ef` | NOT_VERIFIED。Local Repository に object がない（未 fetch） |
| main CI Run | `41030602479`、Required Checks 10/10 PASS | NOT_VERIFIED |
| Public CI の SKIP 3件（M1 Local-only） | 維持 | 設計どおり（`evidence_ci_check.py` `LOCAL_ONLY`） |

### 0-2. Agent が Local で独立に確認した事項（監査時点）

| 項目 | 結果 |
| --- | --- |
| Branch / HEAD | `feature/phase2-m2-wp1`、`76e1b51`（親 `9f63bfe`、その親 `c1b4d82`）。作業ツリー clean |
| Local の `origin/main` | `c1b4d82`（最終 fetch 時点。Merge 後の main は未取得） |
| M2 Validator Source | `0790a1ca4265105a2fe34c434465ede979614cedc7b1c0e5bf8b42d4677b23ee`（Human 提供値と一致） |
| M1 `expected.json` | `ebe177bdd64e8ec74d90fab0c44ff4f982e93122109c9df8cfa524166346e841`（不変） |
| M2 `expected.json` | `f077e03f0ade7961a9b6ff4f38815e385985181ee7e9f769a90ea217e23bf42c`（WP1 Revision 2） |
| 現行の gate 関連 Reason Code | `gate_record_missing`、`gate_evaluation_not_implemented`、`link_check_error` のみ。GV-1〜GV-4 のコードは Catalog に未登録 |

Local の `76e1b51` が Merge 後の main と同じ Tree かは NOT_VERIFIED。WP2 の Branch は Merge 後の main から作る必要がある（§10）。

## 1. WP0 rev1 の Gate Record Schema と GV-1〜GV-4 の整合性

確認方法: `m2-schemas.md` §2、`m2-acceptance-test-matrix.md` M2-08〜M2-10、`iacreview/chain/` の現行実装、`iacreview/evidence/` の Store と Envelope を読み合わせた。

| ID | 所見 | 分類 | 提案 |
| --- | --- | --- | --- |
| A-1 | GV-2 の LINKED 条件に「`author_association` が OWNER / MEMBER / COLLABORATOR」が入っている。WP2 の制約「`author_association` は承認権限の証明として扱わない」と緊張関係にある。必要条件として使うだけでも、権限の部分的な根拠として扱っていることになる | 確認済みの設計上の不整合 | **`author_association` は `observed` に写すだけにし、GV-2 の判定に使わない**（推奨）。GV-2 の LINKED は `distinct_actor` と `approved` だけで決める。`approver_permission` は従来どおり `not_claimed`。理由コード `approver_association_not_shown` は削除。Human 決定 D2-1 |
| A-2 | 1人が複数回 Review した場合（APPROVED の後に CHANGES_REQUESTED など）、どの Review を数えるかが未定義 | 仕様の欠落 | 「Reviewer ごとに、Raw の配列順で最後の `APPROVED` / `CHANGES_REQUESTED` / `DISMISSED` を、その Reviewer の状態とする。`COMMENTED` は状態を変えない」と固定する。最後が `CHANGES_REQUESTED` の Reviewer がいれば GV-2 は `approval_not_shown`。D2-2 |
| A-3 | `DISMISSED` を「写像表外 → `gate_source_unrecognized`（NOT_PROVEN）」としているが、DISMISSED は GitHub の正規の状態で、承認の取り消しを意味する | 仕様の誤り | DISMISSED は写像表に入れ、その Reviewer の承認がない状態として扱う。表外（`PENDING` を含む）だけを `gate_source_unrecognized` にする |
| A-4 | Gate Record の `source.store_revision` と Chain Manifest の `github_evidence.revision` の関係が未定義。別 Revision や Manifest が名指ししない Evidence を出典にできてしまう | Risk（Trust Boundary の穴） | Record の出典は `github_evidence.evidence_ids` に含まれ、同じ Revision にあることを必須にする。違反は GV-1 `gate_source_missing`（INCOMPLETE）。`github_evidence` が `null` で `candidate_review` がある場合も同じ |
| A-5 | Collector は1 Page を1 Evidence にする（`cap-…-p001`、`-p002`）。`pull_reviews` が複数 Page のとき、Record は1つの Evidence id しか指せない | 仕様の欠落 | `source.evidence_id` は Capture の全 Page を表す一覧（`evidence_ids`）にする。Builder は全 Page を連結した Review 列から再生成する。Capture が `INCOMPLETE`（V5）なら GV-1 `gate_source_integrity_not_pass` |
| A-6 | `contract_approval`（`git_ancestry`）は Raw を持たず、内容は contract Link（`config ⊑ base`、Digest）と重複する | 重複 | 残す（Gate の観点を1か所で読めるようにするため）が、再生成元は Git の事実だけ（`binds_to.commit = contract.config_commit`）。contract Link が BROKEN なら GV-3 は判定せず contract Link の結果に従う（二重計上しない） |
| A-7 | Manifest の `gate_records[].kind` と Record 本体の `kind` が両方ある | 冗長 | 既定どおり Record 本体で判定。不一致は GV-1 `gate_record_mismatch` |
| A-8 | `approval_revision_unverifiable` と `approval_self_declared_only` が GV-3 / GV-4（GV-1 / GV-4）の両方に出る。現行の `status.Reason` は Link 単位で、観点の区別を持たない | 実装上の不足 | `Reason` に `aspects` を追加するか、`gate_aspects` の各観点にコードを置き、Link のコードは観点の和集合にする（WP2 で後者を推奨。Catalog の型は変えない） |
| A-9 | `observed_at` は Raw の時刻を写すが、判定に使わない | 整合 | そのまま。Record にだけ置き、Chain Result の Payload に入れない |
| A-10 | `merge_decision` は Status を変えない観測 | 整合 | そのまま。GV-5 は判定しない |

## 2. GitHub Raw からの Record 再生成

```text
M1 Store (Revision r, Integrity PASS)          Local Git
  pull        : PR の head.sha / base.sha / user.id / merged / state
  pull_reviews: [ {id, state, commit_id, user.id, author_association, submitted_at}, ... ]（全 Page）
        │                                         │ config_commit
        ▼                                         ▼
  Gate Record Builder（純関数。入力は bytes と Commit id だけ）
        │ canonical JSON
        ▼
  再生成した Record 集合  ──比較──  Manifest が指す Record ファイル（Untrusted）
```

* Builder の入力型は「Store の Raw bytes（Envelope と照合済み）」と「Git の Commit id」だけ。任意の dict や Agent 出力を受ける引数を持たない（TC-10-08）
* JSON は strict に読む（M1 `facts._json` と同じく、壊れていれば Record を作らない）。`user.id` は整数のみ受け付け、文字列や欠落は `unknown`
* Raw の Login、Avatar URL、Email、`html_url` は Record に写さない。`actor_ref = "u:" + sha256(str(user.id))[:12]`
* 比較は canonical bytes の完全一致。Manifest の Digest と Record ファイルの Digest の不一致も `gate_record_mismatch`
* 再生成は M1 の Store を読むだけで、M1 Code（`store`、`integrity`、`envelope`、`collector`）を変更しない

## 3. 承認者の Account 識別と PR 作成者との分離

| 事実 | 出典 | 扱い |
| --- | --- | --- |
| Reviewer の Account | `pull_reviews[].user.id` | `actor_ref`（仮名） |
| PR 作成者の Account | `pull.user.id` | 比較だけに使い、Record には `relation_to_head_author` として残す |
| `distinct_actor` | 2つの `user.id` が異なる | GV-2 の LINKED 条件 |
| `same_actor` | 同じ | NOT_PROVEN `separation_of_duty_not_shown` |
| `unknown` | どちらかが整数でない・欠落 | NOT_PROVEN `actor_relation_unknown` |

示さないこと（`not_claimed`）: Account の背後の人間（`human_identity`）、Reviewer の権限（`approver_permission`）、承認が Ruleset で数えられたか（`approval_counted_by_rules`）。`author_association` は A-1 の決定に従い観測値。

単一 Owner の Repository では、GitHub が自分の PR の Approve を受け付けないため、GV-2 は `approval_not_shown`（NOT_PROVEN）になる見込み（`github-e2e-plan.md` §6）。

## 4. Revision Binding（GV-3）と Approval Staleness（GV-4）

| 観点 | 比較 | 不一致を確認 | Evidence 不足 | 自己申告のみ |
| --- | --- | --- | --- | --- |
| GV-3 | `contract_approval.binds_to` = `contract.config_commit`、承認 Review の `commit_id` = `subject.head_commit` | BROKEN `gate_binds_other_commit` | NOT_PROVEN `approval_revision_unverifiable` | GV-1 で扱う |
| GV-4 | 取得時の `pull.head.sha` = `subject.head_commit`（承認 Review があればその `commit_id` とも一致） | BROKEN `approval_stale` | NOT_PROVEN `approval_revision_unverifiable` | NOT_PROVEN `approval_self_declared_only` |

D-3（Human 決定）と一致する。追加の確認事項:

* GV-4 は取得時点の状態だけを示す（Time-of-check）。取得後の Push は再取得まで分からない
* `pull.base.sha` は PR の Base Branch の先端で、`subject.base_commit` と一致するとは限らない。WP2 では比較しない（`compare` の照合は WP5）
* `approval_not_shown`（承認がない）の場合、GV-3 の Review 側の比較は対象がないため判定しない（WP0 rev1 §2-2 の注記どおり）

## 5. BROKEN / INCOMPLETE / NOT_PROVEN の使い分け（WP2 で固定する規則）

| Status | 使う場面 | Gate での例 |
| --- | --- | --- |
| BROKEN | 照合先が存在し、矛盾が**確認できた** | Record と Raw の再生成が不一致、Record の Commit と対象 Commit の不一致、`pull.head.sha` と Head の不一致 |
| INCOMPLETE | 必要な Artifact が**ない・読めない・完全でない** | `contract_approval` がない、出典の Raw が Store / Manifest にない、Capture が不完全、Integrity が PASS しない |
| NOT_PROVEN | Artifact は揃ったが、主張に必要な**事実が Evidence にない** | `same_actor`、`user.id` 欠落、承認なし、`commit_id` 欠落、写像表外の状態、自己申告だけ |

判定の原則: 「矛盾が確認できたか」で BROKEN、「入力が欠けたか」で INCOMPLETE、「入力はあるが証明できないか」で NOT_PROVEN。迷う場合は COMPLETE に近づかない側を選ぶ（いずれも COMPLETE にはならない）。

## 6. 既存 Chain Status への統合

* `links.check_gate` を GV-1〜GV-4 の評価に置き換える。`gate` Link の Status = 4観点の代表値（`BROKEN > INCOMPLETE > NOT_PROVEN > LINKED`）
* Gate Record が0件 → 従来どおり INCOMPLETE `gate_record_missing`（WP1 と同じ）
* `gate_evaluation_not_implemented` は WP2 では出なくなる。Catalog から削除するか残すかは D2-3（推奨: 残さない。未使用コードは `test_every_code_the_package_emits_is_in_the_catalog` と逆向きの検査で検出する）
* Gate Link の出力に `gate_aspects`（4観点の Status とコード）を追加する。`observed` に `merge_decision` と `author_association`（A-1）を置く
* `compose` の規則は変えない。COMPLETE は6 Link すべて LINKED のときだけ。WP2 で初めて End-to-end の COMPLETE（TC-06-02）が合成 Chain で到達可能になる
* Validator Identity の Diagnostic（WP1 N-5）と同じく、環境に依存する値は Payload に入れない

## 7. M1 と WP1 Regression Anchor の保護

| 対象 | 方針 | 確認方法 |
| --- | --- | --- |
| M1 固定 Hash、Frozen Evidence、Definition、Evaluator Source | 変更しない（`iacreview/evidence/` は読み取りのみ） | RG-1（`evidence_ci_check.py` exit 0）、TC-00-01 |
| M1 Code の import の向き | Chain → Evidence の一方向を維持 | TC-00-03 |
| WP1 Anchor（`tests/fixtures/chain_replay/expected.json`） | 変わることが予測される。変更は「旧値・原因・新値・元に戻したときの一致」を記録したうえで Human Review を経て行う | 下記 |

Anchor への影響の予測（実行していない、NOT_VERIFIED）:

* `iacreview/chain/` が変わるため、Validator Source（`0790a1ca…`）は必ず変わる
* Replay fixture の Chain は Gate Record 0件なので、`gate` は引き続き INCOMPLETE `gate_record_missing`、`chain_status` も INCOMPLETE のまま
* Payload は `validator.source_sha256` で必ず変わる。`gate_aspects` を Gate Record 0件のときも出す設計なら、その分も変わる
* 検証手順: 新 Payload から (a) Validator Source、(b) 追加した Field を元に戻すと旧 Payload Digest（SC-01 `7c5c30cf…`、SC-02 `f24c0001…`）と一致することを確かめてから値を記録する（WP1 Revision 2 と同じ手順）
* 推奨: Gate を含む新しい Anchor（Gate Record ありの合成 Chain、COMPLETE と NOT_PROVEN の2種）を**別のエントリとして追加**し、既存2エントリの意味（Gate なし）を保つ。追加は Schema `iacreview.chain.replay-expected/1` の `scenarios` key の拡張になるため D2-4

## 8. Test 計画（M2-08〜M2-10）

WP0 rev1 の TC-08-01〜08、TC-09-01〜08、TC-10-01〜09 を基礎に、本監査の修正を反映する。

| AC | Positive | Negative（追加・変更を太字） | Mutation |
| --- | --- | --- | --- |
| M2-08 GV-1 | 同じ Raw から2回同じ bytes。各 `kind` / `decision` | Record の1 Field 改変 → BROKEN。自己申告 Record → NOT_PROVEN。出典 Raw なし → INCOMPLETE。Integrity 不合格 → INCOMPLETE。表外状態 → NOT_PROVEN。**Manifest が名指ししない Evidence / 別 Revision を出典にする → INCOMPLETE（A-4）。複数 Page の Review の1 Page 欠落 → INCOMPLETE（A-5）。Manifest の `kind` と本体の不一致 → BROKEN（A-7）**。Login / Avatar / Email の canary が Record・Result・Summary・例外文に出ない | MU2-21 再生成比較の削除、MU2-22 Schema 違反を承認として数える、MU2-23 `actor_ref` の代わりに login |
| M2-09 GV-3 / GV-4 | 3者一致 → LINKED | 古い Head への承認 → BROKEN。承認後の Push → BROKEN `approval_stale`。`contract_approval` の Commit 違い → BROKEN。`contract_approval` なし → INCOMPLETE。`pull` なし / `head.sha` 欠落 / `commit_id` 欠落 → NOT_PROVEN。自己申告のみ → NOT_PROVEN | MU2-24 Commit 比較の削除、MU2-25 確認できた不一致を NOT_PROVEN に下げる、MU2-26 `pull` なしで LINKED |
| M2-10 GV-2 ほか | 2 Account、Head への Approve → LINKED | same_actor / `user.id` 欠落 / COMMENTED のみ → NOT_PROVEN。**APPROVED の後に同じ Reviewer が CHANGES_REQUESTED → NOT_PROVEN（A-2）。DISMISSED → 承認なし（A-3）。`author_association: NONE` でも GV-2 の Status が変わらないこと（A-1 採用時）**。静的検査（書き込み経路なし、Builder の入力型）。Summary の文言 | MU2-27 same_actor を許す、MU2-28 COMMENTED を承認扱い、MU2-29 `not_claimed` から `merge_enforcement` を外す |
| 統合 | 6 Link LINKED の合成 Chain → COMPLETE（初めて到達、TC-06-02） | Gate だけ NOT_PROVEN → Chain NOT_PROVEN | — |
| 共通 | — | TC-00-01〜04、M1 Mutation 32 / 32、Chain Mutation MU2-01〜20 | **A-1 / A-2 の処理の Mutant を追加する場合は Matrix に追記し事前承認（D2-5）** |

Test は fixture と合成 Repository だけを使い、Network を塞ぐ（P1）。合成 Raw は WP1 の `chain_synth.make_store` を拡張して作る（M1 の `evidence_synth.py` は変更しない）。

## 9. 実 GitHub E2E（WP5）で証明できる事項・できない事項

| 区分 | 事項 |
| --- | --- |
| 証明できる（取得した Raw の範囲で） | Raw が保存後に改変されていないこと（M1 Integrity）。Record が Raw から決定論的に再生成されること。Review の `commit_id`、PR の `head.sha` と Local の Commit の一致 / 不一致。Reviewer と PR 作成者の `user.id` が同じか違うか |
| 証明できない（NOT_PROVEN のまま） | Raw が本当に GitHub から来たこと（`capture_authenticity`）。Reviewer の権限、承認が Ruleset で数えられたこと、Merge Enforcement、Account の背後の人間。取得後の PR の変化。単一 Owner での `distinct_actor` の承認（GitHub が受け付けない） |
| WP2 では扱わない | 実取得（WP4 Transport、WP5）。WP2 は合成 Raw だけで検証する |

## 10. WP2 の最小実装範囲と Acceptance Criteria

### 10-1. 範囲

* 新規: `iacreview/chain/gate.py`（Builder、Reader、GV-1〜GV-4、`gate_aspects`）。`links.check_gate` を `gate.py` の呼び出しに置き換える
* 追加: `status.REASONS` に GV のコード、Reason Code の観点（A-8）
* Test: `tests/unit/test_chain_gate.py`（M2-08〜M2-10）、`chain_synth` の合成 Raw 拡張、Mutant MU2-21〜MU2-29
* CI: `chain_ci_check.py` の必須 Test に Gate の Test を追加（`ci.yml` は変更しない見込み）
* 変更しない: `iacreview/evidence/`、`iacreview/remediation/`、M1 の期待値、`compose` の規則、既存5 Link の判定、CLI（作らない）
* 対象外: Transport（WP4）、実 E2E（WP5）、Merge Enforcement、Ruleset、Kiro Skill

### 10-2. 完了条件

1. M2-08、M2-09、M2-10 の Test Case がすべて期待どおり（FAIL 0、SKIP 0）
2. MU2-21〜MU2-29 を全数検出。MU2-01〜20 と M1 の 32 Mutant も全数検出のまま
3. 合成 Chain で COMPLETE と、Gate 起因の NOT_PROVEN / BROKEN / INCOMPLETE の各1例が再現する
4. RG-1〜RG-9、TC-00 が PASS。M1 固定 Hash 不変
5. WP1 Anchor の更新は §7 の手順の記録つき。Gate を含む Anchor の追加は D2-4 の決定どおり
6. Record、Result、Summary、Log に Login・Email・Token の canary が出ない
7. Python 3.9 / 3.11 / 3.13 の CI で同じ Payload Digest（環境依存値が Payload にない）。CI 結果は Human 提供 Evidence として記録し、Agent が確認できなければ NOT_VERIFIED

### 10-3. 着手前の前提

* WP2 の Branch を Merge 後の main（Human 提供 `3366208…`）から作る。Agent が fetch できない場合は Human 操作が必要
* §11 の Human 決定

## 11. Human 決定が必要な事項

| ID | 事項 | 推奨 |
| --- | --- | --- |
| D2-1 | `author_association` を GV-2 の判定から外し観測値だけにするか（A-1） | 外す |
| D2-2 | 同一 Reviewer の複数 Review の数え方（A-2） | 最後の APPROVED / CHANGES_REQUESTED / DISMISSED |
| D2-3 | `gate_evaluation_not_implemented` を Catalog から削除するか | 削除 |
| D2-4 | Gate を含む Replay Anchor を別エントリとして追加するか（Schema の `scenarios` の拡張） | 追加 |
| D2-5 | A-1 / A-2 / A-4 / A-5 の処理に Mutant を追加するか（MU2-33 以降） | 追加（WP1 の N-5 と同じ欠落を作らない） |
| D2-6 | WP0 rev1 の修正（A-1〜A-5、A-7、A-8、および WP1 で保留の N-1〜N-4・`metadata.diagnostics`）を WP0 rev2 として文書化するか | rev2 として `m2-schemas.md` と Matrix に反映し、WP2 の実装前に承認 |
