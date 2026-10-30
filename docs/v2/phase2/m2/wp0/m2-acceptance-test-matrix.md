# Phase 2 / M2 — Acceptance Test Matrix（M2-01〜M2-12）

状態: **事前定義（WP0 rev1）。未実施。** この表は実装前に固定する。実装後に結果を見て条件を変えない。変更が必要なら新しい Revision と理由を残し、Human の承認を得る。rev0 からの変更は `wp0-revision-1.md` に記録した。

判定語（M1 と同じ）:

* PASS: 事前に固定した条件を、実行した Test / 検査の結果で満たした
* FAILED: 事前に固定した条件に、実行結果が反した
* NOT_PROVEN: 判定に必要な Test / Evidence がない、未実施、Tool 不在、Timeout

NOT_PROVEN、SKIP、Tool 不在、Timeout を PASS として数えない。1つの AC に FAILED の条件が1つでもあれば、その AC は FAILED。AC の PASS は「その AC の Test Case がすべて期待どおり」で、Test Case の一覧（§13）を AC ごとに固定する。

共通の事前条件（全 AC）:

* P0: M1 Baseline と変更禁止範囲（`m2-scope-and-baseline.md` §3、§4 F-1〜F-7）が無変更。Regression 条件 RG-1〜RG-9 が PASS
* P1: GitHub API を呼ぶのは M2-12 だけ。M2-01〜M2-11 の Test は fixture と Local の合成 Git Repository だけを使い、Test 実行中は socket を塞ぐ（M1 の fixture と同じ方式）
* P2: Dependency を追加しない（`pyproject.toml` 不変）
* P3: Schema と語彙は `m2-schemas.md` rev1（D-2 で固定）に従う

Test の種類:

* Positive: 正しい入力で、期待した Status / 値が出る
* Negative: 1点だけ壊した入力で、期待した Status と理由コードが出る（他の Status に落ちない）
* Mutation: Validator の Code に Mutant を入れ、Test がそれを検出する（M1 と同じく Mutant の集合に対する検出率だけを主張する）。Mutant ID は `MU2-xx`。M1 の32 Mutant は別に維持する（RG-4）

用語: 「Chain Root」は Manifest のあるディレクトリ。「合成 Repository」は Test が `git init` で作る Repository（Phase 1 の Test と同じ方式）。Test Case ID は `TC-<AC番号>-<連番>`。`TC-00-xx` は全 AC 共通。

## 0. AC の責務の分け方（rev1 の再点検の結果）

| 層 | AC | 判定するもの | 判定しないもの |
| --- | --- | --- | --- |
| 入力 | M2-01 | Manifest の Schema、Canonical 形式、Locator の安全性、Manifest で選べない値（`api_artifact`） | Link の中身 |
| Link（Artifact） | M2-02〜M2-05 | 各 Link 単独の Status と理由コード | Chain Status、Gate |
| Chain の合成 | M2-06 | Link Status から Chain Status を作る規則と Fail-closed。Link をまたぐ安全側の判定（例: Review が INCOMPLETE なら他が揃っていても COMPLETE にならない） | 各 Link の内部判定 |
| 再現性 | M2-07 | 同じ入力から同じ bytes | — |
| Gate | M2-08〜M2-10 | GV-1 Integrity（M2-08）、GV-3 Revision Binding と GV-4 Staleness（M2-09）、GV-2 Approval Authority と自動化しないこと、GV-5 を主張しないこと（M2-10） | Review_Report の完全性（Gate ではない） |
| 取得 | M2-11、M2-12 | Transport の安全性（fixture）、実 E2E | — |

M2-04 の `errors[]` の異常系についての確認結果: `errors[]` を持つ Review_Report は **Chain の Fail-closed（入力の完全性）** に属し、Human Gate には属さない。Human Gate は「誰がどの Commit を判断したか」だけを扱い、Review_Report を読まない。rev1 では次のように分けた。

* M2-04: `review` Link 単独で `INCOMPLETE`（`review_report_has_errors` / `review_tool_unavailable`）になること
* M2-06: その `INCOMPLETE` が、Verification が `VERIFIED` で Gate が揃っていても、Chain を `COMPLETE` にしないこと（外部 Consumer の誤読に対する安全側の判定、TC-06-05、TC-06-06）

rev0 の重複の解消: rev0 の M2-10 の「Agent 出力を Gate Record として渡す」は M2-08（GV-1）へ移した。rev0 の M2-09 の職務分離は M2-10（GV-2）へ移した。rev0 の M2-03 の `api_artifact` の拒否は M2-01 へ移した。

---

## M2-01 Chain Manifest の Schema と Canonical 形式

| 項目 | 内容 |
| --- | --- |
| 入力 | Chain Manifest の JSON ファイル（`m2-schemas.md` §1） |
| 観測 | Manifest Reader の結果（受理 / 拒否、`manifest_codes`）、受理した Manifest の Canonical bytes と SHA-256、CLI の exit code |
| PASS | TC-01-01〜TC-01-06 がすべて期待どおり |
| FAILED | Negative のどれか1つでも受理する、別の理由コードになる、未処理の例外が出る、exit code が 34 以外 |
| NOT_PROVEN | Test 未実施 |
| Mutation | MU2-01 未知 key の検査を外す、MU2-02 Locator の Containment 検査を外す、MU2-03 Canonical 化で `sort_keys` を外す |
| 必要 Evidence | pytest の JUnit（件数、exit code）、Mutation の検出結果 |
| 担当 | WP1 |

| TC | 種類 | 入力 | 期待 |
| --- | --- | --- | --- |
| TC-01-01 | Positive | 正しい Manifest 3種（review あり / review なし / github_evidence なし） | 受理 |
| TC-01-02 | Positive | TC-01-01 の key 順・空白を変えたもの | Canonical bytes と SHA-256 が同じ |
| TC-01-03 | Negative | 未知 key（各階層）、重複 key、必須 key 欠落、型違い、`NaN` / `Infinity` / 浮動小数点、40 hex でない Commit、大文字 hex、語彙外の `acquisition` / `kind`、`finding_id` 重複、`evidence_ids` 重複 | `manifest_invalid`、exit 34 |
| TC-01-04 | Negative | `acquisition: api_artifact` | `manifest_invalid`（M2 では選べない） |
| TC-01-05 | Negative | Locator の `..`・絶対 Path・`\`・NUL、Root 外を指す Symlink | `locator_outside_root`、exit 34 |
| TC-01-06 | Negative | サイズ上限超過、深さ上限超過、UTF-8 でない bytes、読めないファイル | `manifest_invalid` または `manifest_unreadable`、例外なし |

## M2-02 Subject と Contract の結合

| 項目 | 内容 |
| --- | --- |
| 事前条件 | 合成 Repository に `config_commit ⊑ base ⊑ head` の Commit 列と、config commit に Contract がある |
| 入力 | Manifest（Subject、Contract）、合成 Repository、Phase 1 の Verification Report |
| 観測 | `subject` Link と `contract` Link の Status と理由コード |
| PASS | TC-02-01〜TC-02-09 がすべて期待どおり |
| FAILED | Negative のどれかが `LINKED` になる、Head / Working Tree の Contract が結果に影響する、hooks が実行される |
| Mutation | MU2-04 祖先検査の結果を反転、MU2-05 Contract の読み取り元を Head に変える、MU2-06 Report との照合を省く |
| 必要 Evidence | JUnit、Mutation 結果 |
| 担当 | WP1 |

| TC | 種類 | 入力 | 期待 |
| --- | --- | --- | --- |
| TC-02-01 | Positive | 正しい Commit 列。`config_commit == base` の場合も | 両 Link `LINKED` |
| TC-02-02 | Negative | `head` が `base` の祖先でない | `subject` BROKEN `base_not_ancestor_of_head` |
| TC-02-03 | Negative | `config` が `base` の祖先でない | `contract` BROKEN `config_not_ancestor_of_base` |
| TC-02-04 | Negative | 存在しない Commit | `subject` INCOMPLETE `revision_not_found` |
| TC-02-05 | Negative | Contract の 1 byte 改変（Manifest の Digest はそのまま） | `contract` BROKEN `contract_digest_mismatch` |
| TC-02-06 | Negative | Manifest の `base_commit` と Report の `subject.base.commit` が異なる | `subject` BROKEN `subject_mismatch` |
| TC-02-07 | Negative | Report の `trust.contract_sha256` が異なる | `contract` BROKEN `contract_mismatch_with_report` |
| TC-02-08 | Negative | config tree に Contract がない。Head にだけ別の Contract がある | `contract` INCOMPLETE `contract_blob_missing`（Head の Contract を読まない） |
| TC-02-09 | Negative | Repository の hooks・filter・textconv・fsmonitor を marker を作るよう設定 | marker が作られない（Phase 1 C21d と同じ方式） |

## M2-03 Remediation Verification Report との結合

| 項目 | 内容 |
| --- | --- |
| 入力 | Verification Report ファイル（Phase 1 の 0.1.0）、Manifest の `verification`、合成 Repository と Pin された Tool |
| 観測 | `verification` Link の Status、理由コード、`observed.decision` |
| PASS | TC-03-01〜TC-03-08 がすべて期待どおり |
| FAILED | 改変した Report が `LINKED` になる。`decision: VERIFIED` が Status を上げる。Tool 不在で `LINKED` になる |
| Mutation | MU2-07 再実行を省き Manifest の Digest を信じる、MU2-08 `decision == VERIFIED` で LINKED にする、MU2-09 Tool 不在を LINKED にする |
| 必要 Evidence | JUnit、Mutation 結果、Tool の Version（cfn-lint、cfn-guard） |
| 担当 | WP1 |

| TC | 種類 | 入力 | 期待 |
| --- | --- | --- | --- |
| TC-03-01 | Positive | SC-01、SC-02 の正しい Candidate（VERIFIED）、`local_recompute` | `LINKED`、`observed.decision` = payload の値 |
| TC-03-02 | Positive | 違反の Candidate（BLOCKED） | `LINKED`（`decision` は Status を変えない） |
| TC-03-03 | Positive | `local_import` で、再実行と一致する Report | `LINKED` |
| TC-03-04 | Negative | payload の `decision` を書き換え、`payload_sha256` を再計算した Report | BROKEN `payload_digest_mismatch`（再実行との不一致） |
| TC-03-05 | Negative | `metadata.payload_sha256` だけ不一致 | BROKEN `metadata_digest_mismatch` |
| TC-03-06 | Negative | Report の Subject が Manifest と別、Report ファイルの Digest 不一致、ファイルなし | BROKEN `report_subject_mismatch` / BROKEN `verification_digest_mismatch` / INCOMPLETE `verification_artifact_missing` |
| TC-03-07 | Negative | Report の JSON が壊れている | INCOMPLETE `report_invalid` |
| TC-03-08 | Negative | cfn-guard 不在、Version 不一致 | NOT_PROVEN `recompute_unavailable` |

## M2-04 Review Finding との結合（`review` Link 単独）

| 項目 | 内容 |
| --- | --- |
| 入力 | Review_Report 1.0.0 ファイル、Manifest の `review.finding_refs` |
| 観測 | `review` Link の Status、理由コード、`observed.finding_resource_matches_contract`、Chain の Source Code の静的検査 |
| PASS | TC-04-01〜TC-04-08 がすべて期待どおり |
| FAILED | `errors[]` を持つ Report、Tool 不在の Report が `LINKED` になる。Chain の Code が `passed_all_checks` を参照する |
| Mutation | MU2-10 `errors[]` の検査を外す、MU2-11 `passed_all_checks` で判定する、MU2-12 Finding の Digest 比較を外す |
| 必要 Evidence | JUnit、静的検査の結果、Mutation 結果 |
| 担当 | WP1 |

| TC | 種類 | 入力 | 期待 |
| --- | --- | --- | --- |
| TC-04-01 | Positive | SC-02 の Base 版に対する Review_Report（合成、`errors: []`、全 Tool available）と、対象 Role の Finding 1件 | `LINKED`、`finding_resource_matches_contract: true` |
| TC-04-02 | Negative | `findings: []`、`passed_all_checks: true`、`errors[]` 1件 | INCOMPLETE `review_report_has_errors` |
| TC-04-03 | Negative | Finding はあり `errors: []` だが、Tool が1つ `available: false` | INCOMPLETE `review_tool_unavailable` |
| TC-04-04 | Negative | 存在しない `finding_id` | BROKEN `finding_missing` |
| TC-04-05 | Negative | Finding の `Severity` を変更 / Identity_Key の不一致 | BROKEN `finding_digest_mismatch` / `identity_key_mismatch` |
| TC-04-06 | Negative | `schema_version` が 1.0.0 でない、Report ファイルなし、Digest 不一致 | INCOMPLETE `review_report_invalid` / INCOMPLETE `review_artifact_missing` / BROKEN `review_digest_mismatch` |
| TC-04-07 | Negative | `review: null` | `NOT_PRESENT` |
| TC-04-08 | 静的検査 | `iacreview/chain/` の全 Source | 文字列 `passed_all_checks` が出ない。Review_Report の読み取りは `iacreview.reportcheck` を使う |

## M2-05 GitHub Evidence（M1 Store）との結合

| 項目 | 内容 |
| --- | --- |
| 入力 | M1 Store（合成 Raw。`tests/unit/evidence_synth.py` は変更せず、M2 の Test Helper で生成）、Manifest の `github_evidence` |
| 観測 | `github` Link の Status、理由コード、`observed.capture_authenticity` |
| PASS | TC-05-01〜TC-05-06 がすべて期待どおり |
| FAILED | Integrity が PASS でない Store で `LINKED`。`capture_authenticity` が `NOT_PROVEN` 以外になる |
| Mutation | MU2-13 Integrity の結果を無視、MU2-14 `repository_id` の照合を外す |
| 必要 Evidence | JUnit、Mutation 結果、M1 Evidence Test の再実行結果（RG-3） |
| 担当 | WP1 |

| TC | 種類 | 入力 | 期待 |
| --- | --- | --- | --- |
| TC-05-01 | Positive | 合成 Store 1 Revision、Integrity PASS | `LINKED`、`capture_authenticity: NOT_PROVEN` |
| TC-05-02 | Negative | Raw 1 byte 改変 | INCOMPLETE `integrity_not_pass` |
| TC-05-03 | Negative | Store の MANIFEST と Raw を整合的に改変（Chain Manifest はそのまま） | BROKEN `store_manifest_mismatch` |
| TC-05-04 | Negative | 存在しない Evidence id | INCOMPLETE `evidence_id_missing` |
| TC-05-05 | Negative | 別 Repository の Envelope | BROKEN `repository_mismatch` |
| TC-05-06 | Negative | `completeness_status: INCOMPLETE` の Capture | INCOMPLETE `capture_incomplete` |

## M2-06 Chain Status の合成と Fail-closed

| 項目 | 内容 |
| --- | --- |
| 入力 | 6 Link の Status の全組み合わせ（5^6 = 15,625 通り）を与える純関数の Test、実際の Chain 入力 |
| 観測 | `chain_status`、`not_claimed`、CLI の exit code |
| PASS | TC-06-01〜TC-06-07 がすべて期待どおり |
| FAILED | 規則に反する組み合わせが1つでもある。例外時に exit 0。TC-06-05 / TC-06-06 で COMPLETE |
| Mutation | MU2-15 優先順位の入れ替え（INCOMPLETE と NOT_PROVEN）、MU2-16 `NOT_PRESENT` を `LINKED` 扱い、MU2-17 例外を握りつぶして COMPLETE、MU2-18 `verification` が `VERIFIED` のとき `review` の INCOMPLETE を無視 |
| 必要 Evidence | JUnit（全組み合わせの件数）、Mutation 結果 |
| 担当 | WP1 |

| TC | 種類 | 入力 | 期待 |
| --- | --- | --- | --- |
| TC-06-01 | 網羅 | 15,625 通り | 代表値が `BROKEN > INCOMPLETE > NOT_PROVEN > COMPLETE` の規則と一致。`COMPLETE` は全 LINKED の1通りだけ。`NOT_PRESENT` を含めば `INCOMPLETE` 以下 |
| TC-06-02 | Positive | 全 LINKED の Chain | `COMPLETE`、exit 0 |
| TC-06-03 | Negative | 各 Link を1つずつ他の Status にした Chain | 規則どおりの Status と exit code（31 / 32 / 33） |
| TC-06-04 | Negative | Validator 内部で例外を起こす入力（読み取り不能ファイル、途中で消えるファイル） | `COMPLETE` にならない、exit 非0 |
| TC-06-05 | 外部 Consumer の誤読 | `passed_all_checks: true`・`findings: []`・`errors[]` 1件の Review_Report を起点に、他の5 Link は LINKED、Verification は `VERIFIED` | `chain_status: INCOMPLETE`、exit 32 |
| TC-06-06 | 外部 Consumer の誤読 | TC-06-05 の Report の `passed_all_checks` を `false` に書き換え、Manifest の Digest はそのまま | `review` BROKEN `review_digest_mismatch`、`chain_status: BROKEN` |
| TC-06-07 | 静的検査 | Chain の exit code の集合 | `iacreview.exitcodes.EXIT_CODES` の値、Phase 1 `DECISION_EXIT_CODES` の値、`evidence_ci_check.EXIT` の値と交わらない。`not_claimed` が常に7項目 |

## M2-07 決定論と Replay

| 項目 | 内容 |
| --- | --- |
| 入力 | 合成 Chain 2種（SC-01、SC-02）。M2 用の期待値ファイル `tests/fixtures/chain_replay/expected.json`（新規、M1 の `expected.json` とは別） |
| 観測 | Chain Result の Payload の SHA-256（同一 Process 2回、別 Process 2回 `PYTHONHASHSEED=random`）、Validator の Source SHA-256 |
| PASS | TC-07-01〜TC-07-04 がすべて期待どおり |
| FAILED | 4回のどれかが異なる。Payload に非決定的な値がある |
| NOT_PROVEN | 別 OS・別 Python Version での一致は、M2 用 CI job の Run を Agent が確認するまで NOT_PROVEN（Human 提供の CI 結果は NOT_VERIFIED として記録） |
| Mutation | MU2-19 Payload に `generated_at` を入れる、MU2-20 `links` の順序を dict の挿入順に任せる |
| 必要 Evidence | 4つの SHA-256、期待値ファイルの SHA-256、Python Version |
| 担当 | WP1（Replay）、WP3（統合後の再確認） |

| TC | 種類 | 入力 | 期待 |
| --- | --- | --- | --- |
| TC-07-01 | Positive | 合成 Chain 2種 | 4回の SHA-256 が同じで、期待値ファイルと一致 |
| TC-07-02 | 静的検査 | Payload | 時刻、Host Path、Process id、浮動小数点がない（Metadata にだけある） |
| TC-07-03 | Negative | Validator の Source を1文字変えた Copy | `validator.source_sha256` が変わり、期待値との照合で不一致 |
| TC-07-04 | 静的検査 | Test の Code | 期待値ファイルへの書き込みがない（更新は Human の Review を経た手作業だけ） |

## M2-08 Gate Record の Integrity（GV-1）と出典の制限

| 項目 | 内容 |
| --- | --- |
| 入力 | Gate Record の JSON、M1 Store の合成 Raw（`pull`、`pull_reviews`）、合成 Repository |
| 観測 | GV-1（`gate_aspects.integrity`）の Status と理由コード、Builder が Raw から再生成した Record の Canonical bytes、Record と Result の PII |
| PASS | TC-08-01〜TC-08-08 がすべて期待どおり |
| FAILED | 手書きの Record、Agent が書いた Record、Raw と矛盾する Record で GV-1 が `LINKED` になる。PII が Record・Result に入る |
| Mutation | MU2-21 再生成との比較を外す、MU2-22 Schema 違反の Record を承認として数える、MU2-23 `actor_ref` の代わりに login を入れる |
| 必要 Evidence | JUnit、canary 検索の結果、Mutation 結果 |
| 担当 | WP2 |

| TC | 種類 | 入力 | 期待 |
| --- | --- | --- | --- |
| TC-08-01 | Positive | 同じ Raw から Builder を2回 | 同じ bytes の Record |
| TC-08-02 | Positive | `contract_approval`、`candidate_review`（approved / changes_requested / commented）、`merge_decision`（merged / closed_unmerged / open） | GV-1 `LINKED` |
| TC-08-03 | Negative | Raw があり、Record の `decision` だけ `approved` に書き換え | BROKEN `gate_record_mismatch` |
| TC-08-04 | Negative | `source.type: "agent_statement"`、`approved_by` key、自由記述の承認者。ほかに有効な承認 Record なし | NOT_PROVEN `approval_self_declared_only` |
| TC-08-05 | Negative | Record が参照する Raw が Store にない | INCOMPLETE `gate_source_missing` |
| TC-08-06 | Negative | Raw の Revision が M1 Integrity を PASS しない | INCOMPLETE `gate_source_integrity_not_pass` |
| TC-08-07 | Negative | Raw の Review state が語彙外（`DISMISSED`、`PENDING`） | NOT_PROVEN `gate_source_unrecognized` |
| TC-08-08 | PII | Login 名、Avatar URL、Email の canary を Raw に入れる | Record、Result、Summary、例外文に出ない |

## M2-09 Gate の Revision Binding（GV-3）と Approval Staleness（GV-4）

| 項目 | 内容 |
| --- | --- |
| 入力 | Gate Record の集合、`pull` Raw、Chain Manifest の Subject と Contract |
| 観測 | GV-3（`gate_aspects.revision_binding`）、GV-4（`gate_aspects.staleness`）の Status と理由コード |
| PASS | TC-09-01〜TC-09-08 がすべて期待どおり。判定規則は `m2-schemas.md` §2-2（D-3 で固定） |
| FAILED | 不一致が確認できる入力で BROKEN 以外になる。Evidence 不足・自己申告だけの入力で LINKED または BROKEN になる |
| Mutation | MU2-24 `commit_id` と `head_commit` の比較を外す、MU2-25 確認できた不一致を NOT_PROVEN に下げる、MU2-26 `pull` Raw がないとき LINKED にする |
| 必要 Evidence | JUnit、Mutation 結果 |
| 担当 | WP2 |

| TC | 種類 | 入力 | 期待 |
| --- | --- | --- | --- |
| TC-09-01 | Positive | `pull.head.sha` = 承認の `commit_id` = `head_commit`、`contract_approval` = `config_commit` | GV-3 `LINKED`、GV-4 `LINKED` |
| TC-09-02 | Negative | 承認の `commit_id` が `head_commit` と異なる（古い Head への承認） | GV-3 BROKEN `gate_binds_other_commit` |
| TC-09-03 | Negative | 承認と `head_commit` は一致するが、`pull.head.sha` がさらに新しい（承認の後に Push） | GV-4 BROKEN `approval_stale` |
| TC-09-04 | Negative | `contract_approval` の Commit が `config_commit` と異なる | GV-3 BROKEN `gate_binds_other_commit` |
| TC-09-05 | Negative | `contract_approval` なし | GV-3 INCOMPLETE `gate_record_missing` |
| TC-09-06 | Negative | `pull` Raw なし / `head.sha` 欠落 | GV-4 NOT_PROVEN `approval_revision_unverifiable` |
| TC-09-07 | Negative | Review の `commit_id` 欠落 | GV-3 NOT_PROVEN `approval_revision_unverifiable` |
| TC-09-08 | Negative | Raw に承認がなく、Agent の自己申告 Record だけ | GV-4 NOT_PROVEN `approval_self_declared_only`（GV-1 も同じコード） |

## M2-10 Approval Authority（GV-2）、自動化しないこと、Merge Enforcement を主張しないこと（GV-5）

| 項目 | 内容 |
| --- | --- |
| 入力 | `candidate_review` の Record と Raw、M2 の CLI と Library の全 Entry Point、Chain Result と Summary |
| 観測 | GV-2（`gate_aspects.authority`）の Status と理由コード、Code の静的検査、Result の `not_claimed`、Summary の文言 |
| PASS | TC-10-01〜TC-10-09 がすべて期待どおり |
| FAILED | `same_actor` や Approve なしで GV-2 が LINKED。書き込み経路がある。COMPLETE を Merge 可・Merge Enforcement 済みと表示する。`not_claimed` から `merge_enforcement` が消える |
| Mutation | MU2-27 `same_actor` を許す、MU2-28 `commented` を Approve 扱い、MU2-29 `not_claimed` から `merge_enforcement` を外す、または Summary に「ready to merge」を出す |
| 必要 Evidence | JUnit、静的検査の結果、Mutation 結果 |
| 担当 | WP2（GV-2、静的検査）、WP3（Summary） |

| TC | 種類 | 入力 | 期待 |
| --- | --- | --- | --- |
| TC-10-01 | Positive | 2 Account（合成 Raw の `user.id` が別）、`author_association: COLLABORATOR`、Head に対する Approve | GV-2 `LINKED` |
| TC-10-02 | Negative | Approve が PR 作成者と同じ `user.id` | NOT_PROVEN `separation_of_duty_not_shown` |
| TC-10-03 | Negative | `user.id` 欠落 | NOT_PROVEN `actor_relation_unknown` |
| TC-10-04 | Negative | `author_association: CONTRIBUTOR` / `NONE` / 欠落 | NOT_PROVEN `approver_association_not_shown` |
| TC-10-05 | Negative | `commented` / `changes_requested` だけ | NOT_PROVEN `approval_not_shown` |
| TC-10-06 | Positive | GV-1〜GV-4 がすべて LINKED の Chain | Result の `not_claimed` に `merge_enforcement`、`approval_counted_by_rules`、`approver_permission`、`human_identity` を含む。`merge_decision` は `observed` だけで Status を変えない |
| TC-10-07 | 静的検査 | `iacreview/chain/` の全 Source | GitHub への書き込み（`gh` の GET 以外の `--method`、`gh pr`、`gh api graphql`）、`git push` / `git commit` / `git merge` の呼び出しがない |
| TC-10-08 | 静的検査 | Gate Record Builder の入力 | M1 Store の Evidence と Git の Commit だけ。任意の JSON を受ける引数がない |
| TC-10-09 | 文言 | COMPLETE の Chain の Summary | 固定文言。「merge」「ready」「safe」「approved for merge」「enforced」を含まない。Phase 1 の `enforcement_status: not_verified` を変えない |

## M2-11 Read-only Transport の安全性（fixture）

| 項目 | 内容 |
| --- | --- |
| 入力 | M2 Transport（`gh api` を argv で実行する関数）に、Fake の `gh` 実行器（記録済み応答、Test 用）と、Endpoint の要求を与える |
| 観測 | 実行される argv、拒否と理由、保存される Header、Dry-run の出力 |
| PASS | TC-11-01〜TC-11-07 がすべて期待どおり |
| FAILED | allowlist 外の Request、GET 以外の Method、Redirect の追跡、Token の露出、Dry-run での実行 |
| Mutation | MU2-30 allowlist の検査を外す、MU2-31 Method の固定を外す、MU2-32 Header の allowlist を外す |
| 必要 Evidence | JUnit、canary 検索の結果、Mutation 結果 |
| 担当 | WP4 |

| TC | 種類 | 入力 | 期待 |
| --- | --- | --- | --- |
| TC-11-01 | Positive | `github-e2e-plan.md` §4 の allowlist の各 Endpoint | argv が `gh api --include --method GET <endpoint>`、Shell なし、`proc.run_bounded` 経由 |
| TC-11-02 | Negative | `POST`、`PATCH`、`DELETE`、`graphql`、`..` を含む Path、allowlist 外（`/user`、`/repos/{o}/{r}/actions/secrets`）、Query の任意 key、別 Repository | Request を作らずに拒否 |
| TC-11-03 | Negative | 302 応答 | `http_error`、追加の Request なし |
| TC-11-04 | Negative | `--execute` なし | Request を実行せず、Endpoint 一覧と件数だけを表示 |
| TC-11-05 | Negative | Token の canary を環境変数と応答 Header に入れる | 保存物、Log、例外文に出ない |
| TC-11-06 | Negative | 巨大応答、Page 上限超過、`gh` の非0終了、Timeout | `byte_limit_exceeded` / `page_limit_reached` / `transport_error`。成功にしない |
| TC-11-07 | 環境 | Test 全体 | socket が開かれない |

## M2-12 実 GitHub Read-only E2E（1 Scenario）

| 項目 | 内容 |
| --- | --- |
| 事前条件 | `github-e2e-plan.md` §9 の Human 承認がすべてある。M2-01〜M2-11 が PASS。SC-02 の事前確認（Base に対象 Role の Finding がある）が PASS |
| 入力 | Human が用意した検証用 Repository の1 PR（SC-02、D-4）、fine-grained PAT（Human が作成）、Pin された Tool |
| 観測 | `github-e2e-plan.md` §7 の E2E-1〜E2E-7 |
| PASS | E2E-1〜E2E-7 をすべて満たす。Chain Status の値は問わない（期待値を置かない） |
| FAILED | E2E-1〜E2E-6 のどれかに反する |
| NOT_PROVEN | 承認・Repository・Tool・PAT のいずれかがなく実行できない。E2E-7 が Human から報告されない |
| 予測される NOT_PROVEN（失敗ではない） | GV-2（単一 Owner の場合）、`capture_authenticity`、Job Log、Artifact、GV-5（対象外） |
| 必要 Evidence | 非公開 Store（`.agents/`）、Chain Result、4つの Replay Hash、Secret Scan、Human の Revoke 報告。公開するのは Human が承認した要約だけ |
| 担当 | WP5 |

---

## 12. 共通 Test（全 AC、P0 の確認）

| TC | 内容 | 期待 |
| --- | --- | --- |
| TC-00-01 | RG-1: M1 `evidence_ci_check.py`（Full Clone） | exit 0、3つの Hash が Baseline と一致 |
| TC-00-02 | RG-2: `git diff --name-only` で F-1〜F-7 | M2 の Commit 由来の Path が0件 |
| TC-00-03 | Import の向き（静的検査） | `iacreview/evidence/` と `iacreview/remediation/` の Source が `iacreview.chain` を import しない |
| TC-00-04 | M1 Evidence Test と Mutant（RG-3、RG-4） | 519件（CI では 516 PASS / 3 SKIP の設計）、Mutant 32 / 32 |

## 13. AC と Test Case の対応（rev1 で再点検）

| AC | Test Case | Mutant | 検証観点 |
| --- | --- | --- | --- |
| M2-01 | TC-01-01〜06 | MU2-01〜03 | 入力の Schema、Locator |
| M2-02 | TC-02-01〜09 | MU2-04〜06 | Subject、Contract |
| M2-03 | TC-03-01〜08 | MU2-07〜09 | Verification |
| M2-04 | TC-04-01〜08 | MU2-10〜12 | Review（Link 単独、入力の完全性） |
| M2-05 | TC-05-01〜06 | MU2-13〜14 | GitHub Evidence |
| M2-06 | TC-06-01〜07 | MU2-15〜18 | Chain 合成、Fail-closed、外部 Consumer の誤読、exit code の非衝突 |
| M2-07 | TC-07-01〜04 | MU2-19〜20 | 決定論 |
| M2-08 | TC-08-01〜08 | MU2-21〜23 | GV-1 Integrity、PII |
| M2-09 | TC-09-01〜08 | MU2-24〜26 | GV-3 Revision Binding、GV-4 Staleness |
| M2-10 | TC-10-01〜09 | MU2-27〜29 | GV-2 Approval Authority、非自動化、GV-5 の非主張 |
| M2-11 | TC-11-01〜07 | MU2-30〜32 | Transport |
| M2-12 | E2E-1〜7 | — | 実 E2E |
| 共通 | TC-00-01〜04 | — | M1 非干渉 |

点検の基準: 1つの Test Case は1つの AC にだけ属する。1つの理由コードの初出の Test は1つの AC にだけある（TC-06-05 / TC-06-06 は M2-04 のコードを使うが、検査しているのは Chain の合成で、Link 単独の判定ではない）。Mutant の合計は32個（MU2-01〜MU2-32）。追加する場合は WP の開始前に本表へ追記し、Human が承認する。

## 14. AC → WP

| AC | WP1 | WP2 | WP3 | WP4 | WP5 | WP6 |
| --- | --- | --- | --- | --- | --- | --- |
| M2-01〜M2-06 | 実装・Test | — | 統合確認 | — | 実データで確認 | 最終判定 |
| M2-07 | Replay | — | 統合後に再確認 | — | E2E-3 | 最終判定 |
| M2-08〜M2-10 | — | 実装・Test | Summary（M2-10） | — | 実データで確認 | 最終判定 |
| M2-11 | — | — | — | 実装・Test | — | 最終判定 |
| M2-12 | — | — | — | — | 実行 | 最終判定 |
