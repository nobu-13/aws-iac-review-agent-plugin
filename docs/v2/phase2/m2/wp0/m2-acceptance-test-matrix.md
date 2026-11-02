# Phase 2 / M2 — Acceptance Test Matrix（M2-01〜M2-12）

状態: **事前定義（WP0 rev2）。M2-01〜M2-07 は WP1 で実施済み（Local PASS、GitHub CI は Human 提供 Evidence）、M2-08〜M2-12 は未実施。** この表は実装前に固定する。実装後に結果を見て条件を変えない。変更が必要なら新しい Revision と理由を残し、Human の承認を得る。rev0 → rev1 は `wp0-revision-1.md`、rev1 → rev2 は `wp0-revision-2.md` に記録した。

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
| Gate | M2-08〜M2-10 | GV-1 Integrity（M2-08）、GV-3 Revision Binding と GV-4 Staleness（M2-09）、GV-2 Account Separation（観測。承認権限は証明しない）と自動化しないこと、GV-5 を主張しないこと（M2-10） | Review_Report の完全性（Gate ではない） |
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
| TC-04-02 | Negative | (a) `findings: []`、`passed_all_checks: true`、`errors[]` 1件 / (b) 参照する Finding があり `errors[]` 1件 | (a) `review_report_has_errors` を含み BROKEN（`finding_refs` は1件以上のため `finding_missing` が加わる。rev2 で WP1 N-3 を反映）/ (b) INCOMPLETE `review_report_has_errors` |
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
| TC-06-05 | 外部 Consumer の誤読 | `errors[]` 1件の Review_Report を起点に、他の5 Link は LINKED、Verification は `VERIFIED`。(a) 参照 Finding あり / (b) `findings: []`・`passed_all_checks: true` | (a) `chain_status: INCOMPLETE`、exit 32 / (b) `review_report_has_errors` を含み COMPLETE にならない（BROKEN、rev2 で WP1 N-3 を反映） |
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

## M2-08 Gate の Integrity（GV-1）、Evidence の範囲、Review の集約（rev2）

| 項目 | 内容 |
| --- | --- |
| 入力 | Gate Record の JSON、M1 Store の合成 Raw（`pull`、`pull_reviews` の1〜n Page）、Chain Manifest の `github_evidence` |
| 観測 | `gate_aspects.integrity` の Status とコード、Builder の再生成結果（canonical bytes）、Reviewer ごとの集約結果、Record・Result の PII |
| PASS | TC-08-01〜TC-08-31 がすべて期待どおり。規則は `m2-schemas.md` rev2 §2、§2-1、§2-2、§2-4（S-1〜S-10 を反映）。TC-08-22〜29 は WP2 Implementation Review（N2-2 / N2-3）、TC-08-30〜31 は WP2 最終確認で追加（いずれも Human 承認済み）。Record 単位の規則は `docs/v2/phase2/m2/wp2/wp2-gate-record-decision-table.md` G-01〜G-13a |
| FAILED | 改変・自己申告・範囲外の Raw・不完全な Pagination・矛盾する Review のどれかで GV-1 が LINKED になる。集約結果が配列順で変わる。PII が Record・Result に入る |
| Mutation | MU2-21 再生成との比較を外す、MU2-22 Schema 違反の Record を承認として数える、MU2-23 `actor_ref` の代わりに login を入れる、MU2-33〜MU2-40、MU2-49〜MU2-50、MU2-51〜MU2-62（§13） |
| 必要 Evidence | JUnit、canary 検索の結果、Mutation 結果 |
| 担当 | WP2 |

| TC | 種類 | 入力 | 期待 |
| --- | --- | --- | --- |
| TC-08-01 | Positive | 同じ Raw から Builder を2回 | 同じ bytes の Record 集合 |
| TC-08-02 | Positive | `contract_approval`、`candidate_review`（approved / changes_requested / none）、`merge_decision`（merged / closed_unmerged / open） | GV-1 LINKED |
| TC-08-03 | Positive | `pull_reviews` が3 Page（Page ごとに Review を分割）。Review の配列順を逆にした Raw、Page 内で並べ替えた Raw | 集約結果と Record の bytes が同じ（配列順に依存しない） |
| TC-08-04 | Negative | Raw があり、Record の `decision` だけ `approved` に書き換え | BROKEN `gate_record_mismatch` |
| TC-08-05 | Negative | Manifest の `gate_records[].kind` と Record 本体の `kind` が違う / Record ファイルの Digest が Manifest と違う | BROKEN `gate_record_mismatch` |
| TC-08-06 | Negative | `source.type: "agent_statement"`、`approved_by` key、自由記述の承認者。ほかに有効な承認 Record なし | NOT_PROVEN `approval_self_declared_only` |
| TC-08-07 | Negative | Record の `evidence_ids` に Manifest の `github_evidence.evidence_ids` にない id（同じ Store にはある） | INCOMPLETE `gate_source_missing` |
| TC-08-08 | Negative | Record の `store_revision` が Manifest の Revision と違う（別 Revision に同じ内容の Raw がある） | INCOMPLETE `gate_source_missing` |
| TC-08-09 | Negative | `pull` と `pull_reviews` が別の PR 番号 | INCOMPLETE `gate_source_missing` |
| TC-08-10 | Negative | Raw の Revision が M1 Integrity を PASS しない | INCOMPLETE `gate_source_integrity_not_pass` |
| TC-08-11 | Negative | 3 Page の Capture のうち Page 2 が Store にない / Record が Page 1 と 3 だけを名指す / 途中の Page が `has_next: false` / 最後の Page が `has_next: true` / `completeness_status: INCOMPLETE` | INCOMPLETE `review_capture_incomplete` |
| TC-08-12 | Negative | 同じ Page 番号の Envelope が2つ / 同じ Review id・同じ内容が2 Page に出る（R-13） | INCOMPLETE `review_capture_duplicate` |
| TC-08-13 | Negative | 同じ Review id で `state` が違う2件（R-14） | BROKEN `review_conflict` |
| TC-08-14 | Negative | `state` が語彙外、`submitted_at` が不正、`id` が文字列（R-15） | NOT_PROVEN `gate_source_unrecognized` |
| TC-08-15 | Negative | 同じ Reviewer の APPROVED と CHANGES_REQUESTED が同じ `submitted_at`（R-10） | NOT_PROVEN `review_order_ambiguous`、その Reviewer は数えない |
| TC-08-16 | Negative | 同じ Reviewer の決定 Review で `submitted_at` 順と `id` 順が逆（R-12） | NOT_PROVEN `review_order_inconsistent`、その Reviewer は数えない |
| TC-08-17 | Decision Table | R-01〜R-09、R-11、R-17〜R-19、R-21、R-22 の各 Review 列 | 段階 B の状態と有効承認の数え方が `m2-schemas.md` §2-2 の表どおり |
| TC-08-19 | Negative | 同じ Reviewer の A@Head の後に、別の Review id が却下済み（R-20） | NOT_PROVEN `review_dismissal_effect_unknown`、その Reviewer は数えない |
| TC-08-20 | Negative | A と D が同じ `submitted_at`（R-23） / 決定 Review と却下済み Review で時刻順と id 順が逆 | NOT_PROVEN `review_order_ambiguous` / `review_order_inconsistent` |
| TC-08-21 | Dismissal の単位 | Reviewer X の A(id 10) が却下済み（D）、Reviewer Y の A(id 11)@Head は有効 | X は `none`、Y は有効承認。却下は id 10 にだけ効く（Reviewer Y に影響しない） |
| TC-08-18 | PII | Login 名、Avatar URL、Email の canary を Raw に入れる | Record、Result、Summary、例外文に出ない |
| TC-08-22 | Negative（G-02） | Manifest が名指す Record ファイルがない | INCOMPLETE `gate_record_missing`、`gate_source_missing` なし |
| TC-08-23 | Negative（G-04） | strict JSON でない、Object でない、Schema 外で承認を述べない、64 KiB 超、承認でない Field（`approval_state` など）、未定義の表記（`approvedBy`、`Approver`、自由文）の Record（10入力） | INCOMPLETE `gate_record_invalid`、`approval_self_declared_only` なし |
| TC-08-24 | Negative（G-05） | 有効な承認 Record と自己申告 Record を同時に提示 | NOT_PROVEN `approval_self_declared_only`（有効な承認で隠れない） |
| TC-08-25 | Negative（G-07） | 同じ `(kind, item_ref)` の Record が2件（同一 / 片方が偽造） | 同一は INCOMPLETE `gate_record_invalid`、偽造を含むと BROKEN `gate_record_mismatch` も |
| TC-08-26 | Negative（G-09） | 完全に読めた Raw にない Reviewer / 別の PR 番号の Record | BROKEN `gate_record_mismatch` |
| TC-08-27 | Negative（G-10、G-11） | Capture が範囲内にない（E-7）/ Capture はあるが集約できない（R-15） | BROKEN にならない。それぞれ `gate_source_missing` / 原因のコードだけ |
| TC-08-28 | Negative（G-13） | Raw から再生成される Record（CR、承認、merge_decision）を1件省略 | INCOMPLETE `gate_record_missing`、BROKEN にならない、Raw の CR は GV-2 に残る |
| TC-08-29 | 混在 | 正常な Record の中に異常な Record を1件 / 複数の異常を同時に | 異常ごとの Status と一次原因のコード（Digest 不一致は `gate_record_mismatch` だけ）。複数の異常はすべての原因のコードが残る |
| TC-08-30 | 一次原因（G-13a） | Record ファイルを Schema 違反に置き換え / それに加えて別の Record を省略 / 自己申告に置き換え | `gate_record_invalid` だけ / `gate_record_invalid` と `gate_record_missing` / `approval_self_declared_only` と `gate_record_missing`（自己申告は省略を説明しない） |
| TC-08-31 | 自己申告の形（G-05） | `m2-schemas.md` §2 の3つの形（7入力）/ 承認でない Field と未定義の表記（24入力） | 前者だけを自己申告と判定する |

## M2-09 Gate の Revision Binding（GV-3）と Approval Staleness（GV-4）（rev2）

| 項目 | 内容 |
| --- | --- |
| 入力 | Gate Record の集合、`pull` Raw、Chain Manifest の Subject と Contract |
| 観測 | `gate_aspects.revision_binding`、`gate_aspects.staleness` の Status とコード |
| PASS | TC-09-01〜TC-09-12 がすべて期待どおり。規則は `m2-schemas.md` rev2 §2-4（D-3） |
| FAILED | 不一致が確認できる入力で BROKEN 以外になる。Evidence 不足・自己申告だけの入力で LINKED または BROKEN になる |
| Mutation | MU2-24 `commit_id` と `head_commit` の比較を外す、MU2-25 確認できた不一致を NOT_PROVEN に下げる、MU2-26 `pull` Raw がないとき LINKED にする、MU2-46〜MU2-48（§13） |
| 必要 Evidence | JUnit、Mutation 結果 |
| 担当 | WP2 |

| TC | 種類 | 入力 | 期待 |
| --- | --- | --- | --- |
| TC-09-01 | Positive | `pull.head.sha` = 有効承認の `commit_id` = `head_commit`、`contract_approval` = `config_commit` | GV-3 LINKED、GV-4 LINKED |
| TC-09-02 | Negative | 別 Account の承認が古い Head への1件だけ（R-17） | GV-3 NOT_PROVEN `approval_on_previous_head_only`（BROKEN にしない） |
| TC-09-03 | Positive | 2人の承認のうち1人は古い Head、1人は Head | GV-3 LINKED（古い承認は数えないだけ） |
| TC-09-04 | Negative | 承認と `head_commit` は一致、`pull.head.sha` がさらに新しい（承認の後に Push、Chain は古い Head を検証） | GV-4 BROKEN `pr_head_mismatch` |
| TC-09-05 | Negative | `contract_approval` の Commit が `config_commit` と違う | GV-3 BROKEN `gate_binds_other_commit` |
| TC-09-06 | Negative | `contract_approval` なし | GV-3 INCOMPLETE `gate_record_missing` |
| TC-09-07 | Negative | `pull` Raw なし / `head.sha` 欠落 | GV-4 NOT_PROVEN `approval_revision_unverifiable` |
| TC-09-08 | Negative | 数えた承認の `commit_id` が `null` | GV-3 NOT_PROVEN `approval_revision_unverifiable` |
| TC-09-09 | Negative | Raw に承認がなく、Agent の自己申告 Record だけ | GV-4 NOT_PROVEN `approval_self_declared_only`（GV-1 も同じコード） |
| TC-09-10 | Negative | 承認の後に Push され、Chain は新しい Head を検証（`pull.head.sha` = `head_commit`、承認は古い Head）（R-19 を含む） | GV-4 LINKED、GV-3 NOT_PROVEN `approval_on_previous_head_only`、Chain は COMPLETE にならない |
| TC-09-11 | Negative | Revision の偽装: Raw の決定 Review は古い Head、Record の `binds_to.commit` は Head に書き換え（Digest は整合） | GV-3 BROKEN `approval_revision_misrecorded`、GV-1 BROKEN `gate_record_mismatch` |
| TC-09-12 | 区別 | 同じ Chain で (a) 未解決の CR、(b) 古い Head への承認だけ、(c) Review の Page 欠損を1つずつ入れる | (a) GV-2 `changes_requested_outstanding`、(b) GV-3 `approval_on_previous_head_only`、(c) GV-1 `review_capture_incomplete`。互いのコードを兼用しない |

## M2-10 Account Separation（GV-2、観測）、自動化しないこと、権限と Enforcement を主張しないこと（rev2）

| 項目 | 内容 |
| --- | --- |
| 入力 | `candidate_review` の Record と Raw、M2 の CLI と Library の全 Entry Point、Chain Result と Summary |
| 観測 | `gate_aspects.account_separation` の Status とコード、`observed.approval_authority`、Code の静的検査、Result の `not_claimed`、Summary の文言 |
| PASS | TC-10-01〜TC-10-11 がすべて期待どおり |
| FAILED | `same_actor`・承認なし・未解決の変更要求で GV-2 が LINKED。`author_association` の値で GV-2 の Status が変わる。`approval_authority` が `NOT_PROVEN` 以外になる。書き込み経路がある。COMPLETE を Merge 可・権限あり・Enforcement 済みと表示する |
| Mutation | MU2-27 `same_actor` を許す、MU2-28 `commented` を承認扱い、MU2-29 `not_claimed` から `merge_enforcement` を外す / Summary に「ready to merge」を出す、MU2-41〜MU2-43（§13） |
| 必要 Evidence | JUnit、静的検査の結果、Mutation 結果 |
| 担当 | WP2（GV-2、静的検査）、WP3（Summary） |

| TC | 種類 | 入力 | 期待 |
| --- | --- | --- | --- |
| TC-10-01 | Positive | 2 Account（合成 Raw の `user.id` が別）、Head に対する APPROVED、変更要求なし | GV-2 LINKED、`observed.approval_authority: "NOT_PROVEN"` |
| TC-10-02 | Negative | 承認が PR 作成者自身の Review だけ（R-22。Record には含まれる） | NOT_PROVEN `separation_of_duty_not_shown`、Record に作成者の `candidate_review` がある（R2-3） |
| TC-10-03 | Negative | 決定 Review または PR 作成者の `user.id` が欠落・非整数（R-16） | NOT_PROVEN `actor_relation_unknown` |
| TC-10-04 | Negative | `commented` / `pending` だけ、承認の Review 自体が却下済み（R-05、R-07、R-08） | NOT_PROVEN `approval_not_shown` |
| TC-10-05 | Negative | 別 Account の有効承認と、別の Reviewer の最後の Review が CHANGES_REQUESTED（R-03）/ 古い Head への未解決の CR（R-21） | NOT_PROVEN `changes_requested_outstanding`、Chain は COMPLETE にならない（R2-2） |
| TC-10-06 | 不使用 | TC-10-01 の Raw の `author_association` を `OWNER` / `COLLABORATOR` / `CONTRIBUTOR` / `NONE` / 欠落に変える | GV-2 の Status とコード、Chain Status、Payload が変わらない（Record の `actor.author_association` だけが変わる） |
| TC-10-07 | Positive | GV-1〜GV-4 がすべて LINKED、他の5 Link も LINKED の合成 Chain | `chain_status: COMPLETE`（TC-06-02 の End-to-end）。`not_claimed` の7項目、`approval_authority: "NOT_PROVEN"`、`merge_decision` は `observed` だけ |
| TC-10-08 | 静的検査 | `iacreview/chain/` の全 Source | GitHub への書き込み（`gh` の GET 以外の `--method`、`gh pr`、`gh api graphql`）、`git push` / `git commit` / `git merge` の呼び出しがない。`author_association` を判定の分岐に使っていない |
| TC-10-09 | 静的検査 | Gate Record Builder の入力 | M1 Store の Evidence と Git の Commit だけ。任意の JSON を受ける引数がない |
| TC-10-10 | 文言 | COMPLETE の Chain の Summary（WP3） | `m2-schemas.md` §2-6 の固定文言。「approved for merge」「ready」「safe」「enforced」を主張として含まない。Phase 1 の `enforcement_status: not_verified` を変えない |
| TC-10-11 | 互換性 | Gate Record 0件の Chain（WP1 の Replay fixture） | `gate` は INCOMPLETE `gate_record_missing` のみ、`gate_aspects` なし（WP1 と同じ形）。`gate_evaluation_not_implemented` は Catalog に残る |

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

## 13. AC と Test Case の対応（rev2）

| AC | Test Case | Mutant | 検証観点 |
| --- | --- | --- | --- |
| M2-01 | TC-01-01〜06 | MU2-01〜03 | 入力の Schema、Locator |
| M2-02 | TC-02-01〜09（WP1 で TC-02-05 の字義どおりの Test を追加） | MU2-04〜06 | Subject、Contract |
| M2-03 | TC-03-01〜12（TC-03-09〜12 は WP1 Revision 2 で追加） | MU2-07〜09、MU2-44〜45 | Verification、Validator Identity |
| M2-04 | TC-04-01〜08 | MU2-10〜12 | Review（Link 単独、入力の完全性） |
| M2-05 | TC-05-01〜06（WP1 で TC-05-03 の字義どおりの Test を追加） | MU2-13〜14 | GitHub Evidence |
| M2-06 | TC-06-01〜07 | MU2-15〜18 | Chain 合成、Fail-closed、外部 Consumer の誤読、exit code の非衝突 |
| M2-07 | TC-07-01〜04 | MU2-19〜20 | 決定論 |
| M2-08 | TC-08-01〜31 | MU2-21〜23、MU2-33〜40、MU2-49〜62 | GV-1 Integrity、Evidence の範囲、Review の集約、PII、Record 単位の判定（TC-08-22〜31） |
| M2-09 | TC-09-01〜12 | MU2-24〜26、MU2-46〜48 | GV-3 Revision Binding、GV-4 Staleness |
| M2-10 | TC-10-01〜11 | MU2-27〜29、MU2-41〜43 | GV-2 Account Separation（観測）、非自動化、権限・Enforcement の非主張、WP1 互換 |
| M2-11 | TC-11-01〜07 | MU2-30〜32 | Transport |
| M2-12 | E2E-1〜7 | — | 実 E2E |
| 共通 | TC-00-01〜04 | — | M1 非干渉 |

### 13-1. GV の Status と Reason Code → Test Case（必須修正 7）

| 観点 | Status | Reason Code | Test Case |
| --- | --- | --- | --- |
| GV-1 | LINKED | — | TC-08-01、TC-08-02、TC-08-03 |
| GV-1 | BROKEN | `gate_record_mismatch` | TC-08-04、TC-08-05 |
| GV-1 | BROKEN | `review_conflict` | TC-08-13 |
| GV-1 | INCOMPLETE | `gate_source_missing` | TC-08-07、TC-08-08、TC-08-09 |
| GV-1 | INCOMPLETE | `gate_source_integrity_not_pass` | TC-08-10 |
| GV-1 | INCOMPLETE | `review_capture_incomplete` | TC-08-11 |
| GV-1 | INCOMPLETE | `review_capture_duplicate` | TC-08-12 |
| GV-1 | NOT_PROVEN | `gate_source_unrecognized` | TC-08-14 |
| GV-1 | NOT_PROVEN | `review_order_ambiguous` | TC-08-15、TC-08-20 |
| GV-1 | NOT_PROVEN | `review_order_inconsistent` | TC-08-16、TC-08-20 |
| GV-1 | NOT_PROVEN | `review_dismissal_effect_unknown` | TC-08-19 |
| GV-1 | NOT_PROVEN | `approval_self_declared_only` | TC-08-06、TC-08-24、TC-08-31 |
| GV-1 | BROKEN | `gate_record_mismatch`（G-07、G-09） | TC-08-25、TC-08-26、TC-08-29 |
| GV-1 | INCOMPLETE | `gate_record_missing`（G-02、G-13） | TC-08-22、TC-08-28、TC-08-29 |
| GV-1 | INCOMPLETE | `gate_record_invalid`（G-04、G-07、S-1） | TC-08-23、TC-08-25、TC-08-29、TC-08-30 |
| GV-2 | LINKED | — | TC-10-01、TC-10-06 |
| GV-2 | NOT_PROVEN | `separation_of_duty_not_shown` | TC-10-02 |
| GV-2 | NOT_PROVEN | `actor_relation_unknown` | TC-10-03 |
| GV-2 | NOT_PROVEN | `approval_not_shown` | TC-10-04 |
| GV-2 | NOT_PROVEN | `changes_requested_outstanding` | TC-10-05、TC-09-12 |
| GV-3 | LINKED | — | TC-09-01、TC-09-03 |
| GV-3 | BROKEN | `approval_revision_misrecorded` | TC-09-11 |
| GV-3 | BROKEN | `gate_binds_other_commit` | TC-09-05 |
| GV-3 | NOT_PROVEN | `approval_on_previous_head_only` | TC-09-02、TC-09-10、TC-09-12 |
| GV-3 | INCOMPLETE | `gate_record_missing` | TC-09-06、TC-10-11 |
| GV-3 | NOT_PROVEN | `approval_revision_unverifiable` | TC-09-08 |
| GV-4 | LINKED | — | TC-09-01、TC-09-10 |
| GV-4 | BROKEN | `pr_head_mismatch` | TC-09-04 |
| GV-4 | NOT_PROVEN | `approval_revision_unverifiable` | TC-09-07 |
| GV-4 | NOT_PROVEN | `approval_self_declared_only` | TC-09-09 |
| Decision Table | R-01〜R-23 | — | TC-08-17（R-01〜09、R-11、R-17〜19、R-21、R-22）、TC-10-05（R-03、R-21）、TC-10-04（R-05、R-07、R-08）、TC-08-15（R-10）、TC-08-16（R-12）、TC-08-12（R-13）、TC-08-13（R-14）、TC-08-14（R-15）、TC-10-03（R-16）、TC-09-02（R-17）、TC-09-03（R-18）、TC-09-10（R-19）、TC-08-19（R-20）、TC-10-02（R-22）、TC-08-20（R-23） |

### 13-2. 追加 Mutant（D2-5、MU2-33 以降。既存の MU2-01〜MU2-32 は維持）

| ID | 条件 | Kill Test |
| --- | --- | --- |
| MU2-33 | 集約が `(submitted_at, id)` で並べず、配列順を使う | TC-08-03 |
| MU2-34 | 却下済みの Review を状態を決める Review として扱う（`DISMISSED` を無視） | TC-10-04（R-05）、TC-08-21 |
| MU2-35 | `COMMENTED` が Reviewer の状態を `none` に戻す | TC-08-17（R-02） |
| MU2-36 | `PENDING` を承認として数える | TC-08-17（R-08）、TC-10-04 |
| MU2-37 | 同じ Page 番号の重複を受け付ける | TC-08-12 |
| MU2-38 | Page の欠損（番号の飛び）を受け付ける | TC-08-11 |
| MU2-39 | 同じ Review id の矛盾で後の方を採用する | TC-08-13 |
| MU2-40 | Manifest が名指ししない Evidence を出典に受け付ける | TC-08-07 |
| MU2-41 | GV-2 が `author_association` を条件に使う | TC-10-06 |
| MU2-42 | 同時刻で状態が違う Review を `id` で黙って決める | TC-08-15 |
| MU2-43 | `observed.approval_authority` を承認があれば `"SHOWN"` にする | TC-10-01、TC-10-07 |
| MU2-44 | Validator Identity の形の検査を外す（WP1 N-5 の欠落の補完） | TC-03-09 |
| MU2-45 | Validator Identity の Diagnostic を Payload に入れる（同上） | TC-03-12 |
| MU2-46 | 古い Head への承認を有効承認に数える | TC-09-02、TC-09-10 |
| MU2-47 | 古い Head への承認を BROKEN にする（R2-1 に反する過剰判定） | TC-09-02、TC-09-03 |
| MU2-48 | Record の `binds_to.commit` を Raw と比較しない（Revision の偽装を受け付ける） | TC-09-11 |
| MU2-49 | 却下を Reviewer 単位で適用する（同じ Reviewer の他の Review や他の Reviewer を消す） | TC-08-21 |
| MU2-50 | 後の却下済み Review を無視し、それ以前の承認を数える | TC-08-19 |
| MU2-51 | 省略された Record にコードを付けない | TC-08-28 |
| MU2-52 | 省略を BROKEN にする（WP2 rev1 の N2-2） | TC-08-28 |
| MU2-53 | 完全な Raw と矛盾する Record を BROKEN にしない | TC-08-26 |
| MU2-54 | Schema 違反をすべて自己申告にする（WP2 rev1 の N2-3） | TC-08-23 |
| MU2-55 | 有効な承認があると自己申告を隠す | TC-08-24 |
| MU2-56 | 重複した Record を受け付ける | TC-08-25 |
| MU2-57 | Record ファイルの欠落を Raw 欠損（`gate_source_missing`）にする | TC-08-22 |
| MU2-58 | GV-4 で、承認でない `candidate_review` を自己申告に対する裏付けとみなす | TC-08-06 |
| MU2-59 | 正常な Record があると、他の Record の異常のコードを捨てる | TC-08-29 |
| MU2-60 | 使えない Entry の二次的な結果にも `gate_record_missing` を付ける | TC-08-30 |
| MU2-61 | key が `approv` で始まれば自己申告とする（誤検出） | TC-08-31 |
| MU2-62 | 自己申告の Entry を使えない Entry に数え、省略を隠す | TC-08-30 |

Mutant の ID は62個（MU2-01〜MU2-62）。実装済みは59個: WP1 の MU2-01〜20 と、WP2 の MU2-21〜29、MU2-33〜62（MU2-30〜32 は WP4）。MU2-51〜59 と TC-08-22〜29 は WP2 Implementation Review、MU2-60〜62 と TC-08-30〜31 は WP2 最終確認で追加した（いずれも Human 承認済み）。

点検の基準: 1つの Test Case は1つの AC にだけ属する。1つの理由コードの初出の Test は1つの AC にだけある（TC-06-05 / TC-06-06 は M2-04 のコードを使うが、検査しているのは Chain の合成で、Link 単独の判定ではない）。追加する場合は WP の開始前に本表へ追記し、Human が承認する。

## 14. AC → WP

| AC | WP1 | WP2 | WP3 | WP4 | WP5 | WP6 |
| --- | --- | --- | --- | --- | --- | --- |
| M2-01〜M2-06 | 実装・Test | — | 統合確認 | — | 実データで確認 | 最終判定 |
| M2-07 | Replay | — | 統合後に再確認 | — | E2E-3 | 最終判定 |
| M2-08〜M2-10 | — | 実装・Test | Summary（M2-10） | — | 実データで確認 | 最終判定 |
| M2-11 | — | — | — | 実装・Test | — | 最終判定 |
| M2-12 | — | — | — | — | 実行 | 最終判定 |
