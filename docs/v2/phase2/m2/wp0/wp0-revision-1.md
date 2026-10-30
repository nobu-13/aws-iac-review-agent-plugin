# Phase 2 / M2 — WP0 rev1: Human Review の指摘と変更記録

* 状態: **WP0 rev1。設計文書だけを変更した。** 実装、Commit、Push、Merge はしていない。WP1 の実装は Human 承認まで開始しない
* Human Review（WP0 rev0）: 92/100、条件付き承認。Scope と基本アーキテクチャは承認
* rev0 の写し: 非公開の作業記録（`.agents/`、Git 管理外）に保存し、差分の計算に使った

## 1. 必須修正への対応

| # | 指摘 | 対応 | 反映先 |
| --- | --- | --- | --- |
| 1 | Gate Record の Integrity、Approval Authority、Revision Binding、Approval Staleness、Merge Enforcement を別の検証観点にする。Merge Enforcement は対象外とし、証明済みと主張しない | GV-1〜GV-5 を定義し、観点ごとに Status と理由コードを判定する。`gate` Link は GV-1〜GV-4 の代表値。GV-5 は判定せず、Result の `not_claimed` に常に `merge_enforcement` を入れる。Result に `gate_aspects` を追加 | `m2-schemas.md` §2-1〜§2-3、§3 |
| 2 | `approval_stale` の判定を固定する（不一致確認 → BROKEN、Evidence 不足 → NOT_PROVEN、Agent の自己申告だけ → NOT_PROVEN） | GV-4 の表で固定。`approval_stale`（BROKEN）、`approval_revision_unverifiable`（NOT_PROVEN）、`approval_self_declared_only`（NOT_PROVEN）。GV-3 の Commit 不一致も BROKEN（`gate_binds_other_commit`） | `m2-schemas.md` §2-2、§4 |
| 3 | M2-01〜M2-12 の AC と Test Case の対応を再点検する。M2-04 の `errors[]` 異常系が Chain の Fail-closed に属する可能性を確認する | 確認の結果、`errors[]` は Chain の Fail-closed（入力の完全性）に属し、Human Gate には属さない。M2-04 は Link 単独の判定、Chain 全体への影響は M2-06（TC-06-05、TC-06-06）に分けた。全 AC に Test Case ID（TC-xx-yy）を付け、1つの Test Case が1つの AC にだけ属するよう重複を解消した | `m2-acceptance-test-matrix.md` §0、§13 |

再点検で見つけて直した重複・誤配置（rev0）:

* M2-10 の「Agent 出力を Gate Record として渡す」は M2-08（GV-1）の検査だった → M2-08 へ移動
* M2-09 の職務分離（`same_actor`）は Revision ではなく Authority の検査だった → M2-10（GV-2）へ移動
* M2-03 の `api_artifact` の拒否は Manifest の Schema の検査だった → M2-01 へ移動
* exit code の非衝突の Test がなかった → TC-06-07 を追加
* M1 非干渉の Test が AC に属していなかった → 共通 Test TC-00-01〜04 を追加

## 2. Human 判断の反映

| ID | 決定 | 反映 |
| --- | --- | --- |
| D-1 | `iacreview/chain/` 採用、既存 CLI 維持、新 CLI は候補比較後 | `m2-work-plan.md` §5 に候補 C1〜C5 の比較と導入手順の比較 |
| D-2 | Schema 語彙を固定、Exit code 31〜34 は衝突確認 | `m2-schemas.md` を rev1 固定版にした。§3-1 に Repository 内の exit code の一覧と衝突確認（重なりなし） |
| D-3 | Revision 不一致 BROKEN、Evidence 不足 NOT_PROVEN | `m2-schemas.md` §2-2 |
| D-4 | SC-02 第一候補、Finding の事前確認、第2 Account 任意 | `github-e2e-plan.md` §1、§2、§6 |
| D-5 | M2 専用 CI job、M1 から独立 | `m2-work-plan.md` §4 |
| D-6 | Steering 反映は保留 | `m2-scope-and-baseline.md` §6 |
| D-7 | P-B 承認、既存 Schema・CLI の意味は変えない | `passed-all-checks-investigation.md` §3 |

## 3. 追加確認への回答

| 確認事項 | 回答 | 反映先 |
| --- | --- | --- |
| Chain Manifest と Raw の両方が改変された場合の検出可能範囲 | 段階ごとに表にした。Manifest だけ、Report だけ、Store の Raw だけ、Raw と Store MANIFEST の整合的改変までは検出できる。Raw・Store MANIFEST・Chain Manifest をすべて整合的に改変された場合、Local Git と矛盾する部分だけ検出でき、Review の `state` や `user.id` のような Git に照合先のない Gate の事実は検出できない。Local Git も作り直されれば Offline では検出できない。Anchor と再取得を将来の候補として記録 | `m2-threat-model.md` §5 |
| GitHub Raw から得られる事実と、権限・正当性について追加検証が必要な事実の区別 | Raw が直接示す事実（Review の state、commit_id、user.id、author_association、PR の head.sha など）と、M2 では示さない事実（承認者の権限、Ruleset で数えられたか、Merge Enforcement、人間の同一性、応答の出所、取得後の変化）を分けた。後者は `not_claimed` に入れる | `m2-schemas.md` §2-3 |
| 外部 Consumer が `passed_all_checks` を誤読しても Chain が安全側に判定すること | Chain は `passed_all_checks` を読まない。誤読された Report を起点にしても `review` が INCOMPLETE で Chain は COMPLETE にならない。値を書き換えた Report は Digest 不一致で BROKEN。Test は TC-04-02、TC-04-03、TC-04-08、TC-06-05、TC-06-06、Mutant MU2-11 | `passed-all-checks-investigation.md` §5 |
| 既存 M1 の Hash・Evidence・Regression への非干渉 | Package の分離、Import の向き（Chain → M1 の一方向、静的検査）、Evaluator Source の範囲外、期待値ファイルの分離、CI job の分離、M1 CI の判定への影響（`FORBIDDEN_PREFIXES` に入らない、review required に出るだけ）を表にした | `m2-threat-model.md` §7、`m2-acceptance-test-matrix.md` §12 |
| OSS 利用者が追加 CLI なしで利用可能か | 利用できる（Library API、C1）。導入手順の 1〜3 は CLI の有無で同じで、違いは実行の1行と CI での exit code の利用だけ。推奨は C1 必須、C2 は WP3 で判断 | `m2-work-plan.md` §5 |

## 4. 変更差分（rev0 → rev1、行数）

`git diff --no-index --numstat` で、rev0 の写しと rev1 を比べた結果（追加 / 削除の行数）。

| ファイル | 追加 | 削除 | 主な変更 |
| --- | --- | --- | --- |
| `m2-schemas.md` | 144 | 34 | Gate の検証観点 GV-1〜GV-5、判定規則、Raw の事実の区別、`gate_aspects`、`not_claimed` を7項目に、Manifest のコードの扱い、Exit code の衝突確認、理由コード表の改訂、固定版の宣言 |
| `m2-acceptance-test-matrix.md` | 215 | 77 | 責務の分け方（§0）、Test Case ID、M2-08〜M2-10 の再構成、TC-06-05〜07、共通 Test、AC と Test の対応表、Mutant を32個に |
| `m2-threat-model.md` | 61 | 20 | 改変の検出範囲（§5）、Time-of-check（§6）、M1 非干渉（§7）、外部 Consumer の主体、T-03〜T-06 と T-15 の更新 |
| `m2-work-plan.md` | 78 | 36 | M2 CI job の設計（§4）、CLI の候補比較と導入手順（§5）、Human 判断の状況（§6）、Mutant 範囲の更新 |
| `m2-scope-and-baseline.md` | 22 | 5 | Human 決定 D-1〜D-7 の記録、GV-5 を対象外とする記述、非干渉の参照 |
| `passed-all-checks-investigation.md` | 18 | 3 | P-B 承認の反映、外部 Consumer の誤読に対する Chain の判定（§5） |
| `github-e2e-plan.md` | 6 | 4 | SC-02 第一候補（D-4）、Gate の予測を GV-2 で記述、GV-5 は判定しない |
| `wp0-revision-1.md` | 新規 | — | 本書 |

## 5. 変えていないもの

* M1 の Acceptance Definition、Evaluator Source、期待 Hash、Frozen Evidence、M1 の判定と NOT_PROVEN
* 既存 Schema（Review_Report、Finding、StructuredError、Delta_Report、Remediation_Verification_Report）と既存 CLI の意味
* `docs/v2/phase2/m2/wp0/` 以外のファイル
