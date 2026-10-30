# Phase 2 / M2 — `summary.passed_all_checks` と `errors[]` の調査と修正方針

* 状態: **WP0 調査と提案（rev1）。Code・Schema・既存文書の変更はしていない。** P-A を M2 で実施、P-B は Human 承認済み（D-7、適用は WP6）
* 調査方法: Repository 内の読み取り（`grep`、該当箇所の確認）。Test や CLI は実行していない

## 1. 現状（Code と文書で確認した事実）

| 事実 | 出典 |
| --- | --- |
| `passed_all_checks` は `not findings` で計算される | `iacreview/report.py` `_summary`（`"passed_all_checks": not findings`）。コメントは v1.0 Requirement 7 AC16 を根拠に「Errors は false にしない」と明記 |
| 一部の Source が失敗・不在でも、Review は exit 0 で続き、失敗は `errors[]` に入る | `skills/iac-review/SKILL.md` の Exit codes 節（「affecting only part of a run appear in `errors[]` with exit code 0」）。exit 5 / 6 は「全 Source が不在 / 失敗」のときだけ |
| 文書は、`passed_all_checks` が `errors` を見ないことを明記している | `README.md`（Review_Report の説明）、`docs/finding-schema.md`（summary の表と「`passed_all_checks` says nothing about `errors`」）、`skills/iac-review/SKILL.md`、`skills/cfn-guard-review/SKILL.md` |
| 意味の変更は互換性の不変条件に反する | `.kiro/steering/quality-gates.md`（summary 6 key と `passed_all_checks` の意味）、v1.1 提案 D-1 |
| Repository 内の Code の Consumer | Producer は `report.py` だけ。`deltareport.py` は `FORBIDDEN_KEYS` に入れて Delta_Report に出さない。`reportcheck.summary_comparable` は `errors[]` と `tools[].available` で判定し、`passed_all_checks` を見ない。`benchmark/harness/run_benchmark.py` は `errors` を直接読む。Phase 1 Verifier（`iacreview/remediation/`）は Review_Report を読まない |
| Steering の注意 | `security.md`: 「`summary.passed_all_checks` は `errors[]` を見ないため、単独で合格判定に使わない」 |

結論: Repository 内の Code に誤用はない（確認した範囲）。問題は **外部の Consumer**（CI の Script、Agent、利用者）が `passed_all_checks: true` を「問題なし」と読む危険で、Tool 不在の Review が「合格」に見える（v2 baseline-audit C-3、reuse-and-gap-analysis の指摘と同じ）。

## 2. 失敗の具体例（再現手順の案。WP1 で Test 化する）

入力: cfn-guard を導入していない環境で `run_iac_review.py --target <問題のない Template> --sources cfn-lint,cfn-guard` を実行する。

期待される観測（文書から導いた予測。実行していないため NOT_VERIFIED）:

* exit 0
* `findings: []`、`summary.passed_all_checks: true`
* `errors[]` に cfn-guard の Tool 不在の entry が1件
* `tools[]` の cfn-guard が `available: false`

この Report を M2 の Chain の起点にしたとき、`passed_all_checks` で判断すると「Review 済みで問題なし」の起点になる。M2 はこれを `review_link = INCOMPLETE`（`review_tool_unavailable` / `review_report_has_errors`）として扱う必要がある。

## 3. 修正方針の選択肢

| 案 | 内容 | 互換性 | M2 での扱い |
| --- | --- | --- | --- |
| P-A | `passed_all_checks` を変えない。M2 の Chain Validator は `passed_all_checks` を読まず、独自の述語 `review_evidence_complete` を使う | 影響なし（新 Package 内） | **推奨・M2 で実施** |
| P-B | 利用者向け文書に「CI で Gate にする場合は `errors[]` と `tools[].available` を見る」例を追加 | 文書だけ。既存 Schema・CLI の意味は変えない | **Human 承認済み（D-7）**。WP6 で文書の差分案を作り、適用前に対象ファイル（README、`docs/finding-schema.md`、`SKILL.md` の別）を Human に示す。`SKILL.md` の変更は Skill 変更として個別に承認を得る |
| P-C | summary に新しい key（例: `review_complete`）を追加 | summary 6 key の不変条件に反する。Schema 変更（Human 承認と CHANGELOG） | **M2 では行わない** |
| P-D | CLI に `--fail-on-errors` などを追加し、`errors[]` があれば非0終了 | 既存 CLI の変更。exit code は閉じた集合 | **M2 では行わない**（将来の Issue 候補） |
| P-E | `passed_all_checks` を `not findings and not errors` に変える | 意味の変更。不変条件に反する | **禁止** |

## 4. P-A の定義（M2-04 で検証）

```text
review_evidence_complete(report) :=
      report は reportcheck の strict reader で読める Review_Report 1.0.0
  and report.errors == []
  and report.tools が1件以上で、すべて available == true
```

* Review_Report の読み取りは既存の `iacreview/reportcheck.py`（Delta が使う strict reader）を再利用し、Parser を新しく作らない（`tech.md`）
* `summary.passed_all_checks` は読まない。Chain の Code に `passed_all_checks` という文字列が出ないことを Test で確認する（M2-04 の静的検査）
* `findings` が空であることは、完全性の条件にも、問題がないことの主張にも使わない
* 述語が false のときの理由コード: `review_report_has_errors`、`review_tool_unavailable`、`review_report_invalid`

## 5. 外部 Consumer が誤読しても Chain が安全側に判定すること

外部 Consumer（CI Script、Agent、利用者）が `passed_all_checks: true` を「問題なし」と読んで、その Review_Report を Chain の起点に選んだ場合でも、Chain は次のように判定する（`m2-acceptance-test-matrix.md`）。

| 状況 | Chain の判定 | Test |
| --- | --- | --- |
| `findings: []`、`passed_all_checks: true`、`errors[]` 1件 | `review` INCOMPLETE `review_report_has_errors` | TC-04-02 |
| 同じ Report で、他の5 Link が LINKED、Verification が `VERIFIED` | `chain_status: INCOMPLETE`（COMPLETE にならない） | TC-06-05 |
| Tool が `available: false` | `review` INCOMPLETE `review_tool_unavailable` | TC-04-03 |
| Consumer が Report の `passed_all_checks` の値を書き換えた | Report の Digest 不一致で `review` BROKEN、Chain BROKEN | TC-06-06 |
| Chain の Code が `passed_all_checks` を読むように変えられた | Mutant MU2-11 として Test が検出する | MU2-11 |
| Chain の Code に `passed_all_checks` という文字列がある | 静的検査で FAILED | TC-04-08 |

Chain の判定は `passed_all_checks` の値に依存しないため、誤読は Chain の結果を安全でない側に変えない。Chain の外での誤読（Chain を使わない Consumer）は残り、P-B の文書改善で軽減する。

## 6. 残る Risk

* 外部 Consumer の誤用は P-A では減らない。P-B（文書）と、将来の P-C / P-D は Human の判断事項
* `tools[]` が「要求された Source をすべて含むか」は、`sources_enabled` との対応を WP1 で確認してから述語に入れる（未確認のため本書の定義には入れていない）
