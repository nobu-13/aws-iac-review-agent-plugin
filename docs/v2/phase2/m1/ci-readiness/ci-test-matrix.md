# Phase 2 M1 — CI Test Matrix

* Source: `docs/v2/phase2/m1/wp5/m1-final-ac-matrix.md`（M1-01〜M1-12）、`docs/v2/phase2/m1/precommit/remediation-report.md`、`.github/workflows/ci.yml`、ローカルの浅い Clone での実行結果（`ci-readiness-audit.md` §3）
* 目的: M1 の各 AC について、GitHub Actions で実行できる検査と実行できない検査を分け、SKIP を PASS にしない判定規則を定める
* 状態: 設計のみ。CI は実行していない。「現行 CI」の列は、`ci.yml` を読んで判断した見込み（実行結果ではない）

## 1. 判定の語彙（CI 用）

| 値 | 意味 |
| --- | --- |
| PASS | CI の Job が、その AC に対応する検査を実行し、すべて成功した |
| FAILED | 対応する検査のどれかが失敗した |
| NOT_VERIFIED（CI） | 対応する検査が CI で実行されなかった（SKIP、Job がない、`.agents/` が必要） |
| NOT_PROVEN | 検査を実行しても証明できない（実 GitHub Raw、Raw の出所など）。CI の結果にかかわらず変わらない |

規則:

1. 対応する Test が1件でも SKIP なら、その AC の CI 判定は PASS にしない（NOT_VERIFIED）
2. 「CI で必ず実行する」と決めた Test が SKIP されたら、Job を FAILED にする（§5）
3. `.agents/` を必要とする Test の SKIP は想定どおりとし、AC を NOT_VERIFIED（CI）と表示する。Job は FAILED にしない
4. NOT_PROVEN の項目は、CI の成功で PASS に変わらない

## 2. AC ごとの CI 実行可能性

「現行 CI」は今の `ci.yml` のまま Push した場合の見込み。「計画後」は `ci-implementation-plan.md` の変更を入れた場合。

| AC | CI で実行できる検査 | CI で実行できない検査 | 現行 CI | 計画後 |
| --- | --- | --- | --- | --- |
| M1-01 Git 管理 | Clone（`.agents/`、`.kiro/` なし）からの Evidence Test。Commit SHA（`GITHUB_SHA`）への Binding | — | 実行はされるが、Commit SHA との結び付けを記録しない | PASS の判定が可能 |
| M1-02 条文・Rule・Test の対応 | Registry / Definition の検証、Catalog、Rule の到達結果との整合、条文の Worktree 照合、**History 照合**（検証済み Commit が取得できる場合） | — | History 照合は SKIP（浅い Checkout） → NOT_VERIFIED | `fetch-depth: 0` の Job で PASS / FAILED |
| M1-03 Mutation | `tests/unit/test_evidence_mutations.py`（32 Mutant、一時 Copy） | — | 6組の Matrix で実行 | 同じ。判定は Evidence Job の結果を採用 |
| M1-04 Raw の Hash 付き保存 | 合成 Fixture の Collector / Store Test | 実 GitHub からの取得 | 実行 | PASS（合成）/ 実 Raw は NOT_PROVEN |
| M1-05 Deterministic Replay | 同じ Job 内の2回一致、別 Process（`PYTHONHASHSEED=random`）、`--expect` の拒否理由、Network 不使用 | 実 GitHub Raw の Replay | Job 内の一致だけ。Commit した期待値との一致と OS 間の一致は検査しない | Commit した期待 Hash と、各 Matrix Job で照合（§3） |
| M1-06 欠損・改変の検出 | Integrity、Pipeline の拒否 Test | 保存前の改変 | 実行 | PASS（保存後の改変） |
| M1-07 Provenance | V7、Legacy Map の分類 Test（`.agents/` 不要の部分） | Legacy Map の現物照合 | 実行 | PASS（`.agents/` 不要の部分） |
| M1-08 Secret / PII | Secret Gate の Test、`scan_secrets.py`、**Public Preflight** | 規則外の形式の Secret | `scan_secrets.py` だけ。Preflight は CI にない | Preflight を `repository-hygiene` に追加 |
| M1-09 非上書き Revision | Store、Integrity の Test | — | 実行 | PASS |
| M1-10 Traceability（欠損の追跡） | Map の Schema・一意性・分類の Test | Phase 1 の現物の Hash 照合（`.agents/` 必須） | 現物照合は SKIP | NOT_VERIFIED（CI）のまま |
| M1-10（歴史的 Raw への到達） | — | すべて | NOT_PROVEN | NOT_PROVEN |
| M1-11 Source / Commit / Artifact | 合成 Git と合成 Contents の Test | 実 GitHub 上の内容 | 実行 | PASS（合成）/ 実環境は NOT_PROVEN |
| M1-12 Historical Regression | 公開された Legacy 結果の Header（Evaluator Source と Definition の Hash）が現在の Source と一致すること | Legacy 結果の再生成、Phase 1 Helper Test、Phase 1 原本の Hash（`.agents/` 必須） | 再生成 Test は SKIP | Header の整合だけ CI で検査。Phase 1 部分は NOT_VERIFIED（CI） |

## 3. 指定された検査の実行可否

| 検査 | CI で実行 | 方法 | `.agents/` | 備考 |
| --- | --- | --- | --- | --- |
| Public Preflight | 可 | `python3 .github/scripts/public_preflight.py` | 不要（`.agents/` が ignore されていることを `git check-ignore` で確認するだけ） | 現行 CI にない。浅い Clone の Test 内では実行され PASS（ローカル確認） |
| Secret Scan | 可（実行中） | `scan_secrets.py`（`repository-hygiene`） | 不要 | tracked mode。PR の Merge Commit が対象 |
| Registry / Definition Validation | 可（実行中） | `test_evidence_registry.py`、`test_evidence_s7_definition.py`、`test_evidence_rule_outcomes.py` | 不要 | History 照合だけ履歴が必要 |
| Evidence Test | 可（実行中） | `tests/unit/test_evidence_*.py`（478件） | 3件だけ必要 | 浅い Clone で 474 PASS / 4 SKIP |
| Deterministic Replay | 可 | Pipeline・Replay Test、計画の `evidence_ci_check.py` | 不要 | 期待 Hash の Commit が必要（計画） |
| Mutation Test | 可（実行中） | `test_evidence_mutations.py` | 不要 | Job ごとに約20秒（ローカル実測） |
| Legacy Evidence Traceability | 一部 | Map の構造の Test | 現物照合は必要 | 現物照合は NOT_VERIFIED（CI） |
| Benchmark | 可（実行中） | `run_benchmark.py --mode combined` | 不要 | M1 の変更の影響なし（34 / 34、ローカル） |
| Phase 1 Regression（Helper 516件、原本 Hash） | **不可** | — | 必要 | Phase 1 の Helper と Evidence は `.agents/` にしかない。CI へ持ち込まない（指示の絶対条件） |

## 4. 浅い Clone での全 Test Suite（ローカル実測、参考）

`git clone --depth 1`（`file://`、HEAD `dd6f629`、`.agents/`・`.kiro/`・`sample/` なし）で、CI の `test` Job と同じ Command を実行した（macOS、Python 3.9.6）。

* 結果: exit 0、7,714件中 PASS 7,665 / SKIP 49、coverage 94.88%、726秒
* 作業 Tree（SKIP 36）との差 13件: `.kiro/` がない 8件（M1 以前からの Test）、`.agents/` がない 3件（M1）、履歴がない 1件（M1）、`sample/` がない 1件

| SKIP の原因 | 件数 |
| --- | --- |
| Benchmark / Ground Truth の Case が該当しない（Clean Case など） | 30 |
| `.kiro/` がない | 8 |
| Placeholder の Detector | 4 |
| `.agents/` がない（M1） | 3 |
| 履歴がない（M1、History 照合） | 1 |
| `sample/` がない | 1 |
| OS 固有（APFS） | 1 |
| 他の Test で検査済み | 1 |

## 5. CI で必ず実行する Test（SKIP なら Job を FAILED）

Evidence Job（計画）では、次の Test が SKIP された場合に Job を FAILED にする。SKIP の検出は pytest の JUnit XML（`--junitxml`、pytest 標準）で行う。

* `tests/unit/test_evidence_s7_definition.py::test_every_historical_clause_occurs_once_at_every_verified_commit`（`fetch-depth: 0` の Job）
* `tests/unit/test_evidence_preflight.py::test_this_repository_public_set_passes_the_preflight`
* `tests/unit/test_evidence_mutations.py` の2件
* `tests/unit/test_evidence_pipeline.py` の全件
* 上記以外で、Evidence Test のうち `.agents/` を必要としないものすべて

SKIP を許す Test（AC は NOT_VERIFIED（CI）と表示）: `.agents/` を必要とする3件（`ci-readiness-audit.md` §3 の表の上3行）。

## 6. History の取得方式

| 方式 | 内容 | 長所 | 短所 | 判定 |
| --- | --- | --- | --- | --- |
| A. `fetch-depth: 0` | 全 Branch と全履歴 | 検証済み Commit が、どの Ref から届いても `cat-file` で見つかる。Merge Commit でも Branch の履歴でも同じ。既存の `repository-hygiene` と同じ設定。Repository は小さい（Pack 1.83 MiB、67 Commit） | 履歴が大きくなると Checkout が遅くなる | **推奨** |
| B. `fetch-depth: N`（例: 6） | 先端から N Commit | 速い。ローカルの depth 6 の Clone では History 照合が PASS | N は「HEAD から最古の検証済み Commit までの距離 + 1」に依存する。PR の Merge Commit（`refs/pull/*/merge`）では距離が変わる。Commit が増えるたびに N の見直しが必要。N が足りず一部の Commit だけ取れると FAIL、1つも取れないと SKIP になり、結果が N の選び方で変わる | 非推奨 |
| C. `fetch-depth: 0` + `filter: blob:none` | 全履歴、Blob は必要時に取得 | Clone が軽い | `git show <commit>:<path>` のたびに Blob を Network で取得。動作は未確認 | 履歴が大きくなったときの代替 |
| D. 検証済み Commit だけを `git fetch` | 必要な5 Commit を個別に取得 | 必要最小限 | Commit SHA の Fetch は Server 設定に依存。Step が増える。未確認 | 非推奨 |

前提（方式によらない）:

* 検証済み Commit 5件は、Push されるまで CI から見えない（CI-1）
* Squash Merge や Rebase Merge で `main` に入れると、その Commit は `main` の履歴から消える（CI-7）。方式 A でも、元の Branch を削除すると取得できなくなる。`main` での History 照合を保つには、Merge Commit で取り込むか、Definition の `verified_commits` に `main` 上の Commit を加える（Definition v2、Human 承認）必要がある
