# Phase 2 M1 — CI Integration: Remaining Risks

* Source: `ci-implementation-report.md`、`ci-security-acceptance.md`、`ci-test-results.md`、`docs/v2/phase2/m1/ci-readiness/`
* 目的: CI Integration の後にも残る未検証事項と Risk を、GitHub で確認するときの項目とともに記録する
* 状態: ローカルの検証まで。GitHub Actions での実行はない

## 1. NOT_VERIFIED（実行していないため）

| 項目 | 理由 |
| --- | --- |
| GitHub Actions 上の全 Job の結果 | Push していない。ローカルで GitHub Actions 自体を動かしていない |
| Linux（ubuntu-latest）と Python 3.11 での Replay の bytes | ローカルは macOS の Python 3.9.6 と 3.14.7 だけ。期待値はローカルの値で、Linux で同じになるかは CI の初回実行で分かる |
| Python 3.11 / 3.13 での Evidence Test | 同上 |
| PR の Merge Commit 上での Baseline と History の照合 | Merge Commit をローカルで作っていない |
| Evidence Job の所要時間 | 見込みは2〜4分（ローカルの実測からの推定） |
| `.agents/` を必要とする3件 | CI では SKIP し、Summary で NOT_VERIFIED (CI) と表示する設計 |

## 2. NOT_PROVEN（CI の成功で変わらない）

* 実 GitHub Raw による End-to-End、Raw の出所（`capture_authenticity`）、第三者による独立再現
* M1-10 の歴史的 Raw への到達
* S7-17、S7-18（限界）、S7-19（Q2 / Q3）、P2-IP-01（G3 / G3S / G6）、G11 の Artifact Integrity、G7、Legacy 再評価の S7-01

## 3. Risk

| ID | Risk | 影響 | 扱い |
| --- | --- | --- | --- |
| R-1 | 検証済み Commit 5件と Baseline Commit が Remote にない | Push 前は CI で History と Baseline の照合が成り立たない。Push 後の最初の Run が初めての検証になる | Push は Human 承認後 |
| R-2 | Squash / Rebase Merge で検証済み Commit や Baseline Commit が `main` の履歴から消える | `main` の Run で exit 13 / 14 になる（失敗として表れる。PASS にはならない） | Merge 方式は Human 判断。Merge Commit を推奨 |
| R-3 | PR が Script、Test、期待値、Workflow を同時に変えて Gate を回避できる | CI の結果だけでは改変を検出できない | Review、Summary の変更一覧、Required Check と CODEOWNERS（Repository 設定、未実施） |
| R-4 | Linux で Replay の bytes が違う | exit 15 / 16 で FAILED になる | 原因を調べ、Evaluator の非決定性なら修正、期待値の誤りなら Human Review を経て更新 |
| R-5 | `main` に Phase 1 原本（`docs/v2/phase1/`）の正当な変更が将来入る | Baseline 以降の変更として exit 18 | Phase 1 原本は変更しない方針。変える場合は Baseline の更新とともに Human 判断 |
| R-6 | pytest を範囲指定（`pytest>=7.0`）で導入 | 新しい pytest で JUnit の形式が変わると Script の分類が崩れる可能性 | 既存の方針と同じ。Hash 固定は Dependency 管理の変更として Human 判断 |
| R-7 | Summary は Repository の閲覧者に見える | Hash と Test 名だけで、Secret や Path は書かない | 確認済み（`summary()` の出力項目） |
| R-8 | 既存 Job は `persist-credentials` が既定（true） | Token が Job の間 `.git/config` に残る | 新 Job だけ `false`。既存 Job の変更は任意（ci-readiness の計画どおり） |

## 4. GitHub で検証するときの確認項目

1. Workflow の全 Job（`test` 6組、`determinism`、`repository-hygiene`、`evidence-integrity`、`lint`）の結論
2. `evidence-integrity` の Summary: verdict、`native_result_sha256` と `final_report_sha256` が期待値と一致、`verified_commits: 5`、`skipped: 3`（Local-only の3件だけ）
3. Summary の「Local-only tests (NOT_VERIFIED in CI)」に3件が理由とともに出ていること
4. Summary の「Changed since the baseline, review required」に、今回変更した Path（`ci.yml`、Script、期待値、Test）が出ていること
5. `repository-hygiene` の Public Preflight が PASS
6. `test` Job（浅い Checkout）で History 照合が SKIP されている一方、`evidence-integrity` では実行されていること
7. Python 3.11 / 3.13、ubuntu / macOS の各組で Evidence Test が PASS
8. PR の Run では、Summary の `GITHUB_SHA`（Merge Commit）と PR head が記録されていること
9. Fork からの PR がある場合、Secret なしで同じ結果になること
