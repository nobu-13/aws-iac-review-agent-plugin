# Phase 2 M1 — CI Security Review

* Source: `.github/workflows/ci.yml`、`tests/unit/test_ci.py`、`.agents/` の扱いを定める `.gitignore`、`docs/v2/phase1/ci/remediation-gate.yml`（Phase 1 の `pull_request_target` Gate の Template）、`iacreview/evidence/collector.py`（Transport を持たない）
* 目的: M1 の検査を CI に加えるときの権限、信頼境界、既存 Workflow への影響を、最小権限を前提に評価する
* 状態: 設計のみ。Workflow は変更していない

## 1. 前提とする制約

| 制約 | 設計での扱い |
| --- | --- |
| Repository Contents は Read Only | Workflow 全体の `permissions: contents: read` を維持。新しい Job も上書きしない（`permissions` を Job に書く場合も `contents: read` だけ） |
| Secret や PAT を新規に要求しない | 新しい Job は `secrets.*` を参照しない。M1 の Evidence Test は合成 Evidence だけで動き、GitHub API を呼ばない（Collector は Transport を持たない） |
| GitHub App Key を使わない | 使わない。`actions/create-github-app-token` を使わない |
| Untrusted PR Code を特権 Context で実行しない | Trigger は `pull_request`（Fork からの PR では Read-only Token、Secret なし）。`pull_request_target` と `workflow_run` は使わない |
| `pull_request_target` の Gate と責務を分離 | Phase 1 の Gate（`remediation-gate.yml`）は別 Repository の Template で、この Repository の Workflow には入れない。M1 の CI は「Evidence 基盤の自己検査」だけを行い、Remediation の採否（Check の公開）は行わない |
| CI が Repository 設定・Ruleset・Environment を変更しない | `gh` CLI と GitHub API を呼ぶ Step を作らない。Token は `contents: read` だけで、変更の権限がない |
| `.agents/`、`.kiro/` を必須にしない | Checkout には含まれない（ignore 済み・未追跡）。これらを必要とする Test は SKIP し、AC を NOT_VERIFIED（CI）と表示する |

## 2. Risk と対策

| ID | Risk | 現状 | 対策（計画） | 残る Risk |
| --- | --- | --- | --- | --- |
| S-1 | Checkout が Token を `.git/config` に残す（`persist-credentials` の既定 true）。Test の中の `git` 操作や、Repository を複写する Test（Mutation Harness、Pipeline の Source 変更 Test、Clean Copy）を通して露出面が広がる | 全 Job が既定のまま | 新しい Evidence Job は `persist-credentials: false`。既存 Job の変更は任意（§4） | Token は `contents: read` で、Job 終了で失効する |
| S-2 | PR が Test や `.github/scripts/` を書き換え、検査を弱める | `pull_request` は PR 側の Workflow とコードで動くため、PR は自分の検査を変えられる | Branch Protection / Ruleset で Required Check を `main` の Workflow 名に固定し、Review を必須にする（Repository 設定のため Human 判断。CI からは変更しない） | CI だけでは防げない。Review が境界 |
| S-3 | 依存 Package の供給網（pip が PyPI から取得） | `pytest>=7.0` など範囲指定。`hypothesis` は固定 | Evidence Job は pytest だけを入れる（`iacreview.evidence` は標準ライブラリだけ）。Hash 固定（`--require-hashes`）は Dependency 管理の変更になるため Human 判断 | 範囲指定の Package の更新 |
| S-4 | Cache の汚染 | Cache を使っていない | Cache を使わない（`setup-python` の `cache` も指定しない） | なし |
| S-5 | Artifact からの情報漏えい、改ざんされた Artifact の利用 | Artifact を使っていない | OS 間の比較は Artifact ではなく、Commit した期待 Hash との照合で行う（`ci-implementation-plan.md`）。Artifact を Upload しない | なし |
| S-6 | Log への秘密の出力 | Secret を使っていない | 新しい Step は Secret を扱わない。Evidence の Test は Canary を断片から組み立て、値を出力しない（既存の方針） | 合成 Canary が Log に出る可能性は Test の設計に依存（Secret Gate の Test は値を出さない） |
| S-7 | `GITHUB_STEP_SUMMARY` への書き込み | 使っていない | 計画の Check Script は Summary に AC の判定と Hash を書く。Path、環境変数、Token は書かない | Summary は Repository の閲覧者に見える |
| S-8 | `workflow_dispatch` を誰でも実行できるか | Write 権限を持つ者だけが実行できる（GitHub の仕様） | 変更なし | なし |
| S-9 | Action の差し替え | SHA 固定、First-party のみ（`test_ci.py` が検査） | 新しい Action を増やさない（`checkout` と `setup-python` だけ） | なし |
| S-10 | Network | pip のための外向き通信がある。Test 自体は Network を使わない（Socket を禁止しても Replay が完了することを Test で確認済み） | 変更なし | Runner の Network 制限は GitHub-hosted Runner では設定できない |

## 3. 実行しないこと（CI の責務の外）

* 実 GitHub Raw の取得（`github-e2e-verification-plan.md`、別の Human 承認）
* Phase 1 の Helper Test と原本の Hash 照合（`.agents/` が必要）
* Legacy 再評価の再生成（同上）
* Check Run の作成、Status の投稿、Comment、Label、Release
* Ruleset、Branch Protection、Environment、Secret の変更

## 4. 既存 Workflow を変更する場合の影響範囲

| 変更 | 影響 | 必要な追従 |
| --- | --- | --- |
| `ci.yml` に Job `evidence-integrity` を追加 | `tests/unit/test_ci.py::test_every_job_is_either_a_gate_or_the_advisory_lint_job` が FAIL する（`GATE_JOBS` に未登録の Job） | `test_ci.py` の `GATE_JOBS` に追加（既存 Test の期待値変更。Human 承認） |
| 同上 | Gate Job の共通 Test（`continue-on-error` なし、`|| true` なし、Action の SHA 固定、`shell` の明示）が新しい Job にも適用される | 新しい Job をそれらに適合させる |
| `repository-hygiene` に Preflight の Step を追加 | 既存の2 Step は変わらない。Job の所要時間が数秒増える | `test_ci.py` に Step の存在を検査する Test を追加（任意） |
| 既存 Job の Checkout に `persist-credentials: false` を追加 | Test が `git` を Network 越しに使っていないことの確認が必要。Ground Truth の順序検査は Local の履歴だけを読む | 4 Job すべての Test を一度 CI で実行して確認 |
| `test` Job の Checkout を `fetch-depth: 0` に変更 | 6組すべてで Clone が重くなる。History 照合が6組で動く | 推奨しない。Evidence Job 1つに限定する |
| 別 Workflow ファイル（例: `evidence.yml`）を追加 | `test_ci.py` の検査対象外になる（`WORKFLOW_PATH` は `ci.yml` 固定）。`ci.yml` の冒頭 Comment「the only place where the repository's gates are」と矛盾する | 推奨しない。`ci.yml` への追加を推奨 |

## 5. 結論

M1 の検査は、Secret、PAT、App Key、書き込み権限、`pull_request_target` のどれも必要としない。新しい権限は不要で、最大の Risk は S-2（PR が自分の検査を変えられる）だが、これは Workflow ではなく Repository の Review と Required Check の設定で扱う事項である。
