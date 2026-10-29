# Phase 2 M1 — CI Integration: Security Acceptance

* Source: `.github/workflows/ci.yml`、`.github/scripts/evidence_ci_check.py`、`tests/unit/test_ci.py`、`docs/v2/phase2/m1/ci-readiness/ci-security-review.md`
* 目的: 追加した CI の権限と信頼境界を確認し、CI の内側では防げない限界を記録する
* 状態: ローカルでの確認だけ。GitHub Actions では実行していない。Repository 設定、Ruleset、Branch Protection は変更していない

## 1. 制約の確認

| 制約 | 結果 | 根拠（Test） |
| --- | --- | --- |
| 権限は `contents: read` を維持 | 維持。新 Job は `permissions` を上書きしない | `test_workflow_permissions_are_read_only`、`test_the_evidence_job_keeps_the_read_only_token_and_uses_no_secret_cache_or_artifact` |
| 新 Job の Checkout は `persist-credentials: false` | 設定済み | `test_the_evidence_job_checks_out_full_history_without_persisting_credentials` |
| Secret、PAT、App Key を使わない | Workflow に `${{ secrets.… }}` は0件 | 同上 |
| Cache、Artifact を使わない | 新 Job の Action は `checkout` と `setup-python` だけ。`setup-python` に `cache` なし | 同上 |
| `pull_request_target`、`workflow_run` を追加しない | Trigger は `push`（main）、`pull_request`、`workflow_dispatch` のまま | `test_no_privileged_trigger_is_used` |
| Action は SHA 固定の First-party | 既存と同じ2つ | `test_every_action_is_pinned_to_a_commit_sha`、`test_every_action_is_first_party` |
| Dependency を追加しない | 新 Job は既存の `PYTEST_SPEC` だけを入れる | `test_the_evidence_job_installs_pytest_only` |
| 失敗を Advisory や SKIP にしない | 新 Job は Gate（`GATE_JOBS`）。`continue-on-error` なし。検査 Step の `if: always()` は Summary のためで、失敗した Step の結果は残る | `test_a_gate_job_is_not_allowed_to_fail`、`test_no_gate_command_discards_a_non_zero_exit`、`test_the_evidence_check_runs_even_after_a_test_failure` |
| `.agents/`、`.kiro/` を CI に持ち込まない | Checkout に含まれない。必要とする3件は SKIP → NOT_VERIFIED (CI)。Baseline 以降に `.agents/`、`.kiro/` の追跡ファイルが増えたら exit 18 | `test_a_tracked_private_path_fails` |
| Network を使わない検査 | Replay は Socket を禁止した状態で実行。別 Process の Replay も Transport を持たない | `test_the_replay_needs_no_network` |

## 2. PR が自分の Test や CI Script を変えられる限界

`pull_request` の Run は、PR 側の Workflow、Script、Test、期待値で動く。したがって PR は、次の方法で Evidence Gate を通すことができる。

1. `evidence_ci_check.py` や `tests/unit/test_ci.py` を弱める
2. Evaluator を変え、同時に `expected.json` の Hash と `baseline_commit`（PR 自身の Commit）を書き換える
3. `ci.yml` から `evidence-integrity` を消す、または Step を変える

Script の `check_baseline` は、期待値が `baseline_commit` の Source から来ていることを確かめるが、`baseline_commit` 自体を PR が書き換えれば、この確認は意味を失う。CI の内側だけでは、この回避を防げない。

### 検討した対策

| 対策 | 内容 | 今回の扱い |
| --- | --- | --- |
| Review による確認 | `.github/workflows/`、`.github/scripts/`、`tests/fixtures/evidence_replay/`、`tests/unit/test_ci.py`、`tests/unit/test_evidence_*`、`tests/mutation/`、`iacreview/evidence/` の変更は、Summary の「review required」に Path で出る。Reviewer はこの一覧と差分を確認する | 実装済み（Summary への出力） |
| 変更の検出 | 同上。Baseline 以降の変更を `git diff --name-only <baseline> HEAD` で列挙する。Phase 1 原本と非公開 Directory の変更は FAILED | 実装済み |
| CODEOWNERS | 上の Path に Owner を指定し、Owner の Review を必須にする | 未実施。Repository 設定と同時に使うため Human 判断 |
| Required Check の設定 | `main` の Ruleset / Branch Protection で `evidence integrity (M1)` を Required にし、PR の Approval を必須にする | 未実施。Repository 設定のため変更しない（指示どおり） |
| 独立した検証 | 将来、Repository 外の固定された検証者（GitHub App など）が `main` の固定版の Script と期待値で検証し、Check を公開する | 未実施。Phase 1 の App Gate の設計（`pull_request_target`、Base の Script を使う）が参考になるが、権限と Key の管理が必要になるため別の承認が要る |

## 3. 外部 PR の扱い

* Fork からの `pull_request` は Read-only の Token で動き、Secret は渡されない（GitHub の仕様）。新 Job は Secret を使わないので、Fork の PR でも同じ検査が動く
* 特権付きの Context（`pull_request_target`、`workflow_run`）で外部 PR のコードを実行しない
* Phase 1 の `pull_request_target` Gate は別 Repository の Template で、この Repository の Workflow とは責務を分けたまま

## 4. 残る Risk

`ci-remaining-risks.md` に列挙する。
