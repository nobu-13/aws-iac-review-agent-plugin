# Phase 2 M1 — CI Readiness Audit

* Source: `.github/workflows/ci.yml`（Commit `81f77b5` 以降変更なし）、`tests/unit/test_ci.py`、`tests/unit/test_evidence_*.py`、`iacreview/evidence/registry.py`（`git_source_problems`）、ローカルでの浅い Clone の実行結果
* 目的: M1 の初回 Baseline Commit を GitHub Actions で独立に再現できるかを、実行前に監査する
* 状態: 読み取り調査と設計文書の作成だけ。Push、PR、Merge、GitHub API アクセス、CI Workflow の変更、Git Commit はしていない。GitHub Actions は一度も実行していない（CI 上の結果はすべて **NOT_VERIFIED**）

## 1. Baseline

| 項目 | 確認結果 |
| --- | --- |
| HEAD | `dd6f6295272834175b1eb0eb10ddf23dffc46fed`（承認済み Commit と一致） |
| Branch | `feature/phase1-bounded-remediation` |
| Git Status | Clean（`git status --porcelain --untracked-files=all` 0行。監査前の時点） |
| Remote との関係 | Local の Branch は `origin/feature/phase1-bounded-remediation` より9 Commit 進んでいる（未 Push）。`origin/main`（`a275408`）は HEAD の祖先 |
| §7 の検証済み Commit（Definition の `verified_commits`: `24b7a6e`、`c9c2a9e`、`f00c67f`、`d8c9b53`、`4bd6e01`） | すべて HEAD の祖先（HEAD から 5、4、3、2、1 Commit 前）。**どの Remote Branch にも含まれていない**（`git branch -r --contains` が空）。Push するまで CI からは見えない |
| Repository の大きさ | Pack 1.83 MiB、全 Ref の Commit 67件 |

## 2. 現行 CI の構成（`.github/workflows/ci.yml`、297行）

| 項目 | 内容 |
| --- | --- |
| Trigger | `push`（`main` のみ）、`pull_request`（全 Branch）、`workflow_dispatch` |
| Token Permissions | Workflow 全体で `contents: read`。Job ごとの上書きなし |
| Concurrency | `${{ github.workflow }}-${{ github.ref }}`、`cancel-in-progress: true` |
| Actions | `actions/checkout@3d3c42e…`（v7.0.1）、`actions/setup-python@5fda3b9…`（v7.0.0）。どちらも SHA 固定の First-party |
| Secret の使用 | なし |
| Cache・Artifact | どちらも使っていない（`actions/cache`、`upload-artifact` なし。`setup-python` の `cache` 入力もなし） |
| `pull_request_target` | この Repository の Workflow にはない。Phase 1 の Gate（`pull_request_target`）は `docs/v2/phase1/ci/` の Template で、別の Demo Repository で動く |

| Job | Runner / Python | Checkout | Install | 実行内容 | 区分 |
| --- | --- | --- | --- | --- | --- |
| `test` | ubuntu-latest × 3.9 / 3.11 / 3.13、macos-latest × 3.11 / 3.13、macos-15-intel × 3.9（6組） | 既定（浅い、depth 1） | pip: PyYAML、pytest、pytest-cov、hypothesis（固定）、cfn-lint 1.46.0。cfn-guard は Digest 検証付きで `RUNNER_TEMP` に導入 | `pytest --cov=iacreview --cov=benchmark/harness --cov-fail-under=80`、Benchmark（combined） | Gate |
| `determinism` | ubuntu-latest、3.11 | 既定 | 同上 | `PYTHONHASHSEED=random pytest tests/property/test_prop_determinism.py` | Gate |
| `repository-hygiene` | ubuntu-latest、3.11 | `fetch-depth: 0` | なし（標準ライブラリだけ） | `scan_secrets.py`、`check_ground_truth_order.py` | Gate |
| `lint` | ubuntu-latest、3.11 | 既定 | ruff 0.8.6、mypy 1.14.1 | `ruff check .`、`mypy iacreview` | Advisory（`continue-on-error: true`） |

`tests/unit/test_ci.py`（L75〜L132 の定数、L1116 以降）は `ci.yml` の形を検査する。Gate Job の集合 `GATE_JOBS = (test, determinism, repository-hygiene)` と Advisory の `lint` 以外の Job があると `test_every_job_is_either_a_gate_or_the_advisory_lint_job` が FAIL する。Workflow の Path も `ci.yml` に固定（L75）。

## 3. M1 の Test が CI で SKIP される条件

ローカルで `git clone --depth 1` と `--depth 6`（`file://`、`.agents/` なし、HEAD `dd6f629`）を作り、Evidence Test を実行した。

| Test | 条件 | depth 1 | depth 6 | 作業 Tree（`.agents/` あり） |
| --- | --- | --- | --- | --- |
| `test_evidence_legacy.py::test_every_phase1_source_is_unchanged_since_the_map_was_made` | `.agents/` の Phase 1 Source がない | SKIP | SKIP | PASS |
| `test_evidence_legacy_reeval.py::test_the_committed_results_are_reproduced_byte_for_byte` | 同上 | SKIP | SKIP | PASS |
| `test_evidence_legacy_reeval.py::test_the_phase1_sources_are_unchanged_by_the_reevaluation` | 同上 | SKIP | SKIP | PASS |
| `test_evidence_s7_definition.py::test_every_historical_clause_occurs_once_at_every_verified_commit` | 検証済み Commit が1つも Local にない | SKIP | **PASS** | PASS |
| `test_evidence_preflight.py::test_this_repository_public_set_passes_the_preflight` | `.git` がない | PASS（Clone なので実行） | PASS | PASS |

実測: depth 1 で 474 passed / 4 skipped（24.9秒）、depth 6 で 475 passed / 3 skipped（25.0秒）、ともに exit 0（macOS、Python 3.9.6）。

History 照合 Test の挙動（`registry.git_source_problems`、`git cat-file -e <commit>^{commit}`）:

* 5 Commit のどれもない → SKIP（「NOT VERIFIED」）
* 一部だけある → **FAIL**（`some verified commits are missing locally`）
* すべてある → 条文の Blob と引用を照合

既定の Checkout（depth 1）では SKIP になり、M1-02 の History 照合は CI で検証されない。

全 Test Suite（depth 1 の Clone、`.agents/` なし）の結果は `ci-test-matrix.md` §4。

## 4. Cross-version の確認（ローカル、参考）

同じ合成入力（`test_evidence_pipeline.build` と同じ7 Scenario）の Native Replay を、depth 1 の Clone で2つの Interpreter で実行した。

| Interpreter | 結果の SHA-256 | Bytes | Final Report の SHA-256 |
| --- | --- | --- | --- |
| Python 3.9.6（`/usr/bin/python3`、`PYTHONHASHSEED=random`） | `24f091d1f8be65603a4d5d2cd62052758295155e00be200b59a8ff45238a2a48` | 49,056 | `4b1f2c5441ea9a421bdb0b8d402a608acbf96ced7f128d30f443939746f55b47` |
| Python 3.14.7（PATH の `python3`、PyYAML・pytest なし） | 同じ | 同じ | 同じ |

`iacreview.evidence` は標準ライブラリだけで動き、PyYAML なしで Definition の読み込みと Replay が完了した。Linux と Python 3.11 / 3.13 では未確認（NOT_VERIFIED）。

## 5. 監査で見つかったこと

| ID | 内容 | 影響 |
| --- | --- | --- |
| CI-1 | 検証済み Commit 5件が Remote にない | Push 前は、どの Checkout 方式でも CI で History 照合ができない |
| CI-2 | `test` Job は浅い Checkout で、History 照合 Test は SKIP。Job は exit 0 になる | SKIP が PASS と同じ見た目になる。M1-02 の History 部分を CI で PASS としてはいけない |
| CI-3 | Public Preflight（`.github/scripts/public_preflight.py`）は CI にない | M1-08 / M1-01 の公開安全性は、ローカルの実行だけが根拠 |
| CI-4 | Native Replay の期待 Hash が Repository にない | CI は「同じ Job 内の2回の一致」は検査できるが、「Commit した期待値との一致」と「OS 間の一致」は検査できない |
| CI-5 | Legacy 再評価（`.agents/` 必須）は CI で実行できない | M1-10、M1-12 の Phase 1 部分は CI では NOT_VERIFIED のまま |
| CI-6 | `actions/checkout` の `persist-credentials` は既定（true）。Read-only Token が Job の間 `.git/config` に残る | Test が Git 操作をするため、Token の露出面が Job 内に残る（`ci-security-review.md`） |
| CI-7 | Squash Merge や Rebase Merge では、検証済み Commit が `main` の履歴から消える | Merge 後の `main` で History 照合が SKIP または FAIL になる。過去の PR #7 は Merge Commit で取り込まれている |

## 6. 結論

M1 の大半（合成 Evidence に基づく Test、Mutation、Replay の同一 Job 内一致）は、現行の `test` Job ですでに実行される形になっている。ただし、History 照合、公開安全性、Commit した期待値との Replay 一致、SKIP の扱いは、現行 CI では検証されないか、SKIP が PASS と区別されない。必要な変更は `ci-implementation-plan.md` に示す。
