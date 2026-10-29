# Phase 2 M1 — CI Implementation Plan

* Source: `ci-readiness-audit.md`、`ci-test-matrix.md`、`ci-security-review.md`、`.github/workflows/ci.yml`、`tests/unit/test_ci.py`
* 目的: M1 Baseline（`dd6f6295272834175b1eb0eb10ddf23dffc46fed`）を GitHub Actions で独立に再現するための変更を、実装の前に固定する
* 状態: **計画のみ**。Workflow、Script、Test、Fixture はどれも作成・変更していない。実装、Commit、Push には Human 承認が必要

## 1. 方針

1. 既存の Gate（`test`、`determinism`、`repository-hygiene`）と Advisory の `lint` は、意味を変えない
2. M1 専用の Gate Job `evidence-integrity` を `ci.yml` に1つ追加する。別 Workflow ファイルは作らない（`test_ci.py` の検査対象に入れるため）
3. Public Preflight を `repository-hygiene` に1 Step 追加する
4. Native Replay の期待 Hash を Repository に Commit し、CI の各 Job が同じ値になることを照合する（Artifact は使わない）
5. SKIP を PASS にしない。CI で必ず実行する Test が SKIP されたら Job を FAILED にし、`.agents/` を必要とする Test の SKIP は AC の NOT_VERIFIED（CI）として Summary に出す

## 2. 想定する変更ファイル

| ファイル | 種別 | 内容 |
| --- | --- | --- |
| `.github/workflows/ci.yml` | 変更 | Job `evidence-integrity` の追加、`repository-hygiene` に Preflight の Step を追加 |
| `tests/unit/test_ci.py` | 変更（既存 Test の期待値） | `GATE_JOBS` に `evidence-integrity` を追加。新 Job の `fetch-depth: 0`、`persist-credentials: false`、Secret 不使用、Preflight Step の存在を検査する Test を追加 |
| `.github/scripts/evidence_ci_check.py` | 新規 | §4 の検査。標準ライブラリだけ |
| `tests/fixtures/evidence_replay/expected.json` | 新規 | Native Replay の期待値（§4-2） |
| `tests/unit/test_evidence_ci_check.py` | 新規 | Check Script の Test（SKIP の扱い、Hash 不一致、Binding の拒否） |
| `docs/v2/phase2/m1/ci-readiness/` | 追記 | 実行後の結果（CI の Run を確認してから） |

変更しないもの: Phase 1 の原本・Helper・Evidence・Test、`iacreview/evidence/` の Source、Definition v1、`pyproject.toml`、Dependency、Branch Protection / Ruleset の設定。

## 3. Job の設計（記述例。まだ適用しない）

```yaml
  evidence-integrity:
    # M1 Evidence Integrity Foundation: synthetic evidence only, no secret, no network call by the tests.
    name: evidence integrity (M1)
    runs-on: ubuntu-latest
    timeout-minutes: 20
    steps:
      - name: Check out the repository with full history
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          fetch-depth: 0             # verified commits of the §7 Definition (ci-test-matrix.md §6)
          persist-credentials: false # nothing here pushes or fetches after checkout
      - name: Set up Python
        uses: actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97 # v7.0.0
        with:
          python-version: "3.11"
      - name: Install pytest
        run: |
          python3 -m pip install "${PYTEST_SPEC}"
      - name: Run the evidence tests
        run: |
          python3 -m pytest -p no:cacheprovider -rs \
            --junitxml="${RUNNER_TEMP}/evidence-junit.xml" \
            tests/unit/test_evidence_*.py
      - name: Check skips, replay hashes and the commit binding
        run: |
          python3 .github/scripts/evidence_ci_check.py \
            --junit "${RUNNER_TEMP}/evidence-junit.xml" \
            --expected tests/fixtures/evidence_replay/expected.json \
            --commit "${GITHUB_SHA}"
```

`repository-hygiene` への追加:

```yaml
      - name: Run the public-safety preflight
        run: |
          python3 .github/scripts/public_preflight.py
```

注意: `pull_request` の Run では `GITHUB_SHA` は PR の Merge Commit（`refs/pull/<n>/merge`）を指す。Summary には `GITHUB_SHA` と、PR の Head（`github.event.pull_request.head.sha`、環境変数で渡す）の両方を記録する。

## 4. `evidence_ci_check.py` の検査

### 4-1. SKIP の分類（JUnit XML を読む）

| 分類 | 対象 | 扱い |
| --- | --- | --- |
| 必須 | `ci-test-matrix.md` §5 の Test | SKIP なら exit 1（Job FAILED）。理由を Summary に書く |
| 想定内の SKIP | `.agents/` を必要とする3件 | Job は失敗させない。M1-10、M1-12 の該当部分を NOT_VERIFIED（CI）と表示 |
| 失敗 | failure / error | pytest の Step がすでに失敗する。Check Script も FAILED と表示 |

Test 名の一覧は Script の中に固定し、`tests/unit/test_evidence_ci_check.py` で「Evidence Test に存在する名前だけを挙げていること」を検査する。

### 4-2. Replay の期待値と Binding

`tests/fixtures/evidence_replay/expected.json`（計画）の内容:

```json
{
  "baseline_commit": "dd6f6295272834175b1eb0eb10ddf23dffc46fed",
  "evaluator_version": "iacreview.evidence.evaluator/1",
  "evaluator_source_sha256": "ee765e0c18ba76b9d4a27a0d4277548f21296757f03a77879763d1824dae58d6",
  "definition_version": 1,
  "definition_sha256": "fb4ddef0b86d36e436e4492e1ff2d209812e80b6e993dea47ba07dc7a856b1d0",
  "native_result_sha256": "24f091d1f8be65603a4d5d2cd62052758295155e00be200b59a8ff45238a2a48",
  "final_report_sha256": "4b1f2c5441ea9a421bdb0b8d402a608acbf96ced7f128d30f443939746f55b47",
  "legacy_result_sha256": "731a1846ce5bb6102bea478fbc613b85ccb6b3cf90fc736dd62b8bbeaa8e1748"
}
```

値はローカルの実測（Pre-Commit Remediation の Final Quality Gate と、初回 Commit 前の再検証。Python 3.9.6 と 3.14.7 で同じ）。Linux と Python 3.11 / 3.13 での値は CI の実行で初めて確認する。

検査の順序（最初の不一致で止める）:

1. 現在の `evaluator_source_sha256()` と Definition の SHA-256 が期待値と一致する。違えば `SOURCE_CHANGED` / `DEFINITION_CHANGED` として FAILED（期待値ファイルの更新漏れ。Version Policy §4 の規則に従って更新する）
2. 合成 Spec（`test_evidence_pipeline.build` と同じ7 Scenario）を一時 Directory に作り、同じ Process で2回、`PYTHONHASHSEED=random` の別 Process で2回 Replay する。4回とも `native_result_sha256` と一致する
3. Final Report の SHA-256 が `final_report_sha256` と一致する
4. Commit された `docs/v2/phase2/m1/wp5/legacy-reevaluation-results.json` の SHA-256 が `legacy_result_sha256` と一致し、中の `evaluator.source_sha256` と `definition.definition_sha256` が 1. の値と一致する（再生成は `.agents/` が必要なため行わない。Header の整合だけ）
5. Summary（`GITHUB_STEP_SUMMARY`）に、`GITHUB_SHA`、PR Head、Python の Version、OS、上記 Hash、AC ごとの CI 判定（PASS / FAILED / NOT_VERIFIED（CI） / NOT_PROVEN）を書く

Matrix の6組でも同じ Script の 2.〜3. を実行すれば、OS と Python Version の間で bytes が一致することを Artifact なしで確かめられる。`test` Job に Step を1つ追加するか、Evidence Job を Matrix にするかは、実行時間を見て決める（§6）。

### 4-3. 判定の出力（例）

| AC | CI 判定 | 根拠 |
| --- | --- | --- |
| M1-02 | PASS | History 照合が実行され PASS（SKIP なし） |
| M1-05 | PASS（合成） | 4回の Replay が期待 Hash と一致 |
| M1-10（現物照合） | NOT_VERIFIED（CI） | `.agents/` がない（想定内の SKIP） |
| M1-10（歴史的 Raw） | NOT_PROVEN | CI の結果によらない |

## 5. 実施の手順（承認後）

1. 本計画の承認（Human）
2. 実装: §2 の新規ファイル3件と変更2件。ローカルで `tests/unit/test_ci.py`、新しい Test、Evidence Test を実行
3. ローカルの浅い Clone（depth 1）と完全な Clone で、Check Script が想定どおり FAILED / PASS / NOT_VERIFIED を出すことを確認
4. Commit（Human 承認）
5. Push（Human 承認）。検証済み Commit 5件が初めて Remote に入る
6. PR の作成（Human 承認）と、CI の結果の確認。Summary の Hash を期待値と照合
7. Merge 方式の決定（Human）。Squash / Rebase を使う場合は、`main` での History 照合が成立しなくなる（`ci-test-matrix.md` §6）

## 6. 実行時間の見込み

GitHub Actions での実測はない（過去の Run の所要時間も、API を使わない制約のため取得していない）。以下はローカルの実測からの見込みで、**NOT_VERIFIED**。

| 対象 | ローカルの実測 | CI での見込み | 根拠 |
| --- | --- | --- | --- |
| Evidence Test（478件） | 24.9〜25.0秒（浅い Clone、macOS、Python 3.9.6） | 30〜60秒 | GitHub-hosted の Linux Runner は CPU が少ないことがある。Mutation Test（約20秒）と Pipeline の子 Process を含む |
| Check Script の Replay（4回） | 約7秒（Gate 10 の実測） | 10〜20秒 | 同上 |
| Checkout（`fetch-depth: 0`）、Python の準備、pytest の導入 | 未測定 | 30〜90秒 | Pack 1.83 MiB。pip は1 Package |
| `evidence-integrity` Job の合計 | — | 約2〜4分 | 上の合計 |
| `repository-hygiene` への Preflight の追加 | 約9秒（Gate 8） | 10〜20秒の増加 | `git ls-files` と Secret 規則の走査 |
| `test` Matrix の各 Job | 全 Suite 726秒（浅い Clone）。うち Evidence Test は約25秒 | M1 の Test は Push 後に既に各 Job で実行される（追加の Step なしでも）。Replay の Step を足すなら各 Job 10〜20秒の増加 | M1 の Test は `tests/unit/` にあるため |

Workflow 全体の所要時間は、6組の Matrix のうち最も遅い Job（全 Suite、ローカルで約12分）が決める。Evidence Job は並行して動くため、全体の時間はほぼ増えない見込み。

## 7. Human 承認が必要な操作

| 操作 | 理由 |
| --- | --- |
| 本計画の採用 | CI の変更 |
| `.github/workflows/ci.yml` の変更 | CI の変更（`development-workflow.md`） |
| `tests/unit/test_ci.py` の期待値変更（`GATE_JOBS`） | 既存 Test の期待値の変更 |
| 新規の Script・Fixture・Test の追加と Commit | Commit |
| Push、PR の作成、Merge | Human Gate |
| Merge 方式（Merge Commit / Squash / Rebase） | `main` での History 照合に影響 |
| Required Check と Review の設定（Branch Protection / Ruleset） | Repository 設定。CI からは変更しない（`ci-security-review.md` S-2） |
| 既存 Job への `persist-credentials: false` の追加（任意） | 既存 Gate の変更 |
| Dependency の Hash 固定（任意） | Dependency 管理の変更 |
