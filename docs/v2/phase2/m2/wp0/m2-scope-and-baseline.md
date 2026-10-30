# Phase 2 / M2 — Scope、M1 Baseline、Regression 条件、Milestone と Version の方針

* 状態: **WP0 設計 rev1（Human Review 92/100、条件付き承認を受けた修正版）。未実装。** 実装、Commit、Push、Merge、Ruleset 変更はしていない。WP1 の実装は Human 承認まで開始しない
* 作成日: 2026-10-28（作業 Session 内の日付）
* 判定語: PASS / FAILED / NOT_PROVEN。NOT_VERIFIED は「実行・確認していない」の意味で、判定の補足に使う。NOT_PROVEN、NOT_VERIFIED、SKIP、Tool 不在、Timeout を PASS として数えない
* 関連文書（同じ Directory）:
  * `m2-acceptance-test-matrix.md`（M2-01〜M2-12、Test 計画）
  * `m2-schemas.md`（Chain Manifest、Gate Record、Chain Result）
  * `m2-threat-model.md`（Threat Model、Trust Boundary）
  * `passed-all-checks-investigation.md`（`passed_all_checks` と `errors[]`）
  * `github-e2e-plan.md`（1 Scenario の Read-only E2E）
  * `m2-work-plan.md`（WP1〜WP6、M2 用 CI job、CLI の候補比較）
  * `wp0-revision-1.md`（Human Review の指摘と rev0 → rev1 の変更）

## 1. 名称と Scope（Human 承認済み）

正式名称: **Remediation Evidence Chain & Human Gate Traceability**

| 区分 | 内容 |
| --- | --- |
| A. Remediation Evidence Chain | Review Finding → Contract → Base / Head → Remediation Verification Report → GitHub Evidence を、1つの Chain Manifest で参照し、決定論的な Chain Validator が各リンクを再計算して検証する |
| C. Human Gate Record | Contract の承認、候補の Review、Merge の判断を、Git と GitHub の Raw から作る記録として Chain に入れる。Agent の出力と自己申告は記録の出典にしない |
| B. 実 GitHub Read-only E2E | 1 Scenario に限定。読み取り専用の Transport で Raw を取得し、M1 の Store / Integrity と M2 の Chain Validator で検証する |

対象外（Human 決定）:

* 自律修正 Loop（Agent による候補生成・再試行・委譲の Policy）
* Issuer Pinning の独立検証（M1 文書の「P2」、P2-IP-01）
* Merge Enforcement の証明（AC28、Admin bypass、Ruleset 変更）
* Profile の拡張（SC-01 / SC-02 以外）
* Kiro Power の公開

Merge Enforcement は Gate の検証観点 GV-5 として定義だけを置き、M2 では判定しない。M2 のどの出力も Merge Enforcement を証明済みと主張しない（`m2-schemas.md` §2-1、Result の `not_claimed`）。

M2 の追加の非目標（WP0 の提案）:

* AWS への接続、Deploy、Merge の自動実行（製品方針。変更なし）
* GitHub への書き込み（PR 作成、Review、Status、Check、Ruleset、Comment）。E2E でも Agent は書き込まない
* Dependency の追加（Runtime Dependency は PyYAML のみ）
* 既存 Schema の変更（Finding 13 field、Review_Report 7 key、summary 6 key、`passed_all_checks` の意味、StructuredError、Remediation_Verification_Report 0.1.0、Delta_Report）
* `capture_authenticity` を PASS にすること（設計上 NOT_PROVEN のまま）

### 1-1. Human 決定（WP0 Review、2026-10-28 の Session 内で受領）

| ID | 決定 | 本書群への反映 |
| --- | --- | --- |
| D-1 | `iacreview/chain/` を採用。既存 CLI は維持。新 CLI は候補比較の後に判断 | `m2-work-plan.md` §5（候補比較）。新 CLI の採否は未決 |
| D-2 | Schema の語彙を固定。Exit code 31〜34 は既存 Code との衝突確認が必要 | `m2-schemas.md` rev1 を固定版とする。衝突確認は `m2-schemas.md` §3-1 |
| D-3 | Revision 不一致は BROKEN、Evidence 不足は NOT_PROVEN | `m2-schemas.md` §2-2 GV-3、GV-4 |
| D-4 | SC-02 を第一候補。Finding の存在を事前確認。第2 Account は必須ではない | `github-e2e-plan.md` §2、§6 |
| D-5 | M2 専用 CI job を追加し、M1 とは独立させる | `m2-work-plan.md` §4（設計のみ。`ci.yml` の変更は WP の中で Human 承認後） |
| D-6 | Version 方針の Steering 反映は保留 | §6 は本書の記録のまま |
| D-7 | `passed_all_checks` の文書改善案 P-B は承認。既存 Schema・CLI の意味は変えない | `passed-all-checks-investigation.md` §3 |

## 2. Human 提供 Evidence（M1 の Merge）

以下は **Human が提供した Evidence** で、Agent は Network 上で再確認していない。このため「独立検証済み」とは扱わない。

| 項目 | 値（Human 提供） | Agent 側の確認状況 |
| --- | --- | --- |
| PR #8 | Merge 済み | NOT_VERIFIED（作業環境は `github.com` の DNS 解決ができない） |
| Merge Commit | `c1b4d8275bf592f898dc96932a3f6758aaf54911` | NOT_VERIFIED。この Commit は作業環境の Local Repository に存在しない（未 fetch。`git cat-file` で object なし） |
| main CI Run | `40976984724` | NOT_VERIFIED |
| Workflow | SUCCESS | NOT_VERIFIED |
| Required Checks | 9 / 9 PASS | NOT_VERIFIED |
| M1 Evidence Tests | 516 PASS / 3 SKIP | NOT_VERIFIED。ローカルの Evidence Test 数 519 と、Local-only として CI で SKIP する設計の3件に整合する（整合の観察であり、確認ではない） |
| `verified_commits` | 5 | NOT_VERIFIED。ローカルの予測値 5 と整合 |
| Replay / Definition / Evaluator / Report Hash | 期待値一致 | NOT_VERIFIED。期待値は §3 の値 |

Merge 方式が Merge Commit であることは、`verified_commits` 5 と Baseline 照合の成功（Human 提供）から推定できるが、Agent は Commit の親を確認していない（NOT_VERIFIED）。

## 3. M1 の固定 Baseline

M2 はこの Baseline を変更しない前提で設計する。

| 項目 | 値 | 出典 |
| --- | --- | --- |
| M1 Baseline Commit | `dd6f6295272834175b1eb0eb10ddf23dffc46fed` | `tests/fixtures/evidence_replay/expected.json` `baseline_commit` |
| M1 CI 統合 Commit | `d5970b701d2bf722a617764ddb4f3810378936e8` | PR #8 の head |
| `main` 上の M1 | Merge Commit `c1b4d827…`（Human 提供） | §2 |
| Evaluator | `iacreview.evidence.evaluator/1`、Source SHA-256 `ee765e0c18ba76b9d4a27a0d4277548f21296757f03a77879763d1824dae58d6` | `expected.json` |
| Evaluator Source の対象 | `iacreview/evidence/` の `evaluator.py`、`rules_s7.py`、`open_questions.py`、`rule_s7_evidence.py`、`facts.py`、`canonical.py`、`snapshot.py`、`artifact.py` | `evaluator._SOURCES` |
| Definition | `phase1-app-demo-s7` v1、`iacreview/evidence/definitions/phase1-app-demo-s7.v1.json`、SHA-256 `fb4ddef0b86d36e436e4492e1ff2d209812e80b6e993dea47ba07dc7a856b1d0` | `expected.json`（ファイルの実 Hash と一致することを WP0 で確認） |
| 期待値ファイル | `tests/fixtures/evidence_replay/expected.json`、SHA-256 `ebe177bdd64e8ec74d90fab0c44ff4f982e93122109c9df8cfa524166346e841` | WP0 で計算 |
| Native Replay | `24f091d1f8be65603a4d5d2cd62052758295155e00be200b59a8ff45238a2a48` | `expected.json` |
| Final Report | `4b1f2c5441ea9a421bdb0b8d402a608acbf96ced7f128d30f443939746f55b47` | `expected.json` |
| Legacy 再評価結果 | `docs/v2/phase2/m1/wp5/legacy-reevaluation-results.json`、`731a1846ce5bb6102bea478fbc613b85ccb6b3cf90fc736dd62b8bbeaa8e1748` | `expected.json` |
| Verified Commits | `24b7a6e`、`4bd6e01`、`c9c2a9e`、`d8c9b53`、`f00c67f`（Definition の `historical_sources`） | Definition |
| M1 Mutation | 32 Mutant（`tests/mutation/evidence_mutants.py`） | Pre-Commit Remediation |

M1 の判定は M1 Final AC Matrix と Merge Readiness Audit のとおりで、M2 では変更しない。NOT_PROVEN は維持する: 実 GitHub Raw による End-to-End Replay、`capture_authenticity`、第三者による独立再現、M1-10 の歴史的 Raw、S7-17、S7-18、S7-19（Q2 / Q3）、P2-IP-01、G11 の Artifact Integrity と `phase2_result`、G7、Legacy 再評価の S7-01。M2-12（実 GitHub E2E）の結果は M2 の判定であり、M1 の判定を遡って書き換えない。

## 4. 変更禁止の範囲（M2 全体）

| ID | 対象 | 理由 |
| --- | --- | --- |
| F-1 | `iacreview/evidence/` の既存ファイルすべて（Evaluator Source 8件、`replay.py`、`final_report.py`、`envelope.py`、`store.py`、`integrity.py`、`collector.py`、`secretgate.py`、`registry.py`、`rules.py`、`legacy*.py`、`definitions/`、`schema/`、`legacy/`） | Evaluator Source 以外も Native Replay と Final Report の bytes に影響する。M2 は新しい Package への追加だけにする |
| F-2 | `tests/fixtures/evidence_replay/`、`tests/unit/evidence_synth.py`、`tests/mutation/evidence_mutants.py`、既存の `tests/unit/test_evidence_*.py` | M1 の期待値、合成 Spec、Mutant、Test の期待値 |
| F-3 | `docs/v2/phase2/m1/`、`docs/v2/phase1/` | M1 の Frozen Evidence と Phase 1 原本（`docs/v2/phase1/` の変更は CI で exit 18） |
| F-4 | `.github/scripts/evidence_ci_check.py`、`ci.yml` の `evidence-integrity` job | M1 の Gate。M2 の CI は別 job（D-5）とし、`ci.yml` への追加は Human 承認後（`development-workflow.md`） |
| F-5 | `iacreview/remediation/` の既存ファイル、`iacreview/remediation/profiles/` | Phase 1 Verifier の挙動と53 Case。M2 は Report を読むだけ |
| F-6 | `iacreview/report.py`、`finding.py`、`errors.py`、`exitcodes.py`、`deltareport.py`、`reportcheck.py`、既存5 Skill と `skills/iac-remediation-verify/` | 互換性の不変条件（`quality-gates.md`） |
| F-7 | `pyproject.toml`、`plugin.json`、`.gitignore` | 変更には Human 承認が必要。M2 では変更しない計画 |

M2 の新規 Code は `iacreview/chain/`（新 Package、D-1 で採用）に置く。

## 5. Regression 条件（全 WP の完了条件に含める）

| ID | 条件 | 観測方法 | PASS |
| --- | --- | --- | --- |
| RG-1 | M1 の期待値が不変 | `python3 .github/scripts/evidence_ci_check.py --junit <xml> --expected tests/fixtures/evidence_replay/expected.json`（CI の `evidence-integrity` と同じ手順。Full Clone） | exit 0。native / final report / legacy の Hash が §3 と一致 |
| RG-2 | 変更禁止範囲が無変更 | `git diff --name-only dd6f6295272834175b1eb0eb10ddf23dffc46fed HEAD -- <F-1〜F-7 の Path>` に対し、M1 Baseline 後に Human 承認済みの変更（`d5970b7` の CI 統合）以外が出ないこと | M2 の Commit 由来の Path が0件 |
| RG-3 | M1 Evidence Test | `python3 -m pytest -p no:cacheprovider tests/unit/test_evidence_*.py` | FAIL 0。SKIP は Local-only の3件のみ（CI。`evidence_ci_check.py` `LOCAL_ONLY`）、`.agents/` のあるローカルでは0件 |
| RG-4 | M1 Mutation | `tests/unit/test_evidence_mutations.py`（Mutant 定義は `tests/mutation/evidence_mutants.py`） | 32 / 32 検出 |
| RG-5 | Phase 1 | `benchmark/remediation/cases.json` の53 Case と Phase 1 の Test | 判定がすべて不変 |
| RG-6 | v1.x 互換 | 全体 pytest + coverage ≥ 80%、Benchmark 34/34、Determinism、Secret scan、Ground_Truth 順序、19 Frozen Reports | `quality-gates.md` の CI Gate すべて PASS |
| RG-7 | Advisory Lint | `ruff check .`（ruff 0.8.6）、`mypy iacreview --no-site-packages`（mypy 1.14.1、`python_version = "3.9"`） | ruff 40 件以下、mypy 12 件以下。新規ファイルは0件 |
| RG-8 | Dependency | `pyproject.toml` の差分 | なし |
| RG-9 | Public Safety | `python3 .github/scripts/public_preflight.py` | exit 0 |

RG-1 は Full Clone（`fetch-depth: 0` 相当）で実行する。浅い Clone では exit 13 になり、これは PASS ではない。

M1 との非干渉の仕組み（Package の分離、Import の向き、期待値ファイルと CI job の分離、M1 の CI 判定への影響）は `m2-threat-model.md` §7 にまとめた。

## 6. Phase 2 Milestone と Release Version の独立管理

方針（WP0 の提案。`product.md` と `structure.md` の更新は Steering 変更のため、別途 Human 承認が必要）:

1. **Milestone は作業と検証の単位、Version は利用者に向けた公開の単位**とし、1対1に対応させない。M1、M2 の完了は、Version の Release を意味しない
2. Version は Release 時に、その時点の公開変更から SemVer で決める
   * 既存 Schema・CLI・exit code の非互換変更 → MAJOR（M2 では行わない）
   * 新しい Package、CLI、Schema の追加 → MINOR
   * 修正のみ → PATCH
3. 現在の公開 Version は `v1.1.0`（tag、`plugin.json` `1.1.0`）。Phase 1、M1、M2 の変更は `CHANGELOG.md` の `[Unreleased]` に記録し、Version 番号を付けない
4. `product.md` と `environment-architecture.md` 6-1 の v1.2〜v1.5 の割当は「仮定」と明記されている。Phase 2 の Milestone はこの割当に縛られない。Release を作るときに、含めた Milestone と Version の対応表を CHANGELOG に記録する
5. Milestone の識別子（M1-01、M2-01 など）を Version 番号、Tag、`plugin.json` に使わない
6. Release の判断、Tag、`plugin.json` の Version 変更は Human が行う（`quality-gates.md` Release Gate）

記録場所: 本書（§6）。Steering への反映は保留（D-6）。
