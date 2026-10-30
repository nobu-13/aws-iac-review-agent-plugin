# Phase 2 M1 — Pre-Commit Acceptance Audit

> **Pre-Commit Remediation の注記（後から追加）**: 本書は Remediation の前の監査記録である。C-1〜C-3 の適用結果、最終の Hash、Commit 候補の一覧は `remediation-report.md` を参照する。

* Source: Pre-Commit 監査の指示（監査対象 1〜8）、WP0〜WP5 の成果物、Final Frozen Quality Gate attempt 4 の記録（`.agents/tasks/phase2-m1-wp5/frozen-gate-attempt4/`、Git 管理外）
* 目的: Git Commit の前に、公開安全性と Evidence Integrity を監査する
* 状態: 監査のみ。コード、Test、Definition、既存文書は変更していない。Git Add、Commit、Push、GitHub API アクセス、CI 変更、Dependency 追加なし。HEAD `4bd6e015d88b01d34dc83dc2b2d2ffb0058358b2`

## 1. 監査対象と結果の場所

| # | 監査対象 | 結果 | 詳細 |
| --- | --- | --- | --- |
| 1 | 703 / 706 / 711 の集合差 | 差は WP5 文書8件だけ（固定時に存在した3件、Gate 後に作った5件）。固定範囲は監査時点でも `360d731b…18aec5` で不変 | `publication-file-manifest.md` §1 |
| 2 | Commit 候補の列挙と禁止物の確認 | 候補は `.gitignore` の変更1件と新規78件（＋本監査の文書5件）。`.agents/`、`.kiro/`、Targets、PEM、Token、実 Raw、ログ、ネストした `.git` は 0件。Secret ではないが Human 判断の要る識別子が3種（PC-1〜PC-3） | `publication-file-manifest.md` §2〜§3 |
| 3 | S7-19 の I-1〜I-6 | I-2〜I-6 は原文から正当。I-1（FAILED を返さない）は原文からは正当だが、Definition v1 の `expected_result.violated = FAILED` と矛盾（S7-17、S7-18 も同じ） | `s7-19-interpretation-review.md` |
| 4 | S7-01 と Final Report、実装数と実評価数 | S7-01 は Final Report にも Evaluation 結果にも含まれず、別 Report としての参照もない | 本書 §2 |
| 5 | WP4 / WP5 の結果ファイル | WP4 の結果は現在の Source で再現できない。WP5 の結果は再現できる | `definition-versioning-policy.md` §1-1 |
| 6 | Definition v1 の変更履歴と Version 規則 | WP4 → WP5 の差は1か所だけと実測で確認。WP1〜WP3 の bytes は NOT_PROVEN。規則 D-1〜D-6、E-1〜E-3、R-1〜R-3 を提案 | `definition-versioning-policy.md` |
| 7 | 未検証経路、SKIP、CI | 本書 §3 | 本書 §3 |
| 8 | Commit の可否 | **PARTIAL**（条件付き） | `precommit-decision.md` |

## 2. S7-01 と Final Report（監査対象 4）

### 2-1. 確認した事実

* `evaluator.applicable()` は S7-01 を返さない。Native Replay の結果に S7-01 の判定はない。合成 Pipeline の結果（`test_evidence_pipeline.build` と同じ入力）で実測すると、Scenario の Criterion は22種、S7-18 は `limits`、S7-19 は `open_questions`、S7-02 は各 Scenario の `s7_result`（`s7_compose_rule: s7.compose.all_parts`）に表れ、`S7-01` という文字列は結果の bytes にも Final Report にも現れない
* `evaluator.py`、`final_report.py`、`replay.py`、`legacy_reeval.py` のどれも `rule_s7_evidence`（S7-01 の Rule）を呼ばない（`grep` で0件）
* S7-01 の Rule は `iacreview/evidence/rule_s7_evidence.py` にあり、Store に対して単独で実行する。Test は `tests/unit/test_evidence_store.py::test_s7_evidence_raw_api_data_stored`
* WP5 の文書は「S7-01 は Evaluator の出力に入らない」と記述している（`wp5-acceptance-report.md` §3-4）。ただし Final Report から S7-01 の結果を参照する仕組みはない
* Legacy 再評価には Store がないため S7-01 を評価できない。結果は `capture_integrity.status = NOT_PROVEN` を持つが、S7-01 を名指ししていない

### 2-2. 実装数と実評価数

| 数え方 | 件数 | 対象 |
| --- | --- | --- |
| Rule が IMPLEMENTED の Criterion | 26 / 26 | Catalog 24 Rule（S6-G3 / G3S / G6 が1 Rule を共有） |
| rule_behaviour Test が IMPLEMENTED の Criterion | 26 / 26 | Definition v1 |
| Evaluator の結果に判定が出る Criterion | 25 / 26 | Scenario の22種 + S7-02（合成として）+ S7-18（`limits`）+ S7-19（`open_questions`）。S7-01 は出ない |
| 合成 Raw の Native Replay で Scenario ごとに判定した Criterion | 22 | `test_evidence_pipeline.build` の入力（G0、G1、G2、G3、G3S、G6、G11） |
| PASS に到達しうる Criterion | 23 / 26 | S7-17、S7-18 は常に NOT_PROVEN、S7-19 は現在の Evidence Role では PASS にならない |
| 実 GitHub Raw で評価した Criterion | 0 | 実 Raw の取得なし |

判定: S7-01 は「Rule と Test は実装済み、Final Report には含まれず参照もない」。Final Report だけを読む Reviewer は S7-01 の状態を知ることができない。

## 3. 未検証の経路、SKIP、CI（監査対象 7）

### 3-1. `legacy_reeval.py`

Line coverage 54%（39 statements 中 miss 18。Miss は L50〜L66、L70。Gate 1 と、本監査で `test_evidence_legacy_reeval.py`・`test_evidence_mutations.py` だけを計測した結果が同じ）。

| 経路 | Test | 実行の記録 |
| --- | --- | --- |
| `run()` | `.agents/` のある環境の Test 2件だけ（Clean Copy と CI では Skip） | Gate 1、Gate 10 |
| `main()` の引数処理と正常書き込み（exit 0） | なし | WP4 と WP5 で手で実行し、結果ファイルを作った（Test ではない） |
| `main()` の上書き拒否（`O_EXCL`、exit 2） | なし | WP4 と WP5 で手で1回ずつ観測（Test ではない） |
| `main()` の拒否（`LegacyDrift` / `OSError` / `ValueError`、exit 3） | なし | 一度も実行していない（**NOT_VERIFIED**） |
| `if __name__ == "__main__"` | なし | 手で実行した（Test ではない） |

### 3-2. Clean Checkout の SKIP（5件、PASS に数えない）

| Test | 理由（Skip のメッセージ） |
| --- | --- |
| `tests/unit/test_evidence_legacy.py::test_every_phase1_source_is_unchanged_since_the_map_was_made` | NOT VERIFIED: the private Phase 1 sources are not in this checkout |
| `tests/unit/test_evidence_legacy_reeval.py::test_the_committed_results_are_reproduced_byte_for_byte` | 同上 |
| `tests/unit/test_evidence_legacy_reeval.py::test_the_phase1_sources_are_unchanged_by_the_reevaluation` | 同上 |
| `tests/unit/test_evidence_preflight.py::test_this_repository_public_set_passes_the_preflight` | NOT VERIFIED: not a git checkout |
| `tests/unit/test_evidence_s7_definition.py::test_every_historical_clause_occurs_once_at_every_verified_commit` | NOT VERIFIED: the verified commits are not in this (shallow) clone; the worktree test still ran |

5件とも、作業 Tree（`.agents/` と git 履歴がある環境）の Gate 1 / Gate 2 では Skip されずに PASS した。Clean Copy の環境では未検証のまま。

### 3-3. CI で未検証のもの

`.github/workflows/ci.yml` は変更していないため、Commit 後の CI で次のことが起きる見込み（CI は実行していない）。

| 項目 | 見込み | 根拠 |
| --- | --- | --- |
| History 照合（`test_every_historical_clause_occurs_once_at_every_verified_commit`） | `test` Job の Checkout は既定の浅い Clone（`fetch-depth` 指定なし、ci.yml L96）のため Skip。`fetch-depth: 0` の `repository-hygiene` Job（L210〜L216）は pytest を実行しない | ci.yml |
| Phase 1 の非公開 Evidence を使う Test 3件 | `.agents/` がないため Skip | Skip 条件 `HAVE_PHASE1` |
| Public Preflight（`public_preflight.py`） | CI の Step にない。ローカルの Gate だけ | ci.yml に記述なし |
| Python 3.11 / 3.13、ubuntu / macOS arm64 での Evidence Test | 未実行。ローカルは macOS と Python 3.9.6 だけ | — |
| Mutation Test（pytest 内で Harness を実行） | CI でも実行される。一時 Directory に `iacreview/` を複写するため、実行時間とディスクの使用が増える。実測なし | — |

CI の History 照合を有効にするには CI の変更（`fetch-depth: 0` など）が必要で、本監査の範囲外（Human 判断）。

## 4. 本監査で新たに見つかったこと

| ID | 内容 | 重さ | 文書 |
| --- | --- | --- | --- |
| F-1 | 実在の GitHub App id が Test（`test_evidence_secretgate.py` L163）と WP0 文書にある。WP5 の「合成」の説明と、Clean Checkout の検索（App id を検索語に入れていなかった）に漏れがあった | 中（Secret ではない） | `publication-file-manifest.md` PC-2 |
| F-2 | GitHub Account 名が WP0 文書2件にある（WP0 自身が PII 相当と分類） | 中 | PC-1 |
| F-3 | S7-17、S7-18、S7-19 の `expected_result.violated = FAILED` に Rule が到達しない。Registry はこれを検査しない | 中 | `s7-19-interpretation-review.md` §3 |
| F-4 | S7-01 が Final Report に含まれず、参照もない | 低〜中 | 本書 §2 |
| F-5 | `EVALUATOR_VERSION` が Source の変更後も `…/1` のまま | 低 | `definition-versioning-policy.md` §2 |
| F-6 | S7-19 の状態の一部（Q1 の S7-09 反例、Q2 の2経路、Q4 の `RUN_UNSETTLED`）に Assertion がない | 低 | `s7-19-interpretation-review.md` §5 |
| F-7 | `legacy_reeval.main()` に Test がなく、exit 3 の経路は一度も実行していない | 低 | 本書 §3-1 |

## 5. 監査で実行した Command（すべて読み取り）

* `git ls-files -co --exclude-standard`、`git ls-files -o --exclude-standard`、`git ls-files -m`、`git diff .gitignore`、`git status --porcelain --untracked-files=all`、`git ls-files .agents .kiro`
* 固定 Manifest の再計算（`shasum -a 256`、`docs/v2/phase2/m1/wp5/*.md` と `docs/v2/phase2/m1/precommit/` を除外）→ `360d731b5b10a30e231bbf01ae76b50055698c7ab9bf15d934ec042bba18aec5`
* 候補78件への内容検索（Account 名、Home Path、Demo Repository 名、Run id、App id、Token の形、PEM、email）。App id の値は出力に表示しなかった
* 合成 Pipeline の Replay（一時 Directory、終了後に削除）と、`legacy_reeval` の coverage 計測（`COVERAGE_FILE` は `/tmp`、終了後に削除）
* Definition の S7-19 の Test 状態を WP4 の値に戻した bytes の SHA-256 計算（メモリ上だけ。ファイルは変更していない）
