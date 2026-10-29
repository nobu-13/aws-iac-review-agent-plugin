# Phase 2 / M1 / WP1 — Acceptance Report

* Source: WP1 指示（§8 WP1 Acceptance Criteria）、`docs/v2/phase2/m1/wp0/m1-acceptance-test-matrix.md`（M1-01、M1-02）
* 目的: WP1 の各 Acceptance 条件を、実行した Command と結果で判定する
* 状態: 2026-10-28 から 10-29 にかけて実施。**Git Commit なし**（HEAD `4bd6e015d88b01d34dc83dc2b2d2ffb0058358b2` のまま）。Human レビュー待ち

判定語は PASS / FAILED / NOT_PROVEN。実行していない検証を PASS と書かない。

## 1. 判定

| 条件 | 判定 | 根拠 |
| --- | --- | --- |
| M1-01: 対象ソースが Git 管理可能な構成になっている | 構成: **PASS**。Git 管理の完了: **NOT_PROVEN** | 新規ファイルは公開候補で、Preflight PASS（§3）。`.agents/` は ignore され、公開対象は Plugin Code・Schema・Test・合成 Fixture・文書だけ。Commit は Human 承認後のため未実施 |
| M1-02: §7 条文の対応表が100%で、未実装の Rule / Test が明示されている | **PASS** | §7 全文が Criterion と非規範テキストで覆われることを機械的に検査（`test_every_historical_clause_occurs_once_in_the_worktree_section`、5 commit で `…_at_every_verified_commit`）。26 Criterion → 24 Rule。全 Rule が `PLANNED`、全 `rule_behaviour` Test が `PLANNED`（`test_every_s7_clause_maps_to_one_catalog_rule_and_a_planned_rule_test`） |
| G3 / G3S / G6 の Historical Classification を改変できない | **PASS**（Registry の範囲で） | `test_09_*`（12件）、`test_09b_*`（3件）、`test_09c_*`（6件）、`test_g3_g3s_g6_historical_classification_is_locked`。JSON と `registry.PHASE1_LOCKED` を同時に書き換える変更は Code Review で防ぐ範囲（Architecture Note §3-5） |
| Definition の不正入力を検出できる | **PASS** | §2 の10ケースと追加ケース、すべて拒否 |
| 公開対象に機密ファイルが含まれない | **PASS**（規則の範囲で） | Preflight の8 Check がすべて PASS、649 ファイルを走査（本 Report を含む最終実行）。0件は不存在の証明ではない |
| Phase 1 の Helper と旧 Test に変更がない | **PASS** | §4 |
| 新規 Test が PASS する | **PASS** | 131 passed / 0 failed / 0 skipped |

## 2. Definition Validation（WP1-4 の10ケース）

すべて `tests/unit/test_evidence_registry.py`。

| # | ケース | Test | 結果 |
| --- | --- | --- | --- |
| 1 | 重複 AC ID | `test_01_duplicate_ac_id_is_refused` | 拒否 |
| 2 | 重複 Criterion ID | `test_02_duplicate_criterion_id_is_refused` | 拒否 |
| 3 | 存在しない Evaluator Rule | `test_03_unknown_evaluator_rule_is_refused` | 拒否 |
| 4 | 存在しない Test | `test_04_*`、`test_04b_*`（`IMPLEMENTED` なのに存在しない）、`test_04c_*`（`PLANNED` なのに存在する） | 拒否 |
| 5 | Required Evidence 未定義 | `test_05_*`（空、未知、重複）、`test_05b_*`（field なし） | 拒否 |
| 6 | 不明な Status | `test_06_*`（expected、historical、test status / kind の6通り） | 拒否 |
| 7 | Source Commit SHA の形式異常 | `test_07_*`（短縮、大文字、非 hex、null、数値）、`test_07b_*`（verified 外）、`test_07c_*`（判定記録が Commit を名乗る） | 拒否 |
| 8 | Definition Version の不一致 | `test_08_*`（Index と不一致、File 名と不一致、文字列、bool）、`test_08b_*`（未知 ID） | 拒否 |
| 9 | G3 / G3S / G6 の Historical Classification の改変 | `test_09_*`、`test_09b_*`、`test_09c_*` | 拒否 |
| 10 | Criterion と Rule の対応の欠落 | `test_10_*`（Rule に Criterion がない）、`test_10b_*`（Criterion に Rule がない）、`test_10c_*`（rule_behaviour Test がない）、`test_10d_*`（必須軸がない）、`test_10e_*`（1 Rule が2軸） | 拒否 |

ほかに、未知 field（6か所）、厳格でない JSON（重複 key、NaN、非 UTF-8、途切れ）、1 MiB 超、非 object、`historical_text` の出典が判定記録、Phase 2 の Criterion が Phase 1 の条文を名乗る、Phase 1 Helper を public とする、の各ケースを拒否する。

## 3. 実行した Command と結果

| Command | Exit | 結果 | 所要 |
| --- | --- | --- | --- |
| `PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 -m pytest -q -p no:cacheprovider tests/unit/test_evidence_registry.py tests/unit/test_evidence_s7_definition.py tests/unit/test_evidence_preflight.py` | 0 | 131 passed（registry 85、s7_definition 10、preflight 36）、0 failed、0 skipped | 4秒 |
| 全体 `pytest --cov=iacreview --cov=benchmark/harness --cov-fail-under=80`（`-p no:cacheprovider`、Coverage と Hypothesis の DB は `/tmp` に出力） | 0 | 7,359 件中 FAIL 0 / SKIP 36、coverage 96.37% | 673秒 |
| `python3 benchmark/harness/run_benchmark.py --cases benchmark/cases --mode combined` | 0 | status PASS、34 matched | — |
| `PYTHONHASHSEED=random pytest tests/property/test_prop_determinism.py` | 0 | PASS | — |
| `python3 .github/scripts/scan_secrets.py` | 0 | 0 finding、633 ファイル（tracked mode） | — |
| `python3 .github/scripts/check_ground_truth_order.py --cases benchmark/cases` | 0 | 17/17 | — |
| `python3 .github/scripts/public_preflight.py`（`.gitignore` 変更前） | 1 | FAILED: `agents_ignored`、`public_candidates`（`.agents/` 318件）、`secret_scan`（55件、すべて `.agents/` 内） | — |
| 同（変更後、最終） | 0 | PASS: 8 Check すべて PASS、649 ファイル（追跡＋未追跡、本 Report 作成後） | — |
| `ruff check --no-cache iacreview/evidence .github/scripts/public_preflight.py tests/unit/test_evidence_*.py` | 0 | All checks passed | — |
| `mypy iacreview/evidence .github/scripts/public_preflight.py`（cache は `/tmp`） | 0 | no issues | — |
| Phase 1 Helper Test（`.agents/tasks/phase1/henv`、`test_phase1_*.py`、cache なし） | 0 | 516 passed / 0 failed / 0 skipped | 76秒 |

* 途中の全体 pytest で `tests/unit/test_docs.py::test_no_runtime_file_reads_the_kiro_directory` が1件 FAIL した。原因は、当初の配置 `iacreview/evidence/preflight.py` に `.kiro/` の文字列があったこと。既存 Test は変更せず、Preflight を `.github/scripts/public_preflight.py` に移した（Architecture Note §2）。移動後の全体 pytest は FAIL 0。
* `quality-gates.md` の Baseline（commit `5e5ed36`）にあった既知 FAIL 2件（`test_root_docs.py`）は、今回の実行では発生しなかった。原因は WP1 の範囲外で、調べていない。
* CI 上での実行は **NOT VERIFIED**（Push していない）。CI の test job は shallow checkout なので、`test_every_historical_clause_occurs_once_at_every_verified_commit` は CI では skip（NOT VERIFIED）になる見込み。ローカルでは5 commit すべてで実行し PASS。

## 4. Phase 1 の非変更

* WP0 で記録した SHA-256 と一致（`shasum -a 256 -c`、18ファイルすべて OK）: Helper 3本、E18、E22、E24、E28、E29、E30、rev2 の5ファイル、rev3 の4ファイル
* Helper Test 14本: rev3 `phase2-handoff.md` より後に更新されたものはない（`find -newer`）
* `docs/v2/phase1/app-demo-plan.md`（`fbc6dcc4…`）、`docs/v2/phase1/ac-traceability.json`（`b6df66bd…`）、`.github/scripts/scan_secrets.py`: 変更なし
* Phase 1 の判定（FAILED / PARTIAL / NOT_PROVEN）はどこも変更していない。Definition は rev2 / rev3 の値を引用し、Validator がそれ以外の値を拒否する

## 5. Secret Scan の範囲

| Scanner | 対象 | 結果 |
| --- | --- | --- |
| `scan_secrets.py`（既存、未変更） | 追跡ファイル 633件 | 0 finding |
| `public_preflight.py`（新規） | `git ls-files --cached --others --exclude-standard` の649件（追跡＋ignore されない未追跡。WP0 / WP1 の新規ファイルを含む）。Binary は印字可能部分を走査 | 0 match |
| 対象外 | `.agents/`（ignore 済み、非公開）、`.kiro/`、`.gitignore` で除外された cache 等 | 走査していない |

規則は `scan_secrets.py` の7規則。0件は、規則に一致するものがなかったことだけを示す。

## 6. 未実装・NOT_PROVEN

* M1-01 の Git 管理完了: NOT_PROVEN（Commit は Human 承認待ち）
* Evaluator Rule 24件: すべて PLANNED（WP2: 1、WP3: 2、WP4: 20、WP5: 1）
* `rule_behaviour` Test: すべて PLANNED（`test_evidence_evaluator_s7.py`、`test_evidence_store.py`、`test_evidence_artifact.py`、`test_evidence_report.py` はまだ存在しない）
* Phase 1 Helper の、Evidence 生成時点の版: UNKNOWN（Definition に固定）
* rev2 / rev3 文書の作成時点の内容: WP0 時点の Hash だけで、同一性は NOT_PROVEN
* Secret が存在しないこと: 証明できない（規則に一致しなかっただけ）
* CI 上の実行結果: NOT VERIFIED

## 7. WP2 への引き継ぎ

1. `s7.evidence.raw_api_data_stored`（S7-01）の実装と `tests/unit/test_evidence_store.py`
2. Raw Evidence の保存前 Secret Gate には、`public_preflight.load_scanner` と同じく `scan_secrets.py` の規則を使う（規則集を重複させない）。ただし `.github/scripts/` は Plugin Package から import できないため、Store 側でどう規則を共有するかを WP2 の設計で決める必要がある
3. Rule を `IMPLEMENTED` にするときは、`rules.IMPLEMENTATIONS` への登録、`rules._SPECS` の状態、Definition の Test 状態（`PLANNED` → `IMPLEMENTED`、`planned_wp: null`）を同時に変える。Validator はどれか1つだけの変更を拒否する
4. Definition が2件以上になったら、「Catalog の全 Rule がいずれかの Criterion に使われている」の検査を Definition 単位にする
5. CI で Git 履歴を検査するには `fetch-depth: 0` が必要。CI の変更は要承認
6. Preflight を CI の Gate にするか（CI の変更は要承認）

## 8. Git の状態

```text
 M .gitignore
?? .github/scripts/public_preflight.py
?? docs/v2/phase2/m1/wp0/（5ファイル）
?? docs/v2/phase2/m1/wp1/wp1-architecture-note.md
?? docs/v2/phase2/m1/wp1/wp1-acceptance-report.md
?? iacreview/evidence/（__init__.py、registry.py、rules.py、definitions/、schema/）
?? tests/unit/test_evidence_preflight.py
?? tests/unit/test_evidence_registry.py
?? tests/unit/test_evidence_s7_definition.py
```

Staging 済みのファイル 0件。Commit、Push、GitHub API の呼び出しはしていない。
