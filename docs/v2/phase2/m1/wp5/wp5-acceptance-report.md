# Phase 2 / M1 / WP5 — Acceptance Report

> **Pre-Commit Remediation の注記（後から追加）**: 本書の Hash と実測値（Evaluator Source `dfaec952…`、Definition `efd934b0…`、固定 Manifest `360d731b…`、Replay `4dc16d9b…`、Final Report `27eecd68…`、Legacy 結果 `f205b5d4…`、Mutant 29件など）は Pre-Commit Remediation の前の値で、最終 Source では再現しない。`docs/v2/phase2/m1/wp5/legacy-reevaluation-results.json` は最終 Source から再生成し直した。WP4 の結果ファイルは公開対象から外した。最終の値は `docs/v2/phase2/m1/precommit/remediation-report.md` を参照する。

* Source: WP5 指示（WP5-1〜WP5-8）、WP0〜WP4 の成果物、Final Frozen Quality Gate attempt 4（`.agents/tasks/phase2-m1-wp5/frozen-gate-attempt4/`、Git 管理外）
* 目的: M1 Evidence Integrity Foundation の最終 Acceptance を、実装と検証を分けて記録する
* 状態: 実施済み。**Git Commit なし**（HEAD `4bd6e015d88b01d34dc83dc2b2d2ffb0058358b2`）。GitHub API の呼び出し、Push、PR、Merge、CI 変更、Dependency 追加なし。Human と ChatGPT による M1 最終 Review 待ち

## 1. 結論

| 項目 | 結果 |
| --- | --- |
| M1-01〜M1-12 | PASS 10件（M1-02〜M1-09、M1-11、M1-12。範囲の限定付きを含む）、NOT_PROVEN 1件（M1-01）、M1-10 は「欠損の追跡 PASS / 歴史的 Raw NOT_PROVEN」。表は `m1-final-ac-matrix.md` |
| 26 Criterion / 24 Rule | 実装: 24 / 24 IMPLEMENTED（PLANNED 0）。評価可能性は §3-4 |
| Final Frozen Quality Gate | attempt 4 で12 Gate を実行、固定状態の変化なし。ruff / mypy は Baseline と同じ件数（§6） |
| 実 GitHub による End-to-End | 未実行（計画のみ、`github-e2e-verification-plan.md`） |

## 2. 変更・追加ファイル（WP5）

新規

* `iacreview/evidence/open_questions.py`（S7-19、SHA-256 `479025967e8f11ade944ca6e91dd6d9500ada5ea1ba36c7b1d34f65e014c49ba`）
* `iacreview/evidence/final_report.py`（Final Report、CLI、`6be7e135fe35cfef1ff9aa1c3ff29b458c3a6345377df0cd85e52ee1c17a8135`）
* `tests/unit/test_evidence_report.py`（8件）、`tests/unit/test_evidence_pipeline.py`（12件）
* `docs/v2/phase2/m1/wp5/` の8文書と `legacy-reevaluation-results.json`

変更

* `iacreview/evidence/evaluator.py`: S7-19 を評価に追加（`open_questions`）、`native_replay` が Definition の SHA-256 も照合、Evaluator Source の Hash 対象に `open_questions.py` を追加
* `iacreview/evidence/replay.py`: `verify()` と `--expect`（exit 4、理由コード5種）
* `iacreview/evidence/rules.py`: `s7.open_questions.recorded` を IMPLEMENTED（WP5）
* `iacreview/evidence/definitions/phase1-app-demo-s7.v1.json`: S7-19 の rule_behaviour Test を IMPLEMENTED。`definition_version` は 1 のまま（未 Commit のため）
* `tests/mutation/evidence_mutants.py`: MU-13〜MU-29 を追加、Legacy 結果の複写先を WP5 に変更
* 既存 Test の期待値変更（§7）

変更していないもの: Phase 1 の Helper・Evidence・旧 Test・判定、rev2 / rev3 文書、WP0〜WP4 の文書と WP4 の `legacy-reevaluation-results.json`、CI、`pyproject.toml`、`plugin.json`、`.gitignore`（WP1 の変更のまま）。

## 3. WP5-1: S7-19 Rule

### 3-1. 原文

> Not verified until the run: whether `isRequired` honours the expected source; whether `POST /rulesets` accepts `integration_id` directly; whether `user/installations` reports the permissions as planned; whether step outputs of a failed step reach the publisher (if not, BLOCKED runs still publish failure).

（`docs/v2/phase1/app-demo-plan.md` §7、Definition の S7-19。原文の意味は変えていない）

### 3-2. 判定

* 4つの問い Q1〜Q4 を条文から引用し（空白を正規化した原文に1回ずつ現れることを `test_the_questions_are_quoted_from_the_s7_19_text` で検査）、問いごとに次の5状態の1つを記録する

| 状態 | 意味（WP5 指示の分類） |
| --- | --- |
| `NOT_RUN` | 未実施 |
| `RUN_UNSETTLED` | 実施したが結果が未確定 |
| `EVIDENCE_INSUFFICIENT` | 証拠不足 |
| `LIMIT_DECLARED` | 限界・例外として明示 |
| `EVIDENCE_SATISFIED` | 必要な証拠を満たした（`answer` にどちらかを記録） |

* 状態は、同じ評価の Scenario 判定と Facts から導く。Registry、自己申告、Phase 1 の分類は読まない
* Criterion は4問すべてが `EVIDENCE_SATISFIED` のときだけ PASS。それ以外は NOT_PROVEN（理由コードに未確定の問いの ID）
* Catalog が IMPLEMENTED でなければ `rule_not_implemented` の NOT_PROVEN で、問いを1つも答えない（`test_registration_alone_is_not_an_answer`、MU-22）

### 3-3. 解釈（Human の確認を要する）

原文の意味を変える必要はなかった。ただし、Rule にするために次の解釈を置いた。

| ID | 解釈 | 理由 |
| --- | --- | --- |
| I-1 | S7-19 は FAILED を返さない | 条文は「確認していない」問いを並べるだけで、違反の条件がない。望ましくない答え（例: `isRequired` が期待した発行元を尊重しない）も「答えが出た」ことにし、その判定は S7-08 / S7-15 が FAILED にする |
| I-2 | Q1 は反例1つ、または Spoof 3 Scenario すべての肯定で確定 | 「尊重するか」は一般的な問いで、反例があれば否、3種の偽装すべてで尊重されれば是とした |
| I-3 | Q2 は読み戻した Ruleset に App の `integration_id` があっても `EVIDENCE_INSUFFICIENT` | 問いは作成 Call が受け付けたかで、読み取り専用の Collector は書き込み Call の応答を取得しない |
| I-4 | Q3 は常に `NOT_RUN` | `GET /user/installations` は GitHub App の user access token が必要（Plan §3）。対応する Evidence Role がない |
| I-5 | Q4 は、失敗が期待される Scenario で S7-03b、S7-05、S7-06、S7-07 がすべて PASS なら「出力が Publisher に届いた」 | Publisher が external_id に入れた Digest が、失敗した Step の Report と一致するため。Digest の不一致は「届かなかった」とは読まない |
| I-6 | `LIMIT_DECLARED` は呼び出し側が宣言したときだけ | Evaluator は宣言しない。宣言には Definition の変更と Human 承認が必要 |

### 3-4. 26 Criterion / 24 Rule の実装状態と評価可能性

実装状態: 24 Rule すべて IMPLEMENTED（WP2 1、WP3 2、WP4 20、WP5 1）。26 Criterion すべての rule_behaviour Test が IMPLEMENTED。

評価可能性（実装されていることとは別）:

| 区分 | Criterion | 合成 Raw | 実 GitHub Raw（現 Collector、計画どおりに取得した場合） |
| --- | --- | --- | --- |
| Evaluator が判定し、PASS / FAILED になりうる | S7-02、S7-04、S7-05、S7-07、S7-08、S7-09、S7-10、S7-12、S7-13、S7-14a、S7-14b、S7-15、S7-16、S6-G3、S6-G3S、S6-G6、P2-IP-01、P2-AI-01、P2-AI-02 | 評価可能（Test 済み） | 評価可能の見込み。未実行（NOT_VERIFIED） |
| Job Log・Artifact が必要 | S7-03、S7-03b、S7-06 | 評価可能 | Redirect、Binary、FP-1 のため NOT_PROVEN の見込み（計画 §4 E-1〜E-3） |
| 限界として常に NOT_PROVEN | S7-17、S7-18 | NOT_PROVEN | NOT_PROVEN |
| 一部の問いしか答えられない | S7-19 | Q1 / Q4 は確定、Q2 / Q3 は確定しない → NOT_PROVEN | 同じ |
| Evaluator の出力に入らない | S7-01 | WP2 の Rule を Store に対して単独で実行（`test_s7_evidence_raw_api_data_stored`） | 同じ。Scenario 判定には入らない |

PASS にできない Criterion: S7-17、S7-18（定義上）、S7-19（現在の Evidence Role では Q2 / Q3 が答えられない）。

## 4. WP5-3: Legacy G11 の評価

### 4-1. §7 の判定と Phase 2 の Artifact Integrity の区別

| 項目 | E18 / E19 の G11 | 根拠 |
| --- | --- | --- |
| §7 の判定（`s7_result`、当時の条文だけ） | PASS（gate、app_check、required、steal の各 Part が PASS） | `legacy-reevaluation-results.json`（`f205b5d4…70ed`） |
| `g11_environment_boundary` 軸 | NOT_PROVEN（S7-17 の限界を含む） | 同上 |
| Phase 2 の Artifact Integrity（P2-AI-01 / 02） | **NOT_PROVEN**（再評価に Artifact Evidence を入力していない） | 同上 |
| `phase2_result` | NOT_PROVEN | 同上 |
| Phase 1 の結果 | NOT_PROVEN（変更しない） | rev2 §3-3 |

当時の §7 に Artifact の条項はないため、§7 の判定に Artifact Integrity を入れていない。

### 4-2. 既存 Evidence の調査（読み取りのみ）

| Evidence | Locator | SHA-256 | 内容 |
| --- | --- | --- | --- |
| E26 Branch integrity（Helper 出力、`LOCAL_GIT_DERIVED`、`SELF_DECLARED_UNVERIFIED`） | `.agents/tasks/phase1/henv/out/app-demo-2/branch-integrity.20261028T053023925824Z-1.json` | `0dbdcab3184aa8a64e70a6a94920957d2173094bee39d135da8222e44d20475a` | `g11-publisher-steal`（commit `049f19ea…`、tree `8c16997d…`）の `.github/workflows/steal.yml`: committed `cef683fb…`、source `212809a3…`、`match: false` |
| E26（2回目） | `…/branch-integrity.20261028T055746603637Z-1.json` | `1e00f71b595a18c4a268d72c8124f5aede9022ba2012e3c78374d17b0f5311e1` | 同じ値 |
| GE-RAW-STEAL（Contents API の `content` Field、Phase 1 最終 Acceptance の補足取得） | `.agents/tasks/phase1/final-acceptance/github-evidence-20261028/raw/steal.yml@049f19e.b64` | `1b911f7aaa13590ca887e6e0f82ee65fe163142b311726bdaf30d10148025e0d`（README の記録と一致） | 展開した内容の SHA-256 `cef683fbd7d9d5a5906c5979df3fdaea4b02db40855e07db4f770828be569b44`、git blob id `b31f669ae8185846f3c5a19a52e9b9ec41e51476`（756 bytes） |
| 保存された Local Repository の Git Object | `.agents/tasks/phase1/henv/out/app-demo-2/repo`（`git cat-file`、`GIT_OPTIONAL_LOCKS=0`、読み取りのみ） | — | `049f19ea…:.github/workflows/steal.yml` の blob `b31f669a…`、内容の SHA-256 `cef683fb…`（上と byte 一致） |
| E25 Incident Note（文書） | `.agents/tasks/phase1/henv/g11-artifact-mismatch-incident.md` | `6ffaf020e04702a413071765d2589f5276c66d2a560c8f12bca689329d483d5b` | 監査した Probe `212809a3…` と、Push した旧 Workflow `cef683fb…` の不一致の記録 |

### 4-3. 判定

* Push された内容（`cef683fb…`）は、Helper の記録、Contents API の Field、Git Object の3つで一致した。Git Object は内容 Hash で識別されるため、現在読んでも当時の Commit の内容と同じ
* 一方、P2-AI-01 / 02 の比較先である「承認済み Source」は、Phase 1 に事前固定された記録がない。`212809a3…` は Helper が Push 後に現在の Source から作り直した値と、Incident Note の記述にしかない
* このため、G11 の Artifact Integrity は **NOT_PROVEN のまま**とした。Helper の記録を承認済み Source として採用すれば比較は不一致（FAILED）になるが、その採用は当時なかった基準を後から置くことになるため、Human 判断（H-5）とする
* G11b の PASS（E28〜E30）は G11 に転用していない
* 再評価で新しく作ったデータ（Hash の再計算）は、当時の Raw として扱っていない

### 4-4. E18〜E21 の判定差異（証拠で確認できた範囲）

| 差異 | 確認できた原因 | 証拠 |
| --- | --- | --- |
| E18 / E19 の Helper 分類 G3 / G3S / G6 = NOT_PROVEN / PARTIAL、再評価 = FAILED | Helper の `_required_part` は `isRequired` を記録するだけで判定に使っていない。PARTIAL は §7 にない分類 | WP0 `helper-audit.md` HA-1、Definition の `historical_implementation.alignment = NOT_IMPLEMENTED` |
| E18 / E19 の Helper 分類 G11 = PROVEN / PASS、Phase 1 = NOT_PROVEN | Phase 1 は Artifact の Drift を理由に取り消した。Helper は Drift を見ない | rev2 §3-3、§4-2 の Evidence |
| E21 の Helper 分類 G2、G3、G3S、G4、G5、G6、G9、G10 = FAILED、再評価 = G3 / G3S / G6 以外 PASS | Legacy Map の E21 の記述「Shows G2 etc. as FAILED (wrong rule)」と、E20 が E21 を再分類したファイルであること（`reclassified_from: app-evidence.json`、`previous_classification` が E21 の分類と同じ） | Legacy Map、E20 の Field |
| E20 / E21 の G11 = NOT_PROVEN（再評価も NOT_PROVEN） | 当時 G11 の PR がなかった（Scenario 行が空） | 再評価の全軸が NOT_PROVEN |

E21 の「wrong rule」が Helper のどの版のどの条件だったかは、Helper の当時の Revision が不明（`HELPER_REVISION_UNKNOWN`）のため確認できない。

### 4-5. S7-19 の Legacy 再評価結果（WP5 で追加）

E18〜E21 で同じ: Q1 `EVIDENCE_SATISFIED`（`does_not_honour`、反例: Impostor の `isRequired = true`）、Q2 `EVIDENCE_INSUFFICIENT`（`pin_observed_create_call_not_captured`）、Q3 `NOT_RUN`、Q4 `EVIDENCE_SATISFIED`（`outputs_reach_publisher`）。S7-19 は NOT_PROVEN。入力は Helper の転記 Field で、Capture の完全性は NOT_PROVEN。

## 5. WP5-4、WP5-5、WP5-6

* E2E Replay Integration: `m1-integration-test-results.md`、`m1-reproducibility-report.md`
* Security and Mutation Regression: `m1-security-regression.md`（29 / 29 Killed）
* OSS Usability: `oss-quickstart.md`。Clean Copy で Quickstart の手順を実行（`pip install` を除く）

## 6. WP5-7: Final Frozen Quality Gate（attempt 4）

固定: Manifest SHA-256 `360d731b5b10a30e231bbf01ae76b50055698c7ab9bf15d934ec042bba18aec5`（703 files、`docs/v2/phase2/m1/wp5/*.md` を除く）。各 Gate の開始時・終了時に Manifest、Git Status、Phase 1 の15ファイルの Hash、HEAD を照合し、12 Gate すべてで固定時と一致した（Summary の SHA-256 `f4a49b5c3d26a25fcc0e663933526063fe5bd624050d84e1e0ae1aa97e298757`）。

| # | Gate | Command | exit | 結果 | 秒 |
| --- | --- | --- | --- | --- | --- |
| 1 | Full pytest | `python3 -m pytest -p no:cacheprovider --cov=iacreview --cov=benchmark/harness --cov-fail-under=80` | 0 | 7,685件: PASS 7,649 / FAIL 0 / SKIP 36、coverage 95.06% | 696 |
| 2 | Evidence Test | `python3 -m pytest -p no:cacheprovider tests/unit/test_evidence_*.py` | 0 | 449 passed | 31 |
| 3 | Benchmark | `python3 benchmark/harness/run_benchmark.py --cases benchmark/cases --mode combined` | 0 | PASS、17 Case（PASS 13 / INFO 4）、matched 34 / 34、FP 0、FN 0、errors 0 | 22 |
| 4 | Determinism | `PYTHONHASHSEED=random python3 -m pytest tests/property/test_prop_determinism.py` | 0 | 1 passed | 30 |
| 5 | Ground Truth | `python3 .github/scripts/check_ground_truth_order.py --cases benchmark/cases` | 0 | 17 / 17 verified | 6 |
| 6 | Phase 1 Helper Regression | `cd .agents/tasks/phase1/henv && python3 -m pytest -p no:cacheprovider --rootdir=. test_phase1_*.py` | 0 | 516 passed | 77 |
| 7a | ruff（iacreview） | `ruff check --no-cache iacreview` | 1 | 5 errors（Baseline 5 と同じ） | 5 |
| 7b | ruff（M1 の Path） | `ruff check --no-cache iacreview/evidence tests/unit/test_evidence_*.py tests/unit/evidence_synth.py tests/mutation .github/scripts/public_preflight.py` | 0 | All checks passed | 6 |
| 7c | mypy | `mypy --cache-dir=… iacreview` | 1 | 12 errors in 7 files（Baseline 12 と同じ）、`iacreview/evidence` は 0件 | 7 |
| 8 | Public Preflight | `python3 .github/scripts/public_preflight.py` | 0 | 8 Check PASS、706 files | 9 |
| 9 | Secret Scan | `python3 .github/scripts/scan_secrets.py` | 0 | 0 finding、633 files（tracked mode） | 8 |
| 10 | Replay byte comparison | `.agents/tasks/phase2-m1-wp5/wp5_replay.py` | 0 | Native 8回一致 `4dc16d9b…d6a4`、Report `27eecd68…16d1a`、Legacy byte 一致 `f205b5d4…70ed` | 7 |
| 11 | Mutation Test | `python3 tests/mutation/evidence_mutants.py --json …` | 0 | 29 / 29 Killed | 20 |
| 12 | Clean Checkout Test | `.agents/tasks/phase2-m1-wp5/wp5_clean.sh` | 0 | 444 passed / 5 skipped、Quickstart 全手順が期待どおり | 30 |

Python は `/usr/bin/python3`（3.9.6）、pytest 8.3.4。ruff と mypy は Advisory Gate（CI では `continue-on-error`）で、件数は Baseline 以下。

attempt 1〜3 は採用していない（`m1-reproducibility-report.md` §6）。attempt 1 の Gate 1 FAIL（coverage 54.30%）の原因は、新しい Test の子 Process が pytest-cov の環境変数を引き継いだこと（Test Bug）。

### Gate 後の文書の検査

Gate の後に `docs/v2/phase2/m1/wp5/*.md` を書いたため、文書を対象とする検査を再実行した（§11 に結果）。この再実行は固定範囲のファイルを変えていない（Manifest を再計算して一致を確認）。

## 7. 既存 Test の期待値変更（4回目）

WP1 時点の Test の期待値を WP5 の状態に合わせた。Assertion の緩和、Skip、削除はしていない。

| Test | 変更 |
| --- | --- |
| `test_evidence_registry.py::test_twenty_three_rules_are_implemented_and_one_stays_planned_for_wp5` | `test_all_twenty_four_rules_are_implemented` に変更（24 / 0） |
| `test_evidence_registry.py::test_11b_…`、`test_a_rule_marked_implemented_without_a_callable_is_inconsistent` | S7-19 が PLANNED でなくなったため、Monkeypatch で PLANNED の Catalog（WP4 の状態）を作るか、実装を外して同じ拒否を検査 |
| `test_evidence_registry.py::test_coverage_never_reports_a_criterion_as_proven` | S7-19 の行を (IMPLEMENTED, IMPLEMENTED) に |
| `test_evidence_s7_definition.py::test_every_s7_clause_maps_…` | 全 Criterion が IMPLEMENTED |
| `test_evidence_evaluator_s7.py::test_every_wp4_rule_is_implemented_with_a_callable` | S7-19 の Rule が IMPLEMENTED |
| `test_evidence_replay.py::test_native_replay_judges_the_synthetic_scenarios` | `not_implemented_rules == []`、S7-19 が NOT_PROVEN |
| `test_evidence_legacy_reeval.py` | 比較先を WP5 の結果ファイルに変更、S7-19 の Assertion を追加 |
| `test_evidence_mutations.py` | Mutant 数 12 → 29 |

## 8. Human 承認が必要な操作・判断

| ID | 内容 |
| --- | --- |
| H-1〜H-4 | Secret Gate の誤検知 FP-1 の扱い（WP2 から継続） |
| H-5 | G11 の承認済み Source として Helper の記録（`212809a3…`）を採用するか |
| H-6 | S7-19 の解釈 I-1〜I-6 の承認 |
| H-7 | Commit の範囲と順序（`.gitignore` の変更、`docs/v2/phase2/`、`iacreview/evidence/`、Test、Fixture）、Commit 後の Definition version の扱い |
| H-8 | `github-e2e-verification-plan.md` の承認と実行（対象 Repository、PAT、Gap E-1〜E-5、保存期間、Revoke） |
| H-9 | WP4 の `legacy-reevaluation-results.json` を記録として残すか（現在の Source では再現しない） |
| — | Git Push、PR、Merge、CI 変更 |

## 9. 残る NOT_PROVEN / NOT_VERIFIED

* NOT_PROVEN: M1-01（未 Commit）、M1-10 の歴史的 Raw、実 GitHub Raw の End-to-End（M1-04 / 05 / 06 / 08 / 11 の実環境部分）、`capture_authenticity`、第三者の独立再現、S7-17、S7-18、S7-19、P2-IP-01（G3 / G3S / G6）、G11 の Artifact Integrity と `phase2_result`、G7
* NOT_VERIFIED: CI 上の結果、別 OS・別 Python Version、`pip install` を含む Setup、Setup 時間、実 GitHub の fine-grained 権限（Check Runs、Annotations、GraphQL）

## 10. 新規・残存 Risk

* S7-19 の解釈 I-1〜I-6 が Human に承認されない場合、Rule と Test の変更が必要
* 結果に Source と Definition の Hash が入るため、Commit 前後の小さな変更でも Legacy 結果の再生成が必要（WP4 で1回、WP5 で1回発生）
* Clean Checkout はファイルの複写で、Clone ではない
* WP4 の Mutation 文書は WP0 の ID と条件が一致していなかった（WP5 で訂正）

## 11. Gate 後の文書の検査結果

| 検査 | Command | exit | 結果 |
| --- | --- | --- | --- |
| 固定範囲の不変 | Manifest の再計算 | — | `360d731b…18aec5`（固定時と一致） |
| Docs Test | `python3 -m pytest -p no:cacheprovider tests/unit/test_docs.py tests/unit/test_root_docs.py` | 0 | 165 passed |
| Public Preflight | `python3 .github/scripts/public_preflight.py` | 0 | 8 Check PASS、711 files（WP5 文書を含む） |
| Secret Scan | `python3 .github/scripts/scan_secrets.py` | 0 | 0 finding、633 files（tracked mode。untracked の WP5 文書は Preflight の走査が対象） |
| Account 名・Home Path | `grep` で WP5 文書を検索 | — | Account 名・Home Path 0件。`appdemo-targets` という File 名への言及が1件（`m1-integration-test-results.md`、検索語の説明） |

この検査の後、本節の記入以外に文書を変更していない。
