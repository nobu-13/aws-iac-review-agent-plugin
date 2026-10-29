# Phase 2 / M1 / WP1 — Architecture Note

状態: WP1 実装（未 Commit、Human レビュー待ち）。

* Source: `docs/v2/phase2/m1/wp0/m1-architecture-proposal.md` §3-1・§4-1・§5-5・§8、`acceptance-alignment-audit.md` §2、`repository-baseline.md` §3-1
* 目的: §7 の各条文を、判定規則（Rule）と Test に1対1で結ぶ Registry を作ること。あわせて、公開対象に非公開ファイルが入らないことを Commit 前に確認できるようにすること
* 変更理由: Phase 1 では §7 の `isRequired` 条件が Helper に実装されず、Test が逆の期待値を固定していた（WP0 HA-1、alignment §3-1）。条文と判定コードを結ぶ成果物がなかったことが原因である。また `.agents/` が ignore されておらず、`scan_secrets.py` は未追跡ファイルを走査しない（baseline §3-1）

## 1. 追加・変更したファイル

| ファイル | 種別 | 役割 |
| --- | --- | --- |
| `.gitignore` | 変更（末尾に4行追加のみ） | `.agents/` を除外 |
| `.github/scripts/public_preflight.py` | 新規 | Repository Public Safety Preflight（標準ライブラリのみ） |
| `iacreview/evidence/__init__.py` | 新規 | Package の説明 |
| `iacreview/evidence/registry.py` | 新規 | Definition の厳格な Loader / Validator、条文照合、Coverage |
| `iacreview/evidence/rules.py` | 新規 | Evaluator Rule ID の閉じた Catalog（WP1 では全件 `PLANNED`） |
| `iacreview/evidence/definitions/phase1-app-demo-s7.v1.json` | 新規 | Phase 1 §7（と §6 の偽装3行）の Versioned Definition |
| `iacreview/evidence/schema/acceptance-definition.v1.schema.json` | 新規 | Definition の JSON Schema（形式の文書。強制は `registry.py`） |
| `tests/unit/test_evidence_registry.py` | 新規 | Validation の異常系（WP1-4 の10ケース他） |
| `tests/unit/test_evidence_s7_definition.py` | 新規 | §7 Definition の忠実性と Phase 1 結果の固定 |
| `tests/unit/test_evidence_preflight.py` | 新規 | Preflight の正常系・異常系（一時 Git Repository） |
| `docs/v2/phase2/m1/wp1/*.md` | 新規 | 本書と Acceptance Report |

Phase 1 の Helper、旧 Test、Evidence、`scan_secrets.py`、`pyproject.toml`、CI は変更していない。Dependency の追加もない。

## 2. 配置の判断

* Registry は承認済み配置 `iacreview/evidence/` に置いた（D-1）。Coverage Gate の対象になる。
* **Preflight は `iacreview/evidence/` ではなく `.github/scripts/` に置いた。** 当初は `iacreview/evidence/preflight.py` として実装したが、既存 Test `tests/unit/test_docs.py::test_no_runtime_file_reads_the_kiro_directory` が FAIL した。この Test は、Plugin の Runtime Tree（`iacreview/` 等）に `.kiro` という文字列があることを禁止している。Preflight は非公開 Path として `.kiro/` を名指しする必要がある。既存 Test は変更できず、文字列を分割して検査を逃れるのも不適切なので、Repository 衛生 Tool として `scan_secrets.py` と同じ場所に移した。Plugin の配布物にも入らない。
* Preflight は `scan_secrets.py` を変更せずに読み込み、その `scan_text` / `RULES` をそのまま使う。Secret 規則を2か所に持たない（WP0 architecture §5-1）。

## 3. Acceptance Definition Registry

### 3-1. 形式

JSON（標準ライブラリで読める。重複 key、`NaN`、非 UTF-8、1 MiB 超を拒否）。File 名は `<definition_id>.v<version>.json` で、中身の `definition_version` と `registry.DEFINITION_INDEX` の版が一致しなければ拒否する。

指示の各項目は、Definition の次の field に対応する。

| 指示の項目 | Field |
| --- | --- |
| AC ID | `acceptance_criteria[].ac_id` |
| Criterion ID / Text | `criteria[].criterion_id` / `criterion_text` |
| Definition Version | `definition_version`（File 名・Index と一致） |
| Definition Source | `criteria[].source_id` → `historical_sources[]`（path、section） |
| Source Commit SHA | `historical_sources[].commit`（40桁）と `verified_commits` / `blob_ids` |
| Evaluator Rule ID | `criteria[].evaluator_rule_id`（`rules.RULE_CATALOG` のいずれか） |
| Test ID | `criteria[].tests[].test_id`（`tests/<path>.py::test_<name>`） |
| Required Evidence Types | `criteria[].required_evidence_types`（閉集合） |
| Expected Result | `criteria[].expected_result`（satisfied / violated / evidence_missing） |
| Historical Classification | `criteria[].historical_classification[]`（subject、status、根拠） |

### 3-2. Historical Source と Phase 2 の Machine-readable Definition の区別

* `machine_readable_origin.committed_in_phase1` は常に `false`。この JSON は Phase 2 WP1 で作成したもので、Phase 1 に存在したものとして扱わない。
* `criteria[].origin`:
  * `historical_text`: Phase 1 で Commit された条文の**原文の引用**。出典は `kind: pre_fixed_criterion` の Source に限る
  * `phase2_added`: Phase 2 で追加した基準（Issuer Pinning の独立証明、Artifact Integrity）。出典は `phase2_document` に限り、Commit を持たない
* `historical_sources[].kind`:
  * `pre_fixed_criterion`: Git 管理された事前基準。`app-demo-plan.md` の §7（`coverage: complete`）と §6（`coverage: excerpt`、G3 / G3S / G6 の3行）
  * `phase1_decision_record`: rev2 / rev3 の判定記録。`.agents/` にあり非公開。WP0 時点の SHA-256 だけを持ち、Commit を名乗れない
  * `phase2_document`: WP0 文書
* `historical_evaluator.version_at_evidence_time` は `UNKNOWN` に固定（Validator が他の値を拒否）。Phase 1 Helper は Git 管理されたことがなく、Evidence に版も Hash も残っていないため（WP0 HA-13）。

### 3-3. 条文の照合（引用の忠実性）

* `historical_text` の各 `criterion_text` は、§7 の中にちょうど1回だけ現れなければならない（重複・不一致は拒否）。
* §7（`coverage: complete`）は、Criterion、各行の Source 列、明示した非規範テキスト（見出し、表の header、行ラベル、導入文）の和で**全文**を覆わなければならない。覆われない規範的な文字が残れば拒否する。これにより「対応表 100%」を、件数の主張ではなく機械的な検査で示す。
* 作業ツリーのファイルは、その git blob id が `verified_commits` のいずれかの blob と一致するときだけ使う（Commit 済みの版とバイト単位で同一）。
* Git 履歴に対しては、5つの verified commit（`24b7a6e`〜`4bd6e01`）それぞれで blob id、§7 の存在、全引用の一致を検査する。WP1 時点の実測では §7 は5 commit で同一（SHA-256 `efe674de…`）、§6 は他の行が変わっているが G3 / G3S / G6 の3行は同一。
* CI の test job は shallow checkout なので Commit が無い。その場合、Git 履歴の Test は `NOT VERIFIED` として skip する（PASS と数えない）。作業ツリーの照合は常に実行される。

### 3-4. Rule と Test

* `rules.RULE_CATALOG`: 24 Rule。WP1 ではすべて `PLANNED` で、担当 WP（WP2〜WP5）を持つ。`IMPLEMENTATIONS` は空。`IMPLEMENTED` と実装 callable の有無が食い違えば拒否する。
* Test は2種類に分ける。
  * `rule_behaviour`: Rule の判定を検査する Test。全 Criterion に1件以上必要。WP1 では全件 `PLANNED`（存在しないファイル `tests/unit/test_evidence_evaluator_s7.py` 等を指す）
  * `definition_fidelity`: Definition 自体（引用、固定値）を検査する Test。WP1 で `IMPLEMENTED`
* `check_test_references`: `IMPLEMENTED` の Test は AST で関数の存在を確認する。`PLANNED` の Test がすでに存在すれば、それも拒否する（状態の付け忘れを防ぐ）。
* **存在の確認は、Test の成功を意味しない。** `coverage()` は全行 `proven: false` を返す。合否は Test を実行した結果だけで示す。
* Catalog の全 Rule がいずれかの Criterion に使われていること（Criterion と Rule の対応の欠落）と、1 Rule が複数の軸にまたがらないことを検査する。WP1 の Catalog は §7 Definition 1件のためのもので、Definition が増えたら「全 Rule が使われている」の検査は Definition 単位の Catalog に分ける必要がある（WP4 の課題）。

### 3-5. Phase 1 結果の固定

`registry.PHASE1_LOCKED` に、Phase 1 最終 Acceptance の値をコードとして固定した。Definition の値がこれと異なれば拒否する。

* G3 / G3S / G6: `required_check` = FAILED、`merge_blocking` = PASS、`issuer_pinning_independent_proof` = NOT_PROVEN（`phase1_locked_classifications` と、各 Criterion の `historical_classification` の両方を検査）
* Scenario 15件（PASS 8 / FAILED 3 / PARTIAL 1 / NOT_PROVEN 3）、AC rev3 の件数（PASS 40 / PARTIAL 4 / FAILED 1 / NOT_PROVEN 3）
* `historical_evaluator.version_at_evidence_time` = `UNKNOWN`

Definition の JSON と Validator の定数を同時に書き換えれば固定値は変えられる。これは Code Review と Git 履歴で防ぐ範囲で、Registry 単体では防げない。

### 3-6. 必須の判定軸

`DEFINITION_INDEX` は §7 Definition に7軸（Gate Provenance、App Check Provenance、Required Check、Merge Blocking、Issuer Pinning Independent Proof、G11 Environment Boundary、Artifact Integrity）を必須とする。ほかに `evidence_recording`（S7-01、S7-18、S7-19）と `scenario_composition`（S7-02）を持つ。Required Check と Merge Blocking は別軸で、§7 の required 行のうち `isRequired` の条件は前者、「merge state as expected」は後者に置いた。

## 4. Repository Public Safety Preflight

`python3 .github/scripts/public_preflight.py [--root DIR]`。Exit 0 PASS / 1 FAILED / 2 ERROR。

| Check | FAILED / ERROR の条件 |
| --- | --- |
| `repository_root` | Git の top level でない、Git が使えない → ERROR |
| `agents_ignored` | `.agents/` と `.agents/…/appdemo-targets.json` が ignore されない → FAILED。`check-ignore` 失敗 → ERROR |
| `enumeration` | いずれかの `git ls-files` / `git diff --cached` の失敗 → ERROR（公開対象が不明） |
| `no_tracked_private_path` | `.agents/` または `.kiro/` 配下が追跡されている → FAILED |
| `staged_paths_public` | Staging 済みの非公開 Path → FAILED |
| `public_candidates` | 公開候補（`ls-files --cached --others --exclude-standard` = `git add -A` の対象）に、非公開 prefix、入れ子の Repository（未追跡 Directory、gitlink 160000）、`.git` 配下、`*-targets.json` / `.pem` / `.key` / `.env*` / `credentials*` がある → FAILED |
| `secret_scan_coverage` | 2 MiB 超・読めないファイル → ERROR（走査できないものを合格にしない） |
| `secret_scan` | `scan_secrets.py` の規則に一致 → FAILED（値は表示しない）。規則を読み込めない → ERROR |

* 未追跡ファイルも走査する（`scan_secrets.py` は追跡ファイルだけを走査する）。
* Binary は、印字可能 ASCII の連続部分に分けて走査する（埋め込まれた Token を見逃さないため）。`scan_secrets.py` は Binary を走査しない。
* 実行する Git Command は読み取り専用で、argv 配列・shell なし・timeout 付き。
* PASS は「規則に一致するものがなかった」ことだけを示す。Secret が存在しないことの証明ではない。

## 5. 範囲外（WP2 以降）

* Evaluator Rule の実装と `rule_behaviour` Test（WP2〜WP5。Catalog の `planned_wp`）
* Raw Evidence Collector、Store、Validator、Replay、Report
* Phase 1 再判定 Report（Legacy Replay、WP4）
* M1-01 の Git 管理の完了（Commit は Human 承認後）
