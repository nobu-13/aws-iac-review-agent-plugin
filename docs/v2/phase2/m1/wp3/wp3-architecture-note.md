# Phase 2 / M1 / WP3 — Architecture Note

状態: WP3 実装（未 Commit、Human レビュー待ち）。

* Source: `docs/v2/phase2/m1/wp0/m1-architecture-proposal.md` §3-3（V1〜V9）・§4-3（Legacy Map）・§5、`m1-acceptance-test-matrix.md`（M1-06、M1-08〜M1-11）、`helper-audit.md` §2-6、WP2 `wp2-architecture-note.md`
* 目的: 判定（WP4）の前に、Evidence が壊れていないか、完全か、使ってよいかを機械可読に示すこと。あわせて、Phase 1 Evidence の欠損を正しく記録し、Artifact の Source / Commit / 公開内容の一致を検査し、壊れた Revision を自動修復せずに扱えるようにすること
* 変更理由: Phase 1 では、Evidence の欠損・改変、来歴の混同、Artifact の drift（G11）を、判定の前に検出する手段がなかった（WP0 HA-3、HA-7、HA-13、rev2 C4）

## 1. ファイル

| ファイル | 種別 | 役割 |
| --- | --- | --- |
| `iacreview/evidence/integrity.py` | 新規 | Integrity Validator（V1〜V9、W1〜W5） |
| `iacreview/evidence/legacy.py` | 新規 | Legacy Evidence Map の検証と、現在のファイルの再 Hash（読み取り専用） |
| `iacreview/evidence/legacy/phase1-legacy-evidence-map.v1.json` | 新規 | Phase 1 Evidence の Map（71 entry、7 subject） |
| `iacreview/evidence/artifact.py` | 新規 | Artifact Integrity の3層と、P2-AI-01 / P2-AI-02 の Rule |
| `iacreview/evidence/store.py` | 変更 | 構造化 Finding（check id 付き）、Diagnostic、Quarantine、Directory の fsync、中断した Revision の Envelope の列挙 |
| `iacreview/evidence/secretgate.py` | 変更 | Contents API の base64 `content` を decode して検査（検出を増やす変更。緩和はしていない） |
| `iacreview/evidence/rules.py` | 変更 | P2-AI-01 / P2-AI-02 を `IMPLEMENTED` に（実装 3件、`PLANNED` 21件） |
| `iacreview/evidence/definitions/phase1-app-demo-s7.v1.json` | 変更 | P2-AI-01 / 02 の rule_behaviour Test 2件を `IMPLEMENTED` に |
| `tests/unit/test_evidence_{integrity,legacy,artifact,raw_policy}.py` | 新規 | WP3 の Test |
| `tests/fixtures/evidence_raw/*.json` | 新規 | 合成 GitHub REST 応答（8件、安全な内容と合成 PII だけ） |
| `tests/unit/test_evidence_registry.py`、`test_evidence_s7_definition.py` | 変更 | 「実装 1件 / 計画 23件」の期待値を「3件 / 21件」に変更（§8） |
| `docs/v2/phase2/m1/wp3/*.md` | 新規 | 本書、Raw Evidence Security Policy、Acceptance Report |

Phase 1 の Helper、旧 Test、Evidence、rev2 / rev3 文書、`scan_secrets.py`、CI、`pyproject.toml` は変更していない。

## 2. WP0 との Gap（実装前に確認した点）

| # | Gap | 対応 |
| --- | --- | --- |
| G-1 | V3 は `REVISIONS.json`（追記のみのファイル）を前提にしていた。WP2 は書き換えられるファイルを避けるため、連鎖を各 Manifest の `previous_manifest_sha256` に持たせた | V3 の意味（Manifest の Hash が連鎖と一致する）は変えず、Manifest 内の連鎖で検査する |
| G-2 | V8（失効・置換された Evidence を current として使わない）に必要な失効の仕組みが WP2 にない | WP3 で Revision 単位の Quarantine を追加した。V8 はそれと不正な Quarantine 記録を検査する。Evidence 単位の supersede / revoke は未実装 |
| G-3 | V9（Sanitized Evidence）を前提にした Envelope の `sanitization` field が WP2 の schema 1 にない | V9 は `NOT_APPLICABLE`（理由付き）。Sanitized Artifact は保存しない方針（Raw Security Policy §3） |
| G-4 | 指示の検証要求のうち、Evidence ID の重複・欠落、Subject Commit、不完全 Revision、Secret Gate の再検査、権限は V1〜V9 にない | 番号の意味を変えず、W1〜W5 として追加した |
| G-5 | WP0 の Provenance 区分（API / LOCAL_GIT / LOCAL_FILE / HUMAN / DERIVED / DERIVED_HELPER_OUTPUT）と、WP2 の Envelope（API / LOCAL / HUMAN）が異なる | Envelope は WP2 のまま。Legacy Map は Phase 1 用に別の閉集合（`DERIVED_HELPER_OUTPUT` などを含む）を持つ |

## 3. Integrity Validator（`integrity.py`）

`validate(store, evidence_ids, Requirement(source_type, subject_commit_sha, require_complete))` は、check ごとに `check_id`、`title`、`status`、`reason_codes`、`evidence_ids`、`details` を返し、さらに `overall_status`、`usable_evidence_ids`、`unusable_evidence_ids` を返す。出力に絶対 Path や内容は含めない。

| 検証要求（指示） | Check | 由来 |
| --- | --- | --- |
| Envelope の Schema 一致 | V4 | WP0 |
| Raw の SHA-256 一致 | V1 | WP0 |
| Manifest の構造・参照整合性 | V1（ファイルと Hash、構造）、V2（Manifest 外のファイル、Link） | WP0 |
| Evidence ID の重複・欠落 | W1 | WP3 追加 |
| Revision 番号と Previous Manifest Hash | V3 | WP0（G-1） |
| Capture の Pagination 完全性 | V5 | WP0 |
| Provenance と Subject Commit の整合性 | V7（Source Type）、W2（Subject Commit） | WP0 / WP3 追加 |
| 不完全 Revision・途中失敗 | W3 | WP3 追加 |
| Secret Gate の結果と保存内容の整合性 | W4 | WP3 追加 |
| （WP0 のまま）HTTP 成功・JSON | V6 | WP0 |
| （WP0 のまま）失効の不使用 | V8 | WP0（G-2） |
| （WP0 のまま）Sanitized | V9 = NOT_APPLICABLE | WP0（G-3） |
| 権限 | W5 | WP3 追加 |

規則:

* Store 全体の check（V1〜V4、W1、W3、W5）は、Store の構造化 Finding から作る。Store に Finding があれば、指定した Evidence 以外の問題でも FAILED になる。
* Store が検証に通らなければ、Evidence 単位の check（V5、V6、V7、W2、W4）はすべて `NOT_PROVEN`（`store_integrity_not_verified`）で、使える Evidence は0件になる。**古い Revision への Fallback はしない**（`StoreReport.find` と `read_raw` も Store が無効なら何も返さない）。
* 集計: FAILED が1つでもあれば FAILED、NOT_PROVEN が1つでもあれば NOT_PROVEN、それ以外が PASS。NOT_PROVEN を PASS に変換しない。NOT_APPLICABLE は理由付きの場合だけ許す。

## 4. Artifact Integrity（`artifact.py`）

既存実装の調査:

| 実装 | 内容 | 判断 |
| --- | --- | --- |
| Helper `committed_tree` | 独自の `subprocess` で `git rev-parse` / `ls-tree` / `cat-file`。安全 option（hooks、fsmonitor の無効化）なし | 使わない。読み取りは `gitsnap` に寄せる（D-7） |
| Helper `compare_tree` | 正確な path 集合、`100644` のみ、bytes 一致 | 規則だけを移す |
| Helper `artifact_record` / `require_artifact` | 比較と push 記録の作成、Fail-closed の Stop | 記録の形（`Comparison.record()`）と Fail-closed だけを移す。Push 経路は移さない |
| `iacreview/remediation/gitsnap.py` | Git 管理済み、`proc.run_bounded`、安全 option、plumbing のみ、Test あり | 読み取り層として再利用する |

責務の分離:

1. Git Tree（`read_artifact`）: ref を commit に解決し、tree の全 entry と blob を読む（gitsnap）
2. Content Hash（`compare_content`）: 主張した Artifact Commit と Source Commit、path 集合、mode、bytes、blob の bytes から再計算した git object id を照合する
3. Evidence Manifest（`manifest_reference_problems`）: Store に LOCAL Evidence として保存した Artifact 記録が、Commit、Tree、各ファイルの SHA-256 と一致する

検出する不一致: `source_commit_mismatch`、`artifact_commit_mismatch`、`content_mismatch`、`extra_file`、`missing_file`、`mode_changed`、`symlink`、`gitlink`、`invalid_git_object`（blob の bytes が object id に一致しない）、`blob_too_large`、`manifest_reference_mismatch`。読めない object は MISMATCH ではなく UNVERIFIABLE（→ NOT_PROVEN）にする。

Rule:

* P2-AI-01 `whole_tree_matches_source`: MATCH かつ（与えた場合）保存記録が一致すれば PASS。不一致は FAILED。検証不能・記録なしは NOT_PROVEN
* P2-AI-02 `published_matches_source`: 検証済み Store の COMPLETE な Contents API Evidence（`/repos/<o>/<r>/contents/<path>?ref=<artifact commit>`）について、base64 を decode し、git blob id を再計算して、報告された `sha`、承認済み bytes、commit の blob と比べる。G11 のように公開内容が別の bytes なら FAILED。PASS でも真正性は示さない（API の来歴は自己申告）

新しい Push 処理は実装していない。Test は一時 Directory の Git Repository だけを使い、Phase 1 Helper を import も実行もしない。

## 5. Revision Integrity と Recovery（`store.py`）

検出（すべて Test 済み）: `MANIFEST.json` の欠損（W3）、Raw の欠損（V1）、Revision の欠番（V3）、Previous Manifest Hash の不一致（V3）、Manifest の改変（V1）、Envelope の改変（V1 / V4）、最新 Revision の中断（W3）、古い Revision への Fallback（§3 のとおり起こらない）。

Recovery の手順（自動では修復・削除・上書きしない）:

1. 検出: `verify()`
2. 読み取り専用の診断: `diagnose()`。Revision ごとの状態、Finding、**state digest**（Revision Directory の全 entry の名前・種別・SHA-256・size の Hash）、使用不可の Evidence ID、推奨手順を返す。`diagnostic_sha256` は生成時刻を除いた全体の Hash。`write_diagnostic()` は Store の外へ排他作成で書く
3. 使用不可: Store が無効な間は、すべての Evidence が使用不可
4. Human の判断を待つ
5. 承認された場合だけ: `quarantine_latest(QuarantineApproval)` が、新しい Revision に HUMAN Evidence `quarantine-rev-NNNN`（承認の記録）を書く。承認が対象 Revision の現在の state digest と diagnostic digest に一致しなければ拒否する（古い承認は使えない）。新 Revision の `previous_manifest_sha256` は壊れた Revision の state digest にする

Quarantine の性質:

* 壊れた Revision は Disk 上でそのまま残り、状態は `QUARANTINED`、その Evidence は使用不可（V8 FAILED）
* 承認後に壊れた Revision を1バイトでも変えると、state digest が一致しなくなり、Store は再び無効になる
* 対象は最新の Revision だけ。途中の Revision の破損は、Store の外での Human 判断が必要（`quarantine_latest` は拒否する）
* VALID な Revision に対する Quarantine 記録は V8 FAILED（偽の失効で Evidence を隠せない）
* Quarantine の承認は HUMAN_ATTESTED で、承認者の暗号学的な証明はない

### 5-1. Crash Consistency の境界

`MANIFEST.json` の非上書きだけでは Crash Consistency は保証されない。WP3 で行っていることと、その限界は次のとおり。

| 手順 | 永続化 | 中断時の状態 | 検出 |
| --- | --- | --- | --- |
| Revision Directory の作成 | Store Root の fsync | 空の Revision | W3 `manifest_missing` |
| Raw の書き込み | ファイルの fsync、Directory の fsync | Raw だけ | W3（Envelope があれば列挙） |
| Envelope の書き込み | 同上 | Raw と Envelope | W3 |
| `MANIFEST.json.tmp` | ファイルの fsync、Directory の fsync | tmp あり、Manifest なし | W3 `interrupted_seal` / `manifest_missing` |
| `link()` で `MANIFEST.json` | Directory の fsync | 両方あり | W3 `interrupted_seal`（tmp の残存も不完全として扱う） |
| tmp の削除 | Directory の fsync | 封印完了 | — |

`test_every_crash_boundary_leaves_a_detected_unusable_revision` は、上の5つの境界で中断した状態を作り、どれも Store が無効になり、新しい Revision を始められないことを確認する。

限界:

* 中断は Process の停止として模擬した。電源断、OS の書き込み順序の入れ替え、fsync を無視する Storage（一部の仮想 Disk、Network File System）は Test していない
* `fsync` を Directory に対して拒否する File System では、Directory の fsync を黙って省略する（`_fsync_dir`）
* 部分的に書かれたファイル（途中の bytes）は、Hash の不一致または strict JSON の失敗として検出される。ただし Manifest に載る前のファイルは Hash が記録されていないため、中身の正しさではなく「封印されていない」ことだけが分かる

## 6. Legacy Evidence Map（`legacy.py`）

* 71 entry: E01〜E40（E23 は E23-1〜3、E23b-1〜6 に分かれ、E28-i を含めて49）、H01〜H03、GitHub 補完 4（`GE-*`）、rev1 / rev2 / rev3 文書と `REVISIONS.md` の15
* subject 7件: G3 / G3S / G6（FAILED、3軸）、G11（NOT_PROVEN）、G11b（PASS）、G12（PARTIAL）、AC27（FAILED、6軸）。`registry.PHASE1_LOCKED` と一致しなければ拒否する
* 各 entry の項目: Legacy Evidence ID、Source File（path、存在、現在の SHA-256、size）、Source Type、Provenance Assurance、Raw API Response、Historical Hash（status、種類、記録場所、値）、Completeness、関連 AC / Scenario、Historical Classification（rev2 index の状態）、Traceability Limitation
* 固定規則: Phase 1 には「Raw あり」という値がない（Helper 出力と人手報告は `RAW_UNAVAILABLE`、GitHub 補完の base64 2件だけ `RAW_FIELD_ONLY`）。当時の Hash がなければ `HISTORICAL_INTEGRITY_NOT_PROVEN`。Helper の Revision は `UNKNOWN`。どの entry も `COMPLETE` ではない
* Historical Hash がある14件の内訳: Git 管理された文書6件（E31〜E35、E37。git blob と §7 の section Hash）、`REVISIONS.md` に記録された rev1 の5件、GitHub 補完の README に記録された3件。README と `REVISIONS.md` 自体は Git 管理外で、まとめて書き換えられた可能性を排除できない（Limitation `UNTRACKED_RECORD`）。Git の Commit 日時は自己申告（`GIT_DATE_SELF_DECLARED`）
* `current_state()` は Source File を `O_NOFOLLOW` で読み直す。ないファイルは `SOURCE_MISSING`、変わったファイルは `CHANGED`、Symbolic Link は読まない（`SOURCE_MISSING`）
* `traceability_summary()` は M1-10 を2つに分けて返す: 欠損の追跡（`gap_traceability`）と、当時の Raw への到達（`historical_raw_reachability`、常に NOT_PROVEN）

Map は再判定ではない（`is_reevaluation: false`）。後から取得した Raw は新しい観測で、Legacy entry に付けない。

## 7. Raw Evidence Security Policy

`raw-evidence-security-policy.md` を参照。

## 8. WP1 / WP2 の Test の期待値の変更

| Test | 変更 | 理由 |
| --- | --- | --- |
| `test_only_s7_01_is_implemented_and_the_other_23_rules_stay_planned` | → `test_three_rules_are_implemented_and_the_other_21_stay_planned` | WP3-3 の指示で P2-AI-01 / 02 を実装した |
| `test_coverage_never_reports_a_criterion_as_proven` | IMPLEMENTED の行に P2-AI-01 / 02 を追加。`proven: false` は全行のまま | 同上 |
| `test_every_s7_clause_maps_to_one_catalog_rule_and_a_rule_test_matching_its_status` | 実装済みの Criterion に P2-AI-01 / 02 を追加 | 同上 |

Definition は `definition_version: 1` のまま、P2-AI-01 / 02 の Test 状態だけを変えた（未 Commit のため）。Commit 後は版を上げることを推奨する（WP2 から継続の Human 判断）。
