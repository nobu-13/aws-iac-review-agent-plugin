# Phase 2 M1 — Definition Versioning Policy（提案、Pre-Commit 監査）

> **Pre-Commit Remediation の注記（後から追加）**: 本書は Remediation の前の監査記録である。C-1〜C-3 の適用結果、最終の Hash、Commit 候補の一覧は `remediation-report.md` を参照する。

* Source: `iacreview/evidence/definitions/phase1-app-demo-s7.v1.json`（現在 SHA-256 `efd934b0badd8cbdc50ec13fcc0be4dec0e501ad26bf0507f546dd6d36e28589`）、WP1〜WP5 の Acceptance Report、`docs/v2/phase2/m1/wp4/legacy-reevaluation-results.json`、`docs/v2/phase2/m1/wp5/legacy-reevaluation-results.json`
* 目的: 未 Commit のまま変わってきた Definition v1 の変更履歴を、証拠のある範囲で再構成し、初回 Commit 後の Version 管理規則を提案する
* 状態: §1〜§3 は監査時の記録と提案。§4 は初回ローカル Commit の承認時に確定した規則と Baseline

## 1. 変更履歴の再構成（監査対象 6）

Definition v1 は一度も Commit されていないため、Git の履歴はない。下表は、各 WP の報告と、ファイルに記録された Hash から再構成した。

| WP | 変更 | 変更後の SHA-256 | 証拠 | 確度 |
| --- | --- | --- | --- | --- |
| WP1 | 作成。26 Criterion、`definition_version: 1`。全 Rule が PLANNED、rule_behaviour Test は WP2〜WP5 に PLANNED | 記録なし | `wp1-acceptance-report.md`、`test_evidence_s7_definition.py` の WP1 時点の Docstring | 内容は報告から。bytes は **NOT_PROVEN** |
| WP2 | S7-01 の rule_behaviour Test を IMPLEMENTED | 記録なし | `wp2-acceptance-report.md` §1（M1-02 S7-01 の行） | 同上 |
| WP3 | P2-AI-01 / P2-AI-02 の rule_behaviour Test を IMPLEMENTED | 記録なし | `wp3-acceptance-report.md` §1（M1-11 の行） | 同上 |
| WP4 | 20 Rule に対応する 22 Criterion の rule_behaviour Test を IMPLEMENTED。S7-19 は PLANNED のまま | `460031192a748c0e00a0982dc32751849c472bbf95428da9c7d08aeb9e3caa92` | WP4 の Legacy 結果ファイル（`b17e6881…29f7d544`）の `definition.definition_sha256` | Hash は記録あり |
| WP5 | S7-19 の rule_behaviour Test を IMPLEMENTED（`status`、`planned_wp: "WP5" → null`） | `efd934b0badd8cbdc50ec13fcc0be4dec0e501ad26bf0507f546dd6d36e28589` | WP5 の Legacy 結果ファイル（`f205b5d4…70ed`）、現在のファイル | 確認済み。現在の bytes で S7-19 の Test 状態だけを WP4 の値に戻すと、SHA-256 が `460031…aa92` に一致した（本監査で実測）。WP4 → WP5 の差はこの1か所だけ |

どの WP でも `definition_version` は 1 のまま変わっていない。Criterion の文言（`criterion_text`）は、条文の Fidelity Test（`test_every_historical_clause_occurs_once_in_the_worktree_section` など）が出典の条文と照合しているため、Test が PASS する限り原文から外れていない。ただし WP1〜WP3 の時点で文言以外の Field（`expected_result` など）が変わっていないことは、bytes がないため示せない。

### 1-1. 結果ファイルの Hash と再現可能性（監査対象 5）

| 項目 | WP4 の結果 | WP5 の結果 |
| --- | --- | --- |
| Path | `docs/v2/phase2/m1/wp4/legacy-reevaluation-results.json` | `docs/v2/phase2/m1/wp5/legacy-reevaluation-results.json` |
| ファイルの SHA-256 / Bytes | `b17e6881d20e27987da62716595629212afcdcf0529d9f313e26474a29f7d544` / 88,410 | `f205b5d4e9b1d8b91c8c35869dec7972d918215cefebbdc17d24590ad9bb70ed` / 112,316 |
| Evaluator Version（文字列） | `iacreview.evidence.evaluator/1` | `iacreview.evidence.evaluator/1`（同じ） |
| Evaluator Source の SHA-256 | `2eb4c0d0a94e091f662e5f583d81b246ccf5ad25a322143d4a6831e82df632d5` | `dfaec9527be9861ac3fe4ee85e7c8000cd82259af0b92220f2375db8fe6cdbf8` |
| Definition の SHA-256 | `460031192a748c0e00a0982dc32751849c472bbf95428da9c7d08aeb9e3caa92` | `efd934b0badd8cbdc50ec13fcc0be4dec0e501ad26bf0507f546dd6d36e28589` |
| 生成時点 | ファイルの作成時刻 2026-10-29T13:07:51+0900（WP4 で再生成した時。最初の版 `15b866b8…` は削除済み） | ファイルの作成時刻 2026-10-29T13:37:09+0900 |
| 時点の証拠の強さ | File System の時刻だけ。結果の bytes は時刻を含まない（Canonical の仕様） | 同じ |
| S7-19 | `not_implemented_rules: ["s7.open_questions.recorded"]`、`open_questions` なし | `not_implemented_rules: []`、`open_questions` あり |
| 現在の Source で再現できるか | **できない**。現在の Evaluator Source と Definition の Hash がどちらも違う。`replay.verify` 相当の比較では `SOURCE_CHANGED` / `DEFINITION_CHANGED` になる | **できる**。固定後の Gate 10 で再生成が byte 一致（`f205b5d4…70ed`） |
| 当時の Source の保存 | なし。WP4 時点の Evaluator Source は未 Commit のまま上書きされたため、WP4 の結果を再生成する手段はない | 現在の作業 Tree（未 Commit） |

Evaluator Version の文字列は Source が変わっても `…/1` のままだった。Source の違いは `source_sha256` でしか区別できない。

## 2. 問題点

1. 未 Commit の Definition が5回（WP1〜WP5）変わったが、`definition_version` は変わっていない
2. Evaluator Version の文字列も変わっていない。結果を区別できるのは Hash だけ
3. 旧結果を再生成するための旧 Source が残っていない（WP4）
4. Test の状態（`status`、`planned_wp`）の変更と、判定の意味の変更が、同じ Version の中で区別されていない
5. `expected_result` と Rule の到達範囲を照合する検査がない（`s7-19-interpretation-review.md` §3）

## 3. 初回 Commit 後の Version 管理規則（提案）

### 3-1. Definition

| 規則 | 内容 |
| --- | --- |
| D-1 不変 | Commit した `…v<N>.json` の bytes は変更しない。変更は新しいファイル `…v<N+1>.json` と `definition_version: N+1` で行う |
| D-2 Version を上げる変更 | Criterion の追加・削除、`criterion_text`、`evaluator_rule_id`、`expected_result`、`required_evidence_types`、`historical_classification`、`phase1_final_results`、`phase1_locked_classifications` の変更 |
| D-3 Test 状態の変更 | Test の `status` / `planned_wp` だけの変更も Version を上げる。理由: Definition の SHA-256 が変わり、過去の結果の `definition_sha256` と一致しなくなるため。代案として Test 状態を Definition の外（Registry の別ファイル）へ移す方法があるが、Schema の変更になるため Human 判断とする |
| D-4 旧 Version の保持 | 旧 Version のファイルは削除しない。過去の結果の `definition.definition_version` と `definition_sha256` で参照できるようにする |
| D-5 承認 | 新 Version の作成は Human 承認後。Agent は Definition の意味を変えない（`security.md` の Contract の扱いと同じ） |
| D-6 Hash の記録 | Commit ごとに Definition の SHA-256 を Acceptance Report に記録する |

### 3-2. Evaluator

| 規則 | 内容 |
| --- | --- |
| E-1 | 判定が変わりうる変更（Rule、Facts、合成、Canonical）では `EVALUATOR_VERSION` を上げる（`…/2` など） |
| E-2 | Docstring やコメントだけの変更でも `source_sha256` は変わる。これは意図した挙動とし、Version は上げない |
| E-3 | 公開する結果ファイルは、生成した Commit を記録する（例: 結果の外の README または Report に Commit SHA）。結果の bytes には入れない（Canonical の時刻・環境の禁止を守るため） |

### 3-3. 結果ファイル

| 規則 | 内容 |
| --- | --- |
| R-1 | 結果ファイルは生成した Commit とともに Commit する。Source を変えた Commit では、結果を再生成するか、旧結果を「旧 Source の記録」と明記して残す |
| R-2 | 旧結果を現在の Source で再現できると書かない。再現の主張は `replay.verify` が exit 0 になる組み合わせだけ |
| R-3 | WP4 の結果ファイルは「WP4 時点の記録、再現不能（Source 未保存）」として扱う。残すか削除するかは Human 判断（H-9） |

### 3-4. 初回 Commit の前にだけできること

初回 Commit の前なら、v1 の内容を変えても Version 規則に反しない。次の判断は初回 Commit の前に行うと手戻りが少ない。

* S7-17、S7-18、S7-19 の `expected_result.violated` を Rule の到達範囲に合わせるか（`s7-19-interpretation-review.md` §3 の案 A / B）
* Test 状態を Definition の外へ移すか（D-3 の代案）

v1 を変えた場合は、Legacy 結果の再生成と、Final Frozen Quality Gate の再実行が必要になる。

## 4. 確定した更新規則と初回 Baseline（初回ローカル Commit の承認時に追記）

§3 の提案のうち、次を確定した規則とする。§3 の他の項目は提案のまま残す。

### 4-1. 初回 Baseline

| 項目 | Baseline の値 |
| --- | --- |
| `EVALUATOR_VERSION` | `iacreview.evidence.evaluator/1` |
| Evaluator Source の SHA-256（`evaluator_source_sha256()`、対象: `evaluator.py`、`rules_s7.py`、`open_questions.py`、`rule_s7_evidence.py`、`facts.py`、`canonical.py`、`snapshot.py`、`artifact.py`） | `ee765e0c18ba76b9d4a27a0d4277548f21296757f03a77879763d1824dae58d6` |
| `RESULT_FORMAT` | `iacreview.evidence.evaluation/1` |
| Definition | `phase1-app-demo-s7`、`definition_version: 1` |
| Definition の SHA-256 | `fb4ddef0b86d36e436e4492e1ff2d209812e80b6e993dea47ba07dc7a856b1d0` |
| Baseline で再現できる結果 | `docs/v2/phase2/m1/wp5/legacy-reevaluation-results.json`（`731a1846ce5bb6102bea478fbc613b85ccb6b3cf90fc736dd62b8bbeaa8e1748`） |

現行の値を初回 Baseline にする根拠:

1. `…/1` と Definition v1 は、これまで一度も Commit も公開もされていない。WP1〜WP5 と Pre-Commit Remediation の途中の版（Definition `460031…`、`efd934b0…` など、Evaluator Source `2eb4c0d0…`、`dfaec952…` など）を参照する公開物は、Commit 候補に残っていない（WP4 の結果 JSON は非公開で保全し、旧 Hash を記した文書には旧値である旨の注記がある）
2. 途中の版を `…/1` 以外の番号で残すと、存在しない公開版を参照する番号が生まれる。初回 Commit の内容を `…/1` と v1 とし、以降の変更から規則を適用するほうが、公開された履歴と番号が一致する
3. Baseline の値は、Pre-Commit Remediation の Final Quality Gate と、初回 Commit 前の再検証で、再生成と Replay の byte 一致によって確認した

### 4-2. Definition の更新規則（確定）

| 規則 | 内容 |
| --- | --- |
| D-1 | Commit した `phase1-app-demo-s7.v<N>.json` の bytes は変更しない |
| D-2 | `definition_version` を上げる変更: Criterion の追加・削除、`criterion_text`、`evaluator_rule_id`、`expected_result`、`required_evidence_types`、`historical_classification`、`phase1_final_results`、`phase1_locked_classifications`、Test の `status` / `planned_wp` の変更。つまり、ファイルの bytes が変わる変更はすべて Version を上げる |
| D-3 | 新 Version は新しいファイル（`…v<N+1>.json`）で作り、旧 Version のファイルは削除しない |
| D-4 | Definition の SHA-256 は Version の識別に使う。同じ Version で SHA-256 が違うファイルは、Registry と Snapshot の照合で拒否される状態として扱う |
| D-5 | 新 Version の作成は Human 承認後に限る。Agent は原文の意味を変えない |

### 4-3. Evaluator の更新規則（確定）

| 規則 | 内容 |
| --- | --- |
| E-1 | 判定、出力の形、Canonical Serialization のどれかが変わりうる変更（Rule、Facts、合成、`RESULT_FORMAT`、Canonical）では、`EVALUATOR_VERSION` を上げる（`…/2`、`…/3` と連番） |
| E-2 | Docstring・Comment だけの変更では Version を上げない。Source の SHA-256 は変わるので、結果の再現性は Source の SHA-256 で判定する |
| E-3 | 判定が変わらない変更かどうかは、Source の変更後に Legacy 結果と合成 Replay を再生成し、`source_sha256` 以外の bytes が変わらないことで確認する。変わった場合は E-1 を適用する |
| E-4 | 公開する結果ファイルは、生成した Source と同じ Commit に入れる。Source を変えた Commit では、結果を再生成するか、旧結果を公開対象から外す |
| E-5 | 旧 Source の結果を現在の Source で再現できると書かない。再現の主張は `replay.verify`（`--expect`）が exit 0 になる組み合わせに限る |

§3-2 の E-3（結果の外に Commit SHA を記録する）は提案のまま残す。
