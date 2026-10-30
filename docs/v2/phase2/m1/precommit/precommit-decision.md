# Phase 2 M1 — Pre-Commit Decision

> **Pre-Commit Remediation の注記（後から追加）**: 本書は Remediation の前の監査記録である。C-1〜C-3 の適用結果、最終の Hash、Commit 候補の一覧は `remediation-report.md` を参照する。

* Source: `precommit-audit.md`、`publication-file-manifest.md`、`s7-19-interpretation-review.md`、`definition-versioning-policy.md`、`docs/v2/phase2/m1/wp5/`、Final Frozen Quality Gate attempt 4
* 目的: Git Commit を許可できるかを判定する
* 状態: 判定のみ。Commit、Add、Push はしていない。Human の承認待ち

## 1. 判定

**PARTIAL** — 現在の状態のままでは Commit を許可できない。§3 の条件 C-1〜C-3 を Human が決めた後であれば、Commit を許可できる。

FAILED ではない理由: Secret、PEM、Token、`.agents/`、`.kiro/`、個人 Targets、実 Raw、ログ、ネストした `.git` は候補に含まれず、固定した Source に対する Quality Gate はすべて期待どおりだった。

PASS ではない理由: 公開してよいかを Human が決めていない識別子（PC-1、PC-2）と、Definition と Rule の不整合（F-3）が残っている。F-3 は初回 Commit の前に直すほうが手戻りが少ない（Commit 後は Definition v2 が必要になる）。

## 2. 根拠

### 2-1. 満たしていること

| 項目 | 根拠となるファイル・Test | 結果 |
| --- | --- | --- |
| 禁止物が候補にない | `publication-file-manifest.md` §3 | 0件 |
| Secret Scan / Public Preflight | `.github/scripts/scan_secrets.py`、`.github/scripts/public_preflight.py`、`tests/unit/test_evidence_preflight.py` | 0 finding / PASS（711 files） |
| 固定 Source の Quality Gate 12件 | `docs/v2/phase2/m1/wp5/wp5-acceptance-report.md` §6、Summary `f4a49b5c…757` | 期待どおり、固定状態の変化なし |
| 固定範囲の不変（監査時点） | 固定 Manifest の再計算 | `360d731b…18aec5` で一致 |
| 生成 JSON の再現 | `tests/unit/test_evidence_legacy_reeval.py::test_the_committed_results_are_reproduced_byte_for_byte`、Gate 10 | WP5 の結果 `f205b5d4…70ed` は byte 一致 |
| Phase 1 の不変 | Gate 6（516 passed）、Phase 1 の15ファイルの Hash | 不変 |
| Fixture が合成 | `tests/fixtures/evidence_raw/*.json` | 合成値だけ |

### 2-2. 満たしていないこと、決まっていないこと

| ID | 内容 | 根拠 |
| --- | --- | --- |
| PC-1 | GitHub Account 名が WP0 文書2件にある | `publication-file-manifest.md` §3-1 |
| PC-2 | 実在の App id が Test 1件と WP0 文書1件にある。Test 側は「合成」と説明している | 同上、`tests/unit/test_evidence_secretgate.py` L163 |
| PC-3 | Demo の Commit SHA、Run id、`.agents/` の Path が Legacy Map と WP5 文書にある | 同上 |
| F-3 | S7-17、S7-18、S7-19 の `expected_result.violated = FAILED` に Rule が到達しない | `s7-19-interpretation-review.md` §3 |
| F-4 | S7-01 が Final Report に含まれず、参照もない | `precommit-audit.md` §2 |
| H-9 | WP4 の結果ファイル（現在の Source では再現不能）を Commit するか | `definition-versioning-policy.md` §1-1、R-3 |
| M1-01 | 未 Commit のため NOT_PROVEN。Commit 後に Clone からの Test で再判定が必要 | `docs/v2/phase2/m1/wp5/m1-final-ac-matrix.md` |

## 3. Commit を許可する条件

### 必須（Human の判断が必要）

| 条件 | 選択肢 | 選んだ場合の作業 |
| --- | --- | --- |
| C-1 識別子の公開（PC-1、PC-2、PC-3） | (a) そのまま公開を承認する。(b) 該当箇所を伏せる、または合成値に置き換える | (b) の場合: WP0 文書と `test_evidence_secretgate.py` の変更が必要。Test の変更後は Final Frozen Quality Gate を最初から再実行する |
| C-2 `expected_result` の不整合（F-3）と S7-19 の解釈 I-1〜I-6（H-6） | 案 A: v1 の `violated` を Rule の到達範囲に合わせる。案 B: 文書で意味を定義し、Definition は変えない | 案 A の場合: Definition v1 を変更し、Legacy 結果を再生成し、Quality Gate を再実行する。案 B の場合: 文書の追加だけ |
| C-3 Commit の範囲 | `.gitignore` の変更、新規78件、本監査の5件、WP4 の結果ファイル（H-9）をそれぞれ含めるか | 範囲を決めた後、Commit の直前に `public_preflight.py` を再実行する（Staged の確認を含む） |

### 推奨（Commit の可否には影響しない）

* F-4: Final Report に S7-01 を載せるか、S7-01 は Store の Report であることを Final Report に記す（コードの変更が必要）
* F-5: `definition-versioning-policy.md` の規則 D-1〜D-6、E-1〜E-3、R-1〜R-3 の採用
* F-6、F-7: S7-19 の未 Assert の経路と `legacy_reeval.main()` に Test を足す
* CI: History 照合を CI で通すかどうか（`fetch-depth` の変更は CI の変更にあたる）

## 4. Commit 後に必要なこと

1. Clone（`.agents/` なし）から Evidence Test を実行し、M1-01 を再判定する
2. CI の結果を確認する。Skip される Test（Phase 1 の非公開 Evidence 3件、History 照合1件）は PASS に数えない
3. Commit した Definition の SHA-256 と、結果ファイルの生成元の Commit を記録する

## 5. 本判定で行っていないこと

Commit、Git Add、Push、PR、Merge、GitHub API アクセス、CI の変更、Dependency の追加、コード・Test・Definition・既存文書の変更。
