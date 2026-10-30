# Phase 2 / M2 / WP1 — Implementation Report（Remediation Evidence Chain の安全性基盤）

* 状態: **実装とローカル検証まで。** Commit、Push、Merge はしていない。GitHub Actions 上の結果は NOT_VERIFIED
* 承認: WP0 rev1（96/100）、D-8（WP1 実装）
* 対象 AC: M2-01〜M2-07、共通 TC-00。M2-08〜M2-12 は WP2 以降
* 判定語: PASS / FAILED / NOT_PROVEN。NOT_VERIFIED は「実行・確認していない」

## 1. 変更ファイル

新規（すべて追加）:

| Path | 内容 |
| --- | --- |
| `iacreview/chain/__init__.py` | Package の境界と公開名 |
| `iacreview/chain/status.py` | Link / Status の語彙、Reason Code の Catalog（原因と未証明事項）、`compose`、予約 Exit code 31〜34 |
| `iacreview/chain/manifest.py` | Manifest の strict JSON、閉じた Schema、Locator の安全な読み取り（`O_NOFOLLOW`、Directory fd） |
| `iacreview/chain/links.py` | subject、contract、review、verification、gate（WP1 は未評価）、github の各 Link |
| `iacreview/chain/validator.py` | `validate(manifest_path, repo)`、Chain Result、Validator Source Digest |
| `tests/unit/chain_synth.py` | 合成 Chain の Builder（Test 用、製品ではない） |
| `tests/unit/test_chain_manifest.py`、`test_chain_links.py`、`test_chain_status.py`、`test_chain_replay.py`、`test_chain_isolation.py`、`test_chain_mutations.py`、`test_chain_ci.py` | M2-01〜M2-07、TC-00、Mutation、CI job の Test |
| `tests/mutation/chain_mutants.py` | MU2-01〜MU2-20 の Harness（M1 の Harness と同じ方式） |
| `tests/fixtures/chain_replay/` | Replay の入力（`sc01/`、`sc02/` の `review.json`、`remediation-report.json`、`subject.json`）と `expected.json` |
| `.github/scripts/chain_ci_check.py` | M2 CI job の Check（Exit 0、40〜44） |
| `docs/v2/phase2/m2/wp1/wp1-implementation-report.md` | 本書 |

既存ファイルの変更（追加のみ、削除行0）:

| Path | 変更 | 承認 |
| --- | --- | --- |
| `.github/workflows/ci.yml` | `chain-integrity` job を `lint` の前に追加。既存 job（`evidence-integrity` を含む）は無変更 | D-5（job 追加）で承認済み |
| `tests/unit/test_ci.py` | `CHAIN_JOB` を定義し `GATE_JOBS` に追加（2行の追加と1行のコメント修正） | **要 Human 確認**。既存 Test `test_every_job_is_either_a_gate_or_the_advisory_lint_job` が未分類の job を拒否するため必要。Assertion は緩めず、新 job にも Gate の検査（`continue-on-error` なし、`|| true` なし、lint tool を入れない）がかかる方向の変更 |

変更していないもの: `iacreview/evidence/`、`iacreview/remediation/`、M1 の期待値・Definition・Evaluator Source・Frozen Evidence、`docs/v2/phase1/`、`docs/v2/phase2/m1/`、`pyproject.toml`、`plugin.json`、`.gitignore`。新 CLI は作っていない。

## 2. 実装した AC

| AC | 判定（ローカル） | 根拠 |
| --- | --- | --- |
| M2-01 Manifest Schema / Canonical / Locator | PASS | TC-01-01〜06（Schema 違反23種、strict JSON 4種、Locator 9種と Symlink 4種、Size / 深さ / 非 UTF-8 / 欠落）。MU2-01〜03 検出 |
| M2-02 Subject / Contract | PASS | TC-02-01〜09（hooks・filter・textconv・fsmonitor の marker が作られないことを含む）。MU2-04〜06 検出 |
| M2-03 Verification | PASS | TC-03-01〜08（BLOCKED を VERIFIED に書き換え Digest を整合させた偽造が `payload_digest_mismatch`、Tool 不在と Version 不一致が `recompute_unavailable`）。MU2-07〜09 検出 |
| M2-04 Review | PASS（§4 の注記 N-3 あり） | TC-04-01〜08。Chain の Source に pass flag の文字列がないことを静的検査。MU2-10〜12 検出 |
| M2-05 GitHub Evidence | PASS | TC-05-01〜06。`capture_authenticity` は常に `NOT_PROVEN`。MU2-13〜14 検出 |
| M2-06 Chain Status / Fail-closed | PASS（Pure function と統合 Test）。End-to-end の COMPLETE は **NOT_PROVEN**（WP1 では gate が LINKED にならない） | TC-06-01（15,625 通り）〜07。MU2-15〜18 検出 |
| M2-07 決定論 / Replay | PASS（ローカル、Python 3.9.6）。別 OS・別 Python は **NOT_PROVEN**（CI 未実行） | TC-07-01〜04。MU2-19〜20 検出 |
| TC-00 M1 非干渉 | PASS | M1 期待値ファイルと Evaluator Source / Definition の Hash、Import の向き |

未実装の AC: M2-08〜M2-10（Gate、WP2）、M2-11（Transport、WP4）、M2-12（実 E2E、WP5）。

## 3. 検証結果（ローカル、macOS、`/usr/bin/python3` 3.9.6、cfn-lint 1.46.0、cfn-guard 3.2.1、ruff 0.8.6、mypy 1.14.1）

| Gate | Command | Exit | 結果 |
| --- | --- | --- | --- |
| 全体 pytest + coverage | `python3 -m pytest -p no:cacheprovider -q --cov=iacreview --cov=benchmark/harness --cov-fail-under=80` | 0 | JUnit: 7,935件、PASS 7,899 / FAIL 0 / ERROR 0 / SKIP 36、coverage 95.00%、841 s |
| Chain Test | `python3 -m pytest -p no:cacheprovider -q -rs --junitxml=… tests/unit/test_chain_*.py` | 0 | 158件 PASS、SKIP 0、約107 s |
| Chain CI Check | `python3 .github/scripts/chain_ci_check.py --junit … --expected tests/fixtures/chain_replay/expected.json` | 0 | 必須29件すべて実行、SKIP 0、Validator Source 一致 |
| Clean Copy | 公開対象（`git ls-files --cached --others --exclude-standard`）だけを複写し、`.agents/`・`.kiro/`・`.git` なしで Chain Test と Check | 0 / 0 | 158件 PASS、Check PASS |
| Chain Mutation | `python3 tests/mutation/chain_mutants.py` | 0 | Baseline exit 0（18 Test）、MU2-01〜20 の 20 / 20 検出 |
| M1 Evidence Test | `python3 -m pytest -p no:cacheprovider -q -rs --junitxml=… tests/unit/test_evidence_*.py` | 0 | ローカルは `.agents/` があるため SKIP 0 |
| M1 CI Check（RG-1） | `python3 .github/scripts/evidence_ci_check.py --junit … --expected tests/fixtures/evidence_replay/expected.json` | 0 | §4 の Hash がすべて期待値と一致、`verified_commits` 5 |
| M1 Mutation（RG-4） | 全体 pytest 内の `tests/unit/test_evidence_mutations.py` | 0 | 32 / 32（全体 pytest の PASS に含まれる） |
| Benchmark | `python3 benchmark/harness/run_benchmark.py --cases benchmark/cases --mode combined` | 0 | `status: PASS` |
| Determinism | `PYTHONHASHSEED=random python3 -m pytest tests/property/test_prop_determinism.py` | 0 | PASS |
| Secret scan | `python3 .github/scripts/scan_secrets.py` | 0 | 0 finding（tracked 728 files） |
| Ground_Truth 順序 | `python3 .github/scripts/check_ground_truth_order.py --cases benchmark/cases` | 0 | 17 / 17 |
| Public Preflight | `python3 .github/scripts/public_preflight.py` | 0 | 8 check PASS |
| ruff | `ruff check .` | 1 | 40件（Baseline 40 と同じ）。新規ファイルは 0件 |
| mypy | `mypy iacreview --no-site-packages` | 1 | 12 errors（Baseline 12 と同じ）。`iacreview/chain/` は 0件 |

## 4. M1 固定 Hash の照合（ローカル、M1 CI Check の出力）

| 値 | 観測 | 期待（M1 Baseline） |
| --- | --- | --- |
| `evaluator_source_sha256` | `ee765e0c18ba76b9d4a27a0d4277548f21296757f03a77879763d1824dae58d6` | 一致 |
| `definition_sha256` | `fb4ddef0b86d36e436e4492e1ff2d209812e80b6e993dea47ba07dc7a856b1d0` | 一致 |
| `native_result_sha256` | `24f091d1f8be65603a4d5d2cd62052758295155e00be200b59a8ff45238a2a48` | 一致 |
| `final_report_sha256` | `4b1f2c5441ea9a421bdb0b8d402a608acbf96ced7f128d30f443939746f55b47` | 一致 |
| `legacy_result_sha256` | `731a1846ce5bb6102bea478fbc613b85ccb6b3cf90fc736dd62b8bbeaa8e1748` | 一致 |
| `tests/fixtures/evidence_replay/expected.json` の SHA-256 | `ebe177bdd64e8ec74d90fab0c44ff4f982e93122109c9df8cfa524166346e841` | 一致（TC-00-01） |

注記: M1 CI Check の `changed_since_baseline`（13）と `FORBIDDEN_CHANGE` は `dd6f629..HEAD` の Commit 済み差分を見る。WP1 の変更は未 Commit のため、この値には含まれない。未 Commit の変更範囲は `git status` と `git diff --name-only HEAD -- <変更禁止範囲>`（0件）で確認した。

## 5. M2 の Replay 期待値（Human Review 待ち）

`tests/fixtures/chain_replay/expected.json`（手で記録。Test と CI Check は書き込まない）。**下表は Revision 1 の値。現在の値と変更理由は §10-4**:

| Scenario | `chain_status` | `manifest_sha256` | Payload SHA-256 |
| --- | --- | --- | --- |
| sc01（C01） | INCOMPLETE | `136994dd65ab2115949f8c957f9a7d063e38b80825924938d7da90d6328dec35` | `0863d3bf148e9b93dc5ce6af6382acb24f203484a14ccc3e87364aecee6d6b51` |
| sc02（C02） | INCOMPLETE | `e94da38f22e81abac04c82931b31cf5e1cefdfea64a99a0adb0da1a26d36a8c6` | `7a0a074fc56b10cfe410cf04eafbcd9b8001c83797c720ba7b01f91cffa774c5` |

Validator Source SHA-256: `49a4e338c17fc187f4503195e2cc665430e99b163fb6577dc4b23bde6bd10797`。WP1 では gate が評価されないため、両 Chain は INCOMPLETE（`gate_record_missing`）。`iacreview/chain/` を変えると Validator Source が変わり、期待値の更新（Human Review）が必要になる。

## 6. 仕様との差異と注記（Human 確認事項）

| ID | 内容 | 扱い |
| --- | --- | --- |
| N-1 | Reason Code を2つ追加: `gate_evaluation_not_implemented`（gate、NOT_PROVEN）、`link_check_error`（全 Link、INCOMPLETE） | WP1 で gate を LINKED にしないため、また Link 内の予期しない例外を成功にしないため。D-2 で固定した語彙への追加なので確認が必要 |
| N-2 | `finding_id` を整数にした | Review_Report の `ID` は1以上の整数（`finding.py`）。WP0 の例 `"F-0003"` は誤りで、Schema 表の「Review_Report の ID」に合わせた |
| N-3 | TC-04-02 / TC-06-05 の期待値は、そのままでは成り立たない | `finding_refs` は1件以上（Schema）なので、`findings: []` の Report を起点にすると `finding_missing`（BROKEN）が必ず加わる。実装は (a) Finding なし・pass flag true・`errors[]` あり → `review_report_has_errors` を含み BROKEN、(b) Finding あり・`errors[]` あり → INCOMPLETE（exit 32）の2つで Test した。どちらも COMPLETE にならない。Matrix の期待値の修正（(a) は BROKEN）を提案する |
| N-4 | `tools[]` が1件以上という条件（P-A） | `iam-review` だけの Review は `tools: []` になり `review_tool_unavailable` になる。Fixture は `cfn-lint` と `iam-review` の両方で作った。WP5 の E2E でも Review に `cfn-lint` を含める必要がある |
| N-5 | Verification の再計算との比較から Payload の `validator`（Plugin の Source Digest と Python Version）を除いた | 別 Revision・別 Python で作られた正しい Report を BROKEN にしないため。他の Field はすべて比較する |
| N-6 | TC-02-05 は「Manifest の Digest と Git の Contract の不一致」、TC-05-03 は「Store の MANIFEST と Chain Manifest の不一致」として実装 | 検出する条件は同じで、改変の作り方だけが違う |
| N-7 | TC-06-02 の End-to-end の COMPLETE、TC-00-02（`git diff`）は Test ではない | 前者は WP2 で gate が実装されるまで到達できず、Pure function で確認。後者は Command で確認（§4） |
| N-8 | 新 Test が既存の Phase 1 Fixture と Builder（`tests/remediation_bench/casegen.py`、`benchmark/remediation/`）を読む | 読み取りだけで、変更していない |

## 7. Security 上の未解決事項

* Chain Manifest、Store の Raw と MANIFEST、Local Git をすべて整合的に作り直す改変は検出できない（`m2-threat-model.md` §5）。Anchor は WP1 の範囲外
* `capture_authenticity` は常に NOT_PROVEN
* CPU と RSS の上限はない（Phase 1 と同じ残留 Risk）。入力にはサイズ上限がある（Manifest 256 KiB、Review 16 MiB、Verification 4 MiB）
* Validator 自身を変える PR は、CODEOWNERS / Required Check の設定なしでは CI だけで防げない（T-13）。`chain-integrity` は Required Check に登録していない（Ruleset 変更は対象外）
* 外部 Consumer による pass flag の誤読は Chain の外に残る（P-B は WP6）
* `actor_ref`、Gate Record、Approval Authority は未実装（WP2）。`author_association` は権限の証明として扱わない設計（WP0 rev1 §2-3）を WP2 で実装する

## 8. NOT_VERIFIED

* GitHub Actions 上の全 Job（`chain-integrity` を含む）: Push していない
* Linux、Python 3.11 / 3.13 での Chain の Replay Hash と、Verification の再計算の一致: ローカルは macOS の Python 3.9.6 のみ
* `chain-integrity` job の所要時間（ローカルの Chain Test は約107 s。CI では Tool の導入が加わる）

## 9. 次の WP へ進む条件

1. Human Review: 本書 §6 の N-1〜N-8、`test_ci.py` の変更、`expected.json` の値
2. Commit の承認と、CI（`chain-integrity` を含む全 Job）の結果の確認。Linux / Python 3.11 / 3.13 で Replay Hash が一致すること
3. WP2 の開始承認。WP2 で gate の実装に伴い `iacreview/chain/` が変わるため、`expected.json` の更新を WP2 の Review に含める

## 10. Revision 2（WP1 最終監査を受けた限定修正、95/100 条件付き承認）

Commit、Push、Merge、Ruleset 変更、WP2 の実装はしていない。M1 の固定 Hash と Frozen Evidence は無変更。

### 10-1. N-5 Validator Identity

| 項目 | 実装 |
| --- | --- |
| 形の検査 | `links.validator_identity_problems`。`payload.validator` は `name`（文字列）、`plugin_version`（文字列または null）、`source_sha256`（小文字 64 hex）、`python`（`X.Y`）の4 key だけ（`verification-report-schema.md`、`report.validator_identity`）。未知 key、欠落 key、型違反は `report_invalid`（INCOMPLETE）。`load_report` で検査し、違反した Report は他の Link の比較にも使わない |
| Digest との責務分離 | 変更なし。ファイル Digest、`metadata.payload_sha256`、Manifest の `payload_sha256` の3つは `validator` を含む Payload 全体を見る。`validator` を除くのは再計算との比較（`check_verification`）だけ |
| Diagnostic | `links.identity_diagnostic`。Report と再計算の Identity の一致 / 不一致（違う Field 名）を `validator_identity_matches` / `validator_identity_differs` / `validator_identity_not_compared` として記録する。語彙は `status.DIAGNOSTICS`（Reason Code と重ならない）。Link と Chain の Status は変えない |
| Payload との分離 | Diagnostic は Result の `metadata.diagnostics` にだけ置く（Payload の Digest の対象外）。Payload には環境に依らない定数 `observed.validator_identity: "NOT_PROVEN"` だけを入れる |
| NOT_PROVEN の明示 | 各 Diagnostic に `authenticity: NOT_PROVEN`、`implementation_equivalence: NOT_PROVEN`。Identity が一致しても真正性の証明ではなく、不一致でも挙動の違いを示さない |

Schema への追加（Human 確認事項）: Result の `metadata` に `diagnostics` を追加した（`m2-schemas.md` §3 の metadata は3 key）。Payload の key は変わらない。

### 10-2. N-6 仕様どおりの攻撃条件の Test（既存 Test は残した）

* `test_tc_02_05_literal_…`: config commit の Contract を Git 上で1 byte 変えた Commit（Base の祖先関係は保つ）と、承認時の Digest のままの Manifest → `contract` BROKEN `contract_digest_mismatch`、`config_not_ancestor_of_base` なし
* `test_tc_05_03_literal_…`: Raw、Envelope、Store MANIFEST を整合的に書き換え、M1 Integrity が PASS する状態にした Store と、元の Digest のままの Chain Manifest → `github` BROKEN、コードは `store_manifest_mismatch` だけ

### 10-3. 追加した Test

TC-03-09（Schema 違反 11種）、TC-03-10（1 Field の変更 5種と一致時）、TC-03-11（Identity を変えた Digest 不一致 3種）、TC-03-12（Diagnostic が Payload に入らないこと、再計算がないとき `not_compared`）、Diagnostic の語彙、TC-02-05 / TC-05-03 の字義どおりの Test。`chain_ci_check.py` の必須 Test に6件を追加（29 → 35）。既存 Test の削除なし。既存の Assertion の変更は2件で、どちらも新しい定数 / key を含めて厳密化した（TC-03-01/02 の `observed`、TC-07-02 の metadata key）。

N-5 の新しい処理に対する Mutant は追加していない（MU2-21 以降は Matrix で WP2・WP4 に割り当て済みで、追加には事前の Human 承認が要るため）。新しい処理は Test でのみ検証している。

### 10-4. WP1 Regression Anchor の新旧

| 項目 | 旧（Revision 1） | 新（Revision 2） |
| --- | --- | --- |
| Validator Source | `49a4e338c17fc187f4503195e2cc665430e99b163fb6577dc4b23bde6bd10797` | `0790a1ca4265105a2fe34c434465ede979614cedc7b1c0e5bf8b42d4677b23ee` |
| SC-01 payload | `0863d3bf148e9b93dc5ce6af6382acb24f203484a14ccc3e87364aecee6d6b51` | `7c5c30cf9c07f330d58f27c42b52cc5e14b4652bde0ad8703178ce85eccc7940` |
| SC-02 payload | `7a0a074fc56b10cfe410cf04eafbcd9b8001c83797c720ba7b01f91cffa774c5` | `f24c000188bca6349fcb75c3f130115d12225d7e52047ca22c4f20ed925b6736` |
| SC-01 manifest | `136994dd65ab2115949f8c957f9a7d063e38b80825924938d7da90d6328dec35` | 同じ |
| SC-02 manifest | `e94da38f22e81abac04c82931b31cf5e1cefdfea64a99a0adb0da1a26d36a8c6` | 同じ |
| chain_status | INCOMPLETE / INCOMPLETE | 同じ |

変更原因: (1) `iacreview/chain/` の変更による Validator Source の変化、(2) verification Link の `observed.validator_identity: "NOT_PROVEN"` の追加。新しい Payload からこの2点を元に戻すと、旧 Payload の SHA-256（両 Scenario）とちょうど一致することを確認したうえで値を記録した（実測値の無条件の採用ではない）。Anchor は回帰の検出用で、実装の正しさの独立した証明ではない。

### 10-5. 最終検証（ローカル、macOS、Python 3.9.6）

| Gate | Exit | 結果 |
| --- | --- | --- |
| Chain Test | 0 | 183件 PASS / FAIL 0 / SKIP 0、121 s |
| Chain CI Check | 0 | 必須35件、SKIP 0、Validator Source 一致 |
| Chain Mutation | 0 | 20 / 20 |
| 全体 pytest + coverage | 0 | 7,960件（PASS 7,924 / FAIL 0 / ERROR 0 / SKIP 36）、coverage 95.03%、854 s |
| M1 Evidence Test + M1 CI Check | 0 / 0 | Evaluator `ee765e0c…`、Definition `fb4ddef0…`、native `24f091d1…`、final report `4b1f2c54…`、legacy `731a1846…`、`verified_commits` 5、M1 `expected.json` `ebe177bd…` |
| Clean Copy（`.agents`・`.kiro`・`.git` なし） | 0 / 0 | Chain Test 183件 PASS、Check PASS |
| Benchmark / Determinism / Secret scan / Ground_Truth / Public Preflight | 0 | PASS / PASS / 0 finding（728 files）/ 17/17 / PASS（759 files） |
| `git diff --check` | 0 | 新規 31 ファイルも行末空白・CRLF・末尾改行の欠落 0件 |
| ruff / mypy | 1 / 1（advisory） | 40件 / 12件（Baseline と同じ）、新規ファイル 0件 |
