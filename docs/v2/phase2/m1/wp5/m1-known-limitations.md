# Phase 2 / M1 — Known Limitations

> **Pre-Commit Remediation の注記（後から追加）**: 本書の Hash と実測値（Evaluator Source `dfaec952…`、Definition `efd934b0…`、固定 Manifest `360d731b…`、Replay `4dc16d9b…`、Final Report `27eecd68…`、Legacy 結果 `f205b5d4…`、Mutant 29件など）は Pre-Commit Remediation の前の値で、最終 Source では再現しない。`docs/v2/phase2/m1/wp5/legacy-reevaluation-results.json` は最終 Source から再生成し直した。WP4 の結果ファイルは公開対象から外した。最終の値は `docs/v2/phase2/m1/precommit/remediation-report.md` を参照する。

* Source: WP0〜WP5 の成果物、`iacreview/evidence/`、`docs/v2/phase2/m1/wp5/github-e2e-verification-plan.md`
* 目的: M1 Evidence Integrity Foundation で、示せていないこと、示せないこと、前提にしていることを1か所にまとめる
* 状態: WP5 時点。Git Commit なし

## 1. 証明の範囲

| 項目 | 状態 | 理由 |
| --- | --- | --- |
| 実 GitHub Raw による End-to-End Replay | NOT_PROVEN | 実 Raw を取得していない（計画のみ） |
| Raw の出所（`capture_authenticity`） | NOT_PROVEN（常に） | 全 Envelope の `authenticity_verified` は false。Store が示すのは、保存後に変わっていないことだけ |
| 第三者による独立した再現 | NOT_PROVEN | 実施していない。Clean Checkout Test は同じ Machine、同じ Python で行った |
| Phase 1 当時の Raw への到達 | NOT_PROVEN | Phase 1 は helper が転記した Field だけを残した（`RAW_UNAVAILABLE`） |
| Phase 1 helper の Capture の完全性 | NOT_PROVEN | 同上 |
| Source 管理の完了（M1-01） | NOT_PROVEN | 未 Commit |
| CI 上の結果 | NOT_VERIFIED | Push していない |
| 別 OS・別 Python Version での再現 | NOT_VERIFIED | macOS と Python 3.9.6 だけで実行した |

## 2. Rule と Criterion

* 26 Criterion すべてに IMPLEMENTED の Rule がある。Rule が実装済みであることは、PASS を意味しない
* S7-17（`same_app_with_key`）と S7-18（G8、AC28、admin bypass、same_app_with_key）は限界として常に NOT_PROVEN
* S7-19 は4つの問いのうち Q2（`POST /rulesets` が `integration_id` を受け付けるか）と Q3（`user/installations` の権限）に、読み取り専用の Evidence Role がない。このため S7-19 は現在の Evidence では PASS にならない
* S7-19 の判定は、§7 の条文から Rule を作るときの解釈を含む（`wp5-acceptance-report.md` §3）。FAILED を返さないことも解釈の一つで、Human の確認を要する
* P2-IP-01（Issuer Pinning の独立証明）は、App の失敗が BLOCKED を説明する Head では NOT_PROVEN。G3 / G3S / G6 は Phase 1 の Evidence でこの状態にある
* P2-AI-01 / 02 は「承認済み Source」の記録を前提とする。Phase 1 の G11 には事前に固定された承認済み Source がない

## 3. Capture と Security Gate

* 実 GitHub への Transport はない。Collector は Transport 関数を受け取り、Repository 内の Transport は Test 用の Fake だけ
* Collector は Redirect を追わない。Job Log と Artifact の Download（別 Host への 302）は取得できない
* Artifact の zip は Binary として Secret Gate に拒否される
* 実際の Job Log は、マスク済みの `AUTHORIZATION: basic ***` 行で拒否される見込み（FP-1、Human 決定 H-1〜H-4）
* GraphQL の Cursor Pagination は追わない。`hasNextPage` が true なら不完全として記録する
* Secret Gate の PII 規則は email だけを検出する。Login 名、氏名、住所などは検出しない
* Secret Scan と Secret Gate で 0件でも、Secret が存在しないことの証明にはならない

## 4. 再現性

* 再現性は Canonical Serialization と固定入力に依存する。浮動小数点、時刻、Host Path は出力で拒否する
* 結果には Evaluator Source の SHA-256 と Definition の SHA-256 が入る。Source や Definition を1文字でも変えると、以前の結果は再現されない（`SOURCE_CHANGED` / `DEFINITION_CHANGED` で拒否）。WP4 の `legacy-reevaluation-results.json`（SHA-256 `b17e6881…29f7d544`）は WP4 時点の記録として残し、現在の Source では再現しない。現在の結果は WP5 の同名ファイル
* Mutation Test の検出率は、実施した29個の Mutant に対する値だけを示す。一般的な欠陥検出率ではない

## 5. Legacy Re-evaluation

* 入力は Phase 1 helper の転記 Field で、当時の GitHub 応答ではない
* 再評価は `.agents/` の非公開 Evidence を必要とし、公開 Checkout では実行できない（関連 Test は `NOT VERIFIED` で Skip）
* E21 の helper 分類（G2 などが FAILED）と再評価結果の違いは、Legacy Map の記述（「wrong rule」）と E20 の `reclassified_from` で確認できる範囲だけを説明している。当時の helper の Source Revision は不明（`HELPER_REVISION_UNKNOWN`）

## 6. 運用上の前提

* Store を置く Directory は単一 User が書き込む前提。複数 Process の同時書き込みは扱わない
* Symbolic Link は追わない（`O_NOFOLLOW`）。Store の外の Path は Containment Base で拒否する
* Synthetic Example は Test Helper（`tests/unit/evidence_synth.py`）を使う。製品の Command ではない
* 計測していない: Setup にかかる時間、第三者の導入作業、大きな Store での性能
