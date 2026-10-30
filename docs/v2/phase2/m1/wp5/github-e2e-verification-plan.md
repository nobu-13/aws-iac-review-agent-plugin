# Phase 2 / M1 / WP5 — GitHub E2E Verification Plan（計画のみ・未実行）

* Source: WP5 指示 §9、`docs/v2/phase1/app-demo-plan.md` §3〜§7、`iacreview/evidence/collector.py`（許可 Method / Endpoint）、`iacreview/evidence/facts.py`（Role）、GitHub Docs「Permissions required for fine-grained personal access tokens」（2026-10 に参照）
* 目的: 実 GitHub API で Raw を取得し、Native Replay を End-to-End で検証するための計画を、実行前に固定する
* 状態: **計画のみ。実行していない**。GitHub API へのアクセス、Credential の利用、Raw の取得・保存はしていない。実行には本計画とは別の Human 承認が必要

## 1. 目的と合否

* 目的: M1-05（Deterministic Replay）の「実 GitHub Raw による End-to-End」を NOT_PROVEN から判定可能にする
* 合格の条件（実行前に固定）:
  1. 取得した全 Page が Secret Gate を通り、`COMPLETE` で Store に入る。または、入らなかった理由が Capture Error として記録される
  2. Integrity Validator が対象 Group を PASS とする
  3. 同じ Spec で Replay を2回、別 Process で2回実行し、出力の SHA-256 が一致する
  4. 判定（PASS / FAILED / NOT_PROVEN）は Rule の出力で決まり、本計画では期待値を置かない。期待値を置くと Ground Truth を結果から逆算することになるため
* 実行しても PASS にならないもの: `capture_authenticity`。HTTPS 応答であっても、Envelope の `authenticity_verified` は false のまま。GitHub の署名付き応答がないため

## 2. 対象 Repository

* 対象: Human が所有する検証専用の Repository 1つ（以下 `<owner>/<demo-repo>`）。Phase 1 の Demo Repository を使うかどうかは Human が決める
* 本書と Repository 内の文書には、実際の Owner 名、Repository 名、App id を書かない。実行時の Targets ファイルは `.agents/` 配下に置き、Git 管理しない
* 対象外: 他人の Repository、Organization 全体、Production の Repository

## 3. 使用する Endpoint（読み取りのみ）

Collector が許可するのは GET と、GraphQL の POST（Query のみ）。書き込み Endpoint は使わない。

| Role（`facts.ROLE`） | Method / Endpoint | 必要な権限（fine-grained PAT、GitHub Docs の表） |
| --- | --- | --- |
| `rollup`、`rollup_before` | `POST /graphql`（`statusCheckRollup`、`isRequired`、`mergeStateStatus`、`mergeable`） | GraphQL は認証が必須。必要な権限は実行前に確認（NOT_VERIFIED） |
| `check_runs` | `GET /repos/{o}/{r}/commits/{sha}/check-runs?per_page=100` | 参照した表に Check Runs の行がない。実行前に確認（NOT_VERIFIED） |
| （commit status） | `GET /repos/{o}/{r}/commits/{sha}/statuses` | Commit statuses: read |
| `gate_run` | `GET /repos/{o}/{r}/actions/runs/{run_id}` | Actions: read |
| `gate_jobs`、`steal_jobs/*` | `GET /repos/{o}/{r}/actions/runs/{run_id}/jobs` | Actions: read |
| `gate_log_verify` | `GET /repos/{o}/{r}/actions/jobs/{job_id}/logs` | Actions: read |
| `steal_runs` | `GET /repos/{o}/{r}/actions/runs?head_sha={sha}&per_page=100` | Actions: read |
| `steal_annotations/*` | `GET /repos/{o}/{r}/check-runs/{id}/annotations` | 表に行がない。実行前に確認（NOT_VERIFIED） |
| `report_artifact` | `GET /repos/{o}/{r}/actions/runs/{run_id}/artifacts`、`GET /repos/{o}/{r}/actions/artifacts/{id}/zip` | Actions: read |
| `rules_main` | `GET /repos/{o}/{r}/rules/branches/main` | Metadata: read |
| （ruleset） | `GET /repos/{o}/{r}/rulesets/{ruleset_id}` | Metadata: read |
| `published_contents` | `GET /repos/{o}/{r}/contents/{path}?ref={sha}` | Contents: read |
| （PR） | `GET /repos/{o}/{r}/pulls/{n}` | Pull requests: read（または Contents: read） |

読まないもの: `GET /user/installations`（GitHub App の user access token が必要。S7-19 Q3 は NOT_RUN のまま）、`POST /repos/{o}/{r}/rulesets`（書き込み。S7-19 Q2 は答えられない）、App の JWT や Installation Token を使う Endpoint、Secret、Environment の設定。

Token は fine-grained PAT とし、対象 Repository 1つだけ、上の表の read 権限だけを付ける。有効期限は最短（7日以内）にする。

## 4. 既知の Gap（実行前に解決するか、NOT_PROVEN を受け入れる）

| Gap | 内容 | 影響 |
| --- | --- | --- |
| E-1 Redirect | Job Log と Artifact の Download は別 Host への 302 を返す。Collector は Redirect を追わず、200 以外を `http_error` とする | `gate_log_verify` と `report_artifact` を API から取得できない。S7-03 / S7-03b / S7-06 は NOT_PROVEN |
| E-2 Binary | Artifact は zip。Secret Gate は Binary を走査できないものとして拒否する | `report_artifact` を API Evidence として保存できない（展開した JSON を LOCAL Evidence にする案は Human 判断） |
| E-3 FP-1 | 実際の Job Log には、マスク済みの `AUTHORIZATION: basic ***` 行が含まれる。Secret Gate がこれを検出する見込み | Job Log が拒否される。規則の変更は Human 決定 H-1〜H-4 |
| E-4 GraphQL Pagination | `statusCheckRollup.contexts` の `hasNextPage` が true の場合、Collector はその Capture を不完全とする（Cursor を追わない） | Context が100件を超えると S7-08 などが NOT_PROVEN |
| E-5 権限の未確認 | Check Runs、Annotations、GraphQL に必要な fine-grained 権限を、参照した表で確認できなかった | 実行前に GitHub Docs と `X-Accepted-GitHub-Permissions` で確認する |

## 5. 保存対象、PII / Secret Risk

| 保存する Response | 含まれうる PII / Secret | 対策 |
| --- | --- | --- |
| GraphQL rollup | Login 名（`creator.login`）、Avatar URL | Secret Gate の PII 規則（email のみ検出）。Login 名は検出しない。保存先を非公開にし、公開しない |
| Check Runs、Statuses | App 名、Login 名、外部 URL | 同上 |
| Actions runs / jobs | 実行者の Login、Branch 名 | 同上 |
| Job Log | Token のマスク行、環境変数名、Path | Secret Gate。E-3 のとおり拒否される見込み |
| Contents | 対象 Repository の Workflow や Template | Secret Gate（base64 を展開して検査） |
| Rules / Ruleset | Bypass Actor の id | 同上 |

Response Header は Collector が許可した Header だけを保存する。`Authorization` は保存しない。Token は Log、Envelope、Report、作業報告に出さない。

## 6. Pagination、取得量、Size Limit

* REST: `Link: rel="next"` を同じ Resource の範囲でだけ追う（Collector の既定）。範囲外の next は拒否し、`pagination_next_refused` を記録する
* 上限（Collector の既定値、`collector.py` L55-57）: 1 Page 最大 8 MiB、1 Capture 合計最大 64 MiB、最大 50 Page。Secret Gate の走査上限は 8 MiB（`secretgate.py` L54）。超えた Capture は `byte_limit_exceeded` / `page_limit_reached` を記録して不完全とし、成功にしない。実行時に小さい値（例: 1 MiB / 8 MiB / 10 Page）を指定するかは Human が決める
* 取得量の見込み: 1 Scenario あたり 10〜15 Request、全 11 Scenario で 200 Request 以下。認証済み REST の Rate Limit（5,000 / 時）を超えない。実測していない

## 7. 保存先、保存期間、削除・失効

* 保存先: `.agents/tasks/phase2/github-e2e/<run-id>/evidence-store/`（Git 管理外、Directory 0700、ファイル 0600）
* Repository に Commit しない。公開する場合は、Human が別途承認した要約（Hash と判定）だけにする
* 保存期間: Human の M1 最終 Review が終わるまで。期間は Human が決める（提案は30日）
* 削除: Store の Revision は書き換えない。削除は Human が Directory ごと行う。Agent は削除しない
* 失効: 取得が終わったら、Human が PAT をすぐに Revoke する。失効を確認するまで次の作業に進まない

## 8. Human 承認が必要な操作

1. 対象 Repository の決定と、Targets ファイルの作成
2. fine-grained PAT の作成（権限・期限・対象 Repository）。Agent は Token を作らず、値も読まない
3. Gap E-1〜E-5 の扱い（解決するか、NOT_PROVEN を受け入れるか）
4. 取得の実行。Scenario PR の作成や再実行など、Repository の状態を変える操作は本計画に含めない。必要なら別の承認を得る
5. 保存期間、公開範囲、削除の実行
6. PAT の Revoke

## 9. 想定される NOT_PROVEN

| 項目 | 理由 |
| --- | --- |
| `capture_authenticity` | 応答の署名がない。HTTPS だけでは Raw の出所を事後に示せない |
| S7-03、S7-03b、S7-06 | E-1、E-2、E-3 のいずれか |
| S7-19 Q2、Q3 | 読み取り専用の取得では答えられない |
| S7-17、S7-18 | 限界として定義された項目 |
| P2-AI-01 | Local の Git Tree と承認済み Source の記録が別途必要 |
| G7 | 実行されていない Scenario |
| 第三者による再現 | 本計画の範囲外 |
