# Phase 2 / M2 — 実 GitHub Read-only E2E 計画（1 Scenario）

* 状態: **計画のみ（WP0 rev1）。実行していない。** GitHub API へのアクセス、Credential の利用、Raw の取得・保存はしていない。実行は WP5 で、本計画とは別の Human 承認が必要
* 前提: M1 の `docs/v2/phase2/m1/wp5/github-e2e-verification-plan.md`（以下「M1 計画」）。Endpoint の権限、PII、保存先、失効の規則は M1 計画を引き継ぎ、異なる点だけを本書に書く
* 対応 AC: M2-11（Transport の安全性、fixture）、M2-12（実 E2E）

## 1. 目的と、置かない期待値

目的: 実 GitHub の Raw を起点に、M2 の Chain（Subject → Contract → Review → Verification → Gate → GitHub Evidence）を1回だけ組み立て、Chain Validator が決定論的に判定できることを示す。

* 判定（各 Link の Status と `chain_status`）の**期待値は置かない**。結果から Ground Truth を逆算しないため（M1 計画 §1 と同じ）
* 合格条件は「手順が成立し、判定が再現し、Fail-closed が守られ、Secret が漏れない」ことに置く（§7）
* 単一 Owner の Repository では Gate Link は NOT_PROVEN（GV-2 Approval Authority）になる見込み（§6）。これは失敗ではなく、事前に予測した限界として記録する。第2 Account は必須にしない（D-4）
* Merge Enforcement（GV-5）は M2 の対象外で、E2E でも判定しない・主張しない

## 2. Scenario の選択

第一候補（Human 決定 D-4）: **SC-02 `iam-inline-policy-overbroad-v1`**（1 Scenario、1 Candidate）。Finding の存在を事前確認し、満たさなければ Human と再決定する

| 観点 | SC-01（DynamoDB） | SC-02（IAM、推奨） |
| --- | --- | --- |
| Review Finding の起点 | Base の Template に Review Finding が出るかは未確認 | `Action: "*"` などの過大な Allow は IAM Review の対象で、Finding が出る見込み（NOT_VERIFIED。§5 の事前確認で確定） |
| Phase 1 の Fixture | `benchmark/remediation/scenarios/` | 同じ |
| 機微情報 | 少ない | Policy 文に Account id や ARN を入れない合成 Template を使う |

事前確認（WP5 の最初の Step、ネットワーク不要）: 合成 Template の Base 版に `iac-review` を実行し、対象 Role に Finding が1件以上出ること、`errors[] == []` で全 Tool が available であることを確認する。満たさなければ実行を止め、Scenario を Human と再決定する。

## 3. 対象 Repository と Human の操作

対象: Human が所有する検証専用の Repository 1つ（`<owner>/<demo-repo>`）。名前、Owner、App id は文書と Repository に書かない。Targets ファイルは `.agents/` 配下（Git 管理外）。

Human が行う操作（Agent は行わない。Repository の状態を変える操作は Agent の作業に含めない）:

1. 検証用 Repository の用意と、`main` への合成 Template（SC-02 の Base 版）の Commit
2. Contract の作成と `main` への Commit（この Commit が `config_commit`。Phase 1 の承認方式）
3. Candidate の Branch と PR の作成（Contract の範囲内の正しい修正 1件）
4. PR への Review（単一 Owner では自分の PR を Approve できないため、`COMMENTED` の Review になる見込み）
5. 任意: PR の Merge。Merge するかどうかで `merge_decision` の値が変わるだけで、計画の合否は変わらない
6. fine-grained PAT の作成（対象 Repository 1つ、§4 の read 権限だけ、有効期限7日以内）と、取得後の Revoke

Trusted Gate Workflow（`docs/v2/phase1/ci/remediation-gate.yml`）の設置は必須にしない。設置する場合の Check Run は観測値として取得するが、Chain の Verification Link は Local の再計算で作る（§5）。

## 4. 取得する Endpoint（M2 Transport の allowlist）

M2 の Transport は次の Template だけを受け付ける（閉じた集合）。`{o}/{r}` は Targets ファイルの値、`{n}` は PR 番号（10進）、`{sha}` は 40 hex、`{path}` は Contract / Template の Repository 相対 Path（M1 の `ENDPOINT` 正規表現を満たし、`..` を含まない）。

| Role（M2） | Method / Endpoint | 用途 | 必要な権限（fine-grained PAT） |
| --- | --- | --- | --- |
| `pull` | `GET /repos/{o}/{r}/pulls/{n}` | PR の base / head SHA、作成者 id、Merge 状態 | Pull requests: read |
| `pull_reviews` | `GET /repos/{o}/{r}/pulls/{n}/reviews?per_page=100` | Review の `state`、`commit_id`、`user.id`、`submitted_at` | Pull requests: read |
| `pull_commits` | `GET /repos/{o}/{r}/pulls/{n}/commits?per_page=100` | PR の Commit 列（Head の確認） | Pull requests: read |
| `compare` | `GET /repos/{o}/{r}/compare/{sha}...{sha}` | API が示す merge base と ahead / behind（Local Git の祖先関係と照合） | Contents: read |
| `contract_contents` | `GET /repos/{o}/{r}/contents/{path}?ref={sha}`（ref = `config_commit`） | Contract bytes（Local Git の blob と照合） | Contents: read |
| `template_contents` | 同上（ref = Base、Head の2回） | Template bytes（Local Git の blob と照合） | Contents: read |
| `check_runs`（任意） | `GET /repos/{o}/{r}/commits/{sha}/check-runs?per_page=100` | Gate を設置した場合の観測 | M1 計画 E-5 のとおり、権限は実行前に確認（NOT_VERIFIED） |

取得しないもの: Job Log（E-3 の Token マスク行で Secret Gate に拒否される見込み）、Artifact（E-1 Redirect、E-2 zip）、`/user`、`/user/installations`、Secret、Environment、Ruleset の書き込み、GraphQL の `mutation`。

Request 数の見込み: 7〜9 件（Pagination があれば増える）。Rate Limit の問題はない見込み（実測なし）。

Transport の規則（M2-11 で fixture により検証）:

* `gh api --include --method GET <endpoint>` を argv 配列で実行し、`iacreview.proc.run_bounded` で timeout・出力上限・process group 停止を付ける。Shell を使わない
* `--method` は GET 固定。GraphQL は M2 の E2E では使わない（allowlist にない）
* Redirect を追わない（`gh` の既定動作を前提にせず、3xx は `http_error` として保存し、追加の Request をしない）
* Dry-run 既定。`--execute` なしでは、取得予定の Endpoint 一覧と件数だけを表示する
* Token の値を読まない・渡さない・記録しない。保存する Header は M1 Collector の allowlist だけ
* 上限は M1 Collector の既定値（1 Page 8 MiB、1 Capture 64 MiB、50 Page）を使い、変更しない。より小さい値を使うかは Human が決める

## 5. Chain の組み立て（すべて Local、ネットワーク不要）

1. Local Clone: 検証用 Repository を Human が Clone する（または Human 承認の下で Agent が `git clone` / `git fetch` する。読み取り操作）
2. Review: Base の Template に `iac-review` を実行し、Review_Report を Chain Root に置く。`finding_refs` は対象 Role の Finding を指す
3. Verification: Phase 1 の `verify --repo <clone> --base <base> --head <head> --config-rev <config_commit> --contract <path>` を Local で実行（`acquisition: local_recompute`）。Tool は Profile の Pin（cfn-lint、cfn-guard）を使う。Tool 不在なら `recompute_unavailable`（NOT_PROVEN）として記録し、成功扱いにしない
4. GitHub Evidence: §4 の Raw を M1 Collector + M2 Transport で取得し、M1 Secret Gate → M1 Store（新しい Revision）に保存。M1 Integrity Validator を実行
5. Gate Record: Builder が Store の `pull` / `pull_reviews` から `candidate_review` と `merge_decision` を、Local Git から `contract_approval` を作る
6. Chain Manifest: Builder が 1〜5 の参照から作る
7. Chain Validator を実行し、Chain Result を保存

照合（Local と API の二重確認）:

* `compare` の merge base と ahead / behind が、Local の `merge-base --is-ancestor` の結果と矛盾しないこと。矛盾は `subject` Link の `BROKEN`（`subject_mismatch`）
* `contract_contents` と `template_contents` の本文（base64 を展開した bytes）が、Local Git の blob と一致すること。不一致は `BROKEN`
* `pull` の `head.sha` と `base.sha` が Manifest の Subject と一致すること。PR の Base は Branch の先端なので、Contract の `config_commit` との祖先関係で判断し、`base.sha` との完全一致は要求しない（WP5 で確定）

## 6. 予測される限界（実行前に固定）

| 項目 | 予測 | 理由 |
| --- | --- | --- |
| Gate Link | NOT_PROVEN。GV-2 が `approval_not_shown`（単一 Owner は自分の PR を Approve できず、`COMMENTED` だけになる）。GV-1、GV-3、GV-4 は Raw と Commit の照合で判定し、期待値を置かない | 単一 Owner |
| GV-5 Merge Enforcement | 判定しない（M2 の対象外） | Human 決定 |
| `capture_authenticity` | NOT_PROVEN | 応答に署名がない（M1 と同じ） |
| Verification の `api_artifact` | 使わない | E-1、E-2 |
| Job Log の Evidence | 取得しない | E-3 |
| Chain Status | `NOT_PROVEN` 以下になる見込み（Gate Link のため） | 上記。COMPLETE を期待値にしない |

第2の Account（Write 権限、Bypass なし）を Human が用意した場合だけ、`distinct_actor` の Approve が作れる。その場合も Account の背後の人間の同一性は主張しない。用意するかは Human の判断で、M2 の必須条件にしない。

## 7. 合格条件（実行前に固定、M2-12）

| ID | 条件 | 観測 |
| --- | --- | --- |
| E2E-1 | 取得した全 Page が Secret Gate を通って Store に入る。入らなかった Page は理由付きの Capture Error として記録される | Store の MANIFEST と Capture Error の一覧 |
| E2E-2 | M1 Integrity Validator が、取得した Revision を PASS とする。PASS でなければ `github` Link は `INCOMPLETE` と記録され、それ以上の主張をしない | Integrity の出力 |
| E2E-3 | Chain Validator の Result が、同じ入力で同一 Process 2回、別 Process 2回（`PYTHONHASHSEED=random`）とも byte 単位で一致する | 4つの SHA-256 |
| E2E-4 | すべての `LINKED` に、再計算の根拠（Digest の再計算、Git の照合、Raw からの再生成）が Result の `codes` / `observed` と Test 済みの経路で対応している。Manifest の申告だけで `LINKED` になった Link がない | Result と、同じ入力に対する Unit Test の経路の対応表 |
| E2E-5 | §5 の Local / API の照合結果が Result に反映されている | Result の `subject` / `contract` Link |
| E2E-6 | Token はどこにも出ない。Login 名は非公開 Store の Raw の中にだけあり、Chain Result、Chain Manifest、Gate Record、作業報告、Log に出ない | Secret Scan、canary 文字列の検索（Token の Prefix、Login 名） |
| E2E-7 | PAT の Revoke を Human が確認した | Human の報告（Human 提供 Evidence として記録） |

E2E-1〜E2E-6 のいずれかが満たされなければ M2-12 は FAILED。実行できなかった（承認なし、Repository なし、Tool なし）場合は NOT_PROVEN。

## 8. 保存、公開、削除

* 保存先: `.agents/tasks/phase2-m2/github-e2e/<run-id>/`（Git 管理外。Directory 0700、ファイル 0600）。Chain Root と M1 Store を同じ Run Directory の下に置く
* 公開: Human が承認した要約だけ（Chain Result の Payload の SHA-256、各 Link の Status とコード、Replay の Hash）。Raw、Gate Record の `actor_ref`、Repository 名は公開しない
* 保存期間: M2 の最終 Review まで（提案）。期間と削除は Human が決める。Agent は Store を削除しない
* 失効: 取得後すぐに PAT を Revoke。確認まで次の作業に進まない

## 9. Human 承認が必要な事項（WP5 開始時）

1. 検証用 Repository、Scenario（SC-02 推奨）、Targets ファイル
2. §3 の Human 操作の実施
3. PAT の作成（権限・期限・対象）
4. Local Clone / fetch の実施者（Human か、承認下の Agent か）
5. 取得の実行（`--execute`）
6. 第2 Account を用意するか（任意）
7. 保存期間、公開する要約、削除
