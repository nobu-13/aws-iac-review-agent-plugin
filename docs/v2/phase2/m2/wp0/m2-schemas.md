# Phase 2 / M2 — Schema 案（Chain Manifest、Gate Record、Chain Result）

* 状態: **WP0 の Schema 案 rev2（WP2 Design Audit の Human Review 91/100、D2-1〜D2-6 を反映）。未実装。** WP2 Final Specification Review（97/100）で承認された S-1〜S-10（Gate Record の Record 単位の判定、`docs/v2/phase2/m2/wp2/wp2-gate-record-decision-table.md`）を §2、§2-4、§4 に反映した（rev2 + S-1〜S-10）。 rev1 で固定した語彙に対する rev2 の変更は `wp0-revision-2.md` に記録した。§1（Chain Manifest）と §3-1（Exit code）は rev1 から変更なし。確定後の変更は新 Version の Schema とし、Human の承認を要する
* 既存 Schema は変更しない: Review_Report 1.0.0、Finding 13 field、StructuredError、Delta_Report、Remediation_Verification_Report 0.1.0、M1 Envelope / Store / Definition / Evaluation / Final Report
* 共通規則（M1・Phase 1 と同じ）:
  * JSON、UTF-8。重複 key、未知 key、`NaN` / `Infinity`、浮動小数点数は拒否する
  * Canonical bytes = `json.dumps(obj, sort_keys=True, ensure_ascii=True, separators=(",", ":"))` を ASCII で encode したもの
  * Digest は Canonical bytes の SHA-256（小文字16進64桁）。Digest は改変の検出であり、認証ではない
  * Host の絶対 Path、時刻（Gate Record の Raw 由来の時刻を除く）、Token、Login 名、Template の値、Tool の出力本文を書かない
  * 列挙値はすべて閉じた語彙。語彙外の値は Schema 違反

## 1. Chain Manifest（`iacreview.chain.manifest/1`）

役割: Chain を構成する Artifact の**参照の一覧**。Manifest 自身の記述は信用しない。Chain Validator は Manifest の各参照から対象の bytes を読み、Digest と関係を再計算する。Manifest に書かれた判定（例: `decision`）は入力として受け取らない（Field を持たない）。

```json
{
  "manifest_format": "iacreview.chain.manifest/1",
  "chain_id": "sc02-demo-0001",
  "repository_id": "r:3f2a9c1d0b7e",
  "subject": {
    "base_commit": "<40 hex>",
    "head_commit": "<40 hex>"
  },
  "contract": {
    "config_commit": "<40 hex>",
    "contract_path": "remediation/contracts/sc02.yaml",
    "contract_sha256": "<64 hex>"
  },
  "review": {
    "review_report": {"locator": "artifacts/review-base.json", "sha256": "<64 hex>"},
    "finding_refs": [
      {"finding_id": 3, "identity_key_sha256": "<64 hex>", "finding_sha256": "<64 hex>"}
    ]
  },
  "verification": {
    "report": {"locator": "artifacts/remediation-report.json", "sha256": "<64 hex>"},
    "payload_sha256": "<64 hex>",
    "acquisition": "local_recompute"
  },
  "gate_records": [
    {"locator": "gate/contract-approval.json", "sha256": "<64 hex>", "kind": "contract_approval"},
    {"locator": "gate/candidate-review.json", "sha256": "<64 hex>", "kind": "candidate_review"}
  ],
  "github_evidence": {
    "store_locator": "evidence-store",
    "revision": "rev-0001",
    "manifest_sha256": "<64 hex>",
    "evidence_ids": ["sc02-pull", "sc02-reviews", "sc02-compare"]
  }
}
```

| Field | 型 | 必須 | 制約 | 検証（Chain Validator） |
| --- | --- | --- | --- | --- |
| `manifest_format` | string | 必須 | `iacreview.chain.manifest/1` 固定 | 不一致は `manifest_invalid`（§3 の Manifest 自体の誤り） |
| `chain_id` | string | 必須 | `^[a-z0-9][a-z0-9-]{2,63}$` | 表示用。判定に使わない |
| `repository_id` | string | 必須 | `r:` + 12 hex。`<owner>/<repo>` の SHA-256 先頭12桁 | GitHub Evidence の Envelope の `repository` から再計算して一致 |
| `subject.base_commit` / `head_commit` | string | 必須 | 40 hex 小文字 | Git で存在、`base ⊑ head`、Verification payload の `subject` と一致 |
| `contract.config_commit` | string | 必須 | 40 hex | `config ⊑ base`、payload `trust.trusted_config_commit` と一致 |
| `contract.contract_path` | string | 必須 | Repository 相対 POSIX、`..`・先頭 `/`・`\`・制御文字なし | config commit の tree から blob を読む |
| `contract.contract_sha256` | string | 必須 | 64 hex | blob の SHA-256、payload `trust.contract_sha256` と一致 |
| `review` | object \| null | 任意 | null は「Review 起点なし」 | null のとき `review_link` は `NOT_PRESENT`。Chain Status は COMPLETE になり得ない（§3 の規則） |
| `review.review_report.locator` | string | 必須（review 時） | Chain Root 相対、Root 外・Symlink 不可 | Root 外は `locator_outside_root` |
| `review.review_report.sha256` | string | 必須 | 64 hex | ファイル bytes の SHA-256。不一致は `review_digest_mismatch`、ファイルなしは `review_artifact_missing` |
| `review.finding_refs[]` | list | 必須（review 時） | 1件以上、`finding_id` 重複なし | §1-1 |
| `verification.report` | object | 必須 | locator と sha256 | ファイル bytes の SHA-256。不一致は `verification_digest_mismatch`、ファイルなしは `verification_artifact_missing` |
| `verification.payload_sha256` | string | 必須 | 64 hex | payload を Canonical 化して再計算。`metadata.payload_sha256` とも一致 |
| `verification.acquisition` | enum | 必須 | `local_recompute` \| `local_import` \| `api_artifact` | 来歴の申告。`api_artifact` は M2 では使えない（E-1 / E-2、`github-e2e-plan.md` §4）。申告は判定を上げない |
| `gate_records[]` | list | 必須 | 0件以上、`kind` は Gate Record の語彙。Manifest の `kind` は表示用で、判定は Record 本体の `kind` で行う | 各 Record を §2 で検証。Record ファイルの Digest 不一致は GV-1 の `gate_record_mismatch` |
| `github_evidence` | object \| null | 任意 | M1 Store の参照 | null のとき `github_link` は `NOT_PRESENT` |
| `github_evidence.revision` | string | 必須（存在時） | `^rev-[0-9]{4}$` | M1 Store の Revision。M1 Integrity Validator で PASS が必要 |
| `github_evidence.manifest_sha256` | string | 必須 | 64 hex | M1 Store の `MANIFEST.json` の SHA-256 |
| `github_evidence.evidence_ids[]` | list | 必須 | M1 `envelope.EVIDENCE_ID`、重複なし | Store に存在すること |

Chain Root: Manifest があるディレクトリ。Locator は Root 相対で、Validator は `O_NOFOLLOW` で開き、Root 外への解決（`..`、Symlink、絶対 Path）を拒否する（M1 Store の Containment Base と同じ方針）。

### 1-1. `finding_refs`

| Field | 内容 | 検証 |
| --- | --- | --- |
| `finding_id` | Review_Report の `ID`（Report 内の連番。Report を跨いだ識別子ではない） | Report の `findings[]` に1件だけ存在 |
| `identity_key_sha256` | v1.1 の Identity_Key `{File, Resource, Normalized_Category}` の Canonical bytes の SHA-256 | Finding から再計算して一致 |
| `finding_sha256` | Finding（13 field の dict）の Canonical bytes の SHA-256 | Finding から再計算して一致 |

Review_Report の完全性は `passed_all_checks` を使わず、`errors[] == []` かつ `tools[].available` がすべて true で判断する（`passed-all-checks-investigation.md` §4）。満たさない Report を起点にした Chain は `review_link = INCOMPLETE`（`review_report_has_errors` / `review_tool_unavailable`）。

Finding と Contract の意味的な対応（その Finding をその Contract が直すか）は Chain Validator が判定しない。判定できるのは「参照された Finding が、参照された Report に、その内容で存在する」ことと、「Finding の `Resource` が Contract の対象 Logical ID と一致するか」の観測（`finding_resource_matches_contract`: `true` / `false`、表示のみ、Status を上げない）だけである。

## 2. Gate Record（`iacreview.chain.gate_record/1`、rev2）

役割: Human Gate の判断に関する**観測**を、Git と GitHub の Raw に含まれる事実だけから記録する。Record は Builder（決定論的な純関数）が Raw から作る。Validator は同じ Raw から Record を作り直し、提示された Record と canonical bytes で比較する。Gate Record は、承認者の権限、Ruleset の Enforcement、Account の背後の人間を証明しない（§2-6）。

```json
{
  "record_format": "iacreview.chain.gate_record/1",
  "kind": "candidate_review",
  "decision": "approved",
  "source": {
    "type": "github_pull_review",
    "store_revision": "rev-0001",
    "capture_id": "cap-chain-0002",
    "evidence_ids": ["cap-chain-0002-p001"],
    "raw_sha256": ["<64 hex>"],
    "item_ref": "reviewer:u:9b1c44e0a2f3"
  },
  "binds_to": {"commit": "<40 hex>", "role": "head"},
  "actor": {
    "actor_ref": "u:9b1c44e0a2f3",
    "relation_to_head_author": "distinct_actor",
    "author_association": "COLLABORATOR"
  },
  "deciding_review_ref": "review:81000003",
  "observed_at": "2026-11-02T01:23:45Z"
}
```

| Field | 型 | 制約・語彙 | 出典（再生成の元） |
| --- | --- | --- | --- |
| `record_format` | string | 固定 | — |
| `kind` | enum | `contract_approval` \| `candidate_review` \| `merge_decision` | — |
| `decision` | enum | `contract_approval`: `approved`。`candidate_review`: Reviewer の**集約後の状態**（§2-2）で `approved` \| `changes_requested` \| `none`。`merge_decision`: `merged` \| `closed_unmerged` \| `open` | §2-2 の集約、PR の `merged` / `state` |
| `source.type` | enum | `git_ancestry`（contract_approval）\| `github_pull_review`（candidate_review）\| `github_pull`（merge_decision） | — |
| `source.store_revision` | string \| null | Chain Manifest の `github_evidence.revision` と同じ値。`git_ancestry` は `null` | Manifest |
| `source.capture_id` | string \| null | M1 Envelope の `capture_id`。`git_ancestry` は `null` | Envelope |
| `source.evidence_ids` | list \| null | その Capture の**全 Page** の Evidence id。Page 番号順。`git_ancestry` は `null` | Envelope の `page.index` |
| `source.raw_sha256` | list \| null | 各 Page の Raw の SHA-256（`evidence_ids` と同じ順） | Envelope の `raw_content_sha256` |
| `source.item_ref` | string | `reviewer:u:<12 hex>`、`pull:<10進>`、`git:<40 hex>` | Raw |
| `binds_to.commit` | string \| null | 40 hex。`candidate_review`: 集約を決めた Review（`deciding_review_ref`）の `commit_id`、決めた Review がなければ `null`。`merge_decision`: PR の `head.sha`。`contract_approval`: `config_commit` | Raw / Manifest |
| `binds_to.role` | enum | `head` \| `config` | — |
| `actor.actor_ref` | string \| null | `u:` + SHA-256(`str(user.id)`) の先頭12桁。`user.id` が整数でなければ `null`。`git_ancestry` は `null` | Raw の `user.id` |
| `actor.relation_to_head_author` | enum | `distinct_actor` \| `same_actor` \| `unknown` | Reviewer と PR 作成者（`pull.user.id`）の比較 |
| `actor.author_association` | enum \| null | GitHub の値（`OWNER` など）をそのまま写す。**観測値。どの判定にも使わない**（D2-1） | Raw |
| `deciding_review_ref` | string \| null | 集約を決めた Review の `review:<id>`。`decision: none` で決めた Review がなければ `null` | §2-2 |
| `observed_at` | string \| null | 決めた Review の `submitted_at`、または `merged_at`。判定に使わない | Raw |

規則:

* `actor_ref` は**仮名**で、匿名化ではない（User id から再計算できる）。Login 名、Avatar URL、Email、`html_url` は保存しない
* `candidate_review` は**Reviewer ごとに1件**（PR 作成者自身の Review も1件として記録し、§2-3 で分離を判定する）
* `contract_approval` の根拠は Phase 1 と同じ「Contract が Base の祖先の config commit にある」ことだけ。Raw を持たず、Git の事実から再生成する
* 自由記述の承認者（`approved_by` など）、Agent の出力、Kiro Session の記録は `source.type` の語彙にない。そうした Record は Schema 違反として退け、承認として数えない（S-2）。Schema 違反のうち、JSON Object の top-level で次の3つの形のどれかで承認を述べるものだけを**自己申告**（`approval_self_declared_only`、NOT_PROVEN）とし、他の Schema 違反は `gate_record_invalid`（INCOMPLETE）とする（S-10）:
  * `decision` が文字列 `"approved"`（完全一致）
  * `approved` が真偽値 `true`
  * `approved_by`、`approver`、`approvers`（完全一致、小文字）が空でない文字列または空でない配列
  * これ以外の表記（他の key 名、大文字小文字の違い、入れ子、配列の要素、自由文）は自己申告として検出しない。`gate_record_invalid` は自己申告より弱くならないため、検出の漏れも承認にならず、COMPLETE にならない
* 同じ `(kind, source.item_ref)` の Record が2件以上あるとき、2件目以降は `gate_record_invalid`（S-7）。各 Record は再生成との比較も受ける（偽造の重複は `gate_record_mismatch`）

### 2-1. Evidence の範囲（Fail-closed）

Record の出典にできる Raw は、次をすべて満たすものだけ。1つでも満たさなければ GV-1 は INCOMPLETE（コードは表のとおり）。

| ID | 条件 | 違反時のコード |
| --- | --- | --- |
| E-1 | Chain Manifest に `github_evidence` があり、その Revision が M1 Integrity で PASS する | `gate_source_integrity_not_pass` |
| E-2 | `source.store_revision` が `github_evidence.revision` と同じ | `gate_source_missing` |
| E-3 | `source.evidence_ids` がすべて `github_evidence.evidence_ids` に含まれ、その Revision にある | `gate_source_missing` |
| E-4 | 同じ `capture_id` の Envelope が Revision に `evidence_ids` 以外にない（Page の取りこぼしがない） | `review_capture_incomplete` |
| E-5 | Page 番号が 1 から連続し、重複がない。最後の Page だけ `has_next: false` | 欠損・途中の `has_next: false` → `review_capture_incomplete`。同じ番号が2つ → `review_capture_duplicate` |
| E-6 | すべての Page が `completeness_status: COMPLETE`、`pagination_complete: true`、HTTP 200、Raw が JSON の配列（`pull` は object） | `review_capture_incomplete` |
| E-7 | `pull` と `pull_reviews` の Capture が同じ PR（Endpoint の番号）を指す | `gate_source_missing` |

### 2-2. Review の集約規則（D2-2、R2-1〜R2-3 を反映）

入力: E-1〜E-7 を満たす `pull_reviews` の全 Page の配列を連結したもの。**API の配列順は使わない**。集約は2段階に分ける: 段階 A は **Review id 単位**（検査、重複、矛盾、Dismissal）、段階 B は **Reviewer 単位**（状態の集約）。段階 A の結果だけが段階 B の入力になる。

**段階 A-1: 各 Review の検査**

| 項目 | 有効な値 | 違反時 |
| --- | --- | --- |
| `id` | 1 以上の整数 | `gate_source_unrecognized`（NOT_PROVEN） |
| `state` | `APPROVED`、`CHANGES_REQUESTED`、`COMMENTED`、`DISMISSED`、`PENDING` | `gate_source_unrecognized` |
| `user.id` | 1 以上の整数。欠落・`null`・他の型は「Reviewer 不明」 | その Review は段階 B で Reviewer 不明として扱う |
| `submitted_at` | `PENDING` 以外は `YYYY-MM-DDTHH:MM:SSZ`（UTC、秒精度）。`PENDING` は `null` を許す | `gate_source_unrecognized` |
| `commit_id` | 40 hex または `null` | 他の値は `gate_source_unrecognized` |

**段階 A-2: 重複と矛盾（Review id 単位）**

| 状況 | 扱い |
| --- | --- |
| 同じ `id` が2回あり、canonical 内容が同じ | INCOMPLETE `review_capture_duplicate`（Page の重複取得とみなす） |
| 同じ `id` が2回あり、内容が違う | BROKEN `review_conflict`（矛盾の確認） |

**段階 A-3: Dismissal（Review id 単位）**

GitHub の Reviews API は、却下された Review について、**その Review 自身の** `state` を `DISMISSED` として返す（元の状態、却下の時刻、却下者は返さない）。このため Dismissal は Review id 単位で扱う:

* `state: DISMISSED` の Review は「却下済み」とし、段階 B で状態を決める Review にならない（無効化）。他の Review id の状態は変えない
* `PENDING` は提出されていない Review として除外する
* 却下の時刻・却下者・理由は Raw にないため、記録も判定もしない（NOT_PROVEN。Timeline Events の取得は WP2 の範囲外）

**段階 B: Reviewer ごとの状態（Reviewer 単位）**

* 状態を決める Review（以下「決定 Review」）: 段階 A を通った `APPROVED`、`CHANGES_REQUESTED`。`COMMENTED` は状態を変えない
* 並べ順: `(submitted_at, id)` の昇順。`submitted_at` を主キーにし、`id` は同時刻の区別と食い違いの検出だけに使う
* Reviewer の状態 = 並べ順で最後の決定 Review の状態（`approved` / `changes_requested`）。決定 Review がなければ `none`
* その Reviewer の却下済み Review が、最後の決定 Review より後（並べ順）にある場合、却下の効果（それ以前の Review が有効に戻るか）は Raw から決められない。その Reviewer は `none` とし、NOT_PROVEN `review_dismissal_effect_unknown` を付ける（承認を増やす方向に推測しない）
* 曖昧な順序は Fail-closed（いずれも NOT_PROVEN。その Reviewer は `none` とし、承認に数えない）:
  * 同じ Reviewer の決定 Review が同じ `submitted_at` で、状態が違う → `review_order_ambiguous`
  * 同じ Reviewer の決定 Review、または決定 Review と却下済み Review の間で、`submitted_at` の順と `id` の順が食い違う → `review_order_inconsistent`
  * 却下済み Review と決定 Review が同じ `submitted_at` → `review_order_ambiguous`
* Reviewer 不明（`user.id` が無効）の決定 Review は誰の状態にも入れず、NOT_PROVEN `actor_relation_unknown`

**有効承認（R2-1、R2-3）**

Reviewer の状態が `approved` で、次をすべて満たすものだけを**有効承認**として数える:

1. Reviewer が PR 作成者と別の Account（`distinct_actor`）。PR 作成者自身の Review は Record に含めるが、有効承認に数えない（R2-3）
2. 最後の決定 Review の `commit_id` が Chain の `subject.head_commit` と同じ。**古い Head への承認は数えないが、それだけで BROKEN にしない**（R2-1）

**Decision Table（同一 Reviewer、並べ順で古い → 新しい。A = APPROVED、CR = CHANGES_REQUESTED、C = COMMENTED、P = PENDING、D = DISMISSED。Head = `subject.head_commit`、Old = それ以外の Commit）**

| # | Review 列（Review id 単位の state） | 段階 B の状態 | 有効承認 | 理由コード |
| --- | --- | --- | --- | --- |
| R-01 | A@Head | approved | 数える | — |
| R-02 | A@Head, C | approved | 数える | — |
| R-03 | A@Head, CR | changes_requested | — | GV-2 `changes_requested_outstanding` |
| R-04 | CR, A@Head | approved | 数える | — |
| R-05 | A@Head（その後このReview自体が却下され D） | none | — | GV-2 `approval_not_shown`（他に承認がなければ） |
| R-06 | D, A@Head | approved | 数える | — |
| R-07 | D のみ | none | — | 同上 |
| R-08 | C のみ / P のみ / C, P | none | — | 同上 |
| R-09 | A@Head, P | approved | 数える | — |
| R-10 | A と CR が同じ `submitted_at` | none | — | `review_order_ambiguous` |
| R-11 | A と A が同じ `submitted_at` | approved（状態が同じ） | Head なら数える | — |
| R-12 | `submitted_at` 順で A → CR、`id` 順は逆 | none | — | `review_order_inconsistent` |
| R-13 | 同じ `id` で内容が同じ Review が2件 | （集約しない） | — | `review_capture_duplicate`（INCOMPLETE） |
| R-14 | 同じ `id` で内容が違う Review が2件 | （集約しない） | — | `review_conflict`（BROKEN） |
| R-15 | `state` が語彙外、`submitted_at` が不正 | （集約しない） | — | `gate_source_unrecognized` |
| R-16 | 決定 Review の `user.id` が欠落 | 数えない | — | `actor_relation_unknown` |
| R-17 | A@Old | approved | 数えない | 有効承認が他になければ GV-3 `approval_on_previous_head_only`（NOT_PROVEN）。BROKEN にしない |
| R-18 | A@Old, A@Head | approved | 数える（最後が Head） | — |
| R-19 | A@Head, A@Old（Head の承認の後に古い Commit への承認） | approved | 数えない（最後が Old） | 同 R-17 |
| R-20 | A@Head, D（後の別 Review が却下済み） | none | — | `review_dismissal_effect_unknown` |
| R-21 | CR@Old（解消されていない） | changes_requested | — | GV-2 `changes_requested_outstanding`（Commit に関係なく未解決として扱う） |
| R-22 | PR 作成者の A@Head | approved | 数えない（R2-3） | 他に有効承認がなければ GV-2 `separation_of_duty_not_shown` |
| R-23 | A と D が同じ `submitted_at` | none | — | `review_order_ambiguous` |

### 2-3. Gate の検証観点（rev2）

| ID | 観点 | 問い | Status の意味 |
| --- | --- | --- | --- |
| GV-1 | Integrity | 提示された Record は、§2-1 の範囲の Raw から §2-2 の規則で再生成した Record と一致するか | LINKED は「Record が範囲内の Raw と矛盾しない」こと |
| GV-2 | **Account Separation（観測）** | PR 作成者と別の Account の承認が観測され、未解決の CHANGES_REQUESTED がないか | LINKED は「Raw の上で別 Account の承認が観測され、未解決の変更要求がない」ことだけ。**承認権限（Approval Authority）は証明しない**。Result に定数 `observed.approval_authority: "NOT_PROVEN"` を置く |
| GV-3 | Revision Binding | 有効承認が Chain の Head に対するものとして Raw から示せるか、Record の Revision は Raw と一致するか | 古い Head への承認（Revision の不一致）と、Record の Revision の偽装（記録の矛盾）を分けて判定する（R2-1） |
| GV-4 | Approval Staleness | 取得時点の PR の Head は、Chain の検証対象と同じ Commit か | 取得時点の状態に限る |
| GV-5 | Merge Enforcement | — | **M2 の対象外。判定しない**。`not_claimed` に常に `merge_enforcement` |

`author_association` は GV-1〜GV-4 のどれにも使わない（D2-1）。GV-2 の結果は `author_association` の値によらない（Test TC-10-06）。

### 2-4. 各観点の判定規則（rev2）

**GV-1 Integrity**

| 状況 | Status | 理由コード |
| --- | --- | --- |
| Record が Raw からの再生成と一致し、§2-1 を満たす | LINKED | — |
| Record ファイルが Manifest の Digest と違う、Record が再生成と1 Field でも違う、Manifest の `kind` と Record の `kind` が違う | BROKEN | `gate_record_mismatch` |
| 再生成に同じ `(kind, item_ref)` の Record がなく、その種類の Raw は完全に読めた（E-1〜E-7 を満たし、JSON として読め、集約できた）（S-5） | BROKEN | `gate_record_mismatch` |
| Manifest が名指す Record ファイルがない（S-4） | INCOMPLETE | `gate_record_missing` |
| Raw から再生成した `candidate_review` / `merge_decision` が提示されていない。ただし、その数が、Manifest で同じ `kind` を名乗り使えなかった Entry（ファイルの欠落、Digest 不一致、Schema 違反、`kind` 不一致）の数以下なら、使えない Entry のコード（INCOMPLETE 以上）で説明できる二次的な結果としてコードを追加しない（S-4、S-9） | INCOMPLETE | `gate_record_missing` |
| Record が通常ファイルでない、64 KiB 超、読めない、strict JSON でない、Object でない、閉じた Schema の外で自己申告の形をとらない、同じ `(kind, item_ref)` の2件目以降（S-1、S-2、S-7） | INCOMPLETE | `gate_record_invalid` |
| 同じ Review id で内容が違う（R-14） | BROKEN | `review_conflict` |
| §2-1 E-2 / E-3 違反、E-7 違反などでその種類の Capture が範囲内にない（S-6。Capture はあるが読めない・集約できない場合は、その原因のコードだけを付ける） | INCOMPLETE | `gate_source_missing` |
| §2-1 E-1 違反 | INCOMPLETE | `gate_source_integrity_not_pass` |
| §2-1 E-4 / E-5（欠損）/ E-6 違反 | INCOMPLETE | `review_capture_incomplete` |
| §2-1 E-5（重複）、R-13 | INCOMPLETE | `review_capture_duplicate` |
| R-15 | NOT_PROVEN | `gate_source_unrecognized` |
| R-10 / R-23、R-12 | NOT_PROVEN | `review_order_ambiguous`、`review_order_inconsistent` |
| R-20 | NOT_PROVEN | `review_dismissal_effect_unknown` |
| 自己申告の Record がある（§2 の3つの形）。有効な承認 Record が別にあっても付ける（S-3） | NOT_PROVEN | `approval_self_declared_only` |

**GV-2 Account Separation（観測）**

| 状況 | Status | 理由コード |
| --- | --- | --- |
| `approved` で `distinct_actor` の Reviewer が1人以上、かつ `changes_requested` の Reviewer が0人 | LINKED | — |
| `changes_requested` の Reviewer がいる（R-03、R-21。Commit に関係なく） | NOT_PROVEN | `changes_requested_outstanding` |
| `approved` が PR 作成者だけ（R-22） | NOT_PROVEN | `separation_of_duty_not_shown` |
| `approved` の Reviewer がいない | NOT_PROVEN | `approval_not_shown` |
| 決定 Review または PR 作成者の `user.id` が無効（R-16） | NOT_PROVEN | `actor_relation_unknown` |

`changes_requested_outstanding` は「必要な承認を証明できない状態」を意味し、Chain の COMPLETE を禁止する（NOT_PROVEN は COMPLETE にならない）。承認済みでないこと、Ruleset が Merge を止めることは主張しない（R2-2）。

**GV-3 Revision Binding**（D-3、R2-1）

| 状況 | Status | 理由コード |
| --- | --- | --- |
| `contract_approval.binds_to.commit == config_commit`、かつ有効承認が1件以上（Head への `distinct_actor` の承認） | LINKED | — |
| **Revision の偽装**: Record の `binds_to.commit` が、Raw の決定 Review の `commit_id` と違う | BROKEN | `approval_revision_misrecorded`（GV-1 の `gate_record_mismatch` と同時に出る） |
| `contract_approval` の Commit が `config_commit` と違う | BROKEN | `gate_binds_other_commit` |
| **古い Head への承認だけ**: `distinct_actor` の `approved` はあるが、どれも Head への承認でない（R-17、R-19） | NOT_PROVEN | `approval_on_previous_head_only` |
| `contract_approval` がない（Record 0件を含む） | INCOMPLETE | `gate_record_missing` |
| `distinct_actor` の `approved` の決定 Review の `commit_id` が `null` で、Head への有効承認が他にない | NOT_PROVEN | `approval_revision_unverifiable` |

古い Head への承認は、Head への有効承認が別にあれば判定に影響しない（R-18、TC-09-03）。`distinct_actor` の `approved` が0件のとき、GV-3 の Review 側の判定は行わない（GV-2 が理由を示す）。

**GV-4 Approval Staleness**（D-3）

| 状況 | Status | 理由コード |
| --- | --- | --- |
| `pull` の `head.sha == head_commit` | LINKED | — |
| `pull.head.sha` が `head_commit` と違う（Chain が PR の現在の Head 以外を検証した。承認の後に Push された場合を含む） | BROKEN | `pr_head_mismatch` |
| `pull` の Raw がない、`head.sha` が欠落 | NOT_PROVEN | `approval_revision_unverifiable` |
| 自己申告があり、Raw に裏付けのある承認 Record（再生成と一致した `decision: approved` の `candidate_review`）が提示されていない（S-8） | NOT_PROVEN | `approval_self_declared_only` |

GV-1 の Record は1件ずつ判定し、1件の異常のコードは他の Record が正常でも消えない（S-3、S-9）。判定の順序と各行の根拠は `docs/v2/phase2/m2/wp2/wp2-gate-record-decision-table.md` G-01〜G-13a。

**G-13a の既知の制約（S-9）**: Manifest の `kind` は表示用の値で、使えない Entry の中身は読まない。このため、Record の省略と、同じ `kind` を名乗る使えない Entry の追加が同時にあると、省略は使えない Entry のコードで説明され、`gate_record_missing` は付かない。その場合も Status は使えない Entry のコード（INCOMPLETE 以上）で決まり、Chain は COMPLETE にならない。Raw の CHANGES_REQUESTED は GV-2 に残る。

GV-4 は Chain の Subject と PR の現在の Head の比較だけを行う。承認の Commit と Head の比較は GV-3 で行う（古い承認を BROKEN にしないため、R2-1）。

**理由コードの区別（設計修正 6）**: 未解決の変更要求（`changes_requested_outstanding`、GV-2）、古い Head への承認（`approval_on_previous_head_only`、GV-3）、Evidence の欠損（`gate_source_missing`、`review_capture_incomplete`、`review_capture_duplicate`、`gate_source_integrity_not_pass`、GV-1）、Revision の偽装（`approval_revision_misrecorded`、GV-3）、PR の Head と Subject の不一致（`pr_head_mismatch`、GV-4）は、それぞれ別のコードで、1つの状況に複数のコードを兼用しない。

**`gate` Link の Status** = GV-1〜GV-4 の代表値（`BROKEN > INCOMPLETE > NOT_PROVEN > LINKED`）。Link の `codes` は4観点のコードの和集合。各観点の Status とコードは `gate_aspects`（key: `integrity`、`account_separation`、`revision_binding`、`staleness`）に残す。

**`gate_evaluation_not_implemented`**（D2-3）: Catalog に残す（削除しない）。WP2 以降、`gate_records` がある Chain では出ない。WP1 の Result と Anchor の互換性のため、意味と Status（NOT_PROVEN）は変えない。

### 2-5. GitHub Raw から得られる事実と、得られない事実

| 区分 | 事実 | 出典 | M2 での扱い |
| --- | --- | --- | --- |
| Raw が直接示す | Review の `id`、`state`、`commit_id`、`user.id`、`submitted_at`、`author_association` | `pull_reviews` | §2-2 の集約。`author_association` は観測値のみ。出所は `capture_authenticity` NOT_PROVEN |
| 同上 | PR の `head.sha`、`base.sha`、`user.id`、`merged`、`merged_at`、`state` | `pull` | GV-2（作成者）、GV-4、`merge_decision` |
| 同上 | API が示す merge base、ahead / behind | `compare` | Local Git との照合（WP5） |
| 同上 | Contract・Template の本文 | `contract_contents`、`template_contents` | Local Git との照合（WP5） |
| 追加の検証が必要（M2 では示さない） | Reviewer が Write 以上の権限を持っていたか | Collaborator permission API | `not_claimed: approver_permission` |
| 同上 | 承認が Ruleset / Branch Protection の必要承認として数えられたか、Code Owner の承認か | Ruleset、Branch Protection、承認時点の設定 | `not_claimed: approval_counted_by_rules` |
| 同上 | Review の却下の時刻・却下者・理由 | Timeline Events | 記録しない（NOT_PROVEN） |
| 同上 | Merge がこの検証と承認なしでは不可能だったか | Merge Enforcement | `not_claimed: merge_enforcement`（GV-5） |
| 同上 | Account の背後の人間 | GitHub の外 | `not_claimed: human_identity` |
| 同上 | 応答が本当に GitHub から来たか | 署名なし | `not_claimed: capture_authenticity` |
| 同上 | 取得後に PR が変わっていないか | 再取得 | GV-4 の限界 |

### 2-6. Chain COMPLETE の意味（rev2）

`COMPLETE` は「**Evidence Chain の検証が完了し、参照された Artifact が互いに矛盾しなかった**」ことだけを意味する。次のどれも意味しない: 承認者の権限（`approver_permission`）、承認が規則で数えられたこと（`approval_counted_by_rules`）、Ruleset / Branch Protection の Enforcement（`merge_enforcement`）、人間の同一性（`human_identity`）、Raw の出所（`capture_authenticity`）、Issuer Pinning、Runtime の挙動、修正の正しさ、Merge してよいこと。

固定する表示:

* Result の `not_claimed` は Status によらず常に7項目
* `gate` Link の `observed.approval_authority` は常に `"NOT_PROVEN"`（定数。Payload に入れても環境に依存しない）
* 未解決の CHANGES_REQUESTED（`changes_requested_outstanding`）、古い Head への承認だけ（`approval_on_previous_head_only`）、Evidence の欠損のいずれかがあれば、`gate` は LINKED にならず、Chain は COMPLETE にならない
* Summary（WP3）の COMPLETE の文言は「Evidence chain verified (references agree). Approval authority, rule enforcement and merge readiness are not shown.」に固定し、「approved」「ready」「safe」「enforced」「merge」を単独の主張として使わない（TC-10-09）

## 3. Chain Result（`iacreview.chain.result/1`）

役割: Chain Validator の出力。決定論的な Payload と Run Metadata を分ける（Phase 1 Report と同じ形）。

```json
{
  "result_format": "iacreview.chain.result/1",
  "payload": {
    "chain_status": "NOT_PROVEN",
    "manifest_sha256": "<64 hex>",
    "manifest_codes": [],
    "validator": {"version": "iacreview.chain.validator/1", "source_sha256": "<64 hex>"},
    "links": [
      {"link": "subject", "status": "LINKED", "codes": []},
      {"link": "contract", "status": "LINKED", "codes": []},
      {"link": "review", "status": "LINKED", "codes": [], "observed": {"finding_resource_matches_contract": true}},
      {"link": "verification", "status": "LINKED", "codes": [],
       "observed": {"decision": "VERIFIED", "execution_mode": "local_preview", "validator_identity": "NOT_PROVEN"}},
      {"link": "gate", "status": "NOT_PROVEN", "codes": ["approval_not_shown"],
       "gate_aspects": {"integrity": {"status": "LINKED", "codes": []},
                        "account_separation": {"status": "NOT_PROVEN", "codes": ["approval_not_shown"]},
                        "revision_binding": {"status": "LINKED", "codes": []},
                        "staleness": {"status": "LINKED", "codes": []}},
       "observed": {"approval_authority": "NOT_PROVEN", "merge_decision": "open"}},
      {"link": "github", "status": "LINKED", "codes": [], "observed": {"capture_authenticity": "NOT_PROVEN"}}
    ],
    "not_claimed": ["approval_counted_by_rules", "approver_permission", "capture_authenticity", "human_identity",
                    "issuer_pinning", "merge_enforcement", "runtime_behavior"]
  },
  "metadata": {"generated_at": "...Z", "duration_ms": 0, "payload_sha256": "<64 hex>", "diagnostics": []}
}
```

* `metadata.diagnostics`（WP1 Revision 2 で追加、rev2 で正式化）: 環境に依存する Diagnostic（Validator Identity の一致 / 不一致）。Payload の外で、Status を変えない
* `gate_aspects` は Gate Record が1件以上あるときだけ出す（0件のときは WP1 と同じ `gate_record_missing` だけ）。WP1 Anchor の Payload の形を保つため（§5 互換性、`wp0-revision-2.md` §4）
* `author_association` は `gate` Link の Payload に入れない（Record にだけ残す）。観測値が Payload の判定材料に見えることを避けるため

Link Status（各リンク）: `LINKED` / `BROKEN` / `INCOMPLETE` / `NOT_PROVEN` / `NOT_PRESENT`

* `BROKEN`: 照合先があり、矛盾が確認できた（改変・取り違え・不一致）
* `INCOMPLETE`: 必要な Artifact が欠けている、読めない、完全でない
* `NOT_PROVEN`: Artifact は揃ったが、主張に必要な事実が Evidence にない（自己申告だけの場合を含む）
* `NOT_PRESENT`: 任意リンク（`review`、`github`）が Manifest にない

Chain Status（代表値）: `BROKEN > INCOMPLETE > NOT_PROVEN > COMPLETE`。`COMPLETE` は6リンクすべてが `LINKED` のときだけで、意味は §2-6 に限る。Verification の `decision` は `observed` に写すだけで、Chain Status を上げも下げもしない。Manifest 自体が読めない・Schema 違反のときは `links` が空、`manifest_codes` に理由、`chain_status: BROKEN`、exit code は 34。

### 3-1. Exit code（CLI を採用した場合）

| 値 | 意味 |
| --- | --- |
| 0 | `COMPLETE` |
| 31 | `NOT_PROVEN` |
| 32 | `INCOMPLETE` |
| 33 | `BROKEN` |
| 34 | 入力の誤り（引数、Manifest が読めない・Schema 違反） |

既存 Code との衝突確認（WP0 で Repository 内を検索した結果。実行時の確認ではない）:

| 既存の CLI / Script | 使う exit code | 31〜34 との重なり |
| --- | --- | --- |
| `iacreview/exitcodes.py`（Review CLI、Delta_Tool、Benchmark） | 0〜8、9、10 | なし |
| Phase 1 `python3 -m iacreview.remediation`（`rschema.DECISION_EXIT_CODES`） | 0、20、21、22 | なし |
| M1 `iacreview.evidence.replay` / `final_report` / `legacy_reeval` | 0、2、3、4 | なし |
| `.github/scripts/evidence_ci_check.py` | 0、2、10〜20 | なし |
| `.github/scripts/public_preflight.py`、`scan_secrets.py`、`check_ground_truth_order.py` | 0〜3 | なし |
| 数値 31〜34 の他の用途 | `grep` で exit code としての使用なし（`cfnguard.MAX_CHECK_DEPTH = 32` は exit code ではない） | なし |

WP1 で、Chain の exit code が上表の集合と交わらないことを Test で固定する（TC-06-07）。

## 4. 理由コード（閉じた語彙、rev2）

| Link | BROKEN | INCOMPLETE | NOT_PROVEN |
| --- | --- | --- | --- |
| （Manifest） | `manifest_invalid`、`locator_outside_root` | `manifest_unreadable` | — |
| subject | `base_not_ancestor_of_head`、`subject_mismatch` | `revision_not_found` | — |
| contract | `config_not_ancestor_of_base`、`contract_digest_mismatch`、`contract_mismatch_with_report` | `contract_blob_missing` | — |
| review | `review_digest_mismatch`、`finding_missing`、`finding_digest_mismatch`、`identity_key_mismatch` | `review_artifact_missing`、`review_report_has_errors`、`review_tool_unavailable`、`review_report_invalid` | — |
| verification | `verification_digest_mismatch`、`payload_digest_mismatch`、`metadata_digest_mismatch`、`report_subject_mismatch` | `verification_artifact_missing`、`report_invalid` | `recompute_unavailable` |
| gate（GV-1） | `gate_record_mismatch`、`review_conflict` | `gate_source_missing`、`gate_source_integrity_not_pass`、`review_capture_incomplete`、`review_capture_duplicate`、`gate_record_missing`、`gate_record_invalid` | `gate_source_unrecognized`、`review_order_ambiguous`、`review_order_inconsistent`、`review_dismissal_effect_unknown`、`approval_self_declared_only` |
| gate（GV-2） | — | — | `separation_of_duty_not_shown`、`approval_not_shown`、`changes_requested_outstanding`、`actor_relation_unknown` |
| gate（GV-3） | `approval_revision_misrecorded`、`gate_binds_other_commit` | `gate_record_missing` | `approval_on_previous_head_only`、`approval_revision_unverifiable` |
| gate（GV-4） | `pr_head_mismatch` | — | `approval_revision_unverifiable`、`approval_self_declared_only` |
| gate（WP1 互換、D2-3） | — | — | `gate_evaluation_not_implemented`（Catalog に維持。WP2 以降、Record のある Chain では出ない） |
| github | `store_manifest_mismatch`、`repository_mismatch` | `integrity_not_pass`、`evidence_id_missing`、`capture_incomplete` | — |
| 全 Link（WP1 で追加、rev2 で正式化） | — | `link_check_error` | — |

Diagnostic（Reason Code ではない。`status.DIAGNOSTICS`、Result の `metadata` だけ）: `validator_identity_matches`、`validator_identity_differs`、`validator_identity_not_compared`。

WP2 Final Specification Review（S-1〜S-10）: `gate_record_invalid`（INCOMPLETE、GV-1）を追加（S-1）。`gate_record_missing` を GV-1 でも使う（S-4）。`gate_record_mismatch` に完全な Raw にない Item の Record を含める（S-5）。`approval_self_declared_only` を §2 の3つの形に限る（S-2、S-10）。既存コードの Status は変えていない。Record 0件の Chain は WP1 と同じ結果（INCOMPLETE `gate_record_missing` だけ、`gate_aspects` なし）。

rev2 の追加修正（R2-1〜R2-3）: rev1 の `approval_stale`（GV-4 BROKEN）を廃止し、古い Head への承認は GV-3 `approval_on_previous_head_only`（NOT_PROVEN）、Subject と PR の Head の不一致は GV-4 `pr_head_mismatch`（BROKEN）、Record の Revision の偽装は GV-3 `approval_revision_misrecorded`（BROKEN）に分けた。`review_dismissal_effect_unknown` を追加。`approval_stale` は WP1 の Catalog に未登録のため、互換性への影響はない。

rev1 からの変更: `approver_association_not_shown` を削除（D2-1）。`review_conflict`、`review_capture_incomplete`、`review_capture_duplicate`、`review_order_ambiguous`、`review_order_inconsistent`、`changes_requested_outstanding` を追加（D2-2、必須修正 2・3・5）。`gate_evaluation_not_implemented` と `link_check_error` を正式な語彙にした（WP1 N-1、D2-3）。

Reason Code の観点（GV-1〜GV-4）は `gate_aspects` の各観点のコードで区別する。2観点に出るコード（`approval_revision_unverifiable`、`approval_self_declared_only`、`gate_record_missing`）は、Catalog では gate Link のコードとして1件、どの観点で出たかは `gate_aspects` で示す。
