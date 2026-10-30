# Phase 2 / M2 — Schema 案（Chain Manifest、Gate Record、Chain Result）

* 状態: **WP0 の Schema 案 rev1（Human Review 92/100 の条件付き承認を受けた修正版）。未実装。** Human 決定 D-2 により、本書の Schema 名・Field・閉じた語彙を固定する。固定後の変更は新 Version の Schema とし、Human の承認を要する。Exit code 31〜34 は §3-1 の衝突確認の結果とともに Human の最終確認を待つ
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
      {"finding_id": "F-0003", "identity_key_sha256": "<64 hex>", "finding_sha256": "<64 hex>"}
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

## 2. Gate Record（`iacreview.chain.gate_record/1`）

役割: Human Gate の判断を、Git と GitHub の Raw に含まれる事実だけから記録する。Record は Builder（決定論的な Code）が Raw から作る。Validator は同じ Raw から Record を作り直し、提示された Record と比較する。

```json
{
  "record_format": "iacreview.chain.gate_record/1",
  "kind": "candidate_review",
  "decision": "approved",
  "source": {
    "type": "github_pull_review",
    "evidence_id": "sc02-reviews",
    "store_revision": "rev-0001",
    "raw_sha256": "<64 hex>",
    "item_ref": "review:<numeric id>"
  },
  "binds_to": {"commit": "<40 hex>", "role": "head"},
  "actor": {
    "actor_ref": "u:9b1c44e0a2f3",
    "relation_to_head_author": "same_actor",
    "author_association": "OWNER"
  },
  "observed_at": "2026-11-02T01:23:45Z"
}
```

| Field | 型 | 制約・語彙 | 出典（再生成の元） |
| --- | --- | --- | --- |
| `record_format` | string | 固定 | — |
| `kind` | enum | `contract_approval` \| `candidate_review` \| `merge_decision` | — |
| `decision` | enum | `contract_approval`: `approved`。`candidate_review`: `approved` \| `changes_requested` \| `commented`。`merge_decision`: `merged` \| `closed_unmerged` \| `open` | Raw の値を写像（Review `state` の `APPROVED` / `CHANGES_REQUESTED` / `COMMENTED`、PR の `merged` / `state`）。写像表外の値（例: `DISMISSED`、`PENDING`）は `gate_source_unrecognized` |
| `source.type` | enum | `git_ancestry`（contract_approval）\| `github_pull_review`（candidate_review）\| `github_pull`（merge_decision） | — |
| `source.evidence_id` / `store_revision` / `raw_sha256` | string \| null | M1 Store の Evidence を指す。`git_ancestry` のときは `null` | M1 Store |
| `source.item_ref` | string | `review:<10進>`、`pull:<10進>`、`git:<40 hex>` | Raw の中の項目 |
| `binds_to.commit` | string | 40 hex | `candidate_review`: Review の `commit_id`。`merge_decision`: PR の `head.sha`。`contract_approval`: `config_commit` |
| `binds_to.role` | enum | `head` \| `config` | — |
| `actor.actor_ref` | string \| null | `u:` + 数値 User id（10進文字列）の SHA-256 先頭12桁。`git_ancestry` は `null` | Raw の `user.id` |
| `actor.relation_to_head_author` | enum | `distinct_actor` \| `same_actor` \| `unknown` | Review の `user.id` と PR の `user.id`（PR 作成者）の比較。どちらかが欠ければ `unknown` |
| `actor.author_association` | enum \| null | `OWNER` \| `MEMBER` \| `COLLABORATOR` \| `CONTRIBUTOR` \| `FIRST_TIMER` \| `FIRST_TIME_CONTRIBUTOR` \| `MANNEQUIN` \| `NONE` | Raw の `author_association`（GitHub が応答した値。権限の証明ではない） |
| `observed_at` | string \| null | Raw の `submitted_at` / `merged_at` を UTC 秒精度で写す | Raw。時刻は来歴を証明しない |

規則:

* `actor_ref` は**仮名**で、匿名化ではない（User id から再計算できる）。Login 名、Avatar URL、Email は保存しない
* `contract_approval` の根拠は Phase 1 と同じ「Contract が Base の祖先の config commit にある」ことだけ。承認者の同一性は扱わない（`actor` の各値は `null` / `unknown`）
* 自由記述の承認者（`approved_by` など）、Agent の出力、Kiro Session の記録は `source.type` の語彙にない。この Record は Schema 違反として退け、「承認の自己申告だけがある」状態として扱う（§2-2 の GV-1）

### 2-1. Gate の検証観点（別々に判定する）

| ID | 観点 | 問い | M2 の扱い |
| --- | --- | --- | --- |
| GV-1 | Integrity | 提示された Record は、Store の Raw から再生成した Record と一致するか。Raw は M1 Integrity を PASS しているか | 判定する |
| GV-2 | Approval Authority | 承認したのは PR 作成者と別の Account か。GitHub はその Account をどの関係（`author_association`）と応答したか | 判定する。ただし「その承認が Repository の規則で有効に数えられたか」は判定しない（`approval_counted_by_rules` を `not_claimed` に入れる） |
| GV-3 | Revision Binding | Record が指す Commit は、Chain の検証対象（`candidate_review` / `merge_decision` は `head_commit`、`contract_approval` は `config_commit`）と同じか | 判定する |
| GV-4 | Approval Staleness | 取得時点の PR の Head（`pull` Raw の `head.sha`）は、承認と Chain の検証対象と同じ Commit か。承認の後に PR へ別の Commit が入っていないか | 判定する（取得時点の状態に限る） |
| GV-5 | Merge Enforcement | GitHub がこの承認と検証結果なしの Merge を拒否する設定だったか | **M2 の対象外。判定しない。** `gate` Link の Status に入れず、Result の `not_claimed` に常に `merge_enforcement` を入れる |

### 2-2. 各観点の判定規則

各観点の Status は `LINKED` / `BROKEN` / `INCOMPLETE` / `NOT_PROVEN`。

**GV-1 Integrity**

| 状況 | Status | 理由コード |
| --- | --- | --- |
| Record が Raw からの再生成と一致し、Raw の Revision が M1 Integrity PASS | `LINKED` | — |
| Raw が存在し、Record が再生成と1 Field でも違う（改変・取り違え） | `BROKEN` | `gate_record_mismatch` |
| Record が参照する Raw が Store にない | `INCOMPLETE` | `gate_source_missing` |
| Raw の Revision が M1 Integrity を PASS しない | `INCOMPLETE` | `gate_source_integrity_not_pass` |
| Raw の値が写像表外 | `NOT_PROVEN` | `gate_source_unrecognized` |
| Record が Schema 違反（`source.type` 語彙外、未知 key、`approved_by` など）で、承認を示す有効な Record がほかにない | `NOT_PROVEN` | `approval_self_declared_only` |

**GV-2 Approval Authority**（`candidate_review` の `approved` の Record について）

| 状況 | Status | 理由コード |
| --- | --- | --- |
| `relation_to_head_author == distinct_actor` かつ `author_association` が `OWNER` / `MEMBER` / `COLLABORATOR` | `LINKED` | — |
| `same_actor` | `NOT_PROVEN` | `separation_of_duty_not_shown` |
| `unknown`（`user.id` の欠落） | `NOT_PROVEN` | `actor_relation_unknown` |
| `author_association` が上記以外または `null` | `NOT_PROVEN` | `approver_association_not_shown` |
| `approved` の Record がない（`commented` / `changes_requested` だけ） | `NOT_PROVEN` | `approval_not_shown` |

`LINKED` は「GitHub がその関係と応答した」ことだけを示す。その Account の権限（Write 以上か）、Ruleset の必要承認数を満たしたか、Code Owner の承認か、Account の背後の人間は示さない（§2-3）。

**GV-3 Revision Binding**

| 状況 | Status | 理由コード |
| --- | --- | --- |
| `contract_approval.binds_to.commit == config_commit`、かつ `approved` の `candidate_review` がすべて `binds_to.commit == head_commit`（`approved` が1件もないことは GV-2 の `approval_not_shown` で扱い、GV-3 では判定しない） | `LINKED` | — |
| Record の Commit と Chain の対象 Commit の**不一致が確認できた** | `BROKEN` | `gate_binds_other_commit` |
| `contract_approval` がない | `INCOMPLETE` | `gate_record_missing` |
| Raw に `commit_id` がない等、照合に必要な Evidence が欠けている | `NOT_PROVEN` | `approval_revision_unverifiable` |

**GV-4 Approval Staleness**（Human 決定 D-3 による固定）

| 状況 | Status | 理由コード |
| --- | --- | --- |
| `pull` Raw の `head.sha` == Chain の `head_commit`、かつ `approved` の `candidate_review` があればその `commit_id` とも一致 | `LINKED` | — |
| 対象 Revision の不一致が確認できた（`pull.head.sha` が `head_commit` または承認の `commit_id` と異なる。承認の後に Head が進んだ場合、検証した Head が PR の現在の Head でない場合を含む） | `BROKEN` | `approval_stale` |
| 照合に必要な Evidence が足りない（`pull` Raw がない、`head.sha` がない、`commit_id` がない） | `NOT_PROVEN` | `approval_revision_unverifiable` |
| Agent による承認の自己申告だけがある（Raw に裏付けのある承認 Record がない） | `NOT_PROVEN` | `approval_self_declared_only` |

GV-4 は**取得時点**の状態だけを判定する。取得の後に PR が変わった場合は、再取得するまで分からない（Time-of-check の限界。`m2-threat-model.md` §6）。

**`gate` Link の Status** = GV-1〜GV-4 の代表値（`BROKEN > INCOMPLETE > NOT_PROVEN > LINKED`）。各観点の Status と理由コードは Result の `gate_aspects` に残す。`merge_decision` の Record は観測として `observed` に写し、`gate` Link の Status を変えない。

### 2-3. GitHub Raw から得られる事実と、得られない事実

| 区分 | 事実 | 出典 | M2 での扱い |
| --- | --- | --- | --- |
| Raw が直接示す（GitHub がそう応答した） | Review の `state`、`commit_id`、`user.id`、`author_association`、`submitted_at` | `pull_reviews` | GV-1〜GV-4 に使う。出所は `capture_authenticity` NOT_PROVEN |
| 同上 | PR の `head.sha`、`base.sha`、`user.id`、`merged`、`merged_at`、`state` | `pull` | GV-2、GV-4、`merge_decision` |
| 同上 | API が示す merge base、ahead / behind | `compare` | Local Git との照合 |
| 同上 | Contract・Template の本文 | `contract_contents`、`template_contents` | Local Git との照合 |
| 追加の検証が必要（M2 では示さない） | その Account が Write 以上の権限を持っていたか | Collaborator permission API（Login 名が必要、M2 では取得しない） | `not_claimed: approver_permission` |
| 同上 | その承認が Ruleset / Branch Protection の必要承認として数えられたか | `rules/branches/{branch}`、Ruleset の Bypass 設定、承認時点の設定 | `not_claimed: approval_counted_by_rules` |
| 同上 | Merge がこの検証と承認なしでは不可能だったか | Merge Enforcement（AC28 など） | `not_claimed: merge_enforcement`（GV-5、対象外） |
| 同上 | Account の背後の人間が誰か、別人か | GitHub の外 | `not_claimed: human_identity` |
| 同上 | 応答が本当に GitHub から来たか | 署名なし | `not_claimed: capture_authenticity` |
| 同上 | 取得後に PR が変わっていないか | 再取得 | GV-4 の限界として記録 |

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
      {"link": "verification", "status": "LINKED", "codes": [], "observed": {"decision": "VERIFIED", "execution_mode": "local_preview"}},
      {"link": "gate", "status": "NOT_PROVEN", "codes": ["separation_of_duty_not_shown"],
       "gate_aspects": {"integrity": {"status": "LINKED", "codes": []},
                        "authority": {"status": "NOT_PROVEN", "codes": ["separation_of_duty_not_shown"]},
                        "revision_binding": {"status": "LINKED", "codes": []},
                        "staleness": {"status": "LINKED", "codes": []}},
       "observed": {"merge_decision": "open"}},
      {"link": "github", "status": "LINKED", "codes": [], "observed": {"capture_authenticity": "NOT_PROVEN"}}
    ],
    "not_claimed": ["approval_counted_by_rules", "approver_permission", "capture_authenticity", "human_identity",
                    "issuer_pinning", "merge_enforcement", "runtime_behavior"]
  },
  "metadata": {"generated_at": "...Z", "duration_ms": 0, "payload_sha256": "<64 hex>"}
}
```

Link Status（各リンク）: `LINKED` / `BROKEN` / `INCOMPLETE` / `NOT_PROVEN` / `NOT_PRESENT`

* `BROKEN`: 参照先の bytes、Digest、Git の関係、Revision が、Manifest・他のリンク・Raw と矛盾することが確認できた（改変・取り違え・不一致）
* `INCOMPLETE`: 参照先が欠けている、読めない、M1 Integrity が不完全とした、Review_Report に `errors[]` がある
* `NOT_PROVEN`: 参照は揃ったが、主張に必要な事実が Evidence にない（例: `same_actor`、Tool 不在で再計算できない、自己申告だけ）
* `NOT_PRESENT`: 任意リンク（`review`、`github`）が Manifest にない

Chain Status（代表値）: `BROKEN > INCOMPLETE > NOT_PROVEN > COMPLETE`

* `COMPLETE` は、6リンクすべてが `LINKED` のときだけ。`NOT_PRESENT` が1つでもあれば `INCOMPLETE`
* `COMPLETE` は「参照された Artifact が互いに矛盾せず揃っている」ことだけを意味する。`not_claimed` の7項目（Merge Enforcement、承認が規則で数えられたこと、承認者の権限、人間の同一性、Raw の出所、Issuer Pinning、Runtime の挙動）を示さない。`not_claimed` は Status にかかわらず常にこの7項目
* Verification の `decision`（`VERIFIED` / `BLOCKED` / `UNVERIFIED` / `ERROR`）は `observed` に写すだけで、Chain Status を上げも下げもしない
* Manifest 自体が読めない・Schema 違反のとき: `links` は空、`manifest_codes` に理由（`manifest_invalid`、`locator_outside_root`、`manifest_unreadable`）、`chain_status` は `BROKEN`、exit code は「入力の誤り」

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

## 4. 理由コード（閉じた語彙、rev1）

| Link | BROKEN | INCOMPLETE | NOT_PROVEN |
| --- | --- | --- | --- |
| （Manifest） | `manifest_invalid`、`locator_outside_root` | `manifest_unreadable` | — |
| subject | `base_not_ancestor_of_head`、`subject_mismatch` | `revision_not_found` | — |
| contract | `config_not_ancestor_of_base`、`contract_digest_mismatch`、`contract_mismatch_with_report` | `contract_blob_missing` | — |
| review | `review_digest_mismatch`、`finding_missing`、`finding_digest_mismatch`、`identity_key_mismatch` | `review_artifact_missing`、`review_report_has_errors`、`review_tool_unavailable`、`review_report_invalid` | — |
| verification | `verification_digest_mismatch`、`payload_digest_mismatch`、`metadata_digest_mismatch`、`report_subject_mismatch` | `verification_artifact_missing`、`report_invalid` | `recompute_unavailable` |
| gate（GV-1） | `gate_record_mismatch` | `gate_source_missing`、`gate_source_integrity_not_pass` | `gate_source_unrecognized`、`approval_self_declared_only` |
| gate（GV-2） | — | — | `separation_of_duty_not_shown`、`actor_relation_unknown`、`approver_association_not_shown`、`approval_not_shown` |
| gate（GV-3） | `gate_binds_other_commit` | `gate_record_missing` | `approval_revision_unverifiable` |
| gate（GV-4） | `approval_stale` | — | `approval_revision_unverifiable`、`approval_self_declared_only` |
| github | `store_manifest_mismatch`、`repository_mismatch` | `integrity_not_pass`、`evidence_id_missing`、`capture_incomplete` | — |

rev0 からの変更: `approval_stale` は NOT_PROVEN から BROKEN へ（D-3）。`gate_record_forbidden_source` は削除し、`approval_self_declared_only`（NOT_PROVEN）に置き換えた。Manifest の `digest_mismatch` / `artifact_missing` は、参照する Link ごとのコード（`review_digest_mismatch` など）に分けた。
