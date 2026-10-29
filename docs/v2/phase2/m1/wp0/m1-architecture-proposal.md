# Phase 2 / M1 — Evidence Integrity Foundation: Architecture Proposal

状態: **提案（WP0）。未実装。** Location、公開範囲、`.gitignore` 変更などは Human 判断（§8）。

前提: `repository-baseline.md`、`helper-audit.md`（HA-1〜HA-13）、`acceptance-alignment-audit.md`（S7-xx、AG-1〜AG-8）。

## 1. 目的と非目標

目的:

1. 事前基準の条文と、判定コード・Test を1対1で結ぶ（Phase 1 の §7 乖離を再発させない）
2. GitHub API の応答本文を Hash 付きで保存し、判定をその Raw からオフラインで再生成できるようにする
3. Evidence の欠損・改変・来歴の混同を、判定の前に検出して Fail-closed にする

非目標（M1）:

* GitHub への書き込み（Push、PR、Status、Ruleset）。SHA-pinned Push の新規開発もしない
* Phase 1 の Evidence・判定・Acceptance Criteria の変更、FAILED / NOT_PROVEN の再分類
* P2（Issuer Pinning の独立検証）の実施。M1 はその Evidence を受け取れる基盤まで
* Dependency の追加

## 2. 全体構成

```text
                 (Human承認, 読み取りのみ)
GitHub API ──► [2] Raw Evidence Collector ──► [6-1] Pre-store Secret Gate
                                                   │ pass        │ hit
                                                   ▼             ▼
                                   [4] Immutable Evidence Store  local-only raw / WITHHELD
                                       rev-NNNN/ + MANIFEST.json
                                                   │
[1] Acceptance Definition Registry ───────┐        ▼
   (条文 → axis → rule → test)             │  [3] Evidence Integrity Validator
                                           │        │ ok           │ ng → NOT_PROVEN (fail-closed)
                                           ▼        ▼
                                     [5] Deterministic Evaluator
                                           │ decision payload (canonical JSON, sha256)
                                           ▼
                     [6] Offline Replay ◄──┴──► [7] Acceptance Report Generator
```

境界:

* ネットワークに触れるのは [2] だけ。[1][3][4][5][6][7] は完全オフライン・決定論的
* Agent・LLM・MCP・Kiro に依存しない（`tech.md` Core の独立性）
* [2] は `gh` を argv 配列で呼ぶ外部 Command 実行で、Security Boundary として扱う

## 3. Component Design

### 3-1. Acceptance Definition Registry

責務: 事前基準の条文を機械可読にし、条文 → 判定軸 → 判定規則 → Test → 必要 Evidence を固定する。

* 形式: JSON（標準ライブラリで読める。YAML の曖昧さを避ける）
* 1 Definition = 1 条文。§7 は `acceptance-alignment-audit.md` §2 の S7-01〜S7-19、S6-01 を初期内容にする
* 各 Definition は出典の **Git commit と条文の SHA-256** を持つ。Evaluator は、出典ファイルのその commit 上のバイト列から条文を再抽出し、Hash が一致しない Definition を拒否する
* 判定規則は名前付きの純関数（`rule_id`）で参照する。Registry に式は書かない（評価器を作らない）
* Scenario 合成規則（§7「any FAILED part makes it FAILED」）も Definition として持つ
* 軸を分ける: `s7.required.impostor_not_required`、`s7.required.app_required`、`s7.required.merge_state`、`phase1.issuer_pinning_independent`（§7 外、rev2 で追加）。どの軸が Scenario 判定に入るかを `contributes_to` で固定する

Phase 1 との関係: Phase 1 の §7 を Registry 化するのは「Phase 1 の基準を再判定するため」ではなく、M1 Evaluator の Regression Oracle（rev2 の FAILED と一致すること）を作るためである。出力は Phase 1 の判定を置き換えない（§3-6）。

### 3-2. Raw Evidence Collector

責務: GitHub API の応答をバイト列のまま取得し、Envelope と一緒に Store に渡す。判定はしない。

* `gh api --include <endpoint>`（status line・header・body を1つの stdout で受ける）を argv 配列で実行。`iacreview/proc.run_bounded`（timeout・出力上限・process group 停止）を使う
* 取得は GET（GraphQL は query の POST）だけ。Endpoint は allowlist（Registry の `evidence_requirements` から生成）。任意の path を受け付けない
* 1 page = 1 Raw Evidence。`Link: rel="next"` があれば次 page を取得し、すべての page を同じ Collection に入れる。上限 page 数を超えたら Collection を `complete: false` にする
* GraphQL は `pageInfo { hasNextPage }` と `totalCount` を query に含め、`hasNextPage: true` なら `complete: false`
* 失敗（非0終了、HTTP 4xx/5xx、timeout、出力上限）も Raw として保存する（本文と診断）。失敗を省略しない
* dry-run 既定。`--execute` なしでは取得予定の endpoint 一覧と件数だけを表示する（Helper の `Ctx.run` / `confirm` と同じ形）
* Token は `gh` の認証に任せ、Collector は値を読まない・渡さない・記録しない。どの認証主体で取得したかは `actor_class`（`unauthenticated` / `owner_token` / `app_installation`）として申告値で記録する
* M1 の Test は記録済み応答（fixture）で行い、GitHub API を呼ばない

### 3-3. Evidence Integrity Validator

責務: 判定の前に Evidence Set の完全性を検査する。合否を決めるのは Validator と Evaluator で、Collector や Agent の自己申告ではない。

検査（いずれか1つでも失敗すれば、その Evidence に依存する軸は NOT_PROVEN。PASS / FAILED にしない）:

| ID | 検査 |
| --- | --- |
| V1 | MANIFEST の全ファイルが存在し、SHA-256 と size が一致 |
| V2 | MANIFEST 外のファイルがない（Revision 内） |
| V3 | MANIFEST 自身の Hash が、親 Revision 連鎖（`REVISIONS.json`）の記録と一致 |
| V4 | Envelope の必須 field がある（provenance、observed_at、request、http_status、complete、sanitization） |
| V5 | Collection が `complete: true`（Pagination 欠落、truncation がない） |
| V6 | `http_status` が成功で、body が JSON として parse できる（parse は検査のときだけ。保存は bytes） |
| V7 | Definition が要求する provenance 区分を満たす（例: `API` を要求する軸に `HUMAN` だけの Evidence は不可） |
| V8 | 失効（revoked）・置換（superseded）された Evidence を current として使っていない |
| V9 | Sanitized Evidence の場合、Evaluator が使う field が allowlist 内にあり、redaction の影響を受けていない |

### 3-4. Immutable Evidence Store

責務: Evidence を上書きせず、Revision 単位で固定する。

```text
<store-root>/
├── REVISIONS.json                 Revision 連鎖（append-only）
└── rev-0001/
    ├── MANIFEST.json              全ファイルの path, sha256, size, role
    ├── envelopes/<evidence_id>.json
    ├── raw/<evidence_id>.bin      応答バイト列（公開可のときのみ）
    ├── sanitized/<evidence_id>.json
    └── decisions/<run_id>.json    Evaluator 出力（payload と metadata を分離）
```

* 書き込みは `save_new` と同じ `os.open(O_WRONLY|O_CREAT|O_EXCL, 0o600)`。既存ファイルがあれば失敗する（退避名を作らない。Revision 内で名前が衝突するのは異常）
* Revision の確定 = MANIFEST を書き、`REVISIONS.json` に `{rev, manifest_sha256, prev_manifest_sha256, created_at, reason}` を追記。確定後の Revision には書かない
* 失効・訂正は新 Revision の `supersedes` / `revokes`（evidence_id と理由）で表す。古いファイルは消さない（rev2 §2 の様式を機械可読化）
* Path は `iacreview/pathguard.resolve_within` で Store root 配下に限定。symlink を拒否

### 3-5. Deterministic Evaluator

責務: Registry と Validator 通過済み Evidence から、軸ごとの判定と Scenario 判定を出す。

* 判定語: `PASS` / `FAILED` / `NOT_PROVEN`（軸）、Scenario 合成は Registry の規則（§7 は「FAILED が1つでもあれば FAILED、全 PASS なら PASS、それ以外 NOT_PROVEN」）。`PARTIAL` は Phase 単位の集計語としてだけ使う（rev2 §0）
* 各軸の結果は `{definition_id, rule_id, status, reason_code, evidence_refs[]}`。`reason_code` は閉集合
* Helper から移す純関数: `resolve_contexts`、`classify_app_check`、`report_digest`、`provenance`（欠落を NOT_PROVEN に修正）、`steal_part` の判定部
* 新規: §7 required 軸の3規則（S7-08 / S7-09 / S7-10）、S7-15 の Scenario FAILED 規則
* 出力 payload は canonical JSON（`iacreview/remediation/report.canonical` と同じ: `sort_keys`、`ensure_ascii`、`(",", ":")`）、`payload_sha256` を付ける。実行時刻・host 等は metadata に分離する（Phase 1 AC20 と同じ分離）
* Evaluator は入力を変更しない。I/O は呼び出し側（Replay）が行う

### 3-6. Offline Replay

責務: Store の Revision だけから判定を再生成し、記録済み Decision と byte 比較する。

* 入力: Revision path と Registry（commit 指定）。ネットワーク禁止（Test で socket を塞いで確認）
* 手順: Validator → Evaluator → payload の SHA-256 を記録済みと比較 → 一致 / 不一致を出力
* Phase 1 Legacy Replay: E18 などの抽出済みデータを `provenance: DERIVED_HELPER_OUTPUT` の Evidence として読み、§7 準拠 Evaluator で判定した結果を、rev2 の確定値（Oracle）と比較する。**結果は新しいファイルにだけ書き、Phase 1 のファイルと判定は変更しない。** DERIVED Evidence は M1-04 / M1-10 の「Raw」要件を満たさないため、Legacy Replay の判定は常に「派生データからの再現」と明記する

### 3-7. Acceptance Report Generator

責務: Decision payload から JSON と Markdown を決定論的に生成する。

* 判定を新たに作らない（payload を表にするだけ）。payload にない主張を書かない
* 各行に Definition ID、条文 Hash、Evidence ID、provenance 区分、Revision、payload_sha256
* NOT_PROVEN には理由コードを必ず表示する。Validator の失敗、Tool 不在、検査未実施を PASS と書かない

## 4. Data Model

### 4-1. Acceptance Definition

```json
{
  "definition_id": "s7.required.impostor_not_required",
  "source": {"path": "docs/v2/phase1/app-demo-plan.md", "commit": "24b7a6e…(40桁)", "section": "7",
             "clause_sha256": "…", "clause_locator": {"start_line": 0, "end_line": 0}},
  "axis": "required",
  "rule_id": "impostor_is_required_false",
  "on_violation": "FAILED",
  "on_missing_evidence": "NOT_PROVEN",
  "contributes_to": ["scenario:G3", "scenario:G3S", "scenario:G6"],
  "evidence_requirements": [{"kind": "github_graphql", "query_id": "pr_status_rollup_is_required",
                             "provenance": ["API"], "complete": true}],
  "tests": ["tests/…/test_….py::test_…"],
  "fixed_at": {"commit": "…", "note": "Registry 自体の固定 commit"}
}
```

### 4-2. Evidence Envelope

```json
{
  "envelope_version": 1,
  "evidence_id": "rev-0001/gh/0007",
  "collection_id": "rev-0001/gh/pr-5-rollup",
  "provenance": {"class": "API", "method": "gh api --include", "actor_class": "owner_token",
                 "collector": {"name": "…", "version": "…", "git_commit": "…", "sha256": "…"}},
  "request": {"method": "POST", "endpoint": "graphql", "query_id": "…", "query_sha256": "…",
              "variables": {"owner": "…", "name": "…", "pr": 5}},
  "observed_at": "2026-…Z",
  "server_date": "…",
  "http_status": 200,
  "headers_kept": {"content-type": "…", "etag": "…", "link": "…", "x-github-request-id": "…"},
  "body": {"sha256": "…", "size": 0, "stored_as": "raw|sanitized|withheld", "path": "raw/….bin"},
  "pagination": {"page": 1, "has_next": false, "total_count": 5},
  "complete": true,
  "sanitization": {"status": "none|redacted|withheld", "rules_version": "…", "redaction_count": 0,
                   "sanitized_sha256": null},
  "errors": []
}
```

* `provenance.class` は閉集合: `API`（Collector が取得）、`LOCAL_GIT`（ローカル Git object）、`LOCAL_FILE`、`HUMAN`（人手報告・UI 観察）、`DERIVED`（他の Evidence から計算）、`DERIVED_HELPER_OUTPUT`（Phase 1 Helper の抽出済み出力）
* `HUMAN` は `attested_by`（役割名。個人名・メールは入れない）と `statement` を持ち、`body` を持たない
* 保存しない header: `authorization`、`set-cookie`、`x-oauth-scopes` の値（scope は判定に使わない）など。allowlist 方式

### 4-3. Legacy Evidence Map（Phase 1）

```json
{"evidence_id": "E18", "source_index": "rev2/phase1-evidence-index.md", "path": ".agents/…/app-evidence.20261028T045529589034Z-1.json",
 "sha256_at_wp0": "a1296349…", "provenance": "DERIVED_HELPER_OUTPUT", "status_in_rev2": "current",
 "raw_available": false, "notes": ["required 軸は rev2 で §7 により再判定", "G11 項目は revoked"]}
```

E01〜E40、E23-x、E23b-x、H01〜H03、github-evidence の各項目を同じ形にする。H01〜H03 は `HUMAN`、github-evidence は `API`（ただし `fidelity: transcribed`、Workflow の b64 だけ `raw`）。

### 4-4. Decision

```json
{"payload": {"registry_commit": "…", "evaluator_version": "…", "revision": "rev-0001",
             "axes": [{"definition_id": "…", "subject": "scenario:G3", "status": "FAILED",
                       "reason_code": "impostor_is_required_true", "evidence_refs": ["…"]}],
             "scenarios": [{"id": "G3", "status": "FAILED", "rule": "s7.compose"}]},
 "metadata": {"generated_at": "…", "duration_ms": 0, "payload_sha256": "…"}}
```

## 5. Security Design

### 5-1. 保存前検査（Secret / Token / PII）

* 対象: すべての Raw body、Job log、Artifact、Envelope、Decision、Report
* 規則: Helper の `_SECRET_PATTERNS`（PEM、`gh[opusr]_`、`github_pat_`、`v1.`、JWT）と `.github/scripts/scan_secrets.py` の規則を1か所の規則集に統合する（2つの規則集を並置しない）。PII は GitHub 応答の既知 field（`email`、`avatar_url`、`html_url` of users、`gravatar_id`、commit `author.email` 等）を field 単位で扱う
* 検査は保存の**前**に行う。検出時は §5-2

### 5-2. Raw を安全に保存できない場合

| 状況 | 扱い |
| --- | --- |
| Secret 様の文字列を検出 | Raw を公開 Store に書かない。ローカル専用領域（Git 管理外、0600）に置くか、置かない（`withheld`）かを Human が決める。公開側には Sanitized と `raw_sha256` だけ |
| PII を含む | 公開側は field allowlist で Sanitized を作る。Raw はローカル専用 |
| 検査自体が失敗（規則の読込失敗、decode 不能） | 保存しない。Envelope に `errors` を記録し、その Evidence は NOT_PROVEN |
| Raw がない（Phase 1 の多く） | `raw_available: false`。推測で補わない |

`withheld` / `redacted` の Evidence に依存する軸は、Evaluator が使う field が redaction の影響を受けない場合だけ判定できる（V9）。「Raw と Sanitized で同じ Decision になる」ことを Test で確認する。

Hash の注意: 低エントロピーの値（短い ID 等）を含む Raw の Hash を公開すると、総当たりで値を推定できる場合がある [推論]。Token・鍵は高エントロピーで実用上の問題は小さいが、PII 単体の Hash は公開しない。

### 5-3. Raw と Sanitized の区別

* ファイル名・ディレクトリで分ける（`raw/` と `sanitized/`）。同じファイル名に両方を入れない
* Envelope の `body.stored_as` と `sanitization.status` で区別する。Validator は不一致を拒否
* Sanitized は Raw の部分集合（field 削除と固定文字列置換だけ）。値を書き換えない

### 5-4. Hash と Manifest

* ファイルは SHA-256（`_sha256` と同じ）。JSON の内容 Hash は canonical JSON
* MANIFEST は path 昇順。MANIFEST 自身の SHA-256 を `REVISIONS.json` に連鎖させる（前 Revision の Hash を持つ）

### 5-5. Git 管理対象とローカル専用の境界

| 区分 | 置き場所（案） | Git |
| --- | --- | --- |
| Registry、Evaluator、Validator、Store・Replay・Report のコード、Test、合成 fixture | Git 管理（Location は D-1） | 追跡 |
| Sanitized Evidence、Envelope、MANIFEST、Decision（公開可と判断したもの） | 公開 Store | 追跡（Human 承認後） |
| Raw のうち Secret / PII を含みうるもの、targets（アカウント名） | ローカル専用 Store | 追跡しない |
| Phase 1 の `.agents/` | 現在地のまま | 追跡しない。変更しない |

`.agents/` は現在 ignore されていない（`repository-baseline.md` §3-1）。ローカル専用 Store を `.agents/` 配下に置くなら、`.gitignore` への追加を Human 承認で行うことを推奨する（D-3）。

### 5-6. 不完全 Evidence の Fail-closed

* Validator の V1〜V9 のいずれかが失敗した Evidence に依存する軸は NOT_PROVEN。PASS にも FAILED にもしない
* Tool 不在（`gh` なし等）、Timeout、出力上限超過、Pagination 未完了は、それぞれ別の reason_code
* Evaluator が未知の field 値・未知の Definition を受けたら NOT_PROVEN（既定値で埋めない。HA-5 の修正）

### 5-7. 来歴上の限界（Git Commit だけでは証明できないこと）

* Commit の日時は作成者が自由に設定できる。Commit は「その時点より前に存在した」ことを証明しない。Remote への Push 時刻や外部の Timestamp を使わない限り、事前固定は自己申告である
* GitHub API の応答には署名がない。保存した Raw が GitHub から来たことは、Collector の申告と `x-github-request-id` 等の状況証拠に留まる。TLS のセッションは保存されない
* 取得後の改変は Hash と Manifest で検出できるが、取得前・取得中の改変（Collector 自身の改ざん）は検出できない
* Phase 1 の Evidence は、WP0 時点の Hash を記録しても、作成時点の内容と同じことを証明しない
* Secret scan の0件は、規則に一致するものが見つからなかったことだけを示す。機密情報が存在しない証明ではない

これらは M1 の Report に Known Limitation として常に表示する。

## 6. Dependency

追加しない。

| 用途 | 使うもの |
| --- | --- |
| JSON、Hash、ファイル I/O | 標準ライブラリ（`json`、`hashlib`、`os`） |
| 外部 Command | `iacreview/proc.run_bounded`（既存） |
| Path 安全性 | `iacreview/pathguard`（既存） |
| Canonical JSON | `iacreview/remediation/report.canonical`（既存） |
| Git tree 比較 | `iacreview/remediation/gitsnap` または Helper の `committed_tree`（WP3 でどちらかに統一） |
| Mutation Test | 標準の pytest と手書きの Mutant 関数（mutmut 等は導入しない） |
| GitHub 取得 | 既存の `gh` CLI（Runtime Dependency ではない外部 Tool。不在時は TOOL_UNAVAILABLE 相当で NOT_PROVEN） |

## 7. WP1〜WP5 の実装構成

| WP | 内容 | 主な成果物 | 対応 M1 AC | 再利用 / 新規 | 工数（推定） |
| --- | --- | --- | --- | --- | --- |
| WP1 | Source 管理と Acceptance Definition Registry | 汎用 Helper 部分の抽出（抽出元 SHA-256 を記録）、Registry スキーマと §6〜§7 の Definition、条文 Hash 検証、条文 ↔ 関数 ↔ Test の対応表と、その完全性 Test | M1-01、M1-02 | 抽出: `save_new`、`redact`、`resolve_contexts`、`classify_app_check`、`report_digest`、`committed_tree` / `compare_tree`。新規: Registry | 1.5〜2.5 日 |
| WP2 | Raw Evidence Collector、Immutable Store、保存前 Secret Gate | Envelope、Store（O_EXCL、Revision、MANIFEST、REVISIONS 連鎖）、Collector（fixture Test のみ、実取得なし）、統合 Secret 規則 | M1-04、M1-07、M1-08、M1-09 | 修正: `gh_call` / `gh_json`、`redact`。再利用: `save_new`、`proc.run_bounded`、`pathguard`。新規: Envelope、Store | 2.5〜3.5 日 |
| WP3 | Evidence Integrity Validator、Legacy Evidence Map、Artifact Integrity | V1〜V9、Legacy Map（E01〜E40、H01〜H03、github-evidence）、Source / Commit / Published Artifact の比較 | M1-06、M1-10、M1-11 | 抽出: `compare_tree`、`classify_existing_pr` の判定、blob id 照合。新規: Validator、Legacy Map | 2〜3 日 |
| WP4 | Deterministic Evaluator、Offline Replay、Mutation Test | §7 準拠 Evaluator、Scenario 合成、Replay（ネットワーク遮断 Test）、Mutant 集合と kill Test、Legacy Replay（新ファイルにだけ出力） | M1-03、M1-05、M1-12（判定部） | 修正: `provenance`、`rules_problems`、`_required_part`。新規: required 3規則、合成規則、Replay | 2.5〜3.5 日 |
| WP5 | Acceptance Report Generator と Regression 統合 | Report（JSON / Markdown）、Phase 1 結果の Regression（rev2 / rev3 の固定値）、G11b 安全機構の Regression、M1 Acceptance の実行 | M1-12、全体 | 新規: Report。維持: Push 系は Test 対象としてのみ | 1.5〜2 日 |

合計の目安: 10〜14.5 日（1人、Human レビュー待ち時間を除く）。推定であり、実測ではない。

推奨順序: WP1 → WP2 → WP3 → WP4 → WP5。

* WP1 が先: 条文の対応表がないと、後の Evaluator が Phase 1 と同じ乖離を起こしうる（handoff P1 の理由と同じ）
* WP2 → WP3: Validator は Store の Manifest 形式に依存する
* WP4 は WP3 の Validator 通過を入力の前提にする
* 各 WP の終わりに停止し、Human 承認を得る（`development-workflow.md`）

## 8. Human 判断が必要な事項

| ID | 判断 | 選択肢（推奨を先頭） |
| --- | --- | --- |
| D-1 | Git 管理する Code の Location | (a) オフライン部分を `iacreview/evidence/`（新 Package。Coverage Gate の対象になる）、Collector は同 Package 内だが Skill から import しない (b) `docs/v2/phase2/m1/tools/`（Phase 1 の `docs/v2/phase1/ci/spike/` と同じ扱い。Coverage 対象外） (c) 新しい Root Directory（`structure.md` 変更が必要） |
| D-2 | 公開範囲 | Registry・Code・合成 fixture は公開。targets、Raw、アカウント名を含むものは非公開 |
| D-3 | `.gitignore` に `.agents/` を追加するか | 追加を推奨（誤 commit 防止）。`.gitignore` 変更は要承認 |
| D-4 | ローカル専用 Raw の保存可否と場所 | Secret / PII を含む Raw を保存するか、`withheld` にするか |
| D-5 | Phase 1 Legacy Replay の出力先 | `docs/v2/phase2/m1/` 配下の新ファイル（Phase 1 の場所には書かない） |
| D-6 | 既存 Helper Test の §7 逆期待値の扱い | 変更しない（推奨）。M1 Test で「Phase 1 Helper はこう振る舞った」という記録として参照する |
| D-7 | `gitsnap` と `committed_tree` の統一 | WP3 開始時に差分（mode / extra path の扱い）を比較して決める |
| D-8 | 新 Spec の作成 | `.kiro/specs/<phase2-m1-…>/` に Requirements → Design → Tasks を作るか（`structure.md` の 1 Version = 1 Spec） |

## 9. 再利用・新規実装の根拠（要約）

* 再利用・抽出する: Phase 1 で実測に基づいて作られ、Test がある安全機構（非上書き保存、whole tree 比較、Fail-closed、App check の結合、発行元解決）。作り直すと実測の知見を失う
* 修正して移す: §7 と乖離した判定、欠落を真にする既定値、Raw を捨てる取得経路
* 新規にする: Registry、Envelope、Store の Revision 連鎖、Validator、Replay、Report。既存に相当する実装がない
* 作らない: Push / PR / Status 投稿の新機能。新しい汎用 Framework（Registry は JSON とルール関数の表で足りる）
