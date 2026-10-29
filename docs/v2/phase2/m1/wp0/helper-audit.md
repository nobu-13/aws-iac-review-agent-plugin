# Phase 2 / M1 / WP0 — Helper Responsibility Audit

対象（読み取り専用、未変更）:

* `.agents/tasks/phase1/henv/phase1_appdemo.py`（4,250行、SHA-256 `493177b4…`）
* `.agents/tasks/phase1/henv/phase1_henv.py`（586行、`26b497e0…`）
* `.agents/tasks/phase1/henv/phase1_henv_owner.py`（601行、`47682fb1…`）

行番号はWP0時点のファイルのもの。確度: [実測] コード読解・実行で確認 / [推論] / NOT_VERIFIED。

## 0. 判断区分

| 区分 | 意味 |
| --- | --- |
| 再利用 | 振る舞いを変えずに、Git管理下へ移す（抽出元のHashを記録し、既存Testの趣旨を移植する） |
| 抽出 | 汎用部分だけを移す。アカウント名、demo固有の定数、Scenario定義は持ち込まない |
| 修正 | 移すときに振る舞いを変える。理由は監査所見（§4）に対応させる |
| 新規実装 | 既存に相当する実装がない |
| 維持 | Phase 1の履歴として `.agents/` に残し、M1では使わない。変更もしない |

既存Helperは変更しない（WP0〜M1共通の制約）。「修正」は、新しい場所に移したコードに対するもの。

## 1. Helperの全体構造 [実測]

| Helper | 責務 | 依存 |
| --- | --- | --- |
| `phase1_henv.py` | H-ENV基盤。`Stop`例外、`Ctx`（`run` / `query` / `git` / `confirm` / `save`）、targets検証、legacy demo（`demo-*`）、Kiro比較 | 標準ライブラリ、`git`、`gh` |
| `phase1_henv_owner.py` | Owner run（legacy demo）。`provenance`、`log_facts`、`classify`、`classify_app_check`、`reclassify_saved` | `phase1_henv` |
| `phase1_appdemo.py` | App demo全体。W0、Ruleset、Environment、App JWT、Scenario push、Evidence収集・分類（G0〜G12、G11b）、Artifact Integrity | 上記2つ、`openssl`、PyYAML（遅延import） |

`phase1_appdemo.py` は `sys.path.insert(0, HERE)`（96行）の後に `import phase1_henv as base` / `import phase1_henv_owner as owner`（98〜99行）。3ファイルは一体で動き、単独では抽出できない。

## 2. 機能別の監査

### 2-1. GitHub API の取得方法

| 関数 | 行 | 方法 | 所見 |
| --- | --- | --- | --- |
| `AppCtx.gh_call` | 207 | `subprocess.run(["gh", *args])`（argv配列、shellなし）。stdout/stderrを取得し `diagnose` で要約を `api_log` に追加 | argv方式は安全。stdoutの生バイト列は `decode("utf-8","replace")` と `strip()` の後に返す。**元のバイト列は保持しない** |
| `AppCtx.gh_json` | 216 | `gh_call` の stdout を `json.loads`。非0終了は `Stop(waiting=True)` | **応答本文はここで破棄され、parse済みobjectだけが下流へ渡る** |
| `AppCtx.gh_optional` | 225 | 404だけ `None`、他の失敗は `Stop` | 404と「存在しない」を区別している（良い） |
| `https_json` | 1929 | `urllib.request`、redirect拒否（`_NoRedirect`）、4 MiB 上限で `resp.read` | 4 MiB を超えた本文は切り詰められたまま parse される可能性がある（切り詰めの検出なし）[推論]。App JWT経路のみで使用 |
| `base.Ctx.query` | phase1_henv 100 | `subprocess.run`、stderr は DEVNULL、非0は `None` | **失敗理由が失われる**。`gh run download`（2802行）もこれを使う |
| `GRAPHQL` / `required_view` | 2733 / 2739 | `contexts(first:100)`。`pageInfo` / `totalCount` を取らない | **101件目以降は黙って欠落する** |
| REST一覧 | 1582, 2234, 2844, 3147, 3150, 3271, 3279, 4158 | `per_page=100`、`--paginate` なし、`Link` header を見ない | **Pagination欠落を検出できない**。3271行は `pull_request_target` のRun一覧の最初の100件だけを `display_title` で絞る |

### 2-2. Raw Response の保存

| 保存物 | 関数 | 生バイト列か | 所見 |
| --- | --- | --- | --- |
| `app-evidence*.json`（E18等） | `cmd_app_evidence` 3744 → `collect` 3260 | **いいえ** | `required_view` で平坦化したGraphQL、`_gate_run_detail` でログから抽出したbool、`owner._checks` の抽出fieldだけ。最上位keyは `actions_policy, app_id, classification, effective_rules_main, gate_scripts_commit, pending, repo, scenarios, state, validator_commit` [実測] |
| Job log `app-run-<id>-<job>.log`（E16） | `_job_logs` 2777 | ほぼ生（`gh run view --log` のtext） | `ctx.save`（**上書き**）で保存。Hashなし。Redactなし |
| Report artifact `artifacts/<id>/remediation-report.json`（E17） | `_gate_run_detail` 2800〜2803 | はい（`gh run download` の展開物） | 既存ファイルがあれば再取得しない。取得失敗は `ctx.query` が `None` を返すだけで記録されない。ファイルHashの記録なし（`payload_sha256` の再計算だけ） |
| `ci-run-<id>.json` | phase1_henv `cmd_ci_evidence` 228 | `gh run view --json` のstdout | `ctx.save`（上書き） |
| API呼び出し記録 `app-api-calls.json` | `_report_failed_calls` 4237 | 本文なし（method / endpoint / status） | 失敗時の経路でだけ保存。**`out/` 配下に1件も存在しない** [実測] |

結論: Helperが保存した GitHub API 応答の生本文は存在しない。存在するのは、抽出済みデータ、Job log、Report artifact である（`acceptance-alignment-audit.md` §5）。

### 2-3. Evidence Classification

| 関数 | 行 | 役割 |
| --- | --- | --- |
| `_gate_part` | 3296 | gate部（`owner.provenance` ＋ verify step ＋ publish job） |
| `owner.provenance` | owner 337 | Base gate の8条件 |
| `owner.classify_app_check` | owner 523 | App check（1件、`external_id`、gate run、digest、conclusion） |
| `resolve_contexts` | 3318 | 同名Contextの発行元（REST の `app_id` を優先） |
| `rules_problems` | 3346 | `main` の有効Ruleが App を pin しているか |
| `_required_part` | 3361 | required部。docstring「isRequired is recorded, never decides」 |
| `spoof_part` | 3415 | 偽装耐性 |
| `classify` | 3439 | Scenario単位の合成（`status`） |
| `EXPECTED_OUTCOMES` / `scenario_axes` / `scenario_outcome` | 3510 / 3525 / 3557 | 軸別の結果と `outcome`（PASS / PARTIAL / FAIL / NOT_PROVEN） |
| `steal_part` / `g7_part` | 3601 / 3695 | G11 / G7 |
| `g12_observation` / `g12_classify` | 3858 / 3883 | G12 B1〜B3 |

§7との不一致は `acceptance-alignment-audit.md` §3 で扱う。

### 2-4. Hash計算

| 関数 | 行 | 対象 |
| --- | --- | --- |
| `_sha256` | 610 | bytes の SHA-256 |
| `report_digest` | 2765 | Report の `payload` を canonical JSON（sort_keys、ascii、`(",",":")`）にして SHA-256、`metadata.payload_sha256` と一致したときだけ返す。`iacreview/remediation/report.py` `canonical`（193行）と同じ規則 [実測] |
| `committed_tree` / `compare_tree` | 619 / 643 | commit の全 entry の bytes を読み、承認済み tree の各ファイルと SHA-256 / bytes / mode を比較 |
| `audit_probe_workflow` | 2980 | Probe本文の SHA-256 を `AUDITED_PROBE_SHA256` と比較 |
| `seal_record` / `seal_problems` | 1394 / 1404 | Installation record を App 鍵で署名・検証（`openssl`） |

**保存したEvidenceファイル自体のHashは計算していない。** Manifest もない。

### 2-5. Revision管理・非上書き保存

| 関数 | 行 | 挙動 |
| --- | --- | --- |
| `save_new` | 2418 | 既存なら `<stem>.<UTC>-<n>.<ext>` に退避名を作り、`os.open(O_WRONLY|O_CREAT|O_EXCL, 0o600)` で作成。**上書きしない**（良い） |
| `base.Ctx.save` | phase1_henv 117 | `write_text`。**上書きする** |

`ctx.save` を使う Evidence: `app-simulate.json`（1066, 1071）、`app-state.json`（1846, 1863）、`app-environment*.json`（2161〜2162）、`app-w0-views.json`（2259, 2357）、`app-ruleset.json`（2260, 2360）、`app-w0-start.json`（2337, 2342）、`app-retire-snapshot.json`（2397）、Job log（2782）、`app-api-calls.json`（4245）、owner evidence 一式（owner 148, 259, 510〜511, 586〜587）、legacy demo の ruleset / CI log（phase1_henv 180〜373）[実測]。E09（`app-w0-views.json`）と E16（Job log）はこの経路である。

Revision の機械可読な連鎖（前Revisionとの関係、失効宣言）は Helper にない。失効は rev2 §2 の表（人手）だけで管理されている。

### 2-6. Source / Commit / Artifact Integrity（G11b）

| 機構 | 関数 | 行 | 内容 |
| --- | --- | --- | --- |
| Whole Tree byte comparison | `committed_tree` / `compare_tree` / `artifact_record` | 619 / 643 / 660 | 承認済み tree と commit の全 entry を bytes で比較。余分な path、非regular（symlink、実行bit）、不一致を列挙 |
| Fail-closed | `require_artifact` / `approved_trees` | 673 / 578 | 承認ソースを作れない・読めない・一致しないときは `Stop`。承認ソースのない ref は push 拒否 |
| SHA-pinned Push | `push_refspec` / `push_argv` | 724 / 733 | 40桁SHA `:refs/heads/<ref>`、`+` なし、force 系 flag を拒否 |
| Push前後のSHA検証 | `_push_verified` | 741 | ①local ref が検証済みSHAのまま ②そのSHAを再比較し同じtree ③push ④`ls-remote` が同じSHA |
| 既存PRの分類 | `classify_existing_pr` | 802 | VERIFIED_EXISTING / SKIPPED_UNVERIFIED / BLOCKED。「skip = 安全」としない |
| G11b Gate | `g11b_integrity` | 3048 | source audit、committed workflow、whole tree、approved main 上の1 commit、G11 不変、refspec。全部 ok のときだけ `ready` |
| Push記録 | `_record_push` | 694 | `save_new("push-integrity.json")`（execute時のみ） |

Test: `test_phase1_appdemo_push_gate.py`（40件）、`test_phase1_appdemo_g11b.py`（20件）、`test_phase1_appdemo_branch_integrity.py`（9件）。push primitive に検証 wrapper 経由でしか到達しないことを AST 的に確認する Test（`test_the_push_primitive_is_reached_only_through_the_verifying_wrappers`、push_gate 123行）がある [実測]。

制約: 比較対象の「承認済み tree」は Helper 内の定数と `git show <pin>:<path>` から組み立てる（`demo_files`）。承認の記録自体は Helper の定数（例 `AUDITED_PROBE_SHA256`、2953行）で、承認日時・承認者の機械可読記録はない。

### 2-7. Human承認・dry-run

* `Ctx.confirm`（phase1_henv 107）: TARGET / CHANGE / ROLLBACK を表示し、`--execute` 時は対象名の打ち返しを要求
* `Ctx.run`（phase1_henv 88）: `--execute` なしでは `DRY-RUN:` 表示のみ
* `AppCtx.confirm`（`preconfirmed` で app-w0 の一括承認）
* `refuse_legacy`（298）: legacy demo / 退役 demo を argv に含む呼び出しを拒否

注意: 読み取り系 `ctx.query` / `gh_call` は dry-run でも実行される（読み取りなので意図どおり）[実測]。

### 2-8. Secret Protection

| 機構 | 行 | 内容 | 所見 |
| --- | --- | --- | --- |
| `_SECRET_PATTERNS` / `redact` | 235 / 244 | PEM、`gh[opusr]_`、`github_pat_`、`v1.`、JWT、`Bearer/token/basic`、`authorization/token/password/secret = …` | **`diagnose` の stderr と `_api_message` にだけ適用**。Job log、Evidence JSON、Report artifact には適用しない |
| `pem_problems` | 1181 | `.pem` が git work tree 外にあること等 | 良い |
| `cmd_app_secrets` | 2173 | 鍵を stdin で `gh secret set` に渡す | 値を表示・保存しない設計 |
| `diagnose` | 252 | 本文を記録しない | 良い |

GitHub は Actions log の登録済み Secret をマスクするが、マスクされない形（加工後の値など）は保証されない [推論]。Job log の保存前検査はない。

## 3. 関数単位の再利用判断

| 機能 | 既存実装 | 判断 | 理由 | M1 WP |
| --- | --- | --- | --- | --- |
| 非上書き保存 | `save_new` 2418 | **再利用**（抽出） | O_EXCL・0o600 は要件どおり。退避名の命名だけ Store の Revision 規則に合わせる | WP2 |
| 上書き保存 | `base.Ctx.save` | **維持**（使わない） | 上書きは M1-09 に反する | — |
| `gh` 呼び出し | `gh_call` / `diagnose` | **修正**（抽出） | argv・診断は再利用。stdout を bytes のまま返し、`--include`（status、header）を取れるようにする。`iacreview/proc.run_bounded`（333）で timeout と出力上限を付ける | WP2 |
| JSON化 | `gh_json` | **修正** | parse 前の bytes を Raw として保存し、parse は Validator 通過後に行う | WP2 |
| GraphQL平坦化 | `GRAPHQL` / `required_view` | **修正**（抽出） | 平坦化は Evaluator 側の入力変換として残す。Query に `pageInfo{hasNextPage}` と `totalCount` を追加し、truncation を検出する | WP2 / WP4 |
| REST一覧 | 各 `per_page=100` | **修正** | `Link` header の `rel="next"` を記録し、次 page がある状態を「不完全」として Fail-closed | WP2 |
| 同名Contextの発行元 | `resolve_contexts` 3318 | **再利用** | REST の `app_id` を優先する理由（private App で GraphQL が null）は実測に基づく | WP4 |
| 有効Rule検査 | `rules_problems` 3346 | **修正** | `None`（未読）を NOT_PROVEN にする（現状は required を通す。alignment §3-4） | WP4 |
| gate部 | `_gate_part`, `owner.provenance`, `owner.log_facts` | **修正**（抽出） | 欠落 field の既定値で条件が真になる（alignment §3-3）。欠落は NOT_PROVEN | WP4 |
| App check | `owner.classify_app_check` 523、`report_digest` 2765 | **再利用** | §7 app_check と1対1で対応 | WP4 |
| required部 | `_required_part` 3361 | **修正** | §7 の `isRequired` 条件を実装する（alignment §3-1） | WP4 |
| 偽装部 | `spoof_part` 3415 | **維持**（Phase 1 解釈として保全）＋ **新規**（§7 準拠の判定） | 「Issuer pinning の独立効果」軸として別名で残す価値はある。§7 required 軸の代わりにしない | WP4 |
| Scenario合成 | `classify` / `scenario_outcome` | **修正** | `outcome` の PARTIAL は §7 にない語。Registry の規則で合成する | WP4 |
| G11 / G11b 判定 | `steal_part`, `g11_incident_findings` | **再利用**（判定）。Artifact 結合は **新規** | `steal_part` は workflow 内容を見ない（alignment §3-6） | WP4 |
| G12 | `g12_observation` / `g12_classify` / `G12_EXPERIMENTS` | **維持** | M1 の対象外（P2/P3）。事前定義の作成時刻は検証できない（EG4） | — |
| Whole tree 比較 | `committed_tree` / `compare_tree` / `artifact_record` | **再利用**（抽出） | M1-11 の中核。`iacreview/remediation/gitsnap.py`（`commit_snapshot` 156、`worktree_snapshot` 257）と機能が重なる。gitsnap は blob hash、Helper は bytes＋mode＋extra path。WP3 でどちらに寄せるか決める（重複を作らない） | WP3 |
| Fail-closed 承認 | `require_artifact` | **抽出** | 「承認ソースがない → 拒否」の形を Validator に移す。承認ソースは Registry から得る | WP3 |
| SHA-pinned Push 一式 | `push_refspec` / `push_argv` / `_push_verified` / `push_branch` | **維持** | M1 は Push 機能を新規開発しない。Regression Test の対象として保全（M1-12） | WP5（Test のみ） |
| 既存PR分類 | `classify_existing_pr` | **抽出**（判定のみ） | VERIFIED / SKIPPED_UNVERIFIED / BLOCKED の3値は M1-11 の Published Artifact 判定に使える | WP3 |
| Redact | `_SECRET_PATTERNS` / `redact` | **修正**（抽出） | 保存前の全 Evidence に適用。`scan_secrets.py` の規則と統合し、片方だけの規則を作らない | WP2 |
| PEM検査 | `pem_problems` | **維持** | M1 は鍵を扱わない | — |
| 承認・dry-run | `Ctx.confirm` / `Ctx.run` | **再利用**（形のみ） | M1 Collector は読み取りだけだが、取得先と件数を表示し、`--execute` なしでは取得しない | WP2 |
| 時刻 | `parse_utc` / `utc_iso` / `w0_duration` | **再利用** | 旧 Parser の不具合（E40）を回避済み。Raw の `Date` header 解釈に使う | WP2 |
| 再分類 | `cmd_app_reclassify` 3777 | **修正** | 「新ファイルに書く」は良い。入力が Raw でなく抽出済みデータなので、Replay の入力にはしない | WP4 |

## 4. 実装上の問題（Finding）

| # | 区分 | 所見 | 根拠 |
| --- | --- | --- | --- |
| HA-1 | 確認済み Issue | §7 の `isRequired` 条件が判定に使われない | `_required_part` 3361 の docstring と本体（`is_required_info` に記録するだけ）。Test `test_is_required_is_recorded_but_never_decides`（required 99行）が固定 |
| HA-2 | 確認済み Issue | 現行 Evaluator は G3 / G3S / G6 を PARTIAL と出力し、rev2 の FAILED と異なる | 本WP0で E18 を in-memory で再分類し、保存済み classification と完全一致（`replay identical to saved: True`）、G3 / G3S / G6 = `NOT_PROVEN` / `PARTIAL` [実測] |
| HA-3 | 確認済み Issue | 抽出済みデータだけを保存し、GitHub 応答本文を保存しない | `gh_json` 216、`required_view` 2739、E18 の構造 [実測] |
| HA-4 | 確認済み Issue | Pagination・truncation を検出しない | §2-1 |
| HA-5 | 確認済み Issue | 欠落 field が既定値で真になる | `owner.provenance` 354（`log_validator_checked_out` 既定 True）、357（`token_permissions` 既定 = 期待値）、355（旧 key へのfallback） |
| HA-6 | 確認済み Issue | 有効 Rule を読めなかったとき（`None`）に required が PROVEN になりうる | `rules_problems` 3346〜3349、Test `(None, "PROVEN")`（required 106行） |
| HA-7 | 確認済み Issue | 判定規則の版が Evidence に記録されない。同じ Scenario の判定が Evidence ファイルごとに変わる | `app-evidence.json`: G2 / G3 / G3S / G6 = FAILED、G11 = NOT_PROVEN。`…044355…` / `…045529…`: G2 = PROVEN/PASS、G3 等 = PARTIAL、G11 = PASS。`app-evidence-reclassified.json`: G11 = NOT_PROVEN。いずれも version key なし [実測] |
| HA-8 | 確認済み Issue | 一部 Evidence が上書き保存 | §2-5 |
| HA-9 | 確認済み Issue | Job log・Report artifact に Secret 検査がない | §2-8 |
| HA-10 | 確認済み Issue | 取得時刻が Evidence 本体にない（E18） | E18 最上位 key [実測]。時刻はファイル名（`save_new` の書き込み時刻）と mtime だけ |
| HA-11 | 高い可能性のある Risk | `gh run download` の失敗が記録されない | `ctx.query` は stderr を捨てる（phase1_henv 100）。digest が `None` になり app_check は NOT_PROVEN になるので、PASS 側には倒れない [推論] |
| HA-12 | 文脈依存 | `spoof_part` は App success＋偽装＋BLOCKED を PROVEN とする | 3432〜3433。BLOCKED の原因を他の理由（strict 等）と区別しない [推論] |
| HA-13 | 確認済み Issue | Helper が Git 管理外で、Evidence 生成時の Helper 内容を特定できない | `repository-baseline.md` §3-1 |

HA-1〜HA-13 はいずれも M1 で新しい実装に反映する。既存 Helper と Phase 1 の判定は変更しない。
