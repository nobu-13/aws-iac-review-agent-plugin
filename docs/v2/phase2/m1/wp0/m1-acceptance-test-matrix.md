# Phase 2 / M1 — Acceptance Test Matrix（M1-01〜M1-12）

状態: **事前定義（WP0）。未実施。** この表は実装前に固定する。実装後に結果を見て変更しない（変更が必要なら新 Revision と理由を残す）。

判定語:

* PASS: 事前に固定した条件を、実行した Test / 検査の結果で満たした
* FAILED: 事前に固定した条件に、実行結果が反した
* NOT_PROVEN: 判定に必要な Test / Evidence がない、未実施、Tool 不在、Timeout

NOT_PROVEN、SKIP、Tool 不在、Timeout を PASS として数えない。1つの AC に FAILED の条件が1つでもあれば、その AC は FAILED。

共通の事前条件（全 AC）:

* P0: Phase 1 の Evidence・判定・Helper・Helper Test のファイルが、WP0 時点の SHA-256（`repository-baseline.md` §6）から変わっていない
* P1: GitHub API を呼ばない（Collector の Test は記録済み fixture のみ）。Test 実行中はネットワークを遮断する（socket を塞ぐ fixture）
* P2: Dependency を追加していない（`pyproject.toml` 不変）

---

## M1-01 Helper・AC・Evaluator・Test の Git 管理

| 項目 | 内容 |
| --- | --- |
| 事前条件 | D-1（Location）と D-2（公開範囲）を Human が決定済み |
| 正常系 | ①抽出した Code・Registry・Evaluator・Test が `git ls-files` に含まれる ②抽出元（`.agents/…/phase1_*.py`）の SHA-256 と関数名・行範囲が、抽出先の provenance 記録にある ③clean checkout（`.agents/` `.kiro/` なし）で M1 の Test が実行できる |
| 異常系 | ①抽出先に `<account>` 等のアカウント名（匿名化。Pre-Commit Remediation C-1）、targets、`out/` の Evidence が含まれる ②`.agents/` 配下のファイルを import している ③抽出元 Hash が P0 と異なる |
| 必要 Evidence | `git ls-files` 出力、provenance 記録、clean checkout での pytest ログ（Command、exit code、件数） |
| PASS | 正常系①〜③をすべて満たし、異常系がない |
| FAILED | 異常系のいずれかがある |
| NOT_PROVEN | D-1 / D-2 未決定、または clean checkout を実行していない |
| 限界 | Git 管理に入れたことは、Phase 1 当時の Helper 内容を証明しない（M1-10 と分ける） |
| 担当 | WP1 |

## M1-02 条文と判定コード・Test の対応

| 項目 | 内容 |
| --- | --- |
| 事前条件 | Registry に §6〜§7 の Definition（S7-01〜S7-19、S6-01）が入っている |
| 正常系 | ①各 Definition に `rule_id` が1つ、Test が1つ以上ある ②各 `rule_id` が Evaluator に存在する ③Definition の `clause_sha256` が、出典 commit 上の条文バイト列から再計算した値と一致 ④判定に入る Definition で、Test のない Definition が0件（完全性 Test が検査） |
| 異常系 | ①条文 Hash 不一致（条文が後から変わった、または locator が誤り）→ その Definition を拒否 ②Test のない Definition ③Registry にない `rule_id` を Evaluator が使う ④出典 commit が HEAD の祖先でない |
| 必要 Evidence | 完全性 Test の結果、対応表（Definition → rule → test） |
| PASS | 正常系をすべて満たす |
| FAILED | 異常系①〜④のいずれかが Test で見逃される（Test 自体の欠陥） |
| NOT_PROVEN | Registry 未作成、完全性 Test 未実行 |
| 担当 | WP1 |

## M1-03 Mutation Test による誤実装の検出

| 項目 | 内容 |
| --- | --- |
| 事前条件 | M1-02 PASS。Mutant は実装前に列挙して固定する（下表） |
| 正常系 | 各 Mutant を Evaluator に差し込むと、M1 の条文 Test が少なくとも1件失敗する（kill）。全 Mutant が kill される |
| 異常系 | 生き残る Mutant がある |
| 必要 Evidence | Mutant ごとの kill 結果（Mutant ID、失敗した Test 名） |
| PASS | 固定した Mutant がすべて kill される |
| FAILED | 1件でも生き残る |
| NOT_PROVEN | Mutation Test 未実行 |
| 担当 | WP4 |

固定する Mutant（初期集合。追加は可、削除は不可）:

| ID | Mutant | 由来 |
| --- | --- | --- |
| MU-01 | `isRequired` を判定に使わない（記録だけ） | HA-1、Phase 1 Helper の実際の振る舞い |
| MU-02 | 偽装 `isRequired = true` で Scenario を FAILED にせず NOT_PROVEN にする | S7-15 |
| MU-03 | App check の `isRequired = true` 条件を省く | S7-09 |
| MU-04 | Scenario 合成で FAILED より NOT_PROVEN を優先する | S7-02 |
| MU-05 | 欠落 field を既定値で真にする（`token_permissions`、`log_validator_checked_out`） | HA-5 |
| MU-06 | 有効 Rule 未読（`None`）を PASS 扱い | HA-6 |
| MU-07 | Validator 失敗の Evidence で判定を続ける | §5-6 |
| MU-08 | `complete: false`（Pagination 未完了）を無視 | HA-4 |
| MU-09 | App failure による BLOCKED を Issuer Pinning の PASS として数える | §3-2（alignment） |
| MU-10 | `HUMAN` provenance だけで `API` 要求の軸を PASS | M1-07 |
| MU-11 | Scenario 判定に PARTIAL を返す | S7-02、rev2 §0 |
| MU-12 | 同名 App check が2件のとき PASS | S7-04 |

## M1-04 GitHub API Raw Evidence の Hash 付き保存

| 項目 | 内容 |
| --- | --- |
| 事前条件 | Store と Collector が実装済み。Test は記録済み応答 fixture（合成。実アカウント・Token を含まない） |
| 正常系 | ①応答バイト列が `raw/<id>.bin` に変更なしで保存され、SHA-256 が Envelope と MANIFEST に一致 ②status・header allowlist・`observed_at`・request が Envelope にある ③複数 page が1 Collection にまとまり `complete: true` ④失敗応答（4xx/5xx、timeout）も Envelope 付きで保存される |
| 異常系 | ①`Link: rel="next"` があるのに次 page を取らない → `complete: false` で保存（PASS 扱いにしない） ②GraphQL `hasNextPage: true` → `complete: false` ③出力上限超過 → 切り詰めた本文を完全として保存しない ④`gh` 不在 → 取得しない、NOT_PROVEN の Envelope |
| 必要 Evidence | fixture からの保存結果、MANIFEST、Hash 再計算結果 |
| PASS | 正常系①〜④、異常系①〜④がすべて期待どおり |
| FAILED | 本文の変形、Hash 不一致、不完全を完全として保存 |
| NOT_PROVEN | 実 GitHub からの取得は M1 では行わない。実取得による確認は P2 以降（Human 承認後）で、M1 では NOT_PROVEN のまま残す |
| 限界 | 保存した本文が GitHub 由来であることの暗号学的証明はない（architecture §5-7） |
| 担当 | WP2 |

## M1-05 同一入力による同一判定・同一出力 Hash

| 項目 | 内容 |
| --- | --- |
| 事前条件 | Evaluator、Replay、Report が実装済み |
| 正常系 | ①同じ Revision と Registry commit で2回 Replay し、payload が byte 一致、`payload_sha256` 一致 ②`PYTHONHASHSEED=random` で一致 ③CI の Python（3.9 / 3.11 / 3.13）で一致（CI を実行した場合） ④Report（JSON / Markdown）も byte 一致 ⑤metadata（時刻等）は payload に入らない |
| 異常系 | ①入力 Evidence の1 byte を変える → Validator で拒否（M1-06）②Registry を変える → payload の `registry_commit` が変わる |
| 必要 Evidence | 2回分の payload Hash、Test ログ |
| PASS | 正常系①②④⑤と異常系を満たす。③は CI 実行時のみ判定 |
| FAILED | 同一入力で Hash が異なる |
| NOT_PROVEN | ③を CI で実行していない場合、③だけ NOT_PROVEN（AC 全体は ③を除いて判定し、その旨を明記） |
| 担当 | WP4（判定）、WP5（Report） |

## M1-06 Evidence の欠損・改変の検出

| 項目 | 内容 |
| --- | --- |
| 事前条件 | Validator V1〜V9 が実装済み |
| 正常系 | 改変のない Revision が Validator を通過する |
| 異常系（各1 Test） | ①ファイル削除 ②1 byte 改変 ③MANIFEST 外ファイル追加 ④MANIFEST 改変（REVISIONS 連鎖不一致）⑤Envelope 必須 field 欠落 ⑥`complete: false` ⑦失効 Evidence の使用 ⑧symlink への置換 ⑨Sanitized で判定 field が redact 済み。いずれも、依存する軸が NOT_PROVEN になる（PASS にも FAILED にもならない） |
| 必要 Evidence | 異常系ごとの Validator 結果と Decision |
| PASS | 異常系①〜⑨がすべて検出され、該当軸が NOT_PROVEN |
| FAILED | 1件でも検出漏れ、または欠損で PASS / FAILED が出る |
| NOT_PROVEN | Validator 未実装 |
| 限界 | 検出できるのは保存後の改変。保存前の改変は検出できない |
| 担当 | WP3 |

## M1-07 Human / API / Local Provenance の区別

| 項目 | 内容 |
| --- | --- |
| 事前条件 | Envelope の `provenance.class` 閉集合（API / LOCAL_GIT / LOCAL_FILE / HUMAN / DERIVED / DERIVED_HELPER_OUTPUT） |
| 正常系 | ①全 Envelope が閉集合の値を1つ持つ ②Definition が要求する provenance を満たさない Evidence は使われない（V7）③Report に provenance が表示される ④Phase 1 の H01〜H03 は HUMAN、E18 等は DERIVED_HELPER_OUTPUT、github-evidence は API（`fidelity: transcribed`）として Legacy Map に載る |
| 異常系 | ①未知の class → 拒否 ②HUMAN だけで API 要求の軸を判定 → NOT_PROVEN ③class なし → 拒否 |
| 必要 Evidence | Envelope 検査結果、Legacy Map |
| PASS | 正常系・異常系をすべて満たす |
| FAILED | 異常系のいずれかで判定が進む |
| NOT_PROVEN | Legacy Map 未作成 |
| 担当 | WP2（Envelope）、WP3（V7、Legacy Map） |

## M1-08 Secret / Token / PII の保存・公開防止

| 項目 | 内容 |
| --- | --- |
| 事前条件 | 統合 Secret 規則。Canary は Test 内で生成する偽値（実在の Token ではない） |
| 正常系 | ①Canary（PEM 形、`ghp_` 形、`github_pat_` 形、JWT 形、`Authorization: Bearer …`、email）を含む fixture を保存すると、公開 Store に Canary が出ない ②Canary 検出時の扱いが §5-2 どおり（withheld / redacted、`raw_sha256` のみ）③Decision・Report・ログ・例外メッセージに Canary が出ない ④保存しない header（`authorization`、`set-cookie`）が Envelope にない ⑤M1 の公開対象ファイルで `scan_secrets.py` が0件 |
| 異常系 | ①Secret 規則の読込失敗 → 保存しない ②decode 不能な body → 検査不能として保存しない |
| 必要 Evidence | Canary Test の結果、`scan_secrets.py` の実行ログ |
| PASS | 正常系①〜⑤、異常系①②を満たす |
| FAILED | 公開側に Canary が1つでも出る |
| NOT_PROVEN | 規則外の形式の Secret については常に NOT_PROVEN（Scan 0件は不存在の証明ではない） |
| 担当 | WP2 |

## M1-09 非上書き Revision 管理

| 項目 | 内容 |
| --- | --- |
| 事前条件 | Store 実装済み |
| 正常系 | ①既存 path への書き込みは失敗し、元ファイルは byte 不変 ②確定済み Revision への追加は拒否 ③訂正・失効は新 Revision の `supersedes` / `revokes` で表され、旧ファイルは残る ④REVISIONS.json は追記のみで、前 Revision の MANIFEST Hash を持つ |
| 異常系 | ①同時作成（race）で O_EXCL が片方を失敗させる ②REVISIONS.json の途中行の改変 → V3 で検出 |
| 必要 Evidence | Test 結果（書き込み前後の Hash） |
| PASS | すべて満たす |
| FAILED | 上書き・削除が1件でも成功する |
| NOT_PROVEN | Store 未実装 |
| 担当 | WP2（Store）、WP3（V3） |

## M1-10 rev2 / rev3 Evidence ID から原本への Traceability

この AC は、**欠損を検出できること**と、**過去の事実を証明できること**を分けて判定する。

| 項目 | 内容 |
| --- | --- |
| 事前条件 | Legacy Map（E01〜E40、E23-x、E23b-x、H01〜H03、github-evidence 項目） |
| 正常系（検出） | ①rev2 index と rev3 traceability の全 Evidence ID が Legacy Map に1行ずつある ②各行に path、WP0 時点 SHA-256、provenance、`raw_available`、rev2 状態（current / revoked / superseded / intermediate）③path のファイルが存在し Hash が一致 ④`raw_available: false` の ID を参照する AC 軸が「Raw なし」と Report に表示される ⑤rev3 AC の `evidence` 欄の全 ID が Legacy Map で解決できる |
| 異常系 | ①Map にない ID → 未解決として報告 ②ファイル欠損・Hash 不一致 → 報告 ③revoked の ID を current として参照 → 報告 |
| 必要 Evidence | Legacy Map、解決結果、Hash 照合結果 |
| PASS（検出） | 正常系①〜⑤、異常系①〜③が期待どおり |
| FAILED（検出） | 欠損・不一致・失効参照の見逃し |
| 過去の事実の証明 | **NOT_PROVEN（M1 では変わらない）**。Phase 1 の GitHub 応答本文は存在しない（`helper-audit.md` HA-3）。WP0 時点の Hash は作成時点の内容を証明しない。新たに取得する Raw は新しい観測で、Phase 1 当時の値の代わりにしない |
| 担当 | WP3 |

## M1-11 Source / Commit / Published Artifact の整合性

| 項目 | 内容 |
| --- | --- |
| 事前条件 | 承認済み Source の定義が Registry にある（Helper 定数ではなく）。Published 側は記録済み Raw（Contents API 応答の fixture、または github-evidence の `raw/*.b64`） |
| 正常系 | ①Source のバイト列と commit の whole tree が一致（mode・extra path・非 regular を含む）②commit の blob id と、Published 側の内容から再計算した git blob id が一致 ③Phase 1 G11b の既知値（Probe SHA-256 `a5ba1b5f…`、Head `719f949…`、tree `29c5039…`）を fixture として再現できる ④G11 の drift（`cef683fb…` ≠ 監査済み）を不一致として検出する |
| 異常系 | ①extra file ②symlink・実行 bit ③1 byte 差 ④Published 側 Raw が不完全 → NOT_PROVEN ⑤承認 Source が無い ref → 拒否 |
| 必要 Evidence | 比較結果、Hash、blob id |
| PASS | 正常系・異常系をすべて満たす |
| FAILED | 不一致の見逃し、または不完全を一致と判定 |
| NOT_PROVEN | 実 GitHub 上の現在の内容との照合（M1 では取得しない） |
| 担当 | WP3 |

## M1-12 Phase 1 結果と安全機構の Regression 防止

| 項目 | 内容 |
| --- | --- |
| 事前条件 | P0。Phase 1 の固定値を Oracle として JSON 化（下記）。Oracle は rev2 / rev3 文書から転記し、出典 Hash を付ける |
| 正常系 | ①Phase 1 のファイル群の Hash が P0 と一致（M1 作業で変更なし）②Oracle の値（Scenario PASS 8 / PARTIAL 1 / FAILED 3 / NOT_PROVEN 3、AC rev3 PASS 40 / PARTIAL 4 / FAILED 1 / NOT_PROVEN 3、G3 / G3S / G6 FAILED、G11 NOT_PROVEN、G11b PASS、G12 PARTIAL、AC27 の3軸）が変わっていない ③§7 準拠 Evaluator の Legacy Replay（E18 入力）が G3 / G3S / G6 = FAILED を出し、Oracle と一致 ④Phase 1 Helper Test 516件が、Helper 不変のまま PASS（Helper の振る舞いの保全）⑤G11b 安全機構（whole tree 比較、SHA-pinned refspec、Push 前後の SHA 検証、Fail-closed、非上書き保存）の既存 Test が PASS ⑥M1 の新コードが Push / PR / Status 投稿の経路を持たない（静的検査） |
| 異常系 | ①Oracle と異なる Replay 結果 → **Phase 1 を変更せず**、不一致として報告 ②Helper Test の失敗 → 停止して報告（`testing.md` の原因分類） |
| 必要 Evidence | Hash 照合、Oracle、Replay 結果、pytest ログ |
| PASS | 正常系①〜⑥を満たす |
| FAILED | Phase 1 のファイル・判定が変わった、M1 コードに書き込み経路がある、安全機構の Test が失敗 |
| NOT_PROVEN | 未実行 |
| 注記 | 現行 Helper の Evaluator は E18 で G3 / G3S / G6 = PARTIAL を出す（WP0 実測）。これは既知の不一致であり、④の「Helper Test PASS」は Helper の振る舞いの保全を意味する。§7 準拠であることは意味しない |
| 担当 | WP4（Replay）、WP5（統合） |

---

## AC × WP 対応

| AC | WP1 | WP2 | WP3 | WP4 | WP5 |
| --- | --- | --- | --- | --- | --- |
| M1-01 | ● | | | | |
| M1-02 | ● | | | | |
| M1-03 | | | | ● | |
| M1-04 | | ● | | | |
| M1-05 | | | | ● | ● |
| M1-06 | | | ● | | |
| M1-07 | | ● | ● | | |
| M1-08 | | ● | | | |
| M1-09 | | ● | ● | | |
| M1-10 | | | ● | | |
| M1-11 | | | ● | | |
| M1-12 | | | | ● | ● |

## 実行 Command（予定。Location 確定後に具体化）

| Gate | Command |
| --- | --- |
| M1 Test | `/usr/bin/python3 -m pytest -q -p no:cacheprovider <M1 test path>` |
| Determinism | `PYTHONHASHSEED=random /usr/bin/python3 -m pytest <M1 determinism test>` |
| Secret scan | `/usr/bin/python3 .github/scripts/scan_secrets.py`（公開対象のみ。`.agents/` は走査範囲外であることを併記） |
| Phase 1 Helper 保全 | `cd .agents/tasks/phase1/henv && PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 -m pytest -q -p no:cacheprovider --rootdir=. test_phase1_*.py` |
| 既存 CI Gate | `quality-gates.md` の表（全体 pytest＋coverage、Benchmark、Determinism、Secret scan、Ground_Truth 順序） |
