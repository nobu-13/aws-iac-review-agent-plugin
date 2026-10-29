# Phase 2 / M1 / WP2 — Architecture Note

状態: WP2 実装（未 Commit、Human レビュー待ち）。

* Source: `docs/v2/phase2/m1/wp0/m1-architecture-proposal.md` §3-2〜§3-4・§4-2・§5、WP0 `helper-audit.md` HA-3 / HA-4 / HA-8 / HA-9 / HA-10、WP1 `wp1-architecture-note.md`
* 目的: GitHub API の応答を、JSON に Parse する前のバイト列のまま、来歴付きで、上書きされない形で保存できるようにすること。秘密情報を含むかもしれない内容は保存させない
* 変更理由: Phase 1 の Evidence は Helper が抽出した field の転記だけで、取得時刻、Hash、Pagination の完了も残っていなかった（EG10、HA-3、HA-4、HA-10）。一部の Evidence は上書き保存されていた（HA-8）。Job log には Secret 検査がなかった（HA-9）

## 1. ファイル

| ファイル | 種別 | 役割 |
| --- | --- | --- |
| `iacreview/evidence/envelope.py` | 新規 | Evidence Envelope の定義・検証・完全性判定 |
| `iacreview/evidence/collector.py` | 新規 | Raw Capture（Transport Interface、Pagination、上限、欠落検出） |
| `iacreview/evidence/secretgate.py` | 新規 | 保存前 Security Gate |
| `iacreview/evidence/store.py` | 新規 | Immutable Evidence Store（Revision、Manifest、検証） |
| `iacreview/evidence/rule_s7_evidence.py` | 新規 | Rule `s7.evidence.raw_api_data_stored`（S7-01） |
| `iacreview/evidence/rules.py` | 変更 | S7-01 の Rule を `IMPLEMENTED` に。他の23件は `PLANNED` のまま |
| `iacreview/evidence/registry.py` | 変更 | Rule の状態と rule_behaviour Test の状態の一致を検査 |
| `iacreview/evidence/definitions/phase1-app-demo-s7.v1.json` | 変更 | S7-01 の rule_behaviour Test 1件を `PLANNED` → `IMPLEMENTED`（他の値は不変） |
| `tests/unit/test_evidence_collector.py`、`test_evidence_secretgate.py`、`test_evidence_store.py` | 新規 | WP2 の Test（Envelope の検証は `test_evidence_store.py` に含む） |
| `tests/unit/test_evidence_registry.py`、`test_evidence_s7_definition.py` | 変更 | WP1 の「全 Rule が PLANNED」を前提にした期待値3か所を、WP2 の状態に合わせて変更（§7） |

Phase 1 の Helper、旧 Test、Evidence、`scan_secrets.py`、CI、`pyproject.toml` は変更していない。Dependency の追加もない。

## 2. Evidence Envelope（`envelope.py`）

Field（閉じた集合。未知の field と欠けた field は拒否）:

| Field | 内容 |
| --- | --- |
| `schema_version` | 1 |
| `evidence_id` / `capture_id` | `^[a-z0-9][a-z0-9-]{2,95}$`。1 page = 1 Evidence。`<capture_id>-pNNN` |
| `source_type` | `API` / `LOCAL` / `HUMAN` |
| `source_locator` | 例: `GET /repos/o/r/commits/<sha>/check-runs?per_page=100` |
| `captured_at` | 応答を受け取った時刻（UTC、マイクロ秒） |
| `repository`、`subject_commit_sha` | API では `owner/name` が必須。commit は40桁 hex か null |
| `api` | `{endpoint, method, version}`。API だけ。endpoint は API 相対 Path か `graphql`（scheme、host を持てない） |
| `http_status`、`pagination_complete`、`page` | API だけ。それ以外は null |
| `raw_content_sha256` / `raw_content_length` | Raw バイト列の SHA-256 と長さ。Raw がなければ両方 null |
| `response_headers` | 許可した header だけ（`content-type`、`content-length`、`etag`、`link`、`last-modified`、`x-github-request-id`、`x-github-api-version-selected`、`date`） |
| `capture_tool_version` | `iacreview.evidence.collector/1` |
| `provenance_assurance` | API / LOCAL は `SELF_DECLARED`、HUMAN は `HUMAN_ATTESTED` |
| `authenticity_verified` | 常に `false` |
| `security_scan_status` | Raw があれば `CLEAN` だけが保存可能。Raw がなければ `NOT_SCANNED` |
| `capture_errors` | 閉じた集合（`http_error`、`response_missing`、`body_missing`、`body_truncated`、`byte_limit_exceeded`、`page_limit_reached`、`pagination_next_refused`、`graphql_errors`、`graphql_has_next_page`、`transport_error`、`body_not_json`、`sibling_page_refused`） |
| `completeness_status` | `COMPLETE` / `INCOMPLETE`。Metadata から再計算した値と一致しなければ拒否 |

`COMPLETE` の条件（`expected_completeness`）: Raw があり `CLEAN`、capture_errors が空、API では HTTP 200 かつ `pagination_complete: true`。

**取得時刻と評価時刻**: Envelope は `captured_at` だけを持つ。`evaluated_at` は未知の field として拒否する。Store の検証時刻は `StoreReport.verified_at` に別に記録する。

**API 由来であることの申告と、真正性の区別**: `source_type: API` は Collector の申告である。GitHub の応答には署名がないので、保存したバイト列が GitHub から来たこと、認証付きの呼び出しだったことは証明できない。このため `provenance_assurance` は常に `SELF_DECLARED`、`authenticity_verified` は常に `false` で、`true` や `AUTHENTICATED` は拒否する。

## 3. Raw Capture（`collector.py`）

* `Transport = Callable[[HttpRequest], Optional[HttpResponse]]`。WP2 には GitHub に届く Transport を実装していない。Test は合成応答だけを使う。
* Transport の契約: body は最大 `max_bytes + 1` バイト（超過を見えるようにするため）。失敗は `TransportError`。
* Request: GET（REST）と POST（`graphql` だけ）。それ以外の method や、絶対 URL、`;` などを含む endpoint は Transport を呼ぶ前に拒否する。
* Raw は `response.body` のバイト列そのもの。完全性検査のための JSON Parse は別に行い、Raw を置き換えない。
* Header は許可したものだけを Envelope に入れる（Body と Metadata の分離）。`authorization`、`set-cookie` は残らない。

| 状況 | 結果 |
| --- | --- |
| Page 上限・合計上限を超えた Body | `byte_limit_exceeded`。Body は捨てる（途中まで保存しない） |
| HTTP 200 以外 | `http_error`。Body は記録する。INCOMPLETE |
| 応答・status・Body がない、Transport 例外 | `response_missing` / `body_missing` / `transport_error` |
| `Content-Length` と受信バイト数の不一致 | `body_truncated` |
| `Link: rel="next"` | 同じ API root・同じ Resource Path なら追う。違えば `pagination_next_refused`（追わない） |
| Page 数上限に達した | `page_limit_reached` |
| GraphQL の `hasNextPage: true` / `errors` | `graphql_has_next_page` / `graphql_errors`（WP2 では cursor を追わない） |
| JSON でない Body | `body_not_json`（Raw は保存する） |
| Gate が Page を拒否した | その Page は返さない。残りの Page に `sibling_page_refused` を付ける |

`pagination_complete` は、最後に取得した Page に次がなく、上の事象が1つもないときだけ `true` になる。Capture 単位の値で、全 Page に同じ値が入る。

## 4. Security Gate（`secretgate.py`）

* Rule の再利用: `iacreview.secrets.SECRET_RULES`（AWS access key id、`gh[pousr]_` 等の provider token、PEM）をそのまま使う。
* `.github/scripts/scan_secrets.py` は Plugin Package から import できない。変更もしない。代わりに `test_every_ci_scanner_rule_is_also_caught_by_the_gate` で、Scanner の7規則それぞれの Canary を Gate も検出することを確認する。
* Gate で追加した規則: `github_fine_grained_pat`、`github_v1_installation_token`、`authorization_header`、`bearer_token`、`jwt`、`secret_assignment`（環境変数形式、JSON の key/value。URL 値は除く）、`url_credentials`、`pii_email_address`
* 既存 Scanner と意図的に変えた点（Fail-closed）:
  * Allowlist と除外 marker を持たない（`example` などの語で Token が除外されない）
  * JSON は decode 後の文字列も検査する（`\u` escape で隠した Token も検出）
  * Binary（NUL、非 UTF-8）は内容によらず `UNSCANNABLE` として拒否する
  * 上限超過は `UNSCANNABLE`、検査中の例外は `ERROR`。どちらも拒否する
* 出力は Rule 名、場所（`raw` / `json_string`）、件数だけ。一致した値は Result、Reason、例外メッセージのいずれにも入れない。
* 検査対象: Raw、Envelope の canonical bytes（header 値を含む）、Manifest（revision の reason を含む）。
* 限界: `CLEAN` は、どの規則にも一致しなかったことだけを示す。PII で検出するのは e-mail address だけで、氏名、login、avatar URL、住所、電話番号は検出しない。Pattern Scan で任意の PII を検出できるとは主張しない。
* 偽陽性: `secret_assignment` は `access_tokens_url` などの key にも反応しうる（URL 値は除外済み）。Fail-closed のため保存を拒否する側に倒れる。実際の API 応答（e-mail を含む commit など）を保存するには、Sanitize とローカル専用 Raw の方針（WP0 D-4）を先に決める必要がある。

## 5. Immutable Evidence Store（`store.py`）

```text
<root>/rev-0001/<evidence_id>.raw            Raw バイト列（受信がなければなし）
<root>/rev-0001/<evidence_id>.envelope.json  Envelope（canonical JSON）
<root>/rev-0001/MANIFEST.json                最後に書く。Revision の封印
```

* 書き込みは、`O_NOFOLLOW` で開いた Revision Directory の fd を基準に `O_CREAT | O_EXCL | O_NOFOLLOW` で行う。既存ファイル、Symbolic Link、途中の Path の Link への差し替えは拒否する（追わない）。
* 権限: Directory は `0700`、ファイルは `0600`。広い権限は検証時に報告する。
* Store Root: Containment Base の内側で、Base と同じではなく、途中に Symbolic Link がなく、`..` を含まないこと。
* Evidence ID: Store 全体で一意。区切り文字と `..` を含めない形式に限る。
* 封印: `MANIFEST.json.tmp` を排他作成し、`link()` で `MANIFEST.json` にする（`link` は既存ファイルを置き換えない）。その後 tmp を削除する。
* Manifest: `revision`、`revision_id`、`previous_revision_id`、`previous_manifest_sha256`（前 Manifest のバイト列の SHA-256）、`reason`、`sealed_at`、`entries`（ID 順。各 entry に Envelope と Raw のファイル名・SHA-256・長さ、`source_type`、`completeness_status`）、`entry_count`。
* 保存の前に、Envelope の検証（Raw との Hash・長さの一致を含む）と、Raw・Envelope・Manifest への Gate を通す。

`verify()` が検出するもの:

* Manifest がない Revision（中断・作業中）、`MANIFEST.json.tmp` の残存 → `INCOMPLETE`
* Manifest の不正 JSON、未知・欠けた field、schema version、store format、Revision 番号と Directory 名の不一致、非 canonical 形式
* Revision 番号の欠番、前 Revision の ID と Manifest Hash の不一致、無効な前 Revision への連結、後続のある未封印 Revision
* ファイルの欠落、Manifest にないファイル、Symbolic Link、非 regular file、Hash・長さの不一致
* Envelope 自体の検証失敗、Envelope と Manifest entry の不一致、重複 Evidence ID
* 広すぎる権限

不完全な Bundle が1つでもあれば、新しい Revision は始められない（`begin_revision` が拒否）。修復と過去 Revision の移行は WP3 と Human に残す。

### 5-1. Hash だけでは証明できない改ざん

* Store に書き込める者は、すべてのファイル、すべての Hash、Revision の連結をまとめて書き直せる。Manifest の連結は、そのような一貫した書き直しを検出しない。
* 署名、外部 Timestamp、Write-once の媒体は使っていない。`sealed_at` と `captured_at` は、書いた計算機の時計による自己申告である。
* 削除された最新 Revision は、それより前の Revision だけを見ても分からない（Chain の末尾を切り詰めても、残りは整合する）。
* Collector 自身が改ざんされていれば、保存前のバイト列は検査できない。
* 取得したバイト列が GitHub から来たこと（真正性）は Hash では示せない（§2）。

Hash と Manifest が検出するのは、偶発的な破損と部分的な編集である。外部 Anchor（Git Commit、Remote への Push、署名）との組み合わせは WP3 以降の検討事項とする。

## 6. Rule S7-01（`rule_s7_evidence.py`）

`raw_api_data_stored(report: StoreReport, evidence_ids)`:

| 結果 | 条件 |
| --- | --- |
| NOT_PROVEN | Store が検証に通らない、Evidence の指定なし・重複、Store にない、API でない、不完全（HTTP Error、欠落、上限、Pagination 未完了、隣の Page の拒否）、同じ Capture の他の Page が指定されていない |
| FAILED | HTTP 200 を受け、capture_errors もないのに Raw が保存されていない（Metadata だけ。Phase 1 の形）。他の Evidence の欠落より優先する |
| PASS | 指定した Evidence がすべて API、検証済み Revision にあり、Raw の Hash が一致し、COMPLETE で、Capture の全 Page が指定されている |

PASS は「保存されていること」だけを示す。真正性、§7 の他の3 part については何も示さない。Registry の `coverage()` は引き続き全行 `proven: false` を返す（Rule が実装されていることは、結果ではない）。

## 7. WP1 Test の期待値の変更

WP2-5 で S7-01 を実装したため、WP1 で「全 Rule が PLANNED」を固定していた次の Test の期待値を変えた。理由は、指示された状態変化（1件 IMPLEMENTED、23件 PLANNED）そのものである。Phase 1 の Test ではない。

| Test | 変更 |
| --- | --- |
| `test_every_rule_is_planned_in_wp1_and_none_claims_an_implementation` | → `test_only_s7_01_is_implemented_and_the_other_23_rules_stay_planned` |
| `test_coverage_never_reports_a_criterion_as_proven` | S7-01 行だけ `IMPLEMENTED`、他は `PLANNED`。`proven: false` は全行のまま |
| `test_04_a_test_marked_implemented_that_does_not_exist_is_refused` | 対象を S7-08 から S7-01 に変更（S7-08 の Test を IMPLEMENTED にすると新しい一致検査で先に拒否されるため） |
| `test_every_s7_clause_maps_to_one_catalog_rule_and_a_planned_rule_test` | → `…_and_a_rule_test_matching_its_status` |

Definition JSON は `definition_version: 1` のまま、S7-01 の Test の状態だけを変えた。条文、Rule ID、Historical Classification は変えていない。v1 は未 Commit で、まだ公開された版ではないためである。最初の Commit 以降は、Definition の変更ごとに版を上げることを推奨する（Human 判断）。
