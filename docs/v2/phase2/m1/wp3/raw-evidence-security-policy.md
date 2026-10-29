# Phase 2 / M1 / WP3 — Raw Evidence Security Policy

* Source: WP2 の `iacreview/evidence/secretgate.py`・`collector.py`・`store.py`、WP0 `m1-architecture-proposal.md` §5-1〜§5-3、`steering/security.md`（Credentials、Untrusted Input）
* 目的: どの Raw を保存してよいか、保存できない Raw をどう扱うかを固定すること
* 状態: 方針（WP3）。Gate の規則の緩和は**していない**。緩和が必要な点は §5 に Human 判断事項として挙げる

## 1. 基本方針

| # | 方針 | 実装 |
| --- | --- | --- |
| P1 | Secret を含む Raw は保存を拒否する | Gate が `DETECTED` なら Collector はその Page を返さず、Store も書かない |
| P2 | PII を含む Raw も原則として保存を拒否する | 検出できる PII は e-mail address だけ（`pii_email_address`）。それ以外の PII は検出できない（§4） |
| P3 | 安全を確認できた Raw だけを、ローカルの非公開 Store に保存する | Gate が `CLEAN` のときだけ。Store は Containment Base の内側に置き、権限は 0700 / 0600。公開 Repository の外（ignore された `.agents/` など）に置く |
| P4 | Sanitize したデータは、元の Raw とは別の Artifact として識別する | WP3 では Sanitized Artifact を作らない。作る場合は別の `source_type` と別の evidence id を使い、元 Raw の Hash を参照するだけにする（設計のみ、未実装） |
| P5 | Sanitize したデータを元の Raw と同一として扱わない | Validator V9 は `NOT_APPLICABLE`（Sanitized 型がない）。Sanitized を Raw の代わりに Rule に渡す経路はない |
| P6 | 保存できない Raw に対する完全な Replay は NOT_PROVEN | 拒否された Page は Store に存在しない。その Capture に依存する判定は NOT_PROVEN になる（S7-01 Rule、Validator W1 / V5） |
| P7 | 判定できない内容は保存しない | Binary、上限超過、decode できない base64 の `content`、Scanner の例外は `UNSCANNABLE` / `ERROR` として拒否する |
| P8 | 拒否の記録に値を含めない | Refusal と例外には Rule 名と件数だけを入れる |

## 2. 合成 Fixture と結果

`tests/fixtures/evidence_raw/` の8件は、安全な内容と合成 PII（`example.invalid` など）だけを含む。Secret を含む応答、Prose の偽陽性、不正なサイズは、Test の実行時に断片を組み立てて作る（Repository のファイルに資格情報の形を置かない）。実際の GitHub API からは取得していない。

期待値は Gate を実行する前に `tests/unit/test_evidence_raw_policy.py` の `EXPECTED` に書き、Test で確認した。

| Fixture / 生成データ | Gate の結果 | 保存 | 区分 |
| --- | --- | --- | --- |
| `rest_check_runs_safe.json`（`secret_scanning` などの key を含む） | CLEAN | 可 | 安全 |
| `rest_installation_non_secret_urls.json`（`access_tokens_url`、`repositories_url`、`permissions.secrets: read`） | CLEAN | 可 | 非 Secret field。URL 値は `secret_assignment` から除外済み |
| `rest_pulls_page1.json` / `page2.json`（`Link: rel="next"` 付き） | CLEAN | 可（2 Page とも揃って COMPLETE） | Pagination |
| `rest_http_error_404.json` | CLEAN | 可（INCOMPLETE、`http_error`） | HTTP Error |
| `rest_commit_with_email.json`（commit author の e-mail） | DETECTED（`pii_email_address`） | 不可 | 真陽性（方針 P2） |
| `rest_noreply_email.json`（`<id>+<login>@users.noreply.github.com`） | DETECTED（`pii_email_address`） | 不可 | 方針上の真陽性（User ID を含む識別子） |
| `job_log_masked_header.json`（`AUTHORIZATION: basic ***`） | DETECTED（`authorization_header`） | 不可 | **偽陽性**（値はマスク済み） |
| 生成: Installation token 応答（`ghs_` 形式の偽値） | DETECTED | 不可 | 真陽性 |
| 生成: 文章中の「Password」の直後に英数字の語が続く Prose（具体値は Test 内で生成） | DETECTED（`secret_assignment`） | 不可 | **偽陽性**（文章中の語） |
| 生成: Contents API の base64 に API key の代入形式（具体値は Test 内で生成） | DETECTED | 不可 | 真陽性（WP3 で decode を追加） |
| 生成: Contents API の base64 が Binary | UNSCANNABLE | 不可 | 判定不能 |
| 生成: 上限超過（1,025 / 4,096 バイト超） | Collector が `byte_limit_exceeded` | Body は保存しない | 不正なサイズ |

## 3. 偽陽性の整理

| # | 原因 | 件数（上の表） | 保存 | 影響 |
| --- | --- | --- | --- | --- |
| FP-1 | `authorization_header` が、マスクされた値（`***`）にも一致する。actions/checkout の Job log に典型的に現れる | 1 | 不可 | Job log を Raw Evidence として保存できない |
| FP-2 | `secret_assignment` が、文章中の「Password」と区切り記号に続く語にも一致する | 1 | 不可 | Check run の `output.summary` などの自由記述を含む応答を保存できないことがある |
| （参考）PII | e-mail は方針上の真陽性。ただし commit を含む API 応答（`/commits`、`/pulls/<n>/commits`）はほぼ必ず e-mail を含む | 2 | 不可 | Sanitize の方針なしには、commit 系の Raw を保存できない |

`access_tokens_url` のような URL 値の field は WP2 の時点で除外しており、今回の Fixture でも CLEAN だった（偽陽性 0件）。

## 4. 限界

* Pattern Scan は、規則に挙げた形しか検出しない。`CLEAN` は不存在の証明ではない
* PII で検出するのは e-mail だけで、氏名、login、avatar URL、住所、電話番号は検出しない
* base64 以外の encoding（gzip、他の escape）に隠された値は検出しない
* Gate の規則を後から強めると、以前 `CLEAN` で保存した Raw が拒否されうる。Validator W4 はこれを FAILED として報告する（黙って受け入れない）

## 5. Human 判断事項（規則の緩和は未実施）

| # | 判断 | 選択肢 |
| --- | --- | --- |
| H-1 | FP-1（マスク済み `***`）を `authorization_header` から除外するか | (a) 除外しない（現状、Fail-closed） (b) 値が `***` だけの場合に限り除外する。(b) は規則の緩和なので、承認と回帰 Test が必要 |
| H-2 | FP-2（文章中の Password に続く語）を扱うか | (a) 現状のまま (b) JSON の特定 field（`output.summary` など）だけ別扱いにする。どちらも保存可否に影響する |
| H-3 | e-mail を含む API 応答を保存するか | (a) 保存しない（現状） (b) e-mail だけを置換した Sanitized Artifact を別 ID で保存する（P4。元 Raw は保存しない） (c) 元 Raw をローカル専用の別 Store に保存する（WP0 D-4） |
| H-4 | Job log を Raw Evidence として扱うか | Job log は API 応答の body ではない（Legacy Map でも `JOB_LOG_TEXT_NOT_API_BODY`）。扱う場合は H-1 が前提 |
