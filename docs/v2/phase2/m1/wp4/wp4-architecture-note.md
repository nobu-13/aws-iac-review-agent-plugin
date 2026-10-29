# Phase 2 / M1 / WP4 — Architecture Note

> **Pre-Commit Remediation の注記（後から追加）**: 本書が参照する `docs/v2/phase2/m1/wp4/legacy-reevaluation-results.json`（SHA-256 `b17e6881…29f7d544`、最初の版 `15b866b8…` を含む）は公開対象から外し、非公開の作業領域に保全した。この結果は WP4 時点の Evaluator Source と Definition で作ったもので、現在の Source では再現できない。本書の Hash・件数・判定は WP4 時点の記録であり、現在の判定の根拠にしない。最終の値は `docs/v2/phase2/m1/precommit/remediation-report.md` を参照する。

* Source: WP4 指示（WP4-1〜WP4-6）、`docs/v2/phase2/m1/wp0/m1-architecture-proposal.md`（D-1〜D-8）、`docs/v2/phase2/m1/wp3/wp3-architecture-note.md`、`iacreview/evidence/definitions/phase1-app-demo-s7.v1.json`
* 目的: Versioned Deterministic Evaluator、Snapshot Binding、Offline Replay、Legacy Derived Re-evaluation の構造と Trust Boundary を記録する
* 状態: 実装済み・**Git Commit なし**（HEAD `4bd6e015d88b01d34dc83dc2b2d2ffb0058358b2`）。GitHub API の呼び出しなし。Human レビュー待ち

## 1. Trust Boundary

```text
Raw Collector (WP2) → Immutable Store (WP2) → Integrity Validator V1–V9 / W1–W5 (WP3)
        → snapshot.take（検証 PASS の Group だけを Hash で Binding）
        → Snapshot.read（Binding の再照合）→ facts（正規化）→ rules_s7（純関数）
        → evaluator（合成・軸・canonical）→ canonical bytes（SHA-256 = 出力 Hash）
```

* Evaluator の入力は `Snapshot` だけ。Evidence ID だけで Store を読む経路はない
* Rule は `facts` だけを見る純関数（`rules_s7.py`）。I/O、時刻、Phase 1 の Historical Classification を参照しない
* 欠けている Fact は `None`（欠損）で、既定値を入れない。欠損は NOT_PROVEN になり、PASS にも FAILED にもならない
* 確認された違反は FAILED で、他の Part の PASS で相殺しない（S7-02）
* Agent の判断は含まない。Evaluator は決定論的処理だけ

## 2. Snapshot Binding（`iacreview/evidence/snapshot.py`）

`snapshot.take(store, groups, definition, definition_sha256, evaluator_version)` は Group ごとに `integrity.validate` を実行し、overall が PASS の Group の Evidence だけを次の値に Binding する。

* raw SHA-256、envelope SHA-256、manifest SHA-256、revision id、subject commit、source type
* Snapshot 全体に Definition（id、version、SHA-256）と Evaluator version

検証に失敗した Group は Binding されない。その Evidence を必要とする Rule は NOT_PROVEN になる（`test_a_group_that_fails_validation_is_not_bound`）。

`Snapshot.read(evidence_id)` は次の順に照合し、どれかが違えば `SnapshotDrift` を送出して評価を拒否する。

1. ID が Binding されている（未 Binding・付け替え不可）
2. Binding した revision の `MANIFEST.json` の SHA-256
3. Envelope の SHA-256
4. Raw の SHA-256

`read` は `store.verify()` を呼ばない。呼ぶと MU-08 / MU-09 の各照合が独立に検出されたことを示せなくなるため（§9 の不採用案）。ファイルは `O_NOFOLLOW` で開く。

## 3. 3つの Mode

| Mode | 入力 | Rule が見るもの | 出力 |
| --- | --- | --- | --- |
| `NATIVE_RAW_REPLAY` | Snapshot と Scenario Bundle（Role → Evidence ID） | Binding 済み Raw から作った Facts | canonical bytes。`capture_integrity.authenticity = NOT_PROVEN` |
| `LEGACY_DERIVED_REEVALUATION` | Phase 1 helper の `app-evidence`（E18〜E21）、W0 views（E09）、Report Artifact（E17）。各ファイルを Legacy Map の SHA-256 で照合 | helper が転記した Fact | 新規 Artifact `legacy-reevaluation-results.json`。`capture_integrity.status = NOT_PROVEN`（`RAW_UNAVAILABLE`） |
| `HISTORICAL_CLASSIFICATION_REFERENCE` | Legacy Map の subject（rev2 / rev3 からの引用） | 使わない（`used_by_rules: false`） | 評価後に `attach_historical_reference` で比較欄として付与 |

Legacy Mode と Native Mode は同じ `rules_s7` を使う。Historical Reference は Rule の入力にならない（MU-12 で検査）。

## 4. Canonical Serialization（`iacreview/evidence/canonical.py`）

* `sort_keys`、`ensure_ascii`、区切り `,` `:`、末尾改行1つ、他の改行なし
* 数値は整数のみ。float、NaN、Infinity は拒否（`allow_nan=False` と型検査）
* 実行時刻を表すキーは拒否: `generated_at`、`evaluated_at`、`checked_at`、`verified_at`、`captured_at`、`sealed_at`
* 先頭 `/` の文字列、`\` を含む文字列、Drive Path は拒否（Host Path を出さない）
* 順序に意味のない配列は生成側でソートする。Serializer は並べ替えない
* 出力 Hash は canonical bytes の SHA-256。実行メタデータ（時刻）は Replay CLI の stderr にだけ出す

## 5. 評価の構成（S7-02 と Phase 2 の軸）

| Part | Criterion |
| --- | --- |
| gate | S7-03、S7-03b |
| app_check | S7-04、S7-05、S7-06、S7-07 |
| required | S7-08、S7-09、S7-10、Spoof Scenario では S7-14a、S7-14b、S7-15、S6-G3 / S6-G3S / S6-G6 |
| steal（G11） | S7-12、S7-13、S7-16 |

* `s7_result = compose(各 Part)`。FAILED が1つでもあれば FAILED、全 PASS なら PASS、他は NOT_PROVEN
* S7-17（同じ App と鍵による偽装）は Limit で常に NOT_PROVEN。`s7_result` の合成には入れず、`g11_environment_boundary` 軸に入る
* P2-IP-01（Issuer Pinning 独立証明）と P2-AI-01 / 02（Artifact Integrity）は Phase 2 の軸。`phase2_result = compose(s7_result, issuer 軸, artifact 軸)`
* 報告軸は WP1 Definition の `axis` に従う（`required_check`、`merge_blocking`、`issuer_pinning_independent_proof` など）

### Applicability

| Scenario | 評価する Criterion |
| --- | --- |
| G0 | gate、app_check、S7-10（mergeable を期待） |
| G1、G2、G4、G5、G10 | gate、app_check、required |
| G9 | 上記に加え S7-10 は `mergeable_then_blocked`。W0 views の `mergeable_before_ruleset` が必要 |
| G3、G3S、G6（Spoof） | 上記に加え S7-14a、S7-14b、S7-15、S6-G*、P2-IP-01 |
| G11 | 上記に加え S7-12、S7-13、S7-16、S7-17、P2-AI-01、P2-AI-02 |
| G7 | `scenario_not_run` |
| G8、AC28、admin_bypass、same_app_with_key | S7-18 で NOT_PROVEN（Limit） |
| G11b | §6 にないため §7 Evaluator の対象外 |

### Context の発行元

同名 Context の発行元は REST Check Run の `app_id` で決める。Private App では GraphQL の `app` が `null` になるため。どちらの Source にもない Context は `unknown` とし、発行元に依存する Rule は NOT_PROVEN（`context_origin_unknown`）になる。

### S7-10 の範囲

S7-10 は Merge State だけを判定する。Ruleset の Issuer Pin の確認は S7-10 に追加していない。`rules_main` は P2-IP-01 だけが使う。

## 6. Gap G-6: Job Log（`text/plain`）

* Collector は `text/plain` の Body（Job Log）を受け付ける。UTF-8 として読めなければ Capture Error `body_not_text`
* Integrity V6 は text Body を UTF-8 として検査する
* 実際の Job Log は Secret Gate の誤検知 FP-1（マスク済みの `AUTHORIZATION: basic ***`）で拒否される見込み。規則の緩和は Human 決定 H-1〜H-4 の対象で、WP4 では変更していない

## 7. Replay CLI と Legacy CLI

* `python3 -m iacreview.evidence.replay SPEC.json`: exit 0 = 結果出力、2 = 不正な Spec、3 = Snapshot 後の変更（評価拒否）
* `python3 -m iacreview.evidence.legacy_reeval OUTPUT.json`: 出力は `O_EXCL` で作成し、既存ファイルを上書きしない
* どちらも Network に接続しない（Transport を import しない。`test_replay_never_opens_a_network_socket`）

## 8. ファイル

新規

* `iacreview/evidence/canonical.py`（77行）、`snapshot.py`（140行）、`facts.py`（289行）、`rules_s7.py`（542行）、`evaluator.py`（311行）、`replay.py`（75行）、`legacy_reeval.py`（70行）
* `tests/unit/evidence_synth.py`（Test Helper: `Builder`、`scenario_spec`、`answers`、`direct_facts`、`requirement`）
* `tests/unit/test_evidence_evaluator_s7.py`、`test_evidence_replay.py`、`test_evidence_legacy_reeval.py`、`test_evidence_mutations.py`
* `tests/mutation/evidence_mutants.py`（pytest は収集しない。`test_evidence_mutations.py` から実行）
* `docs/v2/phase2/m1/wp4/` の6文書と `legacy-reevaluation-results.json`

変更

* `iacreview/evidence/rules.py`: WP4 の20 Rule を `IMPLEMENTED` に変更
* `iacreview/evidence/artifact.py`: `judge_contents`、`comparison_from_record` に分割（P2-AI-02 を Native Evaluator から呼ぶため）
* `iacreview/evidence/collector.py`（`is_text_body`）、`envelope.py`（`body_not_text`）、`integrity.py`（V6 text）
* `iacreview/evidence/definitions/phase1-app-demo-s7.v1.json`: 22 Criterion の rule_behaviour Test を `IMPLEMENTED` に変更。S7-19 は変更なし

`definition_version` は 1 のまま。v1 が未 Commit のため。初回 Commit 後に内容を変える場合は version を上げる（Human 判断）。

## 9. 既存 Test の期待値変更（報告事項）

WP1 時点の Test の期待値を WP4 の状態に合わせて変更した。WP2、WP3 に続き3回目。

* `tests/unit/test_evidence_registry.py`: 実装済み Rule 数と PLANNED の例。PLANNED の例は S7-19 に変更
* `tests/unit/test_evidence_s7_definition.py`: rule_behaviour Test の status の期待値

Assertion の緩和、skip、削除はしていない。

## 10. 不採用案

| 案 | 不採用の理由 |
| --- | --- |
| `Snapshot.read` で `store.verify()` を呼ぶ | Manifest / Raw の各照合が独立に効いていることを Mutation Test で示せなくなる |
| Artifact Integrity を §7 の合成に入れる | §7 に Artifact の条項がない。`phase2_result` に入れた |
| Secret Gate の規則を緩めて Job Log を通す | Human 決定 H-1〜H-4 の範囲 |
| S7-10 に Ruleset Pin の確認を追加 | §7 の条文は Merge State だけ。Pin の確認は P2-IP-01 の範囲 |
