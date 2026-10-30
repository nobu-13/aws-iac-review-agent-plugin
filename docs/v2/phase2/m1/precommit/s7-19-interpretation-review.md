# Phase 2 M1 — S7-19 Interpretation Review（Pre-Commit 監査）

> **Pre-Commit Remediation の注記（後から追加）**: 本書は Remediation の前の監査記録である。C-1〜C-3 の適用結果、最終の Hash、Commit 候補の一覧は `remediation-report.md` を参照する。

* Source: `docs/v2/phase1/app-demo-plan.md` §7（Commit `24b7a6e` 以降で同じ条文。Definition の Fidelity Test が検査）、`iacreview/evidence/open_questions.py`（SHA-256 `479025967e8f11ade944ca6e91dd6d9500ada5ea1ba36c7b1d34f65e014c49ba`）、`iacreview/evidence/evaluator.py`、`tests/unit/test_evidence_report.py`、`docs/v2/phase1/ci/spike/remediation-gate-app.yml`、Definition v1（`efd934b0…6cdbf8`）
* 目的: WP5 の解釈 I-1〜I-6 を、原文、解釈、判定コード、Test に1対1で対応させ、原文から正当化できるかを確かめる
* 状態: 監査のみ。コードと Test は変更していない

## 1. 原文と位置

§7 の構成（`app-demo-plan.md` L217〜L252）:

1. 冒頭: 「Per scenario, `app-evidence` stores raw API data and classifies four parts. A scenario is PROVEN only if every part is PROVEN; any FAILED part makes it FAILED.」
2. 4 Part の表（gate、app_check、required、steal）。各行は「PROVEN when」の条件
3. 偽装を示す2つの箇条（S7-14a/b、S7-15、S7-16、S7-17）。FAILED の条件を明示しているのは「If GitHub reports `isRequired = true` for an impostor, the scenario is FAILED」だけ
4. 「Recorded as NOT_PROVEN with the reason: …」（S7-18）
5. **「Not verified until the run: whether `isRequired` honours the expected source; whether `POST /rulesets` accepts `integration_id` directly; whether `user/installations` reports the permissions as planned; whether step outputs of a failed step reach the publisher (if not, BLOCKED runs still publish failure).」**（S7-19、L247〜L251）

S7-19 は Part ではなく、表の「PROVEN when」の行でもない。4つの「whether …」は、Run の前に答えが分からない問いを並べている。

## 2. 1対1の対応

| ID | 原文の語句 | 解釈 | 判定コード | Test | 検証結果 |
| --- | --- | --- | --- | --- | --- |
| I-1 | 「Not verified until the run:」（違反の条件を書いていない） | S7-19 は FAILED を返さない。全問が `EVIDENCE_SATISFIED` なら PASS、それ以外は NOT_PROVEN | `open_questions.py` L182（`status, reason = …`。FAILED を作る経路がない） | `test_evidence_report.py::test_s7_19_never_returns_failed_even_for_a_failed_scenario`（L97）、`test_s7_19_pass_needs_every_question_satisfied`（L86） | **条件付きで正当**（§3） |
| I-2 | 「whether `isRequired` honours the expected source」 | 反例1つ（Impostor の `isRequired = true`、または App check の `isRequired = false`）で「尊重しない」に確定。Spoof 3 Scenario すべてで Impostor が存在し required でなく、App check が required なら「尊重する」に確定。一部だけなら `EVIDENCE_INSUFFICIENT` | `open_questions.py` `_q1`（L88〜L116、反例 L100 / L109、全肯定 L102 / L111、部分 L114） | `test_s7_open_questions_recorded`（L42。全肯定 L52、反例 L59〜L60、未確定 L62〜L64、部分 L66〜L70） | **正当**。ただし App check `isRequired = false` による反例の経路（S7-09 FAILED）を Spoof Scenario で通す Test がない |
| I-3 | 「whether `POST /rulesets` accepts `integration_id` directly」 | 作成 Call の応答が必要。読み戻した Ruleset に App の `integration_id` があっても `EVIDENCE_INSUFFICIENT` | `open_questions.py` `_q2`（L129〜L136）、`_pin_observed`（L119） | `test_s7_open_questions_recorded`（L52、L55: `pin_observed_create_call_not_captured`） | **正当**。Plan §4 L130〜L134 は「one call で作成し、拒否されたら停止」と書いており、読み戻しの一致は「作成 Call が受け付けた」ことと、2段階の作成（Plan が禁じた Fallback）を区別できない。Pin のない Ruleset の経路（`create_call_not_captured`）と Ruleset 未観測（`NOT_RUN`）の Test はない |
| I-4 | 「whether `user/installations` reports the permissions as planned」 | 常に `NOT_RUN` | `open_questions.py` `_q3`（L139〜L140） | `test_s7_open_questions_recorded`（L52、L55）、Mutation MU-21 | **正当**。Plan §3 L65 は「`GET /user/installations` needs a GitHub App *user access token*」と書き、Helper はこれを読まない設計。現行の Evidence Role にもない |
| I-5 | 「whether step outputs of a failed step reach the publisher (if not, BLOCKED runs still publish failure)」 | 失敗が期待される Scenario で S7-03b、S7-05、S7-06、S7-07 がすべて PASS なら「届いた」。Digest の不一致を「届かなかった」とは読まない | `open_questions.py` `_q4`（L143〜L165） | `test_s7_open_questions_recorded`（L52 / L54、Report なし L72〜L74、Gate Run なし L75〜L76） | **正当**（§4）。`RUN_UNSETTLED` の経路（Gate Run 未完了）の Test がない |
| I-6 | （原文に対応する語句なし） | `LIMIT_DECLARED` は呼び出し側が宣言したときだけ。Evaluator は宣言しない | `open_questions.py` L173〜L178、`evaluator.py` `_open_questions`（L132〜L138。`declared_limits` を渡さない） | `test_s7_open_questions_recorded`（L78〜L80） | **正当**（原文にない状態を、原文の判定に入れない設計）。宣言の正規の経路（Definition の Field）はない |

Catalog の確認（I-1〜I-6 の前提）: `evaluator.py` L135〜L137 は Catalog が IMPLEMENTED でなければ `rule_not_implemented` を返す。Test は `test_registration_alone_is_not_an_answer`（L112）、Mutation MU-22。

## 3. I-1「FAILED を返さない」の検証

### 正当化できる点

1. S7-19 の文は「Not verified until the run」で始まり、条件（PROVEN when / FAILED when）を書いていない。§7 で FAILED を定めているのは、冒頭の合成規則（S7-02）と、Impostor の `isRequired = true`（S7-15）だけ
2. 4つの問いの「望ましくない答え」は、§7 の別の条文がすでに判定している
   * Q1 の否（Impostor が required）→ S7-08 / S7-14a / S7-15 / S6 が FAILED
   * Q4 の括弧書き「if not, BLOCKED runs still publish failure」が守られない場合（失敗が Publish されない）→ S7-03b `decision_not_published` が FAILED、S7-07 `conclusion_differs` が FAILED
   * Q2 の否（Plan §4: 作成 Call が拒否されたら停止）と Q3 の否は、Run の手順を止める条件で、Scenario の判定条件ではない
3. したがって S7-19 が FAILED を返さなくても、原文が FAILED と定めた事象を見逃すことはない。S7-19 でも FAILED を返すと、同じ事象を二重に数える

### 正当化できない点・不整合

1. **Definition との不整合**: Definition v1 の S7-19 は `expected_result.violated = "FAILED"` と書いている。Rule はこの値に到達しない。この値は Phase 2 の WP1 が全 Criterion に同じ形で入れたもので（26 Criterion すべてが `violated: FAILED`）、原文から来たものではない。S7-19 の `historical_implementation.alignment` は `NOT_AUDITED`
2. 同じ不整合は S7-17（`s7.limit.same_app_with_key`、常に NOT_PROVEN）と S7-18（`s7.limits.recorded_not_proven`、常に NOT_PROVEN）にもある。両方とも `violated: FAILED` だが、Rule は FAILED に到達しない
3. Registry は `expected_result` と Rule の到達可能性を照合していない（`registry.py` `_check_expected` は値の集合と `evidence_missing = NOT_PROVEN`、`violated != PASS` だけを検査する）
4. Q4 の括弧書きを S7-19 自身の FAILED 条件と読む解釈もありうる。WP5 はこれを S7-03b / S7-07 に任せた。どちらの読みが Plan の意図かは、原文だけでは決められない

### 判定

I-1 は**原文からは正当化できるが、Definition v1 の `expected_result` と矛盾する**。Human が次のどちらかを選ぶ必要がある。

* 案 A: Definition v1 の S7-17、S7-18、S7-19 の `expected_result.violated` を、Rule の到達範囲に合わせて変える（Registry は `NOT_PROVEN` を許す）。v1 は未 Commit なので、初回 Commit の前に行えば version の更新は不要
* 案 B: `expected_result` は「違反があった場合の値の上限」と定義し、Rule が到達しないことを文書に明記する。Definition は変えない

どちらも Code と Definition の変更、または文書の追加を伴うため、本監査では行っていない。

## 4. I-5 の根拠（Workflow の確認）

`docs/v2/phase1/ci/spike/remediation-gate-app.yml` では、verify Job の `outputs.payload_sha256` が Step `outputs` の出力から作られ（L55〜L59）、Publisher Job は `needs.verify.outputs.payload_sha256` を `PAYLOAD_SHA256` として受け取る（L189〜L193）。BLOCKED の Run では、この Step（「Derive the outputs from the report」）は失敗する（Scenario の期待: `GATE_DECISION_FAIL_STEPS`）。

したがって、公開された Check の `external_id` の Digest が Report Artifact から再計算した Digest と一致すれば、失敗した Step の出力が Publisher に届いたと言える。これが I-5 の根拠になる。

限定: 参照したのは Repository 内の Spike 版の Workflow である。Phase 1 で実際に使った Gate Scripts（`f77a58c`）の Workflow と同じかは、本監査では照合していない（NOT_VERIFIED）。

## 5. Test の不足（コードは変えていない）

| 経路 | 状態 |
| --- | --- |
| Q1: Spoof Scenario での App check `isRequired = false` による反例 | Test なし |
| Q2: Pin のない Ruleset（`create_call_not_captured`）、Ruleset 未観測（`NOT_RUN`） | Test なし |
| Q4: `RUN_UNSETTLED`（Gate Run 未完了） | Test なし |
| `expected_result` と Rule の到達範囲の照合 | Registry に検査なし |

`open_questions.py` の line coverage は 99%（Gate 1、99 statements 中 miss 1）。上の経路の多くは行としては通っていても、状態の Assertion がない。
