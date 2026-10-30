# Phase 2 / M2 — Threat Model と Trust Boundary

* 状態: **WP0 設計 rev1（Human Review の条件付き承認を受けた修正版）。未実装**
* 前提文書: `docs/v2/phase1/threat-model.md`（Phase 1）、`docs/v2/phase2/m1/wp3/raw-evidence-security-policy.md`（M1）、`m2-schemas.md`
* 分類（`security.md`）: 確認済み Issue / 高い可能性のある Risk / 文脈依存の Recommendation / Informational。本書の脅威は設計上の想定で、実測ではない

## 1. 保護対象

| ID | 資産 | 失われると |
| --- | --- | --- |
| AS-1 | Chain Result の正しさ（`chain_status` と各 Link） | 揃っていない Chain が揃っていると読まれる |
| AS-2 | Human Gate の事実（誰が、どの Commit に、何を判断したか） | Agent や PR 作成者の自己申告が Human の承認として扱われる |
| AS-3 | M1 Baseline（期待 Hash、Evaluator Source、Definition、Frozen Evidence） | M1 の判定が再現しなくなる、または黙って変わる |
| AS-4 | Credential（GitHub PAT） | Repository への不正アクセス |
| AS-5 | PII（Login 名、User id、Avatar URL、Email） | 公開文書や Report からの個人情報の露出 |
| AS-6 | 作業端末の File System | Root 外の読み取り、上書き |

## 2. 主体と信頼の程度

| 主体 | 信頼 | 理由 |
| --- | --- | --- |
| Human Maintainer | 判断の主体。操作の正しさは Evidence で確認する | Human Gate の判断者。ただし Human 提供の値も、Agent が確認していなければ NOT_VERIFIED |
| Agent（Kiro など） | **Untrusted** | 出力（候補、Manifest、Gate Record、自己申告の検証結果）は入力データとして扱う |
| PR 作成者・Contributor | **Untrusted** | Template、Contract 案、Report ファイル、Workflow を PR に含められる |
| 外部 Consumer（CI Script、他の Tool、利用者） | 判定の利用者。Chain の判定には関与しない | `passed_all_checks` などを誤読する可能性がある（T-06） |
| Chain Validator（M2 Code） | Trusted Computing Base（Review 済みの Commit に限る） | 合否を決める。PR が Validator 自身を変える場合は T-13 |
| M1 Store / Integrity Validator | Trusted（M1 Baseline の Code） | 保存後の改変を検出する。取得時の出所は証明しない |
| GitHub API の応答 | **出所は証明できない**（`capture_authenticity` NOT_PROVEN） | HTTPS 応答だが署名がない。保存後の不変性だけを示せる |
| Git Repository の Object | Commit id で識別。内容は Hash で固定 | ただし誰が Commit したかは証明しない |
| `gh` CLI と PAT | 取得経路。Token の値は Code が扱わない | 認証は `gh` に任せる |

## 3. Trust Boundary

```text
 ┌────────────────────────── Untrusted ──────────────────────────┐
 │ Agent 出力 / PR 内容 / 手書き Manifest / 手書き Gate Record    │
 │ Review_Report・Verification Report ファイル（bytes として）    │
 └──────────────┬────────────────────────────────────────────────┘
                │ TB-1: Chain Root 内のファイルとして読むだけ（O_NOFOLLOW、上限、strict JSON）
                ▼
 ┌──────────────────────── Chain Validator (M2) ─────────────────┐
 │ 再計算: Digest、Git の祖先関係、payload_sha256、Finding、       │
 │         Gate Record（Raw から再生成、GV-1〜GV-4）               │
 │ 判定: Link Status → Chain Status（Fail-closed）                 │
 └───┬───────────────┬─────────────────────┬─────────────────────┘
     │ TB-2          │ TB-3                │ TB-4
     ▼               ▼                     ▼
  Git Repository   M1 Store + Integrity   Phase 1 Verifier（local_recompute）
  (plumbing のみ、  (Read-only、M1 Code)   (`proc.run_bounded`、Pinned Tool)
   hooks 無効)
                     ▲
                     │ TB-5: 取得時だけ Network（Human 承認、Read-only、allowlist）
             ┌───────┴────────┐
             │ GitHub REST    │   TB-6: Token は `gh` の中だけ
             │ API            │
             └────────────────┘
```

| ID | 境界 | 境界を越えるもの | 制御 |
| --- | --- | --- | --- |
| TB-1 | Untrusted ファイル → Chain Validator | Manifest、Report、Gate Record の bytes | Root 外・Symlink 拒否、サイズ上限、strict JSON、未知 key 拒否。Manifest の値は参照としてだけ使い、判定の値として使わない |
| TB-2 | Chain Validator → Git | `rev-parse`、`merge-base --is-ancestor`、`cat-file` | `iacreview.remediation.gitsnap` と同じ global options（hooks・filter・textconv・fsmonitor 無効、`protocol.allow=never`）、argv、`proc.run_bounded`。Chain は gitsnap を import して使い、変更しない |
| TB-3 | Chain Validator → M1 Store | Revision、MANIFEST、Raw | M1 の `store` / `integrity` を読み取り専用で呼ぶ。M1 Code は変更しない。M1 から Chain への import はない（§7） |
| TB-4 | Chain Validator → Phase 1 Verifier | `verify` の再実行（`local_recompute`） | Phase 1 の CLI を argv で実行。Tool 不在・Version 不一致は `recompute_unavailable`（NOT_PROVEN） |
| TB-5 | 作業端末 → GitHub API | 読み取り Request と応答 | Human 承認後だけ。GET のみ。Endpoint は M2 の閉じた allowlist（`github-e2e-plan.md` §4）。Redirect を追わない。上限（Page、bytes、件数）。Dry-run 既定 |
| TB-6 | `gh` → Token | Token | Code は Token を読まない・渡さない・記録しない。`Authorization` Header を保存しない |

Steering は Security Boundary ではない（`security.md`）。上の境界は Code、Test、OS（Sandbox、File Mode）、Credential の有無で実現する。

## 4. 脅威と対策

| ID | 脅威 | 対象 | 対策（設計） | 対応 AC | 残る Risk |
| --- | --- | --- | --- | --- | --- |
| T-01 | Manifest の Digest を、改変した Report に合わせて書き換える | AS-1 | Report の payload を Validator が再計算し、Subject・Contract を Git から再取得して照合。Manifest の Digest だけでは LINKED にしない | M2-02、M2-03 | §5 の「整合的な全面改変」 |
| T-02 | Report の `decision` を `VERIFIED` に書き換える（payload_sha256 も再計算） | AS-1 | `local_recompute` / `local_import` とも Validator が Phase 1 Verifier を再実行し、payload が一致しなければ BROKEN。再実行できなければ NOT_PROVEN | M2-03 | Tool 不在の環境では NOT_PROVEN 止まり |
| T-03 | Agent が「Human が承認した」と自己申告する（Record を作る、Summary に書く） | AS-2 | Gate Record は Raw からの再生成と一致したときだけ有効（GV-1）。Raw の裏付けがない承認は `approval_self_declared_only`（NOT_PROVEN）。Raw と矛盾する Record は `gate_record_mismatch`（BROKEN） | M2-08 | Raw の取得元の出所は NOT_PROVEN（T-07） |
| T-04 | 古い Approve を新しい Head に流用する | AS-2 | GV-3（Record の Commit と `head_commit`）と GV-4（`pull.head.sha` と承認の Commit）。不一致が確認できれば `approval_stale` / `gate_binds_other_commit`（BROKEN）、照合できなければ NOT_PROVEN | M2-09 | 取得後の変化（§6） |
| T-05 | PR 作成者が自分の PR を承認したように見せる（同一 Account、または自分の別 Account） | AS-2 | GV-2 で `same_actor` を NOT_PROVEN。`distinct_actor` でも別人であることは主張しない（`not_claimed: human_identity`） | M2-10 | 別 Account の Sockpuppet は検出できない（Informational） |
| T-06 | 外部 Consumer が `passed_all_checks: true` の Review_Report を「問題なし」と読み、それを Chain の起点にする | AS-1 | Chain は `passed_all_checks` を読まない。`errors[]` と `tools[].available` で判定し、満たさなければ `review` Link が INCOMPLETE で Chain は COMPLETE にならない。`passed_all_checks` の値を書き換えた Report は Report Digest の不一致で BROKEN | M2-04、M2-06 | Chain の外での誤読そのものは残る（P-B の文書改善で軽減） |
| T-07 | GitHub 応答の偽造（中間者、改変した Raw を Store に入れる） | AS-1、AS-2 | 保存後の改変は M1 Integrity が検出。取得時の出所は NOT_PROVEN として明示し、COMPLETE の意味に含めない | M2-05 | `capture_authenticity` は常に NOT_PROVEN（確認済みの限界） |
| T-08 | Locator の Path Traversal / Symlink で Root 外のファイルを読ませる | AS-6 | Root 相対、`..`・絶対 Path 拒否、`O_NOFOLLOW`、Containment 確認 | M2-01 | — |
| T-09 | 巨大・深い JSON、重複 key で Validator を止める・混乱させる | AS-1 | サイズ上限、深さ上限、重複 key 拒否、`NaN` 拒否 | M2-01 | CPU / RSS は制限しない（Phase 1 と同じ残留 Risk） |
| T-10 | Transport が書き込み Endpoint を呼ぶ、または allowlist 外を取得する | AS-4、Repository | Method は GET のみ。Endpoint は Template の閉じた集合。Dry-run 既定 | M2-11 | `gh` 自体の不具合 |
| T-11 | Token が Log、Envelope、Report、作業報告に出る | AS-4 | Header allowlist、Secret Gate（M1）、canary Test、`gh` の環境に Token を渡さない設計 | M2-11 | Secret Gate の規則外の形式（Informational） |
| T-12 | Login 名や User id が公開文書に出る | AS-5 | Gate Record は `actor_ref`（仮名）のみ。Raw は `.agents/` の非公開 Store。公開するのは Hash と判定の要約だけ | M2-08、M2-12 | `actor_ref` は再計算可能な仮名 |
| T-13 | PR が Chain Validator、期待値、Test、Workflow を同時に変えて Gate を通す | AS-1、AS-3 | M2 用 CI job で期待値の変更一覧を Summary に出す。Validator の Source Digest を Result に入れる。CODEOWNERS / Required Check は Repository 設定（M2 対象外、Human） | M2-07 | Repository 設定がない限り残る（M1 ci-remaining-risks R-3 と同じ） |
| T-14 | M2 の変更が M1 の Replay bytes を変える | AS-3 | §7 の非干渉の仕組み | 共通前提 P0 | — |
| T-15 | Chain `COMPLETE` を Merge 承認、Merge Enforcement の証明として扱う | AS-2 | GV-5 は判定しない。`not_claimed` に `merge_enforcement`、`approval_counted_by_rules`、`human_identity`。Summary の文言を固定。Merge は Human | M2-10 | 利用者の誤読（Documentation で対処） |
| T-16 | E2E の Raw に含まれる Token マスク行（`AUTHORIZATION: basic ***`）で Secret Gate が全体を拒否する | 可用性 | M2 の E2E は Job Log を取得しない（`github-e2e-plan.md` §4） | M2-12 | Job Log の Evidence は NOT_PROVEN のまま |

## 5. Chain Manifest と Raw の両方が改変された場合の検出可能範囲

前提: 攻撃者は Chain Root と非公開 Store（`.agents/`）に書き込めるが、Validator の Code と Local Git の Object は改変していない（改変した場合は §5 の最後の行）。

| 改変の範囲 | 検出 | 検出する仕組み | 結果 |
| --- | --- | --- | --- |
| Manifest だけ（Digest、Commit、Locator） | できる | 各 Link の再計算（Report の bytes、Git、Store の MANIFEST） | 対応する Link が BROKEN |
| Report ファイルだけ | できる | Manifest の Digest、`local_recompute` の再実行 | `verification` BROKEN |
| Report と Manifest の Digest を整合的に改変 | できる（再実行できる場合） | Phase 1 Verifier の再実行（Git と Pin された Tool から payload を作り直す） | `verification` BROKEN。Tool 不在なら NOT_PROVEN（成功にはしない） |
| Store の Raw だけ（保存後） | できる | M1 Integrity（Revision の MANIFEST と各ファイルの Hash） | `github` INCOMPLETE、Gate GV-1 INCOMPLETE |
| Raw と Store の MANIFEST を整合的に改変 | できる | Chain Manifest の `github_evidence.manifest_sha256` との不一致 | `github` BROKEN |
| Raw、Store の MANIFEST、Chain Manifest をすべて整合的に改変 | **一部だけ** | Local Git との照合（`compare`、`contract_contents`、`template_contents` の本文と blob、`pull.head.sha` と `head_commit`）は残る。Review の `state`、`user.id`、`author_association` には Local の照合先がない | Git と矛盾する改変は BROKEN。Git と矛盾しない Gate の事実（例: `COMMENTED` を `APPROVED` に、`user.id` を別の値に）の改変は**検出できない** |
| 上の全部に加えて Local Git の履歴も作り直す | **できない**（Offline では） | — | Chain は内部で整合し、COMPLETE になり得る |

検出できない範囲を狭める方法（M2 では実装しない。将来の候補として記録する）:

* Anchor: Chain Result の `payload_sha256` と Chain Manifest の SHA-256 を、改変者が書き換えられない場所（Human が承認した Commit、信頼できる CI の Summary）に記録し、後で照合する
* 再取得: 同じ Endpoint を別の時点・別の端末から再取得して比較する（GitHub 側の状態が変わっていれば差が出るため、完全な証明にはならない）

この限界は `capture_authenticity` NOT_PROVEN（M1）と同じ根から来ている。COMPLETE はこれらの改変がないことを示さない。

## 6. 時間に関する限界（Time-of-check）

* GV-4 は取得時点の `pull.head.sha` との比較で、取得の後に Head が進んでも分からない
* Review の `submitted_at` と Commit の時刻は、改変と時計のずれを区別できないため、判定に使わない（`observed_at` は表示だけ）
* 承認時点の Ruleset と取得時点の Ruleset が同じかは扱わない（`approval_counted_by_rules` は not_claimed）

## 7. M1 との非干渉

| 仕組み | 内容 | 確認方法 |
| --- | --- | --- |
| Package の分離 | M2 の Code は `iacreview/chain/` だけ（D-1） | `git diff --name-only` が F-1〜F-7 に触れない（RG-2） |
| Import の向き | `iacreview.chain` → `iacreview.evidence` / `iacreview.remediation` / `iacreview.reportcheck` の一方向。`iacreview/evidence/` と `iacreview/remediation/` から `iacreview.chain` を import しない | 静的検査 Test（TC-00-03、`m2-acceptance-test-matrix.md` §12） |
| Evaluator Source の範囲 | `evaluator._SOURCES` の8ファイルは `iacreview/evidence/` 内にあり、M2 は変更しない。`iacreview/chain/` は Source Digest の対象外 | RG-1（`evaluator_source_sha256` が `ee765e0c…` のまま） |
| 期待値ファイルの分離 | M2 は `tests/fixtures/chain_replay/expected.json`（新規）を使い、M1 の `tests/fixtures/evidence_replay/expected.json` を読まない・書かない | RG-1、RG-2 |
| CI job の分離 | M2 専用の job（D-5）。`evidence-integrity` job とその Script は変更しない | `ci.yml` の差分に `evidence-integrity` の行がないこと |
| M1 の CI 判定への影響 | M2 の新規ファイルは `evidence_ci_check.py` の `FORBIDDEN_PREFIXES`（`docs/v2/phase1/`、`.agents/`、`.kiro/`）に入らない。`.github/workflows/` と `.github/scripts/` の変更は M1 Summary の「review required」一覧に出る（失敗ではない）。`changed_since_baseline` の件数は増える（情報のみ） | M2 の PR の `evidence-integrity` Summary |
| Test の分離 | M2 の Test は `tests/unit/test_chain_*.py`。M1 の Test と Mutant は変更しない | RG-3、RG-4（M1 Evidence Test 519件、Mutant 32 / 32） |

## 8. 前提と残る Risk

* R-1: Chain Validator が正しいことは、Test と Review に依存する。Validator の Source Digest を Result に入れるが、それは Validator の正しさを証明しない
* R-2: Git の Commit 作成者、GitHub の Account と、実際の人間の対応は証明しない
* R-3: 単一 Owner の Repository では、`distinct_actor` の Approve を作れない（GitHub は自分の PR の Approve を受け付けない）。E2E の Gate Link は NOT_PROVEN（GV-2）になる見込み（`github-e2e-plan.md` §6）
* R-4: Store は単一 User の書き込みを前提とする（M1 と同じ）
* R-5: §5 の整合的な全面改変は Offline では検出できない
