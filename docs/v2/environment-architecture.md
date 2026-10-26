# v2.0 開発環境 Architecture（Step E0 提案）— aws-iac-review-agent-plugin

本書は v2.0 開発環境の **提案** である。根拠は開発環境の調査（以下「環境調査」。端末固有の設定を含むため非公開）と Kiro / AWS の公式 docs で、本書だけで判断の理由が分かるよう要点を本文に記す。記載の構成は、特記がない限り「提案中」である。

- 状態ラベル: 次の 5 つだけを使う。7 章 C 表の「提案中（不採用）」「提案中（保留）」は、まだ存在せず、評価の結果として導入しない / 後で再評価するものを指す。
  - 実装済み: 本 Repository に存在する code・CI
  - 導入済み: 設計時点の開発 Workspace（`.kiro/steering/` 等）と `docs/v2/baseline-audit.md` D-1 の toolchain で存在を確認したもの
  - 前提: 開発者の端末・User scope に存在しうる外部設定（User scope の MCP / Power / skill、Workspace permissions、sandbox 設定）。特定端末の状態としては記さず、存在する場合の扱いを示す
  - 採用済み方針: Human が開発方針として決定したもの（4-5 A 表）。設定内容の網羅的な実機確認は別途行う
  - 提案中 / 未確認
- 代替構成: 4-5 B 表のセキュリティ優先の構成。現在の開発環境では採用していない
- Decision D-1〜D-5 は環境構築計画（非公開）で Human 判断を求めた項目で、結果は本文の該当箇所に記す。
- Step E1 での追記（2026-10-19 JST）: 状態ラベルの統一と Decision D-1〜D-5 の結果の反映だけを行った。設計内容は変えていない。
- 公開用の整理（Step 9-4）: 端末固有の path・設定状態と、非公開文書への参照を一般化した。設計内容・判断は変えていない。
- 方針整合（Step 9-5）: 開発環境の AWS / Git 権限を Human 決定の採用済み方針に合わせ、E0 のセキュリティ優先案を代替構成として分けた（4-5）。v2.0 の Architecture・Milestone・Trust Boundary・製品の自動実行範囲は変えていない。

- 作成日: 2026-10-16（JST）。参照した公式情報は末尾「参照した公式情報」にまとめた。
- 前提: 主開発環境は **Kiro IDE**（設計時点の確認版 1.3.0）。Kiro CLI（設計時点 2.29.0）では fileMatch Steering・standalone Hook・sandbox が効かない可能性が高い（公式 docs の記述に基づく。CLI での実機確認は NOT VERIFIED）。

## 設計方針（v2.0 の主要原則との対応）

| 原則 | 環境側の扱い |
| --- | --- |
| 13-field Finding と Review Report の互換性 | Steering と Spec に不変条件として書き、確認は既存 test（`tests/unit/test_finding.py`, `tests/property/test_prop_finding_schema.py` 等）と CI で行う |
| Core は Kiro / LLM に依存しない | Kiro 固有物は `.kiro/` だけに置く。`skills/`, `iacreview/`, `rules/`, `benchmark/` に `.kiro` を書かない（`tests/unit/test_docs.py` が検査する） |
| 独立した Validator | 合否は pytest・benchmark・CI が決める。Hook や Agent の判断を合否にしない |
| Production Deploy / Merge を自動化しない | 製品は Code と Human Gate で自動実行しない（4-5 C 表）。開発環境では AWS CLI / AWS MCP / Git を許可し、書き込み系と Production への破壊的変更は事前に Human が確認する（4-5 A 表）。技術的に到達を断つ構成は代替構成（4-5 B 表）。Steering は補助 |
| AWS 公式 Tool を再実装しない | cfn-lint / cfn-guard CLI をそのまま使う。同じ機能を持つ MCP を並置しない |
| 導入容易性と再現性 | 追加物は最小。version は固定し、各 Step に Rollback を用意する |

---

## 4. Steering 設計

### 4-1. 提案された 6 file と既存 8 file の対応

| 提案 file | 既存の対応 file | 判断 | 理由 |
| --- | --- | --- | --- |
| `product.md` | `product.md`（always）導入済み | **既存を更新** | v0.1 前提の記述を v2.0 の Stage 1-5 に合わせる。特に非目標の文言を整理する（4-3） |
| `tech.md` | `tech.md`（always）導入済み | **既存を更新** | git 読み取りは `iacreview/proc.py` `run` 経由、Dependency 追加は不可（PyYAML のみ）、MCP 非必須を v2.0 にも明記 |
| `structure.md` | `structure.md`（always）導入済み | **既存を更新** | `docs/v2/`、v1.x Spec の置き場所、`.kiro/` の扱いを追記 |
| `security-policy.md` | `security.md`（always）導入済み | **新設しない。`security.md` を拡張** | 内容が完全に重なる。名前を変えても技術的な利点はなく、2 file に分かれると矛盾の元になる |
| `quality-gates.md` | `testing.md`（fileMatch）一部重複 | **新設（fileMatch）** | `testing.md` は「どう test を書くか」。新 file は「完了前に何を通すか」と互換性の不変条件を扱う。`iacreview/` を編集するときにも読み込まれる必要があり、`testing.md` の pattern では届かない |
| `development-workflow.md` | `development-principles.md`（always）一部重複 | **新設（always、短く）** | 既存は設計原則。新 file は Agent session の運用規則（承認 Gate、失敗時停止、禁止操作、Evidence）。「完了の定義」は既存側を参照して重複させない |

`agent-plugin-standards.md` と `documentation.md` は変更不要（v2.0 でも有効）。`testing.md` は変更しない。

### 4-2. Inclusion mode と context 量

| File | Mode | Pattern（提案） | 目安 |
| --- | --- | --- | --- |
| `product.md`, `tech.md`, `structure.md`, `security.md`, `development-principles.md` | `always`（現状維持） | — | 現在 560 行。更新後も同程度に保つ |
| `development-workflow.md` | `always` | — | 60 行以内 |
| `quality-gates.md` | `fileMatch` | `["iacreview/**/*", "skills/**/*", "tests/**/*", "benchmark/**/*", ".github/**/*", "pyproject.toml"]` | 80 行以内 |
| `agent-plugin-standards.md`, `documentation.md`, `testing.md` | `fileMatch`（現状維持） | 現状どおり | — |

- `fileMatchPattern` の配列形式は Kiro Steering docs の例にある。
- `auto` / `manual` は採用しない。v1.x の作業で毎回必要な規則ばかりで、description 一致に頼る読み込みは「読まれなかった」ことに気付きにくい。
- CLI V1/V2 では `fileMatch` が自動読み込みされない（設計時点の Kiro CLI docs の記述）。CLI で作業するときは `quality-gates.md` が効かない前提になる。
- Custom agent では Steering が自動で入らない（Kiro Steering docs）。Custom agent を使わない理由の 1 つ（6-2）。

### 4-3. 各 file に書く内容（要点）

`product.md`（更新）
- v2.0 の Stage 1-5 と v1.1-v1.5 の対応（6-1 の表）。
- 非目標を 2 つに分ける: (1) **AWS resource の作成・変更・削除、Deploy、Merge は v2.0 でも対象外**、(2) **IaC file の修正案生成は v2.0 の対象**だが、Remediation Contract の範囲内に限り、適用は Human 承認後。現行 `security.md`「修正案の提示は可能だが、自動適用しない」との関係は **Human の判断が必要**（Decision D-1）。→ E1 で D-1 決定: Agent による IaC file の編集は承認済み Remediation Contract の範囲内で許可し、修正・検証の反復も制限内で許可する。本番 Deploy・Merge は自動実行しない。Steering 文言への反映は Step E2 で対応済み（`product.md`「v2.0 Bounded Remediation（計画・未実装）」と非目標の v2.0 での扱い、`security.md`「v2.0 Remediationの範囲（計画・未実装）」）。

`security.md`（拡張）
- Trust Boundary 表: 未信頼 = IaC 入力・Agent findings JSON・Base/Head の git object・MCP 応答、信頼 = pin した Tool・CI。
- 禁止操作（`development-workflow.md` と同じ一覧を参照のみ）。
- 「Steering は Security Boundary ではない」旨の明記（4-4）。

`quality-gates.md`（新設）
- 互換性の不変条件: Finding 13 field（`iacreview/finding.py` `FINDING_FIELDS`）、Report envelope 7 key（`iacreview/report.py` `REPORT_KEYS`）、summary 6 key（`SUMMARY_KEYS`）、`summary.passed_all_checks` の意味を変えない、exit code 0-8（`iacreview/exitcodes.py`）、`run_iac_review.py` の既存引数。
- 確認 command（すべて既存）:
  - 変更 module の test: `/usr/bin/python3 -m pytest -q -p no:cacheprovider tests/unit/test_<module>.py`
  - 完了前の全体: `/usr/bin/python3 -m pytest --cov=iacreview --cov=benchmark/harness --cov-fail-under=80 -rs`（約 414 秒）
  - Determinism: `PYTHONHASHSEED=random /usr/bin/python3 -m pytest tests/property/test_prop_determinism.py -p no:cacheprovider`
  - Benchmark: `/usr/bin/python3 benchmark/harness/run_benchmark.py --cases benchmark/cases --mode combined`
  - Advisory: `ruff check --no-cache iacreview`、`mypy iacreview`
- 既知の失敗（README 見出し 2 test）と既知の lint 件数（`iacreview` 5 件）を Baseline として記録し、「増えていないこと」を確認する。

`development-workflow.md`（新設）
- **Human Approval Gate**（次の前に必ず止まって確認を求める）: Spec の requirements / design / tasks の各 phase 移行、Dependency 追加、`.gitignore`・CI・`pyproject.toml`・`plugin.json` の変更、既存 test の期待値変更、Finding / Report schema に触れる変更、git commit / push / PR、Steering・Hook・MCP 設定の変更。
- **失敗時の停止**: test・benchmark が想定外に失敗したら修正を続けず、原因分類（`testing.md` の 5 分類）を報告して止まる。同じ修正方針で 2 回失敗したら止まる。
- **変更範囲の最小化**: task に書かれた file 以外を変えない。lint の既存指摘を「ついでに」直さない。
- **禁止操作**（E0 提案）: AWS API 呼び出し・Deploy（`cdk deploy`, `aws cloudformation *`）、`git push` / `git reset --hard` / `git clean`、`pip install` / `npm install` / `uv add`、`--fix` 付きの lint、`~/.aws/*` の読み取り。
  - Step E2 で 4-5 A 表の採用済み方針に合わせて置き換えた: 読み取り系の Git / AWS 操作は実行してよい。書き込み系（Commit、Branch 操作、AWS Resource の作成・変更）は事前に Human が確認する。Production への破壊的変更、`git reset --hard`・`git clean`・強制 Push は必ず事前確認する。Git Push・PR 作成・Merge・Production Deploy は Human が実行または承認する。Secrets と `~/.aws/` の内容は出力しない。上記の一律禁止は代替構成（4-5 B 表）に残す。
- **Evidence**: 完了報告に、実行 command・exit code・PASS/FAIL/SKIP 数・所要時間を書く。実行していないものは `NOT VERIFIED`。

### 4-4. Steering は Security Boundary ではない

Steering は Agent への **指示（guidance）** であり、従わない出力を技術的に止めない。Prompt injection を含む未信頼 IaC を読ませる本 Project では特に、Steering の禁止事項を「守られている」と仮定してはいけない。

実際の境界は以下で、Steering はこれらを説明する役割に留める。

| 境界 | 何を止めるか | 状態 |
| --- | --- | --- |
| Code（`iacreview/pathguard.py`, `iacreview/proc.py`, `iacreview/yamlcfn.py` 等） | Path traversal、shell 経由の実行、unsafe YAML、子 process への credentials 環境変数 | 実装済み（Baseline Audit E-1） |
| CI（`.github/workflows/ci.yml`） | 互換性・決定論・coverage・Secret 混入の回帰 | 実装済み（lint は advisory） |
| Kiro Permissions（`deny` は常に優先） | Agent の shell / tool / Power 実行 | 前提（Kiro の標準機能。作業中の承認で allow が広がりやすい）。採用済み方針では AWS CLI / Git を deny しない。一律 deny は代替構成（4-5 B 表）。Power の deny（6-4）は提案中 |
| Local command sandbox（IDE 1.3 以降） | Agent の shell command の file / network 到達範囲 | 採用済み方針（Workspace で有効化）。Sandbox 内での AWS CLI の SSO 認証は未解決（4-5 A 表） |
| OS 権限・credentials の不在 | AWS への到達そのもの | 代替構成（4-5 B 表）。採用済み方針では開発者が AWS CLI / AWS MCP を認証して使いうるため、この境界は効いていない前提で扱う |
| Hook（`PreToolUse` の exit 2） | 特定 tool 実行の阻止 | **補助的な soft guard に過ぎない**。本書では採用しない（5-3） |

### 4-5. 開発環境の AWS / Git 権限と製品の自動実行範囲

開発環境で Agent や Human が持つ権限は、製品（Plugin）が自動実行してよい範囲を意味しない。両者を次の 3 表で分けて扱う。

A. 採用済み開発方針（Human 決定。AWS CLI / AWS MCP / Git / Production の行は Steering `tech.md`「開発環境と製品の操作範囲」、`security.md`「開発環境の操作権限」、`development-workflow.md`「Git操作・AWS操作」「Human Gate」に反映済み。Workspace Sandbox と SSO の未解決事項は Steering には記載していない）

| 項目 | 方針 |
| --- | --- |
| AWS CLI | 利用を許可。参照系 API は実行してよい。AWS Resource の作成・変更は事前に Human が確認する |
| AWS MCP | 利用を許可（MCP は製品の必須依存にしない、という `tech.md` の方針は変わらない） |
| Git | 操作を許可。`status` / `diff` / `log` などの読み取り系は実行してよい。Commit・Branch 操作は事前に Human が確認する。Push・PR 作成・Merge は Human が実行または承認する |
| Production 環境 | 破壊的変更（削除、置換、Deploy、権限変更）は必ず事前に Human が確認する |
| Workspace Sandbox | 有効化する。Agent の shell command の file / network 到達範囲を OS で絞る |
| 未解決事項 | Sandbox 内で AWS CLI の SSO 認証が完了するかは未解決（`NOT VERIFIED`）。解決するまで、Sandbox 内で AWS CLI が使える前提で手順を組まない |
| 出力の制限 | Credentials、Secrets、`~/.aws/` の内容を文書・Log・報告に出力しない |

B. 代替構成（セキュリティ優先。現在の開発環境では採用していない）

| 項目 | 内容 | 使いどころ |
| --- | --- | --- |
| AWS CLI の deny | Workspace permissions で `aws *` を deny し、Agent からの AWS API 呼び出しを一律に止める | AWS 操作が不要な作業だけを行う環境、または未信頼 IaC を大量に扱う検証環境 |
| AWS MCP の無効化 | AWS API に届く MCP を Workspace で無効化する | 同上。MCP の version 固定や接続先を確認できない場合 |
| Credentials を渡さない制限環境 | MCP・子 process に credentials を渡さず、shared credentials file も読めない環境で作業する | CI や独立テスト環境。AWS への到達を技術的に断ちたい場合 |

代替構成を採用する場合は、Human が Steering（`tech.md` / `security.md` / `development-workflow.md`）を併せて更新する。

C. 製品（Plugin）が自動実行してよい範囲（Steering `product.md` / `security.md` と同じ）

| 操作 | v1.0（実装済み） | v2.0（計画・未実装） |
| --- | --- | --- |
| IaC の Review・修正案の提示 | 可（Read Only） | 可 |
| Workspace 内の IaC ファイル編集 | 不可 | 承認済み Remediation Contract の範囲内に限り可 |
| AWS Resource の作成・変更・削除、AWS Account 設定変更 | 不可 | 不可 |
| Deploy、Merge | 不可 | 不可（Human Gate） |

---

## 5. Hooks 設計

### 5-1. 前提（Kiro Hooks 公式 docs の確認結果）

- 形式: `.kiro/hooks/<name>.json`、`{"version": "v1", "hooks": [{"name", "trigger", "matcher"?, "action": {"type": "command", "command"} , "timeout"?, "enabled"?}]}`。
- `PostFileSave` は **Agent による保存だけ**で発火する。matcher は file path への regex。
- `PostTaskExec` は **Spec task の完了時だけ**発火する（通常の chat の編集では発火しない）。
- Command は project root で shell として実行され、event JSON を stdin で受け取る。File 系 event の JSON field 名は docs に例がなく **NOT VERIFIED**。command 文字列内の `{{filePath}}` template 変数は docs に記載がある。
- exit 0 以外は warning 表示で続行（block できるのは `PreToolUse` と `PreTaskExec` の exit 2）。PostFileSave の stdout が Agent context に入るかは docs の記述が割れていて NOT VERIFIED。IDE の説明では非 0 終了時の stderr が Agent に送られる。
- 既定 timeout 60 秒（`timeout` field、秒）。

### 5-2. 候補評価

#### H1: Python 変更後の ruff 検査（`PostFileSave`）

| 案 | Command | 評価 |
| --- | --- | --- |
| H1-a 変更 file だけ | `ruff check --no-cache {{filePath}}` | **不採用**。file path を shell 文字列に埋め込む。Kiro が template 展開時に quote するかは NOT VERIFIED。未信頼 IaC を処理する Agent が作った file 名（`;` や `$(...)` を含む名前）が command injection になりうる。`security.md`「ユーザー入力を文字列連結してコマンド実行してはいけない」にも反する |
| H1-b stdin JSON を読む script | `python3 <script>`（script が stdin から path を取り出し argv で ruff を呼ぶ） | **保留**。安全だが、field 名が NOT VERIFIED。script の置き場が `.kiro/hooks/`（Git 管理外）しかなく、`skills/` 等には `.kiro` 参照を置けない（`tests/unit/test_docs.py`） |
| H1-c 範囲固定・高信号 rule のみ | `ruff check --no-cache --quiet --select E9,F63,F7,F82 iacreview skills benchmark tests .github/scripts 1>&2` | **条件付き採用（Minimum）**。入力を埋め込まない固定 command。対象 rule は構文エラー・未定義名などで、Baseline は 0 件（設計時点の計測）なので、出たら新しい問題。出力を stderr に送るのは、非 0 終了時に Agent が内容を受け取れるようにするため |
| H1-d 既定 rule で `iacreview` 全体 | `ruff check --no-cache iacreview` | **不採用**。既存 5 件（F401 ×4, F841 ×1）で常に失敗し、毎回 warning になる。Agent が無関係な既存指摘を直し始め、変更範囲が広がる |

H1-c の設定案（提案中）:

```json
{
  "version": "v1",
  "hooks": [
    {
      "name": "ruff-high-signal-on-python-save",
      "description": "Advisory only. Not a CI gate. No --fix.",
      "trigger": "PostFileSave",
      "matcher": "\\.py$",
      "action": {
        "type": "command",
        "command": "ruff check --no-cache --quiet --select E9,F63,F7,F82 iacreview skills benchmark tests .github/scripts 1>&2"
      },
      "timeout": 15,
      "enabled": true
    }
  ]
}
```

H1-c の Risk 評価:

| 観点 | 評価 |
| --- | --- |
| 発火頻度 | `.py` を Agent が保存するたび。single file は 0.02 秒。tree 全体の所要時間は未計測（有効化の前に計測する） |
| Timeout | 15 秒。超えたら warning で続行し、作業は止まらない |
| 再帰 | Command 型なので新しい Agent loop は起こさない。stderr を受けた Agent が修正して保存すると再発火するが、指摘が消えれば止まる。`Stop` / agent 型 hook は使わない |
| Context 消費 | 指摘があるときだけ数行。Baseline 0 件のため通常は出力なし |
| 失敗の表示 | IDE の warning と、Agent への stderr 通知 |
| 自動修正 | `--fix` を付けない。Agent への修正指示も書かない |
| Cache 書き込み | `--no-cache` で `.ruff_cache/` を作らない |
| CI との関係 | Hook の PASS は CI Gate の代わりではない。CI `lint` job は現状 advisory のまま |
| Interpreter | PATH 上の `ruff`（0.8.6。設計時点では system Python 3.9 の user site に導入）に依存する。Kiro が hook 実行時に同じ PATH を使うかは NOT VERIFIED（有効化の前に確認する） |

#### H2: Task 完了時の関連 pytest（`PostTaskExec`）

| 観点 | 評価 |
| --- | --- |
| 全体 suite | 約 414 秒。既定 60 秒を大きく超える。timeout を伸ばすと task 完了ごとに 7 分待つ |
| `tests/unit` だけ | 33.6 秒（設計時点の計測）。ただし既知の 2 失敗（README 見出し）で **常に非 0** になり、warning が意味を持たない |
| 「関連 test」の選択 | 変更 file → test file の対応付けに script が要る。stdin の field 名が NOT VERIFIED で、script の置き場も H1-b と同じ問題がある |
| 発火範囲 | Spec task の完了時だけ。task 内の Verify command と重複する |
| 判定 | **v1.1 では不採用**。代わりに `tasks.md` の各 task に Verify command（変更 module の test file を明示）を書き、Agent がそれを実行して結果を Evidence に残す。README の 2 test を解消した後（Decision D-2。E1 で「README の Support / Privacy Policy は維持し、後続工程で test 側の期待値を修正する」と決定）に、`tests/unit` 固定 command・timeout 60 秒の形で再評価する（Recommended の保留項目） |

#### H3（参考）: 危険操作を止める `PreToolUse` hook

`shell` matcher で stdin の command を調べて exit 2 で止める案。Kiro Permissions の `deny` が同じことを built-in で、より確実に（deny は scope を問わず優先）できるため **不採用**。Hook は parse 漏れや timeout で素通りしうる。

### 5-3. Hook の位置付け

- Hook は **開発の早期 feedback** であり、品質 Gate ではない。合否は CI と、完了報告に書かれた test 実行結果で決める。
- Hook 設定は `.kiro/hooks/` に置かれ Git 管理外（`.kiro/` ignore）。CI には影響しない。

---

## 6. Specs / Custom Agents / Powers

### 6-1. v1.1-v1.5 の Feature Spec 管理

**1 version = 1 Feature Spec** とする。1 feature ごとに分けると Spec 間の依存（Delta が Contract に使われる等）が追いにくく、version 単位なら release と CHANGELOG に対応させやすい。

| Version | Spec directory（提案） | 主題 | v2.0 Stage |
| --- | --- | --- | --- |
| v1.1 | `.kiro/specs/v1-1-change-aware-review/` | Semantic Diff・Finding Delta（`docs/v2/v1.1-implementation-proposal.md` を入力にする） | Stage 1 の拡張 |
| v1.2 | `.kiro/specs/v1-2-remediation-contract/` | 修正可能範囲と維持条件（Invariant）の定義 | Stage 2 |
| v1.3 | `.kiro/specs/v1-3-evidence-verification/` | 修正前後の差分・Evidence・Invariant の独立検証 | Stage 4（Stage 3 の修正案入力を含む） |
| v1.4 | `.kiro/specs/v1-4-bounded-autonomy/` | 再試行・停止・Human への委譲の policy | Stage 5 |
| v1.5 | `.kiro/specs/v1-5-power-plugin-ci/` | Kiro Power / Agent Plugins / CI 統合 | 配布 |

version と主題の対応は、依頼文の開発項目 5 つを順に並べた **仮定**であり、Human の確認が必要。

運用規則:

- `workflowType` は既存と同じ `requirements-first`（既存 `.config.kiro`）。phase 移行ごとに Human 承認（4-3）。
- **既存 Spec `.kiro/specs/aws-iac-review-agent-plugin/` は編集しない**。`tests/unit/test_traceability.py` がこの `requirements.md` を読む。新 Spec は別 directory なので、この test には影響しない。
- 新 Spec の要件番号は Spec ごとに独立させ、既存要件を参照するときは「v1.0 Requirement 10 AC9」のように明記する。
- README 見出し test の 2 失敗は Spec にせず、Human 承認後の小さな修正として扱う（Bugfix Spec は規模に対して重い）。
- Spec も `.kiro/` 配下のため Git 管理外。履歴の残し方は Decision D-3（E1 で (a) を条件付き採用: `.kiro/` 内の remote なし独立 repository。追跡 file を限定し、個人設定・Secrets・MCP 環境変数・session 情報は commit しない）。

### 6-2. Custom Agents

**導入しない。**

- 必要な制約（禁止操作・承認 Gate・検証手順）は Steering + Permissions + Spec task で表現できる。
- Custom agent では Steering が自動で読み込まれず、`resources` に列挙し続ける保守が必要（Kiro Steering docs）。
- 「独立した Validator」は LLM agent を増やすことではなく、決定論の code と test（v1.3 の Verification）で実現する方針。
- 再検討の条件: v1.3 以降で「Remediation 担当の Agent から書き込み tool を外した読み取り専用 Reviewer」が必要になり、Permissions だけでは表現できないと分かった場合。

### 6-3. 外部 Kiro Powers

**導入しない。** Steering・Spec・既存 CLI（cfn-lint / cfn-guard / pytest）で開発に必要な機能は揃っている。開発者の User scope に AWS 系 skill がある場合はそれも自動 activate されうるため（前提）、これ以上 context の供給元を増やさない。

### 6-4. 現行 Plugin を開発 Workspace で Power として使うか

**開発 Workspace では使わない**（前提: 開発者の User scope に本 Plugin の Power が install されている場合）。

| Risk | 内容 |
| --- | --- |
| 古い code の実行 | Power の実体は install 時点の commit の copy で、working tree（開発中の変更を含む）とは別物。v1.1 の変更は反映されない |
| 自己 Review の混同 | 開発中の Agent が「AWS template を review して」で Power の skill を自動起動し、古い Review 結果を開発中 code の結果と取り違える |
| 許可の広さ | permissions で `power: aws-iac-review-agent-plugin` を allow していると、開発中でも確認なしに起動しうる |

対応（提案）:
- 本 Workspace の permissions に `capability: power` / `effect: deny` / `match: [aws-iac-review-agent-plugin]` を追加する（deny は allow より優先）。User scope の Power 自体は他 Workspace に影響するため、uninstall は Human 判断（Decision D-4。E1 で (a) に決定: 本 Workspace でのみ利用を禁止し、他 Workspace からは uninstall しない）。
- v2.0 の Power 互換性は **独立したテスト環境**で検証する: 別の `KIRO_HOME`（V3 で文書化）または別 macOS user / VM に、検証対象 tag の local directory から Power を入れ（「Import power from a folder」/ `kiro-cli powers install <path>`）、5 skill の起動を確認する。開発 Workspace と設定を共有しない。

---

## 7. 推奨環境構成

### 採点基準（1-5）

| 観点 | 1 | 5 |
| --- | --- | --- |
| 開発品質への効果 | ほぼ無い | 大きい |
| 開発効率への効果 | 悪化 / 無い | 大きく改善 |
| Security リスク | **低い（良い）** | **高い（悪い）** |
| 保守コスト | 低い（良い） | 高い（悪い） |
| 導入難易度 | 易しい（良い） | 難しい（悪い） |

総合評価: **採用** / **条件付き採用** / **保留**（後の version で再評価）/ **不採用** / **代替構成**（4-5 B 表）。

採点は E0 時点のセキュリティ優先の評価で、数値は変えていない。A7 / A8 / B1 / C4 の総合と状態は、Human が決めた開発方針（4-5 A 表）に合わせて Step 9-5 で更新した。

### A. Minimum Environment（v1.1 開発用）

| # | Component | 状態 | 品質 | 効率 | Risk | 保守 | 難易度 | 総合 | 理由 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| A1 | 既存 toolchain（`/usr/bin/python3` 3.9.6 + pytest 8.3.4、cfn-lint 1.46.0、cfn-guard 3.2.1、ruff 0.8.6、mypy 1.14.1。Baseline Audit D-1） | 導入済み | 5 | 4 | 1 | 1 | 1 | 採用 | CI pin と一致。追加 install 不要 |
| A2 | `.kiro/` の local 履歴（`.kiro/` 内の独立 git repository、remote なし） | 提案中 | 3 | 3 | 1 | 2 | 2 | 採用 | Steering / Spec / Hook 変更の Rollback 手段。外側の repo は `.kiro/` を ignore しているので干渉しない（Decision D-3、E1 で条件付き採用） |
| A3 | 既存 Steering 8 file の v2.0 向け更新（`product.md`, `tech.md`, `structure.md`, `security.md`） | 導入済み（更新は提案中） | 4 | 3 | 1 | 2 | 2 | 採用 | v0.1 前提と Remediation の解釈を解消しないと Agent が矛盾した指示を受ける |
| A4 | `development-workflow.md`（always） | 提案中 | 4 | 3 | 1 | 2 | 1 | 採用 | 承認 Gate・停止・禁止操作を 1 か所に |
| A5 | `quality-gates.md`（fileMatch） | 提案中 | 4 | 4 | 1 | 2 | 1 | 採用 | 互換性の不変条件と確認 command を、code 編集時に必ず読ませる |
| A6 | v1.1 Feature Spec | 提案中 | 5 | 4 | 1 | 2 | 2 | 採用 | 既存提案書から requirements を起こし、task ごとに Verify を持たせる |
| A7 | Workspace permissions の `deny` 追加（push / install / AWS / Deploy の一律禁止） | 代替構成 | 3 | 2 | 1 | 2 | 2 | 代替構成（4-5 B 表） | E0 では採用と評価したが、採用済み開発方針（4-5 A 表）では AWS CLI と Git を deny せず、書き込み系を Human 確認で扱う。`pip *`・`git *` のような広い allow が作業中の承認で増えうる点は残る Risk |
| A8 | User scope にある AWS API 到達 MCP（例: AWS MCP Server）の本 Workspace での無効化 | 代替構成 | 3 | 3 | 1 | 1 | 2 | 代替構成（4-5 B 表） | E0 では採用と評価したが、採用済み開発方針では AWS MCP の利用を許可する。Credentials を使い version が固定されていない構成がありうる点は残る Risk |
| A9 | 開発 Workspace での Power 使用禁止（permissions deny） | 提案中 | 4 | 3 | 1 | 1 | 2 | 採用 | 古い code の実行と自己 Review の混同を防ぐ（6-4） |
| A10 | Hook H1-c（ruff 高信号 rule、PostFileSave） | 提案中 | 2 | 3 | 2 | 2 | 2 | 条件付き採用 | 固定 command で injection なし。Step 6 で所要時間と PATH を確認できた場合だけ有効化。効果が見えなければ外す |

### B. Recommended Environment（v2.0 まで）

A に加えて以下。

| # | Component | 状態 | 品質 | 効率 | Risk | 保守 | 難易度 | 総合 | 理由 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| B1 | Local command sandbox（Workspace の `.kiro/settings/sandbox.json` で有効化） | 採用済み方針 | 3 | 2 | 1 | 2 | 3 | 採用 | v1.3 以降は Agent が IaC を書き換える。shell の到達範囲を OS で絞る。E1 で導入順序を前倒しし、Workspace Foundation（Step E1）の最後に有効化した。test / cfn-lint / cfn-guard が sandbox 内で動くかの網羅確認と、Sandbox 内での AWS CLI の SSO 認証は未解決（4-5 A 表） |
| B2 | 再現可能な開発用 venv（uv で Python 3.9 と 3.11 の `.venv`、`pyproject.toml` の pin を使用） | 提案中 | 4 | 3 | 2 | 2 | 3 | 採用（Human 承認後） | 現在は system Python の user site に依存。CI matrix（3.9 / 3.11 / 3.13）との差を手元で再現できる。Dependency の download を伴うため承認が要る |
| B3 | 後続 Spec（v1.2-v1.5） | 提案中 | 5 | 4 | 1 | 2 | 2 | 採用 | 6-1 |
| B4 | 独立 Power テスト環境（別 `KIRO_HOME` または別 user / VM） | 提案中 | 5 | 2 | 2 | 3 | 4 | 採用（v1.5 で） | v2.0 の Power 互換性を開発環境と分けて検証する（6-4） |
| B5 | AWS Documentation MCP Server（`@1.2.3` 固定、Workspace scope、`autoApprove: []`） | 提案中 | 2 | 3 | 2 | 2 | 2 | 条件付き採用（任意） | Credentials 不要・AWS API なし。ただし web tool で代替でき、検索語が外部に出る。CloudFormation property の調査が頻繁に必要と分かった時点で入れる |
| B6 | Hook H2（`tests/unit` 固定、PostTaskExec、timeout 60 秒） | 提案中 | 3 | 2 | 2 | 3 | 3 | 保留 | README 2 test の解消後に再評価（5-2） |

### C. Deferred / Rejected

| # | Component | 状態 | 品質 | 効率 | Risk | 保守 | 難易度 | 総合 | 理由 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| C1 | AWS IaC MCP Server の Local 検証 / 文書 tool | 提案中（保留） | 2 | 2 | 3 | 3 | 3 | 保留（v1.3 以降に文書 tool のみ再評価） | 検証 tool は cfn-lint / cfn-guard の別 version 複製。文書 tool は B5 と重複 |
| C2 | AWS IaC MCP Server の `troubleshoot_cloudformation_deployment` / `get_cloudformation_pre_deploy_validation_instructions` | 提案中（不採用） | 1 | 1 | 5 | 3 | 3 | 不採用 | Credentials と AWS account（読み取り・change set 作成の誘導）に触れる |
| C3 | 旧 CloudFormation / CDK MCP Server | 提案中（不採用） | 1 | 1 | 3 | 4 | 3 | 不採用 | `src/` から消え、最新 release が yanked |
| C4 | User scope の AWS API 到達 MCP を本 Workspace で有効のまま使う | 採用済み方針 | 2 | 2 | 5 | 2 | 1 | 採用（開発方針） | E0 ではセキュリティ優先で不採用と評価したが、Human が開発方針として AWS MCP の利用を許可した（4-5 A 表）。AWS API 到達・version 非固定の Risk は残り、書き込み系は Human 確認で扱う。無効化は代替構成（A8） |
| C5 | Custom Agents | 提案中（不採用） | 2 | 2 | 2 | 4 | 3 | 不採用 | 6-2 |
| C6 | 外部 Kiro Powers | 提案中（不採用） | 1 | 2 | 3 | 3 | 2 | 不採用 | 6-3 |
| C7 | 開発 Workspace での自 Plugin Power 利用 | 前提 | 1 | 2 | 3 | 2 | 1 | 不採用 | 6-4（A9 で禁止） |
| C8 | Hook H1-a（`{{filePath}}` 埋め込み）/ H1-d（既定 rule） | 提案中（不採用） | 2 | 2 | 4 / 1 | 2 | 1 | 不採用 | Injection の恐れ / 既存 5 件で常時失敗 |
| C9 | 全体 pytest hook・agent 型 hook・`Stop` hook・`--fix` hook | 提案中（不採用） | 2 | 1 | 3 | 3 | 2 | 不採用 | 414 秒、Agent loop の再起動、自動修正禁止に反する |
| C10 | `PreToolUse` 危険操作 guard hook | 提案中（不採用） | 2 | 2 | 2 | 3 | 3 | 不採用 | Permissions `deny` で代替（5-2 H3） |
| C11 | `security-policy.md` の新設 | 提案中（不採用） | 1 | 1 | 1 | 3 | 1 | 不採用 | `security.md` と重複（4-1） |
| C12 | Global steering（`~/.kiro/steering/`） | 提案中（不採用） | 1 | 2 | 1 | 3 | 1 | 不採用 | 他 Workspace に波及する。本 Project の規則は Workspace に閉じる |
| C13 | `.kiro/`（Steering / Spec）を公開 repository に含める | 提案中（保留） | 3 | 2 | 2 | 3 | 3 | 保留（Human 判断） | Contributor への透明性は上がるが、`.gitignore` 変更・Power の clone に `.kiro/` が入る影響・`docs/kiro-power.md` の記述との整合を要確認（Decision D-3。E1 では (a) の独立 local repository を条件付き採用したため、本案は保留のまま） |

### 総括

- **Minimum** は「新しい外部 Tool を入れず、Kiro の設定（Steering / Spec / Permissions / Power 無効化）を整える」構成。追加の download は無い。AWS CLI の deny と AWS MCP の無効化（A7 / A8）は代替構成に移した。
- **Recommended** で初めて download を伴う物（venv、任意の Docs MCP）と OS 境界（sandbox）を足す。ただし sandbox（B1）は E1 で Workspace Foundation に前倒しして有効化した（download は伴わない）。
- 追加の MCP は v1.1 開発には不要。AWS CLI / AWS MCP / Git は採用済み開発方針として開発で利用でき、書き込み系と Production への破壊的変更は Human が確認する（4-5 A 表）。AWS への到達を技術的に断つ構成は代替構成（4-5 B 表）として残す。
- 開発環境の権限は、製品の自動実行範囲（4-5 C 表）を変えない。

## 参照した公式情報

確認日はすべて 2026-10-16。内容は変わりうるため、導入時に再確認する。

| 情報源 | URL |
| --- | --- |
| Kiro Hooks | https://kiro.dev/docs/hooks.md, https://kiro.dev/docs/hooks/types.md, https://kiro.dev/docs/hooks/actions.md |
| Kiro Steering | https://kiro.dev/docs/steering.md |
| Kiro MCP configuration / security | https://kiro.dev/docs/mcp/configuration.md, https://kiro.dev/docs/mcp/security.md |
| Kiro Powers | https://kiro.dev/docs/powers.md, https://kiro.dev/docs/powers/installation.md |
| Kiro Specs | https://kiro.dev/docs/specs.md, https://kiro.dev/docs/specs/feature-specs.md |
| Kiro Custom agents | https://kiro.dev/docs/custom-agents.md |
| Kiro Permissions / Sandbox / Configuration scopes | https://kiro.dev/docs/permissions.md, https://kiro.dev/docs/sandbox.md, https://kiro.dev/docs/configuration.md |
| Kiro CLI V3 | https://kiro.dev/docs/cli/v3.md |
| AWS Documentation MCP Server | https://github.com/awslabs/mcp/tree/main/src/aws-documentation-mcp-server |
| AWS IaC MCP Server | https://github.com/awslabs/mcp/tree/main/src/aws-iac-mcp-server |
| AWS MCP Server | https://docs.aws.amazon.com/aws-mcp/latest/userguide/what-is-mcp-server.html |
