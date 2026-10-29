# Phase 2 / M1 / WP0 — Repository Baseline

作成: 2026-10-28（WP0、読み取り専用の監査）。本書は調査結果であり、実装済み機能の仕様ではない（`structure.md` docs/v2）。

確度の表記: [実測] 本WP0でCommandを実行して得た値 / [文書] 既存文書の記載をそのまま引用 / [推論] 実測からの導出 / NOT_VERIFIED 確認できなかった事項。

## 1. Repository状態 [実測]

| 項目 | 値 | 取得方法 |
| --- | --- | --- |
| Current Branch | `feature/phase1-bounded-remediation` | `git rev-parse --abbrev-ref HEAD` |
| HEAD | `4bd6e015d88b01d34dc83dc2b2d2ffb0058358b2`（2026-10-27T13:50:56+09:00） | `git rev-parse HEAD` |
| 直近Tag | `v1.1.0`（HEADを指すTagはなし） | `git describe --tags --abbrev=0` |
| Git Status（WP0開始時） | `?? .agents/` の1行のみ。追跡ファイルの変更なし | `git status --porcelain=v1` |
| PATH先頭の `python3` | 3.14.7（PyYAML・pytest未導入） | `python3 --version` |
| Test用Python | `/usr/bin/python3` 3.9.6、PyYAML 6.0.3、pytest 8.3.4 | `-c 'import yaml, pytest'` |
| cfn-lint / cfn-guard / gh | PATH上に存在（版は本WP0で未確認） | `which` |
| `.kiro/` Repository | branch `master`、HEAD `23c25d9`（2026-10-24）、作業ツリー clean、remote 0件 | `git -C .kiro …` |
| `.agents/` のサイズ | 32 MB | `du -sh` |

WP0成果物の作成後に増える差分は `docs/v2/phase2/` 配下の新規5ファイルだけである（最終報告で `git status` を再確認する）。

## 2. Dependency [実測]

* Runtime: `PyYAML>=6.0` のみ（`pyproject.toml` `[project] dependencies`）
* Test: `pytest>=7.0`, `pytest-cov>=4.0`, `hypothesis==6.141.1`
* Lint（Advisory）: `ruff==0.8.6`, `mypy==1.14.1`
* Helperは標準ライブラリ＋PyYAML（`audit_probe_workflow` 内で遅延import）＋外部Command（`git`, `gh`, `openssl`）。追加Dependencyなし

M1設計でもDependencyは追加しない（`m1-architecture-proposal.md` §6）。

## 3. Git管理対象と非管理対象

| Path | Git状態 [実測] | 内容 |
| --- | --- | --- |
| `docs/v2/phase1/`（18ファイル） | 追跡 | requirements、design、AC map（`ac-traceability.json`）、`app-demo-plan.md`、gate spike scripts |
| `docs/v2/phase1/app-demo-plan.md` | 追跡。`24b7a6e`〜`4bd6e01` の5 commit。作業ツリーは HEAD と一致 | §7 Evidence 基準 |
| `tests/unit/test_phase1_traceability.py` | 追跡 | `docs/v2/phase1/ac-traceability.json` の構造のみ検査（真偽は検査しない、docstring） |
| `.agents/`（全体） | **未追跡（untracked）**。`.gitignore` に記載なし | Helper、Helper Test、Evidence、Final Acceptance rev1〜rev3 |
| `.kiro/` | `.gitignore` 56行目で除外。独立Repository（remoteなし） | steering、specs |
| `sample/`, `semantic-review/` | `.gitignore` で除外 | — |

`git ls-files .agents .kiro` は0件 [実測]。

### 3-1. 重要な制約

1. **Helperは一度もGit管理されていない。** `phase1_appdemo.py` / `phase1_henv.py` / `phase1_henv_owner.py` と14個のTestファイルは `.agents/tasks/phase1/henv/` にあり未追跡 [実測]。`app-demo-plan.md` §10も「local, under `.agents/`, not committed」と記載 [文書]。WP1でGit管理に入れても、それはPhase 1当時の内容を証明しない。
2. **Helperの現在の内容は、主要Evidenceの生成時の内容と同じであることを証明できない。** `phase1_appdemo.py` の mtime は 2026-10-28T15:40:09+09:00、E18（`app-evidence.20261028T045529589034Z-1.json`）の mtime は 13:55:29+09:00 [実測]。Evidence側にHelperのversion・hashの記録はない（E18の最上位keyに該当なし [実測]）。
3. **`.agents/` は ignore されていない。** `git add .` や `git add -A` で32 MBのEvidence、アカウント名入りのtargets、入れ子の `.git`（`henv/out/demo-repo/.git`、`henv/out/app-demo-2/repo/.git`）が混入しうる [推論]。
4. **Secret scanの対象外。** `.github/scripts/scan_secrets.py` は `git ls-files -z` を優先し（396行目）、未追跡の `.agents/` を走査しない [実測：コード読解]。Phase 2 handoff の「secret scan 0件」は、現行の走査範囲では `.agents/` について何も示さない。
5. **アカウント名（PII相当の識別子）を含むファイル。** `appdemo-targets.json`、`appdemo2-targets.json`、`henv-targets.json`、`phase1_appdemo.py`、Test 6本に `<account>`（匿名化。Pre-Commit Remediation C-1） を含む [実測 grep]。公開範囲の分離が必要（handoff P1-1）。

## 4. 既存構成（M1に関係する部分）

```text
.agents/tasks/phase1/                    (untracked)
├── henv/
│   ├── phase1_appdemo.py        4,250行  App demo Helper（G0〜G12, G11b）
│   ├── phase1_henv.py             586行  H-ENV基盤（Ctx, Stop, save, legacy demo）
│   ├── phase1_henv_owner.py       601行  Owner run / legacy demo 判定
│   ├── test_phase1_*.py         14本     Helper Test（計516件、本WP0で全PASS）
│   ├── *-targets.json                    対象Repository・pin（アカウント名を含む）
│   └── out/
│       ├── app-demo-2/                   demo-2 Evidence（E01〜E30の大半）
│       ├── app-demo/                     初代App demo
│       └── demo-repo/, owner-*           legacy demo
└── final-acceptance/
    ├── (rev1 5ファイル)                  保全、superseded
    ├── rev2/ (5ファイル)                 current
    ├── rev3/ (4ファイル)                 追補
    ├── REVISIONS.md
    └── github-evidence-20261028/         認証なしGETの補完（rev3）
iacreview/remediation/                   (tracked) Phase 1 Core（validator, report, gitsnap 等）
docs/v2/phase1/                          (tracked) Phase 1 公開文書
```

`docs/v2/phase2/` はWP0開始時に存在しなかった [実測]。

## 5. Phase 1 Helper Testの現状 [実測]

| Command | Exit | 結果 | 所要 |
| --- | --- | --- | --- |
| `PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 -m pytest -q -p no:cacheprovider --rootdir=. test_phase1_*.py`（cwd `.agents/tasks/phase1/henv`） | 0 | 516 passed（進捗表示 72×7＋12 から集計）、FAIL 0、SKIP 0 | 67秒 |
| `PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 -m pytest -q -p no:cacheprovider tests/unit/test_phase1_traceability.py` | 0 | 6 passed | 数秒 |

* 実行前後で `git status` は `?? .agents/` のまま [実測]。Cache・bytecodeを書かない指定で実行した。
* 全体pytest、Benchmark、Determinism、Secret scan は本WP0では **NOT VERIFIED**（WP0は設計のみで、既存コードを変更していないため）。

## 6. 主要ファイルのSHA-256（WP0時点の観測）[実測]

WP0時点のバイト列を固定するための記録であり、Phase 1当時の内容を証明するものではない。rev1 の5ファイルは `REVISIONS.md` 記載値と、`github-evidence-20261028/` の3ファイルは README 記載値と一致した。

```text
493177b44f488f96cf54f1aa02d9dedda9a5310cbac6cd61a236e0a8083228bf  .agents/tasks/phase1/henv/phase1_appdemo.py
26b497e0c60e3df1658f3e16e8f5d2d348665f12fc6422bb362d56c4a7491eba  .agents/tasks/phase1/henv/phase1_henv.py
47682fb11fac0201bd040389509f2f321ece50df525c6180796babdf142ff2e9  .agents/tasks/phase1/henv/phase1_henv_owner.py
a12963494033d6a982727eee3af45a3212865722f061c7b7bb5a0241459c5e20  .agents/tasks/phase1/henv/out/app-demo-2/app-evidence.20261028T045529589034Z-1.json   (E18)
aef16bc06cbcdaa3fc353a4ad5c998ba1d2ab63a25b2a00665e56061f410bdce  .agents/tasks/phase1/henv/out/app-demo-2/g12-evidence.20261028T040542388065Z-1.json   (E22)
d3e9fea815cf0d4ef55b2da93131f431829f4203e2ebf6911a9333b40a3ea0fc  .agents/tasks/phase1/henv/out/app-demo-2/g11-incident-evidence.json                     (E24)
7b92541f9b5db639564f7cf0be0374b862f52773d145921eba5f5a021afd8695  .agents/tasks/phase1/henv/out/app-demo-2/g11b-integrity.20261028T071027277739Z-1.json (E28)
cf885c25c986ca17f5f9e47ea7b0d51285d5b3e7d2102564df735e210f903b86  .agents/tasks/phase1/henv/out/app-demo-2/push-integrity.json                             (E29)
8cfc5266a998cc6fec549a3d4bb9b8b2765b620c9481424d47b91a2bea14bd1d  .agents/tasks/phase1/henv/out/app-demo-2/g11b-evidence.json                              (E30)
a78895c46f90da8c9f8876bec68e8a25054ef277a6d6e911ca3abd90e7958e5b  .agents/tasks/phase1/final-acceptance/rev2/phase1-acceptance-matrix.csv
6f1ef692e6ff87643b215e47ff2e2ca1daf42fc1bbddbeb2cefd35d3d4599ac7  .agents/tasks/phase1/final-acceptance/rev2/phase1-community-contribution-summary.md
07216f600b938d5e39936d073da402ebfa914c5b495887f89bd3bb7c4b76520d  .agents/tasks/phase1/final-acceptance/rev2/phase1-evidence-index.md
fabcf5962d0852a1275df5da24797b95e5d0d0fb8a717455e27d9f065a3a7489  .agents/tasks/phase1/final-acceptance/rev2/phase1-final-acceptance-summary.md
facc1da1b0fa4fffc9697d3b486e806aef545fdb1ebf511c0903a7986ac0feb3  .agents/tasks/phase1/final-acceptance/rev2/phase1-open-risks.md
52b3f803f7c0b7d37510c30885be1aa9c6ea227b6b7df907caaaa0e7274d4139  .agents/tasks/phase1/final-acceptance/rev3/phase1-ac-traceability.rev3.json
c472d86c1022dacf49da0aa09faa0e9daa1d739c23f09def9e7fc119beffd20e  .agents/tasks/phase1/final-acceptance/rev3/phase1-ac-traceability.rev3.md
bc6d47206469f7c1ae17a6dde3536f446fd57e40db80254624764cd4a1b1a522  .agents/tasks/phase1/final-acceptance/rev3/phase1-evidence-finalization.md
fe095ad2e851b0f372fc72d87081511b8e17dc055680bcfab69f46b3eae4f56c  .agents/tasks/phase1/final-acceptance/rev3/phase2-handoff.md
fbc6dcc42288cafc2708885e5f66a86fec9df57b0a5169cb03cf7cd4e5542000  docs/v2/phase1/app-demo-plan.md
b6df66bdf8be4ff8a6e7f9ba025bfcf5c2b12c2aa81b043905dbf90489284e60  docs/v2/phase1/ac-traceability.json
```

rev2 / rev3 の文書自体には、作成時に記録されたHashがない（rev1 だけ `REVISIONS.md` にある）[実測]。上記は WP0 時点の値であり、rev2 / rev3 作成時点の値と同一であることは NOT_VERIFIED。

## 7. 公開制約（M1の前提）

* `.agents/` と `.kiro/` は公開物に含めない（`structure.md`、Phase 1 AC41）。M1でGit管理に入れるのは汎用部分だけで、Location は Human が決める（`m1-architecture-proposal.md` D-1）。
* `docs/v2/phase1/ac-traceability.json` は `tests/unit/test_phase1_traceability.py` が読むため、M1では変更しない。
* `.kiro/specs/aws-iac-review-agent-plugin/` は編集しない（`structure.md`）。
* `.gitignore`、CI、`pyproject.toml` の変更は Human 承認が必要（`development-workflow.md`）。
