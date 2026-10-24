# aws-iac-review-agent-plugin

決定論的な静的解析と Agent による意味的レビューを組み合わせ、正規化された 1 つの
Finding レポートを出力する Agent Plugins 1.0.0 パッケージ。

> **この文書は日本語補足である。** 正典は英語版の [`README.md`](README.md) であり、
> この文書は英語版を置き換えない。節構成は英語版と 1 対 1 で対応しているが、記述が
> 食い違った場合は英語版を正しいものとして扱う。英語版に書かれていない機能はここにも
> 書かれていない。

## aws-iac-review-agent-plugin とは

AWS CloudFormation テンプレートと、AWS CDK が synth した出力をレビューする可搬な
plugin パッケージである。構成は manifest 1 つ、Skill 5 つ、共有 Python 3 ライブラリ 1 つ、
cfn-guard の policy rule 群からなる。構文と resource property の妥当性は cfn-lint、
明示的な policy は cfn-guard、危険な権限パターンは plugin 自身の決定論的な IAM detector
が担当する。その後、各 source が見つけたものを統合し、host agent が推論で生成した
Finding を折り込み、1 つの JSON `Review_Report` を stdout へ書き出す。

現時点でできること。

| 機能 | 実現方法 |
| --- | --- |
| CloudFormation の構文と resource property のレビュー | cfn-lint。結果は plugin の Finding schema へ正規化される |
| 組織 policy のレビュー | 同梱の 36 個の `.guard` rule に対する cfn-guard。encryption / public access / logging / tagging / IAM / backup / availability / data protection を対象とする |
| 決定論的な IAM レビュー | wildcard 権限、権限昇格 action、無制限の `iam:PassRole` と `sts:AssumeRole`、confused deputy 条件の欠落、cross-account および wildcard principal を対象とする 15 個の有効な detector |
| 決定論的な network レビュー | gateway アタッチ、default route、インターネット到達性、孤立した network リソースをリソースグラフ解析で検査する |
| 決定論的な secret レビュー | Lambda 環境変数、EC2 UserData、Parameter default に平文で書かれた secret を検出する。出力では値を redact する |
| 決定論的な quality レビュー | condition 論理、未使用 parameter/condition、循環依存、型混在 AllowedValues をテンプレート構造解析で検査する |
| Agent による意味的レビュー | 2 つの Skill (`cloudformation-review`、`iam-review` の layer 2) が決定論的に抽出された事実を推論の入力とし、pipeline が検証してから統合する Finding を生成する |
| 正規化された 1 つのレポート | すべての Finding が同じ 13 フィールド、11 カテゴリのいずれか 1 つ、検出した source を持つ。等価な Finding は統合される。ID は決定論的に付与される |
| SARIF 2.1.0 出力 | `iac-review --format sarif` はレポートを SARIF として出力し、GitHub code scanning や CI の結果ビューアで利用できる。Confidence、カテゴリ、統合された source リストを各 result の `properties` に保持する決定論的変換である |
| synth 済み CDK 出力のレビュー | `cdk.out/` 配下のテンプレートは別グループとしてレビューされる。`cdk synth` は明示的な flag を付けたときだけ実行される |

Read Only である。AWS API を呼ばず、何も deploy せず、修正を適用しない。

## なぜこの Project が必要か

AWS IaC のレビューは、単一のツールでは答えの出ない問いに答える作業である。構文、
CloudFormation 固有 rule、暗号化、public access、logging、backup、tagging、IAM の権限
設計、そして architecture が妥当かどうかは、通常は別々のツールで、別々の出力形式で
確認され、architecture の判断は人間に残される。それらの出力を突き合わせるのは手作業で、
結果は再現しにくい。

この project の立場は、2 種類のレビューはどちらかを選ぶのではなく組み合わせるべきであり、
内部では厳密に分離しておくべきだ、というものである。

- **既存ツールが判定できることは、そのツールが判定する。** CloudFormation の resource
  specification は cfn-lint が担当する。宣言的な policy は cfn-guard が担当する。列挙された
  危険な IAM パターンはコードが照合する。いずれも推論として再実装せず、すべて
  `Confidence: Confirmed` になる。
- **閉じた rule set で表現できないものは Agent の推論に任せる。** resource 間の関係に
  現れる risk、architecture 上の懸念、文脈依存の severity、rule として符号化されていない
  best practice がそれにあたる。これらの Finding は `Likely` または `Contextual` であり、
  `Confirmed` にはならない。
- **検出より後ろはすべて決定論的なコードである。** 正規化、統合、順序付け、番号付け、
  集計は Python で行うため、同じ入力に対するレポートは実行ごとに byte 単位で同一になる。
  これがレビューを前回のレビューと比較可能にしている。

決定論的な処理と Agent の境界は、Agent が構造的にできない 3 つのことを含めて
`docs/architecture.md` が判断ごとに記述している。

## Architecture

```text
IaC (untrusted)
 -> deterministic checks: cfn-lint, cfn-guard, IAM detectors, network graph analysis, secret detection, template quality
 -> agent semantic review: IAM context, security, architecture, best practices
 -> Finding normalization
 -> deduplication and merge
 -> Review_Report (JSON on stdout)
```

Skill は 5 つあり、それぞれが独自の責務と entry point を持つ。互いを呼び出さず、plugin
root の `iacreview/` パッケージを共有するため、Finding はどの Skill が生成したかに依存
しない。

| Skill | 答える問い | 必要なもの |
| --- | --- | --- |
| [`cfn-lint-review`](skills/cfn-lint-review/SKILL.md) | テンプレートは構文的に妥当で deploy 可能か | `PATH` 上の cfn-lint |
| [`cfn-guard-review`](skills/cfn-guard-review/SKILL.md) | 同梱または独自の `.guard` policy rule に適合しているか | `PATH` 上の cfn-guard |
| [`iam-review`](skills/iam-review/SKILL.md) | IAM policy は何を許可しており、どの権限が危険か | 外部ツール不要 |
| [`cloudformation-review`](skills/cloudformation-review/SKILL.md) | 設計は妥当か。resource 横断の risk、単一障害点、文脈依存の severity | 外部ツール不要。Agent 推論を担う Skill |
| [`iac-review`](skills/iac-review/SKILL.md) | 上記すべてを 1 つのレポートとして | cfn-lint と cfn-guard は optional |

Repository の構成。

```text
plugin.json          Agent Plugins 1.0.0 の manifest
skills/              5 つの Skill。それぞれ SKILL.md と scripts/ を持つ
iacreview/           共有される決定論的ライブラリ (import されるだけで install されない)
rules/               6 つのカテゴリディレクトリに置かれた 36 個の cfn-guard rule
benchmark/           測定対象の 15 case、ground truth、harness
examples/            レビューを通ることを意図した小さなテンプレート
tests/               unit / integration / negative / regression / property test
docs/                architecture、security model、Finding schema、benchmark 方法、Kiro
```

pipeline、layer ごとの保証、共有ライブラリが `skills/` の内側ではなく隣に置かれている
理由は `docs/architecture.md` を参照。

## 対応 IaC

| 入力 | 対応 | 備考 |
| --- | --- | --- |
| CloudFormation テンプレート (YAML) | Yes | `SafeLoader` のサブクラスと、CloudFormation short tag の明示的な allowlist で解析する |
| CloudFormation テンプレート (JSON) | Yes | `json.loads`、hook なし。PyYAML が無くても動作する |
| テンプレートを含むディレクトリ | Yes | `*.yaml`、`*.yml`、`*.json`、`*.template`、`*.template.json` を再帰的に走査する |
| synth 済み CDK 出力 (`cdk.out/`) | Yes | 別のテンプレートグループとしてレビューし、summary でも別に数える |
| CDK project のソースから | `--confirm-cdk-synth` 指定時のみ | 流れは `cdk synth` -> CloudFormation テンプレート -> レビュー。synth は利用者の project のコードを sandbox 無しで実行する。Security 上の考慮事項を参照 |
| Terraform、Pulumi、その他の IaC | No | v0.1 では対象外。Roadmap を参照 |

どちらの parser を使うかは拡張子ではなく内容で決まる。空白以外の最初の文字が `{` または
`[` の文書は JSON として解析される。組み込み関数はデータとして長形式へ変換される
(`!Ref X` は `{"Ref": "X"}` になる)。解決や評価は行わない。

## Requirements

実行時。

| 依存 | 最低バージョン | 必須 | 備考 |
| --- | --- | --- | --- |
| Python 3 | 3.9 | Yes | `python3` として起動される |
| PyYAML | 6.0 | YAML テンプレートには Yes | 実行時の Python 依存は**これだけ**。JSON テンプレートは無くてもレビューできる |
| cfn-lint | 1.0.0 | No | 外部の実行時依存。同梱しない |
| cfn-guard | 3.0.0 | No | 外部の実行時依存。同梱しない |
| AWS CDK CLI | 2.0.0 | No | 外部の実行時依存。同梱しない。`--confirm-cdk-synth` 指定時にのみ起動される |

**3 つの外部ツールはいずれもこの plugin に同梱されていない。** どれも `PATH` 上で名前
解決され、実行ごとに 1 回バージョンが検査される。plugin は何も install しない。cfn-lint
または cfn-guard が無い、あるいは古すぎる場合は、最低バージョンと install コマンドと共に
`errors[]` に記録され、`tools[]` では利用不可として列挙され、残りの source がレビューを
生成する。どちらも無い場合でも IAM Finding は報告される。IAM detector は plugin 自身の
コードだからである。

対応 OS は **macOS と Linux** である。Windows は v0.1 の対象外で、テストしておらず、
一部のテスト補助は POSIX shell script である。

開発およびテスト用の依存 (`pytest`、`pytest-cov`、`hypothesis`) は `pyproject.toml` の
`dev` extra に分けて宣言されており、実行時の依存予算には含まれない。`iacreview/`、
`skills/`、`benchmark/` のいずれもこれらを import しない。

## Installation

plugin はディレクトリとして配布される。build 手順は無く、生成物も無く、`pip install`
されることもない。client に渡すディレクトリは、root に `plugin.json` を持つこの
repository のディレクトリそのものである。

```sh
git clone https://github.com/nobu-13/aws-iac-review-agent-plugin.git
cd aws-iac-review-agent-plugin
```


YAML テンプレートのレビューに必要な PyYAML を install する。

```sh
pip install 'PyYAML>=6.0'
```

必要な外部ツールを install する。以下は、ツールが見つからないときに plugin 自身が
remediation として報告するコマンドである。

| ツール | macOS | Linux |
| --- | --- | --- |
| cfn-lint | `pip install cfn-lint` | `pip install cfn-lint` |
| cfn-guard | `brew install cloudformation-guard` | `cargo install cfn-guard` |
| AWS CDK CLI | `npm install -g aws-cdk` | `npm install -g aws-cdk` |

同梱の example をレビューして install を確認する。何も報告されないのが期待結果である。

```sh
python3 skills/iac-review/scripts/run_iac_review.py \
  --target examples/minimal-s3/template.yaml
```

## Kiro Power としての利用

Kiro は Agent Plugins パッケージを Power として読み込む。このパッケージはそのために
追加するものが何も無い。`plugin.json` はパッケージ root にあり、`skills/` は子
ディレクトリを正確に 5 つ持ち、それぞれが `SKILL.md` を持つ。これは非再帰的な discovery
走査が見つける形である。

Power の読み込みが何に依存するか、この repository のどのファイルが Kiro 固有でなぜ可搬な
パッケージの外に置かれているか、そしてこの主張がどこまで検証されているかは
**[`docs/kiro-power.md`](docs/kiro-power.md)** に記載している。

> **Status.** Power の読み込みが前提とする構造的条件は検証済みで、テストで固定されている。
> end-to-end の読み込みは **Kiro 1.0.337 で検証済み**である。5 つの Skill すべてが host agent
> に届き、`iac-review` のエントリポイントが実行されて Review_Report を生成し、パッケージへ
> 追加したものは何もない。以前の読み込みでは `SKILL.md` の `description` が長すぎて 3 つの
> Skill が除外されたが、この不具合は修正済みでテストで防いでいる。`docs/kiro-power.md` に
> 両方の実行を記録している。この結果は version 固有であり、Known Limitations に記載している。

Kiro 固有の開発用ファイル (`.kiro/steering/`、`.kiro/specs/`) は plugin の実行には不要で
ある。`skills/`、`iacreview/`、`rules/`、`benchmark/` 配下のいずれのファイルも `.kiro/`
から何も読み込まない。

## Usage

script は repository root から実行する。作業ディレクトリが workspace root となり、
すべての path はその内側で解決される。各 script は JSON 文書 1 つを stdout へ、診断情報を
すべて stderr へ書く。stdin は読まず、対話的な入力を求めず、workspace へ書き込まない。

レビュー全体を 1 つのレポートとして。

```sh
python3 skills/iac-review/scripts/run_iac_review.py \
  --target examples/minimal-s3/template.yaml
```

```sh
python3 skills/iac-review/scripts/run_iac_review.py --target templates/
```

観点を 1 つずつ。

```sh
python3 skills/cfn-lint-review/scripts/run_cfn_lint.py --target examples/minimal-s3/template.yaml
python3 skills/cfn-guard-review/scripts/run_cfn_guard.py --target examples/minimal-s3/template.yaml
python3 skills/iam-review/scripts/run_iam_scan.py --target examples/lambda-with-role/template.yaml
```

Agent が推論の入力とする事実の抽出。Agent 推論を担う Skill はここから始まる。

```sh
python3 skills/cloudformation-review/scripts/extract_facts.py --target examples/minimal-s3/template.yaml
python3 skills/iam-review/scripts/extract_policies.py --target examples/lambda-with-role/template.yaml
```

抽出した事実から構造化レビュープロンプトを生成する。host agent または任意の MCP 接続
モデルがこれを読んで推論する。

```sh
python3 skills/cloudformation-review/scripts/build_prompt.py --target examples/minimal-s3/template.yaml
```

Agent が生成した Finding をレポートへ統合する。

```sh
python3 skills/iac-review/scripts/run_iac_review.py \
  --target templates/app.yaml \
  --agent-findings agent-findings.json
```

既定の JSON レポートの代わりに SARIF 2.1.0 を出力する。GitHub code scanning や
別の CI 結果ビューア向けである。

```sh
python3 skills/iac-review/scripts/run_iac_review.py \
  --target templates/app.yaml \
  --format sarif > review.sarif
```

`iac-review` の option は `--target` (必須、繰り返し可)、実行する決定論的 source を絞る
`--sources`、同梱 rule に自分の `.guard` rule を追加する `--rules-dir`、
出力形式を選ぶ `--format {json,sarif}` (既定は `json`)、
`--agent-findings`、`--confirm-cdk-synth`、`--verbose` である。各 `SKILL.md` が自身の
option と出力を網羅的に記述している。

**2 つの revision の比較 (Delta_Tool、v1.1、未 Release)。** `iacreview/deltacli.py` は
Base と Head の CloudFormation Template (Semantic Diff) と、Base と Head の Review_Report
(Finding Delta) の一方または両方を比較し、Delta_Report の JSON 文書 1 つを stdout へ書く。
比較 Tool であって品質 Gate ではなく、改善した・修正された・安全である・合格したと主張する
field は無い。読み取り専用であり、command line で指定した file だけを読み、process を起動
せず、network に接続せず、file を書かない。Skill ではなく Python module の entry point で
あり、既存の Skill、Finding、Review_Report、上の exit code 表は何も変えない。workspace root
から実行し、workspace が別の directory なら Plugin root を `PYTHONPATH` に置く。すべての
path は workspace の内側に解決されなければならない。

以下の例は、1 つの stack の 2 つの checkout を置いた作業用 workspace で実行した。Head は
`*` に `*` を許す `AWS::IAM::ManagedPolicy` を追加し、同じ権限を持つ `AWS::IAM::Role` を
削除し、任意の role を pass できる role は残している。

2 つの Template の Semantic Diff (exit 0)。

```sh
PYTHONPATH=<plugin_root> python3 -m iacreview.deltacli \
  --base-template checkout-base/stack/template.yaml \
  --head-template checkout-head/stack/template.yaml
```

```text
semantic_diff: analysis_state=analyzed observation=changes_observed structural_completeness=complete
  added    ["Resources", "id-000001"]  resource_type {base: null, head: AWS::IAM::ManagedPolicy}
  removed  ["Resources", "id-000002"]  resource_type {base: AWS::IAM::Role, head: null}
```

Report は、`Location.File` と `target` が両側で一致するよう、各 checkout を同じ相対 path で
Review して作る。

```sh
(cd checkout-base && python3 <plugin_root>/skills/iac-review/scripts/run_iac_review.py \
  --target stack/template.yaml --sources iam-review > ../base.json)
(cd checkout-head && python3 <plugin_root>/skills/iac-review/scripts/run_iac_review.py \
  --target stack/template.yaml --sources iam-review > ../head.json)
```

Report の 5 つの宣言を付けた、2 つの Report の Finding Delta (exit 0)。

```sh
PYTHONPATH=<plugin_root> python3 -m iacreview.deltacli \
  --base-report base.json --head-report head.json \
  --declare reports_unmodified --declare same_plugin_version --declare same_rule_set \
  --declare same_tool_configuration --declare same_agent_findings_input
```

```text
finding_delta: analysis_state=analyzed classification_completeness=complete comparable=true
  New        head_only  Resource id-000002  (the added managed policy)
  Resolved   base_only  Resource id-000004  (the removed role)
  Unchanged  matched    Resource id-000005  match_stage 1
```

同じ command から `--declare` を除くと、片側の 2 つの Finding は `input_declaration_absent`
付きの `Unconfirmed` になり、欠けている 5 つの Code が `missing_declarations` に並ぶ。

6 つ目の宣言と、両 Report が Template を Review した path を付けて、両 pair を 1 回の実行で
比較する (exit 0)。

```sh
PYTHONPATH=<plugin_root> python3 -m iacreview.deltacli \
  --base-template checkout-base/stack/template.yaml \
  --head-template checkout-head/stack/template.yaml \
  --base-report base.json --head-report head.json \
  --declare reports_unmodified --declare same_plugin_version --declare same_rule_set \
  --declare same_tool_configuration --declare same_agent_findings_input \
  --declare reports_match_templates \
  --reviewed-template-path stack/template.yaml
```

```text
semantic_diff: added id-000001 (AWS::IAM::ManagedPolicy), removed id-000003 (AWS::IAM::Role)
finding_delta: classification_completeness=complete template_report_correspondence=consistent_by_name_only
  reviewed_template_path {"path": "stack/template.yaml", "status": "declared_not_verified"}
  New        head_only  Resource id-000001
  Resolved   base_only  Resource id-000003
  Unchanged  matched    Resource id-000004  match_stage 1
```

`--reviewed-template-path` は宣言であって検証ではない。Tool はその path の file を読まず
(存在しなくてよい)、与えられた Template が Report の Review した Template であることも検査
しない。Template / Report の対応検査で各 Report の `target` と比較する path を置き換える
だけであり、正規化 (`/` 区切り、`.` と空の要素の除去) の後の文字列として比較し、
`reviewed_template_path` に状態 `declared_not_verified` で記録する。大文字小文字、Unicode
正規化、symlink 名が異なれば `inconsistent` になる。Report の内部整合、Comparable、必要な
宣言、rename hint、上限はそのまま適用されるため、疑わしい入力は `Unconfirmed` か
`Ambiguous` のままで、`New` / `Resolved` にはならない。この option が無ければ、両 pair を
1 回で比較すると `inconsistent` になり、この 2 つの Finding は `Ambiguous`
(`template_report_mismatch`) になる。絶対 path、`..` を含む path、symlink を通って
workspace 外を指す path、両 pair が揃っていない場合は exit 2 である。上の抜粋は JSON を
要約したものであり、全出力は記載の command で再現できる。

Delta_Entry の分類の意味。

- `New` / `Resolved`: 照合手順が反対側に対応する Finding を見つけず、記録された条件 (その
  file について Source が両 Report で比較可能、Report が内部整合の検査に合格、Template /
  Report の対応が `inconsistent` でも `unknown` でもない、rename hint が無い) がすべて成り
  立ち、必要な宣言がすべて与えられた。問題が修正された、または持ち込まれたことの証拠では
  ない。
- `Unchanged`: 照合手順が Base と Head の Finding を対応付けた (段階 1 または 2)。同じ原因
  であることは意味しない。
- `Unconfirmed`: 必要な `--declare` の Code が欠けている片側の Finding。欠けている Code が
  列挙される。
- `Ambiguous`: 一意に対応付けられなかった、または記録された条件が成り立たない。理由が列挙
  される。宣言によって `Ambiguous` が `New` や `Resolved` になることはない。

宣言は `declared_not_verified` として記録され、Tool は検査しない。出力は既定で匿名化される。
Logical ID、entry 名、property と mapping の key、未知の Resource Type、RuleId は 1 つの
Delta_Report の中でだけ安定な Identifier_Token (`id-000001`、...) に置き換えられ、Template の
値、Finding の文章、入力の error 文は書かれない。section 名、`AWS::` の Resource Type、
Category、閉集合の値、workspace 相対の file path は平文のままである。`--plain-identifiers`
は識別子をそのまま書くが、値と自由文はやはり書かない。exit 0 は、何が観測されたかに関わらず
要求されたすべての比較が解析できたことを意味する。比較できない入力は最初の失敗の code
(3、4、7、8、parser divergence なら 1) で終了し、その比較を `unanalyzable` とし、もう一方の
比較は完全に書く。不正な引数は exit 2、想定外の例外は exit 1 で、どちらも Delta_Report を
書かない。すべての key、閉集合、失敗 Code、上限は `docs/delta-schema.md` が正典である。

### レポートの外形

stdout はどの source が動いた場合でも常に 7 キーである。`schema_version`、`target`、
`sources_enabled`、`tools`、`findings`、`errors`、`summary`。1 つの Skill だけがその隣に
カウンタを追加する。`cfn-guard-review` は top-level の `stats` object を出力する。cfn-guard
の実行が clean だった場合、いくつの rule を評価したかを述べる必要があるからである。この
plugin が生成する他のカウンタはすべて `--verbose` 時の stderr 診断であり、`--verbose` が
stdout を変えることはない。

`summary.passed_all_checks` は `findings` が空のときちょうど `true` になる。`errors` に
ついては何も述べないため、ツールが見つからなかった実行は、依頼された範囲より狭くしか
レビューしていない状態で `true` を報告しうる。この 2 つを見分けるのが `errors` 配列である。

13 の Finding フィールド、5 つの閉じた値集合、統合規則、レポートの読み方は
`docs/finding-schema.md` が正典である。

### Exit code

| Code | 意味 | stdout |
| --- | --- | --- |
| 0 | 少なくとも 1 つのテンプレートが少なくとも 1 つの source によってレビューされた。Finding 0 件は成功 | レポート |
| 1 | 想定外の内部エラー、または plugin の install が壊れている | 空 |
| 2 | 引数の欠落または未知の引数、あるいは shell metacharacter を含む path | 空 |
| 3 | 入力 path が存在しないか読めない | 空 |
| 4 | 候補テンプレートすべてが解析に失敗した | `errors[]` を含むレポート |
| 5 | 有効な source すべてが利用不可だった | `errors[]` を含むレポート |
| 6 | 有効な source すべてが実行中に失敗した、または `cdk synth` が失敗した | `errors[]` を含むレポート |
| 7 | path が workspace root の外へ解決された | 空 |
| 8 | `--target` 配下にレビュー対象が見つからなかった | `errors[]` を含むレポート |

4、5、6 は *何も* 成功しなかった実行を表す。同じ失敗が実行の一部にしか影響しない場合は
exit code 0 で `errors[]` に現れる。非ゼロで終了すると「レビューして何も見つからなかった」
と「レビューが行われなかった」の違いが消えてしまうからである。

Benchmark harness は独自に 9 と 10 を追加する。これは意図的に plugin の表の外に置かれて
いる。`benchmark/README.md` を参照。

## Review Categories

すべての source のすべての Finding が、11 個の閉じた集合からちょうど 1 つの
`Normalized_Category` を持つ。正典は `iacreview/category_map.json` の `categories` 配列で
ある。

| Category | 対象 |
| --- | --- |
| `IAM` | IAM policy、role、user、group、trust policy、resource-based policy における権限設計 |
| `Encryption` | 保存時の暗号化、通信時の暗号化、KMS key の利用 |
| `PublicAccess` | インターネットから、あるいはすべての AWS account から到達できること |
| `Logging` | access log、audit log、flow log とその有効化 |
| `Tagging` | 必須 tag の付与 |
| `Availability` | Multi-AZ、冗長性、単一障害点 |
| `Backup` | backup 設定、保持期間、削除保護 |
| `NetworkSecurity` | `PublicAccess` に該当しない Security Group / NACL / VPC 境界の設計 |
| `DataProtection` | データ保持、versioning、削除防止、機密データの扱い |
| `TemplateQuality` | 構文、property の妥当性、非推奨の構成、テンプレート構造 |
| `Other` | 上記のいずれにも対応しない Agent Finding。重複排除の照合対象から除外される |

`PublicAccess` と `NetworkSecurity` は 1 つの規則で分けられる。インターネット
(`0.0.0.0/0`) またはすべての AWS account (`Principal: "*"`) からの到達可能性は
`PublicAccess`、それ以外のネットワーク境界の懸念は `NetworkSecurity` である。

同梱の cfn-guard rule は 6 ディレクトリに 36 ファイル。

```text
rules/
  encryption/     s3_bucket_encryption, rds_storage_encrypted
  iam/            iam_policy_no_star_star
  logging/        s3_access_logging, cloudtrail_enabled
  public-access/  s3_public_access_block, security_group_open_ingress, rds_publicly_accessible
  backup/         rds_backup_retention, rds_deletion_protection
  tagging/        required_tags
```

各ディレクトリは `_meta.json` を持ち、配下の rule の FindingType、Severity、
`Normalized_Category` を割り当てる。分類が実行ごとの判断ではなくレビュー可能なデータで
あるようにするためである。独自 rule は `--rules-dir` で追加できる。同梱 rule も常に
評価される。

## Examples

[`examples/`](examples/) には、レビューを通ることを意図した小さく整った テンプレートを
置いている。意図的な欠陥を含むテンプレートはここには無く、benchmark case として置かれて
いる。

| Example | 報告される Finding |
| --- | --- |
| [`examples/minimal-s3/template.yaml`](examples/minimal-s3/template.yaml) | 無し。`summary.passed_all_checks` は `true` |
| [`examples/lambda-with-role/template.yaml`](examples/lambda-with-role/template.yaml) | ちょうど 1 件。実行 role の trust policy に対する `HIGH`、`Security`、`IAM` |
| [`examples/cdk-synth-output/README.md`](examples/cdk-synth-output/README.md) | CDK application を synth した後にレビューする方法 |

どちらの件数も `tests/integration/test_examples.py` が検証しているため、example が新しい
ものを報告し始めた場合は静かに変化するのではなくテストが失敗する。

`lambda-with-role` の 1 件は文書化済みで、かつ正しい。IAM detector は Lambda 実行 role の
trust policy にある条件無しの service principal を報告しており、これは AWS が文書化して
いる trust policy そのものである。この Finding は policy の形について正しく、その
recommendation は当該 service では実行可能ではない。[`examples/README.md`](examples/README.md)
がこの case を最後まで説明しており、Known Limitations にもこの非対称性を記録している。

## Benchmark

Benchmark はレビュー品質を測る。テストスイートとは目的が異なる。`tests/` は plugin が
仕様どおりに振る舞うかを問い、そこでの失敗は defect である。`benchmark/` は既知の欠陥
集合のうちどれだけをレビューが見つけるかを問い、そこでの数値は測定値である。

```sh
python3 benchmark/harness/run_benchmark.py --cases benchmark/cases --mode combined
```

この repository の 15 case について、Python 3.9.6、cfn-lint 1.46.0、cfn-guard 3.2.1 での
現在の測定値。

| 項目 | 値 |
| --- | --- |
| Case | 12 件。`case-001` から `case-010` が意図的な欠陥を含み、`case-101` と `case-102` は clean |
| 期待値 | 21 件。すべて `deterministic` |
| 検出 | 21 / 21、detection rate `100.0` |
| False positive | 0 件、precision `100.0`、severity accuracy `100.0` |
| Category | 7 カテゴリを exercise し、すべて `PASS` |
| `errors` | 空 |
| Exit code | 0 |

この数値が意味すること。この 12 テンプレートが対象とした欠陥はすべて、期待される
severity で、宣言されていない Finding を伴わずに検出されている。将来の変更でいずれかの
検出が失われれば、カテゴリが `FAIL` になり exit code 9 になる。意味しないこと。この
project が書いていないテンプレートについて何も言えない。false positive rate についても、
clean なテンプレート 2 件で測っているにすぎない。

harness は Agent を起動しないため、同じ case を 2 回実行すると stdout は byte 単位で同一に
なる。Ground truth はテンプレートへ意図的に置いた欠陥から、そのテンプレートに対して
レビューを実行する前に記述する。レビュー出力から逆算することはない。

`benchmark/README.md` が運用者向けの手引きで、`docs/benchmark-methodology.md` が各数値の
意味とどこまで一般化できるかを定義している。

## Validation

| 対象 | 方法 |
| --- | --- |
| テストスイート | `python3 -m pytest`。4000 件超、失敗 0 |
| Unit | 決定論的モジュールを対象とする 43 ファイル。解析、正規化、severity 変換、重複排除、path 検証、exit code、network graph 解析、secret 検出、template 品質 |
| Integration | 7 つの entry point を実際の subprocess として実テンプレートに対して動かす 14 ファイル。不正入力 133 件を含む |
| Negative | clean なテンプレートが、数え上げた種類の false positive を出さないこと |
| Regression | security 上の振る舞いと過去に見つけた defect を固定する 11 ファイル。path traversal、不正な YAML と JSON、shell metacharacter を含むファイル名、外部ツール未導入、不正な引数、symlink の循環、error に host path が出ないこと、YAML alias bomb、通常ファイル以外の拒否、timeout 時のプロセスグループ回収 |
| Property | `hypothesis` により 31 個の named property を述べる 13 ファイル。独立した oracle に対する path containment の検証、および `iacreview.proc` が出荷コードで唯一のプロセス起動経路であることを示す AST 走査を含む |
| Coverage | `python3 -m pytest --cov=iacreview --cov=benchmark/harness --cov-fail-under=80` |
| Benchmark | `python3 benchmark/harness/run_benchmark.py --cases benchmark/cases --mode combined`。全カテゴリ `PASS` |

上記のコマンドはすべてこの repository に対して実行済みである。
`docs/security-model.md` には、各 security 上の主張とそれを固定するテストの対応表がある。

v0.8.0 は悪意ある入力に対する堅牢化を行った。5 MiB を超える単一 Template、あるいは合計 50 MiB を超えるディレクトリは読み込まずに拒否する。YAML alias bomb は上限を設けて parse エラーとして失敗させる。Template は単一の file descriptor 経由で読み、containment 検査と読み込みの間に symlink が差し替えられないようにする。timeout したツールの子孫プロセスは回収する。ツール stderr 中の絶対 host path は report へ届く前に伏せる。Benchmark harness は Remediation Accuracy、Human Intervention Count、Review Time を pass/fail に影響しない診断として記録し、Source サブセットモードに加えて `agent-only` / `human-review` モードを提供する。詳細は `docs/security-model.md` (R-2, R-4, R-8, R-9) と `docs/benchmark-methodology.md` を参照。

v0.9.0 は stderr redaction を host path に加えてラベル付き process identifier と認識可能な timestamp まで広げた (裸の rule id・行番号・version は保持する)。Review Time は `--timing-report` で構造化 JSON として stderr に出力する。residual risk R-1, R-5, R-6, R-7 を確定した方針として整理し、予約配列と診断期待フィールドを埋める benchmark 測定ケースを 2 件追加して、`agent-only` / `human-review` モードと 2 つの診断が宣言された期待値を測るようにした。

v1.0.0 は CDK レビューの結果を report の `target.cdk.synthesis` で可視化し (synth skip を clean なレビューと誤読しないようにする)、負っていた Kiro Power 検証を記録テンプレート付きの再現可能な手順に整備し、MCP を「実装しない opt-in の設計文書」として確定した。`cdk synth` のゲートと非 sandbox の姿勢は不変。

## Security 上の考慮事項

この plugin は、信頼する理由の無い Infrastructure as Code を処理する。入力テンプレート、
path、外部ツール出力の 1 byte までを untrusted data として扱う。trust boundary と残存
risk を含む全体像は `docs/security-model.md` にある。以下は要約である。

**既定で Read Only。** AWS resource を作成、変更、削除しない。そもそも AWS API を一切
呼ばない。AWS SDK への依存が無いからである。何も deploy せず、account 設定を変更せず、
どのモジュールも workspace のファイルを書き込みで開かない。

**自動 remediation を行わない。** 修正案は Finding の `SuggestedRemediation` フィールドと
して報告される。それをどこにも適用しない。

**AWS credentials を子プロセスへ渡さない。** プロセス生成は 1 つの関数に集約されており、
子プロセスへは `PATH`、`HOME`、`LANG`、`LC_ALL`、`TMPDIR`、`AWS_REGION`、
`AWS_DEFAULT_REGION` だけの環境変数 allowlist を渡す。それ以外は渡さない。
`AWS_ACCESS_KEY_ID`、`AWS_SECRET_ACCESS_KEY`、`AWS_SESSION_TOKEN`、`AWS_PROFILE`、その他
すべての `AWS_*` 変数は落とされる。denylist ではなく allowlist なのは、AWS が後から追加
する変数も既定で渡されないようにするためである。この repository のどのファイルにも
credential は無い。benchmark と example の値は明らかな placeholder である。

**Shell を使わない。** 外部ツールはすべて argv 配列と `shell=False` で起動し、stdin を
閉じ、timeout を設定する。コマンド文字列を連結して組み立てることはない。property test が
出荷される `.py` すべてを解析し、2 つ目のプロセス起動経路が現れたら失敗する。

**Path containment。** 利用者が与えた path はすべて解決した後、ファイルを開く前、ツールを
起動する前に workspace root の内側にあることを確認する。plugin 所有のリソースは plugin
root の内側に閉じ込める。値は sanitize せず reject する。

**Untrusted IaC は安全に失敗する。** YAML は tag allowlist を明示した `SafeLoader` の
サブクラスで解析するため、`!!python/object/apply:os.system` のような tag は実行されずに
例外になる。JSON は hook を使わない。解析失敗はすべて行と列を持つ型付きエラーであり、
traceback にはならない。

**`cdk synth` が唯一の任意コード実行境界である。** 自動では実行されない。
`--confirm-cdk-synth` が必須で、警告はどちらの経路でも stderr へ書かれ、120 秒の timeout が
あり、fallback は無い。synth プロセスは利用者の project のコードと、その依存の lifecycle
script を、利用者の権限で実行する。**この plugin はその実行に対して sandbox を提供しない。**

**MCP は依存ではない。** plugin root に `mcp.json` は同梱されておらず、すべての中核機能は
それ無しで完全に動作する。自分で設定を追加した場合でも、plugin の決定論的なコードが MCP
接続を開くことはない。開くのは host agent だけである。そしてテンプレートの path や内容が
server へ送られた時点で、それはこの plugin の管理外へ出る。
[`docs/mcp/README.md`](docs/mcp/README.md) が server ごとの記録である。用途、必要な権限、
network access、credentials、外部へ送られるデータ、失敗時の挙動。なお `.gitignore` は現在
`mcp.json` を除外していないため、`docs/mcp/mcp.json.example` を repository へコピーする
場合は、ローカル設定を commit しないよう注意してほしい。

## Known Limitations

隠したり控えめに書いたりしているものは無い。意図的な制約については、理由を記した文書を
併記している。

**スコープ**

- v0.1 は Terraform、Pulumi、runtime security 分析、FinOps 分析、完全な Well-Architected
  review、Web UI、自動 deploy、自動 remediation を扱わない。これらはこのバージョンの
  非目標であり、部分的に実装された機能ではない。Roadmap を参照。
- **Windows は非対応である。** Requirement 10 AC3 は macOS と Linux のみを対象とする。
  コードは Windows で動く可能性はあるがテストしていない。一部のテスト補助は動作しない
  POSIX shell script である。

**実行時の安全性**

- **`cdk synth` に sandbox は無い。** CDK をソースから起点にレビューすることは、その
  コードを利用者の権限で実行することである。plugin による緩和は、明示的な flag を要求
  すること、子プロセスへ AWS credentials を渡さないこと、timeout を設けることだけである。
  不完全な sandbox は無いほうがましだと判断した理由は `docs/security-model.md` に記して
  いる。
- **`$` を含むファイル名は拒否される。** `cost$estimate.yaml` という名前のファイルは v0.1
  ではレビューできない。`$` は利用者が与える path で拒否される 7 つの shell metacharacter
  の 1 つである。拒否は明示的で名前の付いたエラーになる。値を sanitize せず拒否するのは、
  その文字を除去すると読み込み先が黙って別のファイルへ変わってしまうからである。
- **512 段より深い JSON Template は parse failure になる。** `MAX_JSON_NESTING_DEPTH`
  (512) を超えて入れ子になった array と object は、decode の前に `parse_failure` (exit 4)
  として拒否され、これはどの Python version でも同じである。実在の CloudFormation Template
  がこの深さに近づくことはないが、Python 3.9 が以前 review していた 513〜約 990 段の文書は
  拒否されるようになった。
- **`errors[].stderr_head` は外部ツールの出力を持つが、絶対 host path は伏せられる
  (v0.8.0)。** crash したツールからコピーした最大 5 行であり、各行を走査して絶対 host path
  を固定の `<path>` プレースホルダへ置換してから report へ渡すため、同一入力に対して抜粋は
  byte-identical になる。redaction の対象は絶対 POSIX path のみで、process identifier や
  timestamp、その他ツールが入力について出力した内容はそのまま通るため、untrusted な外部
  テキストとして扱うこと。5 行の上限が縛るのは量であって内容ではない
  (`docs/security-model.md`、R-4)。

**再現性**

- **Agent Review の出力は決定論的ではない。** 決定論的な pipeline は同じ入力に対して byte
  単位で同一であり、同じ Agent Finding ファイルに対しても同一である。これが記録した Agent
  出力を regression fixture として使えるようにしている。その Finding の生成は再現可能では
  ない。Agent は 2 回目の実行で異なる Finding を報告したり、異なる言い回しをしたりしうる。
  Agent Finding を統合したレポートは、与えられた Agent 出力と同じ程度にしか再現しない。
- **外部ツールのバージョン差が結果を変える。** cfn-lint と cfn-guard はそれぞれ独自に rule
  set を進化させ、どちらも同梱も pin もされていない。新しい cfn-lint は古いものが報告
  しなかった rule を報告しうる。この理由で異なる Finding は、cross-platform の一貫性保証の
  外にある。あの保証は install されたツールのバージョンではなく OS についてのものである。
  観測されたバージョンは `tools[].version` に記録される。文書の数値とローカル実行が
  食い違う場合は、まずツールのバージョンを比べること (`docs/architecture.md`)。
- **Agent client 間で挙動が異なりうる。** 推論を担う Skill は、パッケージを読み込んだ host
  agent runtime が解釈する。したがって Agent layer の出力はその client に依存する。決定論的
  な layer は依存しない。

**カバレッジ**

- **同梱の cfn-guard rule は、名前を挙げた resource type だけを検査する。** 36 個の rule が
  対象とするのは特定の S3、RDS、IAM、CloudTrail、Security Group の設定である。どの rule も
  言及していない resource type からは cfn-guard の Finding が出ないが、それはその resource が
  適切に設定されている証拠ではない。独自 rule は `--rules-dir` で追加できる。
- **resource-based policy のカバレッジは固定リストである。**
  `AWS::S3::BucketPolicy`、`AWS::KMS::Key`、`AWS::SQS::QueuePolicy`、
  `AWS::SNS::TopicPolicy`、`AWS::ECR::Repository`、
  `AWS::SecretsManager::ResourcePolicy`、`AWS::Lambda::Permission` を v0.1 で検査する。
  他にも resource-based policy を持つ service はあり、それらは未対応である。そのような
  resource 上の policy は、報告されるのではなく対象外になる。
- **Finding が無いことは compliance の証拠ではない。** 各 source は自身が対象とする範囲を
  見るだけで、テンプレートの外側は一切参照しない。AWS account へ接続しないため、
  account レベルの設定、account 側にだけ存在する role、`Ref` / `Fn::GetAtt` /
  `Fn::ImportValue` が deploy 時に解決する値は、どの source からも見えない。
- **Kiro での Power 読み込みは 1 つの Kiro version で検証済みである。** Kiro 1.0.337 で
  読み込みを実施した。5 つの Skill すべてが host agent に届き、`iac-review` のエントリポイントが
  実行されて Review_Report を生成し、パッケージへ追加したものは何もなかった。ある version で
  観測された読み込みはその version についての証拠であり Kiro 一般についてではないため、大きく
  異なる Kiro version では `docs/kiro-power.md` の手順で再確認すべきである。(以前、version を
  記録していない読み込みでは `SKILL.md` の `description` が長すぎて 3 つの Skill が除外された。
  この不具合は修正済みで、1024 文字上限超過で回帰テストが失敗するようにした。)

**Severity と FindingType の保守性**

分類を所有する `docs/finding-schema.md` からの転記である。

- `CRITICAL` Severity は保守的に付与される。報告される条件が deploy を不可能にすると検証
  できた cfn-lint rule だけが昇格されるため、実際に deploy を阻害するエラーの一部は
  `CRITICAL` ではなく `HIGH` として報告される。より低い Severity の代わりに `HIGH` が
  付くことはないため、この方針で過小評価される Finding は無い。
- 調査対象は cfn-lint **1.46.0** の catalogue である。新しい cfn-lint は mapping ファイルが
  知らない rule を追加しうる。それらは level から分類され、`Error` level では `HIGH` として
  報告され、`CRITICAL` にはならない。
- `E3002` の結果は `HIGH` として報告される。実際には多くが deploy を阻害するが、rule ID
  だけでは基になった schema の失敗を特定できないからである。
- `Security` FindingType も cfn-lint の結果に対して保守的に付与される。`Warning` と
  `Informational` の 66 rule のうち 7 つだけが marking されているため、リストに無い rule で
  cfn-lint が報告した security 関連の条件は、`Security` ではなく `BestPractice` または
  `Informational` として現れる。cfn-guard、IAM Review、Network Review、Secret Review、Quality Review、Agent Review の各 Source は、この
  リストとは独立に security 上の条件を扱う。
- 調査対象は cfn-lint **1.46.0** の catalogue である。新しい cfn-lint が追加した rule は
  level から分類され、`Security` にはならない。
- EOL の Lambda runtime と非推奨の RDS engine バージョンは報告されるが、`Security` ではなく
  `BestPractice` である。条件がテンプレートではなく現在の日付に依存するからである。

**文脈依存の Finding、および recommendation が実行可能ではない場合**

- **`Severity` は 1 つの `FindingType` の内側でしか比較できない。** `HIGH` の security
  Finding と `HIGH` の best practice Finding は、同じ重みの 2 件ではない。
- **決定論的な IAM layer は policy の形を報告し、各 AWS service が何を honour するかの
  service 別の表は持たない。** `cross_service_missing_condition` は、`sts:AssumeRole` を
  呼びうる service principal に制限する `Condition` が無いことを報告し、
  `aws:SourceAccount`、`aws:SourceArn`、`aws:PrincipalOrgID` を推奨する。これらの key は
  呼び出し側の service が値を設定して初めて効く。AWS は Lambda が実行 role を assume する
  場合についてそれを文書化していない。そこに追加しても role は堅牢にならず、function が
  作成できなくなる。この Finding は policy の形について正しく、それが
  `Confidence: Confirmed` の主張する内容である。一方でその recommendation はそうした
  service では実行可能ではない。これは意図的な Layer 1 の保守性である。service 別の表を
  符号化すれば detector がこの repository の外で変わるデータに依存することになり、黙って
  いれば、confused deputy の露出が実在する読者からそれを隠すことになる。同じ非対称性は
  confused deputy 条件 key に対応しないすべての service に当てはまる
  (`docs/finding-schema.md`、`examples/README.md`)。
- **`wildcard_resource` は、手書きの Lambda logging 権限が必要とする `:log-stream:*` の
  ARN を報告する。** log stream 名は invoke 時に決まるため、ARN は wildcard で終わらざるを
  得ない。その statement を手で書くと `MEDIUM` の Finding が付く。AWS 管理 policy
  `AWSLambdaBasicExecutionRole` から log 配送を取れば、trade-off を 1 か所の名前の付いた
  場所に留められる。`examples/lambda-with-role` はそうしている。
- **Finding は 1 つのテンプレートの内側でのみ統合される。** 等価性は resource の logical ID
  と正規化カテゴリで照合し、2 つのテンプレートが無関係な resource に同じ logical ID を
  使いうるため、統合がテンプレート境界を越えることはない。

**Benchmark**

- **標本は 12 case** で、欠陥ありが 10、clean が 2 であり、10 カテゴリをおおむね 1 case ずつ
  カバーする。これは regression の signal としては十分で、特定のテンプレートで特定の検出が
  働いたという主張にも十分である。この project が書いていないテンプレートでの detection
  rate、意味のある精度を持つカテゴリ別の rate (期待値 2 件のカテゴリは 50 point 刻みで
  動く)、あるいは false positive rate についての結論を許すものではない。後者は clean な
  テンプレート 2 件で測っている。
- **`cfn-lint-only` モードは何も測っていない。** どの case のどの期待値も `detected_by` に
  cfn-lint を挙げていないため、このモードは空の期待値集合を評価し、すべての rate に
  `"N/A"` を報告する。これは意図的である。cfn-lint の期待値は、case の pass / fail を、
  その case が測るために存在する rule ではなく install された cfn-lint の rule catalogue に
  結び付けてしまう。cfn-lint の正規化は代わりに unit test と integration test で扱っている。
- **Agent の検出は未測定である。** 現在の case の期待値はすべて `deterministic` で、harness
  は Agent を起動しないため、この repository のどの数値も Agent の検出について述べていない。
- **cfn-guard rule の clause 1 つが exercise されていない。** `BackupRetentionPeriod` を
  まったく宣言しない RDS instance を cfn-guard に与える case もテストも無い
  (`docs/benchmark-methodology.md`)。
- **ground truth の commit 順序チェックは未実装である。** レビューを実行する前に ground
  truth を記述するという規則は、現時点では人間のレビューで担保している。case の
  `ground_truth.json` が `template.yaml` と同一の commit か、それより前の commit に現れる
  ことを確認する CI チェックは未了である。

**Delta_Tool (v1.1、未 Release)**

完全な一覧は `docs/delta-schema.md` にある。ここには誤解を招きやすいものを挙げる。

- **比較するのは宣言された Template だけである。** Intrinsic Function、Condition、
  Transform、Macro、動的参照、Parameter の値、Nested Stack は評価しない。`complete` かつ
  `no_changes_observed` でも、Deploy 後の Stack が同等であることは意味しない。
- **照合は段階 1・2 のみである。** 類似度や文面による照合は無い。誤った対応付けは `New` や
  `Resolved` を `Unchanged` の陰に隠しうるが、新たに作り出すことはない。
- **Report の真正性と Report / Template の対応は検証しない。** `report_authenticity` は常に
  `unverified` であり、宣言は記録されるだけで検査されない。`consistent_by_name_only` は
  名前の照合であって、Report がその Template から生成されたことの証明ではない。
- **両 pair を 1 回で比較するには `--reviewed-template-path` が必要で、その宣言は検証され
  ない。** この option が無いと、各 Template の path が自側 Report の `target` にあること、
  Finding は同じ `Location.File` の上でだけ照合されることが必要で、1 つの workspace で読む
  2 つの revision は別の path にあるため、片側の entry は `Ambiguous`
  (`template_report_mismatch`、または `source_not_comparable` と `template_not_reviewed`)
  になり、`New` / `Resolved` は出ない。option を付けると、宣言 path がその検査の Template
  path を置き換えるだけである。与えられた Template が Report の Review した Template かどうか
  は Logical ID の検査以上には判別できないため、Logical ID がたまたま一致する誤った宣言は
  検出されない。Report_Pair 単独では rename hint と対応検査が無いため、Logical ID の rename
  は `Resolved` と `New` の組に見えうる。
- **path の不一致は fail-closed である。** Template の path は `./`、`..`、symlink を解決した
  後の workspace 相対の文字列として Report の `target` と比較する。symlink 名、大文字小文字の
  違い、Unicode 正規化 (NFC / NFD) の違いで記録された Report は `inconsistent` (file system
  が file を見つけられなければ `unknown`) になり、workspace 外の path は exit 7 で `unknown`
  になる。いずれの場合も `New` / `Resolved` は出ない。
- **Finding の `TemplatePath` の list index は、Template をたどれる場合にだけ表示される。**
  v1.0 の Report は list index と数字だけの mapping key をどちらも整数で記録する。
  Report_Pair 単独のとき、Template が解析不能な側、Finding の `Location.File` が比較する
  Template path (`--reviewed-template-path` の値、無ければその Template 自身の path) でない
  とき、および list の範囲外の index は、両者を区別できない。そのような整数はすべて Token
  (`--plain-identifiers` では 10 進の文字列) として書き、account ID のような数字だけの key を
  既定で平文に書くことはない。
- **中立なのは Report の内部整合を保つ並べ替えだけである。** v1.1 Requirement 11 AC5 は、
  `report.build_report` の順序を保ち内部整合の検査に合格する並べ替えを対象とし、その場合は
  Report の digest と側ごとの `ID` 以外を変えない。構築済み Report の raw の `findings[]` の
  並べ替えは `rebuild_mismatch` の検査に失敗し、片側の entry は `report_integrity_failed` で
  `Ambiguous` になる。
- **JSON 出力はデータであって表示用の文字列ではない。** C1 制御文字と双方向制御文字
  (U+202A〜U+202E、U+2066〜U+2069、U+200E、U+200F、U+061C) は `\uXXXX` の escape で書く
  ため、JSON をそのまま端末に出しても表示順は並べ替えられない。decode 後の値は変わらない
  ため、JSON を decode して path を表示する program はこれらの文字を表示しうる。その他の
  不可視文字や紛らわしい Unicode 文字はそのまま書かれる。decode した値を人に見せる前に
  escape すること。stderr は入力由来の文字列を含まず、制御文字と双方向制御文字を
  `\u{XXXX}` に置き換える。Markdown 出力は無い。
- **`output_size_limit_exceeded` で終わる入力もメモリと時間を使う。** Tool は render の前に
  出力 size の下限を 128 MiB の上限と比べ、直列化中も上限を超えた時点で中止するため、上限を
  超える出力の全文は作らない。下限が上限より小さい場合は、直列化の前にすべての
  Change_Entry を render する。1 台の machine での local の計測 (macOS、Python 3.9。保証ではない) では、
  以前は約 2.3 GiB と 2.9 GiB を使った入力の peak が約 250 MiB と 520 MiB になり、下限が
  上限の直下になる入力は約 0.7〜0.75 GiB・14〜16 秒を使った。結果は fail-closed であり、最小の
  Delta_Report だけを書く。
- **利用できないもの:** Markdown 出力、段階 3 (類似度) の照合、Git ref・URL・stdin・
  directory の入力。v1.1 の test の Python 3.11 / 3.13 と GitHub CI での実行は未確認であり、
  local の検証は Python 3.9 で行った。
- **一部の失敗 Code は Python の version で変わる。** 深さの上限を超える JSON Template は
  必ず失敗するが、その Python の JSON parser が止まる深さによって
  `template_depth_limit_exceeded` (exit 3) または `template_parse_failure` (exit 4) になる。
  どちらも fail-closed である。計測した深さは `docs/delta-schema.md` にある。symlink loop の
  入力 path は、どの Python version でも `invalid_arguments` (exit 2) になる。

## Roadmap

計画であって実装ではなく、現時点では利用できない。上記のどの節も以下のいずれにも依存して
いない。項目は目標とするリリースごとにまとめている。目標は意図であって確約ではなく、
リリース間で移動しうる。

**v0.8.0 で提供済み。** 本節が v0.1 時点で挙げていた security 強化と測定の項目は既に出荷
された。入力サイズ上限と YAML alias 展開の予算 (R-8)、descriptor ベースの TOCTOU 安全な
読み込み (R-2)、timeout 時の process group 終了 (R-9)、`stderr_head` の host path redaction
(R-4)。測定側では cfn-lint 貢献測定系列、Agent の N 回実行によるばらつき測定
(`--agent-runs`)、Remediation Accuracy と Human Intervention Count の診断、`agent-only` と
`human-review` モード。詳細は CHANGELOG.md と `docs/security-model.md` を参照。

**v0.9.0 で提供済み。** `stderr_head` の redaction を host path に加えてラベル付き process
identifier と認識可能な timestamp まで広げた (裸の rule id・行番号・version は保持) (R-4)。
Review Time は `--timing-report` で構造化 JSON として stderr に出力する。residual risk
R-1, R-5, R-6, R-7 は `docs/security-model.md` に確定した方針として整理した (未対応課題では
ない)。予約配列と診断期待フィールドを埋める benchmark 測定ケースを 2 件追加し、`agent-only`
/ `human-review` モードと 2 つの診断が宣言された期待値を測るようにした。詳細は CHANGELOG.md
と `docs/benchmark-methodology.md` を参照。

**v1.0.0 で提供済み。** CDK レビューの結果を report の `target.cdk.synthesis`
(`not_applicable` / `skipped_unconfirmed` / `ran`) で可視化し、synth skip を clean な
レビューと誤読しないようにした。Kiro Power の読み込みを Kiro 1.0.337 で検証し (5 つの Skill
すべてが読み込まれ、エントリポイントが実行される)、再現可能な手順と記録を
`docs/kiro-power.md` に整備した。最初の読み込みで 3 つの Skill を除外していた `SKILL.md` の
`description` 長超過は発見・修正済み。MCP は「実装しない opt-in の設計文書」として確定し、
stated かつ checkable なユースケースを待つ。`cdk synth` のゲートと非 sandbox の姿勢は不変。

### v0.10.0 -- IaC と分析の追加

- Terraform 対応。
- Pulumi 対応。
- Runtime security 分析。
- FinOps 分析。
- 完全な Well-Architected review。
- Web UI。

自動 deploy と自動 remediation は roadmap 項目ではなく恒久的な非目標である。この plugin は
報告し、行動しない。

### v1.0.0 以降 -- パッケージングと体験 (一部未了)

- 大きく新しい Kiro version で Power の読み込みを再確認すること。読み込みは Kiro 1.0.337 で
  検証済み (`docs/kiro-power.md`) だが、ある version で観測された読み込みはその version に
  ついての証拠なので、将来の version では記録済みの手順を繰り返すのが望ましい。
- stated かつ checkable なユースケースが出た時点で具体的な MCP server を実装すること。MCP は
  opt-in のままで、中核のレビュー flow の依存にはならない。
- v1.0.0 で追加した `target.cdk.synthesis` の可視化を超える CDK ソースレビュー体験の改善。

## Contributing

Contribution は Apache-2.0 の下で歓迎する。

出発点は `CONTRIBUTING.md` である。開発環境と前提ツールのバージョン、コーディング標準、
テストと benchmark を実行するコマンド、cfn-guard rule の追加方法、Skill の追加方法、
security 問題の報告方法、pull request に求められるものを扱っている。

Contributor 向けの案内。

| 問い | 文書 |
| --- | --- |
| レビューはどう動き、Agent ではなくコードが決めているのは何か | `docs/architecture.md` |
| この plugin は何を防ぎ、何を防がないのか | `docs/security-model.md` |
| Finding とは正確には何か | `docs/finding-schema.md` |
| Benchmark の数値は何を意味するのか | `docs/benchmark-methodology.md` と `benchmark/README.md` |
| Case はどう追加するのか | `benchmark/README.md` |
| これはどう Kiro Power として読み込まれるのか | `docs/kiro-power.md` |

Security 問題は public な issue ではなく非公開で報告してほしい。

なお、公開 OSS の主要文書は英語を基本とする方針であり、この日本語補足は英語版に追加
される形で置かれている。日本語の編集は英語版ではなくこのファイルに対して行うこと。

## License

Apache License 2.0。`plugin.json` は `"license": "Apache-2.0"` を宣言し、root の `LICENSE`
が全文を保持している。

`NOTICE` は project の copyright を記録し、レビュー実行が触れる第三者由来コンポーネント
すべてに帰属を与える。PyYAML、開発とテスト用パッケージ、subprocess として起動される
3 つの外部ツールである。いずれも同梱も再配布もしていないため、その節はこのパッケージが
果たす義務ではなく参考情報である。ソースファイルに license header は付いていない。
Apache-2.0 はそれを要求しない。

## Support

サポートは project の GitHub repository
[nobu-13/aws-iac-review-agent-plugin](https://github.com/nobu-13/aws-iac-review-agent-plugin)
を通じて提供する。

| 用途 | 場所 |
| --- | --- |
| Bug、質問、機能要望 | [Issue を開く](https://github.com/nobu-13/aws-iac-review-agent-plugin/issues) |
| Contribute したい変更 | [`CONTRIBUTING.md`](CONTRIBUTING.md) を参照 |
| Security または Privacy の脆弱性の疑い | public な issue ではなく repository の**非公開**報告 channel で報告する。[`CONTRIBUTING.md`](CONTRIBUTING.md#security-issue-handling) を参照 |

Issue を開く前に、影響を受ける version または commit、platform、挙動を引き起こす入力、
起きたこと、期待したことを含めてほしい。Credential や secret は issue に含めないこと。

## Privacy Policy

この plugin はローカルで read-only に動作する。個人データや telemetry を収集せず、
自身では AWS API も外部サービスも呼び出さず、workspace に何も保存せず、すべての子プロセス
から AWS credentials を秘匿する。host agent と optional な MCP の境界（データが plugin の
制御を離れうる箇所）を含む完全な記述は
[**`docs/privacy-policy.md`**](docs/privacy-policy.md) にある。
