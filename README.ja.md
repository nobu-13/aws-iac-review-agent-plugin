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
| 組織 policy のレビュー | 同梱の 35 個の `.guard` rule に対する cfn-guard。encryption / public access / logging / tagging / IAM / backup / availability / data protection を対象とする |
| 決定論的な IAM レビュー | wildcard 権限、権限昇格 action、無制限の `iam:PassRole` と `sts:AssumeRole`、confused deputy 条件の欠落、cross-account および wildcard principal を対象とする 15 個の detector |
| Agent による意味的レビュー | 2 つの Skill (`cloudformation-review`、`iam-review` の layer 2) が決定論的に抽出された事実を推論の入力とし、pipeline が検証してから統合する Finding を生成する |
| 正規化された 1 つのレポート | すべての Finding が同じ 13 フィールド、11 カテゴリのいずれか 1 つ、検出した source を持つ。等価な Finding は統合される。ID は決定論的に付与される |
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
 -> deterministic checks: cfn-lint, cfn-guard, IAM detectors
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
rules/               6 つのカテゴリディレクトリに置かれた 35 個の cfn-guard rule
benchmark/           測定対象の 12 case、ground truth、harness
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
> 実際の Kiro installation にこのパッケージを読み込ませ、5 つの Skill が host agent に
> 届くことを観測する作業は**行っていない**ため、install 手順は記載していない。Known
> Limitations に記録している。

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

Agent が生成した Finding をレポートへ統合する。

```sh
python3 skills/iac-review/scripts/run_iac_review.py \
  --target templates/app.yaml \
  --agent-findings agent-findings.json
```

`iac-review` の option は `--target` (必須、繰り返し可)、実行する決定論的 source を絞る
`--sources`、同梱 rule に自分の `.guard` rule を追加する `--rules-dir`、
`--agent-findings`、`--confirm-cdk-synth`、`--verbose` である。各 `SKILL.md` が自身の
option と出力を網羅的に記述している。

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

同梱の cfn-guard rule は 6 ディレクトリに 35 ファイル。

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

この repository の 12 case について、Python 3.9.6、cfn-lint 1.46.0、cfn-guard 3.2.1 での
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
| テストスイート | `python3 -m pytest`。3300 件超、失敗 0 |
| Unit | 決定論的モジュールを対象とする 34 ファイル。解析、正規化、severity 変換、重複排除、path 検証、exit code |
| Integration | 6 つの entry point を実際の subprocess として実テンプレートに対して動かす 13 ファイル。不正入力 133 件を含む |
| Negative | clean なテンプレートが、数え上げた種類の false positive を出さないこと |
| Regression | security 上の振る舞いと過去に見つけた defect を固定する 9 ファイル。path traversal、不正な YAML と JSON、shell metacharacter を含むファイル名、外部ツール未導入、不正な引数、symlink の循環、error に host path が出ないこと |
| Property | `hypothesis` により 31 個の named property を述べる 15 ファイル。独立した oracle に対する path containment の検証、および `iacreview.proc` が出荷コードで唯一のプロセス起動経路であることを示す AST 走査を含む |
| Coverage | `python3 -m pytest --cov=iacreview --cov=benchmark/harness --cov-fail-under=80` |
| Benchmark | `python3 benchmark/harness/run_benchmark.py --cases benchmark/cases --mode combined`。全カテゴリ `PASS` |

上記のコマンドはすべてこの repository に対して実行済みである。
`docs/security-model.md` には、各 security 上の主張とそれを固定するテストの対応表がある。

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
- **`errors[].stderr_head` は外部ツールの出力をそのまま持ち、host path を出さない保証の
  外にある。** plugin 自身が組み立てるメッセージはすべて workspace 相対で描画されるが、
  `stderr_head` は crash したツールから無改変でコピーした最大 5 行であり、ツールには
  絶対 path のテンプレートが渡されている。untrusted な外部テキストとして扱うこと。host
  path も、ツールが出力を選んだ何もかもが含まれうる。5 行の上限が縛るのは量であって内容
  ではない。レポートを生成したマシンより広く公開する前に、除去するか確認すること
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

- **同梱の cfn-guard rule は、名前を挙げた resource type だけを検査する。** 35 個の rule が
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
- **Kiro での Power 読み込みは未検証である。** Power の読み込みが前提とする構造的条件は
  機械的に検証されテストで固定されているが、実際の Kiro installation にこのパッケージを
  読み込ませておらず、host agent が 5 つの Skill を列挙する様子も観測していない。Kiro で
  Skill が discoverable であるという主張は観測ではなく構造的な議論に基づく。だから
  `docs/kiro-power.md` は install 手順を記載していない。Requirement 10 AC7 は一部未達の
  ままである。

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
  `Informational` として現れる。cfn-guard、IAM Review、Agent Review の各 Source は、この
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

## Roadmap

計画であって実装ではなく、v0.1 では利用できない。上記のどの節も以下のいずれにも依存して
いない。

**IaC と分析の追加**

- Terraform 対応。
- Pulumi 対応。
- Runtime security 分析。
- FinOps 分析。
- 完全な Well-Architected review。
- Web UI。

自動 deploy と自動 remediation は roadmap 項目ではなく恒久的な非目標である。この plugin は
報告し、行動しない。

**Security 強化**

- 入力サイズ上限と YAML alias 展開の予算。あわせて可搬な resource limit のテスト手法
  (`docs/security-model.md`、R-8)。
- containment 検査と読み込みの間の TOCTOU window を閉じる、descriptor ベースのファイル
  アクセス (R-2)。
- timeout がツールの子孫プロセスも回収するための process group 終了 (R-9)。
- `stderr_head` の整理。実装が両方を満たすには、2 つの requirement を互いに突き合わせて
  解決する必要がある (R-4)。

**測定**

- case を install された rule catalogue に結び付けずに cfn-lint の benchmark 貢献を測る方法。
  宣言された cfn-lint バージョンに pin した別系列の case を、閾値ではなく参考値として評価
  する。
- 各 case について Agent を N 回動かし、点推定ではなくばらつきを報告することで、精度と
  あわせて Agent の安定性も測る。
- 先送りした 3 つの benchmark 指標 (Review Time、Remediation Accuracy、Human Intervention
  Count)。`docs/benchmark-methodology.md` で定義済みで、実装に ground truth 形式の変更は
  不要である。
- benchmark の `agent-only` と `human-review` モード。ground truth 形式は既にフィールドを
  予約しており、v0.1 では常に空である。

**パッケージングと体験**

- 実際の installation で Kiro Power の読み込みを検証すること。Requirement 10 AC7 が残して
  いる課題である。
- MCP enhancement。server が plugin にできないことを行う場合に限る。MCP は opt-in の
  ままで、中核のレビュー flow の依存にはならない。
- `cdk synth` の後にテンプレートをレビューするより良い CDK ソースレビュー体験。

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
