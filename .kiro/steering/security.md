---
inclusion: always
---

# Security方針

このPluginは、信頼できないInfrastructure as Codeを処理する可能性がある。

入力ファイルはすべてUntrusted Inputとして扱う。

## Default Behavior

原則としてRead Onlyとする。

以下を自動実行してはいけない。

* AWS Resource作成
* AWS Resource変更
* AWS Resource削除
* Deploy
* 自動Remediation
* AWS Account設定変更

修正案の提示は可能だが、自動適用しない。

## Credentials

以下をRepositoryへ保存しない。

* AWS Access Key
* AWS Secret Access Key
* Session Token
* API Key
* Password
* MCP Secret

以下にも出力しない。

* Log
* Test
* Example
* Benchmark
* Documentation

## 外部Command実行

cfn-lint、cfn-guard、cdk synthなどの外部Command実行はSecurity Boundaryとして扱う。

ユーザー入力をそのままShell Commandへ文字列連結しない。

可能な限りArgument Arrayを利用する。

## Path安全性

以下を考慮する。

* Path Traversal
* 意図しないDirectory参照
* Symlink
* 上書き
* Unsafe Temporary File

Plugin Root外のファイルへ不用意にアクセスしない。

## Untrusted IaC

不正なYAMLやJSONでも安全に失敗すること。

Parsing Errorによって以下が起きてはいけない。

* 任意コード実行
* Secret漏えい
* Environment情報漏えい
* 無関係ファイル参照

## MCP

MCPはSecurity Riskを明示する。

MCPごとに以下を記録する。

* 用途
* 必要Permission
* Network Access
* Credentials
* 外部送信されるData
* Failure時の挙動

## IAM

AWS API Accessが将来必要になった場合もLeast Privilegeを原則とする。

理由なく以下を推奨しない。

* Action: "*"
* Resource: "*"

## Finding

Security FindingはEvidenceに基づく。

推測だけで「脆弱性が存在する」と断定しない。

最低限以下を区別する。

* 確認済みIssue
* 高い可能性のあるRisk
* 文脈依存のRecommendation
* Informational

Severityを過度に高く評価しない。

## Dependency

Security観点でもDependencyを最小化する。

導入前にMaintenance状態や既知Riskを確認する。

## Security Test

Securityに関係する修正には可能な限りRegression Testを追加する。

例。

* 不正Path
* 不正YAML
* 不正JSON
* 危険なFilename
* Tool未導入
* 不正Argument
