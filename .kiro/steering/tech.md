---
inclusion: always
---

# 技術方針

## 基本方針

実装技術は、単純性、可搬性、安全性、テスト容易性を優先して選択する。

不要なFrameworkや依存関係を追加しない。

## 基本構成

主な構成要素は以下を想定する。

* Agent Plugins 1.0.0
* Kiro
* Skills
* MCP
* Python
* Shell Script
* cfn-lint
* cfn-guard
* AWS CDK
* CloudFormation

ただし、すべてを必須依存にはしない。

## Python

複雑な処理や構造化データ処理にはPythonを優先する。

利用候補。

* JSON解析
* YAML解析
* Finding正規化
* 外部コマンド実行
* Benchmark集計
* Test
* 入力検証

Pythonコードでは以下を優先する。

* 小さな関数
* 明示的な型
* 予測可能な戻り値
* 明確な例外処理
* テスト可能な構造

## Shell Script

Shell Scriptは単純な補助処理に限定する。

複雑な条件分岐やデータ処理をShellに持たせない。

ユーザー入力を文字列連結してコマンド実行してはいけない。

## cfn-lint

CloudFormationの構文、Resource Specification、既知ルールに関する検証は、可能な限りcfn-lintを利用する。

AI Agentにcfn-lintと同じ判定を再実装させない。

## cfn-guard

組織ポリシーや明示的なInfrastructure Policyの検証にはcfn-guardを利用する。

ルールは再利用可能な形で管理する。

## AWS CDK

v0.1ではCDK Sourceそのものを完全解析しない。

原則として以下の流れを採用する。

CDK Source
→ cdk synth
→ CloudFormation Template
→ Review

## MCP

MCPは基本機能の必須依存にしない。

MCPなしでも最低限以下が動作することを優先する。

* cfn-lint
* cfn-guard
* IAM Review
* Agent Review

MCPを導入する場合は、明確な利用価値が必要。

## Dependency

Dependencyを追加する前に以下を確認する。

1. 標準機能では実現できないか
2. 本当に必要か
3. 保守されているか
4. Security Riskはないか
5. 可搬性を損なわないか

数行のコード削減だけを目的にDependencyを追加しない。
