---
inclusion: always
---

# 開発原則

## 基本原則

このRepositoryを設計、実装、修正するときは、以下を常に守る。

1. 単純な設計を優先する
2. Agent Pluginsとしての可搬性を優先する
3. Security by Defaultとする
4. 決定論的処理とAgent判断を分離する
5. Findingは説明可能にする
6. 検証結果を再現可能にする
7. Test可能な構造にする
8. 不要なDependencyを増やさない
9. 過度な抽象化を避ける
10. Communityが再利用できる品質を維持する

## Agentにすべて判断させない

既存ツールで確実に判定できるものは、既存ツールを利用する。

### 決定論的な処理

以下は可能な限りToolで処理する。

* 構文解析
* cfn-lint
* cfn-guard
* JSON / YAML解析
* Known Rule
* 入力検証

### Agentによる処理

以下はAgent Reasoningを利用してよい。

* IAMの文脈的評価
* 複数Resource間の関係
* Architecture Risk
* AWS Best Practice
* Severityの文脈評価
* 修正理由の説明

## 想定Review Flow

```text
IaC
 ↓
決定論的チェック
 ├─ cfn-lint
 └─ cfn-guard
 ↓
Agent Semantic Review
 ├─ IAM
 ├─ Security
 ├─ Architecture
 └─ AWS Best Practices
 ↓
Finding正規化
 ↓
Review Report
```

## Scope管理

v0.1の範囲を不用意に広げない。

便利そうという理由だけで新機能を追加しない。

Scope外の機能はRoadmapまたはIssue候補として記録する。

## 実装完了の定義

コードを生成しただけでは完了としない。

以下を満たした場合に完了とする。

* Requirementを満たす
* Acceptance Criteriaを満たす
* Testが存在する
* Testが成功する
* Error Handlingがある
* Security影響を確認している
* 必要なDocumentationを更新している
* 無関係な変更を含まない

## Architecture変更

大きな設計変更を行う前に以下を確認する。

1. どのRequirementを解決する変更か
2. 現在のArchitectureでは対応できないか
3. Portabilityへの影響
4. Securityへの影響
5. Testへの影響
6. Documentationへの影響

理由なくArchitectureを変更しない。

## OSS品質

第三者が読むことを前提にコードを書く。

以下を優先する。

* 明確な名前
* 小さな関数
* 単一責務
* 明示的なError
* コメントより読みやすいコード
* 再現可能なTest

隠れた前提やMagic Valueを避ける。
