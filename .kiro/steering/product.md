---
inclusion: always
---

# プロダクト方針

## プロジェクト名

`aws-iac-review-agent-plugin`

## 目的

このプロジェクトは、AWS Infrastructure as Code をAI Agentからレビューするための、再利用可能なAgent Pluginを提供することを目的とする。

主な対象は以下。

* AWS CloudFormation
* AWS CDKから生成されたCloudFormation
* IAM Policy
* AWS設計上の基本的なベストプラクティス

このプロジェクトはKiro専用ツールではない。

Kiroを主要な開発・検証環境として利用するが、Agent Plugins仕様に準拠し、対応クライアントで再利用可能な構造を優先する。

## 解決したい課題

AWS IaCレビューでは、以下のような複数の観点を別々に確認する必要がある。

* 構文
* CloudFormation固有ルール
* セキュリティ
* IAM
* 暗号化
* Public Access
* Logging
* Backup
* Tagging
* AWS設計上の妥当性

従来は複数ツールや人手レビューを組み合わせる必要がある。

本プロジェクトでは、

**決定論的な静的解析ツールとAI Agentによる意味的レビューを統合する**

ことで、AWS IaCレビューの品質と再現性を高める。

## プロダクトコンセプト

本プロジェクトの中心コンセプトは、

**Agentic AWS IaC Quality Gate**

とする。

単なるLint Toolのラッパーにはしない。

以下を統合する。

* cfn-lint
* cfn-guard
* IAM Review
* AWS Best Practice Review
* Agentによる意味的レビュー
* 統一されたFinding
* 修正提案

## 主な利用者

想定利用者は以下。

* AWS Developer
* Cloud Engineer
* Platform Engineer
* DevOps Engineer
* Security Engineer
* Infrastructure Engineer
* AWSを利用するOSS Contributor

## v0.1で重視する価値

v0.1では機能数より以下を優先する。

1. 再利用可能であること
2. 安全であること
3. 検証可能であること
4. 結果を説明できること
5. 他の利用者が導入しやすいこと
6. Agent Plugins対応クライアントへ展開可能であること

## 非目標

v0.1では以下を目的としない。

* AWS環境への自動Deploy
* AWSリソースの自動修正
* Terraform対応
* Pulumi対応
* Runtime Security分析
* FinOps分析
* 完全なWell-Architected Review
* Web UI

対象外機能が有用でも、v0.1では無理に実装しない。

将来候補として整理する。
