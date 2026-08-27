---
inclusion: fileMatch
fileMatchPattern: "{README.md,CONTRIBUTING.md,CHANGELOG.md,docs/**/*}"
---

# Documentation方針

このRepositoryはOSSとして第三者が利用することを前提とする。

Documentationは実装の補足ではなく、成果物の一部として扱う。

## README

READMEだけを読んでも最低限以下が理解できるようにする。

* 何のProjectか
* なぜ必要か
* 何ができるか
* 対応IaC
* Architecture
* Requirements
* Installation
* Kiroでの利用方法
* Usage
* Review Categories
* Example
* Benchmark
* Security
* Known Limitations
* Roadmap
* Contributing

## 技術的に正確な記述

実装されていない機能を「利用可能」と記載しない。

将来機能はRoadmapとして明確に分離する。

## Example

Exampleは実際に動作する内容を優先する。

不要に複雑なExampleを作らない。

## Security Documentation

以下を明記する。

* DefaultがRead Onlyであること
* AWS Credentialsの扱い
* MCP利用時のSecurity Boundary
* 自動Remediationを行わないこと
* Untrusted IaCを扱う設計であること

## Known Limitations

制約や未対応事項を隠さない。

以下は積極的に記録する。

* 未対応IaC
* Context依存のFinding
* False Positiveの可能性
* Agent Client間の差異
* Tool Version差異

## CHANGELOG

利用者に影響する変更を記録する。

特に以下。

* Breaking Change
* Finding Schema変更
* Skill変更
* Dependency変更
* Security Fix

## CONTRIBUTING

Contributorが以下を理解できるようにする。

* 開発環境
* Test方法
* Directory構成
* Pull Request方針
* Rule追加方法
* Skill追加方法
* Security Issueの扱い

## 英語と日本語

Kiro内部で利用するSteeringは日本語を使用してよい。

公開OSSの主要Documentationは、海外Communityへの再利用性を考慮して英語を基本とする。

必要に応じて日本語補足を用意する。
