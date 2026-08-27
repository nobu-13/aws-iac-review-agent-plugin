---
inclusion: always
---

# Repository構成方針

Repositoryは、初見の利用者やContributorが理解しやすい構造を維持する。

## 基本構成

以下を基本構造とする。

```text
aws-iac-review-agent-plugin/
├── plugin.json
├── mcp.json
├── skills/
├── rules/
├── benchmark/
├── examples/
├── tests/
├── docs/
├── .kiro/
│   └── steering/
├── README.md
├── CONTRIBUTING.md
├── CHANGELOG.md
└── LICENSE
```

## skills

Agent PluginのSkillを格納する。

Skillは責務ごとに分離する。

候補。

* cloudformation-review
* cfn-lint-review
* cfn-guard-review
* iam-review
* iac-review

巨大な単一Skillを作らない。

## rules

cfn-guardなどの再利用可能なPolicy Ruleを配置する。

例。

```text
rules/
├── encryption/
├── iam/
├── logging/
├── public-access/
├── backup/
└── tagging/
```

## benchmark

意図的に問題を含んだIaCとGround Truthを配置する。

Benchmark用ファイルと通常Exampleを混在させない。

## examples

利用者向けの正常系Sampleを配置する。

Exampleは可能な限り小さく理解しやすくする。

## tests

Unit Test、Integration Test、Regression Testを配置する。

BenchmarkそのものとTestを混同しない。

## docs

READMEに収まらない詳細設計や仕様を格納する。

例。

* Architecture
* Security Model
* Benchmark Methodology
* Finding Schema

## ファイル配置原則

役割が不明確なファイルをRepository Rootに増やさない。

同じ種類のファイルはまとめる。

一時ファイルや生成物をCommitしない。

Kiro固有ファイルは`.kiro/`配下に分離する。
