---
inclusion: fileMatch
fileMatchPattern: "{tests/**/*,benchmark/**/*,skills/**/scripts/**/*}"
---

# Test方針

このプロジェクトでは、動作確認だけでなく再現可能な評価を重視する。

## Testの種類

最低限以下を区別する。

### Unit Test

小さな関数やParserなどを検証する。

対象例。

* Finding変換
* Severity変換
* JSON解析
* Path Validation
* Command Result Parsing

### Integration Test

実際のSample IaCをReview Flowへ入力し、期待結果を確認する。

### Negative Test

正常なIaCに過剰なFindingを出さないことを確認する。

### Regression Test

過去に発見したBugは可能な限りTest化する。

### Tool Unavailable Test

以下が未導入の場合も安全に失敗すること。

* cfn-lint
* cfn-guard
* AWS CDK

## Benchmark

BenchmarkはTestとは別目的とする。

BenchmarkではReview性能を評価する。

主な指標候補。

* Detection Rate
* Precision
* Recall
* False Positive
* False Negative
* Severity Accuracy
* Review Time
* Remediation Accuracy
* Human Intervention Count

## Ground Truth

Benchmark Caseには期待結果を明示する。

例。

```text
case-001

Expected Findings:
- HIGH: Public S3 Bucket
- MEDIUM: Encryption not configured
```

Ground TruthをReview結果から逆算して作らない。

先に期待値を定義する。

## Testデータ

Test Dataは以下を分離する。

* 正常系
* 異常系
* Security Issue
* Parser Error
* Tool Error

## Determinism

決定論的部分のTestは同じInputから同じOutputを得られることを優先する。

Agent Reasoningの評価では、文字列完全一致ではなく構造化された評価基準を利用する。

## Test失敗時

Testを通すためだけにRequirementを弱めない。

原因を確認して以下を判断する。

* Implementation Bug
* Test Bug
* Requirement不足
* Agent非決定性
* Tool差異

理由を明確にして修正する。
