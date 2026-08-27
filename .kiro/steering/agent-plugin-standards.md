---
inclusion: fileMatch
fileMatchPattern: "{plugin.json,mcp.json,skills/**/*}"
---

# Agent Plugin開発標準

本RepositoryはAgent Plugins 1.0.0への準拠を基本方針とする。

Kiroは主要な検証環境だが、Kiro固有仕様をportable coreへ不用意に混在させない。

## Portable Core

常に以下を区別する。

1. Agent Plugins共通機能
2. Kiro固有機能

両方で実現可能な場合はAgent Plugins共通機能を優先する。

## plugin.json

`plugin.json`はPluginのPublic Interfaceとして扱う。

変更時は以下を確認する。

* 必須Field
* Path
* Compatibility
* Breaking Change
* Documentation

Plugin Root外を参照しない。

## Skills

Skillは責務単位で分離する。

各Skillには以下を明確にする。

* 何をするSkillか
* いつ利用するか
* Input
* Output
* Limitation
* Dependency

同一処理を複数Skillへ重複実装しない。

## scripts

Skill内のScriptは決定論的処理を担当する。

Agentの判断をScriptへ埋め込まない。

Scriptは以下を満たす。

* Argument Validation
* 明確なExit Code
* 予測可能なOutput
* 非対話実行
* Tool未導入時の明確なError
* 安全なPath処理

可能であればMachine Readable Outputを優先する。

## MCP

MCPをCore Featureの必須依存にしない。

MCP利用時は以下を明示する。

* 利用目的
* 必要性
* Security Risk
* Failure時のFallback
* 必要Permission

## Kiro

KiroではPowerとして利用できることを検証する。

ただしKiroの都合だけでportableな構造を変更しない。

Kiro固有設定が必要な場合は分離する。

## Specificationが曖昧な場合

仕様を推測して勝手に実装しない。

以下を行う。

1. 曖昧な点を明示する
2. 最も保守的な実装を選択する
3. Assumptionとして記録する
4. 必要ならUpstream Issue候補として残す

Agent Plugins仕様上の不足を発見した場合は、OSS Contribution候補として記録する。
