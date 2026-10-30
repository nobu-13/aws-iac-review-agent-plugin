---
name: iac-remediation-verify
description: >-
  Verifies one candidate fix to a CloudFormation template against a
  human-approved remediation contract and reports VERIFIED, BLOCKED,
  UNVERIFIED or ERROR. The verdict comes from deterministic checks: the
  allowed file / Logical ID / property scope, cfn-lint, fixed cfn-guard rules
  for the purpose and the invariants, and the trusted contract revision. Use
  this skill when the user asks to fix a finding inside an approved contract
  (DynamoDB BillingMode and ProvisionedThroughput, or an over-broad IAM inline
  statement), to draft such a contract, or to check whether an edit stayed
  inside one. Do not use it to find issues in a template (use iac-review), to
  change several resources at once, or to deploy, merge, or call AWS. It never
  edits files and never approves its own contract. Requires git, cfn-lint
  1.46.0 and cfn-guard 3.2.1 on PATH.
---

# IaC Remediation Verify

## Purpose

Let an agent propose one small fix to a CloudFormation template and have that
fix judged by something other than the agent. The skill drives the Phase 1
verifier, `python3 -m iacreview.remediation`, in three steps:

1. `init` writes a DRAFT contract for a shipped profile. A draft is not an
   approval: a human commits it to the protected configuration branch.
2. The agent makes one candidate edit inside the contract's allowed edits.
3. `verify` checks the candidate and `explain` prints the result. The agent
   stops there and hands the result to the human.

The agent must not edit the contract, the profiles, the rules, the verifier or
CI files, and must not retry with a weaker contract. `VERIFIED` means the
listed checks passed for these exact revisions; it is not an approval to
merge or deploy, and runtime behaviour is never verified.

## When to use this skill

Use it when:

- the user asks to fix the DynamoDB billing-mode inconsistency
  (`dynamodb-billing-mode-v1`) or remove an over-broad IAM inline Allow
  statement while keeping a named statement (`iam-inline-policy-overbroad-v1`);
- the user asks for a remediation contract draft for one of those profiles;
- the user asks whether an edit stays inside an approved contract.

Do not use it for:

- finding problems in a template: use `iac-review`;
- linting or policy checks on their own: use `cfn-lint-review` or
  `cfn-guard-review`;
- changes that span several resources, CDK source, Terraform, or Pulumi;
- anything that creates, changes or deletes AWS resources, deploys, pushes,
  opens a pull request or merges.

## Input

Run every command from the repository root, with the plugin root on
`PYTHONPATH`:

```text
PYTHONPATH=<plugin_root> python3 -m iacreview.remediation init --list-profiles
PYTHONPATH=<plugin_root> python3 -m iacreview.remediation init \
    --profile dynamodb-billing-mode-v1 --template infra/template.yaml \
    --resource OrdersTable --output remediation-contract.draft.yaml
PYTHONPATH=<plugin_root> python3 -m iacreview.remediation verify \
    --base main --worktree \
    --config-rev main --contract .iac-remediation/contracts/billing-mode-orders.yaml \
    --output remediation-report.json --summary
PYTHONPATH=<plugin_root> python3 -m iacreview.remediation explain remediation-report.json
```

- `--base`: the revision the fix starts from (normally the protected branch).
- `--head REV` or `--worktree`: a commit, or the working tree as a preview.
  The preview hashes tracked and untracked files that are not ignored.
- `--config-rev` and `--contract`: the trusted revision and the contract path
  inside it. The contract is never read from Head or the working tree.
- `--contract-file`: a draft on disk. Preview only; the result is at most
  UNVERIFIED.

The iam profile also needs `--parameter required_statement_sid=<Sid>` for
`init`.

## Output

`verify` writes one Remediation_Verification_Report JSON document to stdout
and nothing else (or to `--output`). The human Summary goes to stderr with
`--summary`, or to stdout from `explain`. The report holds `payload` (the
deterministic verdict: `decision`, `task_outcome`, `next_action`,
`violations`, `diagnostics`, `outcomes`, `invariants`, `checks`, digests of
every input) and `metadata` (time, run id, payload digest). Template values,
tool output and untrusted keys are not written; untrusted keys and paths
appear as `k:` / `p:` plus 12 hex digits.

Exit codes of `verify`:

| Code | Decision | Meaning |
| --- | --- | --- |
| 0 | VERIFIED | inside the contract, purpose met, invariants held, checks passed |
| 20 | BLOCKED | a scope violation, the purpose not met, an invariant broken, or a failed check |
| 21 | UNVERIFIED | evidence missing: unapproved contract, stale revisions, tool missing, wrong version, timeout, skipped rule, incomplete comparison |
| 22 | ERROR | invalid command line or contract, or an internal failure |

`init` and `explain` return 0 on success (not a verdict) and 22 on invalid
input; `explain --check-binding` returns 21 for a stale report.

## Limitations

- One contract covers one existing Template and one Resource; Phase 1 ships
  two profiles only.
- Resource renames, Type changes, additions and deletions are never allowed.
- Transforms, conditions and dynamic references in an allowed property make
  the result UNVERIFIED; nested stacks are not evaluated.
- The worktree preview does not inspect ignored files or submodule contents
  and compares raw bytes without git filters.
- A local run is a preview of the gate: whoever controls the machine controls
  the verifier. Merge enforcement needs the protected CI gate.
- CPU and memory of cfn-lint and cfn-guard are not limited; each run has a
  60 second timeout and an 8 MiB output limit.

## Dependencies

- Python 3.9 or later with PyYAML, as for the rest of the plugin.
- git, cfn-lint 1.46.0 and cfn-guard 3.2.1 on PATH. They are external runtime
  dependencies, not bundled with the plugin. The skill does not install them;
  a missing or different version is reported as UNVERIFIED.
- No AWS credentials, network access or LLM are needed.
