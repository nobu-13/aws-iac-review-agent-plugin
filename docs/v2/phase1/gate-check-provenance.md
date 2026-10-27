# Trusted gate: check provenance finding and decision request

Status: **decision needed (Human)**. Found in the owner run of the demo gate
(`nobu-13/iac-remediation-gate-demo`, ruleset 25921565, validator
`5412a73`). No workflow, ruleset or permission was changed.

## What the owner run showed

Seven PRs (G1–G6, G10) each got one run of the base gate
(`pull_request_target`, `.github/workflows/remediation-gate.yml`). In every run
the log shows the base commit `786425b` checked out as the subject, validator
`5412a73` checked out, the trusted contract path, `HEAD_SHA` equal to the PR
head, and token permissions `Contents: read`, `Metadata: read` only — so the
base gate ran, including for G10, whose PR edits the gate to ask for write
permissions and a relaxed contract. The verify step succeeded for G1 and
failed for the other six, as expected.

| | G1 | G2 | G3 | G4 | G5 | G6 | G10 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| PR head | `c338cea` | `0f069f9` | `2447973` | `df14c9a` | `01fead5` | `d842070` | `d947851` |
| gate run (event `pull_request_target`) | 40423120048 | 40423126734 | 40423134747 | 40423145317 | 40423152992 | 40423161420 | 40423170996 |
| run `head_sha` | = PR head | = PR head | = PR head | = PR head | = PR head | = PR head | = PR head |
| verify step | success | failure | failure | failure | failure | failure | failure |
| `verify` check runs on the PR head (app `github-actions`, id 15368) | success | failure | failure **and success** | failure | failure | failure **and skipped** | failure |
| merge state / review | BLOCKED / REVIEW_REQUIRED (all seven) | | | | | | |

## Root cause of the seven FAILED results (Evidence Helper)

The helper required the gate run's `head_sha` to differ from the PR head, on
the assumption that a `pull_request_target` run is recorded on the base
commit. GitHub records the run and its check runs on the **PR head**; since
GitHub's change of 2025-12-08 the workflow file and `GITHUB_SHA` come from the
default branch ([changelog](https://github.blog/changelog/2025-11-07-actions-pull_request_target-and-environment-branch-protections-changes/)).
The run SHA is therefore not a provenance signal, and its equality with the PR
head is what lets the gate's check apply to the PR at all. That single
condition was false in all seven runs; every other condition held. The
product's gate behaved as designed; the helper's rule was wrong.

The helper now checks provenance condition by condition (event, workflow
path, run recorded on the PR head, base checked out as subject, validator
pinned and checked out, `HEAD_SHA` = PR head, trusted contract only, token
permissions read-only), links each `verify` check run to the workflow run
that produced it through its check suite, and reports gate, check and
enforcement separately. Re-applied offline to the saved evidence: gate
PROVEN for all seven; check NOT_PROVEN (the saved evidence has no check
suite ids yet); enforcement FAILED for G3 and G6.

## Product finding: the required check can be produced by an untrusted run

In G3 and G6 a workflow added by the PR (`on: pull_request`, job `verify`,
workflow name `remediation-gate`) produced a second check named `verify` from
the same app, GitHub Actions (15368), on the same PR head: `success` in G3,
`skipped` in G6. The status rollup lists both, with the same workflow name.
The ruleset's required check is identified by context `verify` and
integration 15368, which both runs satisfy. Work package §9.1 rules this out
as provenance ("checkの名前・GitHub Actions Appから発行の一致だけをWorkflow来歴の証明にしない").

What is and is not known:

* Known: an untrusted PR workflow can produce a check that matches the
  required check's name and app, next to the gate's failing one.
* Not known: which of the two GitHub uses for the merge decision. Every PR
  was BLOCKED, but code-owner review was also missing, so the merge state
  proves nothing about the check (and a merge attempt is not approved).
* Mitigation already in place, not a fix: a spoof needs a workflow file in
  the PR, which (a) makes the real gate fail (out-of-scope file) and (b) needs
  code-owner review (`CODEOWNERS` covers `.github/`). The merge then depends on
  a human reviewer noticing, not on the gate.

Hence G-P1-4 cannot pass with the current reference configuration, whatever a
second account would show.

## Options (each changes workflow, permissions or ruleset → Human decision)

### Option A — GitHub App check run (recommended for a personal repository)

Spike (prototype, threat model, setup cost, recommendation):
[spike-app-publisher.md](spike-app-publisher.md). The spike refines the
names below to check `remediation-gate/verified` and environment
`remediation-publisher`.

| | Before | After |
| --- | --- | --- |
| Who decides | gate job (base workflow, `contents: read`) | unchanged |
| Who publishes the required check | GitHub Actions, as the job's own check run `verify` (app 15368) | a second job in the same base workflow, `needs: verify`, creates check run `remediation-gate` on the PR head SHA with a GitHub App installation token |
| Required check in the ruleset | `verify`, integration 15368 | `remediation-gate`, integration = the App's id |
| Can a PR workflow produce it? | yes (any job named `verify`) | only with the App's private key |
| Where the key lives | — | an environment secret of environment `remediation-gate` whose deployment branches are the default branch only. Per the 2025-12-08 change, `pull_request` jobs evaluate environment rules against `refs/pull/<n>/merge` and cannot use it; `pull_request_target` evaluates against the default branch |
| PR code executed | none | none (the publisher reads only the verify job's outputs) |
| New permissions | — | App with `checks: write` only, installed on the demo repository; the workflow's `GITHUB_TOKEN` stays `contents: read` |

Needs: create and install the App, an environment with a branch policy and
the secret, a workflow change (publisher job), and a ruleset change (required
check source). Each is a Human action in H-ENV; nothing here is a new
Python dependency. The publisher must set the check's conclusion from the
verify job's result only, and must fail closed when that result is missing.

### Option B — organization ruleset "Require workflows to pass"

Move the demo repository to an organization and require
`.github/workflows/remediation-gate.yml` from a pinned repository and ref.
The requirement is then bound to the workflow file, not to a check name.
Availability depends on the organization's plan (**not verified**), and it
does not work for a personal-account repository.

### Option C — keep the current configuration and document the limit

No change. The reference gate is documented as "decides correctly, but its
check can be imitated by a PR workflow; merge enforcement relies on
code-owner review of workflow changes". G-P1-4 stays NOT VERIFIED and AC27
FAILED (check-name spoof), and Phase 1 cannot reach READY_FOR_PHASE2 on CI
enforcement.

Not options: removing `pull_request` workflows from the repository (a PR
can add one), naming the check something unusual (a PR can copy the name),
or trusting the rollup's workflow name (also copied, as G3 shows).

## What does not change in any option

The verifier, the contract, the profiles and their rules, and the base-only
checkout of the gate. The gate continues to read the PR head as git objects
only, never runs PR code, and keeps `contents: read`.
