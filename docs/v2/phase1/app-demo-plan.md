# Option A on a new synthetic demo repository: plan, evidence, rollback

Status: **planned, nothing on GitHub created or changed**. Supersedes the
in-place plan of [spike-app-publisher.md](spike-app-publisher.md) §7, which
would have disabled the legacy ruleset.

## 1. Decisions (Human)

1. Option A is an optional reference implementation.
2. The verifier stays at validator `5412a73`.
3. The H-ENV baseline stays at `a24fb3f`; its trust conditions are not relaxed.
4. The App publisher's commit is a separate pin.
5. The legacy demo's ruleset `25921565` is neither disabled nor changed.
6. The legacy demo's `main` (`786425b`) is not changed.
7. The App private key is never stored under git.

So the App gate is tested on a **new** public repository whose first commit
already contains the App workflow. The legacy demo is only read.

## 2. Pins

| Target | Value | Checked by |
| --- | --- | --- |
| Validator (verifier code run by the gate) | `5412a73` | fixed in the helper and in the App workflow (`VALIDATOR_COMMIT`) |
| H-ENV baseline (legacy demo runs) | `a24fb3f`, validator `5412a73` | the helper stops if `henv-targets.json` changes |
| Gate scripts (`gate_outputs.py`, `publish_check.py`, workflow template) | `f77a58c` on its own branch `phase1/app-gate-scripts` | blob ids of the three files recorded in `appdemo-targets.json`; the commit must descend from `5412a73` and change only `docs/` and `tests/` after it; no `.agents/` / `.kiro/` in its tree |
| Legacy demo | `nobu-13/iac-remediation-gate-demo`, ruleset `25921565`, `main` `786425b` | every command naming it is refused; the legacy owner-preflight (read-only) runs before every changing step |

PR #8's branch is not moved: the gate scripts are pushed to a new branch.

## 3. Initialization order

```text
local        app-targets → app-prepare → app-simulate          (no network)
plugin repo  app-push-scripts        new branch phase1/app-gate-scripts @ f77a58c
GitHub UI    register the App (no repository needed yet), generate one key outside git
new repo     app-publish             public repo + main (App workflow included)   ── W0 starts
GitHub UI    install the App on the new repository only
read-only    app-verify-installation (App JWT) or app-attest-installation (UI check)
new repo     app-environment         remediation-publisher: main only, no admin bypass
new repo     app-secrets             environment secret (stdin) + 2 repository variables
GitHub UI    Actions policy          allow pull_request_target for the gate file only
new repo     app-bootstrap           g0-bootstrap + g9-probe PRs → first App check
new repo     app-protect             ruleset: required check from the App           ── W0 ends
new repo     app-scenarios           G1–G6, G3S, G10 PRs
new repo     app-push-update         G7
new repo     app-steal               G11 (last)
read-only    app-evidence            after each of the last four
```

Why this order:

* The App's settings do not depend on the repository; installing does.
* The environment, the secret and the variables must exist before the first
  PR, or the bootstrap gate run cannot publish.
* The Actions policy must exist before the first PR: a repository created
  after the 2026-09-17 GA may not get the evaluate-mode grace period (not
  verified), and the gate must not depend on it.
* The ruleset comes last because its expected source needs an App that "must
  have recently submitted a check run" (GitHub documentation). The bootstrap
  PR produces that check through the real gate; no check is posted by hand.

### Verifying the installation

gh's token (an OAuth token of the GitHub CLI) cannot read App installations:
`GET /user/installations` needs a GitHub App *user access token*, and
`GET /repos/{owner}/{repo}/installation` and `GET /app/installations` need
the App's JWT. The helper therefore checks with gh only what gh can read —
the App's public description (`GET /apps/{slug}`: id, owner, permissions,
events) — and requires one of two installation records, no older than 24 h,
before any setting is changed:

* `app-verify-installation --app-key <pem>` (method `app_jwt`): signs a
  9-minute JWT with the system `openssl` (the key is read only by openssl),
  reads `GET /app` and `GET /app/installations`, mints a 1-hour installation
  token restricted to `metadata: read`, lists `GET /installation/repositories`
  and revokes the token (`DELETE /installation/token`). It requires exactly one
  installation, on the owner, `repository_selection: selected`, the demo as
  the only repository, the three permissions, no events, not suspended.
* `app-attest-installation` (method `human_attested`): the Human checks the
  installation page in the UI against a fixed checklist and types the
  repository name. Recorded as attested, not as an API verification; the
  bootstrap App check later corroborates it.

An App installable "only on this account" is private, so `GET /apps/{slug}`
answers 404. Only then may the JWT record stand in for the App's identity: the
record carries what `GET /app` returned with the App's own JWT (id, slug,
owner, permissions, events), and these are checked like the public answer.
When the public endpoint does answer, both must agree. Any other status stops.

The JWT record (`record_version` 2) is accepted only if all of these hold;
otherwise every step fails closed:

* exact key set, `problems: []`, the five calls with 200 / 200 / 201 / 200 / 204;
* `verified_at` within the last 24 h and not in the future (5 min skew);
* App identity, installation (selected, demo only, three permissions, no
  events, not suspended) as planned;
* sealed: SHA-256 of the canonical body, an RS256 signature over it made with
  the key GitHub accepted in the same run, and the key's public half;
* the key's fingerprint (`base64(SHA-256(public key DER))`, GitHub's documented
  format) equals `app_key_fingerprint` in the targets, which the Human copies
  from App settings → Credentials → Key pairs. A record edited after sealing,
  re-signed with another key, or carrying a swapped key is rejected.

Without a record every step stops (dry runs list it as a blocker and exit
WAITING_HUMAN). Every gh call is logged as method, endpoint and HTTP status
(`app-api-calls.json`, `app-state.json`); gh's error line is kept with tokens,
JWTs and key blocks redacted. A 404 means "absent"; any other failure stops
with the call that failed.

## 4. Bootstrap

`app-bootstrap` opens two PRs while no ruleset exists:

* **G0 `g0-bootstrap`**: the correct fix. The base gate runs, the publisher
  posts `remediation-gate/verified` = success. This is the App's first check
  run and proves the App/environment/secret chain end to end before any
  protection depends on it.
* **G9 `g9-probe`**: IAM widened. The App posts failure, and the PR is still
  mergeable, because nothing requires the check yet. After `app-protect` the
  same PR is BLOCKED. This gives G9 ("without the required check the violating
  PR becomes mergeable") without changing any ruleset.

`app-protect` then:

1. requires a completed App check on the G0 head no older than
   `bootstrap_max_age_minutes` (60);
2. records G0 and G9's merge state and `isRequired` while unprotected
   (`app-w0-views.json`), and stops if G9 is not MERGEABLE;
3. creates the ruleset with `integration_id` = the App id in one call and
   reads it back. Any difference stops the step with the rollback.

If GitHub rejects `integration_id` in the create call (not verified), the
step stops. A two-step fallback (create with any source, then set the App)
would open a window in which any same-named check satisfies the rule; it
needs its own approval and is not automated.

## 5. Unprotected period W0

W0 runs from `app-publish` (main pushed) to `app-protect` (ruleset active).
Target: under 60 minutes. During W0, `main` has no protection and only the
owner has write access.

Do not, during W0:

* merge any PR (including G0, which is mergeable), or push to `main`;
* push branches other than `g0-bootstrap` and `g9-probe`, or open other PRs;
* add collaborators, deploy keys, webhooks, other Apps or repository-level secrets;
* change the workflow, the environment, the variables or the App's permissions;
* approve workflow runs of fork PRs (public repository: anyone may open one);
* create the ruleset by any route other than `app-protect`.

`app-state` measures W0 from the repository's `created_at` and reports the
elapsed minutes. Abort conditions (every step stops, `W0 abort: …`):

* W0 open longer than 120 minutes (warning after 60). The Human either
  archives the repository and starts over with a new name, or decides to
  continue with `--w0-extend-to <minutes>` (≤ 1440, recorded in
  `app-state.json`);
* a merged PR, a moved `main`, repository-level secrets, or extra rulesets;
* branches other than `main`, `g0-bootstrap`, `g9-probe`;
* collaborators other than the owner, deploy keys, or webhooks;
* open PRs from this repository other than G0 / G9.

Open fork PRs are a warning (do not approve their workflow runs). The legacy
demo is unaffected either way.

## 6. Scenarios and expected results (fixed before any run)

The App demo ruleset requires a PR but **no approval**, so with one account a
BLOCKED merge state can only come from the required check. Nothing is ever
merged; G1's CLEAN state is read, not used.

| ID | Branch | Change | App check | Merge state | Impostors |
| --- | --- | --- | --- | --- | --- |
| G0 | g0-bootstrap | correct fix (W0) | success | mergeable | — |
| G9 | g9-probe | IAM widened, opened in W0 | failure | MERGEABLE in W0, BLOCKED after | — |
| G1 | g1-correct-fix | correct fix | success, required | CLEAN | — |
| G2 | g2-iam-widened | IAM widened | failure, required | BLOCKED | — |
| G3 | g3-check-spoof | PR workflow with passing jobs `verify` and `remediation-gate/verified` | failure | BLOCKED | Actions checks of the same name, **not required** |
| G3S | g3s-status-spoof | PR workflow sets commit status `remediation-gate/verified` = success with `GITHUB_TOKEN` | failure | BLOCKED | status of the same name, **not required** |
| G4 | g4-fake-report | forged VERIFIED report file | failure | BLOCKED | — |
| G5 | g5-contract-relaxed | contract relaxed in the PR + KeySchema change | failure | BLOCKED | — |
| G6 | g6-skip-spoof | skipped job named `remediation-gate/verified` | failure | BLOCKED | skipped Actions check, **not required** |
| G7 | g1 + one commit | IAM widened after G1 succeeded | failure on the new head; old head keeps success | BLOCKED | — |
| G10 | g10-gate-edited | PR edits the gate (relaxed contract, write permissions, publisher replaced) | failure (the base gate runs) | BLOCKED | — |
| G11 | g11-publisher-steal | PR workflow on `pull_request` and `push` asks for `remediation-publisher` and tries to post an App success | failure | BLOCKED | every `steal.yml` job refused before any step |
| G8 | — | base moved | NOT_PROVEN: needs a merge | | |

`app-simulate` runs the pinned gate offline (validator `5412a73`,
`gate_outputs.py` and the publisher's decision from `f77a58c`) on every
prepared head, with the same report hand-off as the workflow (`verify
--output <dir>/remediation-report.json`, then `gate_outputs.py` reads that
file). A scenario passes only if the verifier wrote a decision report,
`gate_outputs.py` accepted it, the decision is the expected one **and** the
report carries the expected cause codes (below). A failure caused by a
missing or refused report is the gate failing closed, not the scenario's
evidence, and fails the simulation.

| ID | Decision | Cause codes required |
| --- | --- | --- |
| G0, G1 | VERIFIED | none (any code fails) |
| G2, G9 | BLOCKED | `template_change_outside_scope` (IAM edit) |
| G3, G3S, G6, G11 | BLOCKED | `file_added_outside_scope` (PR workflow file) |
| G4 | BLOCKED | `file_added_outside_scope`, `template_change_outside_scope` |
| G5 | BLOCKED | `file_modified_outside_scope` and one of `template_change_outside_scope` / `operation_not_allowed` / `parent_replaced` |
| G10 | BLOCKED | `file_modified_outside_scope`, `file_added_outside_scope`, `template_change_outside_scope` |

Before running, it checks that the interpreter imports PyYAML 6.0.3 and that
cfn-lint 1.46.0 and cfn-guard are on PATH (the workflow's pins); otherwise it
stops without simulating. Every step that pushes (`app-push-scripts`,
`app-publish`, `app-bootstrap`, `app-scenarios`, `app-push-update`,
`app-steal`) refuses unless the saved result passed for all scenarios with
the same validator, gate-scripts pin, demo `main` and scenario heads. The
simulation runs the verifier on the local Python (3.9 here); the workflow uses
3.11 — a difference the GitHub run covers.

## 7. Evidence

Per scenario, `app-evidence` stores raw API data and classifies four parts.
A scenario is PROVEN only if every part is PROVEN; any FAILED part makes it
FAILED.

| Part | PROVEN when | Source |
| --- | --- | --- |
| gate | the run is the base gate: event `pull_request_target`, gate path, recorded on the PR head, base checked out, validator `5412a73` and gate scripts `f77a58c` checked out, `HEAD_SHA` = PR head, trusted contract only, token `Contents: read, Metadata: read`; verify step as expected | Actions run, per-job logs |
| app_check | exactly one check named `remediation-gate/verified` from the App on the head; `external_id` `<run>.<attempt>:<digest>` names that gate run; the downloaded report's recomputed digest equals it; conclusion as expected | Checks API, report artifact |
| required | every same-named check run or status **not** from the App has `isRequired = false`; the App's check has `isRequired = true`; merge state as expected | GraphQL `isRequired(pullRequestNumber:)`, `mergeStateStatus` |
| steal (G11) | every `steal.yml` run concluded and no job executed any step; every App check on the head names a gate run | Actions runs and jobs |

What shows that a fake check cannot satisfy the required check:

* **Same name, other source** (G3, G3S, G6): the impostor exists on the head
  with `isRequired = false`, the App's check is the required one, and the
  merge state is BLOCKED. If GitHub reports `isRequired = true` for an
  impostor, the scenario is FAILED and Option A's claim is not shown.
* **Same name, same App** (G11): the only way is the App key. G11 tries to
  get it from a PR workflow on `pull_request` and `push`; the environment
  must refuse both (no step runs, no token, no App check naming a non-gate
  run). Anyone who already holds the key can post a same-App success; that
  stays a limit (`same_app_with_key`), not a pass.

Recorded as NOT_PROVEN with the reason: G8 (needs a merge), AC28 (needs a
write-only second account), admin bypass (needs a merge attempt),
`same_app_with_key`.

Not verified until the run: whether `isRequired` honours the expected source;
whether `POST /rulesets` accepts `integration_id` directly; whether
`user/installations` reports the permissions as planned; whether step outputs
of a failed step reach the publisher (if not, BLOCKED runs still publish
failure).

## 8. Rollback

| Step | Rollback | After rollback |
| --- | --- | --- |
| app-push-scripts | `git push origin --delete phase1/app-gate-scripts` | the App workflow can no longer check out its scripts (fails closed) |
| App registration | App settings → Advanced → Delete GitHub App | all its keys and installations go with it |
| key | App settings → delete the key; delete the local `.pem` | no new tokens; existing ones expire within 1 h |
| app-publish | Settings → Archive (reversible) or delete by hand | nothing else depends on the repository |
| install | Settings → Applications → uninstall | publish fails (exit 3), PRs blocked |
| app-environment | `gh api -X DELETE repos/<demo>/environments/remediation-publisher` | the secret is deleted with it |
| app-secrets | `gh secret delete … --env remediation-publisher`, `gh variable delete …` | publish fails closed |
| Actions policy | delete the policy | after 2026-12-02 the gate stops (fail closed) |
| app-bootstrap / app-scenarios / app-steal | close the PRs, delete the branches | — |
| app-protect | `gh api -X DELETE repos/<demo>/rulesets/<id>` | the repository is unprotected again; stop using it |

Full teardown, after the evidence is accepted (separate approval): close all
PRs → archive the App demo → uninstall the App → delete its key → delete the
App → delete the scripts branch. Done when `app-preflight` shows the
repository archived or absent and the legacy owner-preflight still passes.

Key compromise (G11 FAILED, a key seen anywhere else, or doubt): delete the
key in the App settings first, suspend the installation, then rotate. Treat
every App check after the exposure as unproven.

Failure during a step: each step re-reads the state and skips what is done,
so it can be re-run. A step never overwrites a remote branch that moved and
never force-pushes.

## 9. Legacy demo vs App demo

| | Legacy demo | App demo |
| --- | --- | --- |
| Repository | `nobu-13/iac-remediation-gate-demo` (unchanged) | `nobu-13/iac-remediation-app-gate-demo` (new) |
| Workflow on `main` | `remediation-gate.yml`, one job `verify` | App workflow from the first commit: `verify` + `publish` |
| Required check | `verify` from GitHub Actions (15368) | `remediation-gate/verified` from the App |
| Reviews | code-owner review, 1 approval | PR required, 0 approvals (to attribute BLOCKED to the check) |
| Protection set up | after `main`, by `demo-protect` | after the bootstrap App check, by `app-protect` (W0 in between) |
| Secrets | none | App key as environment secret (`main` only, no admin bypass) |
| Pins | validator `5412a73` | validator `5412a73` + gate scripts `f77a58c` |
| Same-name spoof (G3/G6) | satisfies the rule (AC27 FAILED) | expected not required (G3, G3S, G6) |
| Same-App spoof | n/a | needs the key; G11 tests that a PR cannot get it |
| G1 mergeability | not observable (own approval impossible) | CLEAN, read only |
| Check vs review attribution | not possible | possible (no review rule) |
| G9 | NOT_PROVEN (ruleset change) | before/after the planned ruleset creation |
| G8, AC28 | NOT_PROVEN | NOT_PROVEN |
| Evidence of "required" | rollup only | GraphQL `isRequired` per check / status |
| Helper | `phase1_henv.py`, `phase1_henv_owner.py` | `phase1_appdemo.py` (legacy is read-only) |
| `pull_request_target` policy (2026-12-02) | still needed for the legacy gate | created before the first PR |

## 10. Automation

`phase1_appdemo.py` (local, under `.agents/`, not committed) runs every step
except four that GitHub only offers in the UI or that hold the key: App
registration, key generation, installation, and the Actions policy. Each
changing step runs the legacy guard and the App demo state check first, then
prints TARGET / CHANGE / ROLLBACK and requires the target name typed back.
Without `--execute` it changes nothing. The key reaches `gh secret set` on
stdin from a file outside any git work tree; the helper never prints or
copies it. 75 offline tests cover the targets, pins, legacy refusal, payloads,
the key handling, the classification and the offline gate run.

## 11. Restart on a second App demo (W0 minimised)

Status: **planned, nothing on GitHub created or changed**. The first App demo
(`nobu-13/iac-remediation-app-gate-demo`) reached 109 of 120 W0 minutes with
`main` only: no environment, no secret, no PR, no ruleset. It is kept as a
record and archived after Human approval. W0 is not extended.

Unchanged: App 5489276 (`nobu-13-remediation-gate`) and its existing key
(fingerprint pinned), validator `5412a73`, gate scripts `f77a58c`, H-ENV
`a24fb3f`, the legacy demo and ruleset `25921565`, PR #8, the W0 limit (120 min).

New: `nobu-13/iac-remediation-app-gate-demo-2`, targets
`appdemo2-targets.json` (same pins; `retired_demos` lists the first App demo,
which every command from this file refuses to touch), working copy and
evidence under `out/app-demo-2/`. `app-prepare` and `app-simulate` (11/11) have
already run for it locally.

### What changes in the flow

* **The repository is created empty** (`app-create-repo`). With no branch
  there is nothing to protect, so the App installation, JWT check,
  environment, secret, variables and Actions policy are all done before `main`
  exists.
* **W0 starts when `main` is created**: the earlier of GitHub's
  `branch_creation` activity for `main` and the helper's own record written
  just before the push. If neither is available, the repository's creation
  time (earlier, so conservative).
* **`app-w0` covers the whole W0 with one approval**: push `main`, push
  `g0-bootstrap` / `g9-probe` and open their PRs, wait for the G0 App check and
  G9 MERGEABLE (records both), create the ruleset, read it back, write
  `app-w0-summary.json` (start, end, minutes). Before anything it requires a
  passing simulation for these heads, the scripts on GitHub, a fresh sealed
  installation record, the environment with the secret, both variables, no
  repository secret, an empty repository and the W0 abort checks. It cannot
  check the Actions policy (UI only); the approval text names it. W0 lasts
  about as long as one gate run (a few minutes; not measured yet).
* **Installation move check**: the JWT record must list exactly the new demo;
  a retired demo still selected, the legacy demo, or the new demo missing are
  reported by name and block every step.
* **`app-retire`** saves a read-only snapshot of its targets' demo, then
  archives it (`gh repo archive`). Archiving makes the repository read-only and
  stops workflows, which ends its W0 at once; `gh repo unarchive` reverses it.

### Order and dependencies

| # | Step | Kind | Depends on | Why this place |
| --- | --- | --- | --- | --- |
| R1 | `app-retire` (first App demo's targets) | GitHub, approval | — | ends the first demo's W0 before 120 min; keeps it as a record |
| R2 | `app-create-repo` (demo-2) | GitHub, approval | simulation, scripts branch | nothing unprotected: no branch |
| R3 | App → Configure: *Only select repositories* = demo-2 only (remove the first demo) | UI | R2 | an App can only be installed on an existing repository |
| R4 | `app-verify-installation --app-key <pem>` | read-only + 1 h token, revoked | R3 | proves demo-2 only, seals the record (valid 24 h) |
| R5 | `app-environment` | GitHub, approval | R4 | every changing step needs the installation record |
| R6 | `app-secrets --pem <pem> --client-id <id>` | GitHub, approval | R5 | the secret lives in the environment |
| R7 | Actions policy: allow `pull_request_target` for `.github/workflows/remediation-gate.yml` | UI | R2 | the first PR must start the gate |
| R8 | `app-preflight` | read-only | R4–R7 | expect `phase: pre_w0`, no problems |
| R9 | `app-w0` | GitHub, one approval | R8, within 24 h of R4 | the whole W0 |
| R10 | delete the local `.pem` | local | R9 | the key is then only the environment secret |

R7 can be done any time between R2 and R9. Scenarios (G1–G11) follow as before
(`app-scenarios`, `app-evidence`, `app-push-update`, `app-steal`).

### Rollback

| Step | Rollback | Effect |
| --- | --- | --- |
| R1 | `gh repo unarchive nobu-13/iac-remediation-app-gate-demo --yes` | first demo writable again (W0 would reopen) |
| R2 | archive (`app-retire` with `appdemo2-targets.json`) or delete by hand | nothing depends on it |
| R3 | Configure: select the first demo again, remove demo-2 | — |
| R4 | none | the token was revoked; if not, it expires within 1 h |
| R5 | `gh api -X DELETE repos/<demo-2>/environments/remediation-publisher` | removes the secret as well |
| R6 | `gh secret delete … --env remediation-publisher`, `gh variable delete …` | publish fails closed |
| R7 | delete the policy | the gate does not start (fail closed) |
| R9 before the ruleset | `app-retire` with `appdemo2-targets.json` | archive ends W0 at once |
| R9 after the ruleset | delete the ruleset only if it is wrong (W0 reopens), otherwise keep | — |

If `app-w0` stops (timeout, gate failure, ruleset differs) it says that W0 is
open and offers exactly two ways on: re-run `app-w0 --execute` (it resumes and
skips what is on GitHub) or `app-retire` (archive). The 120-minute limit and
the abort conditions of §5 apply from the first push of `main`.
