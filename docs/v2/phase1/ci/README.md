# Remediation gate (Phase 1 reference, not released)

`remediation-gate.yml` is a reference GitHub Actions workflow that re-runs the
Phase 1 verifier (`python3 -m iacreview.remediation verify`) for every pull
request, using the contract from the base commit and a pinned validator
commit. It is meant for the repository whose Templates are being repaired,
not for this plugin's own pull requests: a gate on the plugin's own PRs would
run the validator under development and is not an independent gate.

What it does: checks out the base commit, fetches the PR head as git objects
without checking it out, checks out the pinned validator into its own
directory, installs cfn-lint 1.46.0 and the digest-pinned cfn-guard 3.2.1, runs
`verify` and fails the job on any decision other than VERIFIED (exit 20, 21
or 22). The report is kept as an artifact and summarized in the job summary.

What it does not do: merge, approve, push, comment, deploy, or call AWS. It
uses no secrets and `contents: read` only.

Making it a gate needs repository settings the workflow cannot set for
itself. `docs/v2/phase1/handoff.md` lists them and the tests that show they
work:

1. a ruleset on `main` requiring the check `verify` from GitHub Actions,
   requiring pull requests, blocking force pushes, and with no bypass actor
   for the test identity;
2. `CODEOWNERS` covering `.github/workflows/`, `.iac-remediation/` and
   `CODEOWNERS` itself, with code-owner review required;
3. "require branches to be up to date", so a moved base makes the result
   stale until the PR is updated (the verifier also refuses a Base that is not
   an ancestor of Head).

Known limits: a same-named check from another workflow, an admin bypass, or
a repository without rulesets support are not prevented by this file. They
are listed as tests to run, not as guarantees.
