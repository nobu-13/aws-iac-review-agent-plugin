"""Phase 1 bounded remediation verifier (``python3 -m iacreview.remediation``).

Verifies one candidate change against a human-approved Remediation Contract
and writes a Remediation_Verification_Report. It never edits files, never calls
an AWS API and never merges or deploys. See ``docs/v2/phase1/design.md``.

Modules:
    rschema   closed vocabularies, limits and exit codes
    contract  strict Contract loader and validator
    profiles  shipped Profiles and their Guard rules
    gitsnap   read-only Git Snapshot Adapter
    boundary  repository and Template scope checks
    checks    cfn-lint / cfn-guard adapters
    decide    decision and task outcome
    report    report building, serialization, validation and the human Summary
    verify    orchestration of one verification
    cli       ``init`` / ``verify`` / ``explain``
"""
