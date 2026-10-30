"""Phase 2 M1 Evidence Integrity Foundation (deterministic, offline).

Source: ``docs/v2/phase2/m1/wp0/m1-architecture-proposal.md`` (Location D-1
approved: ``iacreview/evidence/``). Purpose: keep pre-fixed acceptance
criteria, their evaluator rules and tests in one machine-readable registry.
Nothing here calls GitHub, AWS, an LLM or MCP.

Modules (WP1):
    registry   strict loader and validator of Acceptance Definitions
    rules      catalog of evaluator rule ids and their implementation status

The repository public-safety preflight is a hygiene script, not plugin code:
``.github/scripts/public_preflight.py``.

Data:
    definitions/  versioned Acceptance Definitions (JSON)
    schema/       the Definition schema (JSON Schema, documentation of the format
                  the registry enforces)

A registry entry is a statement of what will be checked and how. It is not
evidence that a rule or a test exists or passed: see
:func:`iacreview.evidence.registry.coverage`.
"""
