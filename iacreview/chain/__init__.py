"""Remediation Evidence Chain (Phase 2 M2): deterministic checks that the artifacts of one remediation agree.

Source: ``docs/v2/phase2/m2/wp0/`` (rev1, Human approved). WP1 scope: the Chain Manifest, the reason
codes and Chain Status, and the subject, contract, review, verification and GitHub-evidence links.
Gate Records (GV-1..GV-4) are WP2; until then the ``gate`` link is never LINKED.

Boundaries:

* Library only. No CLI in WP1 (D-1); the exit codes 31..34 are reserved in :mod:`iacreview.chain.status`.
* Offline. Git is read through :mod:`iacreview.remediation.gitsnap`; the GitHub evidence is the M1 store,
  read through :mod:`iacreview.evidence.store` and :mod:`iacreview.evidence.integrity` without change.
* One-way imports: this package imports ``iacreview.evidence``, ``iacreview.remediation`` and
  ``iacreview.reportcheck``; none of them imports this package.
* The values written in a Chain Manifest are references, not claims: every link re-reads and recomputes.
* The summary's pass flag of a Review_Report is never read (completeness is ``errors[]`` and ``tools[]``).

A COMPLETE chain means only that the referenced artifacts agree with one another. It does not prove what
``status.NOT_CLAIMED`` lists (merge enforcement, approver permission, human identity, capture authenticity
and the rest).
"""

from iacreview.chain.status import (  # noqa: F401 - re-exported names
    CHAIN_STATUSES,
    EXIT_CODES,
    EXIT_INPUT_INVALID,
    LINK_STATUSES,
    LINKS,
    NOT_CLAIMED,
    REASONS,
    compose,
    exit_code_for,
)
from iacreview.chain.validator import validate  # noqa: F401 - re-exported name
